"""Hindsight extension classes.

``AclTenantExtension`` turns the Bearer key into an identity id (stored in
``RequestContext.tenant_id`` and ``api_key_id``); ``AclValidator`` enforces the
access file on every operation. Both read the same access file, located by
``HINDSIGHT_API_TENANT_ACCESS_FILE``.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os

from hindsight_api.config import get_config as get_hindsight_config
from hindsight_api.extensions import (
    AuthenticationError,
    BankListContext,
    BankListResult,
    BankListScope,
    BankReadContext,
    BankWriteContext,
    CreateBankContext,
    ImportContext,
    MemoryUpdateContext,
    MentalModelGetContext,
    MentalModelRefreshContext,
    OperationValidatorExtension,
    PrecheckContext,
    RecallContext,
    ReflectContext,
    RequestContext,
    RetainContext,
    TagScopeContext,
    Tenant,
    TenantContext,
    TenantExtension,
    ValidationResult,
)

from .config import ROOT_ID, Access, AccessConfig, Identity, get_config
from .policy import access_for, can_read_op, can_write_op, inject_write_tag

logger = logging.getLogger("hindsight_ext_acl")

ROOT_KEY_MIN_LENGTH = 32
_TRUE = ("true", "1", "yes")

# Precheck operations (PrecheckOperation values) that write or spend LLM tokens.
_PRECHECK_WRITES = frozenset({"retain", "files_retain", "mental_model_create", "mental_model_refresh"})


def _refuse_mcp_bypass() -> None:
    # HINDSIGHT_API_MCP_AUTH_TOKEN makes MCP skip the tenant extension entirely, which would
    # let MCP callers act with no identity. Fail at startup instead of running wide open.
    if os.environ.get("HINDSIGHT_API_MCP_AUTH_TOKEN") is not None:
        raise ValueError(
            "HINDSIGHT_API_MCP_AUTH_TOKEN is set: it bypasses the tenant extension on MCP. "
            "Remove it; MCP clients authenticate with their identity key."
        )


class AclTenantExtension(TenantExtension):
    """Key -> identity. Configuration (prefix HINDSIGHT_API_TENANT_):

    - ``ACCESS_FILE``: path of access.yaml (default /etc/hindsight/access.yaml)
    - ``ROOT_KEY``: optional plaintext key with full access, identity ``root`` (the UI)
    """

    def __init__(self, config: dict[str, str]):
        super().__init__(config)
        _refuse_mcp_bypass()
        if config.get("mcp_auth_disabled", "").lower() in _TRUE:
            raise ValueError("HINDSIGHT_API_TENANT_MCP_AUTH_DISABLED is not supported by AclTenantExtension.")
        self._access: AccessConfig = get_config(config.get("access_file"))
        root_key = config.get("root_key")
        if root_key is not None and len(root_key) < ROOT_KEY_MIN_LENGTH:
            raise ValueError(f"HINDSIGHT_API_TENANT_ROOT_KEY must be at least {ROOT_KEY_MIN_LENGTH} characters")
        self._root_key = root_key.encode("utf-8") if root_key else None
        for warning in self._access.warnings:
            logger.warning("access file: %s", warning)
        logger.info(
            "hindsight-ext-acl: %d identities (%d admin), root key %s",
            len(self._access.identities),
            sum(1 for i in self._access.identities.values() if i.admin),
            "set" if self._root_key else "not set",
        )

    def _resolve(self, api_key: str | None) -> str:
        if not api_key:
            raise AuthenticationError("Missing Authorization header. Expected: Bearer <api_key>")
        # Header values arrive latin-1 decoded; surrogateescape keeps odd bytes from
        # turning a bad key into a 500 instead of a 401.
        key_bytes = api_key.encode("utf-8", "surrogateescape")
        if self._root_key is not None and hmac.compare_digest(key_bytes, self._root_key):
            return ROOT_ID
        identity = self._access.by_key_hash.get(hashlib.sha256(key_bytes).hexdigest())
        if identity is None:
            raise AuthenticationError("Invalid API key")
        return identity.id

    async def authenticate(self, context: RequestContext) -> TenantContext:
        identity_id = self._resolve(context.api_key)
        # Read back by the validator, persisted into queued tasks, used for metering/logs.
        context.tenant_id = identity_id
        context.api_key_id = identity_id
        return TenantContext(schema_name=get_hindsight_config().database_schema)

    async def authenticate_mcp(self, context: RequestContext) -> TenantContext:
        return await self.authenticate(context)

    async def list_tenants(self) -> list[Tenant]:
        return [Tenant(schema=get_hindsight_config().database_schema)]


class AclValidator(OperationValidatorExtension):
    """Enforces access.yaml. Reads the file named by HINDSIGHT_API_TENANT_ACCESS_FILE."""

    def __init__(self, config: dict[str, str]):
        super().__init__(config)
        _refuse_mcp_bypass()
        self._access: AccessConfig = get_config()

    # -- identity / level ----------------------------------------------------------

    def _identity(self, rc: RequestContext | None) -> Identity | str | None:
        """None = unrestricted system work; ROOT_ID = root key; else the identity.

        A context with no tenant_id never comes from an outside caller: the tenant
        extension sets it on every authenticated request and the worker restores it
        into queued tasks. What remains is background work (consolidation sweeps,
        scheduled refreshes, tasks queued before this extension was installed).
        """
        if rc is None or rc.internal or rc.tenant_id is None:
            return None
        if rc.tenant_id == ROOT_ID:
            return ROOT_ID
        identity = self._access.identities.get(rc.tenant_id)
        if identity is None:
            # Identity removed from the file after the task was queued.
            return _UNKNOWN
        return identity

    def _level(self, bank_id: str, rc: RequestContext | None) -> Access | None:
        who = self._identity(rc)
        if who is None or who == ROOT_ID:
            return None
        if who is _UNKNOWN:
            return Access.NONE
        return access_for(who, bank_id)  # type: ignore[arg-type]

    @staticmethod
    def _not_found(bank_id: str) -> ValidationResult:
        return ValidationResult.reject(f"Bank '{bank_id}' not found", 404)

    @staticmethod
    def _forbidden(bank_id: str, why: str) -> ValidationResult:
        return ValidationResult.reject(f"Access to bank '{bank_id}' denied: {why}", 403)

    def _read(self, bank_id: str, rc: RequestContext) -> ValidationResult:
        level = self._level(bank_id, rc)
        if level is None or level >= Access.R:
            return ValidationResult.accept()
        return self._not_found(bank_id)

    def _write_full(self, bank_id: str, rc: RequestContext) -> ValidationResult:
        level = self._level(bank_id, rc)
        if level is None or level is Access.RW:
            return ValidationResult.accept()
        if level is Access.NONE:
            return self._not_found(bank_id)
        return self._forbidden(bank_id, f"'{level.label()}' access")

    # -- pre-body check --------------------------------------------------------------

    async def precheck(self, ctx: PrecheckContext) -> ValidationResult:
        level = self._level(ctx.bank_id, ctx.request_context)
        if level is None:
            return ValidationResult.accept()
        if level is Access.NONE:
            return self._not_found(ctx.bank_id)
        if str(ctx.operation) in _PRECHECK_WRITES and level is Access.R:
            return self._forbidden(ctx.bank_id, "read-only ('r') access")
        return ValidationResult.accept()

    # -- core operations ---------------------------------------------------------------

    async def validate_retain(self, ctx: RetainContext) -> ValidationResult:
        level = self._level(ctx.bank_id, ctx.request_context)
        if level is None or level is Access.RW:
            return ValidationResult.accept()
        if level is Access.TAG:
            identity = self._identity(ctx.request_context)
            return ValidationResult.accept_with(contents=inject_write_tag(ctx.contents, identity.write_tag))  # type: ignore[union-attr]
        if level is Access.NONE:
            return self._not_found(ctx.bank_id)
        return self._forbidden(ctx.bank_id, "read-only ('r') access")

    async def validate_recall(self, ctx: RecallContext) -> ValidationResult:
        return self._read(ctx.bank_id, ctx.request_context)

    async def validate_reflect(self, ctx: ReflectContext) -> ValidationResult:
        return self._read(ctx.bank_id, ctx.request_context)

    # validate_consolidate is left at the default (accept): consolidation follows a
    # write the caller was already allowed to make; on-request runs go through
    # validate_bank_write (run_consolidation), which needs 'rw'.

    async def resolve_write_tag_scope(self, ctx: TagScopeContext) -> list[str] | None:
        level = self._level(ctx.bank_id, ctx.request_context)
        if level is Access.TAG:
            identity = self._identity(ctx.request_context)
            return [identity.write_tag]  # type: ignore[union-attr]
        return None

    # -- mental models / curation / import ----------------------------------------------

    async def validate_mental_model_get(self, ctx: MentalModelGetContext) -> ValidationResult:
        return self._read(ctx.bank_id, ctx.request_context)

    async def validate_mental_model_refresh(self, ctx: MentalModelRefreshContext) -> ValidationResult:
        return self._write_full(ctx.bank_id, ctx.request_context)

    async def validate_memory_update(self, ctx: MemoryUpdateContext) -> ValidationResult:
        level = self._level(ctx.bank_id, ctx.request_context)
        if level is None or level >= Access.TAG:
            # 'tag': Hindsight's write tag scope limits it to items carrying its own tag.
            return ValidationResult.accept()
        if level is Access.NONE:
            return self._not_found(ctx.bank_id)
        return self._forbidden(ctx.bank_id, "read-only ('r') access")

    async def validate_import(self, ctx: ImportContext) -> ValidationResult:
        return self._write_full(ctx.bank_id, ctx.request_context)

    # -- bank management -------------------------------------------------------------------

    async def validate_bank_read(self, ctx: BankReadContext) -> ValidationResult:
        level = self._level(ctx.bank_id, ctx.request_context)
        if level is None or can_read_op(level, str(ctx.operation)):
            return ValidationResult.accept()
        if level is Access.NONE:
            return self._not_found(ctx.bank_id)
        return self._forbidden(ctx.bank_id, f"'{ctx.operation}' needs 'rw'")

    async def validate_bank_write(self, ctx: BankWriteContext) -> ValidationResult:
        level = self._level(ctx.bank_id, ctx.request_context)
        if level is None or can_write_op(level, str(ctx.operation)):
            return ValidationResult.accept()
        if level is Access.NONE:
            return self._not_found(ctx.bank_id)
        return self._forbidden(ctx.bank_id, f"'{ctx.operation}' not allowed with '{level.label()}' access")

    async def validate_create_bank(self, ctx: CreateBankContext) -> ValidationResult:
        level = self._level(ctx.bank_id, ctx.request_context)
        if level is None or level is Access.RW:
            return ValidationResult.accept()
        identity = self._identity(ctx.request_context)
        space = getattr(identity, "own_space", None)
        hint = f"; create banks under '{space}'" if space else ""
        return ValidationResult.reject(f"Cannot create bank '{ctx.bank_id}'{hint}", 403)

    async def bank_list_scope(self, request_context: RequestContext) -> BankListScope | None:
        who = self._identity(request_context)
        if who is None or who == ROOT_ID or (isinstance(who, Identity) and who.admin):
            return BankListScope()  # every bank
        return None  # filter_bank_list decides per bank

    async def filter_bank_list(self, ctx: BankListContext) -> BankListResult:
        who = self._identity(ctx.request_context)
        if not isinstance(who, Identity):
            return BankListResult(banks=[] if who is _UNKNOWN else ctx.banks)
        return BankListResult(banks=[b for b in ctx.banks if access_for(who, str(b.get("bank_id"))) >= Access.R])


class _Unknown:
    def __repr__(self) -> str:
        return "<unknown identity>"


_UNKNOWN = _Unknown()
