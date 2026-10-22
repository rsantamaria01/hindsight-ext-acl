"""Load and validate the access file (``access.yaml``).

Validation here is the source of truth at runtime and has no dependency beyond
PyYAML. ``access.schema.json`` mirrors these rules for editors and CI; the test
suite checks that both agree.
"""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

SUPPORTED_VERSION = 1

#: Identity ids, type names and runtimes. Underscore allowed, dash not: ``-`` is the
#: separator in own-space bank ids (``usr-<id>-…``), so a dash inside an id would let
#: one identity's own space overlap another's.
ID_RE = re.compile(r"^[a-z0-9][a-z0-9_]{0,47}$")
PREFIX_RE = re.compile(r"^[a-z0-9]{1,16}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
BANK_PATTERN_RE = re.compile(r"^\S{1,200}$")

#: Identity id used for the root key (env). Not allowed in the file.
ROOT_ID = "root"

DEFAULT_TYPES: dict[str, str | None] = {"user": "usr", "agent": "agn"}

_TOP_KEYS = {"version", "types", "identities"}
_TYPE_KEYS = {"prefix"}
_IDENTITY_KEYS = {"type", "admin", "runtime", "key_sha256", "description", "grants"}
_GRANT_KEYS = {"banks", "access"}


class Access(IntEnum):
    """Access level on a bank. Higher wins when several rules match."""

    NONE = 0
    R = 1
    TAG = 2
    RW = 3

    @classmethod
    def parse(cls, value: str) -> Access:
        return {"r": cls.R, "tag": cls.TAG, "rw": cls.RW}[value]

    def label(self) -> str:
        return {Access.NONE: "none", Access.R: "r", Access.TAG: "tag", Access.RW: "rw"}[self]


class AccessConfigError(ValueError):
    """The access file is invalid. ``errors`` lists every problem found."""

    def __init__(self, errors: list[str], source: str = "access file"):
        self.errors = errors
        super().__init__(f"{source} is invalid:\n  - " + "\n  - ".join(errors))


@dataclass(frozen=True)
class Grant:
    banks: tuple[str, ...]
    access: Access

    def matches(self, bank_id: str) -> bool:
        return any(fnmatchcase(bank_id, pattern) for pattern in self.banks)


@dataclass(frozen=True)
class Identity:
    id: str
    type: str
    key_sha256: str
    admin: bool = False
    runtime: str | None = None
    description: str | None = None
    grants: tuple[Grant, ...] = ()
    #: ``<prefix>-<id>-*``, or None when the type has no prefix.
    own_space: str | None = None

    @property
    def write_tag(self) -> str:
        """Tag forced on writes to ``tag`` banks: ``<type>:<runtime>:<id>`` or ``<type>:<id>``."""
        if self.runtime:
            return f"{self.type}:{self.runtime}:{self.id}"
        return f"{self.type}:{self.id}"


@dataclass(frozen=True)
class AccessConfig:
    types: dict[str, str | None]
    identities: dict[str, Identity]
    by_key_hash: dict[str, Identity] = field(repr=False)
    warnings: tuple[str, ...] = ()


def parse_config(data: Any, source: str = "access file") -> AccessConfig:
    """Validate a parsed YAML document and build the config. Raises AccessConfigError."""
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(data, dict):
        raise AccessConfigError(["top level must be a mapping"], source)

    for key in sorted(set(data) - _TOP_KEYS):
        errors.append(f"unknown top-level key '{key}'")

    version = data.get("version")
    if version != SUPPORTED_VERSION:
        errors.append(f"'version' must be {SUPPORTED_VERSION} (got {version!r})")

    # --- types -----------------------------------------------------------------
    types: dict[str, str | None] = {}
    raw_types = data.get("types")
    if raw_types is None:
        types = dict(DEFAULT_TYPES)
    elif not isinstance(raw_types, dict) or not raw_types:
        errors.append("'types' must be a non-empty mapping when present")
    else:
        seen_prefixes: dict[str, str] = {}
        for name, spec in raw_types.items():
            where = f"types.{name}"
            if not isinstance(name, str) or not ID_RE.match(name):
                errors.append(f"{where}: type name must match {ID_RE.pattern}")
                continue
            if spec is None:
                spec = {}
            if not isinstance(spec, dict):
                errors.append(f"{where}: must be a mapping")
                continue
            for key in sorted(set(spec) - _TYPE_KEYS):
                errors.append(f"{where}: unknown key '{key}'")
            prefix = spec.get("prefix")
            if prefix is not None:
                if not isinstance(prefix, str) or not PREFIX_RE.match(prefix):
                    errors.append(f"{where}.prefix: must match {PREFIX_RE.pattern}")
                    prefix = None
                elif prefix in seen_prefixes:
                    errors.append(f"{where}.prefix: '{prefix}' already used by type '{seen_prefixes[prefix]}'")
                else:
                    seen_prefixes[prefix] = name
            types[name] = prefix

    # --- identities ------------------------------------------------------------
    identities: dict[str, Identity] = {}
    by_hash: dict[str, Identity] = {}
    raw_ids = data.get("identities")
    if not isinstance(raw_ids, dict) or not raw_ids:
        errors.append("'identities' must be a non-empty mapping")
        raw_ids = {}

    for ident_id, spec in raw_ids.items():
        where = f"identities.{ident_id}"
        if not isinstance(ident_id, str) or not ID_RE.match(ident_id):
            errors.append(f"{where}: id must match {ID_RE.pattern}")
            continue
        if ident_id == ROOT_ID:
            errors.append(f"{where}: '{ROOT_ID}' is reserved for the root key")
            continue
        if not isinstance(spec, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        for key in sorted(set(spec) - _IDENTITY_KEYS):
            errors.append(f"{where}: unknown key '{key}'")

        type_name = spec.get("type")
        if type_name not in types:
            errors.append(f"{where}.type: must be one of {sorted(types)} (got {type_name!r})")
            continue

        key_hash = spec.get("key_sha256")
        if not isinstance(key_hash, str) or not SHA256_RE.match(key_hash):
            errors.append(f"{where}.key_sha256: must be 64 lowercase hex characters")
            continue
        if key_hash in by_hash:
            errors.append(f"{where}.key_sha256: same key as identity '{by_hash[key_hash].id}'")
            continue

        admin = spec.get("admin", False)
        if not isinstance(admin, bool):
            errors.append(f"{where}.admin: must be true or false")
            admin = False

        runtime = spec.get("runtime")
        if runtime is not None and (not isinstance(runtime, str) or not ID_RE.match(runtime)):
            errors.append(f"{where}.runtime: must match {ID_RE.pattern}")
            runtime = None

        description = spec.get("description")
        if description is not None and not isinstance(description, str):
            errors.append(f"{where}.description: must be a string")
            description = None

        prefix = types[type_name]
        own_space = f"{prefix}-{ident_id}-*" if prefix else None

        grants: list[Grant] = []
        raw_grants = spec.get("grants", [])
        if raw_grants is None:
            raw_grants = []
        if not isinstance(raw_grants, list):
            errors.append(f"{where}.grants: must be a list")
            raw_grants = []
        for i, g in enumerate(raw_grants):
            gwhere = f"{where}.grants[{i}]"
            if not isinstance(g, dict):
                errors.append(f"{gwhere}: must be a mapping")
                continue
            for key in sorted(set(g) - _GRANT_KEYS):
                errors.append(f"{gwhere}: unknown key '{key}'")
            banks = g.get("banks")
            if (
                not isinstance(banks, list)
                or not banks
                or not all(isinstance(b, str) and BANK_PATTERN_RE.match(b) for b in banks)
            ):
                errors.append(f"{gwhere}.banks: must be a non-empty list of bank ids or glob patterns")
                continue
            access = g.get("access")
            if access not in ("r", "rw", "tag"):
                errors.append(f"{gwhere}.access: must be 'r', 'rw' or 'tag' (got {access!r})")
                continue
            for b in banks:
                if own_space and fnmatchcase(b, own_space):
                    warnings.append(f"{gwhere}: '{b}' is inside the identity's own space; grant is redundant")
            grants.append(Grant(banks=tuple(banks), access=Access.parse(access)))

        if admin and grants:
            warnings.append(f"{where}: admin has access to every bank; its grants are ignored")

        ident = Identity(
            id=ident_id,
            type=type_name,
            key_sha256=key_hash,
            admin=admin,
            runtime=runtime,
            description=description,
            grants=tuple(grants),
            own_space=own_space,
        )
        identities[ident_id] = ident
        by_hash[key_hash] = ident

    if errors:
        raise AccessConfigError(errors, source)
    return AccessConfig(types=types, identities=identities, by_key_hash=by_hash, warnings=tuple(warnings))


def load_config(path: str | os.PathLike[str]) -> AccessConfig:
    """Read and validate an access file."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise AccessConfigError([f"cannot read {p}: {exc.strerror or exc}"], str(p)) from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AccessConfigError([f"YAML syntax error: {exc}"], str(p)) from exc
    return parse_config(data, str(p))


# --- process-wide cache shared by the tenant extension and the validator ----------

ACCESS_FILE_ENV = "HINDSIGHT_API_TENANT_ACCESS_FILE"
DEFAULT_ACCESS_FILE = "/etc/hindsight/access.yaml"

_lock = threading.Lock()
_cache: dict[str, AccessConfig] = {}


def access_file_path(explicit: str | None = None) -> str:
    return explicit or os.environ.get(ACCESS_FILE_ENV) or DEFAULT_ACCESS_FILE


def get_config(path: str | None = None) -> AccessConfig:
    """Load the access file once per process (the file is re-read on service restart)."""
    resolved = access_file_path(path)
    with _lock:
        cfg = _cache.get(resolved)
        if cfg is None:
            cfg = load_config(resolved)
            _cache[resolved] = cfg
        return cfg


def _reset_cache() -> None:
    """Tests only."""
    with _lock:
        _cache.clear()
