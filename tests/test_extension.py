"""Extension classes against the real Hindsight extension interfaces."""

from __future__ import annotations

import types

import pytest
import yaml

pytest.importorskip("hindsight_api")

from hindsight_api.extensions import (  # noqa: E402
    AuthenticationError,
    BankListContext,
    BankReadContext,
    BankReadOperation,
    BankWriteContext,
    BankWriteOperation,
    CreateBankContext,
    MemoryUpdateContext,
    MentalModelRefreshContext,
    PrecheckContext,
    PrecheckOperation,
    RecallContext,
    RequestContext,
    RetainContext,
    TagScopeContext,
)

from hindsight_ext_acl import extension as ext_mod  # noqa: E402
from hindsight_ext_acl import AclTenantExtension, AclValidator  # noqa: E402

from .conftest import base_doc  # noqa: E402

ROOT_KEY = "r" * 40


@pytest.fixture
def env(tmp_path, monkeypatch):
    path = tmp_path / "access.yaml"
    path.write_text(yaml.safe_dump(base_doc()))
    monkeypatch.setenv("HINDSIGHT_API_TENANT_ACCESS_FILE", str(path))
    monkeypatch.delenv("HINDSIGHT_API_MCP_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(ext_mod, "get_hindsight_config", lambda: types.SimpleNamespace(database_schema="public"))
    return path


@pytest.fixture
def tenant(env):
    return AclTenantExtension({"access_file": str(env), "root_key": ROOT_KEY})


@pytest.fixture
def validator(env):
    return AclValidator({})


async def ctx_for(tenant, key: str) -> RequestContext:
    rc = RequestContext(api_key=key)
    await tenant.authenticate(rc)
    return rc


# -- tenant -------------------------------------------------------------------------


async def test_authenticate_identities(tenant):
    rc = await ctx_for(tenant, "k-bob")
    assert rc.tenant_id == "bob" and rc.api_key_id == "bob"
    rc = await ctx_for(tenant, ROOT_KEY)
    assert rc.tenant_id == "root"
    tc = await tenant.authenticate(RequestContext(api_key="k-alice"))
    assert tc.schema_name == "public"


@pytest.mark.parametrize("key", [None, "", "wrong", "k-bob ", "\udcff"])
async def test_authenticate_rejects(tenant, key):
    with pytest.raises(AuthenticationError):
        await tenant.authenticate(RequestContext(api_key=key))


async def test_mcp_uses_same_auth(tenant):
    rc = RequestContext(api_key="k-openclaw")
    await tenant.authenticate_mcp(rc)
    assert rc.tenant_id == "openclaw"
    with pytest.raises(AuthenticationError):
        await tenant.authenticate_mcp(RequestContext(api_key=None))


def test_startup_guards(env, monkeypatch):
    with pytest.raises(ValueError, match="at least 32"):
        AclTenantExtension({"access_file": str(env), "root_key": "short"})
    with pytest.raises(ValueError, match="MCP_AUTH_DISABLED"):
        AclTenantExtension({"access_file": str(env), "mcp_auth_disabled": "true"})
    monkeypatch.setenv("HINDSIGHT_API_MCP_AUTH_TOKEN", "")
    with pytest.raises(ValueError, match="MCP_AUTH_TOKEN"):
        AclTenantExtension({"access_file": str(env)})
    with pytest.raises(ValueError, match="MCP_AUTH_TOKEN"):
        AclValidator({})


def test_root_key_optional(env):
    AclTenantExtension({"access_file": str(env)})


async def test_list_tenants(tenant):
    assert [t.schema for t in await tenant.list_tenants()] == ["public"]


# -- validator ----------------------------------------------------------------------


def denied(result, code):
    return result is not None and not result.allowed and result.status_code == code


def allowed(result):
    return result is not None and result.allowed


async def test_recall(tenant, validator):
    bob = await ctx_for(tenant, "k-bob")
    assert allowed(await validator.validate_recall(RecallContext(bank_id="usr-bob-x", query="q", request_context=bob)))
    assert denied(await validator.validate_recall(RecallContext(bank_id="team-infra", query="q", request_context=bob)), 404)


async def test_retain_levels(tenant, validator):
    oc = await ctx_for(tenant, "k-oc")
    claw = await ctx_for(tenant, "k-openclaw")
    bob = await ctx_for(tenant, "k-bob")
    contents = [{"content": "x", "tags": ["source:test"]}]

    r = await validator.validate_retain(RetainContext(bank_id="team-infra", contents=contents, request_context=oc))
    assert denied(r, 403)
    r = await validator.validate_retain(RetainContext(bank_id="team-infra", contents=contents, request_context=bob))
    assert denied(r, 404)
    r = await validator.validate_retain(RetainContext(bank_id="agn-oc_dev01-x", contents=contents, request_context=oc))
    assert allowed(r) and r.contents is None

    r = await validator.validate_retain(RetainContext(bank_id="team-infra", contents=contents, request_context=claw))
    assert allowed(r)
    assert r.contents[0]["tags"] == ["source:test", "agent:openclaw:openclaw"]
    assert contents[0]["tags"] == ["source:test"]  # caller's list untouched


async def test_write_tag_scope(tenant, validator):
    claw = await ctx_for(tenant, "k-openclaw")
    bob = await ctx_for(tenant, "k-bob")
    assert await validator.resolve_write_tag_scope(TagScopeContext(bank_id="team-infra", request_context=claw)) == [
        "agent:openclaw:openclaw"
    ]
    assert await validator.resolve_write_tag_scope(TagScopeContext(bank_id="agn-openclaw-main", request_context=claw)) is None
    assert await validator.resolve_write_tag_scope(TagScopeContext(bank_id="usr-bob-x", request_context=bob)) is None


async def test_create_bank(tenant, validator):
    bob = await ctx_for(tenant, "k-bob")
    alice = await ctx_for(tenant, "k-alice")
    assert allowed(await validator.validate_create_bank(CreateBankContext(bank_id="usr-bob-budget", request_context=bob)))
    r = await validator.validate_create_bank(CreateBankContext(bank_id="team-new", request_context=bob))
    assert denied(r, 403) and "usr-bob-*" in r.reason
    assert allowed(await validator.validate_create_bank(CreateBankContext(bank_id="team-new", request_context=alice)))


async def test_bank_read_write_ops(tenant, validator):
    claw = await ctx_for(tenant, "k-openclaw")
    oc = await ctx_for(tenant, "k-oc")
    R = lambda op, bank, rc: BankReadContext(bank_id=bank, operation=op, request_context=rc)  # noqa: E731
    W = lambda op, bank, rc: BankWriteContext(bank_id=bank, operation=op, request_context=rc)  # noqa: E731

    assert allowed(await validator.validate_bank_read(R(BankReadOperation.LIST_DOCUMENTS, "team-infra", oc)))
    assert denied(await validator.validate_bank_read(R(BankReadOperation.LIST_WEBHOOKS, "team-infra", oc)), 403)
    assert denied(await validator.validate_bank_read(R(BankReadOperation.LIST_DOCUMENTS, "usr-bob-x", oc)), 404)

    assert allowed(await validator.validate_bank_write(W(BankWriteOperation.DELETE_DOCUMENT, "team-infra", claw)))
    assert denied(await validator.validate_bank_write(W(BankWriteOperation.DELETE_BANK, "team-infra", claw)), 403)
    assert denied(await validator.validate_bank_write(W(BankWriteOperation.DELETE_DOCUMENT, "team-infra", oc)), 403)
    assert allowed(await validator.validate_bank_write(W(BankWriteOperation.DELETE_BANK, "agn-oc_dev01-x", oc)))


async def test_memory_update_and_mental_models(tenant, validator):
    claw = await ctx_for(tenant, "k-openclaw")
    oc = await ctx_for(tenant, "k-oc")
    mu = lambda bank, rc: MemoryUpdateContext(bank_id=bank, memory_id="m", request_context=rc)  # noqa: E731
    assert allowed(await validator.validate_memory_update(mu("team-infra", claw)))
    assert denied(await validator.validate_memory_update(mu("team-infra", oc)), 403)
    mm = lambda bank, rc: MentalModelRefreshContext(bank_id=bank, mental_model_id=None, request_context=rc)  # noqa: E731
    assert denied(await validator.validate_mental_model_refresh(mm("team-infra", claw)), 403)
    assert allowed(await validator.validate_mental_model_refresh(mm("agn-oc_dev01-x", oc)))


async def test_precheck(tenant, validator):
    oc = await ctx_for(tenant, "k-oc")
    pc = lambda op, bank: PrecheckContext(operation=op, bank_id=bank, request_context=oc)  # noqa: E731
    assert denied(await validator.precheck(pc(PrecheckOperation.RETAIN, "team-infra")), 403)
    assert allowed(await validator.precheck(pc(PrecheckOperation.RECALL, "team-infra")))
    assert denied(await validator.precheck(pc(PrecheckOperation.RECALL, "usr-bob-x")), 404)


async def test_bank_list(tenant, validator):
    banks = [{"bank_id": b} for b in ["usr-bob-a", "team-infra", "docs-x", "agn-openclaw-main"]]
    alice = await ctx_for(tenant, "k-alice")
    root = await ctx_for(tenant, ROOT_KEY)
    oc = await ctx_for(tenant, "k-oc")
    scope = await validator.bank_list_scope(alice)
    assert scope is not None and scope.bank_ids is None
    scope = await validator.bank_list_scope(root)
    assert scope is not None and scope.bank_ids is None
    assert await validator.bank_list_scope(oc) is None
    result = await validator.filter_bank_list(BankListContext(banks=banks, request_context=oc))
    assert [b["bank_id"] for b in result.banks] == ["team-infra", "docs-x"]


async def test_root_and_background_are_unrestricted(tenant, validator):
    root = await ctx_for(tenant, ROOT_KEY)
    background = RequestContext(internal=True)
    no_identity = RequestContext()  # e.g. a task queued before the extension was installed
    for rc in (root, background, no_identity):
        r = await validator.validate_retain(RetainContext(bank_id="anything", contents=[{"content": "x"}], request_context=rc))
        assert allowed(r) and r.contents is None


async def test_removed_identity_is_denied(validator):
    stale = RequestContext(tenant_id="ghost")
    assert denied(await validator.validate_recall(RecallContext(bank_id="team-infra", query="q", request_context=stale)), 404)
    result = await validator.filter_bank_list(BankListContext(banks=[{"bank_id": "team-infra"}], request_context=stale))
    assert result.banks == []


# -- decision log -------------------------------------------------------------------


async def test_decision_log(tenant, validator, caplog):
    caplog.set_level("INFO", logger="hindsight_ext_acl")
    bob = await ctx_for(tenant, "k-bob")
    await validator.validate_recall(RecallContext(bank_id="usr-bob-x", query="q", request_context=bob))
    await validator.validate_recall(RecallContext(bank_id="team-infra", query="q", request_context=bob))
    await validator.validate_recall(RecallContext(bank_id="x", query="q", request_context=RequestContext(internal=True)))
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("acl:")]
    assert lines[0] == "acl: identity=bob op=recall bank=usr-bob-x access=rw result=allow"
    assert lines[1].startswith("acl: identity=bob op=recall bank=team-infra access=none result=deny status=404")
    assert len(lines) == 2  # background work is not logged


async def test_decision_log_modes(env, tenant, caplog):
    caplog.set_level("INFO", logger="hindsight_ext_acl")
    bob = await ctx_for(tenant, "k-bob")
    denied_only = AclValidator({"log": "denied"})
    await denied_only.validate_recall(RecallContext(bank_id="usr-bob-x", query="q", request_context=bob))
    await denied_only.validate_recall(RecallContext(bank_id="team-infra", query="q", request_context=bob))
    off = AclValidator({"log": "off"})
    await off.validate_recall(RecallContext(bank_id="team-infra", query="q", request_context=bob))
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("acl:")]
    assert len(lines) == 1 and "result=deny" in lines[0]
    with pytest.raises(ValueError, match="OPERATION_VALIDATOR_LOG"):
        AclValidator({"log": "verbose"})


async def test_bank_list_log(tenant, validator, caplog):
    caplog.set_level("INFO", logger="hindsight_ext_acl")
    oc = await ctx_for(tenant, "k-oc")
    await validator.filter_bank_list(BankListContext(banks=[{"bank_id": "team-infra"}, {"bank_id": "x"}], request_context=oc))
    assert "acl: identity=oc_dev01 op=list_banks result=allow visible=1 of=2" in caplog.text
