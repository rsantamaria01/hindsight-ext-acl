from __future__ import annotations

import copy

import pytest
import yaml

from hindsight_ext_acl.config import Access, AccessConfigError, load_config, parse_config

from .conftest import EXAMPLE, base_doc, sha


def errors_of(doc) -> list[str]:
    with pytest.raises(AccessConfigError) as exc:
        parse_config(doc)
    return exc.value.errors


def test_example_file_is_valid():
    cfg = load_config(EXAMPLE)
    assert set(cfg.identities) == {"alice", "bob", "openclaw", "oc_dev01"}
    assert cfg.types == {"user": "usr", "agent": "agn"}


def test_defaults_and_derived_fields():
    cfg = parse_config(base_doc())
    bob = cfg.identities["bob"]
    assert bob.own_space == "usr-bob-*"
    assert bob.write_tag == "user:bob"
    oc = cfg.identities["openclaw"]
    assert oc.own_space == "agn-openclaw-*"
    assert oc.write_tag == "agent:openclaw:openclaw"
    assert cfg.identities["oc_dev01"].write_tag == "agent:opencode:oc_dev01"
    assert cfg.by_key_hash[sha("k-bob")] is bob


def test_custom_types_replace_defaults():
    doc = base_doc()
    doc["types"] = {"user": {"prefix": "usr"}, "agent": {"prefix": "agn"}, "service": None}
    doc["identities"]["backup"] = {"type": "service", "key_sha256": sha("k-backup")}
    cfg = parse_config(doc)
    assert cfg.identities["backup"].own_space is None

    doc = base_doc()
    doc["types"] = {"person": {"prefix": "per"}}
    errs = errors_of(doc)
    assert any("type: must be one of ['person']" in e for e in errs)


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda d: d.update(version=2), "'version' must be 1"),
        (lambda d: d.update(extra=1), "unknown top-level key 'extra'"),
        (lambda d: d.update(identities={}), "'identities' must be a non-empty mapping"),
        (lambda d: d["identities"].update({"Bad-Id": {"type": "user", "key_sha256": sha("x")}}), "id must match"),
        (lambda d: d["identities"].update({"root": {"type": "user", "key_sha256": sha("x")}}), "reserved"),
        (lambda d: d["identities"]["bob"].update(key_sha256="ABC"), "64 lowercase hex"),
        (lambda d: d["identities"]["bob"].update(key_sha256=sha("k-alice")), "same key as identity 'alice'"),
        (lambda d: d["identities"]["bob"].update(type="robot"), "type: must be one of"),
        (lambda d: d["identities"]["bob"].update(admin="yes"), "admin: must be true or false"),
        (lambda d: d["identities"]["bob"].update(runtime="Open-Claw"), "runtime: must match"),
        (lambda d: d["identities"]["bob"].update(keys=[]), "unknown key 'keys'"),
        (lambda d: d["identities"]["bob"].update(grants={"banks": ["x"]}), "grants: must be a list"),
        (lambda d: d["identities"]["bob"].update(grants=[{"banks": [], "access": "r"}]), "banks: must be a non-empty list"),
        (lambda d: d["identities"]["bob"].update(grants=[{"banks": ["a b"], "access": "r"}]), "banks: must be a non-empty list"),
        (lambda d: d["identities"]["bob"].update(grants=[{"banks": ["x"], "access": "write"}]), "access: must be 'r', 'rw' or 'tag'"),
        (lambda d: d["identities"]["bob"].update(grants=[{"banks": ["x"], "access": "r", "tag": "t"}]), "unknown key 'tag'"),
        (lambda d: d.update(types={"user": {"prefix": "u-s"}}), "prefix: must match"),
        (lambda d: d.update(types={"user": {"prefix": "usr"}, "agent": {"prefix": "usr"}}), "already used by type 'user'"),
    ],
)
def test_invalid_documents(mutate, expected):
    doc = copy.deepcopy(base_doc())
    mutate(doc)
    errs = errors_of(doc)
    assert any(expected in e for e in errs), errs


def test_all_errors_reported_at_once():
    doc = base_doc()
    doc["identities"]["bob"]["key_sha256"] = "nope"
    doc["identities"]["alice"]["type"] = "nope"
    assert len(errors_of(doc)) == 2


def test_warnings():
    doc = base_doc()
    doc["identities"]["alice"]["grants"] = [{"banks": ["x"], "access": "r"}]
    doc["identities"]["bob"]["grants"] = [{"banks": ["usr-bob-*"], "access": "rw"}]
    cfg = parse_config(doc)
    assert any("admin has access to every bank" in w for w in cfg.warnings)
    assert any("inside the identity's own space" in w for w in cfg.warnings)


def test_load_errors(tmp_path):
    with pytest.raises(AccessConfigError, match="cannot read"):
        load_config(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: [1\n")
    with pytest.raises(AccessConfigError, match="YAML syntax error"):
        load_config(bad)
    ok = tmp_path / "ok.yaml"
    ok.write_text(yaml.safe_dump(base_doc()))
    assert load_config(ok).identities["bob"].grants == ()


def test_access_ordering():
    assert Access.NONE < Access.R < Access.TAG < Access.RW
    assert Access.parse("tag") is Access.TAG
