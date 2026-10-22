"""The JSON Schema (for editors) and the runtime validator must agree."""

from __future__ import annotations

import copy
import json
from importlib import resources

import jsonschema
import pytest
import yaml

from hindsight_ext_acl.config import AccessConfigError, parse_config

from .conftest import EXAMPLE, base_doc, sha

SCHEMA = json.loads(resources.files("hindsight_ext_acl").joinpath("access.schema.json").read_text())


def schema_ok(doc) -> bool:
    try:
        jsonschema.validate(doc, SCHEMA)
        return True
    except jsonschema.ValidationError:
        return False


def runtime_ok(doc) -> bool:
    try:
        parse_config(doc)
        return True
    except AccessConfigError:
        return False


def test_schema_is_valid_json_schema():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


def test_example_validates():
    doc = yaml.safe_load(EXAMPLE.read_text())
    assert schema_ok(doc)
    assert runtime_ok(doc)


# Shape errors: both must reject.
@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(version=2),
        lambda d: d.update(extra=1),
        lambda d: d.update(identities={}),
        lambda d: d["identities"].update({"Bad-Id": {"type": "user", "key_sha256": sha("x")}}),
        lambda d: d["identities"].update({"root": {"type": "user", "key_sha256": sha("x")}}),
        lambda d: d["identities"]["bob"].update(key_sha256="ABC"),
        lambda d: d["identities"]["bob"].update(admin="yes"),
        lambda d: d["identities"]["bob"].update(runtime="Open-Claw"),
        lambda d: d["identities"]["bob"].update(keys=[]),
        lambda d: d["identities"]["bob"].pop("key_sha256"),
        lambda d: d["identities"]["bob"].pop("type"),
        lambda d: d["identities"]["bob"].update(grants=[{"banks": [], "access": "r"}]),
        lambda d: d["identities"]["bob"].update(grants=[{"banks": ["a b"], "access": "r"}]),
        lambda d: d["identities"]["bob"].update(grants=[{"banks": ["x"], "access": "write"}]),
        lambda d: d["identities"]["bob"].update(grants=[{"banks": ["x"], "access": "r", "tag": "t"}]),
        lambda d: d.update(types={"user": {"prefix": "u-s"}}),
        lambda d: d.update(types={"user": {"prefix": "usr", "other": 1}}),
    ],
)
def test_shape_errors_rejected_by_both(mutate):
    doc = copy.deepcopy(base_doc())
    mutate(doc)
    assert not schema_ok(doc)
    assert not runtime_ok(doc)


# Cross-field errors: only the runtime validator can see them.
@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["identities"]["bob"].update(key_sha256=sha("k-alice")),
        lambda d: d["identities"]["bob"].update(type="robot"),
        lambda d: d.update(types={"user": {"prefix": "usr"}, "agent": {"prefix": "usr"}}),
    ],
)
def test_cross_field_errors_rejected_at_runtime(mutate):
    doc = copy.deepcopy(base_doc())
    mutate(doc)
    assert schema_ok(doc)
    assert not runtime_ok(doc)
