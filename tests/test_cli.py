from __future__ import annotations

import hashlib
import io
import json

import yaml

from hindsight_ext_acl.cli import main

from .conftest import EXAMPLE, base_doc


def test_check_example(capsys):
    assert main(["check", str(EXAMPLE)]) == 0
    out = capsys.readouterr().out
    assert "OK" in out and "own space:   usr-bob-*" in out and "agent:openclaw:openclaw" in out


def test_check_invalid(tmp_path, capsys):
    doc = base_doc()
    doc["identities"]["bob"]["key_sha256"] = "x"
    path = tmp_path / "a.yaml"
    path.write_text(yaml.safe_dump(doc))
    assert main(["check", str(path)]) == 1
    assert "64 lowercase hex" in capsys.readouterr().err


def test_keygen(capsys):
    assert main(["keygen"]) == 0
    out = capsys.readouterr().out.splitlines()
    key = out[0].split()[1]
    digest = out[1].split('"')[1]
    assert hashlib.sha256(key.encode()).hexdigest() == digest
    assert "," not in key and key.isascii()


def test_hash(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("example-key-bob\n"))
    assert main(["hash"]) == 0
    assert capsys.readouterr().out.strip() == hashlib.sha256(b"example-key-bob").hexdigest()


def test_explain(capsys):
    assert main(["explain", "-f", str(EXAMPLE), "openclaw", "team-infra", "usr-bob-x"]) == 0
    out = capsys.readouterr().out
    assert "openclaw on team-infra: tag" in out and "openclaw on usr-bob-x: none" in out


def test_schema(capsys):
    assert main(["schema"]) == 0
    assert json.loads(capsys.readouterr().out)["title"].startswith("hindsight-ext-acl")
