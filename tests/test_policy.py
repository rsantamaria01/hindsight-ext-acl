from __future__ import annotations

import pytest

from hindsight_ext_acl.config import Access, parse_config
from hindsight_ext_acl.policy import (
    access_for,
    can_read_op,
    can_write_op,
    describe,
    inject_write_tag,
    visible_bank_ids,
)

from .conftest import base_doc

CFG = parse_config(base_doc())
I = CFG.identities


@pytest.mark.parametrize(
    "who, bank, expected",
    [
        ("alice", "anything", Access.RW),
        ("alice", "usr-bob-general", Access.RW),
        ("bob", "usr-bob-general", Access.RW),
        ("bob", "usr-bob-a-b", Access.RW),
        ("bob", "usr-bob", Access.NONE),  # every own bank has a suffix
        ("bob", "usr-bobby-x", Access.NONE),  # no prefix bleed between ids
        ("bob", "usr-alice-x", Access.NONE),
        ("bob", "team-infra", Access.NONE),
        ("openclaw", "team-infra", Access.TAG),
        ("openclaw", "agn-openclaw-main", Access.RW),
        ("openclaw", "agn-openclaw2-main", Access.NONE),
        ("oc_dev01", "team-infra", Access.R),
        ("oc_dev01", "docs-a", Access.R),
        ("oc_dev01", "docs-shared", Access.RW),  # highest match wins
        ("oc_dev01", "agn-oc_dev01-sanosoft", Access.RW),
    ],
)
def test_access_for(who, bank, expected):
    assert access_for(I[who], bank) is expected


def test_visible_bank_ids():
    banks = ["usr-bob-general", "usr-alice-x", "team-infra", "agn-openclaw-main"]
    assert visible_bank_ids(I["bob"], banks) == ["usr-bob-general"]
    assert visible_bank_ids(I["openclaw"], banks) == ["team-infra", "agn-openclaw-main"]
    assert visible_bank_ids(I["alice"], banks) == banks


def test_read_ops():
    assert can_read_op(Access.R, "list_documents")
    assert not can_read_op(Access.NONE, "list_documents")
    assert not can_read_op(Access.R, "list_webhooks")
    assert not can_read_op(Access.TAG, "list_webhook_deliveries")
    assert can_read_op(Access.RW, "list_webhooks")
    assert can_read_op(Access.R, "some_future_read_op")


def test_write_ops():
    assert can_write_op(Access.RW, "delete_bank")
    assert not can_write_op(Access.TAG, "delete_bank")
    assert not can_write_op(Access.TAG, "update_bank_config")
    assert not can_write_op(Access.TAG, "create_webhook")
    assert can_write_op(Access.TAG, "delete_document")
    assert can_write_op(Access.TAG, "update_memory_unit")
    assert not can_write_op(Access.R, "delete_document")
    assert not can_write_op(Access.TAG, "some_future_write_op")


def test_inject_write_tag_is_idempotent_and_copies():
    original = [{"content": "a"}, {"content": "b", "tags": ["agent:openclaw:openclaw"]}]
    out = inject_write_tag(original, "agent:openclaw:openclaw")
    assert out[0]["tags"] == ["agent:openclaw:openclaw"]
    assert out[1]["tags"] == ["agent:openclaw:openclaw"]
    assert "tags" not in original[0]
    assert inject_write_tag(out, "agent:openclaw:openclaw") == out


def test_describe():
    assert "rw (admin)" in describe(CFG, "alice", "x")
    assert "own space usr-bob-*" in describe(CFG, "bob", "usr-bob-x")
    assert "tag (grants team-infra=tag, writes tagged agent:openclaw:openclaw)" in describe(
        CFG, "openclaw", "team-infra"
    )
    assert "none (no matching rule)" in describe(CFG, "bob", "team-infra")
    assert "unknown identity" in describe(CFG, "zed", "x")
