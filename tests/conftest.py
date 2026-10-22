from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hindsight_ext_acl import config as config_mod

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "access.example.yaml"


def sha(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def base_doc() -> dict:
    """A minimal valid access document (mutate copies in tests)."""
    return {
        "version": 1,
        "identities": {
            "alice": {"type": "user", "admin": True, "key_sha256": sha("k-alice")},
            "bob": {"type": "user", "key_sha256": sha("k-bob")},
            "openclaw": {
                "type": "agent",
                "runtime": "openclaw",
                "key_sha256": sha("k-openclaw"),
                "grants": [{"banks": ["team-infra"], "access": "tag"}],
            },
            "oc_dev01": {
                "type": "agent",
                "runtime": "opencode",
                "key_sha256": sha("k-oc"),
                "grants": [
                    {"banks": ["team-infra"], "access": "r"},
                    {"banks": ["docs-*"], "access": "r"},
                    {"banks": ["docs-shared"], "access": "rw"},
                ],
            },
        },
    }


@pytest.fixture(autouse=True)
def _fresh_cache():
    config_mod._reset_cache()
    yield
    config_mod._reset_cache()
