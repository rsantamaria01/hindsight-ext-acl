"""Pure access decisions. No Hindsight imports, so it is unit-testable on its own."""

from __future__ import annotations

from fnmatch import fnmatchcase

from .config import Access, AccessConfig, Identity

#: Bank read operations (``BankReadOperation`` values) that need ``rw``: webhook
#: configuration and delivery logs can carry target URLs and payloads.
READ_OPS_NEED_RW = frozenset({"list_webhooks", "list_webhook_deliveries"})

#: Bank write operations (``BankWriteOperation`` values) a ``tag`` identity may run.
#: Each one targets a single item, and Hindsight's write tag scope then refuses it
#: unless every tag on that item is the identity's own tag.
TAG_WRITE_OPS = frozenset(
    {
        "update_document",
        "delete_document",
        "reprocess_document",
        "update_memory_unit",
        "clear_observations_for_memory",
    }
)


def access_for(identity: Identity, bank_id: str) -> Access:
    """Effective access of ``identity`` on ``bank_id`` (highest matching rule wins)."""
    if identity.admin:
        return Access.RW
    if identity.own_space and fnmatchcase(bank_id, identity.own_space):
        return Access.RW
    level = Access.NONE
    for grant in identity.grants:
        if grant.access > level and grant.matches(bank_id):
            level = grant.access
            if level is Access.RW:
                break
    return level


def visible_bank_ids(identity: Identity, bank_ids: list[str]) -> list[str]:
    return [b for b in bank_ids if access_for(identity, b) >= Access.R]


def can_read_op(level: Access, operation: str) -> bool:
    if level is Access.NONE:
        return False
    if operation in READ_OPS_NEED_RW:
        return level is Access.RW
    return True


def can_write_op(level: Access, operation: str) -> bool:
    if level is Access.RW:
        return True
    if level is Access.TAG:
        return operation in TAG_WRITE_OPS
    return False


def inject_write_tag(contents: list[dict], tag: str) -> list[dict]:
    """Copy of retain ``contents`` with ``tag`` on every item (idempotent)."""
    out: list[dict] = []
    for item in contents:
        new = dict(item)
        tags = list(new.get("tags") or [])
        if tag not in tags:
            tags.append(tag)
        new["tags"] = tags
        out.append(new)
    return out


def describe(config: AccessConfig, identity_id: str, bank_id: str) -> str:
    """Human explanation of one decision (CLI ``explain``)."""
    ident = config.identities.get(identity_id)
    if ident is None:
        return f"unknown identity '{identity_id}'"
    level = access_for(ident, bank_id)
    if ident.admin:
        why = "admin"
    elif ident.own_space and fnmatchcase(bank_id, ident.own_space):
        why = f"own space {ident.own_space}"
    else:
        hits = [f"{','.join(g.banks)}={g.access.label()}" for g in ident.grants if g.matches(bank_id)]
        why = "grants " + "; ".join(hits) if hits else "no matching rule"
    extra = f", writes tagged {ident.write_tag}" if level is Access.TAG else ""
    return f"{identity_id} on {bank_id}: {level.label()} ({why}{extra})"
