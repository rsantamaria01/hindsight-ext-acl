# Changelog

## 0.1.0 — 2026-10-22

- First release, tested against Hindsight 1.1.0.
- `AclTenantExtension`: one key per identity (sha256 in the access file) plus an optional root key for the control-plane UI.
- `AclValidator`: implicit own space `<prefix>-<id>-*`; `r` / `tag` / `rw` grants by bank id or glob; admins; bank list filtering; engine-enforced write tag scope for `tag`.
- `access.yaml` format version 1 with JSON Schema; `hindsight-acl` CLI (`check`, `keygen`, `hash`, `explain`, `schema`).
