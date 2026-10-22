# hindsight-ext-acl

Identity-based access control for self-hosted [Hindsight](https://github.com/vectorize-io/hindsight).

One YAML file declares who can reach which memory banks:

- **One key per identity.** A person, or one agent runtime instance (an OpenClaw gateway, an OpenCode install).
- **Own space, implicit.** Every identity reads, writes, manages and creates banks under `<prefix>-<id>-*` with no configuration (`usr-bob-general`, `usr-bob-budget2027`, `agn-openclaw-main`).
- **Grants for everything else.** Shared or other people's banks get `r`, `tag` or `rw`, by bank id or glob.
- **Admins** reach every bank over the API and MCP. A separate **root key** is used by the control-plane UI.

Everything stays in one PostgreSQL schema. Installing or removing the extension does not move data.

It uses Hindsight's documented extension hooks (`TenantExtension` and `OperationValidatorExtension`), including the engine's own write tag scope. Tested against Hindsight 1.1.0.

## How a request is decided

1. The client sends `Authorization: Bearer <key>` over HTTP or MCP.
2. The tenant extension matches the key to an identity:
   - the root key (env) maps to identity `root`, with full access;
   - otherwise the sha256 of the key is looked up in the file;
   - anything else gets **401**.
3. The identity id is stored in `tenant_id` and `api_key_id`, so Hindsight's logs and metering show who acted. Queued tasks keep it.
4. Every operation names one bank. Its access level is the highest of these that match:

| Rule | Level |
|---|---|
| `admin: true` | `rw` on every bank |
| bank matches own space `<prefix>-<id>-*` | `rw` |
| `grants` entries whose `banks` match | as declared |
| nothing matches | none |

5. The level decides what is allowed:

| Level | Allowed | Refused |
|---|---|---|
| none | — | bank hidden from `list_banks`; any call **404** |
| `r` | recall, reflect, read documents, memories, mental models, knowledge pages | any write (**403**), webhooks |
| `tag` | everything in `r`, plus retain (the identity's tag is added automatically), plus edit or delete of items that carry only that tag | other items, mental model or knowledge page writes, bank-wide operations (**403**) |
| `rw` | everything, including bank config, deletion, and creating a bank whose id matches | — |

The **write tag** is `<type>:<runtime>:<id>`, or `<type>:<id>` when the identity has no `runtime`. Examples: `agent:openclaw:openclaw`, `user:bob`.

With `tag` access, every tag on an item must be the identity's own tag. Hindsight enforces this itself. So a client in `tag` mode must not send extra tags (for example OpenClaw `retainTags`), or its retains are refused.

## Access file

See [`access.example.yaml`](access.example.yaml). The schema lives at [`src/hindsight_ext_acl/access.schema.json`](src/hindsight_ext_acl/access.schema.json). Editors with the YAML language server validate and autocomplete through the `# yaml-language-server: $schema=…` line.

```yaml
version: 1
# types:                 # optional; these are the defaults, defining it replaces them
#   user:  { prefix: usr }
#   agent: { prefix: agn }
identities:
  alice:
    type: user
    admin: true
    key_sha256: "…"
  bob:
    type: user
    key_sha256: "…"
  openclaw:
    type: agent
    runtime: openclaw
    key_sha256: "…"
    grants:
      - banks: [team-infra]
        access: tag
```

Rules checked at startup and by `hindsight-acl check`:
- Ids, type names and runtimes must match `^[a-z0-9][a-z0-9_]*$`. A dash would let own spaces overlap.
- `root` is reserved.
- Keys must be unique.
- Prefixes must be unique.
- Every identity's `type` must be declared.
- Unknown keys are errors.
- A grant inside the identity's own space, or grants on an admin, produce a warning.

The file is read when Hindsight starts. **Restart** after editing it.

## Install

The extension adds no dependencies to the server; PyYAML ships with Hindsight.

### Native (pip / venv)

```bash
/opt/hindsight/venv/bin/pip install "git+https://github.com/rsantamaria01/hindsight-ext-acl@v0.1.0"
```

### Docker

```dockerfile
FROM ghcr.io/vectorize-io/hindsight:1.1.0
RUN uv pip install --python /app/api/.venv/bin/python --no-cache \
      "git+https://github.com/rsantamaria01/hindsight-ext-acl@v0.1.0"
RUN /app/api/.venv/bin/python -c "import hindsight_ext_acl"
```

### Configure (API environment)

```bash
HINDSIGHT_API_TENANT_EXTENSION=hindsight_ext_acl:AclTenantExtension
HINDSIGHT_API_OPERATION_VALIDATOR_EXTENSION=hindsight_ext_acl:AclValidator
HINDSIGHT_API_TENANT_ACCESS_FILE=/etc/hindsight/access.yaml   # default
HINDSIGHT_API_TENANT_ROOT_KEY=<at least 32 chars>              # optional; the UI's key
```

Control plane (UI):

```bash
HINDSIGHT_CP_ACCESS_KEY=<root key>
HINDSIGHT_CP_DATAPLANE_API_KEY=<root key>
```

Decision log (validator environment):

```bash
HINDSIGHT_API_OPERATION_VALIDATOR_LOG=all     # default: one line per decision; or "denied", or "off"
```

```
acl: identity=rsantamaria op=recall bank=hsm-infra access=rw result=allow
acl: identity=bob op=recall bank=team-infra access=none result=deny status=404 reason="Bank 'team-infra' not found"
```

Background work (consolidation, scheduled refreshes) is not logged. A queued retain is logged twice: once when it is submitted, and again when the worker runs it.

The extension refuses to start if `HINDSIGHT_API_MCP_AUTH_TOKEN` is set (that variable bypasses tenant auth on MCP) or if `HINDSIGHT_API_TENANT_MCP_AUTH_DISABLED` is true. Give API and worker processes the same variables.

## CLI

```bash
hindsight-acl keygen                       # new key + key_sha256 line (key shown once)
hindsight-acl hash < keyfile               # sha256 of an existing key
hindsight-acl check [/etc/hindsight/access.yaml]
hindsight-acl explain -f access.yaml bob usr-bob-general team-infra
hindsight-acl schema                       # print the JSON Schema
```

## Agents

One key per **runtime instance**, not per agent. For example, the OpenClaw Hindsight plugin uses one token for the whole gateway, so every agent on a gateway shares its permissions. Separate agents by bank inside the own space:

```json
"agentBankMap": { "main": "agn-openclaw-main", "argus": "agn-openclaw-argus" }
```

An agent that needs different permissions needs its own runtime instance and key.

## Notes

- Background work (consolidation, scheduled refreshes) runs unrestricted, as in stock Hindsight. Consolidation follows a write the caller was already allowed to make.
- Bank aliases resolve to the canonical bank id before checks.
- A bank whose retain strategy has entity labels with `tag: true` can produce tags outside a `tag` identity's scope. Hindsight then refuses that identity's retains there.
- Keys never appear in the file, logs or `tenant_id`; the identity id does.

## Development

```bash
pip install -e '.[test]'
pytest
```

## License

MIT
