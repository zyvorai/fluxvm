# Credential broker

Per-sandbox credential grants. A grant lets one sandbox's outbound HTTP(S) traffic carry a secret
`Authorization` header to specific destination hosts for a limited time. The guest never sees the
secret: the egress proxy injects it into the request after vetting it.

## Roadmap and status

| Item | Implemented and type-checked | Verified on hardware |
|---|---|---|
| Grant store (in memory), host matching, TTL and count limits | yes (unit tests pass) | not yet |
| `POST/GET/DELETE /v1/sandboxes/{id}/grants` | yes | not yet |
| Injection in the egress proxy (CONNECT, TLS intercept, transparent HTTP/TLS) | yes | not yet |
| `credential.grant`, `credential.revoke`, `credential.use` audit events | yes | not yet |
| Secrets never serialized or printed (including `/v1/egress/check`) | yes (unit test) | n/a |
| Global `credential_vault` fallback | yes (unchanged behavior) | not yet |

Nothing in this batch has been run end-to-end on real VMs. In particular, no real request has been
observed carrying an injected header yet.

## Creating a grant

```bash
export FLUXVM_SECRET_GITHUB_TOKEN='Bearer ghp_...'   # in the daemon's environment

curl -sS http://127.0.0.1:7788/v1/sandboxes/$SB/grants \
  -H 'content-type: application/json' \
  -d '{"secret_ref":"github-token","hosts":["api.github.com"],"ttl_seconds":900}'
```

```json
{
  "id": "7e0f0c52-5d57-4b35-8d3f-6a1a3d2b9c10",
  "sandbox_id": "0c1d2e3f-0000-4000-8000-000000000001",
  "secret_ref": "github-token",
  "hosts": ["api.github.com"],
  "created_at": "2026-10-08T12:00:00Z",
  "expires_at": "2026-10-08T12:15:00Z",
  "bound": true
}
```

Request fields:

| Field | Meaning |
|---|---|
| `secret_ref` | Required, 1-128 characters. A label for the secret, and the source of its value when `value` is omitted |
| `value` | Optional, write-only. The full header value to inject, for example `Bearer abc`. Never returned or logged |
| `hosts` | Required, at least one. Bare host names |
| `ttl_seconds` | 1 to 86400. Default 3600 (1 hour) |
| `expires_at` | RFC 3339 alternative to `ttl_seconds`; wins if both are sent. Must be in the future and at most 24 hours away |

**Secret source.** If `value` is present it is used. Otherwise the daemon reads the environment
variable `FLUXVM_SECRET_<REF>`, where `<REF>` is `secret_ref` upper-cased with every non-alphanumeric
character replaced by `_`: `github-token` becomes `FLUXVM_SECRET_GITHUB_TOKEN`. If neither exists (or
the variable is empty) the request fails with 400, naming the variable it looked for. Prefer the
environment form: the secret then never crosses the API.

**Hosts.** Matching is case-insensitive, on the request's Host or SNI, and either an exact match or a
domain suffix on a label boundary: `github.com` matches `github.com` and `api.github.com`, and does
not match `evilgithub.com` or `github.com.evil.io`. A leading `.` is ignored. Patterns containing `*`,
`/`, `:`, `@`, `?` or whitespace are rejected (400).

**Limits.** At most 32 live grants per sandbox (expired ones are dropped first; beyond that, 400:
"revoke one first"). Maximum lifetime 24 hours.

Listing and revoking:

```bash
curl -sS http://127.0.0.1:7788/v1/sandboxes/$SB/grants                       # {"grants": [...]}
curl -sS -X DELETE http://127.0.0.1:7788/v1/sandboxes/$SB/grants/$GRANT_ID   # {"revoked": true} or 404
curl -sS -X DELETE http://127.0.0.1:7788/v1/sandboxes/$SB/grants             # {"revoked": true|false}
```

All four verbs are admin-only, including `GET`: a read-only token must not learn which secrets a
sandbox may use. `GrantInfo` has no secret field at all.

## How a request is matched

1. The egress proxy knows the guest address a connection came from.
2. That address maps to a sandbox. The mapping is recorded when the grant is created, from the
   sandbox's `guest_ip`.
3. A live grant of that sandbox whose `hosts` cover the destination wins, and its value is injected
   as the `Authorization` header.
4. If no grant matches, the global `[sandbox] credential_vault` decision applies as before.

**`guest_ip` requirement and fail-closed matching.** A sandbox with no known guest IP gets a grant with
`bound: false`. Such a grant can never match any traffic, so it injects nothing. Traffic from an
unknown source address, a different sandbox, an expired grant, or a non-matching host also gets
nothing from the broker. There is no wildcard source. Because the binding is taken when the grant is
created, re-create the grant if the sandbox's address changes (for example after a restart that
assigns a new IP).

The egress allow-list and L7 rules are evaluated as before; a grant only changes which value is injected
and does not widen what the proxy allows.

## Lifetime

Grants live **only in daemon memory**. They are not persisted, so:

- A daemon restart drops every grant. Callers must re-grant.
- Deleting a sandbox drops its grants.
- Expired grants stop matching immediately and are no longer listed.

## Audit events

| Event | Fields |
|---|---|
| `credential.grant` | `sandbox_id`, `grant_id`, `secret_ref`, `hosts`, `expires_at` |
| `credential.revoke` | `sandbox_id`, `grant_id` (`all` for a bulk revoke); only emitted when something was revoked |
| `credential.use` | `sandbox_id`, `grant_id`, `secret_ref`, `destination`; one per injected request |

No audit field, log line or API response contains the secret value. The secret type refuses to print
(`Debug` is `Secret([redacted])`) and refuses to serialize. If no audit sink has been registered, the
records go to stderr as `fluxvm_audit ...`.

The same protection now covers the global vault: `POST /v1/egress/check` no longer returns the
`inject_authorization` value, and `Debug` output of the config shows `[redacted]`.

## Fallback to the global vault

`[sandbox] credential_vault` entries keep working, unchanged, for traffic with no matching grant. A
vault entry applies to every sandbox for its host; a grant applies to one sandbox. When both match, the
grant wins.

## Migration advice

1. Leave the global vault in place and add grants for the sandboxes that need a credential. Check for
   `credential.use` events to confirm the grants are being used.
2. Move each secret out of the config file into the daemon's environment as `FLUXVM_SECRET_<REF>`
   (for example from a systemd `EnvironmentFile` with `0600` permissions), and reference it by
   `secret_ref`.
3. Have the orchestrator create grants when it starts a sandbox, with a TTL no longer than the task,
   and re-create them after a daemon restart (list grants to see what is live).
4. Once no sandbox depends on a vault entry, remove it from `credential_vault`, so a sandbox without a
   grant cannot receive that credential at all.
5. Keep grants narrow: the exact host (not a broad suffix) and the shortest TTL that works.
