---
name: fluxvm-egress-acl
description: Write and review egress proxy rules (method, host, path) for FluxVM sandboxes. Use when asked to allow or block HTTP calls from a sandbox, or to check a rule set for gaps.
---

# Egress HTTP ACL

Reference: `docs/http-acl.md`.

```toml
[sandbox]
egress_proxy_listen = "127.0.0.1:18080"
egress_http_rules = [
  "allow GET docs.python.org/*",
  "allow POST api.openai.com/v1/chat/completions",
  "deny * */admin/*",
]
```

## Grammar and semantics

- Rule: `<allow|deny> <METHOD|*> <host-glob>[/<path-glob>]`. `*` matches any run of characters, including `/`.
- A matching `deny` always wins.
- If any `allow` rule exists, everything not matched is denied. With only `deny` rules, everything else is allowed.
- Paths match without the query string and are normalized first (`/a/../admin` is `/admin`).
- A path glob must be a literal decoded path: `%`, `?`, `#`, backslash, `//`, `.` and `..` segments are rejected, and a malformed rule stops the proxy from starting.
- HTTPS is only judged with the opt-in `egress_tls_intercept` (HTTP/1.1, explicit-proxy clients).

## When reviewing rules

- `deny * */admin/*` does not cover `/x/admin/y`; add `deny * */*/admin/*` if nested paths matter.
- A rule set with only `deny` lines is default-allow. Say so.
- Prefer one narrow `allow` per host and method over `allow * host/*`.
