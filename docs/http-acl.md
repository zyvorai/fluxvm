# HTTP method / host / path ACL for the egress proxy

The live L7 egress proxy (`sandbox.egress_proxy_listen`) can enforce rules on
the HTTP method, host and path of each request, on top of the existing
`egress_allow_domains` host allowlist and credential injection.

```toml
[sandbox]
egress_proxy_listen = "127.0.0.1:18080"
egress_http_rules = [
  "allow GET docs.python.org/*",
  "allow POST api.openai.com/v1/chat/completions",
  "deny * */admin/*",
]
```

## Rule grammar

```
<allow|deny> <METHOD|*> <host-glob>[/<path-glob>]
```

* `*` in a host or path glob matches any run of characters, **including `/`**
  and the empty string. Everything else is literal.
* Method and host compare case-insensitively. Paths are case-sensitive.
* Paths are matched **without the query string**.
* An omitted path glob matches any path.
* A path glob must be a literal decoded path: `%`, `?`, `#`, backslash, `//`
  and `.`/`..` segments are rejected at load time, because such a glob could
  never equal a normalized request path (a `deny` that never matches fails
  open). Any malformed rule stops the proxy from starting.

## Semantics

1. No rules: the ACL is off and behaviour is unchanged.
2. A matching `deny` always wins.
3. If any `allow` rule exists, a request must match one, otherwise it is
   denied (default deny). With only `deny` rules, everything else is allowed.
4. Denials return `403` with the reason and count in the egress-deny metric.

`deny * */admin/*` does **not** match the bare path `/admin`. Add
`deny * */admin` as well to cover both.

## Evasion resistance

Before matching, the path is normalized so the rule engine sees what the
upstream will:

| Input | Matched as |
|---|---|
| `/a/../admin` | `/admin` |
| `/./admin`, `//admin`, `/admin//x` | `/admin`, `/admin`, `/admin/x` |
| `/%61dmin`, `/%2e%2e/`, `/.%2E/` | unreserved escapes decoded: `/admin`, `..` |
| `/admin/.` | `/admin/` |
| `/../../admin` | `/admin` (`..` is clamped at the root) |

Other percent-escapes are kept, with upper-case hex (`%3b` becomes `%3B`).
With the ACL active the proxy **forwards the normalized path**, so the request
that is sent is the request that was judged.

Requests that cannot be interpreted unambiguously are denied rather than
guessed at: a malformed `%` escape, `%00`, an encoded slash (`%2F`) or
backslash (`%5C`), a raw backslash, control or non-ASCII bytes, and a path not
starting with `/` (for example `OPTIONS *`). A `;` in a path is not treated
specially, so a backend that gives `;param` meaning should be fronted with an
explicit rule.

### Host handling

The host is taken from the absolute-form request URI when present, otherwise
from the `Host` header. It is canonicalized (lower-case, port and trailing dot
stripped). A request is **denied** if the URI authority and `Host` header
disagree, if there is more than one `Host` header, or if the host contains
userinfo, slashes or whitespace. The same host is used for the domain
allowlist and for credential lookup. The URL forwarded upstream is rebuilt from
the vetted host and path rather than re-parsed from the raw request line.

This also closes an older gap where the domain allowlist judged the `Host`
header while an absolute-form request line decided where the proxy connected.
That check applies whenever a host allowlist or HTTP rules are configured.

## HTTPS and `CONNECT`

Inside a `CONNECT` tunnel the method and path are encrypted, so **path and
method rules cannot be enforced for HTTPS without terminating TLS**. This
proxy does not do MITM, and it does not implement `CONNECT` at all. When rules
are active a `CONNECT` is only ever refused (`403`) or answered `501`:

* refused if any `deny` rule matches the host, because it could not be
  enforced inside the tunnel;
* refused unless an `allow` rule with method `*` (or `CONNECT`) and any path
  covers the host, because allowing the tunnel would allow every method and
  path;
* otherwise `501 Not Implemented`.

Rules therefore apply to plain-HTTP requests and to anything the proxy
terminates itself. To restrict HTTPS by method or path, terminate TLS at a
proxy you control (a future MITM mode) or restrict by host.
