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

A trailing `/*` in a path glob also matches the directory itself, so
`deny * */admin/*` (host `*`, path `/admin/*`) covers `/admin`, `/admin/` and
everything below `/admin/`. It does not cover `/administrator`, `/superadmin`
or `/x/admin/y`: the first `*` is the host glob, and the path glob starts at
`/admin`.

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

Inside a `CONNECT` tunnel the method and path are encrypted, so by default
**path and method rules cannot be enforced for HTTPS**. With interception off
(the default) the proxy does not implement `CONNECT`: when rules are active a
`CONNECT` is only ever refused (`403`) or answered `501`:

* refused if any `deny` rule matches the host, because it could not be
  enforced inside the tunnel;
* refused unless an `allow` rule with method `*` (or `CONNECT`) and any path
  covers the host, because allowing the tunnel would allow every method and
  path;
* otherwise `501 Not Implemented`.

### TLS interception (opt-in)

Turn on interception and the same rules, normalization, host checks and
credential injection apply to HTTPS:

```toml
[sandbox]
egress_proxy_listen = "127.0.0.1:18080"
egress_tls_intercept = true
egress_ca_cert = "/var/lib/fluxvm/egress-ca.crt"   # default shown
egress_ca_key  = "/var/lib/fluxvm/egress-ca.key"   # default shown, mode 0600
egress_tls_ports = [443]            # destination ports a CONNECT may use
egress_tls_allow_private = false    # keep false (see below)
egress_upstream_ca_file = ""        # extra roots to verify upstreams (private CA)
egress_http_rules = ["allow GET api.example.com/v1/*", "deny * */admin/*"]
```

How a request flows:

1. The guest sends `CONNECT host:443` to the proxy.
2. **Before any TLS**, the proxy refuses (`403`) a host outside
   `egress_allow_domains`, a destination port not in `egress_tls_ports`, a
   host no rule could ever allow (a whole-host `deny`, or `allow` rules that
   never name it), and, unless `egress_tls_allow_private` is set, loopback,
   private, link-local (including the `169.254.169.254` metadata address),
   CGNAT, multicast and unspecified targets, plus `localhost` names.
3. It answers `200` and terminates TLS with a leaf certificate minted for the
   CONNECT host and signed by the egress CA. The ClientHello SNI must equal
   the CONNECT host, otherwise the connection is dropped. Only `http/1.1` is
   offered via ALPN.
4. Each decrypted request goes through the same checks as plain HTTP. The
   `Host` header (and any absolute-form authority) must name the tunnel host;
   `Upgrade`/WebSocket requests get `501`; a nested `CONNECT` is denied.
5. The proxy fetches `https://host:port<normalized path>` itself with
   **certificate verification on** (it never disables it), a resolver that
   refuses non-public addresses (unless allowed), and injects the vault
   `Authorization`. Request and response bodies are streamed, hop-by-hop
   headers are dropped, and the guest's own `Authorization` header is never
   forwarded.

#### Trusting the CA in the guest

The CA is created on first start if neither file exists (a lone certificate or
lone key is an error, so a half-replaced CA can never silently invalidate what
guests trust). The private key stays on the host at mode 0600 and is never
logged. Guests must trust `egress_ca_cert`:

```bash
# Debian / Ubuntu guest
install -m 0644 egress-ca.crt /usr/local/share/ca-certificates/fluxvm-egress-ca.crt
update-ca-certificates
# RHEL / Fedora guest
install -m 0644 egress-ca.crt /etc/pki/ca-trust/source/anchors/ && update-ca-trust
```

Language runtimes with their own trust store need it too, for example
`REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, or the JVM
truststore. The intercepting CA can mint a certificate for any host, so treat
the key like a root secret and give each deployment its own CA.

#### Limits

* **HTTP/1.1 only.** HTTP/2 is not intercepted (ALPN advertises `http/1.1`),
  and upstream requests are HTTP/1.1.
* **Certificate pinning fails**: clients that pin the upstream certificate or
  key will reject the minted leaf. Do not intercept those hosts (leave them
  off the allowlist, or do not route them through the proxy).
* **No WebSockets or other upgrades** inside a tunnel (`501`).
* **Explicit proxy only.** Clients must be configured to use the proxy
  (`HTTPS_PROXY`), which makes them send `CONNECT`. Transparent interception
  of raw TLS redirected to the proxy port (for example the `redirect to`
  nftables snippet in `egress.rs`) is not implemented: the proxy speaks HTTP,
  so a bare ClientHello is not understood. Making sure guests cannot bypass
  the proxy is the dataplane's job.
* Bodies are streamed with no size cap; apply limits at the dataplane if
  needed.
* The leaf-certificate cache holds at most 256 hosts.
* Rules cannot see inside a tunnel that is not intercepted; keep
  `egress_tls_intercept` on for any sandbox that relies on path or method
  rules for HTTPS.

## Verified live (2026-09-28)

Against a running daemon with `egress_http_rules`, `egress_tls_intercept` and a
credential-vault entry, using `curl` through the proxy to local HTTP and HTTPS
upstreams: allowed `GET`/`POST` reached the upstream; a request with no
matching allow rule, a `deny` match, a wrong method, `/ok/../admin/x`,
`/%61dmin/x` and `//admin/x` all got 403 (HTTP and HTTPS); the vault
`Authorization` replaced the guest-supplied one; an intercepted CONNECT to a
port outside `egress_tls_ports` and a client that did not trust the proxy CA
both failed. Note that when the daemon runs as root and `egress_proxy_listen`
is set, it also installs the nftables redirect for ports 80/443.
