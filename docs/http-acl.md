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

What `deny * */admin/*` covers. The rule is host glob `*`, path glob
`/admin/*`; a trailing `/*` also matches the directory itself:

| Request path | Denied? |
|---|---|
| `/admin`, `/admin/` | yes (the directory itself) |
| `/admin/x`, `/admin/x/y` | yes |
| `/a/../admin`, `//admin`, `/%61dmin` | yes (normalized to `/admin` first) |
| `/administrator`, `/superadmin` | no (different segment) |
| `/x/admin/y` | no (the path glob starts at `/admin`; add `deny * */*/admin/*` to cover nested ones) |

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
   `Authorization`. Request and response bodies are streamed (with the
   [size cap](#body-size-cap)), hop-by-hop headers are dropped, and the
   guest's own `Authorization` header is never forwarded.

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

#### HTTP/2

Intercepted connections speak whichever protocol the client negotiates via ALPN:
`h2` or `http/1.1`. Every HTTP/2 stream is judged on its own with the same
rules, normalization and vault as HTTP/1.1, and the request's `:authority`
must name the tunnel host (otherwise `403`, so an `h2` client cannot use one
tunnel to reach another host). The upstream leg negotiates `h2` or `http/1.1`
by ALPN too, with certificate verification still on. HTTP/1.1 and HTTP/2
clients can use the proxy at the same time.

#### Body size cap

`egress_max_body_bytes` (default 1 GiB, `0` = unlimited) bounds every request
and response body the proxy streams, over plain HTTP and intercepted HTTPS:

* a request whose `Content-Length` exceeds the cap gets `413` before it is
  forwarded; a chunked request that grows past it is cut off and answered
  `413`;
* a response whose `Content-Length` exceeds the cap becomes `502`; a streamed
  response that grows past it is aborted mid-stream so the client sees a
  failed transfer instead of silently truncated data.

#### Transparent mode

Clients that do not know about the proxy (no `HTTPS_PROXY`) can be redirected
to it:

```toml
[sandbox]
egress_tls_intercept = true
egress_transparent_listen = "0.0.0.0:18889"   # empty = off
```

The listener accepts redirected connections, works out what they are from the
first bytes, and recovers the address the client dialed with `SO_ORIGINAL_DST`:

* **TLS** (a ClientHello): the SNI is required and names the host; there is no
  `CONNECT`, so the checks that `CONNECT` gets run first, against the SNI host
  and the dialed port (`egress_tls_ports`, the allowlist, no rule that could
  never allow the host, private/metadata refusal). A ClientHello without SNI is
  dropped. The proxy then terminates TLS as above (h2 or http/1.1) and reaches
  the upstream by the **name** (SNI), never by the IP the client dialed, so a
  client cannot pair an allowed name with another address.
* **Plain HTTP**: judged by its `Host` header exactly like a proxied request,
  and forwarded to that host on the dialed port.

The redirect itself is an nftables rule that must live inside the guest's
network namespace. `fluxvm_network::transparent_redirect` builds it (table
`inet fluxvm_egress_tp`, a `prerouting` `redirect` restricted to one interface
and a port list) and applies or removes it only through
`ip netns exec <namespace> nft`; it refuses to act without a namespace name,
never touches the host's default namespace, and validates every name it
interpolates. This is separate from the older host-output redirect in
`egress.rs`, which is unchanged.

```bash
cargo run -p fluxvm-network --example egress_proxy_ns -- snippet fvegress fvtap0 80,443 18889
```

#### Limits

* **Certificate pinning fails**: clients that pin the upstream certificate or
  key will reject the minted leaf. Do not intercept those hosts (leave them
  off the allowlist, or do not route them through the proxy).
* **No WebSockets or other upgrades** inside a tunnel (`501`).
* Transparent mode covers TCP ports you redirect (TLS and plain HTTP only);
  other protocols on those ports are dropped. Making sure guests cannot bypass
  the proxy at all is the dataplane's job.
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

## Verified with real traffic (2026-09-29)

`scripts/test-egress-guest.sh` (opt-in, root, lab) builds two throwaway network
namespaces, a stand-alone proxy (`crates/fluxvm-network/examples/egress_proxy_ns.rs`),
an HTTPS+HTTP upstream with a private CA and the nft redirect, and runs a fixed
set of cases:

* **Stage 1 - a real `curl` in a second namespace over a veth** (20 checks, all
  passing): explicit proxy allow/deny by method and path, the bypass forms
  `/a/../admin`, `/%61dmin` and `//admin`, a `CONNECT` to an unlisted host,
  `curl --http2` negotiating h2 with the proxy (both explicit and transparent),
  transparent HTTPS and plain HTTP with no proxy settings in the client (a real
  nft `redirect` and `SO_ORIGINAL_DST`), and an upstream log proving no denied
  request ever reached it.
* **Stage 2 - the golden native-KVM guest** (19 checks, all passing): boots,
  the agent answers over vsock, cloud-init's `ca_certs` installs the proxy CA
  and the guest's `openssl verify` accepts it, the guest's curl 7.58 has
  HTTP/2, it gets a real DHCP lease and resolves `up.test` via dnsmasq, and
  then runs the same explicit-proxy and transparent-redirect cases as stage 1
  over the guest agent. The in-tree KVM virtio-net now has a receive path
  (tap -> guest RX queue 0, see [native-kvm-no-qemu.md](native-kvm-no-qemu.md));
  vhost-net still cannot bind before the guest programs its vrings
  (`VHOST_NET_SET_BACKEND` returns `EFAULT`), so this runs over the userspace
  pump, which now falls back cleanly with one log line instead of leaving the
  device half set up.

The script asserts afterwards that `ip netns list` and `nft list ruleset`
(counters stripped) are identical to before, that `/etc/netns/<ns>` files are
gone, and that no dnsmasq, hypervisor, proxy or upstream of the run is left.
