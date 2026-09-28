// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Live L7 egress proxy: allowlist + credential injection for FluxVm sandboxes.
//!
//! Plain HTTP requests are judged and forwarded. With
//! `sandbox.egress_tls_intercept` on, `CONNECT` tunnels are terminated with a
//! per-host certificate from the egress CA so the same method/host/path rules
//! apply to HTTPS; otherwise `CONNECT` is refused (see `docs/http-acl.md`).

use crate::egress::{EgressDecision, decide};
use crate::http_acl::{self, HttpAcl, Verdict};
use crate::tls_intercept::{FilteringResolver, TlsIntercept, is_public_ip};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderName, Method, Request, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::any,
};
use fluxvm_core::config::SandboxConfig;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_HEADER_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_TLS_PORT: u16 = 443;

#[derive(Clone)]
struct ProxyState {
    cfg: SandboxConfig,
    client: reqwest::Client,
    acl: HttpAcl,
    tls: Option<Arc<TlsState>>,
}

/// Everything the interception path needs; present only when enabled.
struct TlsState {
    intercept: TlsIntercept,
    /// Upstream client for intercepted traffic. Verifies server certificates
    /// (never disabled) and refuses non-public addresses unless allowed.
    client: reqwest::Client,
    ports: Vec<u16>,
    allow_private: bool,
}

/// Bind an HTTP forward proxy that enforces `sandbox.egress_allow_domains`
/// and `sandbox.egress_http_rules`, and injects `sandbox.credential_vault`
/// Authorization headers.
pub async fn serve(listen: SocketAddr, cfg: SandboxConfig) -> anyhow::Result<()> {
    let state = build_state(cfg)?;
    let listener = TcpListener::bind(listen).await?;
    run(listener, state).await
}

/// Like [`serve`], on an already bound listener (used by tests, port 0).
pub async fn serve_on(listener: TcpListener, cfg: SandboxConfig) -> anyhow::Result<()> {
    let state = build_state(cfg)?;
    run(listener, state).await
}

async fn run(listener: TcpListener, state: ProxyState) -> anyhow::Result<()> {
    let app = Router::new()
        .fallback(any(proxy))
        .with_state(Arc::new(state));
    info!(listen = ?listener.local_addr().ok(), "FluxVM egress proxy listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_state(cfg: SandboxConfig) -> anyhow::Result<ProxyState> {
    // A malformed rule must stop startup: silently dropping a `deny` fails open.
    let acl = HttpAcl::parse(&cfg.egress_http_rules).map_err(|e| anyhow::anyhow!(e))?;
    let tls = if cfg.egress_tls_intercept {
        Some(Arc::new(build_tls_state(&cfg)?))
    } else {
        None
    };
    Ok(ProxyState {
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        cfg,
        acl,
        tls,
    })
}

fn build_tls_state(cfg: &SandboxConfig) -> anyhow::Result<TlsState> {
    // Fail closed: if interception was asked for but the CA cannot be set up,
    // do not quietly run without it.
    let intercept = TlsIntercept::from_config(&cfg.egress_ca_cert, &cfg.egress_ca_key)?;
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .dns_resolver(Arc::new(FilteringResolver {
            allow_private: cfg.egress_tls_allow_private,
        }));
    for root in load_extra_roots(&cfg.egress_upstream_ca_file)? {
        builder = builder.add_root_certificate(root);
    }
    let ports = if cfg.egress_tls_ports.is_empty() {
        vec![DEFAULT_TLS_PORT]
    } else {
        cfg.egress_tls_ports.clone()
    };
    info!(
        ports = ?ports,
        "egress TLS interception enabled; guests must trust the egress CA certificate"
    );
    Ok(TlsState {
        intercept,
        client: builder.build()?,
        ports,
        allow_private: cfg.egress_tls_allow_private,
    })
}

/// Extra PEM roots for verifying upstream servers (a private CA). Adds trust;
/// it never turns verification off.
fn load_extra_roots(path: &str) -> anyhow::Result<Vec<reqwest::Certificate>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let pem = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("reading egress_upstream_ca_file {path}: {e}"))?;
    let mut out = Vec::new();
    for der in CertificateDer::pem_slice_iter(&pem) {
        let der = der.map_err(|e| anyhow::anyhow!("egress_upstream_ca_file {path}: {e}"))?;
        out.push(reqwest::Certificate::from_der(der.as_ref())?);
    }
    if out.is_empty() {
        anyhow::bail!("egress_upstream_ca_file {path} contains no certificates");
    }
    Ok(out)
}

/// What the proxy decided about one request, before any upstream I/O.
#[derive(Debug)]
struct Vetted {
    decision: EgressDecision,
    /// Upstream URL rebuilt from the vetted host and normalized path. Set
    /// only when HTTP rules are active, so the request that is sent is
    /// exactly the request that was judged.
    rebuilt_url: Option<String>,
}

fn deny(reason: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, reason.into())
}

/// Judge a request: host allowlist, HTTP rules, credential lookup.
fn vet_request(
    cfg: &SandboxConfig,
    acl: &HttpAcl,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Vetted, (StatusCode, String)> {
    let filtering = acl.is_active() || !cfg.egress_allow_domains.is_empty();
    let header_host = headers.get(header::HOST).and_then(|v| v.to_str().ok());

    // Legacy behaviour when nothing is filtered: the Host header, port stripped.
    let mut host = header_host
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();

    if filtering {
        // Ambiguity between what is judged and what is contacted is the way
        // around any host or path filter, so refuse it outright.
        if headers.get_all(header::HOST).iter().count() > 1 {
            return Err(deny("multiple Host headers"));
        }
        host = http_acl::effective_host(uri.host(), header_host).map_err(deny)?;
    }

    let decision = decide(cfg, &host);
    if !decision.allow {
        return Err(deny(decision.reason));
    }

    if !acl.is_active() {
        return Ok(Vetted {
            decision,
            rebuilt_url: None,
        });
    }

    if method == Method::CONNECT {
        return match acl.check_connect(&host) {
            Verdict::Allow => Err((
                StatusCode::NOT_IMPLEMENTED,
                "CONNECT tunnelling is not supported by the egress proxy".into(),
            )),
            Verdict::Deny(reason) => Err(deny(reason)),
        };
    }

    if let Verdict::Deny(reason) = acl.check(method.as_str(), &host, uri.path()) {
        return Err(deny(reason));
    }

    // Send the normalized path: the upstream must not interpret it any
    // differently from the rule engine.
    let path = http_acl::normalize_path(uri.path()).map_err(deny)?;
    let netloc = match uri.host() {
        Some(h) => match uri.port_u16() {
            Some(p) => format!("{h}:{p}"),
            None => h.to_string(),
        },
        None => header_host.unwrap_or_default().trim().to_string(),
    };
    let scheme = uri.scheme_str().unwrap_or("http");
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    Ok(Vetted {
        decision,
        rebuilt_url: Some(format!("{scheme}://{netloc}{path}{query}")),
    })
}

/// A `CONNECT` target that passed the pre-TLS checks.
#[derive(Debug, Clone)]
struct Tunnel {
    /// Canonical host (lower-case, no port; IPv6 keeps its brackets).
    host: String,
    /// `host:port` exactly as the upstream will be contacted.
    authority: String,
}

/// Judge a `CONNECT` before any TLS: host allowlist and ACL reachability,
/// destination port, and (unless allowed) non-public targets.
fn vet_connect(
    cfg: &SandboxConfig,
    acl: &HttpAcl,
    ports: &[u16],
    allow_private: bool,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Tunnel, (StatusCode, String)> {
    let authority = uri
        .authority()
        .ok_or_else(|| deny("CONNECT needs a host:port target"))?;
    if headers.get_all(header::HOST).iter().count() > 1 {
        return Err(deny("multiple Host headers"));
    }
    let header_host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let host = http_acl::effective_host(Some(authority.host()), header_host).map_err(deny)?;
    let port = authority.port_u16().unwrap_or(DEFAULT_TLS_PORT);
    if !ports.contains(&port) {
        return Err(deny(format!("CONNECT to port {port} is not permitted")));
    }
    let decision = decide(cfg, &host);
    if !decision.allow {
        return Err(deny(decision.reason));
    }
    if let Verdict::Deny(reason) = acl.check_intercepted_connect(&host) {
        return Err(deny(reason));
    }
    if !allow_private {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let internal_name = bare == "localhost" || bare.ends_with(".localhost");
        let internal_ip = bare.parse::<IpAddr>().is_ok_and(|ip| !is_public_ip(ip));
        if internal_name || internal_ip {
            return Err(deny(format!(
                "CONNECT to {host} refused: loopback/private targets are not allowed"
            )));
        }
    }
    Ok(Tunnel {
        authority: format!("{}:{port}", authority.host()),
        host,
    })
}

/// Judge one request read out of an intercepted tunnel. The Host header and
/// any absolute-form authority must name the tunnel's host (else a client
/// could steer the request at a host that was never vetted), and the request
/// then goes through the same checks as a plain-HTTP one. Returns the vetted
/// request and the `https://` URL to fetch.
fn vet_tunnel_request(
    cfg: &SandboxConfig,
    acl: &HttpAcl,
    tunnel: &Tunnel,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<(Vetted, String), (StatusCode, String)> {
    if method == Method::CONNECT {
        return Err(deny("nested CONNECT is not allowed"));
    }
    if is_upgrade(headers) {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "protocol upgrades (e.g. WebSocket) are not supported inside intercepted tunnels"
                .into(),
        ));
    }
    if headers.get_all(header::HOST).iter().count() > 1 {
        return Err(deny("multiple Host headers"));
    }
    if let Some(h) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        let host = http_acl::canon_host(h).map_err(deny)?;
        if host != tunnel.host {
            return Err(deny(format!(
                "Host {host:?} differs from the tunnel host {:?}",
                tunnel.host
            )));
        }
    }
    if let Some(a) = uri.authority() {
        let host = http_acl::canon_host(a.host()).map_err(deny)?;
        if host != tunnel.host {
            return Err(deny(format!(
                "request authority {host:?} differs from the tunnel host {:?}",
                tunnel.host
            )));
        }
    }
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    if !pq.starts_with('/') {
        return Err(deny("unsupported request target"));
    }
    let abs: Uri = format!("https://{}{pq}", tunnel.authority)
        .parse()
        .map_err(|_| deny("invalid request target"))?;
    // Credential lookup and the legacy host path read the Host header; make
    // sure one is present (it is already known to equal the tunnel host).
    let mut hdrs = headers.clone();
    if !hdrs.contains_key(header::HOST) {
        if let Ok(v) = tunnel.host.parse() {
            hdrs.insert(header::HOST, v);
        }
    }
    let vetted = vet_request(cfg, acl, method, &abs, &hdrs)?;
    let url = vetted
        .rebuilt_url
        .clone()
        .unwrap_or_else(|| abs.to_string());
    Ok((vetted, url))
}

fn is_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        || connection_tokens(headers)
            .iter()
            .any(|t| t.eq_ignore_ascii_case("upgrade"))
}

fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Connection-scoped headers a proxy must not forward (RFC 9110 §7.6.1),
/// plus anything the `Connection` header names.
fn is_hop_by_hop(name: &HeaderName, connection_tokens: &[String]) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || connection_tokens.iter().any(|t| t == name.as_str())
}

/// True when the request carries a body that must be forwarded.
fn has_body(headers: &HeaderMap) -> bool {
    headers.contains_key(header::TRANSFER_ENCODING)
        || headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim() != "0")
}

/// Send the vetted request upstream and stream the response back. Bodies are
/// streamed in both directions; hop-by-hop headers are dropped, the guest's
/// own `Authorization` never reaches the upstream, and the vault credential
/// (if any) is injected instead.
async fn forward(
    client: &reqwest::Client,
    method: Method,
    headers: &HeaderMap,
    body: Option<reqwest::Body>,
    url: String,
    inject_authorization: Option<String>,
) -> Response {
    let conn = connection_tokens(headers);
    let mut builder = client.request(method, &url);
    for (name, value) in headers.iter() {
        if name == header::HOST
            || name == header::AUTHORIZATION
            || name == header::EXPECT
            || is_hop_by_hop(name, &conn)
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    if let Some(auth) = &inject_authorization {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    if let Some(body) = body {
        builder = builder.body(body);
    }
    match builder.send().await {
        Ok(upstream) => {
            let status =
                StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let up_conn = connection_tokens(upstream.headers());
            let mut response = Response::builder().status(status);
            for (k, v) in upstream.headers().iter() {
                if !is_hop_by_hop(k, &up_conn) {
                    response = response.header(k, v);
                }
            }
            response
                .body(Body::from_stream(upstream.bytes_stream()))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e) => {
            warn!(error = %e, %url, "egress upstream failed");
            (StatusCode::BAD_GATEWAY, format!("upstream: {e}")).into_response()
        }
    }
}

fn count_denied(status: StatusCode, method: &Method, target: &dyn std::fmt::Display, reason: &str) {
    if status == StatusCode::FORBIDDEN {
        fluxvm_core::metrics::inc_egress_deny();
        warn!(%method, %target, %reason, "egress denied");
    }
}

async fn proxy(State(state): State<Arc<ProxyState>>, mut req: Request<Body>) -> Response {
    if req.method() == Method::CONNECT {
        if let Some(tls) = state.tls.clone() {
            return connect(state, tls, &mut req).await;
        }
    }
    let method = req.method().clone();
    let uri = req.uri().clone();
    let vetted = match vet_request(&state.cfg, &state.acl, &method, &uri, req.headers()) {
        Ok(v) => v,
        Err((status, reason)) => {
            count_denied(status, &method, &uri, &reason);
            return (status, reason).into_response();
        }
    };
    let decision = vetted.decision;
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // Absolute-form URI for forward proxy, or reconstruct from Host.
    let url = if let Some(u) = vetted.rebuilt_url {
        u
    } else if uri.scheme().is_some() {
        uri.to_string()
    } else {
        format!("http://{host}{path_and_query}")
    };

    let headers = req.headers().clone();
    let body =
        has_body(&headers).then(|| reqwest::Body::wrap_stream(req.into_body().into_data_stream()));
    forward(
        &state.client,
        method,
        &headers,
        body,
        url,
        decision.inject_authorization,
    )
    .await
}

/// Accept a vetted `CONNECT`: answer 200 and serve the tunnel in the
/// background once hyper hands over the upgraded connection.
async fn connect(state: Arc<ProxyState>, tls: Arc<TlsState>, req: &mut Request<Body>) -> Response {
    let tunnel = match vet_connect(
        &state.cfg,
        &state.acl,
        &tls.ports,
        tls.allow_private,
        req.uri(),
        req.headers(),
    ) {
        Ok(t) => t,
        Err((status, reason)) => {
            count_denied(status, &Method::CONNECT, req.uri(), &reason);
            return (status, reason).into_response();
        }
    };
    let on_upgrade = hyper::upgrade::on(&mut *req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Err(e) = serve_tunnel(state, tls, TokioIo::new(upgraded), tunnel).await {
                    debug!(error = %e, "intercepted tunnel ended");
                }
            }
            Err(e) => debug!(error = %e, "CONNECT upgrade failed"),
        }
    });
    Response::new(Body::empty())
}

/// Terminate TLS for one tunnel with a certificate for its host and serve the
/// decrypted HTTP/1.1 requests through the same ACL as plain HTTP.
async fn serve_tunnel<I>(
    state: Arc<ProxyState>,
    tls: Arc<TlsState>,
    io: I,
    tunnel: Tunnel,
) -> anyhow::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io);
    let start = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor).await??;

    // The certificate is minted for the CONNECT host, never for whatever name
    // the client puts in the ClientHello, and the two must agree. (IP
    // literals carry no SNI.)
    let is_ip = tunnel
        .host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok();
    if !is_ip {
        let sni = start
            .client_hello()
            .server_name()
            .map(|s| s.trim_end_matches('.').to_ascii_lowercase());
        if sni.as_deref() != Some(tunnel.host.as_str()) {
            anyhow::bail!(
                "TLS SNI {sni:?} does not match CONNECT host {}",
                tunnel.host
            );
        }
    }
    let server_cfg = tls
        .intercept
        .server_config_for(tunnel.host.trim_start_matches('[').trim_end_matches(']'))?;
    let stream =
        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, start.into_stream(server_cfg)).await??;

    let tunnel = Arc::new(tunnel);
    let service = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let tunnel = tunnel.clone();
        async move { Ok::<_, Infallible>(tunnel_request(state, tunnel, req).await) }
    });
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(TUNNEL_HEADER_TIMEOUT)
        .serve_connection(TokioIo::new(stream), service)
        .await?;
    Ok(())
}

async fn tunnel_request(
    state: Arc<ProxyState>,
    tunnel: Arc<Tunnel>,
    req: Request<Incoming>,
) -> Response {
    let Some(tls) = state.tls.as_ref() else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let (parts, body) = req.into_parts();
    let (vetted, url) = match vet_tunnel_request(
        &state.cfg,
        &state.acl,
        &tunnel,
        &parts.method,
        &parts.uri,
        &parts.headers,
    ) {
        Ok(v) => v,
        Err((status, reason)) => {
            count_denied(status, &parts.method, &parts.uri, &reason);
            return (status, reason).into_response();
        }
    };
    let body =
        has_body(&parts.headers).then(|| reqwest::Body::wrap_stream(body.into_data_stream()));
    forward(
        &tls.client,
        parts.method,
        &parts.headers,
        body,
        url,
        vetted.decision.inject_authorization,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(rules: &[&str], domains: &[&str]) -> (SandboxConfig, HttpAcl) {
        let cfg = SandboxConfig {
            egress_allow_domains: domains.iter().map(|s| s.to_string()).collect(),
            egress_http_rules: rules.iter().map(|s| s.to_string()).collect(),
            ..SandboxConfig::default()
        };
        let acl = HttpAcl::parse(&cfg.egress_http_rules).unwrap();
        (cfg, acl)
    }

    fn headers(hosts: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for host in hosts {
            h.append(header::HOST, host.parse().unwrap());
        }
        h
    }

    fn vet(
        c: &(SandboxConfig, HttpAcl),
        method: &str,
        uri: &str,
        hosts: &[&str],
    ) -> Result<Vetted, (StatusCode, String)> {
        vet_request(
            &c.0,
            &c.1,
            &method.parse().unwrap(),
            &uri.parse().unwrap(),
            &headers(hosts),
        )
    }

    #[test]
    fn no_rules_keeps_legacy_behaviour() {
        let c = cfg(&[], &[]);
        let v = vet(&c, "GET", "/anything", &["whatever.example:8080"]).unwrap();
        assert!(v.rebuilt_url.is_none());
        // Legacy: even a mismatched absolute URI is not judged when nothing is filtered.
        assert!(vet(&c, "GET", "http://a.example/x", &["b.example"]).is_ok());
    }

    #[test]
    fn rules_allow_and_deny_by_method_host_path() {
        let c = cfg(
            &[
                "allow GET docs.python.org/*",
                "allow POST api.openai.com/v1/chat/completions",
                "deny * */admin/*",
            ],
            &[],
        );
        assert!(vet(&c, "GET", "/3/library/os.html", &["docs.python.org"]).is_ok());
        assert!(vet(&c, "POST", "/v1/chat/completions", &["api.openai.com"]).is_ok());
        for (m, u, h) in [
            ("POST", "/3/", "docs.python.org"),
            ("GET", "/v1/chat/completions", "api.openai.com"),
            ("GET", "/x", "evil.example"),
            ("GET", "/admin/x", "docs.python.org"),
            ("GET", "/a/../admin/x", "docs.python.org"),
            ("GET", "/%61dmin/x", "docs.python.org"),
            ("GET", "//admin/x", "docs.python.org"),
        ] {
            let e = vet(&c, m, u, &[h]).unwrap_err();
            assert_eq!(e.0, StatusCode::FORBIDDEN, "{m} {u} {h}");
        }
    }

    #[test]
    fn host_and_uri_authority_must_agree() {
        let c = cfg(&["allow GET good.example/*"], &[]);
        let e = vet(&c, "GET", "http://evil.example/x", &["good.example"]).unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        assert!(vet(&c, "GET", "http://good.example/x", &["good.example"]).is_ok());
        assert!(
            vet(
                &c,
                "GET",
                "http://good.example:8080/x",
                &["good.example:8080"]
            )
            .is_ok()
        );
    }

    #[test]
    fn host_mismatch_is_also_refused_for_the_plain_domain_allowlist() {
        // Previously the allowlist judged the Host header while the request
        // went to the absolute-form authority.
        let c = cfg(&[], &["good.example"]);
        let e = vet(&c, "GET", "http://evil.example/x", &["good.example"]).unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn duplicate_host_headers_are_refused() {
        let c = cfg(&["allow GET good.example/*"], &[]);
        let e = vet(&c, "GET", "/x", &["good.example", "evil.example"]).unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn forwarded_url_uses_the_normalized_path_and_keeps_port_and_query() {
        let c = cfg(&["allow GET good.example/*"], &[]);
        let v = vet(&c, "GET", "/a/./b//c?x=1&y=/../z", &["good.example:8080"]).unwrap();
        assert_eq!(
            v.rebuilt_url.as_deref(),
            Some("http://good.example:8080/a/b/c?x=1&y=/../z")
        );
        let v = vet(
            &c,
            "GET",
            "http://good.example:9/%61/x",
            &["good.example:9"],
        )
        .unwrap();
        assert_eq!(v.rebuilt_url.as_deref(), Some("http://good.example:9/a/x"));
    }

    #[test]
    fn connect_is_refused_or_unsupported_never_forwarded() {
        let c = cfg(&["allow GET docs.python.org/*"], &[]);
        let e = vet(
            &c,
            "CONNECT",
            "docs.python.org:443",
            &["docs.python.org:443"],
        )
        .unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        let c = cfg(&["allow * api.example.com"], &[]);
        let e = vet(
            &c,
            "CONNECT",
            "api.example.com:443",
            &["api.example.com:443"],
        )
        .unwrap_err();
        assert_eq!(e.0, StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn credentials_are_looked_up_on_the_vetted_host() {
        let mut c = cfg(&["allow * vault.example/*"], &[]);
        c.0.credential_vault
            .push(fluxvm_core::config::CredentialInject {
                host: "vault.example".into(),
                authorization: "Bearer t".into(),
            });
        let v = vet(&c, "GET", "/x", &["VAULT.example:443"]).unwrap();
        assert_eq!(v.decision.inject_authorization.as_deref(), Some("Bearer t"));
    }

    #[test]
    fn options_star_is_denied_when_rules_are_active() {
        let c = cfg(&["allow * good.example/*"], &[]);
        let e = vet(&c, "OPTIONS", "*", &["good.example"]).unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
    }
}
