// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Live L7 egress proxy: allowlist + credential injection for FluxVm sandboxes.
//!
//! Plain HTTP requests are judged and forwarded. With
//! `sandbox.egress_tls_intercept` on, `CONNECT` tunnels are terminated with a
//! per-host certificate from the egress CA so the same method/host/path rules
//! apply to HTTPS; otherwise `CONNECT` is refused (see `docs/http-acl.md`).
//! Intercepted tunnels speak HTTP/1.1 or HTTP/2 (negotiated with ALPN), and
//! `sandbox.egress_transparent_listen` accepts redirected guest traffic with no
//! proxy settings (see the `transparent` submodule).

mod transparent;

use crate::egress::{EgressDecision, decide};
use crate::http_acl::{self, HttpAcl, Verdict};
use crate::tls_intercept::{FilteringResolver, TlsIntercept, is_public_ip};
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderName, Method, Request, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::any,
};
use fluxvm_core::config::SandboxConfig;
use futures_util::{Stream, StreamExt, TryStreamExt};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Upstream client for transparent-mode plain HTTP: refuses non-public
    /// addresses unless `egress_tls_allow_private`, like the intercepted path.
    transparent_client: reqwest::Client,
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
    let state = Arc::new(build_state(cfg)?);
    let listener = TcpListener::bind(listen).await?;
    if !state.cfg.egress_transparent_listen.is_empty() {
        let addr: SocketAddr = state.cfg.egress_transparent_listen.parse().map_err(|e| {
            anyhow::anyhow!(
                "egress_transparent_listen {:?}: {e}",
                state.cfg.egress_transparent_listen
            )
        })?;
        let transparent = TcpListener::bind(addr).await?;
        info!(listen = %addr, "FluxVM egress transparent listener");
        let state = state.clone();
        tokio::spawn(transparent::run(
            transparent,
            state,
            transparent::Dst::Original,
        ));
    }
    run(listener, state).await
}

/// Like [`serve`], on an already bound listener (used by tests, port 0).
pub async fn serve_on(listener: TcpListener, cfg: SandboxConfig) -> anyhow::Result<()> {
    let state = Arc::new(build_state(cfg)?);
    run(listener, state).await
}

/// Run only the transparent-mode listener on `listener`, treating every
/// connection as if it had been redirected from `fixed_dst` (tests: there is
/// no nftables redirect to recover the original destination from).
#[doc(hidden)]
pub async fn serve_transparent_on(
    listener: TcpListener,
    cfg: SandboxConfig,
    fixed_dst: SocketAddr,
) -> anyhow::Result<()> {
    let state = Arc::new(build_state(cfg)?);
    transparent::run(listener, state, transparent::Dst::Fixed(fixed_dst)).await;
    Ok(())
}

async fn run(listener: TcpListener, state: Arc<ProxyState>) -> anyhow::Result<()> {
    let app = Router::new().fallback(any(proxy)).with_state(state);
    info!(listen = ?listener.local_addr().ok(), "FluxVM egress proxy listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn build_state(cfg: SandboxConfig) -> anyhow::Result<ProxyState> {
    // A malformed rule must stop startup: silently dropping a `deny` fails open.
    let acl = HttpAcl::parse(&cfg.egress_http_rules).map_err(|e| anyhow::anyhow!(e))?;
    // Advisory only: a rule set that parses is loaded as written.
    for f in acl.lint() {
        match f.severity {
            crate::http_acl::LintSeverity::Info => {
                info!(code = f.code, "egress_http_rules: {}", f.message)
            }
            _ => warn!(code = f.code, "egress_http_rules: {}", f.message),
        }
    }
    let tls = if cfg.egress_tls_intercept {
        Some(Arc::new(build_tls_state(&cfg)?))
    } else {
        None
    };
    let transparent_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(FilteringResolver {
            allow_private: cfg.egress_tls_allow_private,
        }))
        .build()?;
    Ok(ProxyState {
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        cfg,
        acl,
        tls,
        transparent_client,
    })
}

fn build_tls_state(cfg: &SandboxConfig) -> anyhow::Result<TlsState> {
    // Fail closed: if interception was asked for but the CA cannot be set up,
    // do not quietly run without it.
    let intercept = TlsIntercept::from_config(&cfg.egress_ca_cert, &cfg.egress_ca_key)?;
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
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
    /// Guest address the tunnel came from, when known (credential grants).
    peer: Option<IpAddr>,
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
    vet_target(cfg, acl, ports, allow_private, host, authority.host(), port)
}

/// The checks shared by `CONNECT` and transparent TLS, once the target host
/// (`host`, canonical) and port are known: destination port, host allowlist and
/// ACL reachability, and (unless allowed) non-public targets. `authority_host`
/// is the host exactly as the upstream will be contacted.
fn vet_target(
    cfg: &SandboxConfig,
    acl: &HttpAcl,
    ports: &[u16],
    allow_private: bool,
    host: String,
    authority_host: &str,
    port: u16,
) -> Result<Tunnel, (StatusCode, String)> {
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
    if !allow_private && is_internal_target(&host) {
        return Err(deny(format!(
            "CONNECT to {host} refused: loopback/private targets are not allowed"
        )));
    }
    Ok(Tunnel {
        authority: format!("{authority_host}:{port}"),
        host,
        peer: None,
    })
}

/// A loopback/private literal or a `*.localhost` name.
fn is_internal_target(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let internal_name = bare == "localhost" || bare.ends_with(".localhost");
    let internal_ip = bare.parse::<IpAddr>().is_ok_and(|ip| !is_public_ip(ip));
    internal_name || internal_ip
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

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A request body as it arrives from the guest, before the size cap.
type RequestBody = Pin<Box<dyn Stream<Item = Result<Bytes, BoxError>> + Send>>;

#[derive(Debug)]
struct BodyTooLarge(u64);

impl std::fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "body exceeds egress_max_body_bytes ({})", self.0)
    }
}

impl std::error::Error for BodyTooLarge {}

/// Count bytes as they stream past and fail once `max` (non-zero) is exceeded,
/// setting `tripped` so the caller can tell a cap from an upstream failure.
fn capped<S, E>(
    stream: S,
    max: u64,
    tripped: Arc<AtomicBool>,
) -> impl Stream<Item = Result<Bytes, BoxError>>
where
    S: Stream<Item = Result<Bytes, E>>,
    E: Into<BoxError>,
{
    let mut seen = 0u64;
    stream.map(move |item| match item {
        Ok(chunk) => {
            seen = seen.saturating_add(chunk.len() as u64);
            if max != 0 && seen > max {
                tripped.store(true, Ordering::SeqCst);
                Err(Box::new(BodyTooLarge(max)) as BoxError)
            } else {
                Ok(chunk)
            }
        }
        Err(e) => Err(e.into()),
    })
}

/// Box the guest's request body stream for [`forward`].
fn request_body<B>(body: B) -> RequestBody
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    Box::pin(
        http_body_util::BodyStream::new(body)
            .try_filter_map(|frame| async move { Ok(frame.into_data().ok()) })
            .map_err(Into::into),
    )
}

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
}

/// Send the vetted request upstream and stream the response back. Bodies are
/// streamed in both directions and capped at `max_body` bytes (0 = unlimited):
/// an oversized request is refused with 413, an oversized response is refused
/// when its length is declared and otherwise cut off mid-stream. Hop-by-hop
/// headers are dropped, the guest's own `Authorization` never reaches the
/// upstream, and the vault credential (if any) is injected instead.
async fn forward(
    client: &reqwest::Client,
    method: Method,
    headers: &HeaderMap,
    body: Option<RequestBody>,
    url: String,
    inject_authorization: Option<String>,
    max_body: u64,
) -> Response {
    if max_body != 0 && declared_length(headers).is_some_and(|n| n > max_body) {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body exceeds egress_max_body_bytes ({max_body})"),
        )
            .into_response();
    }
    let tripped = Arc::new(AtomicBool::new(false));
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
        builder = builder.body(reqwest::Body::wrap_stream(capped(
            body,
            max_body,
            tripped.clone(),
        )));
    }
    match builder.send().await {
        Ok(upstream) => {
            if max_body != 0 && upstream.content_length().is_some_and(|n| n > max_body) {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("upstream response exceeds egress_max_body_bytes ({max_body})"),
                )
                    .into_response();
            }
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
                .body(Body::from_stream(capped(
                    upstream.bytes_stream(),
                    max_body,
                    Arc::new(AtomicBool::new(false)),
                )))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e) if tripped.load(Ordering::SeqCst) => {
            debug!(error = %e, %url, "egress request body over the cap");
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("request body exceeds egress_max_body_bytes ({max_body})"),
            )
                .into_response()
        }
        Err(e) => {
            warn!(error = %e, %url, "egress upstream failed");
            (StatusCode::BAD_GATEWAY, format!("upstream: {e}")).into_response()
        }
    }
}

/// Peer address recorded by `axum::serve` (or inserted by the transparent
/// listener) on a request.
fn peer_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())
}

/// The `Authorization` value to inject for `host`: a live per-sandbox grant of
/// the sandbox behind `peer` wins; otherwise the global vault decision
/// (`fallback`) applies. Every grant use is audited (destination and sandbox
/// id, never the secret).
fn broker_authorization(
    peer: Option<IpAddr>,
    host: &str,
    fallback: Option<String>,
) -> Option<String> {
    if let Some(ip) = peer {
        if let Some(inj) = fluxvm_core::grants::global().resolve(ip, host, chrono::Utc::now()) {
            fluxvm_core::grants::audit_use(&inj, host);
            return Some(inj.authorization.expose().to_string());
        }
    }
    fallback
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
    handle_plain(&state, req.map(request_body), None).await
}

/// Judge and forward one plain-HTTP request. `transparent_port` is set for
/// redirected traffic: the request then goes to the port the guest dialed and
/// through the client that refuses non-public addresses.
async fn handle_plain(
    state: &ProxyState,
    req: Request<RequestBody>,
    transparent_port: Option<u16>,
) -> Response {
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
    if transparent_port.is_some()
        && !state.cfg.egress_tls_allow_private
        && is_internal_target(&host.to_ascii_lowercase())
    {
        let reason = format!("{host} refused: loopback/private targets are not allowed");
        count_denied(StatusCode::FORBIDDEN, &method, &uri, &reason);
        return (StatusCode::FORBIDDEN, reason).into_response();
    }
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // Absolute-form URI for forward proxy, or reconstruct from Host.
    let url = if let Some(u) = vetted.rebuilt_url {
        u
    } else if uri.scheme().is_some() {
        uri.to_string()
    } else {
        format!("http://{host}{path_and_query}")
    };
    let url = match transparent_port {
        Some(port) if port != 80 => with_port(&url, port),
        _ => url,
    };

    let headers = req.headers().clone();
    let inject = broker_authorization(peer_ip(&req), &host, decision.inject_authorization);
    let body = has_body(&headers).then(|| req.into_body());
    let client = if transparent_port.is_some() {
        &state.transparent_client
    } else {
        &state.client
    };
    forward(
        client,
        method,
        &headers,
        body,
        url,
        inject,
        state.cfg.egress_max_body_bytes,
    )
    .await
}

/// `url` with its authority's port replaced by `port` (transparent mode: the
/// guest dialed that port, whatever the Host header omitted).
fn with_port(url: &str, port: u16) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let (authority, tail) = match rest.find(['/', '?']) {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let host = if authority.starts_with('[') {
        match authority.find(']') {
            Some(i) => &authority[..=i],
            None => authority,
        }
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    format!("{scheme}://{host}:{port}{tail}")
}

/// Accept a vetted `CONNECT`: answer 200 and serve the tunnel in the
/// background once hyper hands over the upgraded connection.
async fn connect(state: Arc<ProxyState>, tls: Arc<TlsState>, req: &mut Request<Body>) -> Response {
    let mut tunnel = match vet_connect(
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
    tunnel.peer = peer_ip(&*req);
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
/// decrypted requests (HTTP/1.1 or HTTP/2, as negotiated) through the same ACL
/// as plain HTTP.
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
    serve_intercepted(state, stream, tunnel).await
}

/// Serve requests read from an established, decrypted tunnel.
async fn serve_intercepted<S>(
    state: Arc<ProxyState>,
    stream: S,
    tunnel: Tunnel,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tunnel = Arc::new(tunnel);
    let service = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let tunnel = tunnel.clone();
        async move { Ok::<_, Infallible>(tunnel_request(state, tunnel, req).await) }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(TUNNEL_HEADER_TIMEOUT);
    builder.http2().timer(TokioTimer::new());
    builder
        .serve_connection(TokioIo::new(stream), service)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
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
    let body = has_body(&parts.headers).then(|| request_body(body));
    let inject = broker_authorization(
        tunnel.peer,
        &tunnel.host,
        vetted.decision.inject_authorization,
    );
    forward(
        &tls.client,
        parts.method,
        &parts.headers,
        body,
        url,
        inject,
        state.cfg.egress_max_body_bytes,
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
    fn with_port_replaces_or_adds_the_authority_port() {
        assert_eq!(
            with_port("http://a.example/x?y=1", 8080),
            "http://a.example:8080/x?y=1"
        );
        assert_eq!(
            with_port("http://a.example:80/x", 8080),
            "http://a.example:8080/x"
        );
        assert_eq!(with_port("http://a.example", 81), "http://a.example:81");
        assert_eq!(with_port("http://[::1]:80/x", 9), "http://[::1]:9/x");
        assert_eq!(with_port("http://[::1]/x", 9), "http://[::1]:9/x");
    }

    #[test]
    fn internal_targets_are_recognised() {
        assert!(is_internal_target("localhost"));
        assert!(is_internal_target("a.localhost"));
        assert!(is_internal_target("127.0.0.1"));
        assert!(is_internal_target("10.1.2.3"));
        assert!(is_internal_target("169.254.169.254"));
        assert!(is_internal_target("[::1]"));
        assert!(!is_internal_target("example.com"));
        assert!(!is_internal_target("8.8.8.8"));
    }

    #[test]
    fn options_star_is_denied_when_rules_are_active() {
        let c = cfg(&["allow * good.example/*"], &[]);
        let e = vet(&c, "OPTIONS", "*", &["good.example"]).unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
    }
}
