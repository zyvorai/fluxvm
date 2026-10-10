// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the egress proxy's TLS interception: a real local TLS
//! upstream (with its own test CA), the proxy in interception mode, and a raw
//! client that sends exact request lines (so `..` and `%61dmin` reach the proxy
//! unnormalized, which a URL-parsing client would hide).

use fluxvm_core::config::{CredentialInject, SandboxConfig};
use fluxvm_network::egress_proxy;
use fluxvm_network::tls_intercept::InterceptCa;
use http_body_util::{BodyExt, Full};
use http_body_util::{StreamBody, combinators::BoxBody};
use hyper::body::Frame;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const STEP: Duration = Duration::from_secs(20);

struct Fixture {
    proxy: SocketAddr,
    upstream_port: u16,
    /// Requests that actually reached the upstream.
    hits: Arc<AtomicUsize>,
    proxy_ca_pem: String,
    _dir: tempfile::TempDir,
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A TLS upstream on 127.0.0.1 whose certificate (for `localhost`) is signed by
/// a private test CA; it echoes what it received. With `h2` it also negotiates
/// HTTP/2 (ALPN), otherwise it only speaks HTTP/1.1. `/big` answers with a 2 MiB
/// body of declared length and `/bigchunk` with a 2 MiB chunked body.
async fn start_upstream(dir: &std::path::Path, h2: bool) -> (u16, Arc<AtomicUsize>, PathBuf) {
    let ca = InterceptCa::generate().unwrap();
    let (cert, key) = ca.mint("localhost").unwrap();
    let ca_file = dir.join("upstream-ca.pem");
    std::fs::write(&ca_file, ca.cert_pem()).unwrap();

    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    if h2 {
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let hits = hits_task.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = hits.clone();
                    async move { Ok::<_, Infallible>(echo(req, &hits).await) }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (port, hits, ca_file)
}

type EchoBody = BoxBody<Bytes, Infallible>;

async fn echo(req: Request<Incoming>, hits: &AtomicUsize) -> Response<EchoBody> {
    hits.fetch_add(1, Ordering::SeqCst);
    let (parts, body) = req.into_parts();
    match parts.uri.path() {
        "/big" => {
            return Response::new(Full::new(Bytes::from(vec![b'x'; 2 * 1024 * 1024])).boxed());
        }
        "/bigchunk" => {
            let chunks =
                (0..64).map(|_| Ok::<_, Infallible>(Frame::data(Bytes::from(vec![b'x'; 32768]))));
            return Response::new(BodyExt::boxed(StreamBody::new(futures_util::stream::iter(
                chunks,
            ))));
        }
        _ => {}
    }
    let auth = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let te = parts.headers.contains_key("transfer-encoding");
    let len = body
        .collect()
        .await
        .map(|b| b.to_bytes().len())
        .unwrap_or(0);
    let text = format!(
        "upstream:{}:{}|auth={auth}|host={host}|body={len}|te={te}|ver={:?}",
        parts.method,
        parts
            .uri
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/"),
        parts.version
    );
    Response::new(Full::new(Bytes::from(text)).boxed())
}

/// A plain-HTTP upstream on 127.0.0.1 that echoes `plain:<method>:<path>|body=<n>`.
async fn start_plain_upstream() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let hits = hits_task.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let hits = hits.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let (parts, body) = req.into_parts();
                        let len = body
                            .collect()
                            .await
                            .map(|b| b.to_bytes().len())
                            .unwrap_or(0);
                        let text = format!(
                            "plain:{}:{}|body={len}",
                            parts.method,
                            parts
                                .uri
                                .path_and_query()
                                .map(|p| p.as_str())
                                .unwrap_or("/")
                        );
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(text))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    (port, hits)
}

async fn start(tweak: impl FnOnce(&mut SandboxConfig, u16)) -> Fixture {
    start_opts(true, tweak).await
}

/// `trust_upstream_ca = false` leaves the upstream's test CA out of the
/// proxy's roots, to prove upstream verification is not switched off.
async fn start_opts(
    trust_upstream_ca: bool,
    tweak: impl FnOnce(&mut SandboxConfig, u16),
) -> Fixture {
    start_ex(Opts::default().trust(trust_upstream_ca), tweak).await
}

#[derive(Clone, Copy)]
struct Opts {
    trust_upstream_ca: bool,
    upstream_h2: bool,
    /// Run the transparent listener (every connection treated as redirected
    /// from the upstream's port) instead of the explicit proxy.
    transparent: bool,
    /// Transparent mode + a plain-HTTP upstream as the destination.
    transparent_http: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            trust_upstream_ca: true,
            upstream_h2: false,
            transparent: false,
            transparent_http: false,
        }
    }
}

impl Opts {
    fn trust(mut self, v: bool) -> Self {
        self.trust_upstream_ca = v;
        self
    }
    fn h2_upstream(mut self) -> Self {
        self.upstream_h2 = true;
        self
    }
    fn transparent(mut self) -> Self {
        self.transparent = true;
        self
    }
    fn transparent_http(mut self) -> Self {
        self.transparent = true;
        self.transparent_http = true;
        self
    }
}

async fn start_ex(opts: Opts, tweak: impl FnOnce(&mut SandboxConfig, u16)) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (mut upstream_port, mut hits, upstream_ca) =
        start_upstream(dir.path(), opts.upstream_h2).await;
    if opts.transparent_http {
        // The destination is the plain-HTTP upstream; the TLS one stays unused.
        (upstream_port, hits) = start_plain_upstream().await;
    }
    let ca_cert = dir.path().join("proxy-ca.crt");
    let ca_key = dir.path().join("proxy-ca.key");
    let mut cfg = SandboxConfig {
        egress_tls_intercept: true,
        egress_ca_cert: ca_cert.display().to_string(),
        egress_ca_key: ca_key.display().to_string(),
        egress_tls_ports: vec![upstream_port],
        egress_tls_allow_private: true,
        egress_upstream_ca_file: if opts.trust_upstream_ca {
            upstream_ca.display().to_string()
        } else {
            String::new()
        },
        ..SandboxConfig::default()
    };
    tweak(&mut cfg, upstream_port);
    let intercept = cfg.egress_tls_intercept;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    // The CA is created while the state is built; wait for it below.
    if opts.transparent {
        let dst: SocketAddr = format!("127.0.0.1:{upstream_port}").parse().unwrap();
        tokio::spawn(async move {
            let _ = egress_proxy::serve_transparent_on(listener, cfg, dst).await;
        });
    } else {
        tokio::spawn(async move {
            let _ = egress_proxy::serve_on(listener, cfg).await;
        });
    }
    let mut proxy_ca_pem = String::new();
    if intercept {
        for _ in 0..100 {
            if ca_cert.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        proxy_ca_pem = std::fs::read_to_string(&ca_cert).expect("proxy CA was created");
    }
    Fixture {
        proxy,
        upstream_port,
        hits,
        proxy_ca_pem,
        _dir: dir,
    }
}

/// Read a response head (through the blank line) from a plain stream.
async fn read_head(s: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(STEP, s.read(&mut byte))
            .await
            .expect("head timeout")
            .unwrap();
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn status_of(head: &str) -> u16 {
    head.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Just the `CONNECT` exchange: returns the proxy's status.
async fn connect_status(f: &Fixture, authority: &str) -> u16 {
    let mut tcp = TcpStream::connect(f.proxy).await.unwrap();
    let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    tcp.write_all(req.as_bytes()).await.unwrap();
    status_of(&read_head(&mut tcp).await)
}

fn client_config(ca_pem: &str) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(der.unwrap()).unwrap();
    }
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Open a tunnel to `localhost:<upstream>` and complete the TLS handshake with
/// `sni`, trusting only the proxy CA.
async fn tunnel(
    f: &Fixture,
    sni: &str,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let authority = format!("localhost:{}", f.upstream_port);
    let mut tcp = TcpStream::connect(f.proxy).await?;
    let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    tcp.write_all(req.as_bytes()).await?;
    let head = read_head(&mut tcp).await;
    assert_eq!(status_of(&head), 200, "CONNECT refused: {head}");
    let name = ServerName::try_from(sni.to_string()).unwrap();
    TlsConnector::from(client_config(&f.proxy_ca_pem))
        .connect(name, tcp)
        .await
}

/// Send one raw HTTP/1.1 request through an intercepted tunnel and return
/// `(status, full response text)`.
async fn https(f: &Fixture, raw_request: &str) -> (u16, String) {
    let mut tls = tokio::time::timeout(STEP, tunnel(f, "localhost"))
        .await
        .expect("tunnel timeout")
        .expect("TLS handshake against the proxy CA");
    tls.write_all(raw_request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(STEP, tls.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&out).into_owned();
    (status_of(&text), text)
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
}

fn rules(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn https_reaches_the_upstream_and_the_vault_credential_replaces_the_guest_one() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow GET localhost/*"]);
        cfg.credential_vault = vec![CredentialInject {
            host: "localhost".into(),
            authorization: "Bearer vault-token".into(),
        }];
    })
    .await;
    let req = "GET /ok?x=1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer guest-secret\r\nConnection: close\r\n\r\n";
    let (status, text) = https(&f, req).await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("upstream:GET:/ok?x=1"), "{text}");
    assert!(text.contains("auth=Bearer vault-token"), "{text}");
    assert!(!text.contains("guest-secret"), "{text}");
    assert!(text.contains("host=localhost"), "{text}");
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn method_and_path_rules_apply_inside_https() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&[
            "allow GET localhost/*",
            "allow POST localhost/submit",
            "deny * */admin/*",
        ]);
    })
    .await;

    let mut allowed = 0;
    for path in ["/ok", "/admin-panel", "/superadmin", "/a/./b"] {
        let (status, text) = https(&f, &get(path)).await;
        assert_eq!(status, 200, "{path}: {text}");
        allowed += 1;
    }

    // Every way of spelling the denied directory, including the bare one.
    for path in [
        "/admin",
        "/admin/",
        "/admin/x",
        "/a/../admin",
        "/%61dmin",
        "/%2e%2e/admin",
        "//admin",
        "/admin/.",
    ] {
        let (status, text) = https(&f, &get(path)).await;
        assert_eq!(status, 403, "{path} must be denied: {text}");
    }

    // Methods not allowed on the host/path.
    let (status, _) = https(
        &f,
        "POST /ok HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = https(
        &f,
        "DELETE /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 403);

    let (status, text) = https(
        &f,
        "POST /submit HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("body=5"), "{text}");
    allowed += 1;

    assert_eq!(
        f.hits.load(Ordering::SeqCst),
        allowed,
        "denied requests must never reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_normalized_path_is_what_gets_forwarded() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow GET localhost/*"]);
    })
    .await;
    let (status, text) = https(&f, &get("/a/./b//c/%61")).await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("upstream:GET:/a/b/c/a"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_host_that_is_not_the_tunnel_host_is_denied() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow GET */*"]);
    })
    .await;
    let (status, _) = https(
        &f,
        "GET /x HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = https(
        &f,
        "GET https://evil.example/x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = https(
        &f,
        "GET /x HTTP/1.1\r\nHost: localhost\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        status == 400 || status == 403,
        "duplicate Host must be rejected (got {status})"
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_is_refused_before_any_tls_when_the_target_is_not_allowed() {
    // Host allowlist: only `localhost`.
    let f = start(|cfg, _| {
        cfg.egress_allow_domains = vec!["localhost".into()];
    })
    .await;
    let port = f.upstream_port;
    assert_eq!(
        connect_status(&f, &format!("other.example:{port}")).await,
        403
    );
    // A port that is not configured.
    assert_eq!(connect_status(&f, "localhost:1").await, 403);
    assert_eq!(connect_status(&f, &format!("localhost:{port}")).await, 200);

    // Only allow rules that never mention the host.
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow GET docs.python.org/*"]);
    })
    .await;
    assert_eq!(
        connect_status(&f, &format!("localhost:{}", f.upstream_port)).await,
        403
    );

    // A whole-host deny.
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["deny * localhost"]);
    })
    .await;
    assert_eq!(
        connect_status(&f, &format!("localhost:{}", f.upstream_port)).await,
        403
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn private_and_loopback_targets_are_refused_by_default() {
    let f = start(|cfg, port| {
        cfg.egress_tls_allow_private = false;
        cfg.egress_tls_ports = vec![port, 443];
    })
    .await;
    for target in [
        format!("127.0.0.1:{}", f.upstream_port),
        format!("localhost:{}", f.upstream_port),
        "169.254.169.254:443".to_string(),
        "10.0.0.5:443".to_string(),
        "[::1]:443".to_string(),
    ] {
        assert_eq!(connect_status(&f, &target).await, 403, "{target}");
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_for_a_name_other_than_the_connect_host_fails() {
    let f = start(|_, _| {}).await;
    let res = tokio::time::timeout(STEP, tunnel(&f, "other.example"))
        .await
        .expect("timeout");
    assert!(
        res.is_err(),
        "handshake for a different SNI must not succeed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrades_inside_the_tunnel_are_not_supported() {
    let f = start(|_, _| {}).await;
    let (status, text) = https(
        &f,
        "GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade, close\r\nUpgrade: websocket\r\n\r\n",
    )
    .await;
    assert_eq!(status, 501, "{text}");
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn large_and_chunked_request_bodies_are_streamed_through() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow * localhost/*"]);
    })
    .await;
    let big = vec![b'a'; 3 * 1024 * 1024];
    let mut req = format!(
        "POST /up HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        big.len()
    )
    .into_bytes();
    req.extend_from_slice(&big);
    let mut tls = tunnel(&f, "localhost").await.unwrap();
    tls.write_all(&req).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(STEP, tls.read_to_end(&mut out)).await;
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("body=3145728"), "{text}");

    let chunked = "POST /up HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let (status, text) = https(&f, chunked).await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("body=11"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_certificates_are_still_verified() {
    // The upstream's CA is not in the proxy's roots: the proxy must refuse to
    // talk to it rather than skip verification.
    let f = start_opts(false, |cfg, _| {
        cfg.egress_http_rules = rules(&["allow GET localhost/*"]);
    })
    .await;
    let (status, text) = https(&f, &get("/ok")).await;
    assert_eq!(status, 502, "{text}");
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_interception_connect_is_still_refused() {
    let f = start(|cfg, _| {
        cfg.egress_tls_intercept = false;
        cfg.egress_http_rules = rules(&["allow * localhost"]);
    })
    .await;
    // No CA is created when interception is off.
    let mut tcp = TcpStream::connect(f.proxy).await.unwrap();
    let authority = format!("localhost:{}", f.upstream_port);
    tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(status_of(&read_head(&mut tcp).await), 501);
}

// ---------------------------------------------------------------------------
// HTTP/2 inside intercepted tunnels
// ---------------------------------------------------------------------------

fn client_config_alpn(ca_pem: &str, alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(der.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

/// `CONNECT` to the upstream and complete TLS offering `alpn`.
async fn tunnel_alpn(
    f: &Fixture,
    sni: &str,
    alpn: &[&[u8]],
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let authority = format!("localhost:{}", f.upstream_port);
    let mut tcp = TcpStream::connect(f.proxy).await?;
    let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    tcp.write_all(req.as_bytes()).await?;
    let head = read_head(&mut tcp).await;
    assert_eq!(status_of(&head), 200, "CONNECT refused: {head}");
    let name = ServerName::try_from(sni.to_string()).unwrap();
    TlsConnector::from(client_config_alpn(&f.proxy_ca_pem, alpn))
        .connect(name, tcp)
        .await
}

type H2Sender = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

async fn h2_over(tls: tokio_rustls::client::TlsStream<TcpStream>) -> H2Sender {
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "the proxy did not negotiate h2"
    );
    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

async fn h2_call(
    sender: &mut H2Sender,
    method: &str,
    uri: &str,
    body: &'static [u8],
) -> (u16, String) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Full::new(Bytes::from_static(body)))
        .unwrap();
    let resp = tokio::time::timeout(STEP, sender.send_request(req))
        .await
        .expect("h2 timeout")
        .expect("h2 request");
    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn h2_uri(f: &Fixture, path: &str) -> String {
    format!("https://localhost:{}{path}", f.upstream_port)
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_is_negotiated_and_the_rules_apply_per_request() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&[
            "allow GET localhost/*",
            "allow POST localhost/submit",
            "deny * */admin/*",
        ]);
        cfg.credential_vault = vec![CredentialInject {
            host: "localhost".into(),
            authorization: "Bearer vault-token".into(),
        }];
    })
    .await;
    let tls = tunnel_alpn(&f, "localhost", &[b"h2", b"http/1.1"])
        .await
        .unwrap();
    let mut h2 = h2_over(tls).await;

    let (status, text) = h2_call(&mut h2, "GET", &h2_uri(&f, "/ok"), b"").await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("upstream:GET:/ok"), "{text}");
    assert!(text.contains("auth=Bearer vault-token"), "{text}");
    let (status, text) = h2_call(&mut h2, "POST", &h2_uri(&f, "/submit"), b"hello").await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("body=5"), "{text}");
    let allowed_hits = f.hits.load(Ordering::SeqCst);
    assert_eq!(allowed_hits, 2);

    for (m, path) in [
        ("POST", "/other"),
        ("DELETE", "/ok"),
        ("GET", "/admin/x"),
        ("GET", "/a/../admin/x"),
        ("GET", "/%61dmin/x"),
        ("GET", "//admin/x"),
        ("GET", "/admin/./x"),
    ] {
        let (status, text) = h2_call(&mut h2, m, &h2_uri(&f, path), b"").await;
        assert_eq!(status, 403, "{m} {path}: {text}");
    }
    assert_eq!(
        f.hits.load(Ordering::SeqCst),
        allowed_hits,
        "denied requests must not reach the upstream"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn http1_and_h2_clients_share_one_proxy() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow GET localhost/*", "deny * */admin/*"]);
    })
    .await;
    let h1 = async {
        let tls = tunnel_alpn(&f, "localhost", &[b"http/1.1"]).await.unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
        drop(tls);
        let (ok, _) = https(&f, &get("/ok")).await;
        let (denied, _) = https(&f, &get("/admin/x")).await;
        (ok, denied)
    };
    let h2 = async {
        let tls = tunnel_alpn(&f, "localhost", &[b"h2"]).await.unwrap();
        let mut c = h2_over(tls).await;
        let (ok, _) = h2_call(&mut c, "GET", &h2_uri(&f, "/ok"), b"").await;
        let (denied, _) = h2_call(&mut c, "GET", &h2_uri(&f, "/admin/x"), b"").await;
        (ok, denied)
    };
    let (a, b) = tokio::join!(h1, h2);
    assert_eq!(a, (200, 403));
    assert_eq!(b, (200, 403));
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_authority_must_match_the_tunnel_host() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow GET localhost/*", "allow GET evil.example/*"]);
    })
    .await;
    let tls = tunnel_alpn(&f, "localhost", &[b"h2"]).await.unwrap();
    let mut h2 = h2_over(tls).await;
    let (status, text) = h2_call(&mut h2, "GET", "https://evil.example/ok", b"").await;
    assert_eq!(status, 403, "{text}");
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
    let (status, _) = h2_call(&mut h2, "GET", &h2_uri(&f, "/ok"), b"").await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_h2_upstream_is_used_when_it_offers_h2() {
    let f = start_ex(Opts::default().h2_upstream(), |cfg, _| {
        cfg.egress_http_rules = rules(&["allow * localhost/*"]);
    })
    .await;
    let (status, text) = https(&f, &get("/ok")).await;
    assert_eq!(status, 200, "{text}");
    assert!(
        text.contains("ver=HTTP/2.0"),
        "upstream leg should be h2: {text}"
    );
    let tls = tunnel_alpn(&f, "localhost", &[b"h2"]).await.unwrap();
    let mut h2 = h2_over(tls).await;
    let (status, text) = h2_call(&mut h2, "GET", &h2_uri(&f, "/ok"), b"").await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("ver=HTTP/2.0"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_h1_only_upstream_still_works_for_h2_clients() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow * localhost/*"]);
    })
    .await;
    let tls = tunnel_alpn(&f, "localhost", &[b"h2"]).await.unwrap();
    let mut h2 = h2_over(tls).await;
    let (status, text) = h2_call(&mut h2, "GET", &h2_uri(&f, "/ok"), b"").await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("ver=HTTP/1.1"), "upstream leg is h1: {text}");
}

// ---------------------------------------------------------------------------
// Body size cap
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_request_over_the_cap_is_refused_with_413_and_never_reaches_the_upstream() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow * localhost/*"]);
        cfg.egress_max_body_bytes = 1000;
    })
    .await;
    let mut req =
        "POST /up HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n"
            .as_bytes()
            .to_vec();
    req.extend(vec![b'a'; 5000]);
    let (status, text) = https(&f, &String::from_utf8(req).unwrap()).await;
    assert_eq!(status, 413, "{text}");
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);

    // Under the cap still works.
    let ok = "POST /up HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789";
    let (status, text) = https(&f, ok).await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("body=10"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_chunked_request_that_grows_past_the_cap_is_cut_off_with_413() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow * localhost/*"]);
        cfg.egress_max_body_bytes = 1000;
    })
    .await;
    let chunk = "x".repeat(600);
    let body = format!(
        "{:x}\r\n{chunk}\r\n{:x}\r\n{chunk}\r\n{:x}\r\n{chunk}\r\n0\r\n\r\n",
        600, 600, 600
    );
    let req = format!(
        "POST /up HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{body}"
    );
    let (status, text) = https(&f, &req).await;
    assert_eq!(status, 413, "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_response_with_a_declared_length_over_the_cap_is_refused() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow * localhost/*"]);
        cfg.egress_max_body_bytes = 1024 * 1024;
    })
    .await;
    let (status, text) = https(&f, &get("/big")).await;
    assert_eq!(status, 502, "{}", &text[..text.len().min(300)]);
    assert!(
        text.contains("exceeds egress_max_body_bytes"),
        "{}",
        &text[..text.len().min(300)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streamed_response_over_the_cap_is_cut_off_mid_stream() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow * localhost/*"]);
        cfg.egress_max_body_bytes = 512 * 1024;
    })
    .await;
    let (status, text) = https(&f, &get("/bigchunk")).await;
    assert_eq!(status, 200, "headers were already sent");
    assert!(
        text.len() < 2 * 1024 * 1024 && !text.ends_with("0\r\n\r\n"),
        "the response must be aborted, not completed ({} bytes)",
        text.len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn zero_means_unlimited() {
    let f = start(|cfg, _| {
        cfg.egress_http_rules = rules(&["allow * localhost/*"]);
        cfg.egress_max_body_bytes = 0;
    })
    .await;
    let (status, text) = https(&f, &get("/big")).await;
    assert_eq!(status, 200);
    assert!(text.len() > 2 * 1024 * 1024, "{}", text.len());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cap_also_applies_to_plain_http() {
    let f = start(|cfg, _| {
        cfg.egress_max_body_bytes = 1000;
    })
    .await;
    let (plain_port, plain_hits) = start_plain_upstream().await;
    let send = |len: usize| {
        let proxy = f.proxy;
        async move {
            let mut tcp = TcpStream::connect(proxy).await.unwrap();
            let head = format!(
                "POST http://127.0.0.1:{plain_port}/up HTTP/1.1\r\nHost: 127.0.0.1:{plain_port}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
            );
            tcp.write_all(head.as_bytes()).await.unwrap();
            let _ = tcp.write_all(&vec![b'a'; len]).await;
            let mut out = Vec::new();
            let _ = tokio::time::timeout(STEP, tcp.read_to_end(&mut out)).await;
            let text = String::from_utf8_lossy(&out).into_owned();
            (status_of(&text), text)
        }
    };
    let (status, text) = send(5000).await;
    assert_eq!(status, 413, "{text}");
    assert_eq!(plain_hits.load(Ordering::SeqCst), 0);
    let (status, text) = send(500).await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("plain:POST:/up|body=500"), "{text}");
}

// ---------------------------------------------------------------------------
// Transparent mode (redirected connections, no proxy settings in the client)
// ---------------------------------------------------------------------------

async fn transparent_tls(
    f: &Fixture,
    sni: &str,
    alpn: &[&[u8]],
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(f.proxy).await?;
    let name = ServerName::try_from(sni.to_string()).unwrap();
    TlsConnector::from(client_config_alpn(&f.proxy_ca_pem, alpn))
        .connect(name, tcp)
        .await
}

/// One raw HTTP/1.1 request over a fresh transparent TLS connection.
async fn transparent_https(f: &Fixture, raw: &str) -> (u16, String) {
    let mut tls = transparent_tls(f, "localhost", &[b"http/1.1"])
        .await
        .expect("TLS to the transparent listener");
    tls.write_all(raw.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(STEP, tls.read_to_end(&mut out)).await;
    let text = String::from_utf8_lossy(&out).into_owned();
    (status_of(&text), text)
}

#[tokio::test(flavor = "multi_thread")]
async fn transparent_https_is_intercepted_judged_and_forwarded() {
    let f = start_ex(Opts::default().transparent(), |cfg, _| {
        cfg.egress_http_rules = rules(&["allow GET localhost/*", "deny * */admin/*"]);
        cfg.credential_vault = vec![CredentialInject {
            host: "localhost".into(),
            authorization: "Bearer vault-token".into(),
        }];
    })
    .await;
    let (status, text) = transparent_https(&f, &get("/ok")).await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("upstream:GET:/ok"), "{text}");
    assert!(text.contains("auth=Bearer vault-token"), "{text}");
    for path in ["/admin/x", "/a/../admin/x", "/%61dmin/x", "//admin/x"] {
        let (status, text) = transparent_https(&f, &get(path)).await;
        assert_eq!(status, 403, "{path}: {text}");
    }
    let (status, _) = transparent_https(
        &f,
        "POST /ok HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 403, "POST is not allowed");
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn transparent_https_speaks_h2_too() {
    let f = start_ex(Opts::default().transparent(), |cfg, _| {
        cfg.egress_http_rules = rules(&["allow GET localhost/*", "deny * */admin/*"]);
    })
    .await;
    let tls = transparent_tls(&f, "localhost", &[b"h2", b"http/1.1"])
        .await
        .unwrap();
    let mut h2 = h2_over(tls).await;
    let (status, text) = h2_call(&mut h2, "GET", &h2_uri(&f, "/ok"), b"").await;
    assert_eq!(status, 200, "{text}");
    let (status, _) = h2_call(&mut h2, "GET", &h2_uri(&f, "/admin/x"), b"").await;
    assert_eq!(status, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn transparent_tls_without_sni_or_to_a_forbidden_port_or_target_is_refused() {
    // No SNI (an IP literal sends none): nothing to judge, so refuse.
    let f = start_ex(Opts::default().transparent(), |cfg, _| {
        cfg.egress_http_rules = rules(&["allow * *"]);
    })
    .await;
    assert!(
        transparent_tls(&f, "127.0.0.1", &[b"http/1.1"])
            .await
            .is_err()
    );

    // The dialed port is not in egress_tls_ports.
    let f = start_ex(Opts::default().transparent(), |cfg, _| {
        cfg.egress_http_rules = rules(&["allow * *"]);
        cfg.egress_tls_ports = vec![1];
    })
    .await;
    assert!(
        transparent_tls(&f, "localhost", &[b"http/1.1"])
            .await
            .is_err()
    );

    // Loopback/private targets are refused unless allowed, as for CONNECT.
    let f = start_ex(Opts::default().transparent(), |cfg, _| {
        cfg.egress_http_rules = rules(&["allow * *"]);
        cfg.egress_tls_allow_private = false;
    })
    .await;
    assert!(
        transparent_tls(&f, "localhost", &[b"http/1.1"])
            .await
            .is_err()
    );
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn transparent_tls_needs_interception_to_be_on() {
    let f = start_ex(Opts::default().transparent(), |cfg, _| {
        cfg.egress_tls_intercept = false;
        cfg.egress_http_rules = rules(&["allow * *"]);
    })
    .await;
    let tcp = TcpStream::connect(f.proxy).await.unwrap();
    let cfg = client_config_alpn(&f.proxy_ca_pem, &[b"http/1.1"]);
    let name = ServerName::try_from("localhost".to_string()).unwrap();
    assert!(TlsConnector::from(cfg).connect(name, tcp).await.is_err());
}

/// One raw plain-HTTP request to the transparent listener.
async fn transparent_http(f: &Fixture, raw: &str) -> (u16, String) {
    let mut tcp = TcpStream::connect(f.proxy).await.unwrap();
    tcp.write_all(raw.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(STEP, tcp.read_to_end(&mut out)).await;
    let text = String::from_utf8_lossy(&out).into_owned();
    (status_of(&text), text)
}

#[tokio::test(flavor = "multi_thread")]
async fn transparent_http_is_judged_by_host_and_goes_to_the_dialed_port() {
    let f = start_ex(Opts::default().transparent_http(), |cfg, _| {
        cfg.egress_http_rules = rules(&["allow GET localhost/*", "deny * */admin/*"]);
    })
    .await;
    // The Host header carries no port; the destination port comes from the
    // original destination (here the plain upstream's).
    let (status, text) = transparent_http(
        &f,
        "GET /ok?x=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("plain:GET:/ok?x=1|body=0"), "{text}");
    for req in [
        "GET /admin/x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "GET /a/../admin/x HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "POST /ok HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "GET /ok HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
    ] {
        let (status, text) = transparent_http(&f, req).await;
        assert_eq!(status, 403, "{req:?}: {text}");
    }
    assert_eq!(f.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn transparent_http_refuses_loopback_targets_unless_allowed() {
    let f = start_ex(Opts::default().transparent_http(), |cfg, _| {
        cfg.egress_http_rules = rules(&["allow * *"]);
        cfg.egress_tls_allow_private = false;
    })
    .await;
    let (status, text) = transparent_http(
        &f,
        "GET /ok HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 403, "{text}");
    assert_eq!(f.hits.load(Ordering::SeqCst), 0);
}
