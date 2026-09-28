// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Transparent mode: accept guest connections that nftables redirected to the
//! proxy, so the guest needs no proxy settings.
//!
//! Each connection is classified from its first bytes: a TLS ClientHello is
//! terminated with a certificate minted for its SNI name (needs
//! `egress_tls_intercept`), anything that looks like an HTTP request line is
//! judged by its `Host` header. Either way the request then goes through the
//! same ACL, credential vault and body cap as the explicit-proxy paths.
//!
//! The upstream is contacted **by name** (SNI or Host), never by the address the
//! guest dialed; only the destination *port* is taken from the original
//! destination (`SO_ORIGINAL_DST`), so what is judged is what is contacted.

use super::{
    ProxyState, TLS_HANDSHAKE_TIMEOUT, TUNNEL_HEADER_TIMEOUT, count_denied, handle_plain,
    request_body, serve_intercepted, vet_target,
};
use crate::http_acl;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

const PEEK_TIMEOUT: Duration = Duration::from_secs(10);

/// Where a redirected connection was originally headed.
#[derive(Clone, Copy)]
pub(super) enum Dst {
    /// Recover it from the kernel (`SO_ORIGINAL_DST`); refuse the connection if
    /// it was not redirected.
    Original,
    /// Pretend every connection was redirected from this address (tests: no
    /// nftables redirect exists to read it from).
    Fixed(SocketAddr),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) enum Kind {
    Tls,
    Http,
    Unknown,
}

/// Classify a connection from its first bytes.
pub(super) fn classify(first: &[u8]) -> Kind {
    if first.len() >= 3 && first[0] == 0x16 && first[1] == 0x03 && first[2] <= 0x04 {
        Kind::Tls
    } else if first.first().is_some_and(|b| b.is_ascii_uppercase()) {
        Kind::Http
    } else {
        Kind::Unknown
    }
}

pub(super) async fn run(listener: TcpListener, state: Arc<ProxyState>, dst: Dst) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "transparent accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(state, tcp, dst).await {
                debug!(%peer, error = %e, "transparent connection ended");
            }
        });
    }
}

async fn handle(state: Arc<ProxyState>, tcp: TcpStream, dst: Dst) -> anyhow::Result<()> {
    let dst_addr = match dst {
        Dst::Fixed(a) => a,
        Dst::Original => original_dst(&tcp)
            .ok_or_else(|| anyhow::anyhow!("no original destination: connection not redirected"))?,
    };
    let mut first = [0u8; 8];
    let n = tokio::time::timeout(PEEK_TIMEOUT, async {
        loop {
            let n = tcp.peek(&mut first).await?;
            if n >= 3 || n == 0 {
                return Ok::<_, std::io::Error>(n);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    match classify(&first[..n]) {
        Kind::Tls => serve_tls(state, tcp, dst_addr.port()).await,
        Kind::Http => serve_http(state, tcp, dst_addr.port()).await,
        Kind::Unknown => anyhow::bail!("not TLS and not HTTP"),
    }
}

async fn serve_tls(state: Arc<ProxyState>, tcp: TcpStream, port: u16) -> anyhow::Result<()> {
    let Some(tls) = state.tls.clone() else {
        anyhow::bail!("TLS interception is off: refusing redirected HTTPS");
    };
    let acceptor = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), tcp);
    let start = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor).await??;
    let sni = start
        .client_hello()
        .server_name()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("redirected TLS without SNI cannot be judged"))?;
    let host = http_acl::canon_host(&sni).map_err(|e| anyhow::anyhow!("SNI {sni:?}: {e}"))?;
    let tunnel = match vet_target(
        &state.cfg,
        &state.acl,
        &tls.ports,
        tls.allow_private,
        host.clone(),
        &host,
        port,
    ) {
        Ok(t) => t,
        Err((status, reason)) => {
            count_denied(status, &Method::CONNECT, &host, &reason);
            anyhow::bail!("redirected TLS to {host}:{port} refused: {reason}");
        }
    };
    let server_cfg = tls
        .intercept
        .server_config_for(host.trim_start_matches('[').trim_end_matches(']'))?;
    let stream =
        tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, start.into_stream(server_cfg)).await??;
    serve_intercepted(state, stream, tunnel).await
}

async fn serve_http(state: Arc<ProxyState>, tcp: TcpStream, port: u16) -> anyhow::Result<()> {
    let service = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        async move {
            let req = req.map(request_body);
            Ok::<_, Infallible>(handle_plain(&state, req, Some(port)).await)
        }
    });
    hyper::server::conn::http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(TUNNEL_HEADER_TIMEOUT)
        .serve_connection(TokioIo::new(tcp), service)
        .await?;
    Ok(())
}

/// The address the client dialed before nftables redirected it here.
#[cfg(target_os = "linux")]
fn original_dst(tcp: &TcpStream) -> Option<SocketAddr> {
    use std::mem::{size_of, zeroed};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::AsRawFd;
    // linux/netfilter_ipv4.h SO_ORIGINAL_DST and linux/netfilter_ipv6/ip6_tables.h
    // IP6T_SO_ORIGINAL_DST are both 80.
    const ORIGINAL_DST: libc::c_int = 80;
    let fd = tcp.as_raw_fd();
    let local = tcp.local_addr().ok()?;
    // SAFETY: `fd` is a live socket owned by `tcp`; the out-parameters are
    // zero-initialised structs of exactly the sizes passed as `len`.
    unsafe {
        if local.is_ipv4() {
            let mut a: libc::sockaddr_in = zeroed();
            let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let rc = libc::getsockopt(
                fd,
                libc::SOL_IP,
                ORIGINAL_DST,
                &mut a as *mut _ as *mut libc::c_void,
                &mut len,
            );
            (rc == 0).then(|| {
                SocketAddr::new(
                    Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)).into(),
                    u16::from_be(a.sin_port),
                )
            })
        } else {
            let mut a: libc::sockaddr_in6 = zeroed();
            let mut len = size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let rc = libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                ORIGINAL_DST,
                &mut a as *mut _ as *mut libc::c_void,
                &mut len,
            );
            (rc == 0).then(|| {
                SocketAddr::new(
                    Ipv6Addr::from(a.sin6_addr.s6_addr).into(),
                    u16::from_be(a.sin6_port),
                )
            })
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn original_dst(_tcp: &TcpStream) -> Option<SocketAddr> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_tls_http_and_junk() {
        assert_eq!(classify(&[0x16, 0x03, 0x01, 0x02, 0x00]), Kind::Tls);
        assert_eq!(classify(&[0x16, 0x03, 0x03]), Kind::Tls);
        assert_eq!(classify(b"GET / HTTP/1.1"), Kind::Http);
        assert_eq!(classify(b"POST /x"), Kind::Http);
        assert_eq!(classify(b"CONNECT a:443"), Kind::Http);
        assert_eq!(classify(&[0x16, 0x03]), Kind::Unknown, "too short to call");
        assert_eq!(classify(&[0x16, 0x02, 0x00]), Kind::Unknown, "not SSLv3+");
        assert_eq!(classify(b"\x00\x01\x02"), Kind::Unknown);
        assert_eq!(classify(b""), Kind::Unknown);
        assert_eq!(
            classify(b"get / HTTP/1.1"),
            Kind::Unknown,
            "methods are upper-case"
        );
    }
}
