// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Host-namespace relays for the migration stream.
//!
//! A tap/netns VM's QEMU runs inside the VM's network namespace, where neither
//! the host's addresses nor the other VM's namespace are reachable. UNIX
//! sockets are not bound to a network namespace, so each QEMU speaks to a
//! socket in its own workspace and FluxVM (in the host namespace) carries the
//! bytes over TCP: `tcp -> unix` in front of an adopt-mode receiver, and
//! `unix -> tcp` behind a netns source. Every accepted connection is relayed,
//! so multifd channels work too.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

/// Keeps accepting while `alive()` holds; checked at least once a second.
fn keep_going(alive: &(impl Fn() -> bool + Send + Sync), deadline: Instant) -> bool {
    Instant::now() < deadline && alive()
}

/// Relay TCP connections accepted on `listener` to the UNIX socket `target`.
pub(crate) fn spawn_tcp_to_unix(
    listener: TcpListener,
    target: PathBuf,
    ttl: Duration,
    alive: impl Fn() -> bool + Send + Sync + 'static,
) {
    let deadline = Instant::now() + ttl;
    tokio::spawn(async move {
        while keep_going(&alive, deadline) {
            let accepted = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await;
            let Ok(Ok((mut tcp, peer))) = accepted else {
                continue;
            };
            let target = target.clone();
            tokio::spawn(async move {
                match UnixStream::connect(&target).await {
                    Ok(mut unix) => {
                        let _ = tcp.set_nodelay(true);
                        if let Err(e) = tokio::io::copy_bidirectional(&mut tcp, &mut unix).await {
                            tracing::debug!(%peer, error = %e, "migration relay (tcp->unix) closed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%peer, target = %target.display(), error = %e, "migration relay: receiver socket unreachable");
                    }
                }
            });
        }
    });
}

/// Relay connections accepted on the UNIX socket at `path` to TCP `dest`
/// (`host:port`). The socket file is removed when the relay stops.
pub(crate) fn spawn_unix_to_tcp(
    path: PathBuf,
    dest: String,
    ttl: Duration,
    alive: impl Fn() -> bool + Send + Sync + 'static,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    let deadline = Instant::now() + ttl;
    tokio::spawn(async move {
        while keep_going(&alive, deadline) && path.exists() {
            let accepted = tokio::time::timeout(Duration::from_secs(1), listener.accept()).await;
            let Ok(Ok((mut unix, _))) = accepted else {
                continue;
            };
            let dest = dest.clone();
            tokio::spawn(async move {
                match TcpStream::connect(&dest).await {
                    Ok(mut tcp) => {
                        let _ = tcp.set_nodelay(true);
                        if let Err(e) = tokio::io::copy_bidirectional(&mut unix, &mut tcp).await {
                            tracing::debug!(%dest, error = %e, "migration relay (unix->tcp) closed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%dest, error = %e, "migration relay: destination unreachable");
                    }
                }
            });
        }
        let _ = std::fs::remove_file(&path);
    });
    Ok(())
}

/// `tcp:host:port` -> `host:port` (IPv6 hosts keep their brackets).
pub(crate) fn tcp_target(uri: &str) -> Option<&str> {
    uri.strip_prefix("tcp:").filter(|rest| rest.contains(':'))
}

pub(crate) fn unix_uri(path: &Path) -> String {
    format!("unix:{}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn tcp_targets_parse() {
        assert_eq!(tcp_target("tcp:10.0.0.9:4444"), Some("10.0.0.9:4444"));
        assert_eq!(tcp_target("tcp:[::1]:4444"), Some("[::1]:4444"));
        assert_eq!(tcp_target("unix:/run/x.sock"), None);
        assert_eq!(tcp_target("tcp:nohostport"), None);
    }

    #[tokio::test]
    async fn bytes_cross_unix_tcp_unix() {
        let dir = tempfile::tempdir().unwrap();
        // "Receiver QEMU": a UNIX listener echoing in upper case.
        let recv_sock = dir.path().join("in.sock");
        let recv = UnixListener::bind(&recv_sock).unwrap();
        tokio::spawn(async move {
            let (mut s, _) = recv.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf.to_ascii_uppercase()).await.unwrap();
        });
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        spawn_tcp_to_unix(tcp, recv_sock, Duration::from_secs(30), || true);
        let out_sock = dir.path().join("out.sock");
        spawn_unix_to_tcp(
            out_sock.clone(),
            format!("127.0.0.1:{port}"),
            Duration::from_secs(30),
            || true,
        )
        .unwrap();
        // "Source QEMU" dials its local socket.
        let mut s = UnixStream::connect(&out_sock).await.unwrap();
        s.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"HELLO");
    }
}
