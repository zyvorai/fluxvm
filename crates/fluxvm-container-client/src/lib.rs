// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use fluxvm_container_protocol::{
    ContainerEnvelope, ContainerRequest, ContainerResponse, DEFAULT_CONTAINER_AGENT_PORT,
    DEFAULT_CONTAINER_STREAM_PORT, IoStreamAck, IoStreamAttach, decode_line, encode_line,
};
use fluxvm_core::model::{BackendKind, VmRecord};
use std::{
    io::{Read, Write},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

pub trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

/// Blocking byte stream attached to one guest process stdio channel. The
/// lifecycle RPC remains newline-delimited JSON on port 17778; Set 5 uses the
/// dedicated port 17779 for long-lived stdin/stdout/stderr transfer.
pub struct ContainerStream {
    inner: Box<dyn ReadWrite>,
}

impl Read for ContainerStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
impl Write for ContainerStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub async fn open_stream(
    vm: &VmRecord,
    attach: IoStreamAttach,
    timeout: Duration,
) -> Result<ContainerStream> {
    let agent = vm
        .request
        .agent
        .as_ref()
        .filter(|a| a.enabled)
        .context("FluxVM guest agent must be enabled for secure containers")?;
    let mut attach = attach;
    attach.token = agent.token.clone();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let vm = vm.clone();
        let attempt = attach.clone();
        let error =
            match tokio::task::spawn_blocking(move || open_stream_blocking(&vm, &attempt)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(error)) => error,
                Err(error) => bail!("container stream worker panicked: {error}"),
            };
        if tokio::time::Instant::now() >= deadline {
            return Err(error);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn open_stream_blocking(vm: &VmRecord, attach: &IoStreamAttach) -> Result<ContainerStream> {
    let cid = vm.guest_cid.context("VM has no vsock CID assigned")?;
    match vm.backend {
        BackendKind::Qemu => {
            native_vsock_stream_blocking(cid, DEFAULT_CONTAINER_STREAM_PORT, attach)
        }
        BackendKind::CloudHypervisor | BackendKind::Firecracker | BackendKind::FluxVm => {
            let socket = vm
                .vsock_socket
                .as_deref()
                .context("VM has no vsock proxy socket recorded")?;
            uds_proxy_stream_blocking(socket, DEFAULT_CONTAINER_STREAM_PORT, attach)
        }
        BackendKind::Auto => bail!("unresolved FluxVM backend"),
    }
}

fn read_line_blocking(stream: &mut dyn Read) -> Result<String> {
    let mut bytes = Vec::new();
    let mut b = [0u8; 1];
    while bytes.len() <= 64 * 1024 {
        let n = stream.read(&mut b)?;
        if n == 0 || b[0] == b'\n' {
            break;
        }
        bytes.push(b[0]);
    }
    if bytes.len() > 64 * 1024 {
        bail!("stream handshake line too large");
    }
    Ok(String::from_utf8(bytes).context("stream handshake is not UTF-8")?)
}

fn validate_stream_ack(line: &str) -> Result<()> {
    let ack: IoStreamAck = decode_line(line).context("decoding stream attach ack")?;
    if !ack.ok {
        bail!(
            "container stream attach failed: {}",
            ack.message.unwrap_or_else(|| "unknown error".into())
        );
    }
    Ok(())
}

fn uds_proxy_stream_blocking(
    socket: &std::path::Path,
    guest_port: u32,
    attach: &IoStreamAttach,
) -> Result<ContainerStream> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket)
        .with_context(|| format!("connecting to vsock proxy {}", socket.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.write_all(format!("CONNECT {guest_port}\n").as_bytes())?;
    stream.flush()?;
    let ack = read_line_blocking(&mut stream)?;
    if !ack.trim().to_ascii_uppercase().starts_with("OK") {
        bail!("vsock proxy refused port {guest_port}: {:?}", ack.trim());
    }
    stream.write_all(encode_line(attach)?.as_bytes())?;
    stream.flush()?;
    let ack = read_line_blocking(&mut stream)?;
    validate_stream_ack(&ack)?;
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    Ok(ContainerStream {
        inner: Box::new(stream),
    })
}

#[cfg(target_os = "linux")]
fn native_vsock_stream_blocking(
    cid: u32,
    port: u32,
    attach: &IoStreamAttach,
) -> Result<ContainerStream> {
    use std::os::fd::FromRawFd;
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            bail!("socket(AF_VSOCK): {}", std::io::Error::last_os_error());
        }
        let mut file = std::fs::File::from_raw_fd(fd);
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = cid;
        addr.svm_port = port;
        if libc::connect(
            fd,
            (&addr as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        ) != 0
        {
            bail!(
                "connect(vsock cid={cid} port={port}): {}",
                std::io::Error::last_os_error()
            );
        }
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        file.write_all(encode_line(attach)?.as_bytes())?;
        file.flush()?;
        let ack = read_line_blocking(&mut file)?;
        validate_stream_ack(&ack)?;
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        Ok(ContainerStream {
            inner: Box::new(file),
        })
    }
}

#[cfg(not(target_os = "linux"))]
fn native_vsock_stream_blocking(
    _cid: u32,
    _port: u32,
    _attach: &IoStreamAttach,
) -> Result<ContainerStream> {
    bail!("native AF_VSOCK is supported on Linux only")
}

pub async fn call(
    vm: &VmRecord,
    request: ContainerRequest,
    timeout: Duration,
) -> Result<ContainerResponse> {
    let agent = vm
        .request
        .agent
        .as_ref()
        .filter(|a| a.enabled)
        .context("FluxVM guest agent must be enabled for secure containers")?;
    let envelope = ContainerEnvelope {
        token: agent.token.clone(),
        request,
    };
    let cid = vm.guest_cid.context("VM has no vsock CID assigned")?;

    tokio::time::timeout(timeout, async {
        match vm.backend {
            BackendKind::Qemu => {
                native_vsock_call(cid, DEFAULT_CONTAINER_AGENT_PORT, &envelope, timeout).await
            }
            BackendKind::CloudHypervisor | BackendKind::Firecracker | BackendKind::FluxVm => {
                let socket = vm
                    .vsock_socket
                    .as_deref()
                    .context("VM has no vsock proxy socket recorded")?;
                uds_proxy_call(socket, DEFAULT_CONTAINER_AGENT_PORT, &envelope).await
            }
            BackendKind::Auto => bail!("unresolved FluxVM backend"),
        }
    })
    .await
    .context("FluxVM container-agent call timed out")?
}

pub async fn ping(vm: &VmRecord, timeout: Duration) -> Result<()> {
    match call(vm, ContainerRequest::Ping, timeout).await? {
        ContainerResponse::Pong => Ok(()),
        ContainerResponse::Error { message } => bail!("container agent: {message}"),
        other => bail!("unexpected ping response: {other:?}"),
    }
}

async fn uds_proxy_call(
    socket: &std::path::Path,
    guest_port: u32,
    envelope: &ContainerEnvelope,
) -> Result<ContainerResponse> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to vsock proxy {}", socket.display()))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    write_half
        .write_all(format!("CONNECT {guest_port}\n").as_bytes())
        .await?;
    let mut ack = String::new();
    reader.read_line(&mut ack).await?;
    if !ack.trim().to_ascii_uppercase().starts_with("OK") {
        bail!("vsock proxy refused port {guest_port}: {:?}", ack.trim());
    }
    write_half
        .write_all(encode_line(envelope)?.as_bytes())
        .await?;
    write_half.flush().await?;
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    if line.is_empty() {
        bail!("container agent closed without a response");
    }
    decode_line(&line).context("decoding container-agent response")
}

#[cfg(target_os = "linux")]
async fn native_vsock_call(
    cid: u32,
    port: u32,
    envelope: &ContainerEnvelope,
    timeout: Duration,
) -> Result<ContainerResponse> {
    let envelope = envelope.clone();
    let deadline = std::time::Instant::now() + timeout;
    tokio::task::spawn_blocking(move || native_vsock_call_blocking(cid, port, &envelope, deadline))
        .await
        .context("vsock worker panicked")?
}

#[cfg(target_os = "linux")]
fn native_vsock_call_blocking(
    cid: u32,
    port: u32,
    envelope: &ContainerEnvelope,
    deadline: std::time::Instant,
) -> Result<ContainerResponse> {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;

    // Per-syscall socket timeout used for both connect-retry backoff and the
    // read loop below. Kept short so a single stuck attempt can't eat the
    // caller's whole deadline, while the surrounding retry loops still honor
    // that full deadline overall -- long-blocking requests (Wait, in
    // particular, which can legitimately take anywhere from milliseconds to
    // days depending on the workload) get a generous caller-supplied
    // deadline instead of the single fixed 20s window this used to hard-code
    // regardless of what the caller actually asked for.
    const SOCK_TIMEOUT: libc::timeval = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };

    unsafe {
        let mut file = None;
        let mut last_err = None;
        // AF_VSOCK connect() can return a transient EAGAIN/ECONNRESET when the
        // guest's listener is momentarily busy (e.g. a concurrent connection
        // just landed, or the accept() backlog hasn't drained yet right after
        // the container-agent starts) -- this is the vsock analogue of a busy
        // TCP accept queue, not a fatal condition. Retry with a short backoff
        // until the caller's deadline rather than failing the whole RPC on
        // the first transient hiccup.
        let mut attempt: u32 = 0;
        loop {
            let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
            if fd < 0 {
                bail!("socket(AF_VSOCK): {}", std::io::Error::last_os_error());
            }
            let mut addr: libc::sockaddr_vm = std::mem::zeroed();
            addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
            addr.svm_cid = cid;
            addr.svm_port = port;
            if libc::connect(
                fd,
                (&addr as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            ) == 0
            {
                file = Some(std::fs::File::from_raw_fd(fd));
                break;
            }
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            let retryable = matches!(
                err.raw_os_error(),
                Some(libc::EAGAIN) | Some(libc::ECONNRESET) | Some(libc::ECONNREFUSED)
            );
            let now = std::time::Instant::now();
            last_err = Some(err);
            if !retryable || now >= deadline {
                break;
            }
            let backoff = Duration::from_millis(50 * u64::from(attempt + 1)).min(deadline - now);
            std::thread::sleep(backoff);
            attempt += 1;
        }
        let mut file = match file {
            Some(f) => f,
            None => {
                let err = last_err.expect("connect loop always sets last_err on failure");
                bail!("connect(vsock cid={cid} port={port}): {err}");
            }
        };
        let fd = std::os::fd::AsRawFd::as_raw_fd(&file);
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&SOCK_TIMEOUT as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&SOCK_TIMEOUT as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        file.write_all(encode_line(envelope)?.as_bytes())?;
        file.flush()?;
        let mut bytes = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match file.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    bytes.push(byte[0]);
                }
                // A per-attempt SO_RCVTIMEO expiry surfaces as EAGAIN/EWOULDBLOCK
                // on a blocking socket -- that's just this 5s slice ending with
                // nothing to read yet, not the agent going away. Keep waiting
                // until the caller's actual deadline instead of failing the
                // whole RPC on the first quiet interval, which is exactly what
                // starves a `Wait` for any container that takes longer than a
                // single socket-timeout window to exit.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) && std::time::Instant::now() < deadline =>
                {
                    continue;
                }
                Err(e) => return Err(e).context("reading container-agent response"),
            }
        }
        if bytes.is_empty() {
            bail!("container agent closed without a response");
        }
        decode_line(&String::from_utf8_lossy(&bytes)).context("decoding container-agent response")
    }
}

#[cfg(not(target_os = "linux"))]
async fn native_vsock_call(
    _cid: u32,
    _port: u32,
    _envelope: &ContainerEnvelope,
) -> Result<ContainerResponse> {
    bail!("native AF_VSOCK is supported on Linux only")
}

/// Small protocol-only helper used by unit tests and fuzzers without KVM.
pub fn decode_response(line: &str) -> Result<ContainerResponse> {
    decode_line(line).context("decoding container-agent response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_decode_is_strict() {
        let r = decode_response("{\"result\":\"pong\"}\n").unwrap();
        assert!(matches!(r, ContainerResponse::Pong));
        assert!(decode_response("not-json").is_err());
    }
}
