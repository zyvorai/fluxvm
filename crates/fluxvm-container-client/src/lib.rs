// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use fluxvm_container_protocol::{
    ContainerEnvelope, ContainerRequest, ContainerResponse, DEFAULT_CONTAINER_AGENT_PORT,
    decode_line, encode_line,
};
use fluxvm_core::model::{BackendKind, VmRecord};
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

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
            BackendKind::Qemu => native_vsock_call(cid, DEFAULT_CONTAINER_AGENT_PORT, &envelope).await,
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
    write_half.write_all(encode_line(envelope)?.as_bytes()).await?;
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
) -> Result<ContainerResponse> {
    let envelope = envelope.clone();
    tokio::task::spawn_blocking(move || native_vsock_call_blocking(cid, port, &envelope))
        .await
        .context("vsock worker panicked")?
}

#[cfg(target_os = "linux")]
fn native_vsock_call_blocking(
    cid: u32,
    port: u32,
    envelope: &ContainerEnvelope,
) -> Result<ContainerResponse> {
    use std::io::{Read, Write};
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
            bail!("connect(vsock cid={cid} port={port}): {}", std::io::Error::last_os_error());
        }
        let tv = libc::timeval { tv_sec: 20, tv_usec: 0 };
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
        file.write_all(encode_line(envelope)?.as_bytes())?;
        file.flush()?;
        let mut bytes = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = file.read(&mut byte)?;
            if n == 0 || byte[0] == b'\n' { break; }
            bytes.push(byte[0]);
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
