// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Host-side seccomp NOTIFY policy RPC listener (guest → host over AF_VSOCK).
//!
//! When a guest container uses `io.zyvor.seccomp.notify.mode=remote`, the
//! in-guest broker dials `VMADDR_CID_HOST` on
//! [`fluxvm_container_protocol::DEFAULT_SECCOMP_POLICY_PORT`] (or an annotated
//! override) and asks this listener for a deny/continue decision.
//!
//! Decision sources (first match wins):
//! 1. `FLUXVM_SECCOMP_POLICY_RPC_URL` — HTTP(S) POST of the request JSON;
//!    response body must be a [`SeccompPolicyRpcResponse`].
//! 2. `FLUXVM_SECCOMP_POLICY_RPC=continue` — always continue.
//! 3. Otherwise fail closed with deny (`EPERM`, or `FLUXVM_SECCOMP_POLICY_RPC_ERRNO`).
//!
//! Timeouts and broker errors deny. Syscall argument values are never accepted
//! on the wire (guest does not send them).

use anyhow::{Context, Result as AnyResult, bail};
use fluxvm_container_protocol::{
    SeccompPolicyRpcRequest, SeccompPolicyRpcResponse, DEFAULT_SECCOMP_POLICY_PORT, decode_line,
    encode_line,
};
use log::{info, warn};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::FromRawFd;
use std::os::unix::io::RawFd;
use std::sync::Once;
use std::time::Duration;

static START: Once = Once::new();

/// Start the host AF_VSOCK listener once per shim process.
pub fn ensure_started() {
    START.call_once(|| {
        std::thread::Builder::new()
            .name("fluxvm-seccomp-policy-rpc".into())
            .spawn(|| {
                if let Err(e) = listen_loop(DEFAULT_SECCOMP_POLICY_PORT) {
                    warn!("seccomp policy RPC listener stopped: {e:#}");
                }
            })
            .expect("spawn seccomp policy RPC listener");
        info!(
            "seccomp policy RPC listening on vsock port {}",
            DEFAULT_SECCOMP_POLICY_PORT
        );
    });
}

fn listen_loop(port: u32) -> AnyResult<()> {
    let listener = bind_vsock(port)?;
    loop {
        let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&addr) as libc::socklen_t;
        let client = unsafe {
            libc::accept(
                listener,
                &mut addr as *mut _ as *mut libc::sockaddr,
                &mut len,
            )
        };
        if client < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            bail!("accept seccomp policy RPC: {err}");
        }
        std::thread::spawn(move || {
            if let Err(e) = handle_client(client) {
                warn!("seccomp policy RPC client error: {e:#}");
            }
        });
    }
}

fn bind_vsock(port: u32) -> AnyResult<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        bail!(
            "socket(AF_VSOCK) for seccomp policy RPC: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = libc::VMADDR_CID_ANY;
    addr.svm_port = port;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        bail!("bind(vsock:{port}) seccomp policy RPC: {err}");
    }
    let rc = unsafe { libc::listen(fd, 128) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        bail!("listen(vsock:{port}) seccomp policy RPC: {err}");
    }
    Ok(fd)
}

fn handle_client(fd: RawFd) -> AnyResult<()> {
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut reader = BufReader::new(file.try_clone().context("clone policy RPC client")?);
    let mut writer = file;
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .context("reading seccomp policy RPC request")?;
    let req: SeccompPolicyRpcRequest =
        decode_line(line.trim_end()).context("decoding seccomp policy RPC request")?;
    let resp = decide(&req);
    let out = encode_line(&resp).context("encoding seccomp policy RPC response")?;
    writer
        .write_all(out.as_bytes())
        .context("writing seccomp policy RPC response")?;
    writer.flush().ok();
    Ok(())
}

pub(crate) fn decide(req: &SeccompPolicyRpcRequest) -> SeccompPolicyRpcResponse {
    let timeout = std::env::var("FLUXVM_SECCOMP_POLICY_RPC_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(2));

    if let Ok(url) = std::env::var("FLUXVM_SECCOMP_POLICY_RPC_URL") {
        if !url.is_empty() {
            match http_decide(&url, req, timeout) {
                Ok(resp) => return resp,
                Err(e) => {
                    warn!(
                        "seccomp policy RPC HTTP failed for container={} nr={}: {e:#}; denying",
                        req.container_id, req.syscall_nr
                    );
                    return deny_errno();
                }
            }
        }
    }

    match std::env::var("FLUXVM_SECCOMP_POLICY_RPC")
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "continue" | "allow" => SeccompPolicyRpcResponse::Continue,
        _ => deny_errno(),
    }
}

fn deny_errno() -> SeccompPolicyRpcResponse {
    let errno = std::env::var("FLUXVM_SECCOMP_POLICY_RPC_ERRNO")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|e| (1..=4095).contains(e))
        .unwrap_or(libc::EPERM);
    SeccompPolicyRpcResponse::Deny { errno }
}

fn http_decide(
    url: &str,
    req: &SeccompPolicyRpcRequest,
    timeout: Duration,
) -> AnyResult<SeccompPolicyRpcResponse> {
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .context("building seccomp policy HTTP client")?;
    let response = client
        .post(url)
        .json(req)
        .send()
        .context("POST seccomp policy RPC")?;
    if !response.status().is_success() {
        bail!("policy RPC HTTP status {}", response.status());
    }
    response
        .json::<SeccompPolicyRpcResponse>()
        .context("decoding policy RPC HTTP body")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn static_env_continue_and_default_deny() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: exclusive ENV_LOCK for this process's test threads.
        unsafe {
            std::env::set_var("FLUXVM_SECCOMP_POLICY_RPC", "continue");
            std::env::remove_var("FLUXVM_SECCOMP_POLICY_RPC_URL");
            std::env::remove_var("FLUXVM_SECCOMP_POLICY_RPC_ERRNO");
        }
        let resp = decide(&SeccompPolicyRpcRequest {
            container_id: "c".into(),
            notify_id: 1,
            pid: 1,
            syscall_nr: 1,
            arch: 0,
        });
        assert_eq!(resp, SeccompPolicyRpcResponse::Continue);

        unsafe {
            std::env::remove_var("FLUXVM_SECCOMP_POLICY_RPC");
        }
        let resp = decide(&SeccompPolicyRpcRequest {
            container_id: "c".into(),
            notify_id: 1,
            pid: 1,
            syscall_nr: 1,
            arch: 0,
        });
        assert_eq!(
            resp,
            SeccompPolicyRpcResponse::Deny {
                errno: libc::EPERM
            }
        );
    }
}
