// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Host-side QEMU guest-agent helpers (Zyvor/GuestKit Windows agent channel).

use anyhow::{Context, Result, bail};
use guestkit::agent::qga_client::{call_qga_socket, qga_request};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const EXEC_POLL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QgaExecResult {
    pub exit_code: i64,
    pub stdout: String,
    pub stderr: String,
}

pub fn ping(socket: &Path) -> Result<()> {
    let _ = call_qga_socket(
        &socket.display().to_string(),
        "guest-ping",
        None,
        DEFAULT_TIMEOUT,
    )
    .with_context(|| format!("QGA guest-ping on {}", socket.display()))?;
    Ok(())
}

/// Run `path` with `args` via `guest-exec`, wait for completion, return output.
pub fn exec(
    socket: &Path,
    path: &str,
    args: &[String],
    timeout: Duration,
) -> Result<QgaExecResult> {
    let sock = socket.display().to_string();
    let start = call_qga_socket(
        &sock,
        "guest-exec",
        Some(json!({
            "path": path,
            "arg": args,
            "capture-output": true,
        })),
        timeout,
    )
    .context("QGA guest-exec")?;
    let pid = start
        .get("return")
        .and_then(|r| r.get("pid"))
        .and_then(|p| p.as_i64())
        .context("guest-exec response missing return.pid")?;

    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            bail!("QGA guest-exec timed out waiting for pid {pid}");
        }
        let status = call_qga_socket(
            &sock,
            "guest-exec-status",
            Some(json!({ "pid": pid })),
            timeout,
        )
        .context("QGA guest-exec-status")?;
        let ret = status.get("return").cloned().unwrap_or(Value::Null);
        let exited = ret.get("exited").and_then(|v| v.as_bool()).unwrap_or(false);
        if !exited {
            thread::sleep(EXEC_POLL);
            continue;
        }
        let exit_code = ret.get("exitcode").and_then(|v| v.as_i64()).unwrap_or(-1);
        let stdout = decode_b64_field(&ret, "out-data");
        let stderr = decode_b64_field(&ret, "err-data");
        return Ok(QgaExecResult {
            exit_code,
            stdout,
            stderr,
        });
    }
}

fn decode_b64_field(ret: &Value, key: &str) -> String {
    ret.get(key)
        .and_then(|v| v.as_str())
        .and_then(|s| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(s)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
        })
        .unwrap_or_default()
}

/// Convenience: `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command …`
pub fn powershell(socket: &Path, command: &str, timeout: Duration) -> Result<QgaExecResult> {
    exec(
        socket,
        "powershell.exe",
        &[
            "-NoProfile".into(),
            "-ExecutionPolicy".into(),
            "Bypass".into(),
            "-Command".into(),
            command.into(),
        ],
        timeout,
    )
}

pub fn firewall_open(
    socket: &Path,
    name: &str,
    port: u16,
    protocol: &str,
    timeout: Duration,
) -> Result<QgaExecResult> {
    let proto = protocol.to_ascii_uppercase();
    let cmd = format!(
        "New-NetFirewallRule -DisplayName '{name}' -Direction Inbound -Protocol {proto} \
         -LocalPort {port} -Action Allow -ErrorAction Stop | Out-Null; \
         Write-Output 'opened {name} {proto}/{port}'"
    );
    powershell(socket, &cmd, timeout)
}

pub fn firewall_close(socket: &Path, name: &str, timeout: Duration) -> Result<QgaExecResult> {
    let cmd = format!(
        "Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction Stop; \
         Write-Output 'closed {name}'"
    );
    powershell(socket, &cmd, timeout)
}

/// Low-level raw QGA JSON (for advanced callers).
pub fn raw(
    socket: &Path,
    execute: &str,
    arguments: Option<Value>,
    timeout: Duration,
) -> Result<Value> {
    let _ = qga_request(execute, arguments.clone());
    call_qga_socket(&socket.display().to_string(), execute, arguments, timeout)
}
