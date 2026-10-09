// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Talking to a `vz` guest over SSH: run a command, read and write files.
//!
//! The sandbox API normally reaches a guest through the vsock guest agent. Virtualization.framework guests run stock cloud images
//! with no agent, so the daemon uses SSH instead, with a key of its own that cloud-init authorises at creation.

use anyhow::{Context, Result, bail};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, process::Command};

/// Largest file moved in or out in one call, matching the vsock agent's order of magnitude.
pub const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;

/// Where and how to reach one guest.
#[derive(Debug, Clone)]
pub struct GuestSsh {
    pub ip: String,
    pub user: String,
    pub key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// The daemon's own SSH key (`<dir>/sandbox_ed25519`), created on first use. Returns the public key text and the private key path.
pub fn ensure_key(dir: &Path) -> Result<(String, PathBuf)> {
    let key = dir.join("sandbox_ed25519");
    let public = dir.join("sandbox_ed25519.pub");
    if !key.exists() || !public.exists() {
        std::fs::create_dir_all(dir)?;
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&public);
        let ok = std::process::Command::new("ssh-keygen")
            .args([
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                "fluxvm-sandbox",
                "-f",
            ])
            .arg(&key)
            .status()
            .context("running ssh-keygen")?
            .success();
        if !ok {
            bail!("ssh-keygen failed");
        }
    }
    Ok((std::fs::read_to_string(&public)?.trim().to_owned(), key))
}

/// `'...'` with embedded quotes escaped, safe to put in a POSIX shell command.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn command(g: &GuestSsh) -> Command {
    let mut c = Command::new("ssh");
    c.arg("-i")
        .arg(&g.key)
        .args([
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=5",
        ])
        .arg(format!("{}@{}", g.user, g.ip))
        .kill_on_drop(true);
    c
}

/// Runs `script` with `sh -s` in the guest (the script goes in on stdin, so it needs no quoting) and returns its exit code and output.
pub async fn exec(g: &GuestSsh, script: &str, timeout: Duration) -> Result<ExecOutput> {
    let out = run(g, "sh -s", script.as_bytes(), timeout).await?;
    Ok(ExecOutput {
        exit_code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

async fn run(
    g: &GuestSsh,
    remote: &str,
    stdin: &[u8],
    timeout: Duration,
) -> Result<std::process::Output> {
    let mut child = command(g)
        .arg(remote)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running ssh (is the OpenSSH client installed?)")?;
    let mut input = child.stdin.take().context("ssh stdin")?;
    let data = stdin.to_vec();
    // Written from a task so a command that never reads its input cannot block the wait below.
    tokio::spawn(async move {
        let _ = input.write_all(&data).await;
        let _ = input.shutdown().await;
    });
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(out) => out.context("waiting for ssh"),
        Err(_) => bail!("the command did not finish within {}s", timeout.as_secs()),
    }
}

/// Waits until the guest accepts an SSH login.
pub async fn wait_ready(g: &GuestSsh, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if matches!(exec(g, "true", Duration::from_secs(10)).await, Ok(o) if o.exit_code == 0) {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!(
                "the guest did not accept an SSH login within {}s",
                timeout.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Reads a guest file: its bytes and permission bits.
pub async fn read_file(g: &GuestSsh, path: &str) -> Result<(Vec<u8>, u32)> {
    let q = shell_quote(path);
    // First line: the octal mode; the rest: the file.
    let script = format!("m=$(stat -c %a -- {q}) || exit 1; echo \"$m\"; cat -- {q}");
    let out = run(g, "sh -s", script.as_bytes(), Duration::from_secs(60)).await?;
    if !out.status.success() {
        bail!(
            "cannot read {path}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    parse_read_output(&out.stdout)
}

pub(crate) fn parse_read_output(raw: &[u8]) -> Result<(Vec<u8>, u32)> {
    let nl = raw
        .iter()
        .position(|&b| b == b'\n')
        .context("the guest sent no file header")?;
    let mode = u32::from_str_radix(std::str::from_utf8(&raw[..nl])?.trim(), 8)
        .context("the guest sent an invalid file mode")?;
    let data = raw[nl + 1..].to_vec();
    if data.len() > MAX_FILE_BYTES {
        bail!(
            "file is {} bytes; the limit is {MAX_FILE_BYTES}",
            data.len()
        );
    }
    Ok((data, mode))
}

/// Writes a guest file (creating parent directories) with the given permission bits.
pub async fn write_file(g: &GuestSsh, path: &str, data: &[u8], mode: u32) -> Result<()> {
    if data.len() > MAX_FILE_BYTES {
        bail!(
            "file is {} bytes; the limit is {MAX_FILE_BYTES}",
            data.len()
        );
    }
    let q = shell_quote(path);
    let remote = format!(
        "mkdir -p -- \"$(dirname -- {q})\" && cat > {q} && chmod {:o} -- {q}",
        mode & 0o7777
    );
    let out = run(g, &remote, data, Duration::from_secs(60)).await?;
    if !out.status.success() {
        bail!(
            "cannot write {path}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_survives_spaces_and_quotes() {
        assert_eq!(shell_quote("/tmp/a b"), "'/tmp/a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
    }

    #[test]
    fn read_output_splits_mode_from_contents() {
        let (data, mode) = parse_read_output(b"644\nhello\nworld\n").unwrap();
        assert_eq!(mode, 0o644);
        assert_eq!(data, b"hello\nworld\n");
        let (data, mode) = parse_read_output(b"755\n").unwrap();
        assert_eq!((data.len(), mode), (0, 0o755));
        assert!(parse_read_output(b"no newline").is_err());
        assert!(parse_read_output(b"zz\nx").is_err());
    }

    #[test]
    fn the_key_is_created_once_and_reused() {
        if std::process::Command::new("ssh-keygen")
            .arg("-?")
            .output()
            .is_err()
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (a, path) = ensure_key(dir.path()).unwrap();
        assert!(a.starts_with("ssh-ed25519 "));
        let (b, _) = ensure_key(dir.path()).unwrap();
        assert_eq!(a, b);
        assert!(path.ends_with("sandbox_ed25519"));
    }
}
