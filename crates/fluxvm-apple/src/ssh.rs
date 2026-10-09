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
    /// Reach sshd over the runner's vsock proxy instead of the network (for guests with no network card).
    pub vsock: Option<PathBuf>,
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

/// ssh's ProxyCommand for a guest with no network: `fluxctl vsock-proxy <runner socket> 22` asks the runner for the guest's vsock
/// port 22 (sshd listens there by itself on systemd 256+ images) and relays stdin/stdout. A built-in relay rather than `nc`,
/// whose buffering and half-close behaviour differ between systems.
pub fn proxy_command(exe: &Path, sock: &Path) -> String {
    format!(
        "{} vsock-proxy {} 22",
        shell_quote(&exe.to_string_lossy()),
        shell_quote(&sock.to_string_lossy())
    )
}

/// The relay itself: connect to the runner's proxy socket, ask for `port`, then copy both ways until either side closes.
pub fn vsock_proxy(sock: &Path, port: u32) -> Result<()> {
    use std::io::{Read, Write};
    let mut s = std::os::unix::net::UnixStream::connect(sock)
        .with_context(|| format!("connecting to {}", sock.display()))?;
    s.write_all(format!("CONNECT {port} QUIET\n").as_bytes())?;
    let mut to_guest = s.try_clone()?;
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 32 * 1024];
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 || to_guest.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        let _ = to_guest.shutdown(std::net::Shutdown::Write);
    });
    let mut stdout = std::io::stdout().lock();
    let mut buf = [0u8; 32 * 1024];
    while let Ok(n) = s.read(&mut buf) {
        if n == 0 || stdout.write_all(&buf[..n]).is_err() || stdout.flush().is_err() {
            break;
        }
    }
    Ok(())
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
        .kill_on_drop(true);
    if let Some(sock) = &g.vsock {
        let exe = std::env::current_exe().unwrap_or_else(|_| "fluxctl".into());
        c.arg("-o")
            .arg(format!("ProxyCommand={}", proxy_command(&exe, sock)));
    }
    c.arg(format!("{}@{}", g.user, g.ip));
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
    fn the_vsock_proxy_command_quotes_the_socket_path() {
        let c = proxy_command(
            Path::new("/opt/fluxvm bin/fluxctl"),
            Path::new("/tmp/with space/v.sock"),
        );
        assert_eq!(
            c,
            "'/opt/fluxvm bin/fluxctl' vsock-proxy '/tmp/with space/v.sock' 22"
        );
        let g = GuestSsh {
            ip: "vsock".into(),
            user: "u".into(),
            key: "/k".into(),
            vsock: Some("/tmp/v.sock".into()),
        };
        let args: Vec<String> = command(&g)
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.iter().any(|a| a.starts_with("ProxyCommand=")));
        assert_eq!(args.last().unwrap(), "u@vsock");
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
