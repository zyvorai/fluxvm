// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Bounded packet capture for a Kairon capture session: `tcpdump` on the VM's
//! dataplane interface, writing a pcap the API serves once it finishes.

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// Bytes kept per packet and packets per capture: at most ~32 MiB of pcap.
pub const SNAPLEN: u32 = 1600;
pub const MAX_PACKETS: u32 = 20_000;
const MAX_FILTER: usize = 512;
const MAX_TOKEN: usize = 128;

pub const STATE_RUNNING: &str = "running";
pub const STATE_DONE: &str = "done";
pub const STATE_FAILED: &str = "failed";
pub const STATE_INTERRUPTED: &str = "interrupted";

/// The token names the pcap file; the filter is handed to tcpdump as one argument.
pub fn validate(token: &str, filter: &str) -> Result<()> {
    if token.is_empty() || token.len() > MAX_TOKEN {
        bail!("capture token must be 1-{MAX_TOKEN} characters");
    }
    if !token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("capture token may only contain letters, digits, '-' and '_'");
    }
    if filter.len() > MAX_FILTER {
        bail!("capture filter must be at most {MAX_FILTER} bytes");
    }
    if filter.bytes().any(|b| b.is_ascii_control()) {
        bail!("capture filter contains control characters");
    }
    Ok(())
}

fn command(iface: &str, file: &Path, filter: &str) -> Command {
    let mut cmd = crate::netns_scope::command("tcpdump");
    cmd.args(["-i", iface, "-n", "-U", "-Z", "root"])
        .args(["-s", &SNAPLEN.to_string(), "-c", &MAX_PACKETS.to_string()])
        .arg("-w")
        .arg(file);
    let filter = filter.trim();
    if !filter.is_empty() {
        cmd.arg("--").arg(filter);
    }
    cmd
}

/// Starts tcpdump in the current netns scope. A bad filter or a missing
/// tcpdump fails here, so the caller can reject the session.
pub fn spawn(iface: &str, file: &Path, filter: &str) -> Result<Child> {
    let mut child = command(iface, file, filter)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting tcpdump; is it installed?")?;
    thread::sleep(Duration::from_millis(300));
    if let Some(status) = child.try_wait()? {
        let err = read_stderr(&mut child);
        bail!(
            "tcpdump exited with {status}: {}",
            last_line(&err).unwrap_or("no output")
        );
    }
    Ok(child)
}

pub struct Outcome {
    pub state: &'static str,
    pub packets: u64,
    pub error: String,
}

/// Lets the capture run for `seconds` (or until it hits `MAX_PACKETS`), then
/// stops it with SIGINT so tcpdump flushes the pcap.
pub fn wait(mut child: Child, seconds: u32) -> Outcome {
    let deadline = Instant::now() + Duration::from_secs(u64::from(seconds));
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(200)),
            Ok(None) => {
                interrupt(&mut child);
                break;
            }
            Err(e) => return failed(format!("waiting for tcpdump: {e}")),
        }
    }
    let err = read_stderr(&mut child);
    match child.wait() {
        Ok(status) if status.success() => Outcome {
            state: STATE_DONE,
            packets: parse_packets(&err),
            error: String::new(),
        },
        Ok(status) => failed(format!(
            "tcpdump exited with {status}: {}",
            last_line(&err).unwrap_or("no output")
        )),
        Err(e) => failed(format!("waiting for tcpdump: {e}")),
    }
}

fn interrupt(child: &mut Child) {
    // SAFETY: kill(2) on our own child's pid; it has not been reaped yet.
    unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGINT) };
    let grace = Instant::now() + Duration::from_secs(5);
    while Instant::now() < grace {
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
}

fn failed(error: String) -> Outcome {
    Outcome {
        state: STATE_FAILED,
        packets: 0,
        error,
    }
}

fn read_stderr(child: &mut Child) -> String {
    let mut out = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut out);
    }
    out
}

fn last_line(s: &str) -> Option<&str> {
    s.lines().map(str::trim).rfind(|l| !l.is_empty())
}

/// `N packets captured` from tcpdump's exit summary.
pub fn parse_packets(stderr: &str) -> u64 {
    stderr
        .lines()
        .find(|l| l.contains("packets captured") || l.contains("packet captured"))
        .and_then(|l| l.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_token_and_filter() {
        assert!(validate("c0ffee-01_a", "tcp port 443").is_ok());
        assert!(validate("", "").is_err());
        assert!(validate("../etc", "").is_err());
        assert!(validate("a b", "").is_err());
        assert!(validate("ok", "tcp\nport 1").is_err());
        assert!(validate("ok", &"x".repeat(MAX_FILTER + 1)).is_err());
    }

    #[test]
    fn filter_is_one_argument_after_double_dash() {
        let cmd = command("vh1234", Path::new("/tmp/t.pcap"), " -w /etc/passwd ");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let dd = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(args[dd + 1..], ["-w /etc/passwd".to_string()]);
        assert_eq!(args.iter().filter(|a| *a == "-w").count(), 1);
    }

    #[test]
    fn no_filter_means_no_expression() {
        let cmd = command("tap0", Path::new("/tmp/t.pcap"), "  ");
        assert!(!cmd.get_args().any(|a| a == "--"));
    }

    #[test]
    fn parses_tcpdump_summary() {
        let err = "tcpdump: listening on vh1, link-type EN10MB\n42 packets captured\n45 packets received by filter\n0 packets dropped by kernel\n";
        assert_eq!(parse_packets(err), 42);
        assert_eq!(parse_packets("1 packet captured\n"), 1);
        assert_eq!(parse_packets(""), 0);
    }
}
