// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::backend::{LaunchContext, path_arg};
use crate::config::Config;
use anyhow::{Context, Result, bail};
use std::{fs::OpenOptions, path::Path, process::Stdio, time::Duration};
use tokio::process::{Child, Command};

/// How long `wait_for_socket_ready` waits for a sidecar's listening socket
/// (`swtpm`, and formerly this crate's own copy of the wait used by
/// `fluxvm-qemu`'s `virtiofsd` spawn loop) to appear before giving up.
const SIDECAR_SOCKET_TIMEOUT: Duration = Duration::from_secs(15);

/// `Command::output` with a short retry on Linux ETXTBSY (os error 26).
/// Freshly written shell-script fixtures on GitHub-hosted runners can race
/// the first exec against a still-busy text inode; one or two retries clear it.
async fn command_output_retry_etxtbsy(
    program: &str,
    args: &[String],
) -> std::io::Result<std::process::Output> {
    const ATTEMPTS: u32 = 5;
    let mut last = None;
    for attempt in 0..ATTEMPTS {
        match Command::new(program).args(args).output().await {
            Ok(out) => return Ok(out),
            Err(e) if e.raw_os_error() == Some(26) && attempt + 1 < ATTEMPTS => {
                tokio::time::sleep(Duration::from_millis(25 * (attempt as u64 + 1))).await;
                last = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::from_raw_os_error(26)))
}

pub async fn run_checked(program: &str, args: &[String]) -> Result<()> {
    let out = command_output_retry_etxtbsy(program, args)
        .await
        .with_context(|| format!("starting {program}"))?;
    if !out.status.success() {
        bail!(
            "{} failed ({}): {}",
            program,
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// Like `run_checked`, but bounded — used for calls to a VMM's own control
/// CLI (e.g. `ch-remote`), where a wedged VMM must not hang the caller
/// forever.
pub async fn run_checked_timeout(
    program: &str,
    args: &[String],
    timeout: std::time::Duration,
) -> Result<()> {
    tokio::time::timeout(timeout, run_checked(program, args))
        .await
        .with_context(|| format!("{program} timed out after {timeout:?}"))?
}

pub async fn output_checked(program: &str, args: &[String]) -> Result<String> {
    let out = command_output_retry_etxtbsy(program, args)
        .await
        .with_context(|| format!("starting {program}"))?;
    if !out.status.success() {
        bail!(
            "{} failed: {}",
            program,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Like `output_checked`, but bounded — same rationale as
/// `run_checked_timeout`: a call that both needs a VMM control CLI's
/// stdout *and* can't risk hanging forever against a wedged VMM (e.g.
/// `ch-remote info`, read before a resize to learn the VM's current live
/// vCPU/memory count).
pub async fn output_checked_timeout(
    program: &str,
    args: &[String],
    timeout: std::time::Duration,
) -> Result<String> {
    tokio::time::timeout(timeout, output_checked(program, args))
        .await
        .with_context(|| format!("{program} timed out after {timeout:?}"))?
}

/// When `netns` is `Some`, rewrites `(program, args)` into `("ip", ["netns",
/// "exec", netns, program, ...args])` so the eventual `spawn_logged` call
/// launches the VMM (or, for a jailed Firecracker VM, `jailer` — `ip netns
/// exec` + `setns()` + `exec()` compose fine, the whole process tree stays
/// in the namespace across jailer's own exec into Firecracker) inside that
/// network namespace instead of the host's default one. A no-op passthrough
/// when `netns` is `None`, so every backend can call this unconditionally.
pub fn netns_wrap(netns: Option<&str>, program: &str, args: &[String]) -> (String, Vec<String>) {
    match netns {
        Some(ns) => {
            let mut wrapped = vec![
                "netns".to_string(),
                "exec".to_string(),
                ns.to_string(),
                program.to_string(),
            ];
            wrapped.extend(args.iter().cloned());
            ("ip".to_string(), wrapped)
        }
        None => (program.to_string(), args.to_vec()),
    }
}

pub async fn spawn_logged(program: &str, args: &[String], log: &Path) -> Result<Child> {
    spawn_logged_with_env(program, args, log, &[]).await
}

pub async fn spawn_logged_with_env(
    program: &str,
    args: &[String],
    log: &Path,
    env: &[(&str, &str)],
) -> Result<Child> {
    let stdout = OpenOptions::new().create(true).append(true).open(log)?;
    let stderr = stdout.try_clone()?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .process_group(0);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.spawn().with_context(|| format!("spawning {program}"))
}

/// Polls `process_alive` every 100ms, up to `attempts` times, returning
/// `true` as soon as the process is gone (or `false` if it's still alive
/// after the last attempt). Public so callers like a graceful-shutdown path
/// can wait a bounded amount before falling back to a forceful stop.
pub async fn wait_for_exit(pid: u32, attempts: u32) -> bool {
    for _ in 0..attempts {
        if !process_alive(pid).await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

/// Sends SIGTERM and waits for the process to actually exit (escalating to
/// SIGKILL after a grace period) so callers can safely reclaim resources the
/// process held, e.g. a TAP device's file descriptor, once this returns.
pub async fn terminate_pid(pid: u32) -> Result<()> {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .await
        .context("running kill")?;
    if !status.success() {
        bail!("failed to terminate pid {pid}");
    }
    if wait_for_exit(pid, 50).await {
        return Ok(());
    }
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg(pid.to_string())
        .status()
        .await;
    if wait_for_exit(pid, 20).await {
        return Ok(());
    }
    bail!("pid {pid} did not exit after SIGTERM/SIGKILL");
}

/// Polls `socket` for a listening child process (`pid`) to become ready --
/// existence + liveness, then a brief settle-then-recheck once it appears
/// (a virtiofsd/swtpm-shaped subprocess can create the socket and still
/// exit right after, e.g. capability sync failing under
/// NoNewPrivileges). SIGKILLs `pid` and returns an error on any failure
/// path (timeout, the process died before the socket appeared, or it died
/// right after) -- never leaves `pid` running on an `Err` return. Does not
/// touch any other already-spawned sibling process; a caller with its own
/// accumulated pids list (e.g. `fluxvm-qemu`'s `spawn_virtiofsd_instances`)
/// is responsible for killing those itself on error. Shared here (rather
/// than living in one backend crate) because both the QEMU and Cloud
/// Hypervisor backends spawn a `swtpm` sidecar via `spawn_swtpm` below.
pub async fn wait_for_socket_ready(
    pid: u32,
    socket: &Path,
    timeout: Duration,
    what: &str,
    log: &Path,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
            anyhow::bail!(
                "{what}: socket {} not ready within {:?}; see {}",
                socket.display(),
                timeout,
                log.display()
            );
        }
        let alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
        if !alive {
            anyhow::bail!(
                "{what}: exited before socket was ready; see {}",
                log.display()
            );
        }
        if socket.exists() {
            // Brief settle so bind/listen completes after the inode appears,
            // then re-check liveness — the child can create the socket and
            // still exit right after.
            tokio::time::sleep(Duration::from_millis(250)).await;
            let still_alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
            if !still_alive {
                anyhow::bail!(
                    "{what}: exited right after creating socket; see {}",
                    log.display()
                );
            }
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Spawns the `swtpm` sidecar backing `req.tpm`, listening on
/// `<workspace>/swtpm.sock` -- the socket both the QEMU backend
/// (`-chardev socket,id=chrtpm,...`) and the Cloud Hypervisor backend
/// (`--tpm socket=...`) point their own TPM device wiring at. TPM state
/// (NVRAM/keys) is written to `<workspace>/tpm/`, which persists for the
/// VM's lifetime (deleted only on VM delete, same as the disk file) --
/// unlike this function's own return value, which is a fresh process
/// spawned on every `launch()` call (create and every subsequent start),
/// mirroring `virtiofsd`'s respawn-every-launch model rather than
/// `qemu-nbd`'s kept-alive-across-stop model.
pub async fn spawn_swtpm(cfg: &Config, ctx: &LaunchContext) -> Result<u32> {
    let tpm_dir = ctx.workspace.join("tpm");
    tokio::fs::create_dir_all(&tpm_dir)
        .await
        .context("creating swtpm state directory")?;
    let sock = ctx.workspace.join("swtpm.sock");
    // Stale socket from a previous failed launch -- same reasoning as
    // virtiofsd's own stale-socket cleanup has for its own sockets.
    let _ = tokio::fs::remove_file(&sock).await;
    let args = vec![
        "socket".to_string(),
        "--tpmstate".to_string(),
        format!("dir={}", path_arg(&tpm_dir)),
        "--ctrl".to_string(),
        format!("type=unixio,path={}", path_arg(&sock)),
        "--tpm2".to_string(),
    ];
    let log = ctx.workspace.join("swtpm.log");
    let child = spawn_logged(&cfg.swtpm_binary, &args, &log)
        .await
        .context("spawning swtpm")?;
    let Some(pid) = child.id() else {
        anyhow::bail!("swtpm exited before PID was available");
    };
    wait_for_socket_ready(pid, &sock, SIDECAR_SOCKET_TIMEOUT, "swtpm", &log).await?;
    Ok(pid)
}

/// Closes a raw fd handed off to a VMM child (e.g. a macvtap device fd) once
/// it has been inherited across exec; the parent no longer needs its copy.
pub fn close_fd(fd: i32) {
    unsafe {
        libc::close(fd);
    }
}

pub async fn process_alive(pid: u32) -> bool {
    // A dead pid is an expected, common result (e.g. while polling for exit
    // in terminate_pid), so capture output rather than let `kill`'s "No such
    // process" message leak to our stderr on every negative check.
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netns_wrap_passes_through_unchanged_when_no_namespace() {
        let (program, args) = netns_wrap(None, "qemu-system-x86_64", &["-m".into(), "512".into()]);
        assert_eq!(program, "qemu-system-x86_64");
        assert_eq!(args, vec!["-m".to_string(), "512".to_string()]);
    }

    #[test]
    fn netns_wrap_prefixes_ip_netns_exec_when_namespaced() {
        let (program, args) = netns_wrap(
            Some("eph-abcd1234"),
            "qemu-system-x86_64",
            &["-m".into(), "512".into()],
        );
        assert_eq!(program, "ip");
        assert_eq!(
            args,
            vec![
                "netns",
                "exec",
                "eph-abcd1234",
                "qemu-system-x86_64",
                "-m",
                "512"
            ]
        );
    }
}
