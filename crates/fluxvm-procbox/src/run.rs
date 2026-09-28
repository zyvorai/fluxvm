// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Spawn a confined child and report what happened.

use crate::policy::{Enforcement, Policy};
use anyhow::Result;
use serde::Serialize;

/// Per-run edits to the default seccomp denylist (from a profile's
/// `syscall_deny` / `syscall_allow`). Names are resolved by
/// `seccomp::syscall_by_name`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyscallOverrides {
    pub deny: Vec<String>,
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Capture stdout/stderr into the result (stdin is closed). Otherwise the
    /// child inherits the parent's stdio.
    pub capture: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    /// Signal that terminated the child, if any.
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub output_truncated: bool,
    pub wall_ms: u64,
    pub enforcement: Enforcement,
}

impl RunResult {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }
}

/// Environment for the child: `PATH` and `HOME` only when `clean_env`, plus
/// the policy's explicit variables.
pub fn build_env(policy: &Policy) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if policy.clean_env {
        env.push((
            "PATH".to_string(),
            "/usr/local/bin:/usr/bin:/bin".to_string(),
        ));
        env.push(("HOME".to_string(), "/tmp".to_string()));
    }
    env.extend(policy.env.iter().cloned());
    env
}

/// Run `argv` confined by `policy` with the default seccomp denylist.
pub fn run(policy: &Policy, argv: &[String], opts: &RunOptions) -> Result<RunResult> {
    run_with(policy, &SyscallOverrides::default(), argv, opts)
}

/// Like [`run`], with edits to the seccomp denylist.
#[cfg(target_os = "linux")]
pub fn run_with(
    policy: &Policy,
    overrides: &SyscallOverrides,
    argv: &[String],
    opts: &RunOptions,
) -> Result<RunResult> {
    imp::run(policy, overrides, argv, opts)
}

#[cfg(not(target_os = "linux"))]
pub fn run_with(
    _policy: &Policy,
    _overrides: &SyscallOverrides,
    _argv: &[String],
    _opts: &RunOptions,
) -> Result<RunResult> {
    anyhow::bail!("fluxvm-procbox only runs on Linux (Landlock and seccomp)")
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::{landlock, seccomp};
    use anyhow::{bail, Context};
    use std::io::{self, Read};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Command, Stdio};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    #[derive(Clone, Copy)]
    struct Limits {
        memory: Option<u64>,
        nproc: Option<u64>,
        cpu: Option<u64>,
    }

    macro_rules! set_limit {
        ($res:expr, $val:expr) => {{
            let rl = libc::rlimit {
                rlim_cur: $val as libc::rlim_t,
                rlim_max: $val as libc::rlim_t,
            };
            if unsafe { libc::setrlimit($res, &rl) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }};
    }

    /// Async-signal-safe: only `setrlimit` calls.
    fn apply_rlimits(l: &Limits) -> io::Result<()> {
        set_limit!(libc::RLIMIT_CORE, 0u64);
        if let Some(v) = l.memory {
            set_limit!(libc::RLIMIT_AS, v);
        }
        if let Some(v) = l.nproc {
            set_limit!(libc::RLIMIT_NPROC, v);
        }
        if let Some(v) = l.cpu {
            set_limit!(libc::RLIMIT_CPU, v);
        }
        Ok(())
    }

    fn read_capped<R: Read + Send + 'static>(mut r: R, cap: usize) -> JoinHandle<(Vec<u8>, bool)> {
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut truncated = false;
            let mut buf = [0u8; 8192];
            loop {
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let room = cap.saturating_sub(out.len());
                        if n > room {
                            truncated = true;
                        }
                        out.extend_from_slice(&buf[..n.min(room)]);
                    }
                }
            }
            (out, truncated)
        })
    }

    pub fn run(
        policy: &Policy,
        overrides: &SyscallOverrides,
        argv: &[String],
        opts: &RunOptions,
    ) -> Result<RunResult> {
        if argv.is_empty() {
            bail!("no command given");
        }

        // Everything fallible or allocating happens here, in the parent.
        let mut plan = landlock::plan(policy, landlock::kernel_abi())?;
        let (prepared, notes) = landlock::prepare(&plan, policy)?;
        plan.enforcement.not_enforced.extend(notes);

        let programs = match policy.seccomp {
            Some(mode) => {
                plan.enforcement.seccomp = true;
                seccomp::compile_with(
                    mode,
                    policy.allow_namespaces,
                    &overrides.deny,
                    &overrides.allow,
                )?
            }
            None => {
                plan.enforcement
                    .not_enforced
                    .push("seccomp denylist (disabled by policy)".into());
                Vec::new()
            }
        };
        let limits = Limits {
            memory: policy.max_memory,
            nproc: policy.max_processes,
            cpu: policy.cpu_seconds,
        };
        let ll_fd = prepared.as_ref().map(|p| p.raw_fd());

        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        if policy.clean_env {
            cmd.env_clear();
        }
        for (k, v) in build_env(policy) {
            cmd.env(k, v);
        }
        if let Some(cwd) = &policy.cwd {
            cmd.current_dir(cwd);
        }
        if opts.capture {
            cmd.stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
        cmd.process_group(0);

        // SAFETY: the closure only makes raw syscalls on data prepared above
        // (setrlimit, prctl, landlock_restrict_self, seccomp). Order matters:
        // limits, no_new_privs, Landlock, and seccomp last so the filter does
        // not have to allow the setup calls above.
        unsafe {
            cmd.pre_exec(move || {
                apply_rlimits(&limits)?;
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if let Some(fd) = ll_fd {
                    landlock::restrict_self(fd)?;
                }
                seccomp::apply(&programs)?;
                Ok(())
            });
        }

        let start = Instant::now();
        let mut child = cmd.spawn().with_context(|| {
            format!(
                "failed to start {:?} inside the sandbox (the command and its libraries must be \
                 under a --read/--write path)",
                argv[0]
            )
        })?;
        drop(prepared);

        let pgid = child.id() as i32;
        let cap = policy.max_output_bytes;
        let out_reader = child.stdout.take().map(|s| read_capped(s, cap));
        let err_reader = child.stderr.take().map(|s| read_capped(s, cap));

        let deadline = policy.timeout_secs.map(|s| start + Duration::from_secs(s));
        let mut timed_out = false;
        let status = loop {
            if let Some(st) = child.try_wait().context("waiting for child")? {
                break st;
            }
            if let Some(d) = deadline {
                if !timed_out && Instant::now() >= d {
                    timed_out = true;
                    unsafe { libc::kill(-pgid, libc::SIGKILL) };
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        // Reap anything the child left behind in its process group so no
        // sandboxed process outlives the run (and pipe readers can finish).
        unsafe { libc::kill(-pgid, libc::SIGKILL) };

        let (mut stdout, mut truncated) = (Vec::new(), false);
        if let Some(h) = out_reader {
            if let Ok((b, t)) = h.join() {
                stdout = b;
                truncated |= t;
            }
        }
        let mut stderr = Vec::new();
        if let Some(h) = err_reader {
            if let Ok((b, t)) = h.join() {
                stderr = b;
                truncated |= t;
            }
        }

        Ok(RunResult {
            exit_code: status.code(),
            signal: status.signal(),
            timed_out,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            output_truncated: truncated,
            wall_ms: start.elapsed().as_millis() as u64,
            enforcement: plan.enforcement,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_env_keeps_only_a_minimal_path_and_explicit_vars() {
        let mut p = Policy::default();
        p.clean_env = true;
        p.env = vec![("FOO".into(), "bar".into())];
        let env = build_env(&p);
        assert!(env.iter().any(|(k, _)| k == "PATH"));
        assert!(env.contains(&("FOO".into(), "bar".into())));
        assert_eq!(env.len(), 3);
    }

    #[test]
    fn inherited_env_adds_only_explicit_vars() {
        let mut p = Policy::default();
        p.env = vec![("A".into(), "1".into())];
        assert_eq!(build_env(&p), vec![("A".to_string(), "1".to_string())]);
    }
}
