// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use fluxvm_procbox::learn::{self, LearnOptions};
use fluxvm_procbox::{
    parse_size, Policy, Profile, RunOptions, SeccompMode, SyscallOverrides, TcpRule,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "fluxvm-procbox",
    version,
    about = "Rootless Landlock + seccomp process sandbox"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a command inside the sandbox.
    Run(RunArgs),
    /// Run a command unconfined but observed, and write the profile that
    /// would allow exactly what it did. The program really runs, with its
    /// real side effects: use a disposable environment.
    Learn(LearnArgs),
    /// Work with TOML policy profiles.
    #[command(subcommand)]
    Profile(ProfileCmd),
    /// Show which protections this kernel can enforce.
    Probe {
        #[arg(long)]
        json: bool,
    },
    #[command(hide = true)]
    Selftest { op: String, arg: Option<String> },
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Parse a profile, check every key and path, and summarize it.
    Validate {
        /// A path, or a name looked up in $XDG_CONFIG_HOME/fluxvm-procbox/profiles.
        profile: String,
    },
}

#[derive(Args)]
struct LearnArgs {
    /// Write the profile here instead of stdout (the program's own stdout
    /// then goes to stderr so the profile stays clean).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Overwrite --out if it exists.
    #[arg(long)]
    force: bool,
    /// Kill the program after this many seconds.
    #[arg(short = 't', long = "timeout")]
    timeout: Option<u64>,
    /// Working directory for the command.
    #[arg(long)]
    cwd: Option<PathBuf>,
    /// Extra environment variable KEY=VALUE; repeatable.
    #[arg(long = "env")]
    env: Vec<String>,
    /// Print the full observation and profile as JSON instead of TOML.
    #[arg(long)]
    json: bool,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Args)]
struct RunArgs {
    /// Start from a TOML profile: a path, or a name in
    /// $XDG_CONFIG_HOME/fluxvm-procbox/profiles. Flags below are applied on
    /// top: lists (-r, -w, --env) are added to, scalars replace.
    #[arg(short = 'p', long = "profile")]
    profile: Option<String>,
    /// Read-only (and executable) path; repeatable.
    #[arg(short = 'r', long = "read")]
    read: Vec<PathBuf>,
    /// Read-write path; repeatable.
    #[arg(short = 'w', long = "write")]
    write: Vec<PathBuf>,
    /// Allow outbound TCP connect to this port only; repeatable.
    #[arg(long = "net-port")]
    net_port: Vec<u16>,
    /// Allow binding this TCP port only; repeatable.
    #[arg(long = "bind-port")]
    bind_port: Vec<u16>,
    /// Deny all TCP connect and bind.
    #[arg(long = "no-net")]
    no_net: bool,
    /// Memory limit, e.g. 256M (address space).
    #[arg(short = 'm', long = "max-memory")]
    max_memory: Option<String>,
    /// Process limit (RLIMIT_NPROC, counted per user, not per sandbox).
    #[arg(short = 'P', long = "max-procs")]
    max_procs: Option<u64>,
    /// Wall-clock timeout in seconds.
    #[arg(short = 't', long = "timeout")]
    timeout: Option<u64>,
    /// CPU-time limit in seconds.
    #[arg(long = "cpu-seconds")]
    cpu_seconds: Option<u64>,
    /// Run with whatever the kernel can enforce and report the gaps.
    #[arg(long = "best-effort")]
    best_effort: bool,
    /// Capture output and print a JSON result.
    #[arg(long)]
    json: bool,
    /// Start from an empty environment (PATH and HOME only).
    #[arg(long = "clean-env")]
    clean_env: bool,
    /// Extra environment variable KEY=VALUE; repeatable.
    #[arg(long = "env")]
    env: Vec<String>,
    /// Working directory for the command.
    #[arg(long)]
    cwd: Option<PathBuf>,
    /// Do not scope abstract unix sockets and signals to the sandbox.
    #[arg(long = "no-scope")]
    no_scope: bool,
    /// Permit creating namespaces.
    #[arg(long = "allow-namespaces")]
    allow_namespaces: bool,
    /// Kill the process on a denied syscall instead of returning EPERM.
    #[arg(long = "seccomp-kill")]
    seccomp_kill: bool,
    /// Disable the seccomp denylist.
    #[arg(long = "no-seccomp")]
    no_seccomp: bool,
    /// Treat the kernel's Landlock ABI as at most this.
    #[arg(long = "max-abi")]
    max_abi: Option<u32>,
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn policy_from(a: &RunArgs) -> Result<(Policy, SyscallOverrides)> {
    let mut p = Policy::default();
    let mut ov = SyscallOverrides::default();
    if let Some(spec) = &a.profile {
        Profile::load(spec)?.apply(&mut p, &mut ov)?;
    }
    p.read.extend(a.read.iter().cloned());
    p.write.extend(a.write.iter().cloned());
    if a.no_net {
        if !a.net_port.is_empty() || !a.bind_port.is_empty() {
            bail!("--no-net cannot be combined with --net-port/--bind-port");
        }
        p.tcp_connect = TcpRule::Deny;
        p.tcp_bind = TcpRule::Deny;
    } else {
        if !a.net_port.is_empty() {
            p.tcp_connect = TcpRule::Ports(a.net_port.clone());
        }
        if !a.bind_port.is_empty() {
            p.tcp_bind = TcpRule::Ports(a.bind_port.clone());
        }
    }
    if let Some(m) = &a.max_memory {
        p.max_memory = Some(parse_size(m).map_err(anyhow::Error::msg)?);
    }
    if a.max_procs.is_some() {
        p.max_processes = a.max_procs;
    }
    if a.timeout.is_some() {
        p.timeout_secs = a.timeout;
    }
    if a.cpu_seconds.is_some() {
        p.cpu_seconds = a.cpu_seconds;
    }
    p.best_effort |= a.best_effort;
    p.clean_env |= a.clean_env;
    for (k, v) in parse_env(&a.env)? {
        p.env.retain(|(pk, _)| *pk != k);
        p.env.push((k, v));
    }
    if a.cwd.is_some() {
        p.cwd = a.cwd.clone();
    }
    if a.no_scope {
        p.scope_ipc = false;
    }
    p.allow_namespaces |= a.allow_namespaces;
    if a.no_seccomp {
        p.seccomp = None;
    } else if a.seccomp_kill {
        p.seccomp = Some(SeccompMode::Kill);
    }
    if a.max_abi.is_some() {
        p.max_abi = a.max_abi;
    }
    Ok((p, ov))
}

fn parse_env(kvs: &[String]) -> Result<Vec<(String, String)>> {
    kvs.iter()
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
            _ => bail!("--env expects KEY=VALUE, got {kv:?}"),
        })
        .collect()
}

fn main() {
    std::process::exit(match real_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("fluxvm-procbox: {e:#}");
            2
        }
    });
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Probe { json } => {
            let p = fluxvm_procbox::probe::probe();
            if json {
                println!("{}", serde_json::to_string_pretty(&p)?);
            } else {
                print!("{}", p.render());
            }
            Ok(0)
        }
        Cmd::Selftest { op, arg } => {
            let (line, ok) = fluxvm_procbox::selftest::run_op(&op, arg.as_deref());
            println!("{line}");
            Ok(if ok { 0 } else { 1 })
        }
        Cmd::Profile(ProfileCmd::Validate { profile }) => {
            let prof = Profile::load(&profile)?;
            println!("ok: {profile}");
            for line in prof.summary() {
                println!("  {line}");
            }
            Ok(0)
        }
        Cmd::Learn(a) => {
            if let Some(out) = &a.out {
                if out.exists() && !a.force {
                    bail!("{} exists; pass --force to overwrite it", out.display());
                }
            }
            let opts = LearnOptions {
                cwd: a.cwd.clone(),
                env: parse_env(&a.env)?,
                timeout_secs: a.timeout,
                stdout_to_stderr: a.out.is_none() && !a.json,
            };
            let res = learn::learn(&a.command, &opts)?;
            let text = if a.json {
                let mut v = serde_json::to_value(&res)?;
                v["profile_toml"] = learn::render_toml(&res)?.into();
                serde_json::to_string_pretty(&v)?
            } else {
                learn::render_toml(&res)?
            };
            match &a.out {
                Some(out) => {
                    std::fs::write(out, &text)?;
                    eprintln!(
                        "fluxvm-procbox: wrote {} ({} read, {} write path(s)); review the \
                         comments at the top before using it",
                        out.display(),
                        res.generalized.profile.fs_read.len(),
                        res.generalized.profile.fs_write.len()
                    );
                }
                None => println!("{text}"),
            }
            if !res.program_succeeded() {
                eprintln!(
                    "fluxvm-procbox: the traced program did not exit 0; the profile may be incomplete"
                );
            }
            Ok(if res.program_succeeded() { 0 } else { 3 })
        }
        Cmd::Run(a) => {
            let (policy, overrides) = policy_from(&a)?;
            let res = fluxvm_procbox::run_with(
                &policy,
                &overrides,
                &a.command,
                &RunOptions { capture: a.json },
            )?;
            if a.json {
                println!("{}", serde_json::to_string_pretty(&res)?);
            } else if !res.enforcement.not_enforced.is_empty() {
                eprintln!("fluxvm-procbox: NOT enforced:");
                for g in &res.enforcement.not_enforced {
                    eprintln!("  - {g}");
                }
            }
            Ok(if a.json {
                0
            } else if res.timed_out {
                124
            } else if let Some(c) = res.exit_code {
                c
            } else {
                128 + res.signal.unwrap_or(0)
            })
        }
    }
}
