// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use fluxvm_procbox::{parse_size, Policy, RunOptions, SeccompMode, TcpRule};
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
    /// Show which protections this kernel can enforce.
    Probe {
        #[arg(long)]
        json: bool,
    },
    #[command(hide = true)]
    Selftest { op: String, arg: Option<String> },
}

#[derive(Args)]
struct RunArgs {
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

fn policy_from(a: &RunArgs) -> Result<Policy> {
    let mut p = Policy::default();
    p.read = a.read.clone();
    p.write = a.write.clone();
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
    p.max_memory = a
        .max_memory
        .as_deref()
        .map(parse_size)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    p.max_processes = a.max_procs;
    p.timeout_secs = a.timeout;
    p.cpu_seconds = a.cpu_seconds;
    p.best_effort = a.best_effort;
    p.clean_env = a.clean_env;
    for kv in &a.env {
        match kv.split_once('=') {
            Some((k, v)) if !k.is_empty() => p.env.push((k.to_string(), v.to_string())),
            _ => bail!("--env expects KEY=VALUE, got {kv:?}"),
        }
    }
    p.cwd = a.cwd.clone();
    p.scope_ipc = !a.no_scope;
    p.allow_namespaces = a.allow_namespaces;
    p.seccomp = if a.no_seccomp {
        None
    } else if a.seccomp_kill {
        Some(SeccompMode::Kill)
    } else {
        Some(SeccompMode::Errno)
    };
    p.max_abi = a.max_abi;
    Ok(p)
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
        Cmd::Run(a) => {
            let policy = policy_from(&a)?;
            let res = fluxvm_procbox::run(&policy, &a.command, &RunOptions { capture: a.json })?;
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
