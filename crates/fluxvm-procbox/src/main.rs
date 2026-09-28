// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
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
    /// Merge with an earlier learned profile: its `<profile>.observed.json`
    /// observations are unioned with this run's and the profile is
    /// regenerated. Non-learned keys (limits, syscall overrides, env, ...) are
    /// kept; comments are not. Use `--out` with the same path to update in place.
    #[arg(long, value_name = "PROFILE")]
    merge: Option<PathBuf>,
    /// With --merge: the prior profile has no observation file (hand-written
    /// or older); treat its grants as observations labelled `prior`.
    #[arg(long, requires = "merge")]
    merge_profile_only: bool,
    /// Drop an earlier run (by label) from the merged observations; repeatable.
    #[arg(long, value_name = "LABEL", requires = "merge")]
    forget: Vec<String>,
    /// Label for the command after `--` (default: the command line).
    #[arg(long, value_name = "NAME")]
    label: Option<String>,
    /// Another command to learn in the same invocation, split like a shell
    /// would ('sh -c "..."'); repeatable, run in order. Its label is the text.
    #[arg(long = "cmd", value_name = "COMMAND")]
    cmd: Vec<String>,
    #[arg(last = true, required_unless_present = "cmd")]
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
            // `--out P --merge P` updates a profile in place.
            let same_path = match (&a.out, &a.merge) {
                (Some(o), Some(m)) => {
                    o == m
                        || matches!((o.canonicalize(), m.canonicalize()), (Ok(x), Ok(y)) if x == y)
                }
                _ => false,
            };
            if let Some(out) = &a.out {
                if out.exists() && !a.force && !same_path {
                    bail!("{} exists; pass --force to overwrite it", out.display());
                }
            }
            let opts = LearnOptions {
                cwd: a.cwd.clone(),
                env: parse_env(&a.env)?,
                timeout_secs: a.timeout,
                stdout_to_stderr: a.out.is_none() && !a.json,
            };
            if a.label.is_some() && a.command.is_empty() {
                bail!(
                    "--label names the command after `--`; --cmd runs are labelled by their text"
                );
            }
            if a.merge.is_none() && a.forget.is_empty() && a.cmd.is_empty() {
                // One fresh run: the original behaviour, plus the observation file.
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
                        let label = a.label.clone().unwrap_or_else(|| a.command.join(" "));
                        let mut sidecar = learn::Sidecar::default();
                        sidecar.add_run(learn::RunRecord::from_result(label, &res));
                        learn::write_profile_and_sidecar(out, &text, &sidecar)?;
                        eprintln!(
                            "fluxvm-procbox: wrote {} ({} read, {} write path(s)) and {}; review \
                             the comments at the top before using it",
                            out.display(),
                            res.generalized.profile.fs_read.len(),
                            res.generalized.profile.fs_write.len(),
                            learn::Sidecar::path_for(out).display()
                        );
                    }
                    None => println!("{text}"),
                }
                if !res.program_succeeded() {
                    eprintln!(
                        "fluxvm-procbox: the traced program did not exit 0; the profile may be incomplete"
                    );
                }
                return Ok(if res.program_succeeded() { 0 } else { 3 });
            }

            // Merge and/or several runs.
            let mut runs: Vec<(String, Vec<String>)> = Vec::new();
            if !a.command.is_empty() {
                runs.push((
                    a.label.clone().unwrap_or_else(|| a.command.join(" ")),
                    a.command.clone(),
                ));
            }
            for c in &a.cmd {
                runs.push((c.clone(), learn::split_command(c)?));
            }
            let prior = match &a.merge {
                None => learn::Prior::None,
                Some(path) => {
                    let text = std::fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    let profile = Profile::from_toml_str(&text)
                        .with_context(|| format!("prior profile {}", path.display()))?;
                    let side = learn::Sidecar::path_for(path);
                    if side.exists() {
                        learn::Prior::Full {
                            profile,
                            sidecar: learn::Sidecar::load(&side)?,
                        }
                    } else if a.merge_profile_only {
                        learn::Prior::ProfileOnly { profile }
                    } else {
                        bail!(
                            "{} has no observation file ({}); pass --merge-profile-only to treat \
                             its grants as observations, or learn it again to create one",
                            path.display(),
                            side.display()
                        );
                    }
                }
            };
            // Fail before running anything for a label that cannot be dropped.
            if let learn::Prior::Full { sidecar, .. } = &prior {
                for f in &a.forget {
                    if !sidecar.runs.iter().any(|r| &r.label == f) {
                        bail!("--forget {f:?}: no such run in the prior observations");
                    }
                }
            } else if !a.forget.is_empty() {
                bail!("--forget needs a prior profile with an observation file");
            }
            let records = learn::learn_all(&runs, &opts)?;
            let new_ok = records.iter().all(learn::RunRecord::succeeded);
            let is_file =
                |p: &std::path::Path| std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false);
            let merged = learn::plan_merge(prior, &a.forget, records, &is_file)?;
            let text = learn::render_merged_toml(&merged)?;
            let printed = if a.json {
                serde_json::to_string_pretty(&serde_json::json!({
                    "runs": merged.sidecar.runs,
                    "observed": merged.observed,
                    "notes": merged.notes,
                    "profile_toml": text,
                }))?
            } else {
                text.clone()
            };
            match &a.out {
                Some(out) => {
                    learn::write_profile_and_sidecar(out, &text, &merged.sidecar)?;
                    eprintln!(
                        "fluxvm-procbox: wrote {} ({} run(s), {} read, {} write path(s)) and {}; \
                         review the comments at the top before using it",
                        out.display(),
                        merged.sidecar.runs.len(),
                        merged.generalized.profile.fs_read.len(),
                        merged.generalized.profile.fs_write.len(),
                        learn::Sidecar::path_for(out).display()
                    );
                }
                None => println!("{printed}"),
            }
            if !new_ok {
                eprintln!(
                    "fluxvm-procbox: a traced program did not exit 0; the profile may be incomplete"
                );
            }
            Ok(if new_ok { 0 } else { 3 })
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
