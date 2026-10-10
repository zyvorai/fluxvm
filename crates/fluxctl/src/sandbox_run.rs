// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `fluxctl sandbox run IMAGE -- CMD…`: one container sandbox (one VM), its console output, its exit code.

use crate::remote::Remote;
use anyhow::{Context, Result, bail};
use fluxvm_core::model::VmStatus;
use fluxvm_scheduler::oci_sandbox::SandboxLogs;
use fluxvm_scheduler::{SandboxCreateRequest, VmManager};
use reqwest::Method;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// The most console lines one poll asks for; output beyond it between two polls is skipped.
const POLL_LINES: usize = 10_000;
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, clap::Args)]
pub struct RunArgs {
    /// linux/arm64 image, e.g. `alpine:3.22`.
    pub image: String,
    #[arg(long)]
    pub name: Option<String>,
    /// Sandbox size: tiny (1 vCPU, 512 MiB), small or standard; see docs/agent-density.md.
    #[arg(long)]
    pub profile: Option<String>,
    #[arg(long)]
    pub vcpus: Option<u8>,
    #[arg(long)]
    pub memory_mib: Option<u64>,
    /// No network card at all.
    #[arg(long, conflicts_with = "allow_hosts")]
    pub offline: bool,
    /// Allow egress to HOST (repeatable); everything else is refused.
    #[arg(long = "allow-host")]
    pub allow_hosts: Vec<String>,
    /// `KEY=value` (repeatable).
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,
    #[arg(short = 'w', long)]
    pub workdir: Option<String>,
    /// `uid[:gid]` or `name[:group]`.
    #[arg(short = 'u', long)]
    pub user: Option<String>,
    /// Replace the image's entrypoint (space-separated argv).
    #[arg(long)]
    pub entrypoint: Option<String>,
    /// Mount the sandbox's own copy of the image read-write (default: read-only; `/tmp` and `/run` are tmpfs either way).
    #[arg(long)]
    pub writable_root: bool,
    /// Publish a TCP port, `HOST:CONTAINER` (repeatable): the Mac's 127.0.0.1:HOST reaches the container.
    #[arg(short = 'p', long = "publish")]
    pub publish: Vec<String>,
    /// Persistent named volume, `NAME:/path[:ro]` (repeatable); it survives the sandbox.
    #[arg(short = 'v', long = "volume")]
    pub volumes: Vec<String>,
    /// Restart the process: no, on-failure or always.
    #[arg(long)]
    pub restart: Option<String>,
    #[arg(long)]
    pub max_restarts: Option<u32>,
    /// Health check command, run without a shell (space-separated argv).
    #[arg(long)]
    pub health_cmd: Option<String>,
    #[arg(long, requires = "health_cmd")]
    pub health_interval: Option<u64>,
    /// Delete the sandbox when the process has exited.
    #[arg(long)]
    pub rm: bool,
    /// Give up (and stop following) after this many seconds.
    #[arg(long, default_value_t = 3600)]
    pub timeout_seconds: u64,
    /// Replaces the image's `Cmd`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

impl RunArgs {
    pub fn request(&self) -> Result<Value> {
        let mut oci = json!({
            "image": self.image,
            "env": self.env,
            "workdir": self.workdir,
            "user": self.user,
            "read_only_root": !self.writable_root,
            "exit_policy": "poweroff",
        });
        if !self.command.is_empty() {
            oci["command"] = json!(self.command);
        }
        if let Some(ep) = &self.entrypoint {
            oci["entrypoint"] = json!(ep.split_whitespace().collect::<Vec<_>>());
        }
        if !self.publish.is_empty() {
            oci["ports"] = json!(self.publish);
        }
        if let Some(r) = &self.restart {
            oci["restart"] = json!(r);
        }
        if let Some(n) = self.max_restarts {
            oci["max_restarts"] = json!(n);
        }
        if let Some(cmd) = &self.health_cmd {
            let mut hc = json!({"command": cmd.split_whitespace().collect::<Vec<_>>()});
            if let Some(i) = self.health_interval {
                hc["interval_seconds"] = json!(i);
            }
            oci["healthcheck"] = hc;
        }
        let mut req = json!({
            "name": self.name.clone().unwrap_or_else(|| default_name(&self.image)),
            "oci": oci,
            "offline": self.offline,
            "allow_hosts": self.allow_hosts,
        });
        for (k, v) in [
            ("profile", json!(self.profile)),
            ("vcpus", json!(self.vcpus)),
            ("memory_mib", json!(self.memory_mib)),
            ("volumes", volumes_json(&self.volumes)?),
        ] {
            if !v.is_null() {
                req[k] = v;
            }
        }
        Ok(req)
    }
}

/// `NAME:/path[:ro]` → `{"name", "guest_path", "read_only"}`; `null` when there are none.
fn volumes_json(specs: &[String]) -> Result<Value> {
    if specs.is_empty() {
        return Ok(Value::Null);
    }
    let mut out = Vec::new();
    for v in specs {
        let mut parts = v.splitn(3, ':');
        let (Some(name), Some(path)) = (parts.next(), parts.next()) else {
            bail!("volume {v:?}: use NAME:/path[:ro]");
        };
        let read_only = match parts.next() {
            None | Some("rw") => false,
            Some("ro") => true,
            Some(o) => bail!("volume {v:?}: unknown option {o:?} (ro or rw)"),
        };
        out.push(json!({"name": name, "guest_path": path, "read_only": read_only}));
    }
    Ok(Value::Array(out))
}

/// `alpine:3.22` → `alpine-1a2b3c`: the image's last path segment and a short random suffix.
fn default_name(image: &str) -> String {
    let base = image
        .rsplit('/')
        .next()
        .unwrap_or(image)
        .split(['@', ':'])
        .next()
        .unwrap_or("sandbox");
    let base: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(40)
        .collect();
    let suffix = &Uuid::new_v4().simple().to_string()[..6];
    format!("{}-{suffix}", base.trim_matches('-'))
}

pub enum Target<'a> {
    Local(&'a Arc<VmManager>),
    Remote(&'a Remote),
}

impl Target<'_> {
    async fn create(&self, req: Value) -> Result<Uuid> {
        let id = match self {
            Target::Local(m) => {
                let req: SandboxCreateRequest = serde_json::from_value(req)?;
                m.create_sandbox(req, None, None).await?.id
            }
            Target::Remote(r) => {
                let vm = r.call(Method::POST, "/v1/sandboxes", Some(req)).await?;
                vm["id"]
                    .as_str()
                    .context("the daemon returned no sandbox id")?
                    .parse()?
            }
        };
        Ok(id)
    }

    pub async fn logs(&self, id: Uuid, lines: usize) -> Result<SandboxLogs> {
        match self {
            Target::Local(m) => m.sandbox_logs(id, lines).await,
            Target::Remote(r) => Ok(serde_json::from_value(
                r.call(
                    Method::GET,
                    &format!("/v1/sandboxes/{id}/logs?lines={lines}"),
                    None,
                )
                .await?,
            )?),
        }
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        match self {
            Target::Local(m) => m.delete(id).await,
            Target::Remote(r) => r
                .call(Method::DELETE, &format!("/v1/vms/{id}"), None)
                .await
                .map(drop),
        }
    }
}

/// Lines of `now` not yet printed, given the `printed` lines of the previous poll's tail.
fn unseen<'a>(printed: &[&str], now: &'a str) -> Vec<&'a str> {
    let now: Vec<&str> = now.lines().collect();
    if printed.is_empty() {
        return now;
    }
    // The longest suffix of what was printed that is a prefix of the new tail.
    for start in 0..printed.len() {
        let overlap = &printed[start..];
        if now.len() >= overlap.len() && now[..overlap.len()] == *overlap {
            return now[overlap.len()..].to_vec();
        }
    }
    now
}

/// Creates the sandbox, follows its console until the process exits, and returns the process's exit code.
pub async fn run(target: Target<'_>, args: &RunArgs) -> Result<i32> {
    let id = target.create(args.request()?).await?;
    eprintln!("sandbox {id} started from {}", args.image);
    let outcome = follow(&target, id, Duration::from_secs(args.timeout_seconds)).await;
    if args.rm
        && let Err(e) = target.delete(id).await
    {
        eprintln!("warning: deleting sandbox {id}: {e:#}");
    }
    outcome
}

async fn follow(target: &Target<'_>, id: Uuid, timeout: Duration) -> Result<i32> {
    let started = Instant::now();
    let mut last = String::new();
    let mut stopped = false;
    loop {
        let logs = target.logs(id, POLL_LINES).await?;
        {
            let printed: Vec<&str> = last.lines().collect();
            for line in unseen(&printed, &logs.log) {
                println!("{line}");
            }
        }
        last = logs.log;
        if let Some(reason) = logs.init_error {
            bail!("the container did not start: {reason}");
        }
        if let Some(code) = logs.exit_code {
            return Ok(code);
        }
        // Init logs the exit code before powering off; one more look covers a log read that raced the stop.
        if matches!(logs.status, VmStatus::Stopped | VmStatus::Failed) {
            if stopped {
                bail!("sandbox {id} stopped without reporting an exit code");
            }
            stopped = true;
        }
        if started.elapsed() > timeout {
            bail!(
                "sandbox {id} still running after {}s; it was left as is",
                timeout.as_secs()
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unseen_lines_follow_a_moving_tail() {
        assert_eq!(unseen(&[], "a\nb"), ["a", "b"]);
        assert_eq!(unseen(&["a", "b"], "a\nb\nc"), ["c"]);
        assert_eq!(unseen(&["a", "b", "c"], "b\nc\nd\ne"), ["d", "e"]);
        assert!(unseen(&["a", "b"], "a\nb").is_empty());
    }

    #[test]
    fn names_come_from_the_image() {
        let n = default_name("ghcr.io/org/My_App:1.2");
        assert!(n.starts_with("my-app-"), "{n}");
        assert_eq!(n.len(), "my-app-".len() + 6);
        assert!(default_name("alpine@sha256:abc").starts_with("alpine-"));
    }

    #[test]
    fn run_requests_poweroff_and_a_read_only_root() {
        let args = RunArgs {
            image: "alpine:3.22".into(),
            name: Some("t".into()),
            profile: None,
            vcpus: None,
            memory_mib: Some(256),
            offline: false,
            allow_hosts: vec![],
            env: vec!["A=1".into()],
            workdir: None,
            user: None,
            entrypoint: Some("/bin/sh -c".into()),
            writable_root: false,
            publish: vec!["8080:80".into()],
            volumes: vec!["data:/data".into(), "cfg:/srv/cfg:ro".into()],
            restart: Some("on-failure".into()),
            max_restarts: Some(2),
            health_cmd: Some("wget -q -O /dev/null http://127.0.0.1".into()),
            health_interval: Some(5),
            rm: true,
            timeout_seconds: 10,
            command: vec!["echo".into(), "hi".into()],
        };
        let req: SandboxCreateRequest = serde_json::from_value(args.request().unwrap()).unwrap();
        let oci = req.oci.unwrap();
        assert_eq!(oci.command.unwrap(), ["echo", "hi"]);
        assert_eq!(oci.entrypoint.unwrap(), ["/bin/sh", "-c"]);
        assert!(oci.read_only_root);
        assert_eq!(
            serde_json::to_value(oci.exit_policy).unwrap(),
            json!("poweroff")
        );
        assert_eq!(oci.ports, ["8080:80"]);
        assert_eq!(oci.max_restarts, Some(2));
        assert_eq!(oci.healthcheck.unwrap().interval_seconds, 5);
        assert_eq!(req.volumes.len(), 2);
        assert!(req.volumes[1].read_only && req.volumes[1].guest_path == "/srv/cfg");
        assert_eq!(req.memory_mib, Some(256));
        assert!(volumes_json(&["bad".into()]).is_err());
        assert!(volumes_json(&["a:/b:xx".into()]).is_err());
    }
}
