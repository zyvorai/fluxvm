// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `fluxctl up | down | ps`: the VMs a project needs, described in one `fluxvm.toml` and managed together.
//!
//! A stack is not a daemon concept: its VMs are ordinary VMs carrying three labels (`fluxvm.stack`, `fluxvm.service`,
//! `fluxvm.spec-hash`), so the same code drives the local state dir and `--server`, and nothing is lost if the checkout moves.

use crate::run::{self, VmApi};
use anyhow::{Context, Result, bail};
use fluxvm_core::model::VmStatus;
use futures_util::future::try_join_all;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const L_STACK: &str = "fluxvm.stack";
pub const L_SERVICE: &str = "fluxvm.service";
pub const L_HASH: &str = "fluxvm.spec-hash";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub image: Option<String>,
    pub cpus: Option<u8>,
    pub memory_mib: Option<u64>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub image: Option<String>,
    /// Run this OCI image as a container sandbox (its own small VM, no SSH) instead of a full VM. `volumes` are then
    /// named volumes (`NAME:/path[:ro]`), `ready` runs inside the container as its health check, and the services it
    /// `depends_on` resolve by name.
    pub container: Option<String>,
    /// Container services: replaces the image's `Cmd`.
    pub command: Option<Vec<String>>,
    /// Container services: replaces the image's `Entrypoint`.
    pub entrypoint: Option<Vec<String>>,
    /// Container services: `KEY=value`.
    #[serde(default)]
    pub env: Vec<String>,
    /// Container services: `no` (default), `on-failure` or `always`.
    pub restart: Option<String>,
    pub cpus: Option<u8>,
    pub memory_mib: Option<u64>,
    pub user: Option<String>,
    /// Packages installed by cloud-init on first boot.
    #[serde(default)]
    pub packages: Vec<String>,
    /// Commands cloud-init runs on first boot (before the other services' names are known).
    #[serde(default)]
    pub run: Vec<String>,
    /// `HOST:GUEST` TCP forwards from 127.0.0.1.
    #[serde(default)]
    pub ports: Vec<String>,
    /// TCP ports other services may connect to (`db:5432`). VMs on the Mac's NAT cannot reach each other directly, so
    /// each exposed port is relayed through the Mac: every service name resolves to the NAT gateway, and the same port
    /// number there reaches this service. Port numbers must therefore be unique across the stack.
    #[serde(default)]
    pub expose: Vec<u16>,
    /// `HOST:GUEST[:ro]` shared folders; relative host paths are relative to the file.
    #[serde(default)]
    pub volumes: Vec<String>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// A shell command that must succeed in the guest before dependents start.
    pub ready: Option<String>,
    /// Commands run over SSH once, after every service is up and the other services' names resolve. Only when the
    /// service was created by this `up`.
    #[serde(default)]
    pub after_up: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StackFile {
    pub name: String,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub service: BTreeMap<String, Service>,
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// VM-only settings on a container service, or container-only settings on a VM service, are mistakes.
fn check_kind(name: &str, svc: &Service) -> Result<()> {
    let (wrong, kind): (&[(bool, &str)], &str) = if svc.container.is_some() {
        (
            &[
                (svc.image.is_some(), "image"),
                (svc.user.is_some(), "user"),
                (!svc.packages.is_empty(), "packages"),
                (!svc.run.is_empty(), "run"),
                (!svc.after_up.is_empty(), "after_up"),
            ],
            "a container service",
        )
    } else {
        (
            &[
                (svc.command.is_some(), "command"),
                (svc.entrypoint.is_some(), "entrypoint"),
                (!svc.env.is_empty(), "env"),
                (svc.restart.is_some(), "restart"),
            ],
            "a VM service (set container = \"IMAGE\" for a container)",
        )
    };
    if let Some((_, field)) = wrong.iter().find(|(set, _)| *set) {
        bail!("service {name}: {field} is not used by {kind}");
    }
    if svc.container.is_some() {
        for p in &svc.ports {
            fluxvm_scheduler::oci_sandbox::parse_port(p)
                .with_context(|| format!("service {name}"))?;
        }
        crate::sandbox_run::volumes_json(&svc.volumes)
            .with_context(|| format!("service {name}"))?;
    }
    Ok(())
}

pub fn parse(text: &str) -> Result<StackFile> {
    let f: StackFile = toml::from_str(text).context("reading the stack file")?;
    if !valid_name(&f.name) {
        bail!(
            "stack name {:?} must be 1-32 characters of a-z, 0-9 and '-'",
            f.name
        );
    }
    if f.service.is_empty() {
        bail!("the stack file defines no [service.*]");
    }
    for (name, svc) in &f.service {
        if !valid_name(name) {
            bail!("service name {name:?} must be 1-32 characters of a-z, 0-9 and '-'");
        }
        check_kind(name, svc)?;
        for d in &svc.depends_on {
            if d == name {
                bail!("service {name} depends on itself");
            }
            if !f.service.contains_key(d) {
                bail!("service {name} depends on {d}, which is not defined");
            }
        }
    }
    let mut owner: BTreeMap<u16, &str> = BTreeMap::new();
    for (name, svc) in &f.service {
        for &port in &svc.expose {
            if port < 1024 {
                bail!(
                    "service {name} exposes port {port}: ports below 1024 need root on the Mac (map it to a higher port inside the guest)"
                );
            }
            if let Some(other) = owner.insert(port, name) {
                bail!(
                    "port {port} is exposed by both {other} and {name}: exposed ports are relayed through one address, so they must be unique"
                );
            }
        }
    }
    levels(&f, None)?;
    Ok(f)
}

/// Start order as batches: every service in a batch only depends on earlier batches, so a batch can start in parallel.
/// With `only`, just those services and what they depend on.
pub fn levels(f: &StackFile, only: Option<&[String]>) -> Result<Vec<Vec<String>>> {
    let mut want: BTreeSet<String> = match only {
        None => f.service.keys().cloned().collect(),
        Some(names) => names.iter().cloned().collect(),
    };
    for n in &want {
        if !f.service.contains_key(n) {
            bail!("no service named {n:?} in the stack file");
        }
    }
    let mut stack: Vec<String> = want.iter().cloned().collect();
    while let Some(n) = stack.pop() {
        for d in &f.service[&n].depends_on {
            if want.insert(d.clone()) {
                stack.push(d.clone());
            }
        }
    }
    let mut remaining = want;
    let mut done: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::new();
    while !remaining.is_empty() {
        let level: Vec<String> = remaining
            .iter()
            .filter(|n| f.service[*n].depends_on.iter().all(|d| done.contains(d)))
            .cloned()
            .collect();
        if level.is_empty() {
            bail!(
                "dependency cycle among: {}",
                remaining.iter().cloned().collect::<Vec<_>>().join(", ")
            );
        }
        for n in &level {
            remaining.remove(n);
            done.insert(n.clone());
        }
        out.push(level);
    }
    Ok(out)
}

pub fn vm_name(stack: &str, service: &str) -> String {
    format!("{stack}-{service}")
}

/// The `CreateVmRequest` JSON for one service.
pub fn service_spec(
    f: &StackFile,
    name: &str,
    dir: &Path,
    home: &Path,
    default_user: &str,
    pubkey: &str,
) -> Result<Value> {
    let svc = &f.service[name];
    let mut forwards = svc
        .ports
        .iter()
        .map(|p| run::parse_port(p).with_context(|| format!("service {name}")))
        .collect::<Result<Vec<_>>>()?;
    forwards.extend(
        svc.expose
            .iter()
            .map(|p| json!({"host_port": p, "guest_port": p, "guests": true})),
    );
    let volumes = svc
        .volumes
        .iter()
        .map(|v| run::parse_volume(v, dir, Some(home)).with_context(|| format!("service {name}")))
        .collect::<Result<Vec<_>>>()?;
    let user = svc
        .user
        .clone()
        .or_else(|| f.defaults.user.clone())
        .unwrap_or_else(|| default_user.to_owned());
    Ok(json!({
        "name": vm_name(&f.name, name),
        "backend": "auto",
        "image": svc.image.clone().or_else(|| f.defaults.image.clone()).unwrap_or_else(|| "debian-13".into()),
        "vcpus": svc.cpus.or(f.defaults.cpus).unwrap_or(2),
        "memory_mib": svc.memory_mib.or(f.defaults.memory_mib).unwrap_or(2048),
        "network": {"mode": "user", "forwards": forwards},
        "shared_folders": volumes,
        "cloud_init": {
            "hostname": vm_name(&f.name, name),
            "user": user,
            "ssh_authorized_keys": [pubkey],
            "packages": svc.packages,
            "runcmd": svc.run,
        },
    }))
}

/// The `POST /v1/sandboxes` request for a container service. The services it depends on resolve to the NAT gateway,
/// which relays their exposed ports.
pub fn container_spec(f: &StackFile, name: &str) -> Result<Value> {
    let svc = &f.service[name];
    let image = svc
        .container
        .as_deref()
        .context("not a container service")?;
    let gateway_hosts: BTreeSet<String> = svc
        .depends_on
        .iter()
        .flat_map(|d| [d.clone(), vm_name(&f.name, d)])
        .collect();
    let mut oci = json!({
        "image": image,
        "env": svc.env,
        "ports": svc.ports,
        "expose": svc.expose,
        "gateway_hosts": gateway_hosts,
        "read_only_root": false,
    });
    for (k, v) in [
        ("command", json!(svc.command)),
        ("entrypoint", json!(svc.entrypoint)),
        ("restart", json!(svc.restart)),
    ] {
        if !v.is_null() {
            oci[k] = v;
        }
    }
    if let Some(cmd) = &svc.ready {
        oci["healthcheck"] = json!({
            "command": ["/bin/sh", "-c", cmd],
            "interval_seconds": 2,
            "retries": 1,
        });
    }
    let mut req = json!({"name": vm_name(&f.name, name), "oci": oci});
    for (k, v) in [
        ("vcpus", json!(svc.cpus.or(f.defaults.cpus))),
        (
            "memory_mib",
            json!(svc.memory_mib.or(f.defaults.memory_mib)),
        ),
        ("volumes", crate::sandbox_run::volumes_json(&svc.volumes)?),
    ] {
        if !v.is_null() {
            req[k] = v;
        }
    }
    Ok(req)
}

/// Waits until a container service is running (and, with `ready`, healthy).
async fn wait_container<A: VmApi>(
    api: &A,
    id: Uuid,
    vm_name: &str,
    healthcheck: bool,
    fresh: bool,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let logs = api.sandbox_logs(id).await?;
        if let Some(reason) = logs.init_error {
            bail!("{vm_name} did not start: {reason}");
        }
        // An older boot's exit marker may still be in the console log of a restarted service.
        if fresh && let Some(code) = logs.exit_code {
            bail!("{vm_name} exited with code {code}");
        }
        match logs.status {
            VmStatus::Running if !healthcheck || logs.health.as_deref() == Some("healthy") => {
                return Ok(());
            }
            VmStatus::Stopped | VmStatus::Failed => bail!("{vm_name} stopped"),
            _ => {}
        }
        if Instant::now() > deadline {
            bail!("{vm_name} was not ready within 180s");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

pub fn spec_hash(spec: &Value) -> String {
    Sha256::digest(spec.to_string().as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A stack VM as the daemon reports it.
#[derive(Debug, Clone)]
pub struct StackVm {
    pub id: Uuid,
    pub name: String,
    pub service: String,
    pub hash: String,
    pub status: String,
}

/// The address guests reach the Mac at: their NAT subnet's `.1`.
pub fn gateway_of(guest_ip: &str) -> Option<String> {
    let o: Vec<&str> = guest_ip.split('.').collect();
    (o.len() == 4).then(|| format!("{}.{}.{}.1", o[0], o[1], o[2]))
}

/// The managed `/etc/hosts` block. Guests cannot reach each other directly, so every service name points at the Mac
/// (`gateway`), which relays each service's exposed ports; both the VM name and the short name are listed.
pub fn render_hosts(stack: &str, gateway: &str, services: &[String]) -> String {
    let mut s = String::from("# BEGIN fluxvm-stack\n");
    for service in services {
        s.push_str(&format!(
            "{gateway} {} {service}\n",
            vm_name(stack, service)
        ));
    }
    s.push_str("# END fluxvm-stack\n");
    s
}

fn hosts_script(block: &str) -> String {
    format!(
        "set -e\nsudo sed -i '/# BEGIN fluxvm-stack/,/# END fluxvm-stack/d' /etc/hosts\nsudo tee -a /etc/hosts >/dev/null <<'FLUXVM_HOSTS'\n{block}FLUXVM_HOSTS\n"
    )
}

/// Runs a script in the guest over SSH (fed on stdin), returning whether it succeeded and its output.
async fn ssh_script(
    ip: &str,
    user: &str,
    identity: &Option<PathBuf>,
    script: &str,
) -> Result<(bool, String)> {
    use tokio::io::AsyncWriteExt;
    let mut c = tokio::process::Command::from(run::ssh_base(ip, user, identity));
    c.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "sh", "-s"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = c.spawn().context("running ssh")?;
    let mut stdin = child.stdin.take().context("ssh stdin")?;
    stdin.write_all(script.as_bytes()).await?;
    drop(stdin);
    let out = child.wait_with_output().await?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

struct Ready {
    service: String,
    ip: String,
    user: String,
    created: bool,
    /// A VM reached over SSH; container services have no SSH and get their names through `gateway_hosts`.
    ssh: bool,
}

#[allow(clippy::too_many_arguments)]
async fn ensure_service<A: VmApi>(
    api: &A,
    f: &StackFile,
    name: &str,
    existing: &BTreeMap<String, StackVm>,
    dependency_changed: bool,
    dir: &Path,
    home: &Path,
    default_user: &str,
    pubkey: &str,
    identity: &Option<PathBuf>,
) -> Result<Ready> {
    let container = f.service[name].container.is_some();
    let spec = if container {
        container_spec(f, name)?
    } else {
        service_spec(f, name, dir, home, default_user, pubkey)?
    };
    let user = spec["cloud_init"]["user"]
        .as_str()
        .unwrap_or(default_user)
        .to_owned();
    let hash = spec_hash(&spec);
    let vm_name = vm_name(&f.name, name);
    let (id, created) = match existing.get(name) {
        Some(v) if v.hash == hash && !dependency_changed => {
            if v.status != "running" {
                eprintln!("starting {vm_name}…");
                api.start(v.id)
                    .await
                    .with_context(|| format!("starting {vm_name}"))?;
            }
            (v.id, false)
        }
        old => {
            if let Some(v) = old {
                let why = if v.hash == hash {
                    "a dependency changed"
                } else {
                    "its definition changed"
                };
                eprintln!("recreating {vm_name} ({why})…");
                api.delete(v.id)
                    .await
                    .with_context(|| format!("deleting {vm_name}"))?;
            } else {
                eprintln!("creating {vm_name}…");
            }
            let id = if container {
                api.create_sandbox(spec).await
            } else {
                api.create(spec).await
            }
            .with_context(|| format!("creating {vm_name}"))?;
            let labels = BTreeMap::from([
                (L_STACK.to_owned(), f.name.clone()),
                (L_SERVICE.to_owned(), name.to_owned()),
                (L_HASH.to_owned(), hash),
            ]);
            api.set_labels(id, labels).await?;
            (id, true)
        }
    };
    if container {
        wait_container(api, id, &vm_name, f.service[name].ready.is_some(), created).await?;
        eprintln!("{vm_name} is up");
        return Ok(Ready {
            service: name.to_owned(),
            ip: String::new(),
            user,
            created,
            ssh: false,
        });
    }
    let ip = run::wait_ssh(api, id, &user, identity)
        .await
        .with_context(|| format!("waiting for {vm_name}"))?;
    if let Some(cmd) = &f.service[name].ready {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            let (ok, out) = ssh_script(&ip, &user, identity, cmd).await?;
            if ok {
                break;
            }
            if Instant::now() > deadline {
                bail!(
                    "{vm_name} was not ready within 180s (`{cmd}`): {}",
                    out.trim()
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    eprintln!("{vm_name} is up at {ip}");
    Ok(Ready {
        service: name.to_owned(),
        ip,
        user,
        created,
        ssh: true,
    })
}

/// Creates what is missing, starts what is stopped, recreates what changed (and what depends on it), then makes the
/// services reachable by name and runs each new service's `after_up`.
pub async fn up<A: VmApi>(
    api: &A,
    f: &StackFile,
    dir: &Path,
    only: Option<&[String]>,
) -> Result<()> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
    let default_user = std::env::var("USER").unwrap_or_else(|_| "fluxvm".into());
    let (pubkey, identity) = run::ssh_key(&home)?;
    let existing: BTreeMap<String, StackVm> = api
        .list_stack(&f.name)
        .await?
        .into_iter()
        .map(|v| (v.service.clone(), v))
        .collect();
    for (svc, v) in &existing {
        if !f.service.contains_key(svc) {
            eprintln!(
                "note: {} is not in the stack file any more (`fluxctl down` removes it)",
                v.name
            );
        }
    }
    let mut changed: BTreeSet<String> = BTreeSet::new();
    let mut ready: Vec<Ready> = Vec::new();
    for level in levels(f, only)? {
        let tasks = level.iter().map(|name| {
            let dep_changed = f.service[name]
                .depends_on
                .iter()
                .any(|d| changed.contains(d));
            ensure_service(
                api,
                f,
                name,
                &existing,
                dep_changed,
                dir,
                &home,
                &default_user,
                &pubkey,
                &identity,
            )
        });
        for r in try_join_all(tasks).await? {
            if r.created {
                changed.insert(r.service.clone());
            }
            ready.push(r);
        }
    }

    let services: Vec<String> = ready.iter().map(|r| r.service.clone()).collect();
    let vms: Vec<&Ready> = ready.iter().filter(|r| r.ssh).collect();
    if vms.is_empty() {
        eprintln!("stack {} is up", f.name);
        return Ok(());
    }
    let gateway = vms
        .iter()
        .find_map(|r| gateway_of(&r.ip))
        .context("could not work out the NAT gateway address")?;
    let script = hosts_script(&render_hosts(&f.name, &gateway, &services));
    try_join_all(vms.iter().map(|r| async {
        let (ok, out) = ssh_script(&r.ip, &r.user, &identity, &script).await?;
        if !ok {
            bail!(
                "could not write /etc/hosts in {}: {}",
                vm_name(&f.name, &r.service),
                out.trim()
            );
        }
        Ok(())
    }))
    .await?;

    for r in vms.iter().filter(|r| r.created) {
        let cmds = &f.service[&r.service].after_up;
        if cmds.is_empty() {
            continue;
        }
        eprintln!("running after_up for {}…", vm_name(&f.name, &r.service));
        let script = format!("set -e\n{}\n", cmds.join("\n"));
        let (ok, out) = ssh_script(&r.ip, &r.user, &identity, &script).await?;
        if !ok {
            bail!(
                "after_up failed in {}: {}",
                vm_name(&f.name, &r.service),
                out.trim()
            );
        }
    }
    eprintln!("stack {} is up", f.name);
    Ok(())
}

/// Deletes (or with `keep`, stops) the stack's VMs: in reverse start order when the file is known, else all at once.
pub async fn down<A: VmApi>(
    api: &A,
    stack: &str,
    file: Option<&StackFile>,
    keep: bool,
) -> Result<()> {
    let mut vms: BTreeMap<String, StackVm> = api
        .list_stack(stack)
        .await?
        .into_iter()
        .map(|v| (v.service.clone(), v))
        .collect();
    if vms.is_empty() {
        eprintln!("no VMs in stack {stack}");
        return Ok(());
    }
    let mut order: Vec<StackVm> = Vec::new();
    if let Some(f) = file {
        for level in levels(f, None)?.into_iter().rev() {
            for svc in level {
                order.extend(vms.remove(&svc));
            }
        }
    }
    order.extend(vms.into_values());
    for v in order {
        if keep {
            eprintln!("stopping {}…", v.name);
            api.stop(v.id).await?;
        } else {
            eprintln!("deleting {}…", v.name);
            api.delete(v.id).await?;
        }
    }
    Ok(())
}

/// `service  vm  status  address` rows.
pub async fn ps<A: VmApi>(api: &A, stack: &str) -> Result<Vec<[String; 4]>> {
    let mut rows = Vec::new();
    for v in api.list_stack(stack).await? {
        let ip = if v.status == "running" {
            api.guest_ip(v.id).await?.unwrap_or_default()
        } else {
            String::new()
        };
        rows.push([v.service, v.name, v.status, ip]);
    }
    rows.sort();
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r#"
name = "myapp"
[defaults]
memory_mib = 1024
[service.db]
packages = ["postgresql"]
ports = ["5432:5432"]
expose = [5432]
ready = "pg_isready"
[service.app]
depends_on = ["db"]
volumes = ["./:/srv/app"]
after_up = ["psql -h db -c 'select 1'"]
[service.worker]
depends_on = ["db", "app"]
"#;

    #[test]
    fn parses_and_orders_by_dependency() {
        let f = parse(FILE).unwrap();
        assert_eq!(f.name, "myapp");
        assert_eq!(
            levels(&f, None).unwrap(),
            vec![
                vec!["db".to_string()],
                vec!["app".to_string()],
                vec!["worker".to_string()]
            ]
        );
    }

    #[test]
    fn independent_services_share_a_level_and_only_pulls_in_dependencies() {
        let f =
            parse("name = \"s\"\n[service.a]\n[service.b]\n[service.c]\ndepends_on = [\"a\"]\n")
                .unwrap();
        assert_eq!(
            levels(&f, None).unwrap()[0],
            vec!["a".to_string(), "b".to_string()]
        );
        let only = levels(&f, Some(&["c".to_string()])).unwrap();
        assert_eq!(only, vec![vec!["a".to_string()], vec!["c".to_string()]]);
    }

    #[test]
    fn rejects_bad_files_with_a_reason() {
        for (text, needle) in [
            (
                "name = \"s\"\n[service.a]\ndepends_on = [\"b\"]\n[service.b]\ndepends_on = [\"a\"]\n",
                "cycle",
            ),
            (
                "name = \"s\"\n[service.a]\ndepends_on = [\"zzz\"]\n",
                "not defined",
            ),
            (
                "name = \"s\"\n[service.a]\ndepends_on = [\"a\"]\n",
                "itself",
            ),
            ("name = \"Bad_Name\"\n[service.a]\n", "stack name"),
            ("name = \"s\"\n[service.A]\n", "service name"),
            ("name = \"s\"\n", "no [service"),
            ("name = \"s\"\n[service.a]\nexpose = [80]\n", "below 1024"),
            (
                "name = \"s\"\n[service.a]\nexpose = [5000]\n[service.b]\nexpose = [5000]\n",
                "unique",
            ),
            ("name = \"s\"\n[service.a]\nimag = \"x\"\n", "unknown field"),
        ] {
            let err = format!("{:#}", parse(text).unwrap_err());
            assert!(err.contains(needle), "{text:?}: {err}");
        }
    }

    #[test]
    fn spec_uses_defaults_and_hash_tracks_the_definition() {
        let f = parse(FILE).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let home = Path::new("/home/x");
        let db = service_spec(&f, "db", dir.path(), home, "dev", "ssh-ed25519 AAA").unwrap();
        assert_eq!(db["name"], "myapp-db");
        assert_eq!(db["memory_mib"], 1024);
        assert_eq!(db["image"], "debian-13");
        assert_eq!(db["network"]["forwards"][0]["host_port"], 5432);
        assert_eq!(db["network"]["forwards"][1]["guests"], true);
        assert_eq!(db["cloud_init"]["user"], "dev");
        assert_eq!(db["cloud_init"]["packages"][0], "postgresql");
        let again = service_spec(&f, "db", dir.path(), home, "dev", "ssh-ed25519 AAA").unwrap();
        assert_eq!(spec_hash(&db), spec_hash(&again));
        let mut g = f.clone();
        g.service.get_mut("db").unwrap().memory_mib = Some(4096);
        let changed = service_spec(&g, "db", dir.path(), home, "dev", "ssh-ed25519 AAA").unwrap();
        assert_ne!(spec_hash(&db), spec_hash(&changed));
    }

    #[test]
    fn container_services_become_sandboxes_that_reach_their_dependencies() {
        let f = parse(
            r#"
name = "shop"
[service.db]
container = "postgres:17"
env = ["POSTGRES_PASSWORD=dev"]
expose = [5432]
volumes = ["pgdata:/var/lib/postgresql/data"]
ready = "pg_isready -U postgres"
restart = "always"
[service.web]
container = "ghcr.io/acme/web:1"
ports = ["8080:80"]
depends_on = ["db"]
"#,
        )
        .unwrap();
        let db = container_spec(&f, "db").unwrap();
        let req: fluxvm_scheduler::SandboxCreateRequest =
            serde_json::from_value(db.clone()).unwrap();
        let oci = req.oci.unwrap();
        assert_eq!(oci.expose, [5432]);
        assert!(!oci.read_only_root);
        assert_eq!(
            oci.healthcheck.unwrap().command,
            ["/bin/sh", "-c", "pg_isready -U postgres"]
        );
        assert_eq!(req.volumes[0].name, "pgdata");
        assert!(db.get("vcpus").is_none());
        let web = container_spec(&f, "web").unwrap();
        assert_eq!(web["name"], "shop-web");
        assert_eq!(web["oci"]["gateway_hosts"], json!(["db", "shop-db"]));
        assert_eq!(web["oci"]["ports"], json!(["8080:80"]));
        assert!(web["oci"].get("healthcheck").is_none());
    }

    #[test]
    fn container_and_vm_settings_do_not_mix() {
        for (text, needle) in [
            (
                "name = \"s\"\n[service.a]\ncontainer = \"nginx\"\npackages = [\"x\"]\n",
                "packages is not used by a container",
            ),
            (
                "name = \"s\"\n[service.a]\ncontainer = \"nginx\"\nimage = \"debian-13\"\n",
                "image is not used",
            ),
            (
                "name = \"s\"\n[service.a]\nenv = [\"A=1\"]\n",
                "env is not used by a VM",
            ),
            (
                "name = \"s\"\n[service.a]\ncontainer = \"nginx\"\nports = [\"80:80\"]\n",
                "below 1024",
            ),
            (
                "name = \"s\"\n[service.a]\ncontainer = \"nginx\"\nvolumes = [\"./x\"]\n",
                "NAME:/path",
            ),
        ] {
            let err = format!("{:#}", parse(text).unwrap_err());
            assert!(err.contains(needle), "{text:?}: {err}");
        }
    }

    #[test]
    fn hosts_block_names_each_service_two_ways() {
        assert_eq!(
            gateway_of("192.168.64.112").as_deref(),
            Some("192.168.64.1")
        );
        assert_eq!(gateway_of("nope"), None);
        let block = render_hosts("myapp", "192.168.64.1", &["db".into(), "app".into()]);
        assert_eq!(
            block,
            "# BEGIN fluxvm-stack\n192.168.64.1 myapp-db db\n192.168.64.1 myapp-app app\n# END fluxvm-stack\n"
        );
        assert!(
            hosts_script(&block).contains("sed -i '/# BEGIN fluxvm-stack/,/# END fluxvm-stack/d'")
        );
    }
}
