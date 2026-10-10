// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! OCI sandboxes on `vz`: one lightweight Linux VM per container. The image's rootfs (built once per manifest digest, see
//! [`crate::oci_images`]) is APFS-cloned for the sandbox and booted directly with the OCI kernel and initramfs; PID 1 is
//! `fluxvm-oci-init`, which starts the guest agent and runs the image's process. Exec and files go over the agent on vsock
//! only (there is no SSH in an image), and the sandbox keeps every other sandbox property: TTL, quotas, profiles,
//! offline mode or an egress allow-list, hibernation.

use crate::VmManager;
use crate::oci_images;
use crate::sandbox::{SandboxCreateRequest, SandboxVolume};
use anyhow::{Context, Result, bail};
use fluxvm_core::agent_density::AgentProfile;
use fluxvm_core::model::{
    AppleShare, CreateVmRequest, NetworkSpec, PortForward, VmPatch, VmRecord, VmStatus,
};
use fluxvm_guest_protocol::{AgentRequest, AgentResponse};
use fluxvm_image::oci_boot::OciBoot;
use fluxvm_image::oci_registry::{Arch, PulledImage};
use fluxvm_oci_init::config as init;
use fluxvm_oci_init::supervise::{self, HealthCheck, RestartPolicy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Label holding the reference the sandbox was created from (the digest is under [`oci_images::OCI_LABEL`]).
pub const OCI_IMAGE_LABEL: &str = "fluxvm.oci.image";
pub const OCI_DEFAULT_VCPUS: u8 = 1;
pub const OCI_DEFAULT_MEMORY_MIB: u64 = 512;
/// From VM start to the agent answering (or the process having already exited).
const READY_TIMEOUT: Duration = Duration::from_secs(60);

fn default_true() -> bool {
    true
}

/// `SandboxCreateRequest.oci`: run a container image as the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciSandboxSpec {
    /// e.g. `alpine:3.22`, `ghcr.io/org/app:1.2`, `nginx@sha256:…`.
    pub image: String,
    /// `linux/arm64` (default) or `linux/amd64`, which runs under Rosetta (installed with
    /// `softwareupdate --install-rosetta --agree-to-license`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// Replaces the image's `Cmd`.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// Replaces the image's `Entrypoint` (and drops its `Cmd`, as `docker run --entrypoint` does).
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    /// `KEY=value`, added to or replacing the image's.
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub workdir: Option<String>,
    /// `uid[:gid]` or `name[:group]`. Default: the image's `User`, else 65534 (nobody).
    #[serde(default)]
    pub user: Option<String>,
    /// Mount the root read-only. `false` mounts the sandbox's own copy of the image read-write (kept until the sandbox is
    /// deleted). `/tmp` and `/run` are tmpfs either way.
    #[serde(default = "default_true")]
    pub read_only_root: bool,
    /// `keep` (default) leaves the VM up for exec after the process exits; `poweroff` stops it.
    #[serde(default)]
    pub exit_policy: init::ExitPolicy,
    /// Published TCP ports, Docker's `HOST:CONTAINER` (or `PORT` for the same number on both sides): the Mac's
    /// `127.0.0.1:HOST` reaches the container's `CONTAINER`. Host ports are 1024 and up. Not with `offline`/`allow_hosts`.
    #[serde(default)]
    pub ports: Vec<String>,
    /// Container ports *other* sandboxes and VMs on this Mac reach at the NAT gateway address, same number on both
    /// sides (`http://<gateway>:PORT`); used by stacks to connect services. 1024 and up.
    #[serde(default)]
    pub expose: Vec<u16>,
    /// Host names that resolve to the NAT gateway inside the container (`/etc/hosts`), so `db` reaches a service
    /// another sandbox `expose`s.
    #[serde(default)]
    pub gateway_hosts: Vec<String>,
    /// `no` (default), `on-failure` or `always`; restarts back off from 1 s to 60 s.
    #[serde(default)]
    pub restart: RestartPolicy,
    #[serde(default)]
    pub max_restarts: Option<u32>,
    /// A command run in the sandbox every `interval_seconds`; after `retries` failures the process is unhealthy, and
    /// with a restart policy it is stopped and restarted.
    #[serde(default)]
    pub healthcheck: Option<HealthCheck>,
    /// `{"NAME": "value"}` added to the process's environment like `env`, but write-only: kept out of the VM record and
    /// every API response, and stored only in a 0600 file in the VM's private meta share until the VM is deleted.
    #[serde(default, skip_serializing)]
    pub secret_env: BTreeMap<String, fluxvm_core::grants::Secret>,
    /// Private VM-to-VM networks to join (`10.89.N.0/24`, see `apple.networks`); works with `offline` too.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<fluxvm_core::model::AppleNetwork>,
    /// Extra `/etc/hosts` entries, e.g. the private-network addresses of the other services in a stack.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<init::HostEntry>,
}

/// Most secrets per sandbox, and their combined size.
const MAX_SECRET_ENV: usize = 64;
const MAX_SECRET_ENV_BYTES: usize = 64 * 1024;

/// `HOST:CONTAINER`, `HOST:CONTAINER/tcp`, or `PORT`.
pub fn parse_port(spec: &str) -> Result<(u16, u16)> {
    let s = spec.trim();
    let s = match s.split_once('/') {
        Some((p, proto)) if proto.eq_ignore_ascii_case("tcp") => p,
        Some((_, proto)) => bail!("port {spec:?}: only tcp can be published, not {proto}"),
        None => s,
    };
    let num = |p: &str| -> Result<u16> {
        match p.trim().parse::<u16>() {
            Ok(n) if n > 0 => Ok(n),
            _ => bail!("port {spec:?}: {p:?} is not a port number"),
        }
    };
    let (host, guest) = match s.split_once(':') {
        Some((h, g)) => (num(h)?, num(g)?),
        None => {
            let p = num(s)?;
            (p, p)
        }
    };
    if host < 1024 {
        bail!("port {spec:?}: host ports below 1024 cannot be published on the Mac");
    }
    Ok((host, guest))
}

impl OciSandboxSpec {
    pub fn arch(&self) -> Result<Arch> {
        self.platform
            .as_deref()
            .map(Arch::parse)
            .transpose()
            .map(Option::unwrap_or_default)
    }

    fn overrides(&self) -> init::ProcessOverrides {
        init::ProcessOverrides {
            entrypoint: self.entrypoint.clone(),
            command: self.command.clone(),
            env: self.env.clone(),
            workdir: self.workdir.clone(),
            user: self.user.clone(),
        }
    }
}

/// What may not be combined with `oci`.
pub(crate) fn validate(req: &SandboxCreateRequest) -> Result<()> {
    let Some(oci) = &req.oci else {
        return Ok(());
    };
    if oci.image.trim().is_empty() {
        bail!("oci.image is empty");
    }
    oci.arch()?;
    let clash = [
        (req.template.is_some(), "template"),
        (req.spec.is_some(), "spec"),
        (req.image.is_some(), "image"),
        (req.procbox.is_some(), "procbox"),
        (req.gpus.unwrap_or(0) > 0, "gpus"),
        (req.confidential.is_some(), "confidential"),
    ];
    if let Some((_, what)) = clash.iter().find(|(set, _)| *set) {
        bail!("oci cannot be combined with {what}: the image is the whole sandbox");
    }
    let mut seen = std::collections::HashSet::new();
    for p in &oci.ports {
        let (host, _) = parse_port(p)?;
        if !seen.insert(host) {
            bail!("host port {host} is published more than once");
        }
    }
    let mut exposed = std::collections::HashSet::new();
    for &p in &oci.expose {
        if p < 1024 {
            bail!("exposed port {p}: ports below 1024 cannot be relayed on the Mac");
        }
        if !exposed.insert(p) {
            bail!("port {p} is exposed more than once");
        }
    }
    let networked =
        !oci.ports.is_empty() || !oci.expose.is_empty() || !oci.gateway_hosts.is_empty();
    if networked && (req.offline || !req.allow_hosts.is_empty()) {
        bail!(
            "ports, expose and gateway_hosts need the sandbox's network card: they cannot be combined with offline or allow_hosts"
        );
    }
    if oci.gateway_hosts.len() > 64 {
        bail!("at most 64 gateway_hosts");
    }
    for h in &oci.gateway_hosts {
        if !init::valid_host_name(h) {
            bail!("gateway host {h:?} is not a valid host name");
        }
    }
    if let Some(h) = &oci.healthcheck {
        h.validate().map_err(anyhow::Error::msg)?;
    }
    fluxvm_apple::vznet::validate(&oci.networks)?;
    if !oci.networks.is_empty() && !req.allow_hosts.is_empty() {
        bail!(
            "networks cannot be combined with allow_hosts: another guest could relay around the proxy"
        );
    }
    if oci.hosts.len() > 256 {
        bail!("at most 256 hosts entries");
    }
    for e in &oci.hosts {
        if e.names.is_empty() {
            bail!("hosts entry {} has no names", e.ip);
        }
        if let Some(bad) = e.names.iter().find(|n| !init::valid_host_name(n)) {
            bail!("host {bad:?} is not a valid host name");
        }
    }
    if oci.secret_env.len() > MAX_SECRET_ENV {
        bail!("at most {MAX_SECRET_ENV} secret_env entries");
    }
    let mut size = 0;
    for (k, v) in &oci.secret_env {
        if !init::valid_env_name(k) {
            bail!("secret_env name {k:?} is not an environment variable name");
        }
        if v.expose().contains('\0') {
            bail!("secret_env {k} contains a NUL byte");
        }
        size += k.len() + v.expose().len();
    }
    if size > MAX_SECRET_ENV_BYTES {
        bail!("secret_env is larger than {MAX_SECRET_ENV_BYTES} bytes");
    }
    Ok(())
}

/// The forwards for `ports` (loopback) and `expose` (gateway), refused when another VM on this Mac already listens
/// there.
fn forwards(oci: &OciSandboxSpec, taken: &[(u16, bool)]) -> Result<Vec<PortForward>> {
    let published = oci
        .ports
        .iter()
        .map(|p| parse_port(p).map(|(h, g)| (h, g, false)));
    let exposed = oci.expose.iter().map(|&p| Ok((p, p, true)));
    let mut out = Vec::new();
    for f in published.chain(exposed) {
        let (host_port, guest_port, guests) = f?;
        if taken.contains(&(host_port, guests)) {
            bail!("host port {host_port} is already published by another VM");
        }
        out.push(PortForward {
            host_port,
            guest_port,
            protocol: "tcp".into(),
            guests,
        });
    }
    Ok(out)
}

/// The volume shares and their mounts: share `fluxvm-vol<N>` is mounted at the volume's `guest_path`.
fn volume_shares(
    volumes: &[SandboxVolume],
    hosts: &[PathBuf],
) -> (Vec<AppleShare>, Vec<init::VolumeMount>) {
    volumes
        .iter()
        .zip(hosts)
        .enumerate()
        .map(|(i, (v, host))| {
            let tag = init::volume_tag(i);
            (
                AppleShare {
                    tag: tag.clone(),
                    host_path: host.clone(),
                    read_only: v.read_only,
                },
                init::VolumeMount {
                    tag,
                    target: v.guest_path.clone(),
                    read_only: v.read_only,
                },
            )
        })
        .unzip()
}

/// A DNS label from the sandbox name.
fn hostname_for(name: &str) -> String {
    let h: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let h = h.trim_matches('-');
    let h = &h[..h.len().min(63)];
    if h.is_empty() {
        "sandbox".into()
    } else {
        h.trim_end_matches('-').into()
    }
}

fn image_process(image: &PulledImage) -> init::ImageProcess {
    init::ImageProcess {
        entrypoint: image.config.entrypoint.clone(),
        cmd: image.config.cmd.clone(),
        env: image.config.env.clone(),
        working_dir: image.config.working_dir.clone(),
        user: image.config.user.clone(),
    }
}

/// The VM request for one OCI sandbox; pure, so the shape is unit-tested.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_create(
    name: &str,
    rootfs: &Path,
    boot: &OciBoot,
    process: init::ProcessSpec,
    spec: &OciSandboxSpec,
    (vcpus, memory_mib): (u8, u64),
    offline: bool,
    allow_hosts: &[String],
    forwards: Vec<PortForward>,
    (shares, mounts): (Vec<AppleShare>, Vec<init::VolumeMount>),
) -> Result<CreateVmRequest> {
    let init_config = init::InitConfig::Boot(init::BootConfig {
        hostname: hostname_for(name),
        process,
        read_only_root: spec.read_only_root,
        network: if offline {
            init::NetworkMode::None
        } else {
            init::NetworkMode::Dhcp
        },
        egress_proxy: !allow_hosts.is_empty(),
        exit_policy: spec.exit_policy,
        agent_port: fluxvm_guest_protocol::DEFAULT_PORT,
        restart: spec.restart,
        max_restarts: spec.max_restarts,
        healthcheck: spec.healthcheck.clone(),
        mounts,
        gateway_hosts: spec.gateway_hosts.clone(),
        networks: Vec::new(),
        hosts: spec.hosts.clone(),
        rosetta: spec.arch()? == Arch::Amd64,
    });
    let mut create: CreateVmRequest = serde_json::from_value(serde_json::json!({
        "name": name,
        "backend": "vz",
        "image": rootfs,
        "vcpus": vcpus,
        "memory_mib": memory_mib,
        "kernel": boot.kernel,
        "initrd": boot.initrd,
        "kernel_args": boot.cmdline,
        "agent": {"enabled": true, "port": fluxvm_guest_protocol::DEFAULT_PORT},
        "apple": {
            "guest_os": "linux",
            "root_read_only": spec.read_only_root,
            "egress_allow": allow_hosts,
            "init_config": init_config,
            "tagged_shares": shares,
            "networks": spec.networks,
            "rosetta": spec.arch()? == Arch::Amd64,
        },
    }))
    .context("building the OCI sandbox VM request")?;
    if let Some(apple) = create.apple.as_mut() {
        apple.secret_env = spec.secret_env.clone();
    }
    create.network = if offline {
        if !forwards.is_empty() {
            bail!("an offline sandbox has no network card to publish ports on");
        }
        NetworkSpec::None
    } else {
        NetworkSpec::User { forwards }
    };
    Ok(create)
}

/// `GET /v1/sandboxes/{id}/logs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxLogs {
    pub id: Uuid,
    pub status: VmStatus,
    /// A container sandbox: `exit_code` and `init_error` come from its init.
    pub oci: bool,
    pub exit_code: Option<i32>,
    pub init_error: Option<String>,
    /// How many times init restarted the process (`restart` policy).
    #[serde(default)]
    pub restarts: u32,
    /// `healthy` / `unhealthy` once a `healthcheck` has run.
    #[serde(default)]
    pub health: Option<String>,
    pub log: String,
}

/// An OCI sandbox VM: exec and files only through its guest agent.
pub(crate) fn is_oci(vm: &VmRecord) -> bool {
    vm.request
        .apple
        .as_ref()
        .is_some_and(|a| a.init_config.is_some())
}

impl VmManager {
    pub(crate) async fn create_oci_sandbox(
        self: &std::sync::Arc<Self>,
        req: SandboxCreateRequest,
        token_tenant: Option<&str>,
        created_by_token: Option<&str>,
    ) -> Result<VmRecord> {
        validate(&req)?;
        let oci = req.oci.clone().context("not an OCI sandbox request")?;
        if !cfg!(target_os = "macos") {
            bail!("OCI sandboxes run on the vz backend (macOS on Apple silicon)");
        }
        let (v, m) = AgentProfile::resolve(req.profile, req.vcpus, req.memory_mib);
        let vcpus = v
            .or(req.profile.map(AgentProfile::vcpus))
            .unwrap_or(OCI_DEFAULT_VCPUS);
        let memory = m
            .or(req.profile.map(AgentProfile::memory_mib))
            .unwrap_or(OCI_DEFAULT_MEMORY_MIB);
        if vcpus == 0 {
            bail!("vcpus must be at least 1");
        }
        if memory < crate::sandbox::MIN_SANDBOX_MEMORY_MIB {
            bail!(
                "memory_mib must be at least {}",
                crate::sandbox::MIN_SANDBOX_MEMORY_MIB
            );
        }
        // Boot artifacts first: without them nothing below can work, and the pull may be large.
        let boot = fluxvm_image::oci_boot::resolve(&self.cfg).await?;
        let arch = oci.arch()?;
        if arch == Arch::Amd64 && !fluxvm_apple::rosetta_installed() {
            bail!(
                "linux/amd64 images run under Rosetta, which is not installed: run `softwareupdate --install-rosetta --agree-to-license`"
            );
        }
        let image = oci_images::pull(&self.cfg, &oci.image, arch).await?;
        let process = init::resolve_process(&image_process(&image), &oci.overrides())?;
        let rootfs = oci_images::ensure_rootfs(&self.cfg, &image).await?;

        let name = req
            .name
            .clone()
            .unwrap_or_else(|| format!("sandbox-{}", Uuid::new_v4()));
        let offline = req.offline || !req.allow_hosts.is_empty();
        let taken: Vec<(u16, bool)> = self
            .list()
            .await
            .into_iter()
            .filter(|vm| vm.status != VmStatus::Failed)
            .flat_map(|vm| match vm.request.network {
                NetworkSpec::User { forwards } => forwards
                    .into_iter()
                    .map(|f| (f.host_port, f.guests))
                    .collect(),
                _ => Vec::new(),
            })
            .collect();
        let forwards = forwards(&oci, &taken)?;
        let tenant = token_tenant.map(str::to_owned);
        let hosts = self
            .resolve_volumes(tenant.as_deref(), &req.volumes, true)
            .await?;
        let mut create = build_create(
            &name,
            &rootfs,
            &boot,
            process,
            &oci,
            (vcpus, memory),
            offline,
            &req.allow_hosts,
            forwards,
            volume_shares(&req.volumes, &hosts),
        )?;
        create.ttl_seconds = req.ttl_seconds;
        crate::sandbox::enforce_sandbox_tenant(&mut create, token_tenant)?;
        create.created_by_token = created_by_token.map(String::from);
        self.enforce_token_quotas(created_by_token, &create).await?;

        let record = self.create(create).await?;
        let id = record.id;
        let labelled = async {
            self.label_vz_sandbox(id).await?;
            let labels = BTreeMap::from([
                (
                    oci_images::OCI_LABEL.to_owned(),
                    Some(image.manifest_digest.clone()),
                ),
                (OCI_IMAGE_LABEL.to_owned(), Some(image.reference.clone())),
            ]);
            self.patch(id, VmPatch { name: None, labels }).await?;
            self.wait_oci_ready(id, READY_TIMEOUT).await
        }
        .await;
        if let Err(e) = labelled {
            let _ = self.delete(id).await;
            return Err(e.context("starting the OCI sandbox"));
        }
        let record = self.get(id).await?;
        self.write_sandbox_proxy_meta(&record, req.http_proxy_port, &req.http_proxy_ports)
            .await?;
        Ok(record)
    }

    /// The last `lines` lines of the sandbox console with, for a container sandbox, the process's exit code once it has
    /// exited and init's own startup error when it failed. The markers are looked for in the whole log, not just the tail.
    pub async fn sandbox_logs(&self, id: Uuid, lines: usize) -> Result<SandboxLogs> {
        let vm = self.get(id).await?;
        let log = match tokio::fs::read(&vm.log_path).await {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", vm.log_path.display())),
        };
        Ok(SandboxLogs {
            id,
            status: vm.status,
            oci: is_oci(&vm),
            exit_code: init::exit_code_from_log(&log),
            init_error: init::init_error_from_log(&log),
            restarts: supervise::restarts_from_log(&log),
            health: supervise::health_from_log(&log),
            log: oci_images::tail(&log, lines.max(1)),
        })
    }

    /// Ready when the agent answers a ping, or when the process has already run to completion (`exit_policy: poweroff`
    /// can stop the VM before the first ping). Init's own errors (unknown user, missing binary) fail at once.
    pub(crate) async fn wait_oci_ready(&self, id: Uuid, timeout: Duration) -> Result<()> {
        let started = Instant::now();
        loop {
            let vm = self.get(id).await?;
            let log = tokio::fs::read_to_string(&vm.log_path)
                .await
                .unwrap_or_default();
            if let Some(reason) = init::init_error_from_log(&log) {
                bail!("the container did not start: {reason}");
            }
            if init::exit_code_from_log(&log).is_some() {
                return Ok(());
            }
            if !matches!(vm.status, VmStatus::Running | VmStatus::Creating) {
                bail!(
                    "the sandbox VM stopped while booting; console: {}",
                    oci_images::tail(&log, 8)
                );
            }
            if let Ok(AgentResponse::Pong) =
                fluxvm_vsock_client::call(&vm, AgentRequest::Ping, Duration::from_secs(2)).await
            {
                return Ok(());
            }
            if started.elapsed() > timeout {
                bail!(
                    "the guest agent did not answer within {}s; console: {}",
                    timeout.as_secs(),
                    oci_images::tail(&log, 8)
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(json: serde_json::Value) -> OciSandboxSpec {
        serde_json::from_value(json).unwrap()
    }

    fn sandbox(json: serde_json::Value) -> SandboxCreateRequest {
        serde_json::from_value(json).unwrap()
    }

    #[test]
    fn spec_defaults_are_safe() {
        let s = spec(serde_json::json!({"image": "alpine:3.22"}));
        assert!(s.read_only_root);
        assert_eq!(s.exit_policy, init::ExitPolicy::Keep);
        assert!(s.command.is_none() && s.user.is_none());
    }

    #[test]
    fn oci_excludes_other_sandbox_kinds() {
        assert!(
            validate(&sandbox(
                serde_json::json!({"oci": {"image": "alpine"}, "ttl_seconds": 60})
            ))
            .is_ok()
        );
        for extra in [
            serde_json::json!({"template": "t"}),
            serde_json::json!({"image": "debian-13"}),
            serde_json::json!({"procbox": {}}),
            serde_json::json!({"gpus": 1}),
            serde_json::json!({"confidential": "auto"}),
        ] {
            let mut j = serde_json::json!({"oci": {"image": "alpine"}});
            j.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(validate(&sandbox(j.clone())).is_err(), "{j}");
        }
        assert!(validate(&sandbox(serde_json::json!({"oci": {"image": " "}}))).is_err());
        assert!(
            validate(&sandbox(serde_json::json!({
                "oci": {"image": "alpine"}, "volumes": [{"name": "v", "guest_path": "/data/v"}],
            })))
            .is_ok(),
            "volumes are persistent shares for container sandboxes"
        );
    }

    #[test]
    fn hostnames_are_dns_labels() {
        assert_eq!(hostname_for("My_Sandbox.1"), "my-sandbox-1");
        assert_eq!(hostname_for("---"), "sandbox");
        assert_eq!(hostname_for(&"a".repeat(80)).len(), 63);
    }

    #[test]
    fn create_request_boots_the_image_directly() {
        let boot = OciBoot {
            kernel: "/b/oci-kernel".into(),
            initrd: "/b/oci-initrd".into(),
            cmdline: "console=hvc0".into(),
        };
        let process = init::ProcessSpec {
            argv: vec!["/bin/sh".into()],
            env: vec![],
            cwd: "/".into(),
            user: "65534:65534".into(),
        };
        let s = spec(serde_json::json!({"image": "alpine", "exit_policy": "poweroff"}));
        let c = build_create(
            "web",
            Path::new("/c/rootfs.ext4"),
            &boot,
            process.clone(),
            &s,
            (1, 512),
            true,
            &["pypi.org".to_string()],
            vec![],
            (vec![], vec![]),
        )
        .unwrap();
        assert_eq!(c.backend, fluxvm_core::model::BackendKind::Vz);
        assert_eq!(c.image, Path::new("/c/rootfs.ext4"));
        assert_eq!(c.kernel.as_deref(), Some(Path::new("/b/oci-kernel")));
        assert!(matches!(c.network, NetworkSpec::None));
        assert!(c.agent.as_ref().is_some_and(|a| a.enabled));
        assert!(c.cloud_init.is_none());
        let apple = c.apple.as_ref().unwrap();
        assert!(apple.root_read_only);
        assert_eq!(apple.egress_allow, ["pypi.org"]);
        let init::InitConfig::Boot(b) =
            serde_json::from_value(apple.init_config.clone().unwrap()).unwrap()
        else {
            panic!("not a boot config")
        };
        assert_eq!(b.hostname, "web");
        assert_eq!(b.process, process);
        assert!(b.egress_proxy);
        assert_eq!(b.network, init::NetworkMode::None);
        assert_eq!(b.exit_policy, init::ExitPolicy::Poweroff);
        fluxvm_apple::validate_request(&c).unwrap();

        let online = build_create(
            "web",
            Path::new("/r"),
            &boot,
            process,
            &s,
            (1, 512),
            false,
            &[],
            vec![],
            (vec![], vec![]),
        )
        .unwrap();
        assert!(matches!(online.network, NetworkSpec::User { .. }));
    }

    #[test]
    fn amd64_images_get_the_rosetta_share_and_registration() {
        let boot = OciBoot {
            kernel: "/k".into(),
            initrd: "/i".into(),
            cmdline: "console=hvc0".into(),
        };
        let process = init::ProcessSpec {
            argv: vec!["/bin/sh".into()],
            env: vec![],
            cwd: "/".into(),
            user: "0:0".into(),
        };
        let build = |s: &OciSandboxSpec| {
            build_create(
                "x",
                Path::new("/r"),
                &boot,
                process.clone(),
                s,
                (1, 512),
                true,
                &[],
                vec![],
                (vec![], vec![]),
            )
            .unwrap()
        };
        let boot_cfg = |c: &CreateVmRequest| -> init::BootConfig {
            let init::InitConfig::Boot(b) =
                serde_json::from_value(c.apple.as_ref().unwrap().init_config.clone().unwrap())
                    .unwrap()
            else {
                panic!("not a boot config")
            };
            b
        };
        let amd = build(&spec(
            serde_json::json!({"image": "x", "platform": "linux/amd64"}),
        ));
        assert!(amd.apple.as_ref().unwrap().rosetta);
        assert!(boot_cfg(&amd).rosetta);
        fluxvm_apple::validate_request(&amd).unwrap();
        let arm = build(&spec(serde_json::json!({"image": "x"})));
        assert!(!arm.apple.as_ref().unwrap().rosetta);
        assert!(!boot_cfg(&arm).rosetta);
        assert!(
            validate(&sandbox(
                serde_json::json!({"oci": {"image": "x", "platform": "linux/s390x"}})
            ))
            .is_err()
        );
    }

    #[test]
    fn private_networks_and_hosts_reach_the_vm_request() {
        let boot = OciBoot {
            kernel: "/k".into(),
            initrd: "/i".into(),
            cmdline: "console=hvc0".into(),
        };
        let process = init::ProcessSpec {
            argv: vec!["/bin/sh".into()],
            env: vec![],
            cwd: "/".into(),
            user: "0:0".into(),
        };
        let s = spec(serde_json::json!({
            "image": "alpine",
            "networks": [{"name": "stack-shop", "address": "10.89.4.10/24"}],
            "hosts": [{"ip": "10.89.4.11", "names": ["db"]}],
        }));
        let c = build_create(
            "web",
            Path::new("/r"),
            &boot,
            process,
            &s,
            (1, 512),
            true,
            &[],
            vec![],
            (vec![], vec![]),
        )
        .unwrap();
        let apple = c.apple.as_ref().unwrap();
        assert_eq!(apple.networks[0].name, "stack-shop");
        assert_eq!(apple.networks[0].address.as_deref(), Some("10.89.4.10/24"));
        let init::InitConfig::Boot(b) =
            serde_json::from_value(apple.init_config.clone().unwrap()).unwrap()
        else {
            panic!("not a boot config")
        };
        assert_eq!(b.hosts[0].names, ["db"]);
        fluxvm_apple::validate_request(&c).unwrap();

        let relay = sandbox(serde_json::json!({
            "oci": {"image": "alpine", "networks": [{"name": "n"}]},
            "allow_hosts": ["pypi.org"],
        }));
        assert!(validate(&relay).is_err());
        let offline = sandbox(serde_json::json!({
            "oci": {"image": "alpine", "networks": [{"name": "n"}]},
            "offline": true,
        }));
        assert!(
            validate(&offline).is_ok(),
            "an offline sandbox may still join a private network"
        );
        let bad_host = sandbox(serde_json::json!({
            "oci": {"image": "alpine", "hosts": [{"ip": "10.89.0.2", "names": ["a b"]}]},
        }));
        assert!(validate(&bad_host).is_err());
    }

    #[test]
    fn ports_parse_like_docker() {
        assert_eq!(parse_port("8080:80").unwrap(), (8080, 80));
        assert_eq!(parse_port(" 8080:80/tcp ").unwrap(), (8080, 80));
        assert_eq!(parse_port("5000").unwrap(), (5000, 5000));
        for bad in ["80:80", "8080:80/udp", "x:80", "8080:0", "", "70000:1"] {
            assert!(parse_port(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ports_need_a_network_card_and_unique_host_ports() {
        let ok = sandbox(serde_json::json!({"oci": {"image": "nginx", "ports": ["8080:80"]}}));
        assert!(validate(&ok).is_ok());
        for bad in [
            serde_json::json!({"oci": {"image": "nginx", "ports": ["8080:80"]}, "offline": true}),
            serde_json::json!({"oci": {"image": "nginx", "ports": ["8080:80"]}, "allow_hosts": ["a.com"]}),
            serde_json::json!({"oci": {"image": "nginx", "ports": ["8080:80", "8080:81"]}}),
            serde_json::json!({"oci": {"image": "nginx", "expose": [80]}}),
            serde_json::json!({"oci": {"image": "nginx", "expose": [5432, 5432]}}),
            serde_json::json!({"oci": {"image": "nginx", "expose": [5432]}, "offline": true}),
            serde_json::json!({"oci": {"image": "nginx", "gateway_hosts": ["db"]}, "allow_hosts": ["a.com"]}),
            serde_json::json!({"oci": {"image": "nginx", "gateway_hosts": ["bad host"]}}),
            serde_json::json!({"oci": {"image": "nginx", "healthcheck": {"command": []}}}),
            serde_json::json!({"oci": {"image": "nginx", "secret_env": {"BAD-NAME": "x"}}}),
            serde_json::json!({"oci": {"image": "nginx", "secret_env": {"A": "x\u{0}y"}}}),
        ] {
            assert!(validate(&sandbox(bad.clone())).is_err(), "{bad}");
        }
        let both = spec(
            serde_json::json!({"image": "nginx", "ports": ["8080:80"], "expose": [5432], "gateway_hosts": ["db"]}),
        );
        let f = forwards(&both, &[]).unwrap();
        assert_eq!(f.len(), 2);
        assert!(!f[0].guests && f[0].host_port == 8080 && f[0].guest_port == 80);
        assert!(f[1].guests && f[1].host_port == 5432 && f[1].guest_port == 5432);
        assert!(forwards(&both, &[(8080, false)]).is_err());
        assert!(forwards(&both, &[(5432, true)]).is_err());
        assert!(forwards(&both, &[(8080, true), (5432, false)]).is_ok());
    }

    #[test]
    fn volumes_become_tagged_shares_mounted_by_init() {
        let dir = tempfile::tempdir().unwrap();
        let vols: Vec<SandboxVolume> = serde_json::from_value(serde_json::json!([
            {"name": "data", "guest_path": "/data"},
            {"name": "cfg", "guest_path": "/srv/cfg", "read_only": true},
        ]))
        .unwrap();
        let hosts = vec![dir.path().to_path_buf(), dir.path().to_path_buf()];
        let (shares, mounts) = volume_shares(&vols, &hosts);
        assert_eq!(shares[1].tag, "fluxvm-vol1");
        assert!(shares[1].read_only && !shares[0].read_only);
        assert_eq!(mounts[1].target, "/srv/cfg");
        assert!(mounts.iter().all(|m| m.validate().is_ok()));

        let boot = OciBoot {
            kernel: "/b/k".into(),
            initrd: "/b/i".into(),
            cmdline: "console=hvc0".into(),
        };
        let process = init::ProcessSpec {
            argv: vec!["nginx".into()],
            env: vec![],
            cwd: "/".into(),
            user: "0:0".into(),
        };
        let s = spec(serde_json::json!({
            "image": "nginx", "ports": ["8080:80"], "restart": "on-failure", "max_restarts": 5,
            "healthcheck": {"command": ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1"], "interval_seconds": 10},
            "secret_env": {"API_KEY": "hunter2"},
        }));
        assert!(!serde_json::to_string(&s).unwrap().contains("hunter2"));
        let c = build_create(
            "web",
            Path::new("/r"),
            &boot,
            process,
            &s,
            (1, 512),
            false,
            &[],
            forwards(&s, &[]).unwrap(),
            (shares, mounts),
        )
        .unwrap();
        let NetworkSpec::User { forwards } = &c.network else {
            panic!("no network card")
        };
        assert_eq!((forwards[0].host_port, forwards[0].guest_port), (8080, 80));
        let apple = c.apple.as_ref().unwrap();
        assert_eq!(apple.tagged_shares.len(), 2);
        let init::InitConfig::Boot(b) =
            serde_json::from_value(apple.init_config.clone().unwrap()).unwrap()
        else {
            panic!("not a boot config")
        };
        assert_eq!(b.restart, RestartPolicy::OnFailure);
        assert_eq!(b.max_restarts, Some(5));
        assert_eq!(b.healthcheck.unwrap().interval_seconds, 10);
        assert_eq!(b.mounts.len(), 2);
        assert_eq!(apple.secret_env["API_KEY"].expose(), "hunter2");
        assert!(!serde_json::to_string(&c).unwrap().contains("hunter2"));
        fluxvm_apple::validate_request(&c).unwrap();
    }
}
