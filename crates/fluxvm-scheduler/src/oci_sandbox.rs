// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! OCI sandboxes on `vz`: one lightweight Linux VM per container. The image's rootfs (built once per manifest digest, see
//! [`crate::oci_images`]) is APFS-cloned for the sandbox and booted directly with the OCI kernel and initramfs; PID 1 is
//! `fluxvm-oci-init`, which starts the guest agent and runs the image's process. Exec and files go over the agent on vsock
//! only (there is no SSH in an image), and the sandbox keeps every other sandbox property: TTL, quotas, profiles,
//! offline mode or an egress allow-list, hibernation.

use crate::VmManager;
use crate::oci_images;
use crate::sandbox::SandboxCreateRequest;
use anyhow::{Context, Result, bail};
use fluxvm_core::agent_density::AgentProfile;
use fluxvm_core::model::{CreateVmRequest, NetworkSpec, VmPatch, VmRecord, VmStatus};
use fluxvm_guest_protocol::{AgentRequest, AgentResponse};
use fluxvm_image::oci_boot::OciBoot;
use fluxvm_image::oci_registry::PulledImage;
use fluxvm_oci_init::config as init;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
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
    /// linux/arm64 image, e.g. `alpine:3.22`, `ghcr.io/org/app:1.2`, `nginx@sha256:…`.
    pub image: String,
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
}

impl OciSandboxSpec {
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
    let clash = [
        (req.template.is_some(), "template"),
        (req.spec.is_some(), "spec"),
        (req.image.is_some(), "image"),
        (req.procbox.is_some(), "procbox"),
        (!req.volumes.is_empty(), "volumes"),
        (req.gpus.unwrap_or(0) > 0, "gpus"),
        (req.confidential.is_some(), "confidential"),
    ];
    if let Some((_, what)) = clash.iter().find(|(set, _)| *set) {
        bail!("oci cannot be combined with {what}: the image is the whole sandbox");
    }
    Ok(())
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
        },
    }))
    .context("building the OCI sandbox VM request")?;
    if offline {
        create.network = NetworkSpec::None;
    }
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
        let image = oci_images::pull(&self.cfg, &oci.image).await?;
        let process = init::resolve_process(&image_process(&image), &oci.overrides())?;
        let rootfs = oci_images::ensure_rootfs(&self.cfg, &image).await?;

        let name = req
            .name
            .clone()
            .unwrap_or_else(|| format!("sandbox-{}", Uuid::new_v4()));
        let offline = req.offline || !req.allow_hosts.is_empty();
        let mut create = build_create(
            &name,
            &rootfs,
            &boot,
            process,
            &oci,
            (vcpus, memory),
            offline,
            &req.allow_hosts,
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
            serde_json::json!({"volumes": [{"name": "v", "guest_path": "/data/v"}]}),
            serde_json::json!({"confidential": "auto"}),
        ] {
            let mut j = serde_json::json!({"oci": {"image": "alpine"}});
            j.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            assert!(validate(&sandbox(j.clone())).is_err(), "{j}");
        }
        assert!(validate(&sandbox(serde_json::json!({"oci": {"image": " "}}))).is_err());
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
        )
        .unwrap();
        assert!(matches!(online.network, NetworkSpec::User { .. }));
    }
}
