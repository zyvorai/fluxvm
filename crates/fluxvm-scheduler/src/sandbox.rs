// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Agent-sandbox helpers: templates, AutoPause activity tracking, snapshot create.

use anyhow::{Context, Result, bail};
use chrono::{Duration, Utc};
use fluxvm_core::model::{BackendKind, CreateVmRequest, VmRecord, VmStatus};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::VmManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxCreateRequest {
    /// Optional human name (defaults to sandbox-<uuid>).
    #[serde(default)]
    pub name: Option<String>,
    /// Named template under `cfg.sandbox.templates_dir`, or a raw create spec.
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub spec: Option<CreateVmRequest>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    /// Default guest port for `/sandbox/{id}/…` HTTP proxy (overrides config).
    #[serde(default)]
    pub http_proxy_port: Option<u16>,
    /// Extra guest ports exposed via `/v1/sandboxes/{id}/http/{port}/…`.
    #[serde(default)]
    pub http_proxy_ports: Vec<u16>,
    /// Named persistent volumes to attach. Needs a QEMU-backed `template`
    /// (virtiofs is not supported by the in-tree FluxVm backend). A volume
    /// belongs to the caller's tenant and can be attached to one VM at a time.
    #[serde(default)]
    pub volumes: Vec<SandboxVolume>,
    /// Override the template's vCPU count. Must not exceed the template's own
    /// `max_vcpus` when it sets one.
    #[serde(default)]
    pub vcpus: Option<u8>,
    /// Override the template's memory. Must not exceed the template's own
    /// `max_memory_mib` when it sets one.
    #[serde(default)]
    pub memory_mib: Option<u64>,
}

pub const MIN_SANDBOX_MEMORY_MIB: u64 = 128;

/// Apply a per-sandbox size override. A template's `max_*` fields are the
/// operator's ceiling, so a caller can shrink or grow within them but never past.
fn apply_resources(
    create: &mut CreateVmRequest,
    vcpus: Option<u8>,
    memory_mib: Option<u64>,
) -> Result<()> {
    if let Some(vcpus) = vcpus {
        if vcpus == 0 {
            bail!("vcpus must be at least 1");
        }
        if let Some(max) = create.max_vcpus {
            if vcpus > max {
                bail!("vcpus {vcpus} exceeds the template's max_vcpus {max}");
            }
        }
        create.vcpus = vcpus;
    }
    if let Some(memory) = memory_mib {
        if memory < MIN_SANDBOX_MEMORY_MIB {
            bail!("memory_mib must be at least {MIN_SANDBOX_MEMORY_MIB}");
        }
        if let Some(max) = create.max_memory_mib {
            if memory > max {
                bail!("memory_mib {memory} exceeds the template's max_memory_mib {max}");
            }
        }
        create.memory_mib = memory;
    }
    Ok(())
}

/// A persistent host directory shared into a sandbox over virtiofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxVolume {
    /// Lowercase `[a-z0-9._-]`, at most 63 characters, starting with a letter or digit.
    pub name: String,
    /// Absolute mount point inside the guest.
    pub guest_path: String,
    #[serde(default)]
    pub read_only: bool,
}

pub const MAX_SANDBOX_VOLUMES: usize = 4;

/// Top-level guest directories a volume may be mounted under. The mount point
/// is interpolated into generated cloud-init commands, so it is both
/// character-restricted and kept away from system directories.
const VOLUME_GUEST_ROOTS: &[&str] = &["home", "mnt", "data", "srv", "opt", "workspace", "root"];

fn valid_volume_component(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.len() <= 63
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn validate_volume(v: &SandboxVolume) -> Result<()> {
    if !valid_volume_component(&v.name) {
        bail!(
            "invalid volume name {:?}: use 1-63 characters from [a-z0-9._-], starting with a letter or digit",
            v.name
        );
    }
    let path = &v.guest_path;
    if path.len() > 128
        || !path.starts_with('/')
        || !path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '.' | '-'))
    {
        bail!(
            "invalid guest_path {path:?}: must be absolute, at most 128 characters from [A-Za-z0-9/_.-]"
        );
    }
    let components: Vec<&str> = path[1..].split('/').collect();
    if components
        .iter()
        .any(|c| c.is_empty() || *c == "." || *c == "..")
    {
        bail!("invalid guest_path {path:?}: empty, '.' and '..' components are not allowed");
    }
    if !VOLUME_GUEST_ROOTS.contains(&components[0]) {
        bail!(
            "guest_path {path:?} must be under one of: {}",
            VOLUME_GUEST_ROOTS
                .iter()
                .map(|r| format!("/{r}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

/// Directory that backs `name` for `tenant`. Tenants get separate subtrees;
/// untenanted callers use `_shared`, which no valid tenant name can equal.
fn volume_host_path(root: &Path, tenant: Option<&str>, name: &str) -> Result<PathBuf> {
    let tenant_dir = match tenant {
        Some(t) if valid_volume_component(t) => t,
        Some(t) => bail!("tenant {t:?} cannot own volumes: it is not a valid path component"),
        None => "_shared",
    };
    Ok(root.join(tenant_dir).join(name))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub name: String,
    pub path: PathBuf,
    pub snapshot: bool,
}

impl VmManager {
    /// Create a sandbox VM. Forces `BackendKind::FluxVm` unless the embedded
    /// spec already names FluxVm. `token_tenant`, when the caller's own API
    /// token carries one, is authoritative over both a `template`'s own
    /// resolved spec and an explicit `req.spec` -- mirroring exactly how
    /// `create_vm` (`fluxvm-api`) already forces `CreateVmRequest.tenant`
    /// for a plain VM create. Without this, a tenant-scoped token could
    /// create a sandbox tagged with no tenant at all (or, worse, an
    /// explicit `spec.tenant` naming a *different* tenant), which would
    /// have made `tenant_guard_middleware`'s per-VM tenant check
    /// meaningless for that sandbox from the moment it was created.
    ///
    /// `created_by_token`, the caller's own token identity, is stamped the
    /// same way and then checked against quotas via
    /// `enforce_token_quotas` -- a sandbox is a `VmRecord` like any other
    /// (see `tenant_guard_middleware`'s own doc comment), so it must not
    /// be able to bypass `max_vms_per_token`/`max_memory_mib_per_token`
    /// just by going through this path instead of plain `create_vm`.
    pub async fn create_sandbox(
        self: &std::sync::Arc<Self>,
        req: SandboxCreateRequest,
        token_tenant: Option<&str>,
        created_by_token: Option<&str>,
    ) -> Result<VmRecord> {
        let from_template = req.template.is_some();
        let mut create = if let Some(template) = &req.template {
            self.load_template_spec(template).await?
        } else if let Some(spec) = req.spec {
            spec
        } else {
            bail!("sandbox create requires `template` or `spec`");
        };
        apply_resources(&mut create, req.vcpus, req.memory_mib)?;
        enforce_sandbox_tenant(&mut create, token_tenant)?;
        create.created_by_token = created_by_token.map(String::from);
        // A client-supplied `spec` is always the in-tree backend. Only an
        // operator-authored template may opt into QEMU (needed for volumes).
        create.backend = if from_template && create.backend == BackendKind::Qemu {
            BackendKind::Qemu
        } else {
            BackendKind::FluxVm
        };
        if let Some(name) = req.name {
            create.name = name;
        } else if create.name.is_empty() {
            create.name = format!("sandbox-{}", Uuid::new_v4());
        }
        if let Some(ttl) = req.ttl_seconds {
            create.ttl_seconds = Some(ttl);
        }
        // Agent on by default for sandbox exec/filesystem APIs.
        if create.agent.is_none() {
            create.agent = Some(fluxvm_core::model::AgentSpec {
                enabled: true,
                port: 17777,
                token: None,
            });
        } else if let Some(a) = create.agent.as_mut() {
            a.enabled = true;
        }
        self.enforce_token_quotas(created_by_token, &create).await?;
        // Held from the "already attached?" check until the VM record exists.
        let _volume_guard = if req.volumes.is_empty() {
            None
        } else {
            let guard = self.sandbox_volume_lock.lock().await;
            self.attach_volumes(&mut create, &req.volumes).await?;
            Some(guard)
        };
        let record = self.create(create).await?;
        let proxy_ports: Vec<u16> = {
            let mut ports = Vec::new();
            if let Some(p) = req.http_proxy_port {
                ports.push(p);
            } else {
                ports.push(self.cfg.sandbox.http_proxy_default_port);
            }
            for p in req.http_proxy_ports {
                if !ports.contains(&p) {
                    ports.push(p);
                }
            }
            ports
        };
        let meta = serde_json::json!({
            "http_proxy_default_port": proxy_ports.first().copied().unwrap_or(8080),
            "http_proxy_ports": proxy_ports,
        });
        tokio::fs::write(
            record.workspace.join("sandbox-proxy.json"),
            serde_json::to_vec_pretty(&meta)?,
        )
        .await?;
        Ok(record)
    }

    /// Resolve `volumes` to host directories and append them to
    /// `create.shared_folders`. Fails if a volume is invalid, the sandbox is
    /// not QEMU-backed, or another VM already has the volume attached.
    async fn attach_volumes(
        &self,
        create: &mut CreateVmRequest,
        volumes: &[SandboxVolume],
    ) -> Result<()> {
        if create.backend != BackendKind::Qemu {
            bail!(
                "volumes need a QEMU-backed template: the in-tree FluxVm backend has no virtiofs support"
            );
        }
        if volumes.len() > MAX_SANDBOX_VOLUMES {
            bail!("at most {MAX_SANDBOX_VOLUMES} volumes per sandbox");
        }
        for (i, v) in volumes.iter().enumerate() {
            validate_volume(v)?;
            if volumes[..i]
                .iter()
                .any(|o| o.name == v.name || o.guest_path == v.guest_path)
            {
                bail!("duplicate volume name or guest_path: {}", v.name);
            }
        }
        let root = self
            .cfg
            .sandbox
            .volumes_dir
            .clone()
            .unwrap_or_else(|| self.cfg.state_dir.join("volumes"));
        tokio::fs::create_dir_all(&root).await?;
        let root = tokio::fs::canonicalize(&root).await?;

        let mut hosts = Vec::with_capacity(volumes.len());
        for v in volumes {
            let path = volume_host_path(&root, create.tenant.as_deref(), &v.name)?;
            tokio::fs::create_dir_all(&path).await?;
            // Refuse a volume directory that was replaced by a symlink out of the root.
            let resolved = tokio::fs::canonicalize(&path).await?;
            if !resolved.starts_with(&root) {
                bail!("volume {:?} resolves outside the volumes directory", v.name);
            }
            hosts.push(resolved);
        }

        let attached: Vec<PathBuf> = self
            .list()
            .await
            .into_iter()
            .filter(|vm| vm.status != VmStatus::Failed)
            .flat_map(|vm| vm.request.shared_folders.into_iter().map(|s| s.host_path))
            .collect();
        for (v, host) in volumes.iter().zip(&hosts) {
            if attached.iter().any(|a| a == host) {
                bail!("volume {:?} is already attached to another VM", v.name);
            }
        }
        for (v, host) in volumes.iter().zip(hosts) {
            create.shared_folders.push(fluxvm_core::model::SharedFolder {
                host_path: host,
                guest_path: v.guest_path.clone(),
                read_only: v.read_only,
            });
        }
        Ok(())
    }

    async fn load_template_spec(&self, name: &str) -> Result<CreateVmRequest> {
        let dir = self
            .cfg
            .sandbox
            .templates_dir
            .clone()
            .unwrap_or_else(|| self.cfg.state_dir.join("templates"));
        let spec_path = dir.join(name).join("spec.json");
        let raw = tokio::fs::read_to_string(&spec_path)
            .await
            .with_context(|| format!("reading template spec {}", spec_path.display()))?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub async fn list_templates(&self) -> Result<Vec<TemplateInfo>> {
        let dir = self
            .cfg
            .sandbox
            .templates_dir
            .clone()
            .unwrap_or_else(|| self.cfg.state_dir.join("templates"));
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        let mut rd = tokio::fs::read_dir(&dir).await?;
        while let Some(ent) = rd.next_entry().await? {
            if !ent.file_type().await?.is_dir() {
                continue;
            }
            let name = ent.file_name().to_string_lossy().into_owned();
            let snap = ent.path().join("template.snap");
            out.push(TemplateInfo {
                name,
                path: ent.path(),
                snapshot: snap.exists(),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Build a template directory from an OCI image reference via `skopeo`+`umoci` or a local rootfs tarball.
    pub async fn build_oci_template(&self, name: &str, image_ref: &str) -> Result<TemplateInfo> {
        let dir = self
            .cfg
            .sandbox
            .templates_dir
            .clone()
            .unwrap_or_else(|| self.cfg.state_dir.join("templates"));
        let tdir = dir.join(name);
        tokio::fs::create_dir_all(&tdir).await?;
        let rootfs = tdir.join("rootfs.raw");
        fluxvm_image::oci::export_rootfs_raw(image_ref, &rootfs).await?;
        let kernel = self
            .cfg
            .fluxvm_kernel
            .clone()
            .or_else(|| self.cfg.firecracker_kernel.clone())
            .context("OCI template build needs config.fluxvm_kernel or firecracker_kernel")?;
        let spec = CreateVmRequest {
            name: name.into(),
            tenant: None,
            created_by_token: None,
            backend: BackendKind::FluxVm,
            image: rootfs.clone(),
            vcpus: 1,
            memory_mib: 512,
            max_vcpus: None,
            max_memory_mib: None,
            disk_size_gib: None,
            kernel: Some(kernel),
            initrd: None,
            firmware: None,
            kernel_args: None,
            network: fluxvm_core::model::NetworkSpec::None,
            cloud_init: None,
            ttl_seconds: None,
            loadvm_tag: None,
            extra_args: Vec::new(),
            shared_memory: false,
            agent: Some(fluxvm_core::model::AgentSpec {
                enabled: true,
                port: 17777,
                token: None,
            }),
            qga: None,
            hyperv: false,
            storage: Default::default(),
            shared_folders: Vec::new(),
            numa_node: None,
            cpuset: None,
            hugepages: None,
            vfio_devices: vec![],
            pod_uid: None,
            secure_boot: None,
            tpm: None,
            security_profile: Default::default(),
            measurement_policy: None,
            net_mbit_limit: None,
            net_pps_limit: None,
            blk_mbit_limit: None,
            blk_ops_limit: None,
            cpu_template: None,
        };
        tokio::fs::write(tdir.join("spec.json"), serde_json::to_vec_pretty(&spec)?).await?;
        Ok(TemplateInfo {
            name: name.into(),
            path: tdir,
            snapshot: false,
        })
    }

    /// Snapshot a running FluxVm sandbox into its template dir (or a named path).
    pub async fn snapshot_sandbox(&self, id: Uuid, dest: &Path) -> Result<()> {
        let vm = self.get(id).await?;
        if vm.backend != BackendKind::FluxVm {
            bail!("snapshot_sandbox requires BackendKind::FluxVm");
        }
        let sock = vm
            .control_socket
            .as_ref()
            .context("sandbox has no control socket")?;
        let req = fluxvm_hypervisor::ApiRequest::SnapshotSave {
            path: dest.to_path_buf(),
        };
        let resp = fluxvm_hypervisor::control::request(sock, &req).await?;
        match resp {
            fluxvm_hypervisor::ApiResponse::Ok { .. } => Ok(()),
            fluxvm_hypervisor::ApiResponse::Error { message } => bail!("{message}"),
            other => bail!("unexpected snapshot response: {other:?}"),
        }
    }

    /// AutoPause: pause Running FluxVm sandboxes idle longer than configured.
    pub async fn autopause_tick(self: &std::sync::Arc<Self>) -> Result<usize> {
        let idle = self.cfg.sandbox.autopause_idle_secs;
        if idle == 0 {
            return Ok(0);
        }
        let cutoff = Utc::now() - Duration::seconds(idle as i64);
        let mut n = 0;
        for vm in self.list().await {
            if vm.backend != BackendKind::FluxVm || vm.status != VmStatus::Running {
                continue;
            }
            let last = self.last_activity(vm.id).await.unwrap_or(vm.created_at);
            if last < cutoff {
                if self.pause(vm.id).await.is_ok() {
                    n += 1;
                    tracing::info!(vm = %vm.id, "autopause paused idle sandbox");
                }
            }
        }
        Ok(n)
    }

    /// Default HTTP proxy port for a sandbox (`/sandbox/{id}/…`).
    pub async fn sandbox_http_proxy_port(&self, vm: &VmRecord) -> u16 {
        let path = vm.workspace.join("sandbox-proxy.json");
        if let Ok(raw) = tokio::fs::read_to_string(&path).await {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(p) = v.get("http_proxy_default_port").and_then(|p| p.as_u64()) {
                    return p as u16;
                }
            }
        }
        self.cfg.sandbox.http_proxy_default_port
    }

    pub fn spawn_autopause_loop(self: &std::sync::Arc<Self>) {
        let idle = self.cfg.sandbox.autopause_idle_secs;
        if idle == 0 {
            return;
        }
        let scan = std::cmp::max(1, self.cfg.sandbox.autopause_scan_secs);
        let mgr = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(scan));
            loop {
                interval.tick().await;
                if let Err(e) = mgr.autopause_tick().await {
                    tracing::warn!(error = %e, "autopause tick failed");
                }
            }
        });
    }
}

/// A tenant-scoped token is authoritative over a resolved sandbox spec's
/// own `tenant` field: inherited when unset, rejected outright when it
/// names a *different* tenant. Extracted as a pure, sync function (no
/// `VmManager`/I/O) so the actual enforcement decision is unit-testable
/// without needing a real `create()` call -- see `create_sandbox`'s own
/// doc comment for why this exists at all.
fn enforce_sandbox_tenant(create: &mut CreateVmRequest, token_tenant: Option<&str>) -> Result<()> {
    let Some(t) = token_tenant else {
        return Ok(());
    };
    if let Some(ref body) = create.tenant {
        if body != t {
            bail!("token tenant '{t}' cannot create a sandbox for tenant '{body}'");
        }
    }
    create.tenant = Some(t.to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req() -> CreateVmRequest {
        CreateVmRequest {
            name: String::new(),
            tenant: None,
            created_by_token: None,
            backend: BackendKind::FluxVm,
            image: PathBuf::from("/does/not/exist.qcow2"),
            vcpus: 1,
            memory_mib: 512,
            max_vcpus: None,
            max_memory_mib: None,
            loadvm_tag: None,
            disk_size_gib: None,
            kernel: None,
            initrd: None,
            firmware: None,
            kernel_args: None,
            network: fluxvm_core::model::NetworkSpec::None,
            cloud_init: None,
            ttl_seconds: None,
            extra_args: vec![],
            shared_memory: false,
            agent: None,
            qga: None,
            hyperv: false,
            storage: Default::default(),
            shared_folders: vec![],
            numa_node: None,
            cpuset: None,
            hugepages: None,
            vfio_devices: vec![],
            pod_uid: None,
            secure_boot: None,
            tpm: None,
            security_profile: Default::default(),
            measurement_policy: None,
            net_mbit_limit: None,
            net_pps_limit: None,
            blk_mbit_limit: None,
            blk_ops_limit: None,
            cpu_template: None,
        }
    }

    #[test]
    fn no_token_tenant_leaves_an_untenanted_spec_untenanted() {
        let mut create = req();
        enforce_sandbox_tenant(&mut create, None).unwrap();
        assert_eq!(create.tenant, None);
    }

    #[test]
    fn token_tenant_is_inherited_when_the_spec_names_none() {
        let mut create = req();
        enforce_sandbox_tenant(&mut create, Some("acme")).unwrap();
        assert_eq!(create.tenant.as_deref(), Some("acme"));
    }

    #[test]
    fn token_tenant_matching_the_specs_own_tenant_is_a_noop() {
        let mut create = req();
        create.tenant = Some("acme".into());
        enforce_sandbox_tenant(&mut create, Some("acme")).unwrap();
        assert_eq!(create.tenant.as_deref(), Some("acme"));
    }

    #[test]
    fn token_tenant_rejects_a_spec_naming_a_different_tenant() {
        // Without this, a tenant-scoped token could spoof a sandbox into
        // another tenant's name (or, via a template with no tenant of its
        // own, create one with no tenant at all) -- either would make
        // tenant_guard_middleware's per-record check meaningless for that
        // sandbox from the moment it was created.
        let mut create = req();
        create.tenant = Some("other-tenant".into());
        let err = enforce_sandbox_tenant(&mut create, Some("acme")).unwrap_err();
        assert!(err.to_string().contains("cannot create a sandbox"));
    }

    #[test]
    fn resources_override_the_template_within_its_ceiling() {
        let mut create = req();
        create.max_vcpus = Some(4);
        create.max_memory_mib = Some(8192);
        apply_resources(&mut create, Some(2), Some(7900)).unwrap();
        assert_eq!((create.vcpus, create.memory_mib), (2, 7900));
    }

    #[test]
    fn no_resources_leaves_the_template_alone() {
        let mut create = req();
        let (v, m) = (create.vcpus, create.memory_mib);
        apply_resources(&mut create, None, None).unwrap();
        assert_eq!((create.vcpus, create.memory_mib), (v, m));
    }

    #[test]
    fn resources_past_the_ceiling_or_below_the_floor_are_rejected() {
        let mut create = req();
        create.max_vcpus = Some(2);
        create.max_memory_mib = Some(1024);
        assert!(apply_resources(&mut create, Some(3), None).is_err());
        assert!(apply_resources(&mut create, None, Some(2048)).is_err());
        assert!(apply_resources(&mut create, Some(0), None).is_err());
        assert!(apply_resources(&mut create, None, Some(64)).is_err());
    }

    fn volume(name: &str, guest_path: &str) -> SandboxVolume {
        SandboxVolume {
            name: name.into(),
            guest_path: guest_path.into(),
            read_only: false,
        }
    }

    #[test]
    fn accepts_ordinary_volumes() {
        for (n, p) in [
            ("home", "/home/agent"),
            ("agent-1.data_x", "/data"),
            ("a", "/mnt/deep/er-path_1.2"),
            ("w", "/workspace"),
        ] {
            validate_volume(&volume(n, p)).unwrap_or_else(|e| panic!("{n} {p}: {e}"));
        }
    }

    #[test]
    fn rejects_bad_volume_names() {
        for n in ["", "Home", "-x", ".x", "a/b", "a..b", "a b", "a;b", &"x".repeat(64)] {
            assert!(validate_volume(&volume(n, "/home/a")).is_err(), "name {n:?}");
        }
    }

    #[test]
    fn rejects_unsafe_guest_paths() {
        // Anything that could alter the generated cloud-init runcmd / fstab line,
        // escape a directory, or shadow a system directory must be refused.
        for p in [
            "",
            "home/agent",
            "/",
            "/etc",
            "/etc/passwd",
            "/usr/bin",
            "/home/../etc",
            "/home/./a",
            "/home//a",
            "/home/a/",
            "/home/a b",
            "/home/a;reboot",
            "/home/a'b",
            "/home/a\nb",
            "/home/$(id)",
            "/proc/x",
        ] {
            assert!(validate_volume(&volume("v", p)).is_err(), "path {p:?}");
        }
    }

    #[test]
    fn volume_paths_are_scoped_per_tenant() {
        let root = Path::new("/var/lib/fluxvm/volumes");
        assert_eq!(
            volume_host_path(root, Some("acme"), "home").unwrap(),
            root.join("acme/home")
        );
        assert_eq!(
            volume_host_path(root, None, "home").unwrap(),
            root.join("_shared/home")
        );
        assert_ne!(
            volume_host_path(root, Some("acme"), "home").unwrap(),
            volume_host_path(root, Some("other"), "home").unwrap()
        );
        // "_shared" is not a valid tenant name, so a tenant cannot alias the untenanted tree.
        assert!(volume_host_path(root, Some("_shared"), "home").is_err());
        assert!(volume_host_path(root, Some("../x"), "home").is_err());
    }
}
