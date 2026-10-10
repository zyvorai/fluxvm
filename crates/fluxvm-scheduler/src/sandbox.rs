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
    /// Named size (`tiny` 1 vCPU / 512 MiB, `small` 1 / 1024, `standard` 2 / 2048). Explicit
    /// `vcpus` / `memory_mib` win. A non-standard profile cold-boots (warm slots are standard-sized).
    #[serde(default)]
    pub profile: Option<fluxvm_core::agent_density::AgentProfile>,
    /// `auto` uses a hardware-encrypted VM when the host can and otherwise runs a
    /// normal one; `required` refuses to run without one. See [`crate::confidential`].
    #[serde(default)]
    pub confidential: Option<crate::confidential::ConfidentialMode>,
    /// Run this sandbox as a rootless Landlock + seccomp process on the host
    /// instead of a VM (`{}` for defaults). Needs `sandbox.procbox.enabled`;
    /// see [`crate::procbox_sandbox`].
    #[serde(default)]
    pub procbox: Option<crate::procbox_sandbox::ProcboxRequest>,
    /// How many GPUs to pass through with VFIO. FluxVM picks free ones itself, under a lock, so
    /// two callers cannot be given the same GPU: one that is bound to `vfio-pci` and that no VM or
    /// process holds. Needs a QEMU-backed `template`. Refused with `confidential` or `procbox`, and
    /// with a clear error when fewer than this many GPUs are free (HTTP 503). The chosen addresses
    /// appear in the returned record as `request.vfio_devices`. Absent or 0 means none.
    #[serde(default)]
    pub gpus: Option<u8>,
    /// vz only: give the sandbox no network card at all, so it cannot reach anything. Commands and files still work (over
    /// vsock). Cold-boots (the warm pool is for sandboxes with a network).
    #[serde(default)]
    pub offline: bool,
    /// vz only: host names the sandbox may reach (`example.com`, `*.example.com`; ports 80 and 443). Implies `offline`: the guest has
    /// no network card, and the only way out is an HTTP(S) proxy on the host that refuses everything not listed. Enforced by the host.
    #[serde(default)]
    pub allow_hosts: Vec<String>,
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
        let gpus = usize::from(req.gpus.unwrap_or(0));
        if gpus > fluxvm_core::gpu::MAX_SANDBOX_GPUS {
            bail!(
                "gpus must be at most {}",
                fluxvm_core::gpu::MAX_SANDBOX_GPUS
            );
        }
        if gpus > 0 && req.procbox.is_some() {
            bail!(
                "gpus cannot be combined with procbox: a process sandbox has no device passthrough"
            );
        }
        if gpus > 0 && req.confidential.is_some() {
            bail!(
                "gpus cannot be combined with confidential: a passed-through device is outside the encrypted guest"
            );
        }
        if let Some(pb) = req.procbox.clone() {
            return self
                .create_procbox_sandbox(req, pb, token_tenant, created_by_token)
                .await;
        }
        // Decide first, so a `required` request on a host that cannot honor it
        // fails before anything is created.
        let confidential =
            crate::confidential::resolve(req.confidential, &crate::confidential::detect())?;
        let (vcpus, memory_mib) = fluxvm_core::agent_density::AgentProfile::resolve(
            req.profile,
            req.vcpus,
            req.memory_mib,
        );
        // The shape a warm slot has: nothing but defaults asked for, and no tenant to scope the VM to (token quotas were checked above).
        let default_shape = cfg!(target_os = "macos")
            && req.template.is_none()
            && req.spec.is_none()
            && req.volumes.is_empty()
            && vcpus.is_none()
            && memory_mib.is_none()
            && gpus == 0
            && !req.offline
            && req.allow_hosts.is_empty()
            && token_tenant.is_none();
        let (claim_name, claim_ttl) = (req.name.clone(), req.ttl_seconds);
        let allow_hosts = req.allow_hosts.clone();
        let offline = req.offline || !allow_hosts.is_empty();
        let from_template = req.template.is_some();
        let mut create = if let Some(template) = &req.template {
            self.load_template_spec(template).await?
        } else if let Some(spec) = req.spec {
            spec
        } else if cfg!(target_os = "macos") {
            // Nothing asked for: a small Debian VM on the Mac's own hypervisor, so `sandbox_create {}` just works.
            serde_json::from_value(crate::sandbox_pool::default_sandbox_spec())?
        } else {
            bail!("sandbox create requires `template` or `spec`");
        };
        apply_resources(&mut create, vcpus, memory_mib)?;
        enforce_sandbox_tenant(&mut create, token_tenant)?;
        create.created_by_token = created_by_token.map(String::from);
        // On a Mac the only backend that runs is Apple's (`vz`), so a spec that did not ask for another one gets it.
        // Elsewhere a client-supplied `spec` is always the in-tree backend, and only an operator-authored template may
        // opt into QEMU (virtiofs volumes) or Firecracker (stronger microVM cell; no virtiofs: volumes stay QEMU-only).
        let on_vz = cfg!(target_os = "macos")
            && matches!(create.backend, BackendKind::Vz | BackendKind::Auto);
        create.backend = if on_vz {
            BackendKind::Vz
        } else if from_template
            && matches!(create.backend, BackendKind::Qemu | BackendKind::Firecracker)
        {
            create.backend
        } else {
            BackendKind::FluxVm
        };
        // `vfio_devices` is silently ignored by every backend but QEMU, and a caller who asked for a
        // GPU and got a CPU-only VM has been misled, so this is a hard error.
        if gpus > 0 && create.backend != BackendKind::Qemu {
            bail!("gpus need a QEMU-backed template: other backends ignore device passthrough");
        }
        if let Some(name) = req.name {
            create.name = name;
        } else if create.name.is_empty() {
            create.name = format!("sandbox-{}", Uuid::new_v4());
        }
        if let Some(ttl) = req.ttl_seconds {
            create.ttl_seconds = Some(ttl);
        }
        if offline {
            if create.backend != BackendKind::Vz {
                bail!("offline sandboxes are only supported on the vz backend (macOS)");
            }
            create.network = fluxvm_core::model::NetworkSpec::None;
        }
        if !allow_hosts.is_empty() {
            create
                .apple
                .get_or_insert_with(Default::default)
                .egress_allow = allow_hosts.clone();
            let ci = create.cloud_init.take().unwrap_or_default();
            create.cloud_init = Some(fluxvm_apple::with_egress_forwarder(ci));
        }
        if create.backend == BackendKind::Vz {
            self.prepare_vz_sandbox(&mut create)?;
        } else if create.agent.is_none() {
            // Agent on by default for sandbox exec/filesystem APIs.
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
        // Held from picking the GPUs until the VM record exists, so the next sandbox sees them taken.
        let _gpu_guard = if gpus == 0 {
            None
        } else {
            let guard = self.sandbox_gpu_lock.lock().await;
            self.assign_gpus(&mut create, gpus).await?;
            Some(guard)
        };
        let on_vz = create.backend == BackendKind::Vz;
        let claimed = if on_vz && default_shape {
            self.claim_warm_sandbox(claim_name.as_deref(), claim_ttl, created_by_token)
                .await?
        } else {
            None
        };
        if on_vz && default_shape {
            fluxvm_core::agent_density::record_warm_claim(claimed.is_some());
        }
        let mut record = match claimed {
            Some(vm) => vm,
            None => self.create(create).await?,
        };
        if on_vz {
            record = self.label_vz_sandbox(record.id).await?;
        }
        if on_vz && default_shape {
            self.spawn_pool_fill();
        }
        if on_vz {
            // A sandbox is ready when commands can run in it, so wait for the guest to accept SSH.
            let ready = match self
                .wait_vz_guest(record.id, std::time::Duration::from_secs(120))
                .await
            {
                // The proxy forwarder is installed by cloud-init, a little after sshd is up.
                Ok(guest) if !allow_hosts.is_empty() => fluxvm_apple::ssh::exec(
                    &guest,
                    "cloud-init status --wait >/dev/null 2>&1; systemctl is-active --quiet fluxvm-egress",
                    std::time::Duration::from_secs(120),
                )
                .await
                .and_then(|o| {
                    if o.exit_code == 0 {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!("the egress forwarder did not start in the guest"))
                    }
                }),
                other => other.map(|_| ()),
            };
            if let Err(e) = ready {
                let _ = self.delete(record.id).await;
                return Err(e.context("starting the sandbox"));
            }
            record = self.get(record.id).await?;
        }
        if let Some(status) = &confidential {
            crate::confidential::write_status(&record.workspace, status).await?;
        }
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

    /// vz guests have no vsock agent: exec and files go over SSH with the daemon's own key (see `vz_guest`), authorised through
    /// cloud-init for the sandbox user.
    pub(crate) fn prepare_vz_sandbox(&self, create: &mut CreateVmRequest) -> Result<()> {
        create.agent = None;
        let (public_key, _) = self.sandbox_ssh_key()?;
        let ci = create.cloud_init.get_or_insert_with(Default::default);
        ci.user
            .get_or_insert_with(|| crate::vz_guest::DEFAULT_SANDBOX_USER.into());
        if !ci.ssh_authorized_keys.contains(&public_key) {
            ci.ssh_authorized_keys.push(public_key);
        }
        Ok(())
    }

    /// Waits for a vz VM to report an address and accept SSH; returns how to reach it.
    pub(crate) async fn wait_vz_guest(
        &self,
        id: Uuid,
        timeout: std::time::Duration,
    ) -> Result<fluxvm_apple::ssh::GuestSsh> {
        let started = std::time::Instant::now();
        let guest = loop {
            let vm = self.get(id).await?;
            // An offline guest never reports an address; it is reached over vsock as soon as it has booted.
            if vm.guest_ip.is_some()
                || matches!(vm.request.network, fluxvm_core::model::NetworkSpec::None)
            {
                break self.vz_guest(&vm)?;
            }
            if started.elapsed() > timeout {
                bail!(
                    "the sandbox did not report an address within {}s",
                    timeout.as_secs()
                );
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        };
        fluxvm_apple::ssh::wait_ready(&guest, timeout).await?;
        Ok(guest)
    }

    /// Choose `count` free GPUs and add them to `create.vfio_devices`. The caller holds
    /// `sandbox_gpu_lock`. A GPU counts as taken when any VM that has not failed lists it, or when a
    /// process holds its VFIO group.
    async fn assign_gpus(&self, create: &mut CreateVmRequest, count: usize) -> Result<()> {
        let taken: std::collections::HashSet<String> = self
            .list()
            .await
            .into_iter()
            .filter(|vm| vm.status != VmStatus::Failed)
            .flat_map(|vm| vm.request.vfio_devices)
            .map(|b| b.trim().to_ascii_lowercase())
            .collect();
        let state_dir = self.cfg.state_dir.clone();
        let for_scan = taken.clone();
        let inventory = tokio::task::spawn_blocking(move || {
            fluxvm_core::gpu::list_host_gpus(&state_dir, &for_scan)
        })
        .await
        .context("scanning host GPUs")??;
        let picked = gpu_assignment(create, count, &inventory)?;
        create.vfio_devices.extend(picked);
        Ok(())
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
            create
                .shared_folders
                .push(fluxvm_core::model::SharedFolder {
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
            apple: None,
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
            data_disks: vec![],
            cdroms: vec![],
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
        crate::procbox_sandbox::require_guest(&vm, "a snapshot")?;
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

    /// AutoPause: pause Running sandboxes (FluxVm, and labelled `vz` ones) idle longer than configured.
    pub async fn autopause_tick(self: &std::sync::Arc<Self>) -> Result<usize> {
        // Idle reclaim (balloon inflate) runs on the same scan, before pausing; hibernate after.
        if let Err(e) = self.idle_reclaim_tick().await {
            tracing::warn!(error = %e, "idle reclaim tick failed");
        }
        self.hibernate_tick().await;
        let idle = self.cfg.sandbox.autopause_idle_secs;
        if idle == 0 {
            return Ok(0);
        }
        let cutoff = Utc::now() - Duration::seconds(idle as i64);
        let mut n = 0;
        for vm in self.list().await {
            if !crate::sandbox_density::autopause_eligible(&vm) || vm.status != VmStatus::Running {
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
        if idle == 0
            && self.cfg.sandbox.idle_balloon_secs == 0
            && self.cfg.sandbox.hibernate_idle_secs == 0
        {
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
            apple: None,
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
            data_disks: vec![],
            cdroms: vec![],
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
        for n in [
            "",
            "Home",
            "-x",
            ".x",
            "a/b",
            "a..b",
            "a b",
            "a;b",
            &"x".repeat(64),
        ] {
            assert!(
                validate_volume(&volume(n, "/home/a")).is_err(),
                "name {n:?}"
            );
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

/// The GPUs to add to `create` for a request of `count`: free ones from `inventory`, never one the
/// template already lists. A shortage is a typed error so the API can answer 503.
fn gpu_assignment(
    create: &CreateVmRequest,
    count: usize,
    inventory: &[fluxvm_core::gpu::HostGpu],
) -> Result<Vec<String>> {
    let already: std::collections::HashSet<String> = create
        .vfio_devices
        .iter()
        .map(|b| b.trim().to_ascii_lowercase())
        .collect();
    fluxvm_core::gpu::pick_free_gpus(inventory, count, &already).map_err(anyhow::Error::new)
}

#[cfg(test)]
mod gpu_tests {
    use super::*;

    fn manager() -> (tempfile::TempDir, std::sync::Arc<crate::VmManager>) {
        let d = tempfile::tempdir().unwrap();
        let mut c = fluxvm_core::config::Config::default();
        c.state_dir = d.path().join("state");
        c.run_dir = d.path().join("run");
        (d, crate::VmManager::new(c).unwrap())
    }

    /// The smallest spec the API accepts.
    fn spec() -> serde_json::Value {
        serde_json::json!({
            "name": "x", "backend": "flux-vm", "image": "/x", "vcpus": 1,
            "memory_mib": 128, "network": {"mode": "none"}
        })
    }

    fn req(v: serde_json::Value) -> SandboxCreateRequest {
        serde_json::from_value(v).unwrap()
    }

    async fn error(m: &std::sync::Arc<crate::VmManager>, v: serde_json::Value) -> String {
        match m.create_sandbox(req(v), None, None).await {
            Ok(_) => panic!("expected an error"),
            Err(e) => format!("{e:#}"),
        }
    }

    #[tokio::test]
    async fn gpus_are_refused_where_they_cannot_be_honoured() {
        let (_d, m) = manager();
        // A raw spec is always the in-tree backend, which has no device passthrough.
        let e = error(&m, serde_json::json!({"spec": spec(), "gpus": 1})).await;
        assert!(e.contains("QEMU-backed template"), "{e}");
        let e = error(&m, serde_json::json!({"procbox": {}, "gpus": 1})).await;
        assert!(e.contains("procbox"), "{e}");
        let e = error(
            &m,
            serde_json::json!({"template": "t", "gpus": 1, "confidential": "auto"}),
        )
        .await;
        assert!(e.contains("confidential"), "{e}");
        let e = error(&m, serde_json::json!({"template": "t", "gpus": 9})).await;
        assert!(e.contains("at most"), "{e}");
        // Zero is the same as absent: it reaches the normal path and fails there instead. (On a Mac that path boots a default
        // sandbox, which a unit test must not do.)
        #[cfg(not(target_os = "macos"))]
        {
            let e = error(&m, serde_json::json!({"gpus": 0})).await;
            assert!(e.contains("requires `template` or `spec`"), "{e}");
        }
    }

    fn gpu(bdf: &str, free: bool) -> fluxvm_core::gpu::HostGpu {
        fluxvm_core::gpu::HostGpu {
            bdf: bdf.into(),
            vendor_id: 0x10de,
            device_id: 0x2330,
            vendor: "NVIDIA".into(),
            class_id: 0x0302,
            driver: Some("vfio-pci".into()),
            iommu_group: Some(1),
            iommu_members: vec![bdf.into()],
            group_bound_to_vfio: true,
            group_held: !free,
            numa_node: Some(0),
            vram_gib: None,
            previous_driver: None,
        }
    }

    #[test]
    fn the_assignment_skips_devices_the_template_already_lists_and_reports_a_shortage() {
        let mut create: CreateVmRequest = serde_json::from_value(spec()).unwrap();
        create.vfio_devices = vec!["0000:01:00.0".into()];
        let inv = [
            gpu("0000:01:00.0", true),
            gpu("0000:02:00.0", true),
            gpu("0000:03:00.0", false),
        ];
        assert_eq!(gpu_assignment(&create, 1, &inv).unwrap(), ["0000:02:00.0"]);
        let err = gpu_assignment(&create, 2, &inv).unwrap_err();
        let short = err
            .downcast_ref::<fluxvm_core::gpu::GpuShortage>()
            .expect("a typed shortage");
        assert_eq!((short.requested, short.free), (2, 1));
    }
}
