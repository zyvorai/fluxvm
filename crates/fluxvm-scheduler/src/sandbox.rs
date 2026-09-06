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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub name: String,
    pub path: PathBuf,
    pub snapshot: bool,
}

impl VmManager {
    /// Create a sandbox VM. Forces `BackendKind::FluxVm` unless the embedded
    /// spec already names FluxVm.
    pub async fn create_sandbox(
        self: &std::sync::Arc<Self>,
        req: SandboxCreateRequest,
    ) -> Result<VmRecord> {
        let mut create = if let Some(template) = &req.template {
            self.load_template_spec(template).await?
        } else if let Some(spec) = req.spec {
            spec
        } else {
            bail!("sandbox create requires `template` or `spec`");
        };
        create.backend = BackendKind::FluxVm;
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
            agent: Some(fluxvm_core::model::AgentSpec {
                enabled: true,
                port: 17777,
                token: None,
            }),
            qga: None,
            storage: Default::default(),
            shared_folders: Vec::new(),
            numa_node: None,
            cpuset: None,
            hugepages: None,
            vfio_devices: vec![],
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
