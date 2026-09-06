// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Guest runtime: spawn Firecracker as the KVM engine behind the FluxVM
//! control API so create/exec/pause/resume work end-to-end today while the
//! in-tree KVM demo path remains available for freestanding netboot.

use crate::api::BootConfig;
use crate::config::{GuestKind, VmConfig};
use crate::VirtualMachine;
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tracing::info;

const FC_API_TIMEOUT: Duration = Duration::from_secs(10);

enum GuestEngine {
    Firecracker {
        child: Child,
        api_sock: PathBuf,
    },
    Kvm {
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    },
}

pub struct GuestHandle {
    pub workspace: PathBuf,
    engine: GuestEngine,
}

impl Drop for GuestHandle {
    fn drop(&mut self) {
        match &mut self.engine {
            GuestEngine::Firecracker { child, .. } => {
                let _ = child.start_kill();
            }
            GuestEngine::Kvm { stop, thread } => {
                stop.store(true, Ordering::SeqCst);
                if let Some(t) = thread.take() {
                    let _ = t.join();
                }
            }
        }
    }
}

impl GuestHandle {
    pub async fn pause(&self) -> Result<()> {
        match &self.engine {
            GuestEngine::Firecracker { api_sock, .. } => pause(api_sock).await,
            GuestEngine::Kvm { .. } => Ok(()),
        }
    }

    pub async fn resume(&self) -> Result<()> {
        match &self.engine {
            GuestEngine::Firecracker { api_sock, .. } => resume(api_sock).await,
            GuestEngine::Kvm { .. } => Ok(()),
        }
    }

    pub async fn shutdown(mut self) -> Result<()> {
        match &mut self.engine {
            GuestEngine::Firecracker { child, api_sock } => {
                shutdown(api_sock).await.ok();
                let _ = child.kill().await;
            }
            GuestEngine::Kvm { stop, thread } => {
                stop.store(true, Ordering::SeqCst);
                if let Some(t) = thread.take() {
                    let _ = t.join();
                }
            }
        }
        Ok(())
    }

    pub async fn snapshot_create(&self, vmstate: &Path, mem: &Path) -> Result<()> {
        match &self.engine {
            GuestEngine::Firecracker { api_sock, .. } => {
                snapshot_create(api_sock, vmstate, mem).await
            }
            GuestEngine::Kvm { .. } => {
                bail!("memory snapshots require fluxvm_engine=firecracker")
            }
        }
    }

    pub fn kill(&mut self) {
        match &mut self.engine {
            GuestEngine::Firecracker { child, .. } => {
                let _ = child.start_kill();
            }
            GuestEngine::Kvm { stop, thread } => {
                stop.store(true, Ordering::SeqCst);
                if let Some(t) = thread.take() {
                    let _ = t.join();
                }
            }
        }
    }
}

pub async fn start(cfg: &BootConfig, workspace: &Path) -> Result<GuestHandle> {
    fs::create_dir_all(workspace)?;
    let api_sock = workspace.join("firecracker.sock");
    let _ = fs::remove_file(&api_sock);
    let cfg_path = workspace.join("firecracker.json");
    fs::write(
        &cfg_path,
        serde_json::to_vec_pretty(&firecracker_config(cfg)?)?,
    )?;

    let binary =
        std::env::var("FLUXVM_FIRECRACKER_BINARY").unwrap_or_else(|_| "firecracker".into());
    let log = workspace.join("firecracker.log");
    let stdout = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)?;
    let stderr = stdout.try_clone()?;

    let mut child = Command::new(&binary)
        .args([
            "--api-sock",
            &api_sock.display().to_string(),
            "--config-file",
            &cfg_path.display().to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .process_group(0)
        .spawn()
        .with_context(|| format!("spawning Firecracker ({binary})"))?;

    // Wait until the API socket accepts connections.
    let deadline = tokio::time::Instant::now() + FC_API_TIMEOUT;
    loop {
        if tokio::time::Instant::now() > deadline {
            let _ = child.kill().await;
            bail!("Firecracker API socket not ready within {FC_API_TIMEOUT:?}");
        }
        if api_sock.exists() {
            if fc_request(&api_sock, "GET", "/", None).await.is_ok() {
                break;
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            bail!("Firecracker exited early: {status}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    info!(
        pid = child.id().unwrap_or(0),
        "Firecracker guest started under fluxvm-hypervisor"
    );
    Ok(GuestHandle {
        workspace: workspace.to_path_buf(),
        engine: GuestEngine::Firecracker { child, api_sock },
    })
}

/// Boot via the in-tree KVM path (no Firecracker child process).
pub async fn start_kvm(cfg: &BootConfig, workspace: &Path) -> Result<GuestHandle> {
    fs::create_dir_all(workspace)?;
    let vm_cfg = boot_to_vm_config(cfg)?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let ws = workspace.to_path_buf();
    let thread = std::thread::spawn(move || {
        match VirtualMachine::from_boot_config(vm_cfg) {
            Ok(vm) => {
                if let Err(e) = vm.run_until(stop_thread) {
                    eprintln!("[kvm-engine] run error: {e}");
                }
            }
            Err(e) => eprintln!("[kvm-engine] instantiate failed: {e:#}"),
        }
        let _ = ws;
    });
    info!("in-tree KVM engine guest thread started");
    Ok(GuestHandle {
        workspace: workspace.to_path_buf(),
        engine: GuestEngine::Kvm {
            stop,
            thread: Some(thread),
        },
    })
}

fn boot_to_vm_config(cfg: &BootConfig) -> Result<VmConfig> {
    Ok(VmConfig {
        memory_mib: cfg.memory_mib.min(u32::MAX as u64) as u32,
        cpus: cfg.vcpus,
        guest: GuestKind::Linux,
        kernel: Some(cfg.kernel.clone()),
        initrd: cfg.initrd.clone(),
        disk: Some(cfg.rootfs.clone()),
        tap: cfg.tap.clone(),
        mac: cfg
            .mac
            .clone()
            .unwrap_or_else(|| "02:00:AC:10:00:02".into()),
        vhost_net: true,
        net_queues: 1,
        cmdline: cfg
            .kernel_args
            .clone()
            .unwrap_or_else(|| "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw".into()),
        firmware: None,
        net_mbit_limit: 0,
        dry_run: false,
        print_host_net: false,
    })
}

fn firecracker_config(cfg: &BootConfig) -> Result<serde_json::Value> {
    let boot_args = cfg
        .kernel_args
        .clone()
        .unwrap_or_else(|| "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw".into());

    let mut drives = vec![json!({
        "drive_id": "rootfs",
        "path_on_host": cfg.rootfs.display().to_string(),
        "is_root_device": true,
        "is_read_only": false
    })];
    if let Some(seed) = &cfg.seed {
        drives.push(json!({
            "drive_id": "seed",
            "path_on_host": seed.display().to_string(),
            "is_root_device": false,
            "is_read_only": true
        }));
    }

    let mut root = json!({
        "boot-source": {
            "kernel_image_path": cfg.kernel.display().to_string(),
            "boot_args": boot_args
        },
        "drives": drives,
        "machine-config": {
            "vcpu_count": cfg.vcpus,
            "mem_size_mib": cfg.memory_mib,
            "smt": false,
            "track_dirty_pages": true
        }
    });

    if let Some(tap) = &cfg.tap {
        let guest_mac = cfg
            .mac
            .clone()
            .unwrap_or_else(|| "06:00:AC:10:00:02".into());
        root.as_object_mut().unwrap().insert(
            "network-interfaces".into(),
            json!([{
                "iface_id": "eth0",
                "guest_mac": guest_mac,
                "host_dev_name": tap
            }]),
        );
    }

    if let (Some(cid), Some(uds)) = (cfg.vsock_cid, &cfg.vsock_uds) {
        root.as_object_mut().unwrap().insert(
            "vsock".into(),
            json!({
                "guest_cid": cid,
                "uds_path": uds.display().to_string()
            }),
        );
    }

    Ok(root)
}

pub async fn pause(api: &Path) -> Result<()> {
    fc_request(api, "PATCH", "/vm", Some(&json!({"state": "Paused"}))).await
}

pub async fn resume(api: &Path) -> Result<()> {
    fc_request(api, "PATCH", "/vm", Some(&json!({"state": "Resumed"}))).await
}

pub async fn shutdown(api: &Path) -> Result<()> {
    fc_request(
        api,
        "PUT",
        "/actions",
        Some(&json!({"action_type": "SendCtrlAltDel"})),
    )
    .await
}

/// Create a full Firecracker snapshot (VM must already be Paused).
pub async fn snapshot_create(api: &Path, snapshot_path: &Path, mem_path: &Path) -> Result<()> {
    fc_request(
        api,
        "PUT",
        "/snapshot/create",
        Some(&json!({
            "snapshot_type": "Full",
            "snapshot_path": snapshot_path.display().to_string(),
            "mem_file_path": mem_path.display().to_string()
        })),
    )
    .await
}

/// Start a fresh Firecracker process and load a snapshot (fast path).
pub async fn start_from_snapshot(
    workspace: &Path,
    snapshot_path: &Path,
    mem_path: &Path,
    vsock_uds: Option<&Path>,
) -> Result<GuestHandle> {
    fs::create_dir_all(workspace)?;
    let api_sock = workspace.join("firecracker.sock");
    let _ = fs::remove_file(&api_sock);

    let binary =
        std::env::var("FLUXVM_FIRECRACKER_BINARY").unwrap_or_else(|_| "firecracker".into());
    let log = workspace.join("firecracker.log");
    let stdout = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)?;
    let stderr = stdout.try_clone()?;

    let mut child = Command::new(&binary)
        .args(["--api-sock", &api_sock.display().to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .process_group(0)
        .spawn()
        .with_context(|| format!("spawning Firecracker for snapshot load ({binary})"))?;

    let deadline = tokio::time::Instant::now() + FC_API_TIMEOUT;
    loop {
        if tokio::time::Instant::now() > deadline {
            let _ = child.kill().await;
            bail!("Firecracker API not ready for snapshot load");
        }
        if api_sock.exists() && fc_request(&api_sock, "GET", "/", None).await.is_ok() {
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            bail!("Firecracker exited before snapshot load: {status}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let mut body = json!({
        "snapshot_path": snapshot_path.display().to_string(),
        "mem_file_path": mem_path.display().to_string(),
        "track_dirty_pages": true,
        "resume_vm": true
    });
    if let Some(uds) = vsock_uds {
        body.as_object_mut()
            .unwrap()
            .insert("vsock_override".into(), json!(uds.display().to_string()));
    }

    if let Err(e) = fc_request(&api_sock, "PUT", "/snapshot/load", Some(&body)).await {
        let _ = child.kill().await;
        return Err(e).context("Firecracker snapshot load");
    }

    info!(
        pid = child.id().unwrap_or(0),
        "Firecracker restored from memory snapshot"
    );
    Ok(GuestHandle {
        workspace: workspace.to_path_buf(),
        engine: GuestEngine::Firecracker { child, api_sock },
    })
}

async fn fc_request(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<()> {
    tokio::time::timeout(FC_API_TIMEOUT, fc_request_inner(socket, method, path, body))
        .await
        .with_context(|| format!("Firecracker {method} {path} timed out"))?
}

async fn fc_request_inner(
    socket: &Path,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<()> {
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connecting to {}", socket.display()))?;
    let body_bytes = body
        .map(serde_json::to_vec)
        .transpose()?
        .unwrap_or_default();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body_bytes.len()
    );
    if !body_bytes.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.write_all(&body_bytes).await?;

    let mut raw = Vec::new();
    let boundary = loop {
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("Firecracker closed before complete headers");
        }
        raw.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&raw[..boundary]).into_owned();
    let mut body = raw.split_off(boundary + 4);
    let status: u16 = head
        .lines()
        .next()
        .context("no status line")?
        .split_whitespace()
        .nth(1)
        .context("bad status")?
        .parse()?;
    let content_length: usize = head
        .lines()
        .find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        })
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    while body.len() < content_length {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    if !(200..300).contains(&status) {
        bail!(
            "Firecracker {method} {path} -> HTTP {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    Ok(())
}
