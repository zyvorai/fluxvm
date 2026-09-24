// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

mod http;
pub mod snapshot;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use fluxvm_core::{
    backend::{LaunchContext, LaunchResult, VmBackend},
    config::Config,
    model::{BackendKind, CreateVmRequest, NetworkSpec, VmRecord},
    process::{run_checked, spawn_logged},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

const API_TIMEOUT: Duration = Duration::from_secs(10);

pub struct FirecrackerBackend;

/// Where each resource is placed in the config JSON: as an absolute host
/// path when launching Firecracker directly, or as a path relative to the
/// jail's own chroot root (which Firecracker sees as `/`) when launching
/// through `jailer` — see `launch_jailed`.
struct ResourcePaths {
    kernel: PathBuf,
    rootfs: PathBuf,
    seed: Option<PathBuf>,
    vsock_uds: Option<PathBuf>,
}

fn config_json(
    req: &CreateVmRequest,
    ctx: &LaunchContext,
    paths: &ResourcePaths,
    jailed: bool,
) -> Result<serde_json::Value> {
    let boot_args = req.kernel_args.clone().unwrap_or_else(|| {
        // Firecracker prod-host-setup: disable serial in production (jailed)
        // so guest cannot unbounded-flood host stdout. Lab/direct keeps
        // console=ttyS0 for debugging.
        if jailed {
            "reboot=k panic=1 pci=off root=/dev/vda rw quiet 8250.nr_uarts=0".into()
        } else {
            "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw".into()
        }
    });

    let mut root_drive = json!({
        "drive_id": "rootfs",
        "path_on_host": paths.rootfs.display().to_string(),
        "is_root_device": true,
        "is_read_only": false
    });
    if let Some(rl) = fc_rate_limiter(req.blk_mbit_limit, req.blk_ops_limit) {
        root_drive
            .as_object_mut()
            .unwrap()
            .insert("rate_limiter".into(), rl);
    }
    let mut drives = vec![root_drive];
    if let Some(seed) = &paths.seed {
        drives.push(json!({
            "drive_id": "seed",
            "path_on_host": seed.display().to_string(),
            "is_root_device": false,
            "is_read_only": true
        }));
    }

    let mut machine = json!({
        "vcpu_count": req.vcpus,
        "mem_size_mib": req.memory_mib,
        "smt": false,
        "track_dirty_pages": false
    });
    if let Some(t) = req
        .cpu_template
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        machine
            .as_object_mut()
            .unwrap()
            .insert("cpu_template".into(), json!(t));
    }

    let mut root = json!({
        "boot-source": {
            "kernel_image_path": paths.kernel.display().to_string(),
            "boot_args": boot_args
        },
        "drives": drives,
        "machine-config": machine
    });

    match &ctx.network.spec {
        NetworkSpec::None => {}
        NetworkSpec::Tap { .. } if ctx.network.tap_fd.is_some() => bail!(
            "Firecracker backend cannot attach a tap by fd: its API only accepts a host_dev_name \
             it opens itself inside its own network namespace. A bridge-less direct tap in a \
             foreign netns needs the QEMU or Cloud Hypervisor backend."
        ),
        NetworkSpec::Tap {
            tap_name: Some(tap),
            mac,
            extra,
            ..
        } => {
            let guest_mac = mac.clone().unwrap_or_else(|| "06:00:AC:10:00:02".into());
            let mut ifaces = Vec::new();
            let mut iface = json!({
                "iface_id": "eth0",
                "guest_mac": guest_mac,
                "host_dev_name": tap
            });
            if let Some(rl) = fc_rate_limiter(req.net_mbit_limit, req.net_pps_limit) {
                iface
                    .as_object_mut()
                    .unwrap()
                    .insert("rate_limiter".into(), rl);
            }
            ifaces.push(iface);
            for (i, nic) in extra.iter().enumerate() {
                let Some(tap) = &nic.tap_name else {
                    continue;
                };
                let guest_mac = nic
                    .mac
                    .clone()
                    .unwrap_or_else(|| format!("06:00:AC:10:00:{:02x}", i + 3));
                ifaces.push(json!({
                    "iface_id": format!("eth{}", i + 1),
                    "guest_mac": guest_mac,
                    "host_dev_name": tap
                }));
            }
            root.as_object_mut()
                .unwrap()
                .insert("network-interfaces".into(), Value::from(ifaces));
        }
        NetworkSpec::Tap { tap_name: None, .. } => bail!("tap network was not prepared"),
        NetworkSpec::Macvtap { .. } => bail!(
            "Firecracker backend does not support macvtap: its API only accepts a host_dev_name \
             it opens itself via /dev/net/tun, with no fd-passing option for a macvtap character \
             device. Use network.mode=tap with a bridge, or mode=none."
        ),
        NetworkSpec::User { .. } => bail!("Firecracker backend requires network.mode=none or tap"),
    }

    if req.agent.as_ref().is_some_and(|a| a.enabled) {
        let cid = ctx
            .guest_cid
            .context("agent enabled but no vsock CID was assigned")?;
        let socket = paths
            .vsock_uds
            .as_ref()
            .context("agent enabled but no vsock socket path was assigned")?;
        root.as_object_mut().unwrap().insert(
            "vsock".into(),
            json!({"guest_cid": cid, "uds_path": socket.display().to_string()}),
        );
    }

    Ok(root)
}

/// Build a Firecracker `rate_limiter` object from optional Mbit/s and
/// ops/s caps. `None` or `0` for both means no limiter (omit the field).
/// Token bucket: refill the full `size` every `refill_time` ms → rate =
/// size * 1000 / refill_time per second.
fn fc_rate_limiter(mbit: Option<u32>, ops: Option<u64>) -> Option<serde_json::Value> {
    let mut obj = serde_json::Map::new();
    if let Some(mb) = mbit.filter(|&v| v > 0) {
        let bytes_per_sec = (mb as u64) * 1_000_000 / 8;
        obj.insert(
            "bandwidth".into(),
            json!({
                "size": bytes_per_sec,
                "one_time_burst": bytes_per_sec,
                "refill_time": 1000
            }),
        );
    }
    if let Some(n) = ops.filter(|&v| v > 0) {
        obj.insert(
            "ops".into(),
            json!({
                "size": n,
                "one_time_burst": n,
                "refill_time": 1000
            }),
        );
    }
    if obj.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(obj))
    }
}

#[async_trait]
impl VmBackend for FirecrackerBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Firecracker
    }

    async fn launch(
        &self,
        cfg: &Config,
        req: &CreateVmRequest,
        ctx: &LaunchContext,
    ) -> Result<LaunchResult> {
        if cfg.jailer_required() && !cfg.jailer.enabled {
            bail!(
                "Firecracker jailer is required (jailer.enforce or auth.require on non-loopback \
                 listen) but jailer.enabled is false — set [jailer] enabled = true, or disable \
                 enforce / use loopback listen for lab"
            );
        }
        if cfg.jailer.enabled {
            launch_jailed(cfg, req, ctx).await
        } else {
            launch_direct(cfg, req, ctx).await
        }
    }

    async fn pause(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        set_vm_state(vm, "Paused").await
    }

    async fn resume(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        set_vm_state(vm, "Resumed").await
    }

    async fn graceful_shutdown(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        // x86_64-only action; Firecracker has no ARM equivalent in its
        // public API today. This project targets x86_64 hosts only.
        http::request(
            control_socket(vm)?,
            "PUT",
            "/actions",
            Some(&json!({"action_type": "SendCtrlAltDel"})),
            API_TIMEOUT,
        )
        .await
    }
}

async fn launch_direct(
    cfg: &Config,
    req: &CreateVmRequest,
    ctx: &LaunchContext,
) -> Result<LaunchResult> {
    let kernel = req
        .kernel
        .as_ref()
        .or(cfg.firecracker_kernel.as_ref())
        .context(
            "Firecracker requires a Linux kernel via request.kernel or config.firecracker_kernel",
        )?;
    let paths = ResourcePaths {
        kernel: kernel.clone(),
        rootfs: ctx.disk.clone(),
        seed: ctx.seed_disk.clone(),
        vsock_uds: ctx.vsock_socket.clone(),
    };
    let api = ctx.workspace.join("firecracker.sock");
    let cfg_path = ctx.workspace.join("firecracker.json");
    fs::write(
        &cfg_path,
        serde_json::to_vec_pretty(&config_json(req, ctx, &paths, false)?)?,
    )?;
    let args = vec![
        "--api-sock".into(),
        api.display().to_string(),
        "--config-file".into(),
        cfg_path.display().to_string(),
    ];
    let (program, args) = fluxvm_core::process::netns_wrap(
        ctx.network.netns.as_deref(),
        &cfg.firecracker_binary,
        &args,
    );
    let child = spawn_logged(&program, &args, &ctx.log_path).await?;
    let pid = child
        .id()
        .context("Firecracker exited before PID was available")?;
    Ok(LaunchResult {
        pid,
        control_socket: Some(api),
        jail_path: None,
        vsock_socket: ctx.vsock_socket.clone(),
        virtiofsd_pids: Vec::new(),
        swtpm_pid: None,
    })
}

/// Runs Firecracker through its own `jailer` binary (chroot, uid/gid drop,
/// cgroups) instead of exec'ing it directly. Verified by hand against the
/// real `jailer` on the test host before writing this: `jailer` itself only
/// creates the chroot directory and places (a copy/hardlink of) the
/// exec-file inside it — the *caller* is responsible for placing every
/// other resource the jailed process needs (kernel, rootfs, its own JSON
/// config) inside that same chroot beforehand, and referencing them by
/// their in-jail path (i.e. as Firecracker itself will see them, relative
/// to its own `/`) in that config. `jailer` execs straight into Firecracker
/// after chrooting (no intermediate fork), so the pid `spawn_logged` sees
/// for the `jailer` invocation IS Firecracker's real pid — every existing
/// pid-based lifecycle path (`process_alive`, `terminate_pid`, ...) needs
/// no changes to work with a jailed VM.
async fn launch_jailed(
    cfg: &Config,
    req: &CreateVmRequest,
    ctx: &LaunchContext,
) -> Result<LaunchResult> {
    let kernel = req
        .kernel
        .as_ref()
        .or(cfg.firecracker_kernel.as_ref())
        .context(
            "Firecracker requires a Linux kernel via request.kernel or config.firecracker_kernel",
        )?;
    if !cfg.firecracker_binary.starts_with('/') {
        bail!(
            "jailer.enabled requires config.firecracker_binary to be an absolute path (jailer's \
             --exec-file needs a real path, not a bare command resolved via $PATH); got {:?}",
            cfg.firecracker_binary
        );
    }
    let exec_file_name = Path::new(&cfg.firecracker_binary)
        .file_name()
        .context("firecracker_binary has no file name component")?;

    // jailer's own convention: <chroot_base_dir>/<exec-file basename>/<id>/root/
    let chroot_root = cfg
        .jailer
        .chroot_base_dir
        .join(exec_file_name)
        .join(ctx.id.to_string())
        .join("root");
    fs::create_dir_all(&chroot_root)
        .with_context(|| format!("creating jail chroot dir {}", chroot_root.display()))?;

    link_or_copy(kernel, &chroot_root.join("vmlinux")).context("placing kernel in jail")?;
    link_or_copy(&ctx.disk, &chroot_root.join("rootfs")).context("placing rootfs in jail")?;
    let seed_in_jail = match &ctx.seed_disk {
        Some(seed) => {
            link_or_copy(seed, &chroot_root.join("seed"))
                .context("placing cloud-init seed in jail")?;
            Some(PathBuf::from("/seed"))
        }
        None => None,
    };
    // Not pre-placed: Firecracker (running inside the jail) creates this
    // socket itself at startup, same as it would outside a jail — the
    // in-jail path here just tells it *where*, under its own chrooted `/`.
    let vsock_in_jail = ctx
        .vsock_socket
        .as_ref()
        .map(|_| PathBuf::from("/vsock.sock"));

    let paths = ResourcePaths {
        kernel: PathBuf::from("/vmlinux"),
        rootfs: PathBuf::from("/rootfs"),
        seed: seed_in_jail,
        vsock_uds: vsock_in_jail.clone(),
    };
    let cfg_json_path = chroot_root.join("config.json");
    fs::write(
        &cfg_json_path,
        serde_json::to_vec_pretty(&config_json(req, ctx, &paths, true)?)?,
    )?;

    // Everything placed above is root-owned by default; Firecracker runs as
    // jailer.uid/gid after the chroot+setuid, so it needs access to all of it.
    let (jail_uid, jail_gid) =
        fluxvm_core::config::assign_tenant_uid(&cfg.state_dir, &cfg.jailer, req.tenant.as_deref())?;
    run_checked(
        "chown",
        &[
            "-R".into(),
            format!("{jail_uid}:{jail_gid}"),
            chroot_root.display().to_string(),
        ],
    )
    .await
    .context("chowning jail contents to the jailer uid/gid")?;

    let jailer_args = vec![
        "--id".into(),
        ctx.id.to_string(),
        "--exec-file".into(),
        cfg.firecracker_binary.clone(),
        "--uid".into(),
        jail_uid.to_string(),
        "--gid".into(),
        jail_gid.to_string(),
        "--chroot-base-dir".into(),
        cfg.jailer.chroot_base_dir.display().to_string(),
        "--".into(),
        "--api-sock".into(),
        "/run/firecracker.socket".into(),
        "--config-file".into(),
        "/config.json".into(),
    ];
    let (program, jailer_args) = fluxvm_core::process::netns_wrap(
        ctx.network.netns.as_deref(),
        &cfg.jailer.jailer_binary,
        &jailer_args,
    );
    let child = spawn_logged(&program, &jailer_args, &ctx.log_path).await?;
    let pid = child
        .id()
        .context("jailer exited before PID was available")?;

    let vsock_socket_host = vsock_in_jail
        .as_ref()
        .map(|_| chroot_root.join("vsock.sock"));
    Ok(LaunchResult {
        pid,
        control_socket: Some(chroot_root.join("run/firecracker.socket")),
        vsock_socket: vsock_socket_host,
        jail_path: Some(chroot_root),
        virtiofsd_pids: Vec::new(),
        swtpm_pid: None,
    })
}

/// Hardlinks `src` into `dst` (instant, no extra disk space — the common
/// case, since `jailer.chroot_base_dir` is expected on the same filesystem
/// as `state_dir`) and falls back to a real copy if that's not possible
/// (`EXDEV`, a chroot base on a different mount), matching the same
/// reflink-then-copy-fallback pattern `fluxvm_image::clone_for_vm` already
/// uses for the same underlying reason.
fn link_or_copy(src: &Path, dst: &Path) -> Result<()> {
    if fs::hard_link(src, dst).is_ok() {
        return Ok(());
    }
    fs::copy(src, dst).with_context(|| {
        format!(
            "copying {} to {} (hardlink failed, likely a cross-device chroot_base_dir)",
            src.display(),
            dst.display()
        )
    })?;
    Ok(())
}

fn control_socket(vm: &VmRecord) -> Result<&Path> {
    vm.control_socket
        .as_deref()
        .context("Firecracker VM has no control socket recorded")
}

async fn set_vm_state(vm: &VmRecord, state: &str) -> Result<()> {
    http::request(
        control_socket(vm)?,
        "PATCH",
        "/vm",
        Some(&json!({"state": state})),
        API_TIMEOUT,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_core::backend::PreparedNetwork;
    use uuid::Uuid;

    fn bare_req() -> CreateVmRequest {
        serde_json::from_value(serde_json::json!({
            "name": "t",
            "backend": "firecracker",
            "image": "/tmp/rootfs.ext4",
            "vcpus": 1,
            "memory_mib": 128,
            "network": {"mode": "none"},
        }))
        .unwrap()
    }

    fn bare_ctx() -> LaunchContext {
        LaunchContext {
            id: Uuid::nil(),
            workspace: PathBuf::from("/tmp/ws"),
            disk: PathBuf::from("/tmp/rootfs.ext4"),
            seed_disk: None,
            log_path: PathBuf::from("/tmp/fc.log"),
            network: PreparedNetwork {
                spec: NetworkSpec::None,
                tap_name: None,
                tap_fd: None,
                netns: None,
                dhcp_leasefile: None,
                guest_ip: None,
                guest_cidr: None,
                gateway: None,
            },
            guest_cid: None,
            vsock_socket: None,
            disk_format: "raw".into(),
            nbd_export: None,
        }
    }

    #[test]
    fn rate_limiter_omitted_when_unset() {
        assert!(fc_rate_limiter(None, None).is_none());
        assert!(fc_rate_limiter(Some(0), Some(0)).is_none());
    }

    #[test]
    fn rate_limiter_bandwidth_bytes_per_sec() {
        let rl = fc_rate_limiter(Some(8), None).unwrap();
        // 8 Mbit/s = 1_000_000 bytes/s
        assert_eq!(rl["bandwidth"]["size"], 1_000_000);
        assert_eq!(rl["bandwidth"]["refill_time"], 1000);
        assert!(rl.get("ops").is_none());
    }

    #[test]
    fn rate_limiter_ops_and_bandwidth_combined() {
        let rl = fc_rate_limiter(Some(1), Some(100)).unwrap();
        assert!(rl.get("bandwidth").is_some());
        assert_eq!(rl["ops"]["size"], 100);
    }

    #[test]
    fn config_json_embeds_net_and_blk_limiters() {
        let mut req = bare_req();
        req.net_mbit_limit = Some(100);
        req.net_pps_limit = Some(50_000);
        req.blk_mbit_limit = Some(200);
        req.blk_ops_limit = Some(10_000);
        let mut ctx = bare_ctx();
        ctx.network.spec = NetworkSpec::Tap {
            tap_name: Some("tap0".into()),
            bridge: None,
            mac: Some("06:00:00:00:00:01".into()),
            netns: false,
            direct: None,
            extra: vec![],
        };
        let paths = ResourcePaths {
            kernel: PathBuf::from("/vmlinux"),
            rootfs: PathBuf::from("/rootfs"),
            seed: None,
            vsock_uds: None,
        };
        let cfg = config_json(&req, &ctx, &paths, false).unwrap();
        let drives = cfg["drives"].as_array().unwrap();
        assert!(drives[0].get("rate_limiter").is_some());
        assert_eq!(drives[0]["rate_limiter"]["bandwidth"]["size"], 25_000_000);
        let ifaces = cfg["network-interfaces"].as_array().unwrap();
        assert_eq!(ifaces[0]["rate_limiter"]["ops"]["size"], 50_000);
    }

    #[test]
    fn config_json_attaches_multus_extra_nics() {
        let req = bare_req();
        let mut ctx = bare_ctx();
        ctx.network.spec = NetworkSpec::Tap {
            tap_name: Some("tap0".into()),
            bridge: Some("br0".into()),
            mac: Some("02:00:00:00:00:01".into()),
            netns: false,
            direct: None,
            extra: vec![fluxvm_core::model::ExtraNic {
                bridge: "br1".into(),
                mac: Some("02:00:00:00:00:02".into()),
                tap_name: Some("tap1".into()),
            }],
        };
        let paths = ResourcePaths {
            kernel: PathBuf::from("/vmlinux"),
            rootfs: PathBuf::from("/rootfs"),
            seed: None,
            vsock_uds: None,
        };
        let cfg = config_json(&req, &ctx, &paths, false).unwrap();
        let ifaces = cfg["network-interfaces"].as_array().unwrap();
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0]["iface_id"], "eth0");
        assert_eq!(ifaces[0]["host_dev_name"], "tap0");
        assert_eq!(ifaces[1]["iface_id"], "eth1");
        assert_eq!(ifaces[1]["host_dev_name"], "tap1");
        assert_eq!(ifaces[1]["guest_mac"], "02:00:00:00:00:02");
    }

    #[test]
    fn config_json_embeds_cpu_template() {
        let mut req = bare_req();
        req.cpu_template = Some("T2".into());
        let ctx = bare_ctx();
        let paths = ResourcePaths {
            kernel: PathBuf::from("/vmlinux"),
            rootfs: PathBuf::from("/rootfs"),
            seed: None,
            vsock_uds: None,
        };
        let cfg = config_json(&req, &ctx, &paths, false).unwrap();
        assert_eq!(cfg["machine-config"]["cpu_template"], "T2");
    }

    #[test]
    fn jailed_default_boot_args_disable_serial() {
        let req = bare_req();
        let ctx = bare_ctx();
        let paths = ResourcePaths {
            kernel: PathBuf::from("/vmlinux"),
            rootfs: PathBuf::from("/rootfs"),
            seed: None,
            vsock_uds: None,
        };
        let cfg = config_json(&req, &ctx, &paths, true).unwrap();
        let args = cfg["boot-source"]["boot_args"].as_str().unwrap();
        assert!(args.contains("8250.nr_uarts=0"));
        assert!(!args.contains("console=ttyS0"));
    }

    #[test]
    fn config_json_refuses_a_tap_that_can_only_be_attached_by_fd() {
        let req = bare_req();
        let mut ctx = bare_ctx();
        ctx.network.spec = NetworkSpec::Tap {
            tap_name: Some("tap0".into()),
            bridge: None,
            mac: Some("02:00:00:00:00:01".into()),
            netns: false,
            direct: Some(fluxvm_core::model::DirectSpec {
                outer: "eth0".into(),
                netns_path: Some("/run/netns/fvcni-abc".into()),
                mode: fluxvm_core::model::DirectMode::PeerVeth,
                guest_ips: vec![],
            }),
            extra: vec![],
        };
        ctx.network.tap_fd = Some(9);
        let paths = ResourcePaths {
            kernel: PathBuf::from("/vmlinux"),
            rootfs: PathBuf::from("/rootfs"),
            seed: None,
            vsock_uds: None,
        };
        let err = config_json(&req, &ctx, &paths, false).unwrap_err();
        assert!(format!("{err:#}").contains("by fd"), "{err:#}");
    }
}
