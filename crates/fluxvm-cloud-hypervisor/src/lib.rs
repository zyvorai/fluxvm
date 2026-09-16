// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use fluxvm_core::{
    backend::{LaunchContext, LaunchResult, VmBackend, path_arg},
    config::Config,
    model::{BackendKind, CreateVmRequest, NetworkSpec, VmRecord},
    process::{run_checked_timeout, spawn_logged, spawn_swtpm},
};
use std::time::Duration;

const CH_REMOTE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct CloudHypervisorBackend;

pub fn build_args(cfg: &Config, req: &CreateVmRequest, ctx: &LaunchContext) -> Result<Vec<String>> {
    // Restore from a prior Cloud Hypervisor snapshot — config comes from the
    // snapshot bundle, not the create request.
    if let Some(tag) = &req.loadvm_tag {
        let snap_dir = ctx.workspace.join("snapshots").join(tag);
        return Ok(vec![
            "--api-socket".into(),
            ctx.workspace.join("ch-api.sock").display().to_string(),
            "--restore".into(),
            format!("source_url=file://{}", path_arg(&snap_dir)),
        ]);
    }

    let api = ctx.workspace.join("ch-api.sock");
    let mut a = vec![
        "--api-socket".into(),
        api.display().to_string(),
        "--cpus".into(),
        if req.hyperv {
            format!("boot={},kvm_hyperv=on", req.vcpus)
        } else {
            format!("boot={}", req.vcpus)
        },
        "--memory".into(),
        format!("size={}M", req.memory_mib),
        "--disk".into(),
        format!("path={}", path_arg(&ctx.disk)),
    ];
    // QGA on CH: serial unix socket at workspace/qga.sock (same path the
    // scheduler already records). Console file keeps SAC/boot logs.
    if req.qga.as_ref().is_some_and(|q| q.enabled) {
        let qga = ctx.workspace.join("qga.sock");
        a.extend([
            "--serial".into(),
            format!("socket={}", path_arg(&qga)),
            "--console".into(),
            format!("file={}", ctx.log_path.display()),
        ]);
    } else {
        a.extend([
            "--serial".into(),
            format!("file={}", ctx.log_path.display()),
            "--console".into(),
            "off".into(),
        ]);
    }
    if let Some(seed) = &ctx.seed_disk {
        a.extend([
            "--disk".into(),
            format!("path={},readonly=on", path_arg(seed)),
        ]);
    }

    match &ctx.network.spec {
        NetworkSpec::None => {}
        NetworkSpec::Tap {
            tap_name: Some(tap),
            mac,
            ..
        } => {
            let mut n = format!("tap={tap}");
            if let Some(mac) = mac {
                n.push_str(&format!(",mac={mac}"));
            }
            a.extend(["--net".into(), n]);
        }
        NetworkSpec::Tap { tap_name: None, .. } => bail!("tap network was not prepared"),
        NetworkSpec::Macvtap { mac, .. } => {
            let fd = ctx
                .network
                .macvtap_fd
                .context("macvtap network was not prepared")?;
            let mut n = format!("fd={fd}");
            if let Some(mac) = mac {
                n.push_str(&format!(",mac={mac}"));
            }
            a.extend(["--net".into(), n]);
        }
        NetworkSpec::User { .. } => bail!(
            "Cloud Hypervisor backend requires network.mode=none, tap, or macvtap in this MVP"
        ),
    }

    if req.agent.as_ref().is_some_and(|ag| ag.enabled) {
        let cid = ctx
            .guest_cid
            .context("agent enabled but no vsock CID was assigned")?;
        let socket = ctx
            .vsock_socket
            .as_ref()
            .context("agent enabled but no vsock socket path was assigned")?;
        a.extend([
            "--vsock".into(),
            format!("cid={cid},socket={}", path_arg(socket)),
        ]);
    }

    if req.tpm.unwrap_or(false) {
        // `launch()` spawns the shared `swtpm` sidecar (see
        // fluxvm_core::process::spawn_swtpm, also used by the QEMU
        // backend) before this function ever runs, listening on this
        // exact socket. Cloud Hypervisor's own `--tpm` flag is a single
        // `socket=<path>` parameter -- no separate chardev/tpmdev/device
        // triad the way QEMU needs, CH abstracts that away itself.
        a.extend([
            "--tpm".into(),
            format!("socket={}", path_arg(&ctx.workspace.join("swtpm.sock"))),
        ]);
    }

    if let Some(kernel) = &req.kernel {
        a.extend(["--kernel".into(), path_arg(kernel)]);
        if let Some(initrd) = &req.initrd {
            a.extend(["--initramfs".into(), path_arg(initrd)]);
        }
        if let Some(kargs) = &req.kernel_args {
            a.extend(["--cmdline".into(), kargs.clone()]);
        }
    } else if let Some(fw) = req
        .firmware
        .as_ref()
        .or(cfg.cloud_hypervisor_firmware.as_ref())
    {
        a.extend(["--firmware".into(), path_arg(fw)]);
    } else {
        bail!(
            "Cloud Hypervisor needs req.kernel for direct boot or firmware/config cloud_hypervisor_firmware"
        );
    }

    a.extend(req.extra_args.clone());
    Ok(a)
}

#[async_trait]
impl VmBackend for CloudHypervisorBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::CloudHypervisor
    }

    async fn launch(
        &self,
        cfg: &Config,
        req: &CreateVmRequest,
        ctx: &LaunchContext,
    ) -> Result<LaunchResult> {
        let swtpm_pid = if req.tpm.unwrap_or(false) {
            match spawn_swtpm(cfg, ctx).await {
                Ok(pid) => Some(pid),
                Err(e) => {
                    if let Some(fd) = ctx.network.macvtap_fd {
                        fluxvm_core::process::close_fd(fd);
                    }
                    return Err(e);
                }
            }
        } else {
            None
        };

        let args = build_args(cfg, req, ctx)?;
        let (program, args) = fluxvm_core::process::netns_wrap(
            ctx.network.netns.as_deref(),
            &cfg.cloud_hypervisor_binary,
            &args,
        );
        let spawned = spawn_logged(&program, &args, &ctx.log_path).await;
        if let Some(fd) = ctx.network.macvtap_fd {
            fluxvm_core::process::close_fd(fd);
        }
        let child = match spawned {
            Ok(c) => c,
            Err(e) => {
                if let Some(pid) = swtpm_pid {
                    let _ = fluxvm_core::process::terminate_pid(pid).await;
                }
                return Err(e);
            }
        };
        let Some(pid) = child.id() else {
            if let Some(pid) = swtpm_pid {
                let _ = fluxvm_core::process::terminate_pid(pid).await;
            }
            bail!("Cloud Hypervisor exited before PID was available");
        };
        Ok(LaunchResult {
            pid,
            control_socket: Some(ctx.workspace.join("ch-api.sock")),
            jail_path: None,
            vsock_socket: ctx.vsock_socket.clone(),
            virtiofsd_pids: Vec::new(),
            swtpm_pid,
        })
    }

    async fn pause(&self, cfg: &Config, vm: &VmRecord) -> Result<()> {
        ch_remote(cfg, vm, "pause").await
    }

    async fn resume(&self, cfg: &Config, vm: &VmRecord) -> Result<()> {
        ch_remote(cfg, vm, "resume").await
    }

    async fn graceful_shutdown(&self, cfg: &Config, vm: &VmRecord) -> Result<()> {
        ch_remote(cfg, vm, "shutdown").await
    }
}

/// Pause, snapshot to `dest`, resume. `dest` is a directory URL path
/// (`file:///…`) without the scheme — written under the VM workspace.
///
/// The resume result is never discarded: this used to be a bare
/// `let _ = ch_remote(cfg, vm, "resume").await;`, so a resume failure after
/// a *successful* snapshot still returned `Ok(())` -- the caller believed
/// the snapshot fully succeeded with the VM still running, when it was
/// actually left paused with no error surfaced anywhere (the same bug
/// already fixed for the QEMU backend's own `snapshot_save`, see
/// fluxvm-qemu). Both failure combinations are reported explicitly.
pub async fn snapshot_save(cfg: &Config, vm: &VmRecord, dest: &std::path::Path) -> Result<()> {
    ch_remote(cfg, vm, "pause").await?;
    let url = format!("file://{}", path_arg(dest));
    let api = vm.workspace.join("ch-api.sock");
    let snapshot_result = run_checked_timeout(
        &cfg.ch_remote_binary,
        &[
            "--api-socket".into(),
            api.display().to_string(),
            "snapshot".into(),
            url,
        ],
        CH_REMOTE_TIMEOUT,
    )
    .await;
    if let Err(resume_err) = ch_remote(cfg, vm, "resume").await {
        return match snapshot_result {
            Ok(_) => Err(resume_err).context(
                "snapshot saved, but the VM failed to resume afterward and is now paused, not running",
            ),
            Err(snapshot_err) => Err(snapshot_err.context(format!(
                "snapshot failed, and the VM also failed to resume afterward: {resume_err}"
            ))),
        };
    }
    snapshot_result?;
    Ok(())
}

async fn ch_remote(cfg: &Config, vm: &VmRecord, subcommand: &str) -> Result<()> {
    let api = vm.workspace.join("ch-api.sock");
    run_checked_timeout(
        &cfg.ch_remote_binary,
        &[
            "--api-socket".into(),
            api.display().to_string(),
            subcommand.into(),
        ],
        CH_REMOTE_TIMEOUT,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_core::backend::PreparedNetwork;

    #[test]
    fn qga_serial_socket_flag_shape() {
        let sock = std::path::PathBuf::from("/tmp/ch-ws/qga.sock");
        let flag = format!("socket={}", path_arg(&sock));
        assert!(flag.contains("qga.sock"));
        assert!(flag.starts_with("socket="));
    }

    fn cfg() -> Config {
        Config::default()
    }

    fn req() -> CreateVmRequest {
        CreateVmRequest {
            name: "fixture".into(),
            tenant: None,
            backend: BackendKind::CloudHypervisor,
            image: "/tmp/base.raw".into(),
            vcpus: 1,
            memory_mib: 512,
            max_vcpus: None,
            max_memory_mib: None,
            loadvm_tag: None,
            disk_size_gib: None,
            kernel: None,
            initrd: None,
            firmware: Some("/usr/share/cloud-hypervisor/CLOUDHV.fd".into()),
            kernel_args: None,
            network: NetworkSpec::None,
            cloud_init: None,
            ttl_seconds: None,
            extra_args: vec![],
            agent: None,
            qga: None,
            hyperv: false,
            storage: fluxvm_core::model::StorageBackend::Default,
            shared_folders: vec![],
            numa_node: None,
            cpuset: None,
            hugepages: None,
            vfio_devices: vec![],
            pod_uid: None,
            secure_boot: None,
            tpm: None,
        }
    }

    fn ctx() -> LaunchContext {
        LaunchContext {
            id: uuid::Uuid::nil(),
            workspace: "/tmp/eph-ch-fixture".into(),
            disk: "/tmp/eph-ch-fixture/root.raw".into(),
            seed_disk: None,
            log_path: "/tmp/eph-ch-fixture/console.log".into(),
            network: PreparedNetwork {
                spec: NetworkSpec::None,
                tap_name: None,
                macvtap_fd: None,
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

    fn vm_record(workspace: std::path::PathBuf) -> VmRecord {
        VmRecord {
            id: uuid::Uuid::new_v4(),
            name: "fixture".into(),
            backend: BackendKind::CloudHypervisor,
            status: fluxvm_core::model::VmStatus::Running,
            pid: None,
            created_at: chrono_now(),
            expires_at: None,
            workspace: workspace.clone(),
            disk: workspace.join("root.raw"),
            seed_disk: None,
            tap_name: None,
            control_socket: None,
            log_path: workspace.join("console.log"),
            error: None,
            request: req(),
            guest_cid: None,
            jail_path: None,
            vsock_socket: None,
            qga_socket: None,
            cgroup_path: None,
            netns: None,
            lvm_lv: None,
            nbd_pid: None,
            virtiofsd_pids: Vec::new(),
            swtpm_pid: None,
            dhcp_leasefile: None,
            guest_ip: None,
        }
    }

    fn chrono_now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    /// Writes an executable fake `ch-remote` under `dir` whose exit code
    /// for each subcommand is looked up from `outcomes` (subcommand ->
    /// success). A subcommand not present in `outcomes` always succeeds --
    /// matching real `ch-remote`'s behavior for any call this test doesn't
    /// care about. Matches `subcommand` as a whole word anywhere in the
    /// argv (`snapshot` is followed by a URL argument, `pause`/`resume`
    /// are not, so this can't just check the last word).
    fn fake_ch_remote(dir: &std::path::Path, outcomes: &[(&str, bool)]) -> String {
        let mut script = String::from("#!/bin/sh\nargs=\" $* \"\ncase \"$args\" in\n");
        for (subcommand, ok) in outcomes {
            let exit = if *ok { 0 } else { 1 };
            script.push_str(&format!("  *\" {subcommand} \"*) exit {exit} ;;\n"));
        }
        script.push_str("  *) exit 0 ;;\nesac\n");
        let path = dir.join("fake-ch-remote.sh");
        std::fs::write(&path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path.display().to_string()
    }

    #[tokio::test]
    async fn snapshot_save_success_path_resumes() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg();
        cfg.ch_remote_binary = fake_ch_remote(dir.path(), &[]);
        let vm = vm_record(dir.path().to_path_buf());
        let dest = dir.path().join("snap");
        snapshot_save(&cfg, &vm, &dest).await.unwrap();
    }

    #[tokio::test]
    async fn snapshot_save_reports_resume_failure_after_successful_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg();
        cfg.ch_remote_binary = fake_ch_remote(dir.path(), &[("resume", false)]);
        let vm = vm_record(dir.path().to_path_buf());
        let dest = dir.path().join("snap");
        let err = snapshot_save(&cfg, &vm, &dest).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("snapshot saved") && msg.contains("resume"),
            "expected a resume-after-success message, got: {msg}"
        );
    }

    #[tokio::test]
    async fn snapshot_save_reports_both_failures() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg();
        cfg.ch_remote_binary =
            fake_ch_remote(dir.path(), &[("snapshot", false), ("resume", false)]);
        let vm = vm_record(dir.path().to_path_buf());
        let dest = dir.path().join("snap");
        let err = snapshot_save(&cfg, &vm, &dest).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("also failed to resume"),
            "expected both-failed message, got: {msg}"
        );
    }

    #[tokio::test]
    async fn snapshot_save_propagates_snapshot_failure_when_resume_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = cfg();
        cfg.ch_remote_binary = fake_ch_remote(dir.path(), &[("snapshot", false)]);
        let vm = vm_record(dir.path().to_path_buf());
        let dest = dir.path().join("snap");
        let err = snapshot_save(&cfg, &vm, &dest).await.unwrap_err();
        // The pre-existing behavior for this combination: only the
        // snapshot error, resume having succeeded needs no mention.
        assert!(!format!("{err:#}").contains("also failed to resume"));
    }

    #[test]
    fn tpm_disabled_omits_tpm_flag() {
        let args = build_args(&cfg(), &req(), &ctx()).unwrap();
        assert!(!args.iter().any(|a| a == "--tpm"));
    }

    #[test]
    fn tpm_enabled_adds_tpm_socket_flag() {
        let mut r = req();
        r.tpm = Some(true);
        let args = build_args(&cfg(), &r, &ctx()).unwrap();
        let idx = args
            .iter()
            .position(|a| a == "--tpm")
            .expect("missing --tpm flag");
        assert_eq!(args[idx + 1], "socket=/tmp/eph-ch-fixture/swtpm.sock");
    }
}
