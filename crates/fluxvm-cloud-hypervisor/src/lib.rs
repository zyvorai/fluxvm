// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use fluxvm_core::{
    backend::{LaunchContext, LaunchResult, VmBackend, path_arg, validate_migration_transport},
    config::Config,
    model::{
        BackendKind, CreateVmRequest, MigrationMode, MigrationPhase, MigrationStartRequest,
        MigrationStatus, NetworkSpec, VmRecord,
    },
    process::{output_checked_timeout, run_checked_timeout, spawn_logged, spawn_swtpm},
};
use serde_json::Value;
use std::time::Duration;

const CH_REMOTE_TIMEOUT: Duration = Duration::from_secs(10);
/// `send-migration` itself returns as soon as Cloud Hypervisor *accepts*
/// the request (verified live -- see `migration_start`), so this only ever
/// needs to cover a wedged local `ch-remote`/VMM pair, not an actual
/// migration's real transfer time. Kept a little more generous than the
/// plain `CH_REMOTE_TIMEOUT` anyway, since establishing the initial
/// destination connection (particularly `tcp:` to a real remote host) is
/// slower than the purely-local `info`/`resize`/`pause` calls that constant
/// is used for.
const CH_SEND_MIGRATION_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound this backend will ever pass to `--cpus boot=N,max=M`.
/// Deliberately the exact same value as `fluxvm-qemu`'s own
/// `MAX_VCPUS_CEILING` -- an arbitrary-but-generous shared policy choice
/// between the two backends (nowhere near either hypervisor's own real
/// limit), not a Cloud Hypervisor-specific constraint, so a Machine that
/// doesn't set `max_vcpus` gets the same headroom regardless of which
/// backend it lands on.
const MAX_VCPUS_CEILING: u8 = 254;
/// Every Cloud Hypervisor ACPI memory-hotplug add must be a whole multiple
/// of this many MiB — verified live against a real `cloud-hypervisor`/
/// `ch-remote` v53.0 pair: a non-aligned `resize --memory` target fails
/// with Cloud Hypervisor's own "the requested hotplug memory addition is
/// not a valid size". Checked up front in `hotplug_memory` for a clearer
/// error than relaying that raw one.
const MEMORY_HOTPLUG_ALIGNMENT_MIB: u64 = 128;

pub struct CloudHypervisorBackend;

/// The absolute vCPU ceiling this VM was (or would be) booted with —
/// mirrors `fluxvm-qemu`'s own default-headroom formula exactly, so a
/// Machine that doesn't set `max_vcpus` gets comparable hotplug headroom on
/// either backend. Shared between `build_args` (which passes it as `--cpus
/// boot=N,max=M`) and `hotplug_cpu` (which needs the identical ceiling to
/// give a clear "exceeds max_vcpus" error instead of relaying Cloud
/// Hypervisor's own raw one) so the two can never drift apart.
fn max_vcpus(req: &CreateVmRequest) -> u8 {
    req.max_vcpus
        .unwrap_or_else(|| req.vcpus.saturating_mul(2))
        .max(req.vcpus)
        .min(MAX_VCPUS_CEILING)
}

/// The absolute memory ceiling in MiB — same role as `max_vcpus` above,
/// mirroring `fluxvm-qemu`'s own default-headroom formula exactly. Cloud
/// Hypervisor's own `--memory` flag reserves headroom as an *additive*
/// `hotplug_size` rather than QEMU's absolute `-m maxmem=`, so `build_args`
/// itself still has to subtract `req.memory_mib` back out of this — this
/// function always returns the same absolute ceiling either backend would
/// use for the same request.
fn max_memory_mib(req: &CreateVmRequest) -> u64 {
    req.max_memory_mib.unwrap_or_else(|| {
        req.memory_mib
            .saturating_mul(2)
            .max(req.memory_mib.saturating_add(2048))
    })
}

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

    // Reserve hotplug headroom by default, exactly mirroring fluxvm-qemu's
    // own `-smp maxcpus=`/`-m maxmem=` reasoning -- a bare `--cpus boot=N`/
    // `--memory size=NM` with no `max=`/`hotplug_size=` leaves `resize`
    // nothing to grow into (verified live: `ch-remote resize --cpus`
    // against a VM booted without `max=` fails "Requested vCPUs exceed
    // maximum" the instant it asks for even one more than boot count).
    // Cloud Hypervisor's own headroom scheme is *additive* rather than
    // QEMU's absolute `maxmem=`, so `hotplug_size` here is `max_memory_mib`
    // (the same absolute ceiling `fluxvm-qemu` would compute for an
    // identical request) with `req.memory_mib` subtracted back out.
    let max_vcpus = max_vcpus(req);
    let hotplug_size_mib = max_memory_mib(req).saturating_sub(req.memory_mib);
    let api = ctx.workspace.join("ch-api.sock");
    let mut a = vec![
        "--api-socket".into(),
        api.display().to_string(),
        "--cpus".into(),
        if req.hyperv {
            format!("boot={},max={max_vcpus},kvm_hyperv=on", req.vcpus)
        } else {
            format!("boot={},max={max_vcpus}", req.vcpus)
        },
        "--memory".into(),
        format!("size={}M,hotplug_size={hotplug_size_mib}M", req.memory_mib),
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

// ZYVOR_RUNTIME_BOUNDARY_V1: node-local live-migration primitives.
/// Node-local send-side live migration for a running Cloud Hypervisor VM --
/// same `MigrationStartRequest` contract `fluxvm_qemu::migration_start`
/// already has (destination validated to `tcp:`/`unix:` by the same shared
/// [`validate_migration_transport`]), routed through `ch-remote
/// send-migration` instead of QMP's `migrate`.
///
/// Verified live against a real `cloud-hypervisor`/`ch-remote` v53.0 pair,
/// over both `unix:` and `tcp:` destinations: a running VM was fully
/// handed off from one VMM process to another -- the destination's
/// `ch-remote info` came back with the migrated config and `"state":
/// "Running"`, and the source process exited on its own right after,
/// exactly as Cloud Hypervisor's own docs describe. That source exit is
/// also already handled correctly by this project's existing reconcile
/// loop with no changes needed here: it notices the pid is gone and marks
/// the VM `Stopped` (cleaning up its tap/netns/sandbox policy on this
/// node), the same as it would for any other process that exited on its
/// own -- which is exactly the right outcome for a VM that just left this
/// node for another one.
///
/// Cloud Hypervisor's own `send-migration` has real constraints this
/// checks up front rather than relaying its raw validation error for --
/// all three verified live against that same real binary pair:
///   - it has no bandwidth-throttle knob at all (unlike QEMU's
///     `max-bandwidth`), so `bandwidth_mbps` is rejected outright instead
///     of being silently ignored;
///   - `connections` (its multifd analogue) and a `unix:` destination are
///     mutually exclusive: "UNIX sockets and connections option cannot be
///     used at the same time.";
///   - post-copy mode requires exactly one connection: "memory_mode=
///     postcopy currently requires a single connection (connections=1)."
///
/// Also verified live, and the single biggest way this contract differs
/// from QEMU's: `send-migration` returns as soon as Cloud Hypervisor
/// *accepts* the request, not once the transfer actually finishes -- even
/// pointed at a destination nothing was listening on, the call still
/// returned success immediately, with the real failure only ever showing
/// up seconds later in the VMM's own log file. Cloud Hypervisor's API has
/// no status-query or cancellation primitive to observe or stop what
/// happens next (see `RuntimeMigrationCapability::status_pollable`), so
/// the [`MigrationStatus`] returned here reports the request was accepted,
/// not a confirmed outcome -- `fluxvm-api` deliberately leaves
/// `migration_status`/`cancel_migration` qemu-only rather than inventing a
/// status this backend cannot actually report.
pub async fn migration_start(
    cfg: &Config,
    vm: &VmRecord,
    request: &MigrationStartRequest,
) -> Result<MigrationStatus> {
    validate_migration_transport(&request.destination)?;

    if request.bandwidth_mbps.is_some() {
        bail!(
            "Cloud Hypervisor's migration API has no bandwidth throttle -- leave bandwidth_mbps unset for this backend"
        );
    }
    if request.multifd_channels == Some(0) {
        bail!("multifd_channels must be >= 1 when set");
    }
    let connections = request.multifd_channels.filter(|c| *c > 1);
    let is_unix = request.destination.starts_with("unix:");
    if connections.is_some() && is_unix {
        bail!(
            "Cloud Hypervisor rejects multifd_channels > 1 over a unix: destination -- use tcp: instead, or drop multifd_channels"
        );
    }
    if connections.is_some() && request.mode == MigrationMode::PostCopy {
        bail!(
            "Cloud Hypervisor's post-copy mode requires a single connection -- leave multifd_channels unset (or 1) when mode is post-copy"
        );
    }

    let mut send_config = format!("destination_url={}", request.destination);
    if let Some(ms) = request.max_downtime_ms {
        send_config.push_str(&format!(",downtime_ms={ms}"));
    }
    if request.mode == MigrationMode::PostCopy {
        send_config.push_str(",memory_mode=postcopy");
    }
    if let Some(n) = connections {
        send_config.push_str(&format!(",connections={n}"));
    }

    let api = vm.workspace.join("ch-api.sock");
    run_checked_timeout(
        &cfg.ch_remote_binary,
        &[
            "--api-socket".into(),
            api.display().to_string(),
            "send-migration".into(),
            send_config,
        ],
        CH_SEND_MIGRATION_TIMEOUT,
    )
    .await
    .context("Cloud Hypervisor rejected the send-migration request")?;

    Ok(MigrationStatus {
        phase: MigrationPhase::Active,
        status: "accepted by Cloud Hypervisor -- this backend's migration API is fire-and-forget, \
                 success or failure is only observable by this VM disappearing from GET /v1/vms \
                 on this node (see RuntimeMigrationCapability::status_pollable)"
            .into(),
        ram_transferred: None,
        ram_remaining: None,
        ram_total: None,
        total_time_ms: None,
        downtime_ms: None,
        error: None,
    })
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

/// Hot-add `add_vcpus` vCPUs to a running Cloud Hypervisor VM without a
/// reboot. Returns the VM's new total live vCPU count. Bounded by the
/// `max_vcpus` headroom reserved at launch (`build_args`'s own `--cpus
/// boot=N,max=M`), the same contract `fluxvm-qemu::hotplug_cpu` already
/// has.
///
/// Verified live against a real `cloud-hypervisor`/`ch-remote` v53.0 pair:
/// `ch-remote resize --cpus` takes an *absolute* target vCPU count, not a
/// delta, and `ch-remote info`'s own `config.cpus.boot_vcpus` field is
/// live-mutated by a prior resize (despite the "boot" name, it reports the
/// VM's *current* count, confirmed by resizing and re-querying) -- so this
/// reads the current count first, computes the new absolute target, then
/// resizes to it. Also verified live: `resize --cpus` accepts a *smaller*
/// target than the current count (Cloud Hypervisor auto-offlines the
/// surplus vCPUs in the guest) -- deliberately not exposed here, since
/// this project's own hotplug contract is grow-only (matching
/// `fluxvm-qemu::hotplug_cpu`, which has no unplug primitive at all).
pub async fn hotplug_cpu(cfg: &Config, vm: &VmRecord, add_vcpus: u8) -> Result<u8> {
    if add_vcpus == 0 {
        bail!("add_vcpus must be greater than zero");
    }
    let api = vm.workspace.join("ch-api.sock");
    let info = ch_info(cfg, &api).await?;
    let current = cpus_boot_vcpus(&info)?;
    let ceiling = cpus_max_vcpus(&info)?;
    let target = current.checked_add(add_vcpus).filter(|t| *t <= ceiling);
    let Some(target) = target else {
        bail!(
            "adding {add_vcpus} vCPU(s) to the current {current} would exceed the {ceiling}-vCPU headroom reserved at creation"
        );
    };
    run_checked_timeout(
        &cfg.ch_remote_binary,
        &[
            "--api-socket".into(),
            api.display().to_string(),
            "resize".into(),
            "--cpus".into(),
            target.to_string(),
        ],
        CH_REMOTE_TIMEOUT,
    )
    .await
    .context("resizing vCPU count")?;
    Ok(target)
}

/// Hot-add `add_memory_mib` MiB of RAM to a running Cloud Hypervisor VM
/// without a reboot. Returns the VM's new *total* live memory in MiB —
/// same "query current, resize to an absolute new total" shape as
/// `hotplug_cpu` above (`ch-remote resize --memory` also takes an absolute
/// byte target, verified live against the same real `cloud-hypervisor`/
/// `ch-remote` v53.0 pair). Bounded by the `hotplug_size` headroom
/// `build_args` reserved at launch -- verified live: a target beyond the
/// boot-time `size + hotplug_size` ceiling fails Cloud Hypervisor's own
/// "Not enough space in the hotplug RAM region", which surfaces here
/// wrapped with which target/current values produced it rather than
/// relaying the raw string alone.
pub async fn hotplug_memory(cfg: &Config, vm: &VmRecord, add_memory_mib: u64) -> Result<u64> {
    if add_memory_mib == 0 {
        bail!("add_memory_mib must be greater than zero");
    }
    if !add_memory_mib.is_multiple_of(MEMORY_HOTPLUG_ALIGNMENT_MIB) {
        bail!(
            "add_memory_mib ({add_memory_mib}) must be a multiple of {MEMORY_HOTPLUG_ALIGNMENT_MIB}MiB -- Cloud Hypervisor's own ACPI memory hotplug requires it"
        );
    }
    let api = vm.workspace.join("ch-api.sock");
    let info = ch_info(cfg, &api).await?;
    let current_bytes = memory_size_bytes(&info)?;
    let add_bytes = add_memory_mib.saturating_mul(1024 * 1024);
    let target_bytes = current_bytes.saturating_add(add_bytes);
    run_checked_timeout(
        &cfg.ch_remote_binary,
        &[
            "--api-socket".into(),
            api.display().to_string(),
            "resize".into(),
            "--memory".into(),
            target_bytes.to_string(),
        ],
        CH_REMOTE_TIMEOUT,
    )
    .await
    .with_context(|| {
        format!(
            "resizing memory from {current_bytes} to {target_bytes} bytes (may exceed the hotplug headroom reserved at creation)"
        )
    })?;
    Ok(target_bytes / (1024 * 1024))
}

/// Runs `ch-remote info` and parses its JSON stdout -- the one query this
/// backend has for a running VM's own live vCPU/memory state (Cloud
/// Hypervisor has no QMP-style socket protocol of its own; `ch-remote` is
/// always a real subprocess call, the same shape `ch_remote`/
/// `snapshot_save` above already use for mutating calls).
async fn ch_info(cfg: &Config, api: &std::path::Path) -> Result<Value> {
    let out = output_checked_timeout(
        &cfg.ch_remote_binary,
        &[
            "--api-socket".into(),
            api.display().to_string(),
            "info".into(),
        ],
        CH_REMOTE_TIMEOUT,
    )
    .await
    .context("querying Cloud Hypervisor VM info")?;
    serde_json::from_str(&out).context("parsing `ch-remote info` output")
}

fn cpus_boot_vcpus(info: &Value) -> Result<u8> {
    json_u64(info, &["config", "cpus", "boot_vcpus"])?
        .try_into()
        .context("`ch-remote info`'s config.cpus.boot_vcpus does not fit in a u8")
}

fn cpus_max_vcpus(info: &Value) -> Result<u8> {
    json_u64(info, &["config", "cpus", "max_vcpus"])?
        .try_into()
        .context("`ch-remote info`'s config.cpus.max_vcpus does not fit in a u8")
}

fn memory_size_bytes(info: &Value) -> Result<u64> {
    json_u64(info, &["config", "memory", "size"])
}

fn json_u64(info: &Value, path: &[&str]) -> Result<u64> {
    let mut cur = info;
    for key in path {
        cur = cur
            .get(key)
            .with_context(|| format!("`ch-remote info` output has no {}", path.join(".")))?;
    }
    cur.as_u64()
        .with_context(|| format!("`ch-remote info`'s {} is not an integer", path.join(".")))
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
            created_by_token: None,
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
            net_mbit_limit: None,
            net_pps_limit: None,
            blk_mbit_limit: None,
            blk_ops_limit: None,
            cpu_template: None,
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

    /// Process-wide lock for hotplug fake-`ch-remote` tests. GitHub-hosted
    /// runners intermittently return ETXTBSY (os error 26) when parallel
    /// tokio tests exec freshly written shell scripts; holding this for the
    /// whole test body serializes those execs.
    fn hotplug_fake_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Writes an executable fake `ch-remote` for `hotplug_cpu`/
    /// `hotplug_memory` tests: `info` prints `info_json` verbatim to
    /// stdout, `resize` appends its own full argv to `log` (one line) and
    /// exits with `resize_exit`, anything else exits 0 -- lets a test
    /// assert both the *target* this crate computed (from `log`) and the
    /// resulting `Result` (from `resize_exit`), without a real
    /// `cloud-hypervisor` VMM behind the socket.
    ///
    /// Caller must hold [`hotplug_fake_lock`] for the whole test that execs
    /// the returned path.
    fn fake_ch_remote_hotplug(
        dir: &std::path::Path,
        info_json: &str,
        resize_exit: i32,
        log: &std::path::Path,
    ) -> String {
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};

        let script = format!(
            "#!/bin/sh\nargs=\" $* \"\ncase \"$args\" in\n  *\" info \"*) cat <<'CH_INFO_JSON'\n{info_json}\nCH_INFO_JSON\n    exit 0 ;;\n  *\" resize \"*) echo \"$*\" >> {log:?} ; exit {resize_exit} ;;\n  *) exit 0 ;;\nesac\n"
        );
        // Unique final path per call — never overwrite an inode another
        // thread might still be exec'ing.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("fake-ch-remote-hotplug-{n}.sh"));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(script.as_bytes()).unwrap();
            f.sync_all().unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path.display().to_string()
    }

    #[tokio::test]
    async fn hotplug_cpu_resizes_to_current_plus_add() {
        let _lock = hotplug_fake_lock();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("resize.log");
        let mut cfg = cfg();
        cfg.ch_remote_binary = fake_ch_remote_hotplug(
            dir.path(),
            r#"{"config":{"cpus":{"boot_vcpus":2,"max_vcpus":8},"memory":{"size":536870912,"hotplug_size":2147483648}}}"#,
            0,
            &log,
        );
        let vm = vm_record(dir.path().to_path_buf());
        let vcpus = hotplug_cpu(&cfg, &vm, 3).await.unwrap();
        assert_eq!(vcpus, 5);
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(
            logged.contains("resize --cpus 5"),
            "expected an absolute target of 5, got: {logged}"
        );
    }

    #[tokio::test]
    async fn hotplug_cpu_rejects_exceeding_max_vcpus_headroom() {
        let _lock = hotplug_fake_lock();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("resize.log");
        let mut cfg = cfg();
        cfg.ch_remote_binary = fake_ch_remote_hotplug(
            dir.path(),
            r#"{"config":{"cpus":{"boot_vcpus":6,"max_vcpus":8},"memory":{"size":536870912,"hotplug_size":2147483648}}}"#,
            0,
            &log,
        );
        let vm = vm_record(dir.path().to_path_buf());
        let err = hotplug_cpu(&cfg, &vm, 5).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("exceed the 8-vCPU headroom"),
            "unexpected error: {err:#}"
        );
        assert!(
            !log.exists(),
            "resize must never be called once the pre-check already refused it"
        );
    }

    #[tokio::test]
    async fn hotplug_cpu_rejects_zero() {
        let cfg = cfg();
        let dir = tempfile::tempdir().unwrap();
        let vm = vm_record(dir.path().to_path_buf());
        let err = hotplug_cpu(&cfg, &vm, 0).await.unwrap_err();
        assert!(format!("{err:#}").contains("greater than zero"));
    }

    #[tokio::test]
    async fn hotplug_cpu_propagates_a_real_resize_failure() {
        let _lock = hotplug_fake_lock();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("resize.log");
        let mut cfg = cfg();
        cfg.ch_remote_binary = fake_ch_remote_hotplug(
            dir.path(),
            r#"{"config":{"cpus":{"boot_vcpus":1,"max_vcpus":8},"memory":{"size":536870912,"hotplug_size":2147483648}}}"#,
            1,
            &log,
        );
        let vm = vm_record(dir.path().to_path_buf());
        let err = hotplug_cpu(&cfg, &vm, 1).await.unwrap_err();
        assert!(format!("{err:#}").contains("resizing vCPU count"));
    }

    #[tokio::test]
    async fn hotplug_memory_resizes_to_current_plus_add() {
        let _lock = hotplug_fake_lock();
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("resize.log");
        let mut cfg = cfg();
        cfg.ch_remote_binary = fake_ch_remote_hotplug(
            dir.path(),
            r#"{"config":{"cpus":{"boot_vcpus":1,"max_vcpus":8},"memory":{"size":536870912,"hotplug_size":2147483648}}}"#,
            0,
            &log,
        );
        let vm = vm_record(dir.path().to_path_buf());
        // 536870912 bytes (512 MiB) + 256 MiB = 805306368 bytes (768 MiB).
        let memory_mib = hotplug_memory(&cfg, &vm, 256).await.unwrap();
        assert_eq!(memory_mib, 768);
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(
            logged.contains("resize --memory 805306368"),
            "expected an absolute byte target, got: {logged}"
        );
    }

    #[tokio::test]
    async fn hotplug_memory_rejects_non_128mib_multiple() {
        let cfg = cfg();
        let dir = tempfile::tempdir().unwrap();
        let vm = vm_record(dir.path().to_path_buf());
        let err = hotplug_memory(&cfg, &vm, 100).await.unwrap_err();
        assert!(format!("{err:#}").contains("multiple of 128MiB"));
    }

    #[tokio::test]
    async fn hotplug_memory_rejects_zero() {
        let cfg = cfg();
        let dir = tempfile::tempdir().unwrap();
        let vm = vm_record(dir.path().to_path_buf());
        let err = hotplug_memory(&cfg, &vm, 0).await.unwrap_err();
        assert!(format!("{err:#}").contains("greater than zero"));
    }

    #[test]
    fn cpu_and_memory_hotplug_headroom_defaults_when_unset() {
        let args = build_args(&cfg(), &req(), &ctx()).unwrap();
        let cpus = args
            .iter()
            .position(|a| a == "--cpus")
            .map(|i| &args[i + 1])
            .unwrap();
        // req().vcpus == 1, req().memory_mib == 512 (see `req()` below) --
        // the same doubling-with-a-floor default fluxvm-qemu computes.
        assert_eq!(cpus, "boot=1,max=2");
        let memory = args
            .iter()
            .position(|a| a == "--memory")
            .map(|i| &args[i + 1])
            .unwrap();
        // max_memory_mib defaults to max(512*2, 512+2048) = 2560 (the
        // absolute ceiling); hotplug_size is that minus req.memory_mib
        // itself (512), since Cloud Hypervisor's own headroom parameter is
        // additive, not absolute.
        assert_eq!(memory, "size=512M,hotplug_size=2048M");
    }

    #[test]
    fn cpu_and_memory_hotplug_headroom_respects_explicit_request() {
        let mut r = req();
        r.vcpus = 4;
        r.max_vcpus = Some(8);
        r.memory_mib = 1024;
        r.max_memory_mib = Some(4096);
        let args = build_args(&cfg(), &r, &ctx()).unwrap();
        let cpus = args
            .iter()
            .position(|a| a == "--cpus")
            .map(|i| &args[i + 1])
            .unwrap();
        assert_eq!(cpus, "boot=4,max=8");
        let memory = args
            .iter()
            .position(|a| a == "--memory")
            .map(|i| &args[i + 1])
            .unwrap();
        assert_eq!(memory, "size=1024M,hotplug_size=3072M");
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

    fn migration_request(destination: &str) -> MigrationStartRequest {
        MigrationStartRequest {
            destination: destination.into(),
            mode: MigrationMode::PreCopy,
            bandwidth_mbps: None,
            max_downtime_ms: None,
            multifd_channels: None,
        }
    }

    /// Writes an executable fake `ch-remote` for `migration_start` tests:
    /// `send-migration` appends its own full argv to `log` (one line per
    /// call) and exits with `send_migration_exit`, anything else exits 0.
    fn fake_ch_remote_migration(
        dir: &std::path::Path,
        send_migration_exit: i32,
        log: &std::path::Path,
    ) -> String {
        let script = format!(
            "#!/bin/sh\nargs=\" $* \"\ncase \"$args\" in\n  *\" send-migration \"*) echo \"$*\" >> {log:?} ; exit {send_migration_exit} ;;\n  *) exit 0 ;;\nesac\n"
        );
        let path = dir.join("fake-ch-remote-migration.sh");
        std::fs::write(&path, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path.display().to_string()
    }

    #[tokio::test]
    async fn migration_start_rejects_a_non_tcp_unix_destination() {
        let cfg = cfg();
        let dir = tempfile::tempdir().unwrap();
        let vm = vm_record(dir.path().to_path_buf());
        let err = migration_start(&cfg, &vm, &migration_request("exec:cat > /tmp/x"))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("tcp: or unix:"));
    }

    #[tokio::test]
    async fn migration_start_rejects_bandwidth_mbps() {
        let cfg = cfg();
        let dir = tempfile::tempdir().unwrap();
        let vm = vm_record(dir.path().to_path_buf());
        let mut req = migration_request("tcp:10.0.0.5:4444");
        req.bandwidth_mbps = Some(100);
        let err = migration_start(&cfg, &vm, &req).await.unwrap_err();
        assert!(format!("{err:#}").contains("no bandwidth throttle"));
    }

    #[tokio::test]
    async fn migration_start_rejects_zero_multifd_channels() {
        let cfg = cfg();
        let dir = tempfile::tempdir().unwrap();
        let vm = vm_record(dir.path().to_path_buf());
        let mut req = migration_request("tcp:10.0.0.5:4444");
        req.multifd_channels = Some(0);
        let err = migration_start(&cfg, &vm, &req).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("greater than zero") || format!("{err:#}").contains(">= 1")
        );
    }

    #[tokio::test]
    async fn migration_start_rejects_multifd_over_a_unix_destination() {
        let cfg = cfg();
        let dir = tempfile::tempdir().unwrap();
        let vm = vm_record(dir.path().to_path_buf());
        let mut req = migration_request("unix:/tmp/mig.sock");
        req.multifd_channels = Some(4);
        let err = migration_start(&cfg, &vm, &req).await.unwrap_err();
        assert!(format!("{err:#}").contains("unix:"));
    }

    #[tokio::test]
    async fn migration_start_rejects_multifd_with_post_copy() {
        let cfg = cfg();
        let dir = tempfile::tempdir().unwrap();
        let vm = vm_record(dir.path().to_path_buf());
        let mut req = migration_request("tcp:10.0.0.5:4444");
        req.mode = MigrationMode::PostCopy;
        req.multifd_channels = Some(4);
        let err = migration_start(&cfg, &vm, &req).await.unwrap_err();
        assert!(format!("{err:#}").contains("post-copy"));
    }

    #[tokio::test]
    async fn migration_start_builds_the_expected_send_migration_config() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("send-migration.log");
        let mut cfg = cfg();
        cfg.ch_remote_binary = fake_ch_remote_migration(dir.path(), 0, &log);
        let vm = vm_record(dir.path().to_path_buf());
        let mut req = migration_request("tcp:10.0.0.5:4444");
        req.max_downtime_ms = Some(300);
        req.multifd_channels = Some(4);
        let status = migration_start(&cfg, &vm, &req).await.unwrap();
        assert_eq!(status.phase, MigrationPhase::Active);
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(
            logged.contains(
                "send-migration destination_url=tcp:10.0.0.5:4444,downtime_ms=300,connections=4"
            ),
            "unexpected argv: {logged}"
        );
    }

    #[tokio::test]
    async fn migration_start_adds_memory_mode_postcopy_for_post_copy_requests() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("send-migration.log");
        let mut cfg = cfg();
        cfg.ch_remote_binary = fake_ch_remote_migration(dir.path(), 0, &log);
        let vm = vm_record(dir.path().to_path_buf());
        let mut req = migration_request("unix:/tmp/mig.sock");
        req.mode = MigrationMode::PostCopy;
        migration_start(&cfg, &vm, &req).await.unwrap();
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(
            logged.contains("destination_url=unix:/tmp/mig.sock,memory_mode=postcopy"),
            "unexpected argv: {logged}"
        );
    }

    #[tokio::test]
    async fn migration_start_propagates_a_real_send_migration_failure() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("send-migration.log");
        let mut cfg = cfg();
        cfg.ch_remote_binary = fake_ch_remote_migration(dir.path(), 1, &log);
        let vm = vm_record(dir.path().to_path_buf());
        let err = migration_start(&cfg, &vm, &migration_request("tcp:10.0.0.5:4444"))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("send-migration request"));
    }
}
