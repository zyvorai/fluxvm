// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

mod qmp;

use anyhow::{Context, Result};
use async_trait::async_trait;
use fluxvm_core::{
    backend::{LaunchContext, LaunchResult, VmBackend, path_arg},
    config::Config,
    model::{BackendKind, CreateVmRequest, NetworkSpec, VmRecord},
    process::{spawn_logged, spawn_swtpm, wait_for_socket_ready},
};
use std::path::{Path, PathBuf};
use std::time::Duration;

const QMP_TIMEOUT: Duration = Duration::from_secs(10);
/// `savevm` writes guest RAM+device state into the qcow2 — can take well over
/// 10s on multi-GB cloud images, so use a longer budget than other QMP ops.
const QMP_SAVEVM_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait for each `virtiofsd` listening socket to accept
/// connections before failing the launch (QEMU is a vhost-user client).
const VIRTIOFSD_SOCKET_TIMEOUT: Duration = Duration::from_secs(15);
/// DIMM slots reserved for memory hotplug when `req.max_memory_mib` isn't
/// set. Each `device_add pc-dimm` (one per hotplug-memory call) consumes
/// one slot regardless of its size, so this caps hotplug *calls*, not
/// total addable memory (that's bounded by `maxmem` - `memory_mib`
/// instead) -- 4 is plenty for the incremental hot-adds this is meant for
/// without reserving excessive address space for VMs that never use it.
const DEFAULT_MEMORY_HOTPLUG_SLOTS: u32 = 4;
/// Upper bound this backend will ever pass to `-smp maxcpus=`. Comfortably
/// under QEMU's default limit (255 for i440fx/q35 without extra config)
/// while leaving room for `req.vcpus` itself to approach it.
const MAX_VCPUS_CEILING: u8 = 254;
/// Empty `pcie-root-port` slots reserved at boot for device hotplug (NIC,
/// extra disks). q35's root complex (`pcie.0`) itself refuses `device_add`
/// outright -- found live: "Bus 'pcie.0' does not support hotplugging" --
/// PCIe hotplug only works on a dedicated root port declared up front.
/// Each port holds exactly one device, so this also bounds how many
/// hotplug device_adds a VM can receive before needing a restart. IDs
/// follow the fixed, predictable `hotplug-pcie-0..N` convention (mirrored
/// independently in zyvor-fabricd's hotplug handlers, which target one via
/// `device_add`'s `bus` field, trying each until one's free -- the same
/// out-of-process REST relationship as the `vnc.sock` path convention
/// above, not a Rust dependency, so the convention can't be shared as code).
const HOTPLUG_PCIE_PORTS: u8 = 8;
/// First of the root ports reserved for hot-added virtiofs shares; the ports below it (0..4) are the NICs'
/// (the scheduler caps NIC hotplug at 4). Shares are tried from the top down.
const SHARE_PORTS_START: u8 = 4;

pub struct QemuBackend;

/// One `virtiofsd` instance's device-facing identity, resolved before QEMU
/// itself is built/launched — `(tag, socket_path)`, index-ordered with
/// `req.shared_folders` (`tag` is always `"fs{index}"`).
pub type VirtiofsSocket = (String, PathBuf);

pub fn build_args(
    cfg: &Config,
    req: &CreateVmRequest,
    ctx: &LaunchContext,
    virtiofs_sockets: &[VirtiofsSocket],
) -> Result<Vec<String>> {
    // `req.firmware` always wins over the host-wide `cfg.qemu_ovmf_code`
    // default when both are set -- same "per-request overrides config
    // default" convention `cloud_hypervisor_firmware` already has on the
    // Cloud Hypervisor backend.
    let effective_firmware = req.firmware.clone().or_else(|| cfg.qemu_ovmf_code.clone());
    // A `StorageBackend::Nbd` disk isn't opened as a local file at all — it's
    // attached via QEMU's native nbd: block client against the qemu-nbd
    // export this VM owns. Every other storage backend (including the
    // Default qcow2 overlay) opens `ctx.disk` directly, just with a format
    // that varies by backend (see `fluxvm_image::storage::disk_format`).
    let disk_drive = match &ctx.nbd_export {
        Some(socket) => format!("file=nbd:unix:{},if=virtio,format=raw", socket.display()),
        // writeback (not cache=none) so QMP `savevm` / internal snapshots work on
        // CoW overlays — O_DIRECT hangs human-monitor-command savevm indefinitely.
        None => format!(
            "file={},if=virtio,format={},cache=writeback",
            path_arg(&ctx.disk),
            ctx.disk_format
        ),
    };
    // Reserve hotplug headroom by default so `device_add` (CPU) and
    // `device_add pc-dimm` (memory) have somewhere to land -- found live:
    // with a bare `-smp N`/`-m N`, `query-hotpluggable-cpus` reports zero
    // unrealized slots (hotplug-cpu silently added 0 vCPUs, HTTP 200) and
    // DIMM hotplug fails outright ("no slots where allocated"). Declaring
    // extra `maxcpus`/`maxmem` address space here doesn't reserve real
    // RAM or spin up real vCPU threads up front -- only `req.vcpus` and
    // `req.memory_mib` are actually allocated at boot -- so this is cheap
    // even for VMs that never hotplug.
    let max_vcpus = req
        .max_vcpus
        .unwrap_or_else(|| req.vcpus.saturating_mul(2))
        .max(req.vcpus)
        .min(MAX_VCPUS_CEILING);
    let max_memory_mib = req.max_memory_mib.unwrap_or_else(|| {
        req.memory_mib
            .saturating_mul(2)
            .max(req.memory_mib.saturating_add(2048))
    });
    // `smm=on` is required for OVMF's SMM-based UEFI variable service --
    // needed for any pflash/OVMF boot, not only when Secure Boot
    // enforcement itself is on, matching the standard modern QEMU+OVMF+q35
    // invocation (the same shape libvirt itself generates).
    let machine = if effective_firmware.is_some() {
        "q35,accel=kvm,smm=on".to_string()
    } else {
        "q35,accel=kvm".to_string()
    };
    let mut a = vec![
        "-enable-kvm".into(),
        "-machine".into(),
        machine,
        "-cpu".into(),
        "host".into(),
        "-smp".into(),
        format!("cpus={},maxcpus={}", req.vcpus, max_vcpus),
        "-m".into(),
        format!(
            "{}M,slots={},maxmem={}M",
            req.memory_mib, DEFAULT_MEMORY_HOTPLUG_SLOTS, max_memory_mib
        ),
        "-nodefaults".into(),
        "-display".into(),
        "none".into(),
        // `-nodefaults` also drops QEMU's implicit default VGA card, so
        // without an explicit one here the guest has no graphics device
        // at all -- VNC is still a valid display *server*, but with
        // nothing in the guest to render, every frame is solid black
        // regardless of what's running inside (BIOS splash, GRUB, a
        // fully booted desktop, all equally invisible). `std` is the
        // most broadly compatible QEMU VGA model across guest OSes.
        "-vga".into(),
        "std".into(),
        // Fixed, well-known path within this VM's own workspace — no port
        // allocation, no collision bookkeeping needed. Consumers (e.g.
        // zyvor-fabric's VNC proxy) derive the same path themselves from
        // `VmRecord::workspace`, already exposed via the REST API.
        "-vnc".into(),
        format!("unix:{}", path_arg(&ctx.workspace.join("vnc.sock"))),
        "-serial".into(),
        "stdio".into(),
        "-drive".into(),
        disk_drive,
    ];
    if let Some(fw) = &effective_firmware {
        // Split code/vars pflash: `unit=0` (read-only, admin-provided
        // OVMF_CODE.fd) + `unit=1` (writable, this VM's own per-workspace
        // copy of `cfg.qemu_ovmf_vars_template` -- copied by `launch()`
        // before this function runs, never written here). `secure=on` on
        // cfi.pflash01 enables the flash variant OVMF's variable service
        // needs; it doesn't by itself force Secure Boot enforcement, which
        // is controlled entirely by the vars store's own enrolled-key
        // content -- safe/recommended to set for any OVMF boot, not only
        // when `req.secure_boot` is set.
        a.extend([
            "-global".into(),
            "driver=cfi.pflash01,property=secure,value=on".into(),
            "-drive".into(),
            format!(
                "if=pflash,format=raw,unit=0,readonly=on,file={}",
                path_arg(fw)
            ),
            "-drive".into(),
            format!(
                "if=pflash,format=raw,unit=1,file={}",
                path_arg(&ctx.workspace.join("ovmf_vars.fd"))
            ),
        ]);
    }
    for i in 0..HOTPLUG_PCIE_PORTS {
        a.extend([
            "-device".into(),
            format!(
                "pcie-root-port,id=hotplug-pcie-{i},bus=pcie.0,chassis={},slot={i}",
                i + 1
            ),
        ]);
    }
    // A virtio-scsi controller for disk hotplug with bus="scsi" -- unlike
    // the PCIe root ports above (one device per port), a single
    // virtio-scsi-pci controller can host many hot-added scsi-hd devices
    // on its own "scsi0.0" bus, so one is enough. q35 has no built-in
    // SCSI controller (unlike IDE -- see zyvor-fabricd's hotplug_disk,
    // which targets the ich9-ahci controller's existing empty ide.0..5
    // ports directly, no boot-time device needed for that path).
    a.extend([
        "-device".into(),
        "virtio-scsi-pci,id=scsi0,bus=pcie.0".into(),
    ]);

    if let Some(seed) = &ctx.seed_disk {
        a.extend([
            "-drive".into(),
            format!("file={},if=virtio,format=raw,readonly=on", path_arg(seed)),
        ]);
    }

    // virtiofs requires the guest's RAM to be backed by shared memory, not
    // QEMU's default anonymous allocation — `vhost-user-fs-pci` otherwise
    // fails to attach. `-m` above still sets the *size*; this object is
    // what makes the *backing* shareable with the virtiofsd process(es).
    if !virtiofs_sockets.is_empty() || req.shared_memory {
        a.extend([
            "-object".into(),
            format!(
                "memory-backend-memfd,id=mem,size={}M,share=on",
                req.memory_mib
            ),
        ]);
        a.extend(["-numa".into(), "node,memdev=mem".into()]);
    } else if req.hugepages == Some(true) {
        a.extend([
            "-object".into(),
            format!(
                "memory-backend-file,id=hp_mem,size={}M,mem-path=/dev/hugepages,share=on,prealloc=on",
                req.memory_mib
            ),
        ]);
        a.extend(["-numa".into(), "node,memdev=hp_mem".into()]);
    } else if req.numa_node.is_some() || req.cpuset.is_some() {
        a.extend(["-numa".into(), "node,nodeid=0".into()]);
    }
    if let Some(cpus) = &req.cpuset {
        a.extend(["-numa".into(), format!("cpu={cpus},node=0")]);
    } else if req.numa_node.is_some() {
        a.extend([
            "-numa".into(),
            format!("cpu=0-{},node=0", req.vcpus.saturating_sub(1)),
        ]);
    }
    for host in &req.vfio_devices {
        a.extend(["-device".into(), format!("vfio-pci,host={host}")]);
    }
    for (i, (tag, socket)) in virtiofs_sockets.iter().enumerate() {
        a.extend([
            "-chardev".into(),
            format!("socket,id=vfsock{i},path={}", path_arg(socket)),
        ]);
        a.extend([
            "-device".into(),
            format!("vhost-user-fs-pci,queue-size=1024,chardev=vfsock{i},tag={tag}"),
        ]);
    }

    match &ctx.network.spec {
        NetworkSpec::None => {}
        NetworkSpec::User { forwards } => {
            let mut netdev = "user,id=net0".to_string();
            // Bind to all interfaces, not just loopback: these forwards
            // exist specifically so a caller outside the host (e.g. SSH
            // from a laptop) can reach the guest -- 127.0.0.1 would make
            // every exposed port reachable only from processes already on
            // the host itself, defeating the feature entirely.
            for f in forwards {
                netdev.push_str(&format!(
                    ",hostfwd={}:0.0.0.0:{}-:{}",
                    f.protocol, f.host_port, f.guest_port
                ));
            }
            a.extend([
                "-netdev".into(),
                netdev,
                "-device".into(),
                "virtio-net-pci,netdev=net0".into(),
            ]);
        }
        NetworkSpec::Tap {
            tap_name,
            mac,
            extra,
            ..
        } => {
            if let Some(tap) = tap_name {
                let bus = if extra.is_empty() {
                    String::new()
                } else {
                    ",bus=hotplug-pcie-0".into()
                };
                // A tap in a foreign netns (bridge-less direct attach) cannot
                // be opened by name from the VMM's namespace, so the daemon
                // hands over an already-open fd instead.
                let netdev = match ctx.network.tap_fd {
                    Some(fd) => format!("tap,id=net0,fd={fd}"),
                    None => format!("tap,id=net0,ifname={tap},script=no,downscript=no"),
                };
                a.extend(["-netdev".into(), netdev]);
                let dev = match mac {
                    Some(m) => format!("virtio-net-pci,netdev=net0,mac={m}{bus}"),
                    None => format!("virtio-net-pci,netdev=net0{bus}"),
                };
                a.extend(["-device".into(), dev]);
            }
            for (i, nic) in extra.iter().enumerate() {
                let Some(tap) = &nic.tap_name else {
                    continue;
                };
                let id = i + 1;
                let mut dev = format!("virtio-net-pci,netdev=net{id},bus=hotplug-pcie-{id}");
                if let Some(m) = &nic.mac {
                    dev.push_str(&format!(",mac={m}"));
                }
                a.extend([
                    "-netdev".into(),
                    format!("tap,id=net{id},ifname={tap},script=no,downscript=no"),
                    "-device".into(),
                    dev,
                ]);
            }
        }
        NetworkSpec::Macvtap { mac, .. } => {
            let fd = ctx
                .network
                .tap_fd
                .context("macvtap network was not prepared")?;
            a.extend(["-netdev".into(), format!("tap,id=net0,fd={fd}")]);
            let dev = mac
                .as_ref()
                .map(|m| format!("virtio-net-pci,netdev=net0,mac={m}"))
                .unwrap_or_else(|| "virtio-net-pci,netdev=net0".into());
            a.extend(["-device".into(), dev]);
        }
    }

    if req.agent.as_ref().is_some_and(|a| a.enabled) {
        if let Some(cid) = ctx.guest_cid {
            a.extend(["-device".into(), format!("vhost-vsock-pci,guest-cid={cid}")]);
        }
    }

    if req.qga.as_ref().is_some_and(|q| q.enabled) {
        let qga = ctx.workspace.join("qga.sock");
        a.extend([
            "-chardev".into(),
            format!("socket,path={},server=on,wait=off,id=qga0", path_arg(&qga)),
            "-device".into(),
            "virtio-serial-pci,id=virtio-serial0".into(),
            "-device".into(),
            "virtserialport,bus=virtio-serial0.0,chardev=qga0,name=org.qemu.guest_agent.0".into(),
        ]);
    }

    if req.tpm.unwrap_or(false) {
        // `launch()` spawns the `swtpm` sidecar listening on this exact
        // socket path before build_args ever runs -- see spawn_swtpm.
        // `tpm-crb` (not the older `tpm-tis`) is the modern-recommended
        // device for q35/UEFI guests.
        a.extend([
            "-chardev".into(),
            format!(
                "socket,id=chrtpm,path={}",
                path_arg(&ctx.workspace.join("swtpm.sock"))
            ),
            "-tpmdev".into(),
            "emulator,id=tpm0,chardev=chrtpm".into(),
            "-device".into(),
            "tpm-crb,tpmdev=tpm0".into(),
        ]);
    }

    if let Some(kernel) = &req.kernel {
        a.extend(["-kernel".into(), path_arg(kernel)]);
        if let Some(initrd) = &req.initrd {
            a.extend(["-initrd".into(), path_arg(initrd)]);
        }
        if let Some(kargs) = &req.kernel_args {
            a.extend(["-append".into(), kargs.clone()]);
        }
    }

    let qmp = ctx.workspace.join("qmp.sock");
    a.extend([
        "-qmp".into(),
        format!("unix:{},server=on,wait=off", qmp.display()),
    ]);
    a.extend(req.extra_args.clone());
    // Restores CPU/memory/device state from an existing internal snapshot
    // on this VM's own disk instead of a normal cold boot -- see
    // CreateVmRequest.loadvm_tag's doc comment for why this is a one-shot
    // launch override, never persisted onto the stored request.
    if let Some(tag) = &req.loadvm_tag {
        a.extend(["-loadvm".into(), tag.clone()]);
    }
    Ok(a)
}

/// Starts one `virtiofsd` serving `host_path` on `workspace/virtiofs-{index}.sock` and waits until its socket
/// is ready. Returns the pid and the socket path; the caller owns the process.
async fn spawn_virtiofsd_one(
    cfg: &Config,
    workspace: &Path,
    index: usize,
    host_path: &Path,
) -> Result<(u32, PathBuf)> {
    let socket = workspace.join(format!("virtiofs-{index}.sock"));
    // Stale sockets from a previous failed launch make exists()/connect
    // race: the path is present but nothing accepts → Connection refused.
    let _ = tokio::fs::remove_file(&socket).await;
    let args = vec![
        // Ubuntu/systemd hosts often fail virtiofsd's default namespace
        // sandbox ("Error creating sandbox" / capability sync) when
        // spawned under ProtectSystem/NoNewPrivileges. Fail-open to an
        // explicit none sandbox so Secure Containers shared folders work.
        "--sandbox".to_string(),
        "none".to_string(),
        "--seccomp".to_string(),
        "none".to_string(),
        "--socket-path".to_string(),
        path_arg(&socket),
        "--shared-dir".to_string(),
        path_arg(host_path),
    ];
    // rust-vmm virtiofsd (common on Ubuntu/k3s hosts) has no --readonly /
    // -o ro. Enforce read-only via guest fstab in the scheduler when
    // share.read_only is set; do not pass a flag that aborts virtiofsd
    // before it binds the vhost-user socket.
    let log = workspace.join(format!("virtiofsd-{index}.log"));
    let child = spawn_logged(&cfg.virtiofsd_binary, &args, &log)
        .await
        .with_context(|| {
            format!(
                "spawning virtiofsd for shared_folders[{index}] ({})",
                host_path.display()
            )
        })?;
    let Some(pid) = child.id() else {
        anyhow::bail!("virtiofsd for shared_folders[{index}] exited before PID was available");
    };
    // QEMU connects as the vhost-user *client*. Do not probe with
    // UnixStream::connect — that can consume virtiofsd's single accept.
    // Stale sockets (path present, nothing listening) caused Connection
    // refused; we unlink before spawn and wait for a *new* path while
    // the child is still alive.
    if let Err(e) = wait_for_socket_ready(
        pid,
        &socket,
        VIRTIOFSD_SOCKET_TIMEOUT,
        &format!("virtiofsd for shared_folders[{index}]"),
        &log,
    )
    .await
    {
        kill_pids(&[pid]);
        return Err(e);
    }
    Ok((pid, socket))
}

/// Spawns one `virtiofsd` per `req.shared_folders` entry, in order, each
/// listening on its own socket under `ctx.workspace`. On any failure,
/// already-spawned instances from this call are killed before returning —
/// callers never have to reconcile a partial set themselves.
async fn spawn_virtiofsd_instances(
    cfg: &Config,
    req: &CreateVmRequest,
    ctx: &LaunchContext,
) -> Result<(Vec<u32>, Vec<VirtiofsSocket>)> {
    let mut pids = Vec::new();
    let mut sockets = Vec::new();
    for (i, share) in req.shared_folders.iter().enumerate() {
        match spawn_virtiofsd_one(cfg, &ctx.workspace, i, &share.host_path).await {
            Ok((pid, socket)) => {
                pids.push(pid);
                sockets.push((format!("fs{i}"), socket));
            }
            Err(e) => {
                kill_pids(&pids);
                return Err(e);
            }
        }
    }
    Ok((pids, sockets))
}

/// Hot-adds a virtiofs share to a running QEMU VM: starts a `virtiofsd` for `host_path` and plugs a
/// `vhost-user-fs-pci` device on the first free of the top root ports. `index` is the share's index in the
/// VM's `shared_folders` (its tag is `fs{index}`). Returns the `virtiofsd` pid, which the caller records
/// so stop/delete reaps it. On failure the `virtiofsd` is killed.
pub async fn hotplug_virtiofs(
    cfg: &Config,
    vm: &VmRecord,
    host_path: &Path,
    index: usize,
) -> Result<u32> {
    let tag = format!("fs{index}");
    let qmp_socket = vm.workspace.join("qmp.sock");
    let mut last_err = None;
    for port in (SHARE_PORTS_START..HOTPLUG_PCIE_PORTS).rev() {
        // A `virtiofsd` serves exactly one vhost-user connection and exits when it drops, so a failed
        // attempt (port already taken) must not reuse it: start a fresh one per port.
        let (pid, socket) = spawn_virtiofsd_one(cfg, &vm.workspace, index, host_path).await?;
        match qmp::hotplug_virtiofs(&qmp_socket, index, &socket, &tag, port, QMP_TIMEOUT).await {
            Ok(()) => return Ok(pid),
            Err(e) => {
                kill_pids(&[pid]);
                last_err = Some(e);
            }
        }
    }
    Err(last_err
        .unwrap_or_else(|| anyhow::anyhow!("no PCIe root port reserved for virtiofs shares")))
    .context(format!(
        "hot-adding virtiofs share {tag} (no free root port, or the VM has no shareable memory)"
    ))
}

fn kill_pids(pids: &[u32]) {
    for pid in pids {
        unsafe {
            libc::kill(*pid as libc::pid_t, libc::SIGKILL);
        }
    }
}

#[async_trait]
impl VmBackend for QemuBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Qemu
    }

    async fn launch(
        &self,
        cfg: &Config,
        req: &CreateVmRequest,
        ctx: &LaunchContext,
    ) -> Result<LaunchResult> {
        let (virtiofsd_pids, virtiofs_sockets) =
            match spawn_virtiofsd_instances(cfg, req, ctx).await {
                Ok(v) => v,
                Err(e) => {
                    if let Some(fd) = ctx.network.tap_fd {
                        fluxvm_core::process::close_fd(fd);
                    }
                    return Err(e);
                }
            };

        let effective_firmware = req.firmware.clone().or_else(|| cfg.qemu_ovmf_code.clone());
        if req.secure_boot.unwrap_or(false) {
            if effective_firmware.is_none() {
                kill_pids(&virtiofsd_pids);
                if let Some(fd) = ctx.network.tap_fd {
                    fluxvm_core::process::close_fd(fd);
                }
                anyhow::bail!(
                    "secure_boot requires UEFI firmware (req.firmware, or Config::qemu_ovmf_code as a host default)"
                );
            }
            if cfg.qemu_ovmf_vars_template.is_none() {
                kill_pids(&virtiofsd_pids);
                if let Some(fd) = ctx.network.tap_fd {
                    fluxvm_core::process::close_fd(fd);
                }
                anyhow::bail!(
                    "secure_boot requires Config::qemu_ovmf_vars_template (a vars store with enrolled UEFI CA keys) to be configured"
                );
            }
        }
        // First launch of this VM id: seed its own per-workspace vars
        // copy from the admin-provided template. A later `start` after
        // `stop` reuses the same workspace/id and must NOT re-copy, so
        // enrolled keys / boot order set inside the guest survive --
        // exactly like the disk file itself.
        if effective_firmware.is_some() {
            let vars_path = ctx.workspace.join("ovmf_vars.fd");
            if !vars_path.exists() {
                let Some(template) = &cfg.qemu_ovmf_vars_template else {
                    kill_pids(&virtiofsd_pids);
                    if let Some(fd) = ctx.network.tap_fd {
                        fluxvm_core::process::close_fd(fd);
                    }
                    anyhow::bail!(
                        "firmware is set but Config::qemu_ovmf_vars_template is not configured -- see docs/secure-boot-tpm.md"
                    );
                };
                if let Err(e) = tokio::fs::copy(template, &vars_path)
                    .await
                    .context("copying OVMF vars template")
                {
                    kill_pids(&virtiofsd_pids);
                    if let Some(fd) = ctx.network.tap_fd {
                        fluxvm_core::process::close_fd(fd);
                    }
                    return Err(e);
                }
            }
        }

        let swtpm_pid = if req.tpm.unwrap_or(false) {
            match spawn_swtpm(cfg, ctx).await {
                Ok(pid) => Some(pid),
                Err(e) => {
                    kill_pids(&virtiofsd_pids);
                    if let Some(fd) = ctx.network.tap_fd {
                        fluxvm_core::process::close_fd(fd);
                    }
                    return Err(e);
                }
            }
        } else {
            None
        };
        let sidecar_pids: Vec<u32> = virtiofsd_pids.iter().copied().chain(swtpm_pid).collect();

        let args = build_args(cfg, req, ctx, &virtiofs_sockets)?;
        let (program, args) =
            fluxvm_core::process::netns_wrap(ctx.network.netns.as_deref(), &cfg.qemu_binary, &args);
        let spawned = spawn_logged(&program, &args, &ctx.log_path).await;
        // The child inherits the macvtap fd across exec (or spawn failed and
        // there's nothing to inherit); either way the parent's copy is done.
        if let Some(fd) = ctx.network.tap_fd {
            fluxvm_core::process::close_fd(fd);
        }
        let child = match spawned {
            Ok(c) => c,
            Err(e) => {
                kill_pids(&sidecar_pids);
                return Err(e);
            }
        };
        let Some(pid) = child.id() else {
            kill_pids(&sidecar_pids);
            anyhow::bail!("QEMU exited before PID was available");
        };
        Ok(LaunchResult {
            pid,
            control_socket: Some(ctx.workspace.join("qmp.sock")),
            jail_path: None,
            vsock_socket: None,
            virtiofsd_pids,
            swtpm_pid,
        })
    }

    async fn pause(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        qmp::execute(&vm.workspace.join("qmp.sock"), "stop", None, QMP_TIMEOUT).await?;
        Ok(())
    }

    async fn resume(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        qmp::execute(&vm.workspace.join("qmp.sock"), "cont", None, QMP_TIMEOUT).await?;
        Ok(())
    }

    async fn graceful_shutdown(&self, _cfg: &Config, vm: &VmRecord) -> Result<()> {
        qmp::execute(
            &vm.workspace.join("qmp.sock"),
            "system_powerdown",
            None,
            QMP_TIMEOUT,
        )
        .await?;
        Ok(())
    }
}

// ZYVOR_RUNTIME_BOUNDARY_V1: node-local live-migration primitives.
pub async fn migration_start(
    _cfg: &Config,
    vm: &VmRecord,
    request: &fluxvm_core::model::MigrationStartRequest,
) -> Result<fluxvm_core::model::MigrationStatus> {
    qmp::migration_start(&vm.workspace.join("qmp.sock"), request, QMP_SAVEVM_TIMEOUT).await
}

pub async fn migration_status(
    _cfg: &Config,
    vm: &VmRecord,
) -> Result<fluxvm_core::model::MigrationStatus> {
    qmp::migration_status(&vm.workspace.join("qmp.sock"), QMP_TIMEOUT).await
}

pub async fn migration_cancel(
    _cfg: &Config,
    vm: &VmRecord,
) -> Result<fluxvm_core::model::MigrationStatus> {
    qmp::migration_cancel(&vm.workspace.join("qmp.sock"), QMP_TIMEOUT).await
}

/// Hot-add `add_vcpus` vCPUs. Returns the realized vCPU count after adding
/// (bounded by `max_vcpus`'s headroom reserved at launch — see `build_args`).
pub async fn hotplug_cpu(_cfg: &Config, vm: &VmRecord, add_vcpus: u8) -> Result<u8> {
    qmp::hotplug_cpu(&vm.workspace.join("qmp.sock"), add_vcpus, QMP_TIMEOUT).await
}

/// Hot-add `add_memory_mib` MiB of RAM. Returns the VM's new *total* live
/// memory (boot-time `memory_mib` plus every hot-added DIMM so far), not
/// just what this one call added.
pub async fn hotplug_memory(_cfg: &Config, vm: &VmRecord, add_memory_mib: u64) -> Result<u64> {
    let hotplugged =
        qmp::hotplug_memory(&vm.workspace.join("qmp.sock"), add_memory_mib, QMP_TIMEOUT).await?;
    Ok(vm.request.memory_mib.saturating_add(hotplugged))
}

/// Hot-add a virtio-net NIC on an already-created TAP. `index` selects
/// `hotplug-pcie-{index}` (0..HOTPLUG_PCIE_PORTS). The caller owns the TAP.
pub async fn hotplug_nic(vm: &VmRecord, tap: &str, mac: Option<&str>, index: u8) -> Result<()> {
    qmp::hotplug_nic(&vm.workspace.join("qmp.sock"), tap, mac, index, QMP_TIMEOUT).await
}

/// [`hotplug_nic`] for a TAP the daemon already opened, passed as a descriptor because it lives in
/// another network namespace (a bridge-less direct tap inside a Pod netns). The caller keeps
/// ownership of `tap_fd` and closes its own copy afterwards.
pub async fn hotplug_nic_fd(
    vm: &VmRecord,
    tap_fd: std::os::fd::RawFd,
    mac: Option<&str>,
    index: u8,
) -> Result<()> {
    qmp::hotplug_nic_fd(
        &vm.workspace.join("qmp.sock"),
        tap_fd,
        mac,
        index,
        QMP_TIMEOUT,
    )
    .await
}

/// Pause, save an internal snapshot tagged `name`, then resume if the VM was
/// running. Pairs with `-loadvm` / [`VmManager::start_from_snapshot`].
///
/// The resume (`cont`) result is never discarded: this used to be a bare
/// `let _ = ...`, so a `cont` failure after a *successful* `savevm` still
/// returned `Ok(())` -- the caller believed the snapshot fully succeeded
/// with the VM still running, when it was actually left paused with no
/// error surfaced anywhere. Both failure combinations are now reported
/// explicitly, since a caller acting on `Ok(())` here has no other way to
/// learn the VM didn't come back up.
pub async fn snapshot_save(_cfg: &Config, vm: &VmRecord, name: &str) -> Result<()> {
    let sock = vm.workspace.join("qmp.sock");
    let was_running = vm.status == fluxvm_core::model::VmStatus::Running;
    if was_running {
        qmp::execute(&sock, "stop", None, QMP_TIMEOUT).await?;
    }
    let save_result = qmp::savevm(&sock, name, QMP_SAVEVM_TIMEOUT).await;
    if was_running && let Err(resume_err) = qmp::execute(&sock, "cont", None, QMP_TIMEOUT).await {
        return match save_result {
            Ok(_) => Err(resume_err).context(format!(
                "snapshot '{name}' saved, but the VM failed to resume afterward and is now paused, not running"
            )),
            Err(save_err) => Err(save_err.context(format!(
                "snapshot '{name}' failed, and the VM also failed to resume afterward: {resume_err}"
            ))),
        };
    }
    save_result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_core::backend::PreparedNetwork;
    use fluxvm_core::model::NetworkSpec;

    fn req(memory_mib: u64) -> CreateVmRequest {
        CreateVmRequest {
            name: "fixture".into(),
            tenant: None,
            created_by_token: None,
            backend: BackendKind::Qemu,
            image: "/tmp/base.qcow2".into(),
            vcpus: 1,
            memory_mib,
            max_vcpus: None,
            max_memory_mib: None,
            loadvm_tag: None,
            disk_size_gib: None,
            kernel: None,
            initrd: None,
            firmware: None,
            kernel_args: None,
            network: NetworkSpec::None,
            cloud_init: None,
            ttl_seconds: None,
            extra_args: vec![],
            shared_memory: false,
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

    fn cfg() -> Config {
        Config::default()
    }

    fn ctx() -> LaunchContext {
        LaunchContext {
            id: uuid::Uuid::nil(),
            workspace: "/tmp/eph-fixture".into(),
            disk: "/tmp/eph-fixture/root.qcow2".into(),
            seed_disk: None,
            log_path: "/tmp/eph-fixture/console.log".into(),
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
            disk_format: "qcow2".into(),
            nbd_export: None,
        }
    }

    #[test]
    fn no_shares_means_no_virtiofs_args() {
        let args = build_args(&cfg(), &req(2048), &ctx(), &[]).unwrap();
        assert!(!args.iter().any(|a| a.contains("memory-backend-memfd")));
        assert!(!args.iter().any(|a| a.contains("vhost-user-fs-pci")));
        assert!(args.iter().any(|a| a.starts_with("2048M,slots=")));
    }

    #[test]
    fn reserves_hotpluggable_pcie_root_ports() {
        let args = build_args(&cfg(), &req(2048), &ctx(), &[]).unwrap();
        for i in 0..HOTPLUG_PCIE_PORTS {
            assert!(
                args.iter()
                    .any(|a| a.contains(&format!("pcie-root-port,id=hotplug-pcie-{i},"))),
                "missing hotplug-pcie-{i} root port in {args:?}"
            );
        }
    }

    #[test]
    fn primary_tap_without_extras_does_not_pin_a_hotplug_port() {
        let mut c = ctx();
        c.network.spec = NetworkSpec::Tap {
            tap_name: Some("tap0".into()),
            bridge: Some("br0".into()),
            mac: Some("02:00:00:00:00:01".into()),
            netns: false,
            direct: None,
            extra: vec![],
        };
        let args = build_args(&cfg(), &req(2048), &c, &[]).unwrap();
        let dev = args
            .iter()
            .find(|a| a.starts_with("virtio-net-pci,netdev=net0"))
            .expect("primary nic");
        assert!(!dev.contains("bus="));
        assert!(dev.contains("mac=02:00:00:00:00:01"));
    }

    #[test]
    fn multus_extra_nics_use_successive_hotplug_ports() {
        let mut c = ctx();
        c.network.spec = NetworkSpec::Tap {
            tap_name: Some("tap0".into()),
            bridge: Some("br0".into()),
            mac: Some("02:00:00:00:00:01".into()),
            netns: false,
            direct: None,
            extra: vec![
                fluxvm_core::model::ExtraNic {
                    bridge: "br1".into(),
                    mac: Some("02:00:00:00:00:02".into()),
                    tap_name: Some("tap1".into()),
                },
                fluxvm_core::model::ExtraNic {
                    bridge: "br2".into(),
                    mac: None,
                    tap_name: Some("tap2".into()),
                },
            ],
        };
        let args = build_args(&cfg(), &req(2048), &c, &[]).unwrap();
        assert!(args.iter().any(|a| {
            a.contains("virtio-net-pci,netdev=net0") && a.contains("bus=hotplug-pcie-0")
        }));
        assert!(
            args.iter()
                .any(|a| a == "tap,id=net1,ifname=tap1,script=no,downscript=no")
        );
        assert!(args.iter().any(|a| {
            a.contains("netdev=net1")
                && a.contains("bus=hotplug-pcie-1")
                && a.contains("mac=02:00:00:00:00:02")
        }));
        assert!(args.iter().any(|a| {
            a.contains("netdev=net2") && a.contains("bus=hotplug-pcie-2") && !a.contains("mac=")
        }));
    }

    #[test]
    fn adds_a_virtio_scsi_controller_for_scsi_hotplug() {
        let args = build_args(&cfg(), &req(2048), &ctx(), &[]).unwrap();
        assert!(
            args.iter()
                .any(|a| a.starts_with("virtio-scsi-pci,id=scsi0"))
        );
    }

    #[test]
    fn no_loadvm_flag_when_tag_unset() {
        let args = build_args(&cfg(), &req(2048), &ctx(), &[]).unwrap();
        assert!(!args.iter().any(|a| a == "-loadvm"));
    }

    #[test]
    fn appends_loadvm_when_tag_set() {
        let mut r = req(2048);
        r.loadvm_tag = Some("hibernate-20260101".into());
        let args = build_args(&cfg(), &r, &ctx(), &[]).unwrap();
        let idx = args
            .iter()
            .position(|a| a == "-loadvm")
            .expect("missing -loadvm flag");
        assert_eq!(args[idx + 1], "hibernate-20260101");
    }

    #[test]
    fn memory_and_cpu_hotplug_headroom_defaults_when_unset() {
        let args = build_args(&cfg(), &req(2048), &ctx(), &[]).unwrap();
        let smp = args
            .iter()
            .position(|a| a == "-smp")
            .map(|i| &args[i + 1])
            .unwrap();
        assert_eq!(smp, "cpus=1,maxcpus=2");
        let m = args
            .iter()
            .position(|a| a == "-m")
            .map(|i| &args[i + 1])
            .unwrap();
        assert_eq!(m, "2048M,slots=4,maxmem=4096M");
    }

    #[test]
    fn memory_and_cpu_hotplug_headroom_respects_explicit_request() {
        let mut r = req(1024);
        r.vcpus = 4;
        r.max_vcpus = Some(8);
        r.max_memory_mib = Some(4096);
        let args = build_args(&cfg(), &r, &ctx(), &[]).unwrap();
        let smp = args
            .iter()
            .position(|a| a == "-smp")
            .map(|i| &args[i + 1])
            .unwrap();
        assert_eq!(smp, "cpus=4,maxcpus=8");
        let m = args
            .iter()
            .position(|a| a == "-m")
            .map(|i| &args[i + 1])
            .unwrap();
        assert_eq!(m, "1024M,slots=4,maxmem=4096M");
    }

    #[test]
    fn shares_add_shared_memory_backend_and_one_device_per_share() {
        let sockets: Vec<VirtiofsSocket> = vec![
            ("fs0".to_string(), "/tmp/eph-fixture/virtiofs-0.sock".into()),
            ("fs1".to_string(), "/tmp/eph-fixture/virtiofs-1.sock".into()),
        ];
        let args = build_args(&cfg(), &req(4096), &ctx(), &sockets).unwrap();
        let joined = args.join(" ");
        assert!(joined.contains("memory-backend-memfd,id=mem,size=4096M,share=on"));
        assert!(joined.contains("numa node,memdev=mem"));
        assert!(joined.contains("chardev=vfsock0,tag=fs0"));
        assert!(joined.contains("chardev=vfsock1,tag=fs1"));
        assert_eq!(
            args.iter()
                .filter(
                    |a| a.as_str() == "vhost-user-fs-pci,queue-size=1024,chardev=vfsock0,tag=fs0"
                )
                .count(),
            1
        );
    }

    #[test]
    fn qga_enabled_adds_virtio_serial_channel() {
        let mut r = req(2048);
        r.qga = Some(fluxvm_core::model::QgaSpec { enabled: true });
        let args = build_args(&cfg(), &r, &ctx(), &[]).unwrap();
        let joined = args.join(" ");
        assert!(joined.contains("id=qga0"));
        assert!(joined.contains("virtio-serial-pci"));
        assert!(joined.contains("name=org.qemu.guest_agent.0"));
        assert!(joined.contains("qga.sock"));
    }

    #[test]
    fn firmware_none_omits_pflash_and_smm() {
        let args = build_args(&cfg(), &req(2048), &ctx(), &[]).unwrap();
        assert!(!args.iter().any(|a| a.contains("if=pflash")));
        assert!(!args.iter().any(|a| a.contains("cfi.pflash01")));
        let machine = args
            .iter()
            .position(|a| a == "-machine")
            .map(|i| &args[i + 1])
            .unwrap();
        assert!(!machine.contains("smm=on"));
    }

    #[test]
    fn firmware_set_adds_split_pflash_and_smm() {
        let mut r = req(2048);
        r.firmware = Some("/usr/share/OVMF/OVMF_CODE_4M.ms.fd".into());
        let args = build_args(&cfg(), &r, &ctx(), &[]).unwrap();
        let joined = args.join(" ");
        assert!(joined.contains(
            "if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.ms.fd"
        ));
        assert!(joined.contains("if=pflash,format=raw,unit=1,file=/tmp/eph-fixture/ovmf_vars.fd"));
        assert!(joined.contains("driver=cfi.pflash01,property=secure,value=on"));
        let machine = args
            .iter()
            .position(|a| a == "-machine")
            .map(|i| &args[i + 1])
            .unwrap();
        assert!(machine.contains("smm=on"), "machine line: {machine}");
    }

    #[test]
    fn firmware_falls_back_to_config_default_when_request_omits_it() {
        let mut c = cfg();
        c.qemu_ovmf_code = Some("/usr/share/OVMF/OVMF_CODE_4M.fd".into());
        let args = build_args(&c, &req(2048), &ctx(), &[]).unwrap();
        assert!(
            args.iter()
                .any(|a| a.contains("unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd"))
        );
    }

    #[test]
    fn firmware_request_overrides_config_default() {
        let mut c = cfg();
        c.qemu_ovmf_code = Some("/usr/share/OVMF/config-default.fd".into());
        let mut r = req(2048);
        r.firmware = Some("/usr/share/OVMF/request-wins.fd".into());
        let args = build_args(&c, &r, &ctx(), &[]).unwrap();
        let joined = args.join(" ");
        assert!(joined.contains("file=/usr/share/OVMF/request-wins.fd"));
        assert!(!joined.contains("config-default.fd"));
    }

    #[test]
    fn tpm_disabled_omits_chardev_tpmdev_device() {
        let args = build_args(&cfg(), &req(2048), &ctx(), &[]).unwrap();
        assert!(!args.iter().any(|a| a.contains("chrtpm")));
        assert!(!args.iter().any(|a| a.contains("tpmdev")));
        assert!(!args.iter().any(|a| a.contains("tpm-crb")));
    }

    #[test]
    fn tpm_enabled_adds_chardev_tpmdev_device() {
        let mut r = req(2048);
        r.tpm = Some(true);
        let args = build_args(&cfg(), &r, &ctx(), &[]).unwrap();
        let joined = args.join(" ");
        assert!(joined.contains("socket,id=chrtpm,path=/tmp/eph-fixture/swtpm.sock"));
        assert!(joined.contains("emulator,id=tpm0,chardev=chrtpm"));
        assert!(joined.contains("tpm-crb,tpmdev=tpm0"));
    }

    #[test]
    fn tpm_is_independent_of_firmware() {
        // A TPM is useful under legacy BIOS too (measured boot, disk
        // encryption unseal) -- setting tpm without firmware must not
        // pull in any pflash/smm args.
        let mut r = req(2048);
        r.tpm = Some(true);
        let args = build_args(&cfg(), &r, &ctx(), &[]).unwrap();
        assert!(!args.iter().any(|a| a.contains("if=pflash")));
        assert!(args.iter().any(|a| a.contains("chrtpm")));
    }

    #[test]
    fn direct_tap_with_prepared_fd_is_attached_by_fd_not_ifname() {
        // A tap in a foreign netns cannot be opened by name from QEMU's own
        // namespace, so the daemon passes an inherited fd instead.
        let mut c = ctx();
        c.network.spec = NetworkSpec::Tap {
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
        c.network.tap_fd = Some(9);
        let args = build_args(&cfg(), &req(2048), &c, &[]).unwrap();
        assert!(args.iter().any(|a| a == "tap,id=net0,fd=9"), "{args:?}");
        assert!(!args.iter().any(|a| a.contains("ifname=")), "{args:?}");
        assert!(args.iter().any(|a| {
            a.starts_with("virtio-net-pci,netdev=net0") && a.contains("mac=02:00:00:00:00:01")
        }));
    }

    #[test]
    fn bridged_tap_without_fd_still_uses_ifname() {
        let mut c = ctx();
        c.network.spec = NetworkSpec::Tap {
            tap_name: Some("tap0".into()),
            bridge: Some("br0".into()),
            mac: None,
            netns: false,
            direct: None,
            extra: vec![],
        };
        c.network.tap_fd = None;
        let args = build_args(&cfg(), &req(2048), &c, &[]).unwrap();
        assert!(
            args.iter()
                .any(|a| a == "tap,id=net0,ifname=tap0,script=no,downscript=no")
        );
    }
}

#[cfg(test)]
mod snapshot_save_tests {
    use super::*;
    use fluxvm_core::model::{CreateVmRequest, NetworkSpec, StorageBackend, VmStatus};
    use serde_json::{Value, json};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    fn vm_record(workspace: PathBuf, status: VmStatus) -> VmRecord {
        VmRecord {
            id: uuid::Uuid::new_v4(),
            name: "fixture".into(),
            backend: BackendKind::Qemu,
            status,
            pid: None,
            created_at: chrono::Utc::now(),
            expires_at: None,
            workspace: workspace.clone(),
            disk: workspace.join("root.qcow2"),
            seed_disk: None,
            tap_name: None,
            control_socket: None,
            log_path: workspace.join("console.log"),
            error: None,
            request: CreateVmRequest {
                name: "fixture".into(),
                tenant: None,
                created_by_token: None,
                backend: BackendKind::Qemu,
                image: PathBuf::from("/tmp/base.qcow2"),
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
                network: NetworkSpec::None,
                cloud_init: None,
                ttl_seconds: None,
                extra_args: vec![],
                shared_memory: false,
                agent: None,
                qga: None,
                hyperv: false,
                storage: StorageBackend::Default,
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
            },
            guest_cid: None,
            jail_path: None,
            vsock_socket: None,
            qga_socket: None,
            cgroup_path: None,
            netns: None,
            lvm_lv: None,
            nbd_pid: None,
            virtiofsd_pids: vec![],
            swtpm_pid: None,
            dhcp_leasefile: None,
            guest_ip: None,
        }
    }

    /// Serves one QMP connection per step, replying `{"return": reply}`
    /// for a successful step or `{"error": {...}}` for a failing one --
    /// mirrors `qmp::hotplug_tests::serve_script`, which lives in a
    /// different module and isn't reusable from here.
    async fn serve_steps(listener: UnixListener, steps: Vec<(&'static str, Result<Value, ()>)>) {
        for (expect_command, outcome) in steps {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);

            write_half
                .write_all(b"{\"QMP\":{\"version\":{}}}\n")
                .await
                .unwrap();
            let mut caps = String::new();
            reader.read_line(&mut caps).await.unwrap();
            write_half.write_all(b"{\"return\":{}}\n").await.unwrap();

            let mut req = String::new();
            reader.read_line(&mut req).await.unwrap();
            let req: Value = serde_json::from_str(&req).unwrap();
            assert_eq!(req["execute"], expect_command, "unexpected command");

            let resp = match outcome {
                Ok(reply) => json!({"return": reply}),
                Err(()) => json!({"error": {"class": "GenericError", "desc": "boom"}}),
            };
            write_half
                .write_all(format!("{resp}\n").as_bytes())
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn resumes_after_a_successful_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let server = tokio::spawn(serve_steps(
            listener,
            vec![
                ("stop", Ok(json!({}))),
                ("human-monitor-command", Ok(json!({}))),
                ("cont", Ok(json!({}))),
            ],
        ));

        let vm = vm_record(dir.path().to_path_buf(), VmStatus::Running);
        snapshot_save(&Config::default(), &vm, "tag1")
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn reports_resume_failure_after_a_successful_snapshot() {
        // Regression test: this used to discard `cont`'s error entirely
        // (`let _ = ...`) and return `Ok(())` here, even though the VM was
        // left paused instead of running.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let server = tokio::spawn(serve_steps(
            listener,
            vec![
                ("stop", Ok(json!({}))),
                ("human-monitor-command", Ok(json!({}))),
                ("cont", Err(())),
            ],
        ));

        let vm = vm_record(dir.path().to_path_buf(), VmStatus::Running);
        let err = snapshot_save(&Config::default(), &vm, "tag1")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("failed to resume"),
            "unexpected error: {err}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn reports_both_failures_when_savevm_and_resume_both_fail() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let server = tokio::spawn(serve_steps(
            listener,
            vec![
                ("stop", Ok(json!({}))),
                ("human-monitor-command", Err(())),
                ("cont", Err(())),
            ],
        ));

        let vm = vm_record(dir.path().to_path_buf(), VmStatus::Running);
        let err = snapshot_save(&Config::default(), &vm, "tag1")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("also failed to resume"),
            "unexpected error: {msg}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn does_not_touch_stop_or_cont_when_vm_is_already_paused() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        // Only `savevm` should be sent -- a Paused VM was never told to
        // `stop` and must never be told to `cont` either.
        let server = tokio::spawn(serve_steps(
            listener,
            vec![("human-monitor-command", Ok(json!({})))],
        ));

        let vm = vm_record(dir.path().to_path_buf(), VmStatus::Paused);
        snapshot_save(&Config::default(), &vm, "tag1")
            .await
            .unwrap();
        server.await.unwrap();
    }
}
