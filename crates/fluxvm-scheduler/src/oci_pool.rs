// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! A pool of pre-booted OCI sandbox VMs ("slots").
//!
//! A slot is a running `vz` VM of one size (`apple.oci_warm_sizes`) whose init is in `wait` mode: the kernel has booted, the
//! NIC holds its DHCP lease, and init listens on vsock for a claim. Its root disk is a tiny placeholder and its volume shares
//! (`fluxvm-vol0..3`) point at an empty directory. Claiming one for a sandbox:
//!
//! 1. clones the image's rootfs into the slot's workspace and writes the real boot config (under a fresh name) and the
//!    sandbox's secrets to the meta share;
//! 2. points each volume share at the volume's directory (`share-set`);
//! 3. hot-attaches the rootfs as USB mass storage (`usb-attach`, macOS 15+);
//! 4. sends the claim over vsock; init mounts `/dev/sda` and starts the container as on a cold boot;
//! 5. rewrites the VM record as an ordinary OCI sandbox whose disk is the rootfs, so a restart cold-boots normally.
//!
//! Only sandboxes a slot can serve are claimed: the NAT network with no published or exposed ports, no `allow_hosts`, no
//! private networks, at most four volumes, and an exact size match. Anything else, or any failure, cold-boots.

use crate::VmManager;
use crate::oci_sandbox::OCI_MIN_MEMORY_MIB;
use anyhow::{Context, Result, bail};
use fluxvm_core::agent_density::DensityReport;
use fluxvm_core::model::{
    AppleShare, BackendKind, CreateVmRequest, NetworkSpec, VmPatch, VmRecord, VmStatus,
};
use fluxvm_image::oci_boot::OciBoot;
use fluxvm_oci_init::config as init;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// `VCPUSxMEMORY_MIB` of a waiting slot; removed when the slot is claimed.
pub const WARM_LABEL: &str = "fluxvm.oci-warm";
/// On a claimed sandbox: the runner pid whose guest has its root on USB. Such a guest is not hibernated (its saved state
/// would not restore with the record's devices); after a restart the pid differs and the label no longer applies.
pub const CLAIMED_LABEL: &str = "fluxvm.oci-warm-claimed";
/// Volume shares every slot carries.
pub const WARM_VOLUMES: usize = 4;
/// The hot-attached rootfs: the only USB mass-storage device, so the first SCSI disk.
const CLAIM_DISK: &str = "/dev/sda";
const ROOTFS_FILE: &str = "rootfs.raw";
const BOOT_TIMEOUT: Duration = Duration::from_secs(60);
/// After a failed claim the pool is not refilled for this long (an older kernel without USB storage would fail every time).
const FAILURE_BACKOFF_SECS: i64 = 600;

static CLAIM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static FILLING: AtomicBool = AtomicBool::new(false);
static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static LAST_CLAIM_MS: AtomicU64 = AtomicU64::new(0);
static BACKOFF_UNTIL: AtomicI64 = AtomicI64::new(0);

/// `"2x1024"` -> `(2, 1024)`.
pub fn parse_size(s: &str) -> Result<(u8, u64)> {
    let (v, m) = s
        .trim()
        .split_once(['x', 'X'])
        .with_context(|| format!("warm size {s:?} is not VCPUSxMEMORY_MIB"))?;
    let vcpus: u8 = v
        .parse()
        .ok()
        .filter(|&v| v > 0)
        .with_context(|| format!("warm size {s:?}: {v:?} is not a vCPU count"))?;
    let mib: u64 = m
        .parse()
        .ok()
        .filter(|&m| m >= OCI_MIN_MEMORY_MIB)
        .with_context(|| {
            format!("warm size {s:?}: memory must be at least {OCI_MIN_MEMORY_MIB} MiB")
        })?;
    Ok((vcpus, mib))
}

pub fn size_label(vcpus: u8, memory_mib: u64) -> String {
    format!("{vcpus}x{memory_mib}")
}

pub(crate) fn is_warm_slot(vm: &VmRecord) -> bool {
    vm.backend == BackendKind::Vz && vm.labels.contains_key(WARM_LABEL)
}

/// VM lists leave out waiting warm slots unless asked for everything (`?all=true`, `fluxctl ls --all`) or the label selector
/// names [`WARM_LABEL`].
pub fn listed(vm: &VmRecord, all: bool, selector: Option<&str>) -> bool {
    all || selector.is_some_and(|s| s.contains(WARM_LABEL)) || !is_warm_slot(vm)
}

/// Whether a slot can become this sandbox (everything but the size, which the claim matches).
pub(crate) fn eligible(create: &CreateVmRequest) -> bool {
    let Some(apple) = create.apple.as_ref() else {
        return false;
    };
    create.backend == BackendKind::Vz
        && apple.init_config.is_some()
        && matches!(&create.network, NetworkSpec::User { forwards } if forwards.is_empty())
        && apple.egress_allow.is_empty()
        && apple.networks.is_empty()
        && apple.tagged_shares.len() <= WARM_VOLUMES
}

/// The VM request for one slot; pure, so the shape is unit-tested.
pub(crate) fn slot_request(
    name: &str,
    boot: &OciBoot,
    (vcpus, memory_mib): (u8, u64),
    placeholder_disk: &Path,
    empty_dir: &Path,
    rosetta: bool,
) -> Result<CreateVmRequest> {
    let init_config = init::InitConfig::Wait(init::WaitConfig {
        port: init::WARM_PORT,
        network: init::NetworkMode::Dhcp,
    });
    let shares: Vec<AppleShare> = (0..WARM_VOLUMES)
        .map(|i| AppleShare {
            tag: init::volume_tag(i),
            host_path: empty_dir.to_path_buf(),
            read_only: true,
        })
        .collect();
    let mut create: CreateVmRequest = serde_json::from_value(serde_json::json!({
        "name": name,
        "backend": "vz",
        "image": placeholder_disk,
        "vcpus": vcpus,
        "memory_mib": memory_mib,
        "kernel": boot.kernel,
        "initrd": boot.initrd,
        // usb-storage otherwise waits a second before scanning the hot-attached rootfs.
        "kernel_args": format!("{} usb_storage.delay_use=0", boot.cmdline),
        "agent": {"enabled": true, "port": fluxvm_guest_protocol::DEFAULT_PORT},
        "apple": {
            "guest_os": "linux",
            "root_read_only": true,
            "usb_controller": true,
            "init_config": init_config,
            "tagged_shares": shares,
            "rosetta": rosetta,
        },
    }))
    .context("building the warm slot VM request")?;
    create.network = NetworkSpec::User {
        forwards: Vec::new(),
    };
    Ok(create)
}

/// The pool's half of the density report.
pub(crate) fn summarize(vms: &[VmRecord], configured: usize, r: &mut DensityReport) {
    r.oci_warm_slots_configured = configured;
    r.oci_warm_hits = HITS.load(Ordering::Relaxed);
    r.oci_warm_misses = MISSES.load(Ordering::Relaxed);
    r.oci_warm_last_claim_ms = Some(LAST_CLAIM_MS.load(Ordering::Relaxed)).filter(|&ms| ms > 0);
    for vm in vms.iter().filter(|v| is_warm_slot(v)) {
        match vm.status {
            VmStatus::Running if ready(vm) => {
                r.oci_warm_slots_ready += 1;
                r.oci_warm_resident_mib += vm.request.memory_mib;
            }
            VmStatus::Running | VmStatus::Creating => {
                r.oci_warm_slots_booting += 1;
                r.oci_warm_resident_mib += vm.request.memory_mib;
            }
            _ => {}
        }
    }
}

/// A claimed sandbox still running in the VM it was claimed in (root disk on USB).
pub(crate) fn runs_claimed(vm: &VmRecord) -> bool {
    vm.labels
        .get(CLAIMED_LABEL)
        .is_some_and(|pid| vm.pid.map(|p| p.to_string()).as_deref() == Some(pid.as_str()))
}

/// Init in the slot has printed [`init::WARM_READY`].
fn ready(vm: &VmRecord) -> bool {
    std::fs::read_to_string(&vm.log_path).is_ok_and(|log| init::warm_ready_in_log(&log))
}

/// Called once the claimed sandbox's agent answers.
pub(crate) fn record_claim_time(ms: u64) {
    LAST_CLAIM_MS.store(ms.max(1), Ordering::Relaxed);
}

fn in_backoff() -> bool {
    chrono::Utc::now().timestamp() < BACKOFF_UNTIL.load(Ordering::Relaxed)
}

impl VmManager {
    fn oci_warm_sizes(&self) -> Vec<(u8, u64)> {
        self.cfg
            .apple
            .oci_warm_sizes
            .iter()
            .filter_map(|s| match parse_size(s) {
                Ok(size) => Some(size),
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), "ignoring apple.oci_warm_sizes entry");
                    None
                }
            })
            .collect()
    }

    pub(crate) fn oci_warm_configured(&self) -> usize {
        self.cfg.apple.oci_warm_slots * self.oci_warm_sizes().len()
    }

    /// A 1 MiB placeholder root disk (never mounted) and an empty directory for the volume shares.
    fn warm_placeholders(&self) -> Result<(PathBuf, PathBuf)> {
        let dir = self.cfg.state_dir.join("oci-warm");
        let empty = dir.join("empty");
        std::fs::create_dir_all(&empty).with_context(|| format!("creating {}", empty.display()))?;
        let disk = dir.join("placeholder.raw");
        if !disk.exists() {
            let f = std::fs::File::create(&disk)
                .with_context(|| format!("creating {}", disk.display()))?;
            f.set_len(1 << 20)?;
        }
        Ok((disk, empty))
    }

    /// Starts topping the pool up to `apple.oci_warm_slots` per size in the background (one filler at a time).
    pub(crate) fn spawn_oci_pool_fill(self: &Arc<Self>) {
        let per_size = self.cfg.apple.oci_warm_slots;
        if per_size == 0 || !cfg!(target_os = "macos") || in_backoff() {
            return;
        }
        if FILLING.swap(true, Ordering::SeqCst) {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            // Slots that stopped (a daemon restart, a crashed runner) cannot be claimed; replace them.
            for vm in this.list().await.into_iter().filter(|v| {
                is_warm_slot(v) && !matches!(v.status, VmStatus::Running | VmStatus::Creating)
            }) {
                let _ = this.delete(vm.id).await;
            }
            'sizes: for size in this.oci_warm_sizes() {
                let label = size_label(size.0, size.1);
                loop {
                    let have = this
                        .list()
                        .await
                        .iter()
                        .filter(|v| v.labels.get(WARM_LABEL) == Some(&label))
                        .count();
                    if have >= per_size {
                        break;
                    }
                    if let Err(e) = this.build_oci_warm_slot(size).await {
                        tracing::warn!(error = %format!("{e:#}"), size = %label, "building a warm OCI slot failed");
                        break 'sizes;
                    }
                }
            }
            FILLING.store(false, Ordering::SeqCst);
        });
    }

    async fn build_oci_warm_slot(self: &Arc<Self>, size: (u8, u64)) -> Result<()> {
        let boot = fluxvm_image::oci_boot::resolve(&self.cfg).await?;
        let (disk, empty) = self.warm_placeholders()?;
        let name = format!("oci-warm-{}", &Uuid::new_v4().simple().to_string()[..8]);
        let create = slot_request(
            &name,
            &boot,
            size,
            &disk,
            &empty,
            fluxvm_apple::rosetta_installed(),
        )?;
        let vm = self.create(create).await?;
        let booted = async {
            let labels =
                BTreeMap::from([(WARM_LABEL.to_owned(), Some(size_label(size.0, size.1)))]);
            self.patch(vm.id, VmPatch { name: None, labels }).await?;
            let started = Instant::now();
            loop {
                let vm = self.get(vm.id).await?;
                if ready(&vm) {
                    return Ok(());
                }
                let log = tokio::fs::read_to_string(&vm.log_path)
                    .await
                    .unwrap_or_default();
                if let Some(reason) = init::init_error_from_log(&log) {
                    bail!("the warm slot's init failed: {reason}");
                }
                if !matches!(vm.status, VmStatus::Running | VmStatus::Creating) {
                    bail!("the warm slot stopped while booting");
                }
                if started.elapsed() > BOOT_TIMEOUT {
                    bail!(
                        "the warm slot was not ready within {}s",
                        BOOT_TIMEOUT.as_secs()
                    );
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        .await;
        if let Err(e) = booted {
            let _ = self.delete(vm.id).await;
            return Err(e);
        }
        Ok(())
    }

    /// Turns a waiting slot into the sandbox `create` describes. `None` means "cold-boot instead" (no matching slot, or the
    /// claim failed and the slot was thrown away).
    pub(crate) async fn claim_oci_warm(
        self: &Arc<Self>,
        create: &CreateVmRequest,
        rootfs: &Path,
    ) -> Option<VmRecord> {
        if self.cfg.apple.oci_warm_slots == 0 || !eligible(create) {
            return None;
        }
        let label = size_label(create.vcpus, create.memory_mib);
        let rosetta = create.apple.as_ref().is_some_and(|a| a.rosetta);
        let slot = {
            let _guard = CLAIM_LOCK.lock().await;
            let slot = self.list().await.into_iter().find(|v| {
                v.labels.get(WARM_LABEL) == Some(&label)
                    && v.status == VmStatus::Running
                    && (!rosetta || v.request.apple.as_ref().is_some_and(|a| a.rosetta))
                    && ready(v)
            });
            if let Some(slot) = &slot {
                let labels = BTreeMap::from([(WARM_LABEL.to_owned(), None)]);
                if self
                    .patch(slot.id, VmPatch { name: None, labels })
                    .await
                    .is_err()
                {
                    return None;
                }
            }
            slot
        };
        let Some(slot) = slot else {
            MISSES.fetch_add(1, Ordering::Relaxed);
            self.spawn_oci_pool_fill();
            return None;
        };
        let started = Instant::now();
        let claimed = self.assign_warm_slot(&slot, create, rootfs).await;
        let out = match claimed {
            Ok(vm) => {
                HITS.fetch_add(1, Ordering::Relaxed);
                tracing::info!(vm = %vm.id, ms = started.elapsed().as_millis() as u64, "claimed a warm OCI slot");
                Some(vm)
            }
            Err(e) => {
                MISSES.fetch_add(1, Ordering::Relaxed);
                BACKOFF_UNTIL.store(
                    chrono::Utc::now().timestamp() + FAILURE_BACKOFF_SECS,
                    Ordering::Relaxed,
                );
                tracing::warn!(slot = %slot.id, error = %format!("{e:#}"), "claiming a warm OCI slot failed; cold-booting instead");
                let _ = self.delete(slot.id).await;
                None
            }
        };
        self.spawn_oci_pool_fill();
        out
    }

    async fn assign_warm_slot(
        self: &Arc<Self>,
        slot: &VmRecord,
        create: &CreateVmRequest,
        rootfs: &Path,
    ) -> Result<VmRecord> {
        let apple = create.apple.as_ref().context("not a vz request")?;
        let disk = slot.workspace.join(ROOTFS_FILE);
        let (from, to) = (rootfs.to_path_buf(), disk.clone());
        tokio::task::spawn_blocking(move || fluxvm_apple::clone_file(&from, &to))
            .await
            .context("cloning the rootfs")??;

        let mut req = create.clone();
        req.agent = slot.request.agent.clone();
        let config = format!("claim-{}.json", &Uuid::new_v4().simple().to_string()[..12]);
        fluxvm_apple::write_oci_meta_as(&req, &slot.workspace, &config)?;
        for share in &apple.tagged_shares {
            fluxvm_apple::share_set(slot, &share.tag, &share.host_path, share.read_only)
                .await
                .with_context(|| format!("pointing {} at the volume", share.tag))?;
        }
        fluxvm_apple::usb_attach(slot, &disk, apple.root_read_only)
            .await
            .context("attaching the rootfs")?;
        fluxvm_apple::warm_claim(
            slot,
            init::WARM_PORT,
            &init::Claim {
                config,
                disk: CLAIM_DISK.into(),
            },
        )
        .await?;

        let mut vm = self.get(slot.id).await?;
        vm.name = req.name.clone();
        vm.disk = disk;
        vm.expires_at = req
            .ttl_seconds
            .map(|t| chrono::Utc::now() + chrono::Duration::seconds(t as i64));
        if let Some(a) = req.apple.as_mut() {
            a.secret_env.clear();
        }
        vm.request = req;
        vm.labels.remove(WARM_LABEL);
        if let Some(pid) = vm.pid {
            vm.labels.insert(CLAIMED_LABEL.to_owned(), pid.to_string());
        }
        self.store.update(vm.clone()).await?;
        Ok(vm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot() -> OciBoot {
        OciBoot {
            kernel: "/b/oci-kernel".into(),
            initrd: "/b/oci-initrd".into(),
            cmdline: "console=hvc0".into(),
        }
    }

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("1x512").unwrap(), (1, 512));
        assert_eq!(parse_size(" 2X1024 ").unwrap(), (2, 1024));
        for bad in [
            "", "512", "0x512", "1x", "1x16", "1x256", "ax512", "300x512",
        ] {
            assert!(parse_size(bad).is_err(), "{bad}");
        }
        assert_eq!(size_label(2, 1024), "2x1024");
    }

    #[test]
    fn slots_wait_with_usb_and_placeholder_volume_shares() {
        let c = slot_request(
            "oci-warm-1",
            &boot(),
            (1, 512),
            Path::new("/s/placeholder.raw"),
            Path::new("/s/empty"),
            true,
        )
        .unwrap();
        let a = c.apple.as_ref().unwrap();
        assert!(a.usb_controller && a.rosetta && a.root_read_only);
        assert_eq!(a.init_config.as_ref().unwrap()["mode"], "wait");
        assert_eq!(a.tagged_shares.len(), WARM_VOLUMES);
        assert_eq!(a.tagged_shares[3].tag, "fluxvm-vol3");
        assert!(matches!(&c.network, NetworkSpec::User { forwards } if forwards.is_empty()));
        assert!(c.agent.as_ref().unwrap().enabled);
        assert_eq!(
            c.kernel_args.as_deref(),
            Some("console=hvc0 usb_storage.delay_use=0")
        );
    }

    #[test]
    fn only_plain_nat_sandboxes_are_eligible() {
        let base = slot_request(
            "s",
            &boot(),
            (1, 512),
            Path::new("/p"),
            Path::new("/e"),
            false,
        )
        .unwrap();
        assert!(eligible(&base));
        let mut c = base.clone();
        c.network = NetworkSpec::None;
        assert!(!eligible(&c), "offline");
        let mut c = base.clone();
        c.network = NetworkSpec::User {
            forwards: vec![fluxvm_core::model::PortForward {
                host_port: 8080,
                guest_port: 80,
                protocol: "tcp".into(),
                guests: false,
            }],
        };
        assert!(!eligible(&c), "published ports");
        let mut c = base.clone();
        c.apple.as_mut().unwrap().egress_allow = vec!["example.com".into()];
        assert!(!eligible(&c), "allow_hosts");
        let mut c = base.clone();
        c.apple.as_mut().unwrap().networks = vec![fluxvm_core::model::AppleNetwork {
            name: "n".into(),
            address: None,
            mac: None,
        }];
        assert!(!eligible(&c), "private networks");
        let mut c = base.clone();
        let extra = c.apple.as_ref().unwrap().tagged_shares[0].clone();
        c.apple.as_mut().unwrap().tagged_shares.push(extra);
        assert!(!eligible(&c), "five volumes");
    }

    #[test]
    fn a_claimed_sandbox_is_special_only_in_the_runner_it_was_claimed_in() {
        let mut vm: VmRecord = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(), "name": "x", "backend": "vz", "status": "running", "pid": 41,
            "created_at": "2026-01-01T00:00:00Z", "expires_at": null, "workspace": "/tmp/w",
            "disk": "/tmp/w/rootfs.raw", "seed_disk": null, "tap_name": null, "control_socket": null,
            "log_path": "/tmp/w/console.log", "error": null,
            "request": {"name": "x", "image": "/img", "vcpus": 1, "memory_mib": 512, "backend": "vz"},
        }))
        .unwrap();
        assert!(!runs_claimed(&vm));
        vm.labels.insert(CLAIMED_LABEL.into(), "41".into());
        assert!(runs_claimed(&vm));
        vm.pid = Some(77);
        assert!(!runs_claimed(&vm), "restarted: the root is on virtio now");
    }

    #[test]
    fn lists_hide_waiting_slots_unless_asked() {
        let mut vm: VmRecord = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(), "name": "x", "backend": "vz", "status": "running", "pid": 1,
            "created_at": "2026-01-01T00:00:00Z", "expires_at": null, "workspace": "/tmp/w",
            "disk": "/tmp/w/root.raw", "seed_disk": null, "tap_name": null, "control_socket": null,
            "log_path": "/tmp/w/console.log", "error": null,
            "request": {"name": "x", "image": "/img", "vcpus": 1, "memory_mib": 512, "backend": "vz"},
        }))
        .unwrap();
        assert!(listed(&vm, false, None));
        vm.labels.insert(WARM_LABEL.into(), "1x512".into());
        assert!(!listed(&vm, false, None));
        assert!(!listed(&vm, false, Some("env=dev")));
        assert!(listed(&vm, true, None));
        assert!(listed(&vm, false, Some("fluxvm.oci-warm=1x512")));
    }

    #[test]
    fn density_counts_ready_and_booting_slots() {
        let dir = tempfile::tempdir().unwrap();
        let rec = |status: VmStatus, log: &str| {
            let path = dir.path().join(format!("{}.log", Uuid::new_v4()));
            std::fs::write(&path, log).unwrap();
            let mut v: VmRecord = serde_json::from_value(serde_json::json!({
                "id": Uuid::new_v4(), "name": "x", "backend": "vz", "status": status, "pid": null,
                "created_at": "2026-01-01T00:00:00Z", "expires_at": null, "workspace": "/tmp/w",
                "disk": "/tmp/w/disk.raw", "seed_disk": null, "tap_name": null, "control_socket": null,
                "log_path": path, "error": null,
                "request": {"name": "x", "image": "/img", "vcpus": 1, "memory_mib": 512, "backend": "vz"},
            }))
            .unwrap();
            v.labels.insert(WARM_LABEL.into(), "1x512".into());
            v
        };
        let vms = vec![
            rec(VmStatus::Running, "boot\nFLUXVM-WARM-READY\n"),
            rec(VmStatus::Running, "booting\n"),
            rec(VmStatus::Stopped, "FLUXVM-WARM-READY\n"),
        ];
        let mut r = DensityReport::default();
        summarize(&vms, 2, &mut r);
        assert_eq!(r.oci_warm_slots_configured, 2);
        assert_eq!(r.oci_warm_slots_ready, 1);
        assert_eq!(r.oci_warm_slots_booting, 1);
        assert_eq!(r.oci_warm_resident_mib, 1024);
    }
}
