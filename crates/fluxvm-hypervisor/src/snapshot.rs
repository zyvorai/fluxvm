// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::api::{FluxVmEngine, SnapshotSpec};
use crate::kvm_snap;
use crate::state::{VmLifecycle, VmState};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Check the saved CPU/RAM shape before stopping a currently running VM.
/// The guest still needs a real restore after this check; this only rejects
/// malformed and incompatible bundles without destroying the live guest.
pub fn preflight_restore(spec: &SnapshotSpec) -> Result<()> {
    if spec.boot.engine != FluxVmEngine::Kvm {
        return Ok(());
    }
    let vmstate = spec
        .vmstate_path
        .as_ref()
        .context("native KVM restore requires a vmstate file")?;
    let cpu = kvm_snap::load_cpu(vmstate).context("reading KVM vmstate")?;
    let expected = spec
        .boot
        .memory_mib
        .checked_mul(1024 * 1024)
        .context("snapshot RAM size overflow")?;
    if cpu.mem_len != expected || fs::metadata(&spec.memory_path)?.len() != expected {
        bail!("snapshot RAM size does not match the saved VM configuration");
    }
    if cpu.all_vcpus.len() != usize::from(spec.boot.vcpus) {
        bail!("snapshot vCPU count does not match the saved VM configuration");
    }
    if cpu.version >= 5 {
        let complete = cpu.vcpu_states.len() == cpu.all_vcpus.len()
            && cpu.vcpu_states.iter().all(|v| v.is_complete())
            && cpu.vm_state.as_ref().map_or(false, |v| v.is_complete());
        if !complete {
            bail!("FLUXKVM1 v5 vmstate is missing vCPU or VM state sections");
        }
    }
    if cpu.all_vcpus.len() > 1 && cpu.mp_states.len() != cpu.all_vcpus.len() {
        bail!("multi-vCPU restore requires FLUXKVM1 v4 MP state for every vCPU");
    }
    Ok(())
}

/// Save a full template: Firecracker memory+vmstate snapshot + FICLONE of rootfs.
pub async fn save(st: &VmState, path: &Path) -> Result<()> {
    let boot = st.boot.as_ref().context("no boot config to snapshot")?;
    let guest = st.guest.as_ref().context("no live guest to snapshot")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let disk_snap = path.with_extension("rootfs");
    let mem_snap = path.with_extension("mem");
    let vmstate = path.with_extension("vmstate");
    // A repeated tag must not overwrite any part of a snapshot that readers
    // can already see. Publish the metadata only after all three files move.
    for dest in [path, &disk_snap, &mem_snap, &vmstate] {
        if dest.exists() {
            bail!(
                "snapshot already exists at {}; delete it before reusing the tag",
                dest.display()
            );
        }
    }
    let parent = path.parent().context("snapshot has no parent directory")?;
    let stage = parent.join(format!(".fluxvm-snapshot-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&stage)?;
    let result = async {
        let staged_disk = stage.join("rootfs");
        let staged_mem = stage.join("mem");
        let staged_vmstate = stage.join("vmstate");

        // Wait for every vCPU to leave KVM_RUN before reading CPU and RAM.
        guest
            .pause()
            .await
            .context("quiescing guest for snapshot")?;
        guest
            .snapshot_create(&staged_vmstate, &staged_mem)
            .await
            .context("guest snapshot/create")?;

        clone_cow(&boot.rootfs, &staged_disk)
            .with_context(|| format!("cloning rootfs to {}", staged_disk.display()))?;

        let mut boot = boot.clone();
        boot.rootfs = disk_snap.clone();
        let spec = SnapshotSpec {
            memory_path: mem_snap.clone(),
            disk_path: disk_snap.clone(),
            vmstate_path: Some(vmstate.clone()),
            boot,
        };
        fs::write(stage.join("metadata"), serde_json::to_vec_pretty(&spec)?)?;
        fs::rename(staged_disk, &disk_snap)?;
        fs::rename(staged_mem, &mem_snap)?;
        fs::rename(staged_vmstate, &vmstate)?;
        fs::rename(stage.join("metadata"), path)?;
        Ok(())
    }
    .await;
    if result.is_err() && !path.exists() {
        for dest in [&disk_snap, &mem_snap, &vmstate] {
            let _ = fs::remove_file(dest);
        }
    }
    let _ = fs::remove_dir_all(stage);
    result
}

/// Load snapshot metadata only (caller reboots/restores guest).
pub fn load_spec(path: &Path) -> Result<SnapshotSpec> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("reading snapshot {}", path.display()))?;
    let spec: SnapshotSpec = serde_json::from_str(&raw)?;
    if !spec.disk_path.exists() {
        bail!("snapshot disk missing: {}", spec.disk_path.display());
    }
    if let Some(vs) = &spec.vmstate_path {
        if !vs.exists() {
            bail!("snapshot vmstate missing: {}", vs.display());
        }
    }
    if !spec.memory_path.exists() {
        bail!("snapshot memory missing: {}", spec.memory_path.display());
    }
    Ok(spec)
}

pub async fn restore_meta(st: &mut VmState, path: &Path) -> Result<SnapshotSpec> {
    let spec = load_spec(path)?;
    st.boot = Some(spec.boot.clone());
    st.lifecycle = VmLifecycle::Created;
    st.touch();
    Ok(spec)
}

/// Prefer `cp --reflink=auto`; fall back to plain copy.
pub fn clone_cow(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        fs::remove_file(dst)?;
    }
    let status = Command::new("cp")
        .args(["--reflink=auto", "--sparse=always"])
        .arg(src)
        .arg(dst)
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => {
            fs::copy(src, dst)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn boot(dir: &Path, vcpus: u8) -> crate::api::BootConfig {
        serde_json::from_value(serde_json::json!({
            "kernel": dir.join("vmlinux"),
            "rootfs": dir.join("root.raw"),
            "memory_mib": 64,
            "vcpus": vcpus,
            "engine": "kvm"
        }))
        .unwrap()
    }

    #[test]
    fn refuses_multi_vcpu_snapshot_without_mp_states() {
        let dir = tempfile::tempdir().unwrap();
        let mem = dir.path().join("snap.mem");
        fs::File::create(&mem)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        let vmstate = dir.path().join("snap.vmstate");
        let mut f = fs::File::create(&vmstate).unwrap();
        f.write_all(kvm_snap::MAGIC).unwrap();
        f.write_all(&3u32.to_le_bytes()).unwrap();
        f.write_all(&(64u64 * 1024 * 1024).to_le_bytes()).unwrap();
        f.write_all(&2u32.to_le_bytes()).unwrap();
        let pair_len = std::mem::size_of::<crate::kvm::KvmRegs>()
            + std::mem::size_of::<crate::kvm::KvmSregs>();
        f.write_all(&vec![0; pair_len * 2]).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap(); // v3 virtio device count
        let spec = SnapshotSpec {
            memory_path: mem,
            disk_path: dir.path().join("root.raw"),
            vmstate_path: Some(vmstate),
            boot: boot(dir.path(), 2),
        };
        let err = preflight_restore(&spec).unwrap_err();
        assert!(format!("{err:#}").contains("v4 MP state"));
    }

    #[test]
    fn rejects_missing_kvm_vmstate_before_live_guest_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let spec = SnapshotSpec {
            memory_path: dir.path().join("mem"),
            disk_path: dir.path().join("root.raw"),
            vmstate_path: None,
            boot: boot(dir.path(), 1),
        };
        assert!(format!("{:#}", preflight_restore(&spec).unwrap_err()).contains("vmstate"));
    }
}
