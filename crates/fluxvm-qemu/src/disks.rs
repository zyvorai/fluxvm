//! Data disks: qcow2 files under `<workspace>/disks/<name>.qcow2`, attached
//! as `scsi-hd` on the boot-time `scsi0` controller. The directory is the
//! source of truth, so a disk attached live is re-attached on every boot.

use crate::{QMP_TIMEOUT, qmp};
use anyhow::{Context, Result, bail};
use fluxvm_core::backend::path_arg;
use fluxvm_core::config::Config;
use fluxvm_core::model::{VmDiskInfo, VmRecord, VmStatus};
use serde_json::json;
use std::path::{Path, PathBuf};

pub const ROOT_DISK: &str = "root";
/// `-drive if=virtio` without an id gets the BlockBackend name `virtio0`.
const ROOT_BLOCK_DEVICE: &str = "virtio0";

pub fn disks_dir(workspace: &Path) -> PathBuf {
    workspace.join("disks")
}

pub fn validate_disk_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 32
        || name == ROOT_DISK
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        || name.starts_with('-')
    {
        bail!("invalid disk name {name:?}: use 1-32 of [a-z0-9-], not 'root'");
    }
    Ok(())
}

/// Sorted `(name, path)` of every data disk in `workspace`.
pub fn data_disks(workspace: &Path) -> Vec<(String, PathBuf)> {
    let Ok(rd) = std::fs::read_dir(disks_dir(workspace)) else {
        return vec![];
    };
    let mut out: Vec<(String, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "qcow2"))
        .filter_map(|p| {
            let name = p.file_stem()?.to_str()?.to_string();
            validate_disk_name(&name).ok()?;
            Some((name, p))
        })
        .collect();
    out.sort();
    out
}

fn node_name(name: &str) -> String {
    format!("data-{name}")
}

fn device_id(name: &str) -> String {
    format!("disk-{name}")
}

/// Boot-time `-blockdev`/`-device` pairs for every data disk.
pub fn boot_args(workspace: &Path) -> Vec<String> {
    let mut a = Vec::new();
    for (name, path) in data_disks(workspace) {
        a.extend([
            "-blockdev".into(),
            format!(
                "driver=qcow2,node-name={},cache.direct=off,file.driver=file,file.filename={}",
                node_name(&name),
                path_arg(&path)
            ),
            "-device".into(),
            format!(
                "scsi-hd,bus=scsi0.0,drive={},id={},serial={name}",
                node_name(&name),
                device_id(&name)
            ),
        ]);
    }
    a
}

async fn qemu_img(cfg: &Config, args: &[&str], path: &Path) -> Result<Vec<u8>> {
    let out = tokio::process::Command::new(&cfg.qemu_img_binary)
        .args(args)
        .arg(path)
        .output()
        .await
        .with_context(|| format!("running {}", cfg.qemu_img_binary))?;
    if !out.status.success() {
        bail!(
            "qemu-img {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

async fn virtual_size(cfg: &Config, path: &Path) -> Result<(u64, String)> {
    let out = qemu_img(cfg, &["info", "-U", "--output=json"], path).await?;
    let v: serde_json::Value = serde_json::from_slice(&out).context("parsing qemu-img info")?;
    Ok((
        v.get("virtual-size").and_then(|s| s.as_u64()).unwrap_or(0),
        v.get("format")
            .and_then(|s| s.as_str())
            .unwrap_or("raw")
            .to_string(),
    ))
}

async fn disk_info(cfg: &Config, name: &str, path: &Path, bus: &str) -> Result<VmDiskInfo> {
    let (size_bytes, format) = virtual_size(cfg, path).await?;
    let allocated_bytes = std::fs::metadata(path)
        .map(|m| {
            use std::os::unix::fs::MetadataExt;
            m.blocks() * 512
        })
        .unwrap_or(0);
    Ok(VmDiskInfo {
        name: name.to_string(),
        path: path.to_path_buf(),
        bus: bus.to_string(),
        format,
        size_bytes,
        allocated_bytes,
    })
}

pub async fn list(cfg: &Config, vm: &VmRecord) -> Result<Vec<VmDiskInfo>> {
    let mut out = vec![disk_info(cfg, ROOT_DISK, &vm.disk, "virtio").await?];
    for (name, path) in data_disks(&vm.workspace) {
        out.push(disk_info(cfg, &name, &path, "scsi").await?);
    }
    Ok(out)
}

fn is_live(vm: &VmRecord) -> bool {
    matches!(vm.status, VmStatus::Running | VmStatus::Paused)
}

/// Create a new qcow2 data disk and, when the VM is live, hot-add it.
pub async fn attach(cfg: &Config, vm: &VmRecord, name: &str, size_gib: u64) -> Result<VmDiskInfo> {
    validate_disk_name(name)?;
    if size_gib == 0 || size_gib > 16 * 1024 {
        bail!("disk size must be 1..=16384 GiB");
    }
    let dir = disks_dir(&vm.workspace);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(format!("{name}.qcow2"));
    if path.exists() {
        bail!("disk {name:?} already exists");
    }
    let out = tokio::process::Command::new(&cfg.qemu_img_binary)
        .args(["create", "-q", "-f", "qcow2"])
        .arg(&path)
        .arg(format!("{size_gib}G"))
        .output()
        .await
        .with_context(|| format!("running {}", cfg.qemu_img_binary))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&path);
        bail!(
            "qemu-img create failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    if is_live(vm)
        && let Err(e) = hot_add(vm, name, &path).await
    {
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    disk_info(cfg, name, &path, "scsi").await
}

async fn hot_add(vm: &VmRecord, name: &str, path: &Path) -> Result<()> {
    let sock = vm.workspace.join("qmp.sock");
    qmp::execute(
        &sock,
        "blockdev-add",
        Some(json!({
            "driver": "qcow2",
            "node-name": node_name(name),
            "file": {"driver": "file", "filename": path.to_string_lossy()},
        })),
        QMP_TIMEOUT,
    )
    .await
    .context("blockdev-add")?;
    if let Err(e) = qmp::execute(
        &sock,
        "device_add",
        Some(json!({
            "driver": "scsi-hd",
            "bus": "scsi0.0",
            "drive": node_name(name),
            "id": device_id(name),
            "serial": name,
        })),
        QMP_TIMEOUT,
    )
    .await
    {
        let _ = qmp::execute(
            &sock,
            "blockdev-del",
            Some(json!({"node-name": node_name(name)})),
            QMP_TIMEOUT,
        )
        .await;
        return Err(e).context("device_add scsi-hd");
    }
    Ok(())
}

/// Detach (hot-unplug when live) and delete a data disk's file.
pub async fn detach(vm: &VmRecord, name: &str) -> Result<()> {
    validate_disk_name(name)?;
    let path = disks_dir(&vm.workspace).join(format!("{name}.qcow2"));
    if !path.is_file() {
        bail!("disk {name:?} not found");
    }
    if is_live(vm) {
        let sock = vm.workspace.join("qmp.sock");
        qmp::execute(
            &sock,
            "device_del",
            Some(json!({"id": device_id(name)})),
            QMP_TIMEOUT,
        )
        .await
        .context("device_del")?;
        // SCSI unplug completes asynchronously; blockdev-del fails with
        // "in use" until the device is gone.
        let mut last = None;
        for _ in 0..50 {
            match qmp::execute(
                &sock,
                "blockdev-del",
                Some(json!({"node-name": node_name(name)})),
                QMP_TIMEOUT,
            )
            .await
            {
                Ok(_) => {
                    last = None;
                    break;
                }
                Err(e) => last = Some(e),
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        if let Some(e) = last {
            return Err(e).context("blockdev-del after device_del");
        }
    }
    std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))
}

/// Grow a disk to `size_gib`. Shrinking is refused.
pub async fn resize(cfg: &Config, vm: &VmRecord, name: &str, size_gib: u64) -> Result<VmDiskInfo> {
    let (path, bus) = if name == ROOT_DISK {
        (vm.disk.clone(), "virtio")
    } else {
        validate_disk_name(name)?;
        (
            disks_dir(&vm.workspace).join(format!("{name}.qcow2")),
            "scsi",
        )
    };
    if !path.is_file() {
        bail!("disk {name:?} not found");
    }
    let new_bytes = size_gib
        .checked_mul(1 << 30)
        .context("disk size overflow")?;
    let (cur, _) = virtual_size(cfg, &path).await?;
    if new_bytes <= cur {
        bail!("disk {name:?} is already {cur} bytes; resize only grows");
    }
    if is_live(vm) {
        let target = if name == ROOT_DISK {
            json!({"device": ROOT_BLOCK_DEVICE, "size": new_bytes})
        } else {
            json!({"node-name": node_name(name), "size": new_bytes})
        };
        qmp::execute(
            &vm.workspace.join("qmp.sock"),
            "block_resize",
            Some(target),
            QMP_TIMEOUT,
        )
        .await
        .context("block_resize")?;
    } else {
        let out = tokio::process::Command::new(&cfg.qemu_img_binary)
            .arg("resize")
            .arg(&path)
            .arg(new_bytes.to_string())
            .output()
            .await
            .with_context(|| format!("running {}", cfg.qemu_img_binary))?;
        if !out.status.success() {
            bail!(
                "qemu-img resize failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    }
    disk_info(cfg, name, &path, bus).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_names() {
        assert!(validate_disk_name("data-1").is_ok());
        for bad in ["", "root", "-x", "Upper", "a/b", "a.b", &"x".repeat(33)] {
            assert!(validate_disk_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn boot_args_follow_the_disks_dir() {
        let tmp = std::env::temp_dir().join(format!("fluxvm-disks-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(disks_dir(&tmp)).unwrap();
        assert!(boot_args(&tmp).is_empty());
        for n in ["b", "a", "bad.name"] {
            std::fs::write(disks_dir(&tmp).join(format!("{n}.qcow2")), b"").unwrap();
        }
        std::fs::write(disks_dir(&tmp).join("c.raw"), b"").unwrap();
        let args = boot_args(&tmp).join(" ");
        assert!(args.find("node-name=data-a").unwrap() < args.find("node-name=data-b").unwrap());
        assert!(args.contains("scsi-hd,bus=scsi0.0,drive=data-a,id=disk-a,serial=a"));
        assert!(!args.contains("bad") && !args.contains("data-c"));
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
