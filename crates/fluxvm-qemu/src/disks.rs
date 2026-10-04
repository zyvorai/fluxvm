//! Data disks: qcow2 files under `<workspace>/disks/<name>.qcow2`, attached
//! as `scsi-hd` on the boot-time `scsi0` controller. The directory is the
//! source of truth, so a disk attached live is re-attached on every boot.
//!
//! An existing image or block device (a PVC's volume, an RBD map) is attached
//! as a symlink `<name>.qcow2` / `<name>.raw` pointing at it. Detach removes
//! the link only; the source belongs to whoever created it.

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
        .filter(|p| p.extension().is_some_and(|x| x == "qcow2" || x == "raw"))
        .filter_map(|p| {
            let name = p.file_stem()?.to_str()?.to_string();
            validate_disk_name(&name).ok()?;
            Some((name, p))
        })
        .collect();
    out.sort();
    out
}

/// The data disk named `name`, whichever format it was attached as.
fn find_disk(workspace: &Path, name: &str) -> Option<PathBuf> {
    data_disks(workspace)
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, p)| p)
}

/// `qcow2` or `raw`, from the file extension.
fn disk_format(path: &Path) -> &'static str {
    if path.extension().is_some_and(|x| x == "raw") {
        "raw"
    } else {
        "qcow2"
    }
}

/// True for a disk attached from an existing image (a symlink in `disks/`).
pub fn is_external(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

fn is_block_device(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(path).is_ok_and(|m| m.file_type().is_block_device())
}

/// The `file` protocol driver for `path`: `host_device` for a block device.
fn file_driver(path: &Path) -> &'static str {
    if is_block_device(path) {
        "host_device"
    } else {
        "file"
    }
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
                "driver={},node-name={},cache.direct=off,file.driver={},file.filename={}",
                disk_format(&path),
                node_name(&name),
                file_driver(&path),
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
    if find_disk(&vm.workspace, name).is_some() {
        bail!("disk {name:?} already exists");
    }
    let path = dir.join(format!("{name}.qcow2"));
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

/// Attach an existing qcow2/raw image or block device as data disk `name`
/// (hot-adding it when the VM is live). The source is never modified by
/// detach; QEMU's image locking refuses a source another VM has open.
pub async fn attach_existing(
    cfg: &Config,
    vm: &VmRecord,
    name: &str,
    source: &Path,
) -> Result<VmDiskInfo> {
    validate_disk_name(name)?;
    if !source.is_absolute() {
        bail!("disk source {} must be an absolute path", source.display());
    }
    let meta =
        std::fs::metadata(source).with_context(|| format!("disk source {}", source.display()))?;
    let format = if is_block_device(source) {
        "raw".to_string()
    } else if meta.is_file() {
        virtual_size(cfg, source).await?.1
    } else {
        bail!(
            "disk source {} is neither a file nor a block device",
            source.display()
        );
    };
    if format != "raw" && format != "qcow2" {
        bail!("disk source format {format:?} is not supported (raw or qcow2)");
    }
    let real = std::fs::canonicalize(source)?;
    if real.starts_with(std::fs::canonicalize(&vm.workspace)?) {
        bail!("disk source must live outside the VM workspace");
    }
    if find_disk(&vm.workspace, name).is_some() {
        bail!("disk {name:?} already exists");
    }
    let dir = disks_dir(&vm.workspace);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let link = dir.join(format!("{name}.{format}"));
    std::os::unix::fs::symlink(&real, &link)
        .with_context(|| format!("linking {} -> {}", link.display(), real.display()))?;
    if is_live(vm)
        && let Err(e) = hot_add(vm, name, &link).await
    {
        let _ = std::fs::remove_file(&link);
        return Err(e);
    }
    disk_info(cfg, name, &link, "scsi").await
}

async fn hot_add(vm: &VmRecord, name: &str, path: &Path) -> Result<()> {
    let sock = vm.workspace.join("qmp.sock");
    qmp::execute(
        &sock,
        "blockdev-add",
        Some(json!({
            "driver": disk_format(path),
            "node-name": node_name(name),
            "file": {"driver": file_driver(path), "filename": path.to_string_lossy()},
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

/// Detach (hot-unplug when live) and delete a data disk's file, or only the
/// link for a disk attached from an existing image.
pub async fn detach(vm: &VmRecord, name: &str) -> Result<()> {
    validate_disk_name(name)?;
    let Some(path) = find_disk(&vm.workspace, name) else {
        bail!("disk {name:?} not found");
    };
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
        let Some(path) = find_disk(&vm.workspace, name) else {
            bail!("disk {name:?} not found");
        };
        if is_external(&path) {
            bail!("disk {name:?} is attached from an existing image; resize its source");
        }
        (path, "scsi")
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
        std::fs::write(disks_dir(&tmp).join("c.img"), b"").unwrap();
        let args = boot_args(&tmp).join(" ");
        assert!(args.find("node-name=data-a").unwrap() < args.find("node-name=data-b").unwrap());
        assert!(args.contains("scsi-hd,bus=scsi0.0,drive=data-a,id=disk-a,serial=a"));
        assert!(!args.contains("bad") && !args.contains("data-c"));
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn linked_disks_boot_with_their_format_and_stay_external() {
        let tmp = std::env::temp_dir().join(format!("fluxvm-disks-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(disks_dir(&tmp)).unwrap();
        let src = tmp.join("pvc.img");
        std::fs::write(&src, b"").unwrap();
        let link = disks_dir(&tmp).join("pvc.raw");
        std::os::unix::fs::symlink(&src, &link).unwrap();
        std::fs::write(disks_dir(&tmp).join("own.qcow2"), b"").unwrap();
        let args = boot_args(&tmp).join(" ");
        assert!(args.contains("driver=raw,node-name=data-pvc,cache.direct=off,file.driver=file"));
        assert!(args.contains("driver=qcow2,node-name=data-own"));
        assert!(is_external(&link));
        assert!(!is_external(&disks_dir(&tmp).join("own.qcow2")));
        assert_eq!(find_disk(&tmp, "pvc"), Some(link));
        assert_eq!(find_disk(&tmp, "nope"), None);
        std::fs::remove_dir_all(&tmp).unwrap();
    }
}
