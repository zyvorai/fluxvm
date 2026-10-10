// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Extra disks of `vz` Linux guests (`apple.extra_disks`): image files, host block devices and NBD exports on virtio, NVMe or
//! USB controllers. Virtualization.framework fixes a VM's devices when it starts, so a change applies at the next start, except
//! a USB image disk, which is also hot-attached to a running guest (macOS 15) and hot-detached again.

use crate::VmManager;
use anyhow::{Context, Result, bail};
use fluxvm_core::model::{
    AppleDisk, AppleDiskController, AppleDiskKind, AppleGuest, BackendKind, VmDiskInfo, VmRecord,
    VmStatus,
};
use std::path::Path;
use uuid::Uuid;

/// Most extra disks per VM (virtio and NVMe each take a PCI slot).
const MAX_EXTRA_DISKS: usize = 16;
/// `{"<disk name>": {"uuid": "<runner usb id>", "pid": <runner pid>}}`: disks hot-attached to the running guest.
const HOTPLUG_FILE: &str = "usb-hotplug.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct Hotplug {
    uuid: String,
    /// The runner the disk was attached to; after a restart the id means nothing.
    pid: Option<u32>,
}

fn read_hotplug(workspace: &Path) -> std::collections::BTreeMap<String, Hotplug> {
    std::fs::read(workspace.join(HOTPLUG_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn write_hotplug(
    workspace: &Path,
    map: &std::collections::BTreeMap<String, Hotplug>,
) -> Result<()> {
    let path = workspace.join(HOTPLUG_FILE);
    if map.is_empty() {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    std::fs::write(&path, serde_json::to_vec(map)?)
        .with_context(|| format!("writing {}", path.display()))
}

fn controller_name(c: AppleDiskController) -> &'static str {
    match c {
        AppleDiskController::Virtio => "virtio",
        AppleDiskController::Nvme => "nvme",
        AppleDiskController::Usb => "usb",
    }
}

fn kind_name(k: AppleDiskKind) -> &'static str {
    match k {
        AppleDiskKind::Image => "raw",
        AppleDiskKind::Block => "block",
        AppleDiskKind::Nbd => "nbd",
    }
}

fn sizes(path: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).map_or((0, 0), |m| (m.len(), m.blocks() * 512))
}

/// `GET /v1/vms/{id}/disks` for a `vz` VM: `root`, then each extra disk.
pub(crate) fn list(vm: &VmRecord) -> Vec<VmDiskInfo> {
    let (size, allocated) = sizes(&vm.disk);
    let mut out = vec![VmDiskInfo {
        name: "root".into(),
        path: vm.disk.clone(),
        bus: "virtio".into(),
        format: "raw".into(),
        size_bytes: size,
        allocated_bytes: allocated,
    }];
    let extra = vm
        .request
        .apple
        .as_ref()
        .map(|a| a.extra_disks.as_slice())
        .unwrap_or_default();
    for (i, d) in extra.iter().enumerate() {
        let (size_bytes, allocated_bytes) = match d.kind {
            AppleDiskKind::Image => sizes(&d.path),
            _ => (0, 0),
        };
        out.push(VmDiskInfo {
            name: d.name_at(i),
            path: match d.kind {
                AppleDiskKind::Nbd => d.url.clone().unwrap_or_default().into(),
                _ => d.path.clone(),
            },
            bus: controller_name(d.controller).into(),
            format: kind_name(d.kind).into(),
            size_bytes,
            allocated_bytes,
        });
    }
    out
}

impl VmManager {
    async fn vz_linux_vm(&self, id: Uuid) -> Result<VmRecord> {
        let vm = self.get(id).await?;
        if vm.backend != BackendKind::Vz {
            bail!("not a vz VM");
        }
        if vm
            .request
            .apple
            .as_ref()
            .is_some_and(|a| a.guest_os == AppleGuest::Macos)
        {
            bail!("extra disks are a Linux-guest feature on vz");
        }
        Ok(vm)
    }

    pub async fn list_vz_disks(&self, id: Uuid) -> Result<Vec<VmDiskInfo>> {
        Ok(list(&self.vz_linux_vm(id).await?))
    }

    /// Adds extra disk `name` to a `vz` VM: `disk` as given, or with `size_gib` a new sparse image in the VM's workspace.
    pub async fn attach_vz_disk(
        &self,
        id: Uuid,
        name: &str,
        mut disk: AppleDisk,
        size_gib: Option<u64>,
    ) -> Result<VmDiskInfo> {
        let mut vm = self.vz_linux_vm(id).await?;
        disk.name = Some(name.to_owned());
        let apple = vm.request.apple.get_or_insert_with(Default::default);
        if apple.extra_disks.len() >= MAX_EXTRA_DISKS {
            bail!("at most {MAX_EXTRA_DISKS} extra disks");
        }
        if apple
            .extra_disks
            .iter()
            .enumerate()
            .any(|(i, d)| d.name_at(i) == name)
        {
            bail!("disk {name:?} already exists");
        }
        match (size_gib, disk.kind) {
            (Some(gib), AppleDiskKind::Image) if disk.path.as_os_str().is_empty() => {
                if gib == 0 || gib > 16 * 1024 {
                    bail!("size_gib must be 1-16384");
                }
                fluxvm_apple::validate_disk(&AppleDisk {
                    path: "/placeholder".into(),
                    ..disk.clone()
                })?;
                let dir = vm.workspace.join("disks");
                std::fs::create_dir_all(&dir)?;
                let path = dir.join(format!("{name}.raw"));
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .with_context(|| format!("creating {}", path.display()))?;
                f.set_len(gib << 30)?;
                disk.path = path;
            }
            (Some(_), _) => bail!(
                "size_gib creates a new image disk; it cannot be combined with path, url or kind"
            ),
            (None, AppleDiskKind::Image | AppleDiskKind::Block) => {
                disk.path = self.check_disk_source(&disk.path)?;
            }
            (None, AppleDiskKind::Nbd) => {}
        }
        fluxvm_apple::validate_disk(&disk)?;
        apple.extra_disks.push(disk.clone());
        fluxvm_apple::validate_request(&vm.request)?;
        let live = matches!(vm.status, VmStatus::Running | VmStatus::Paused)
            && disk.kind == AppleDiskKind::Image
            && disk.controller == AppleDiskController::Usb;
        if live {
            let uuid = fluxvm_apple::usb_attach(&vm, &disk.path, disk.read_only, disk.usb_bus)
                .await
                .context("hot-attaching the USB disk")?;
            let mut map = read_hotplug(&vm.workspace);
            map.insert(name.to_owned(), Hotplug { uuid, pid: vm.pid });
            write_hotplug(&vm.workspace, &map)?;
        }
        if !live && matches!(vm.status, VmStatus::Running | VmStatus::Paused) {
            tracing::warn!(
                vm = %id,
                disk = name,
                "vz can only hot-attach USB image disks; this disk applies at the next boot"
            );
        }
        self.store.update(vm.clone()).await?;
        crate::audit_event(
            "vm.disk.attach",
            &[
                ("vm_id", &id.to_string()),
                ("disk", name),
                ("kind", kind_name(disk.kind)),
                ("live", if live { "true" } else { "false" }),
            ],
        );
        let idx = vm.request.apple.as_ref().map_or(0, |a| a.extra_disks.len());
        list(&vm)
            .into_iter()
            .nth(idx)
            .context("the new disk is missing from the list")
    }

    /// Removes extra disk `name`: at once when it was hot-attached to the running guest, otherwise at the next start. A new
    /// image made by `attach_vz_disk` is deleted with it once nothing uses it.
    pub async fn detach_vz_disk(&self, id: Uuid, name: &str) -> Result<()> {
        let mut vm = self.vz_linux_vm(id).await?;
        let mut hotplug = read_hotplug(&vm.workspace);
        let mut live = false;
        if let Some(h) = hotplug.remove(name) {
            if matches!(vm.status, VmStatus::Running | VmStatus::Paused) && h.pid == vm.pid {
                fluxvm_apple::usb_detach(&vm, &h.uuid)
                    .await
                    .context("hot-detaching the USB disk")?;
                live = true;
            }
            write_hotplug(&vm.workspace, &hotplug)?;
        }
        let workspace_disks = vm.workspace.join("disks");
        let apple = vm.request.apple.get_or_insert_with(Default::default);
        let Some(i) = apple
            .extra_disks
            .iter()
            .enumerate()
            .position(|(i, d)| d.name_at(i) == name)
        else {
            bail!("disk {name:?} not found");
        };
        let removed = apple.extra_disks.remove(i);
        // Unnamed disks are numbered by position; keep the others' names stable.
        for (j, d) in apple.extra_disks.iter_mut().enumerate() {
            if d.name.is_none() {
                d.name = Some(format!("disk{}", if j >= i { j + 1 } else { j }));
            }
        }
        let unused = live || matches!(vm.status, VmStatus::Stopped | VmStatus::Failed);
        self.store.update(vm).await?;
        if unused && removed.path.starts_with(&workspace_disks) {
            let _ = std::fs::remove_file(&removed.path);
        }
        crate::audit_event(
            "vm.disk.detach",
            &[
                ("vm_id", &id.to_string()),
                ("disk", name),
                ("live", if live { "true" } else { "false" }),
            ],
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_names_and_describes_each_disk() {
        let mut vm: VmRecord = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(), "name": "x", "backend": "vz", "status": "stopped", "pid": null,
            "created_at": "2026-01-01T00:00:00Z", "expires_at": null, "workspace": "/tmp/w",
            "disk": "/nonexistent/root.raw", "seed_disk": null, "tap_name": null, "control_socket": null,
            "log_path": "/tmp/w/console.log", "error": null,
            "request": {"name": "x", "image": "/img", "vcpus": 1, "memory_mib": 512, "backend": "vz"},
        }))
        .unwrap();
        vm.request.apple = Some(
            serde_json::from_value(serde_json::json!({
                "extra_disks": [
                    {"path": "/nonexistent/a.raw", "controller": "nvme"},
                    {"name": "net", "kind": "nbd", "url": "nbd://h:10809/v"},
                ]
            }))
            .unwrap(),
        );
        let l = list(&vm);
        let rows: Vec<_> = l
            .iter()
            .map(|d| (d.name.as_str(), d.bus.as_str(), d.format.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("root", "virtio", "raw"),
                ("disk0", "nvme", "raw"),
                ("net", "virtio", "nbd")
            ]
        );
        assert_eq!(l[2].path, Path::new("nbd://h:10809/v"));
    }
}
