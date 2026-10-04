// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Import a VMware (or other hypervisor) VM: OVA, OVF, VMDK, VHD(X) or
//! qcow2 in, raw disks plus a suggested create request out. With `repair`,
//! the boot disk is fixed offline through guestkit so it boots on virtio:
//! VMware tools disabled or removed, virtio modules forced into the
//! initramfs, `/dev/sdX` references moved to `/dev/vdX`, stale persistent
//! NIC names dropped and a DHCP fallback added. Windows guests get the
//! virtio-win drivers injected offline when `virtio_win_dir` is configured.

use crate::ova::{OvfSummary, extract_ova, parse_ovf};
use anyhow::{Context, Result, bail};
use fluxvm_core::config::Config;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    /// Host path of the `.ova`, `.ovf`, or a single disk image.
    pub source: PathBuf,
    /// Output name; disks land in `<state_dir>/images/imported/<name>/`.
    pub name: String,
    #[serde(default = "yes")]
    pub repair: bool,
    /// Uninstall open-vm-tools / vmware-tools packages instead of only
    /// disabling their services.
    #[serde(default)]
    pub remove_vmware_tools: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    /// Boot disk (raw).
    pub image: PathBuf,
    pub extra_disks: Vec<PathBuf>,
    pub ovf: Option<OvfSummary>,
    pub repair: Option<RepairReport>,
    /// Starting point for `POST /v1/vms`.
    pub suggested: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RepairReport {
    pub os_type: String,
    pub distro: String,
    pub actions: Vec<String>,
    pub warnings: Vec<String>,
}

const VMWARE_UNITS: &[&str] = &[
    "vmtoolsd.service",
    "open-vm-tools.service",
    "vmware-tools.service",
    "vgauth.service",
    "vmware-tools-thinprint.service",
    "run-vmblock\\x2dfuse.mount",
];
const VMWARE_PACKAGES: &[&str] = &["open-vm-tools", "open-vm-tools-desktop", "vmware-tools"];
const VIRTIO_MODULES: &[&str] = &[
    "virtio_blk",
    "virtio_scsi",
    "virtio_net",
    "virtio_pci",
    "virtio_console",
];

pub async fn import_image(cfg: &Config, req: &ImportRequest) -> Result<ImportResult> {
    validate_name(&req.name)?;
    check_source_allowed(cfg, &req.source)?;
    let out_dir = cfg
        .state_dir
        .join("images")
        .join("imported")
        .join(&req.name);
    if out_dir.exists() {
        bail!(
            "import {} already exists at {}",
            req.name,
            out_dir.display()
        );
    }
    fs::create_dir_all(&out_dir)?;
    let result = import_into(cfg, req, &out_dir).await;
    if result.is_err() {
        let _ = fs::remove_dir_all(&out_dir);
    }
    result
}

async fn import_into(cfg: &Config, req: &ImportRequest, out_dir: &Path) -> Result<ImportResult> {
    let staging = out_dir.join(".staging");
    let lower = req.source.to_string_lossy().to_ascii_lowercase();
    let (ovf, sources): (Option<OvfSummary>, Vec<PathBuf>) = if lower.ends_with(".ova") {
        let src = req.source.clone();
        let stage = staging.clone();
        let ovf_path = tokio::task::spawn_blocking(move || extract_ova(&src, &stage))
            .await
            .context("OVA extraction worker panicked")??;
        let summary = parse_ovf(&fs::read_to_string(&ovf_path)?)?;
        let disks = summary
            .disks
            .iter()
            .map(|d| staging.join(&d.href))
            .collect();
        (Some(summary), disks)
    } else if lower.ends_with(".ovf") {
        let summary = parse_ovf(&fs::read_to_string(&req.source)?)?;
        let base = req.source.parent().unwrap_or(Path::new("."));
        let mut disks = Vec::new();
        for d in &summary.disks {
            if d.href.contains('/') || d.href.contains("..") {
                bail!("OVF disk href {:?} must be a bare file name", d.href);
            }
            disks.push(base.join(&d.href));
        }
        (Some(summary), disks)
    } else {
        (None, vec![req.source.clone()])
    };
    if sources.is_empty() {
        bail!("no disks found in {}", req.source.display());
    }

    let mut outputs = Vec::with_capacity(sources.len());
    for (i, src) in sources.iter().enumerate() {
        if !src.is_file() {
            bail!("disk {} is missing", src.display());
        }
        let out = out_dir.join(format!("disk{i}.raw"));
        let format = crate::image_format(cfg, src).await?;
        if format == "raw" {
            copy_raw(src, &out)?;
        } else {
            crate::convert_image(cfg, src, &out, "raw")
                .await
                .with_context(|| format!("converting {} ({format}) to raw", src.display()))?;
        }
        outputs.push(out);
    }
    let _ = fs::remove_dir_all(&staging);

    let repair = if req.repair {
        let disk = outputs[0].clone();
        let remove = req.remove_vmware_tools;
        let virtio_win = cfg.virtio_win_dir.clone();
        Some(
            tokio::task::spawn_blocking(move || {
                repair_blocking(&disk, remove, virtio_win.as_deref())
            })
            .await
            .context("guestkit worker thread panicked")??,
        )
    } else {
        None
    };

    let suggested = suggested_request(
        &req.name,
        &outputs,
        ovf.as_ref(),
        cfg.qemu_ovmf_code.as_deref(),
    );
    Ok(ImportResult {
        image: outputs[0].clone(),
        extra_disks: outputs[1..].to_vec(),
        ovf,
        repair,
        suggested,
    })
}

/// Copies a raw source, using a reflink where the filesystem supports one.
fn copy_raw(src: &Path, dst: &Path) -> Result<()> {
    let status = std::process::Command::new("cp")
        .args(["--reflink=auto", "--sparse=always"])
        .arg(src)
        .arg(dst)
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        _ => fs::copy(src, dst)
            .map(|_| ())
            .with_context(|| format!("copying {}", src.display())),
    }
}

fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 63
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && !name.starts_with('-');
    if !ok {
        bail!("import name must be 1-63 characters of [A-Za-z0-9_-]");
    }
    Ok(())
}

/// Applies `policy.allowed_image_dirs` to the import source, like create
/// does for `image`.
fn check_source_allowed(cfg: &Config, source: &Path) -> Result<()> {
    let Some(dirs) = &cfg.policy.allowed_image_dirs else {
        return Ok(());
    };
    let real =
        fs::canonicalize(source).with_context(|| format!("resolving {}", source.display()))?;
    for d in dirs {
        if let Ok(dir) = fs::canonicalize(d)
            && real.starts_with(&dir)
        {
            return Ok(());
        }
    }
    bail!(
        "import source {} is not under any policy allowed_image_dirs {:?}",
        source.display(),
        dirs
    )
}

/// A `POST /v1/vms` body for the import, plus `notes` for what the body
/// can't express (strip `notes` before sending).
fn suggested_request(
    name: &str,
    disks: &[PathBuf],
    ovf: Option<&OvfSummary>,
    ovmf_code: Option<&Path>,
) -> serde_json::Value {
    let mut notes = Vec::new();
    let mut req = serde_json::json!({
        "name": name.to_ascii_lowercase().replace('_', "-"),
        "image": disks[0],
        "backend": "qemu",
        "vcpus": ovf.and_then(|o| o.vcpus).unwrap_or(2),
        "memory_mib": ovf.and_then(|o| o.memory_mib).unwrap_or(2048),
    });
    if ovf.and_then(|o| o.firmware.as_deref()) == Some("efi") {
        match ovmf_code {
            Some(code) => req["firmware"] = serde_json::json!(code),
            None => {
                notes.push("source VM used UEFI: set firmware to an OVMF_CODE.fd path".to_string())
            }
        }
    }
    if disks.len() > 1 {
        req["data_disks"] = disks
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, p)| serde_json::json!({"name": format!("disk{i}"), "backing": p}))
            .collect();
    }
    if ovf.is_some_and(|o| o.nics > 1) {
        notes.push(format!(
            "source VM had {} NICs; add the others with POST /v1/vms/{{id}}/hotplug/nic",
            ovf.map_or(0, |o| o.nics)
        ));
    }
    if !notes.is_empty() {
        req["notes"] = serde_json::json!(notes);
    }
    req
}

/// Rewrites whole-word `/dev/sdX[N]` and `/dev/hdX[N]` to `/dev/vdX[N]`.
pub(crate) fn rewrite_scsi_devices(text: &str) -> (String, usize) {
    let mut out = String::with_capacity(text.len());
    let mut count = 0;
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let rest = &text[i..];
        let hit = ["/dev/sd", "/dev/hd"]
            .iter()
            .find(|p| rest.starts_with(**p));
        let boundary = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'/');
        if let (Some(p), true) = (hit, boundary)
            && rest
                .as_bytes()
                .get(p.len())
                .is_some_and(|c| c.is_ascii_lowercase())
        {
            out.push_str("/dev/vd");
            i += p.len();
            count += 1;
            continue;
        }
        let ch = rest.chars().next().unwrap_or_default();
        out.push(ch);
        i += ch.len_utf8();
    }
    (out, count)
}

fn repair_blocking(
    disk: &Path,
    remove_tools: bool,
    virtio_win: Option<&Path>,
) -> Result<RepairReport> {
    use guestkit::Guestfs;

    let mut g = Guestfs::new().context("creating guestkit handle")?;
    g.add_drive(disk)
        .with_context(|| format!("adding drive {}", disk.display()))?;
    g.launch().context("launching guestfs")?;
    let roots = g.inspect_os().context("inspecting guest OS")?;
    let root = roots
        .first()
        .context("no operating system found in the boot disk")?
        .clone();
    let mut report = RepairReport {
        os_type: g.inspect_get_type(&root).unwrap_or_default(),
        distro: g.inspect_get_distro(&root).unwrap_or_default(),
        ..Default::default()
    };
    if report.os_type == "windows" {
        match virtio_win {
            Some(tree) => repair_windows(&mut g, &root, tree, &mut report)?,
            None => report.warnings.push(
                "Windows guest: no virtio_win_dir configured, so no drivers were injected; set it to an \
                 extracted virtio-win ISO, or install viostor, vioscsi and netkvm inside the VM before exporting it"
                    .into(),
            ),
        }
        let _ = g.umount_all();
        g.shutdown().context("shutting down guestfs")?;
        return Ok(report);
    }
    if report.os_type != "linux" {
        report.warnings.push(format!(
            "unsupported guest type {:?}; no repair done",
            report.os_type
        ));
        let _ = g.shutdown();
        return Ok(report);
    }
    let mounts = g
        .inspect_get_mountpoints(&root)
        .context("getting mountpoints")?;
    for (mountpoint, device) in &crate::depth_ordered_mounts(mounts) {
        g.mount(device, mountpoint)
            .with_context(|| format!("mounting {device} at {mountpoint}"))?;
    }

    repair_vmware_tools(&mut g, remove_tools, &mut report);
    repair_device_names(&mut g, &mut report);
    repair_network(&mut g, &mut report);
    repair_initramfs(&mut g, &mut report);

    let _ = g.umount_all();
    g.shutdown().context("shutting down guestfs")?;
    Ok(report)
}

/// virtio-win driver directories injected into Windows guests. viostor is
/// the boot disk driver for FluxVM's default virtio-blk bus.
const WINDOWS_DRIVERS: &[&str] = &["viostor", "vioscsi", "NetKVM", "vioserial"];

/// Guest directory every injected driver is copied into. One shared
/// directory, because each injection sets the SOFTWARE-hive `DevicePath` to
/// `%SystemRoot%\inf` plus its own directory.
const WINDOWS_DRIVER_DEST: &str = "VirtIO";

fn repair_windows(
    g: &mut guestkit::Guestfs,
    root: &str,
    tree: &Path,
    report: &mut RepairReport,
) -> Result<()> {
    let mounts = g
        .inspect_get_mountpoints(root)
        .context("getting mountpoints")?;
    for (mountpoint, device) in &crate::depth_ordered_mounts(mounts) {
        g.mount(device, mountpoint)
            .with_context(|| format!("mounting {device} at {mountpoint}"))?;
    }
    let major = g.inspect_get_major_version(root).unwrap_or(0);
    let minor = g.inspect_get_minor_version(root).unwrap_or(0);
    let product = g.inspect_get_product_name(root).unwrap_or_default();
    let os_dirs = windows_os_dirs(major, minor, &product);
    for driver in WINDOWS_DRIVERS {
        let Some(dir) = find_driver_dir(tree, driver, os_dirs) else {
            report.warnings.push(format!(
                "{driver} not found under {} for {product:?}",
                tree.display()
            ));
            continue;
        };
        match guestkit::agent::inject::inject_windows_driver_dir(
            g,
            root,
            &dir,
            WINDOWS_DRIVER_DEST,
            false,
        ) {
            Ok(()) => report
                .actions
                .push(format!("injected {driver} from {}", dir.display())),
            Err(e) => report
                .warnings
                .push(format!("injecting {driver} failed: {e:#}")),
        }
    }
    if !report
        .actions
        .iter()
        .any(|a| a.starts_with("injected viostor"))
    {
        report.warnings.push(
            "viostor was not injected: the guest will not find its boot disk on virtio-blk; \
             boot it on IDE/SATA and install the driver inside"
                .into(),
        );
    }
    Ok(())
}

/// virtio-win per-OS directory names to try for a guest, best match first.
pub(crate) fn windows_os_dirs(major: i32, minor: i32, product: &str) -> &'static [&'static str] {
    let p = product.to_ascii_lowercase();
    if p.contains("server") {
        return if p.contains("2025") {
            &["2k25", "2k22"]
        } else if p.contains("2022") {
            &["2k22", "2k19"]
        } else if p.contains("2019") {
            &["2k19", "2k16"]
        } else if p.contains("2016") {
            &["2k16"]
        } else if p.contains("2012 r2") {
            &["2k12R2"]
        } else {
            &["2k22", "2k19", "2k16"]
        };
    }
    match (major, minor) {
        (10, _) if p.contains("windows 11") => &["w11", "w10"],
        (10, _) => &["w10", "w11"],
        (6, 3) => &["w8.1"],
        (6, 2) => &["w8"],
        (6, 1) => &["w7"],
        _ => &["w10", "w11"],
    }
}

/// `<tree>/<driver>/<os>/amd64` for the first OS directory holding an INF,
/// else guestkit's generic virtio-win layout search.
pub(crate) fn find_driver_dir(tree: &Path, driver: &str, os_dirs: &[&str]) -> Option<PathBuf> {
    for os in os_dirs {
        let dir = tree.join(driver).join(os).join("amd64");
        if has_inf(&dir) {
            return Some(dir);
        }
    }
    guestkit::cli::virtio_win::resolve_driver_dir(tree, driver).filter(|d| has_inf(d))
}

fn has_inf(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok_and(|rd| {
        rd.flatten().any(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("inf"))
        })
    })
}

fn unit_exists(g: &mut guestkit::Guestfs, unit: &str) -> bool {
    [
        "/usr/lib/systemd/system/",
        "/lib/systemd/system/",
        "/etc/systemd/system/",
    ]
    .iter()
    .any(|d| g.exists(&format!("{d}{unit}")).unwrap_or(false))
}

fn repair_vmware_tools(g: &mut guestkit::Guestfs, remove: bool, report: &mut RepairReport) {
    for unit in VMWARE_UNITS {
        if unit_exists(g, unit) {
            match g.command(&["systemctl", "disable", unit]) {
                Ok(_) => report.actions.push(format!("disabled {unit}")),
                Err(e) => report
                    .warnings
                    .push(format!("could not disable {unit}: {e}")),
            }
        }
    }
    if !remove {
        return;
    }
    let dpkg = g.exists("/var/lib/dpkg/status").unwrap_or(false);
    let rpm = g.exists("/usr/bin/rpm").unwrap_or(false);
    for pkg in VMWARE_PACKAGES {
        let installed = if dpkg {
            g.command(&["dpkg-query", "-W", "-f=${Status}", pkg])
                .is_ok_and(|s| s.contains("install ok installed"))
        } else if rpm {
            g.command(&["rpm", "-q", pkg]).is_ok()
        } else {
            false
        };
        if !installed {
            continue;
        }
        let res = if dpkg {
            g.command(&["dpkg", "--purge", pkg])
        } else {
            g.command(&["rpm", "-e", "--nodeps", pkg])
        };
        match res {
            Ok(_) => report.actions.push(format!("removed package {pkg}")),
            Err(e) => report.warnings.push(format!("could not remove {pkg}: {e}")),
        }
    }
}

fn repair_device_names(g: &mut guestkit::Guestfs, report: &mut RepairReport) {
    let mut files = vec!["/etc/fstab".to_string(), "/etc/default/grub".to_string()];
    for pattern in [
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
        "/boot/efi/EFI/*/grub.cfg",
    ] {
        files.extend(g.glob_expand(pattern).unwrap_or_default());
    }
    for path in files {
        let Ok(bytes) = g.read_file(&path) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        let (new, n) = rewrite_scsi_devices(&text);
        if n == 0 {
            continue;
        }
        match g.write(&path, new.as_bytes()) {
            Ok(()) => report.actions.push(format!(
                "{path}: {n} /dev/sdX reference(s) moved to /dev/vdX"
            )),
            Err(e) => report
                .warnings
                .push(format!("could not rewrite {path}: {e}")),
        }
    }
}

fn repair_network(g: &mut guestkit::Guestfs, report: &mut RepairReport) {
    for rules in [
        "/etc/udev/rules.d/70-persistent-net.rules",
        "/etc/udev/rules.d/75-persistent-net-generator.rules",
    ] {
        if g.exists(rules).unwrap_or(false) && g.rm_f(rules).is_ok() {
            report.actions.push(format!("removed {rules}"));
        }
    }
    if g.is_dir("/etc/netplan").unwrap_or(false) {
        let conf = "network:\n  version: 2\n  ethernets:\n    fluxvm-any:\n      match:\n        name: \"en*\"\n      dhcp4: true\n      dhcp6: true\n      optional: true\n";
        if g.write("/etc/netplan/90-fluxvm-dhcp.yaml", conf.as_bytes())
            .is_ok()
        {
            let _ = g.command(&["chmod", "600", "/etc/netplan/90-fluxvm-dhcp.yaml"]);
            report
                .actions
                .push("added netplan DHCP fallback for en* interfaces".into());
        }
    } else if g
        .is_dir("/etc/NetworkManager/system-connections")
        .unwrap_or(false)
    {
        let conf = "[connection]\nid=fluxvm-dhcp\ntype=ethernet\nautoconnect-priority=-100\n\n[match]\ninterface-name=en*;eth*;\n\n[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n";
        let path = "/etc/NetworkManager/system-connections/fluxvm-dhcp.nmconnection";
        if g.write(path, conf.as_bytes()).is_ok() {
            let _ = g.command(&["chmod", "600", path]);
            report
                .actions
                .push("added NetworkManager DHCP fallback for en*/eth* interfaces".into());
        }
    }
    for dir in ["/etc/sysconfig/network-scripts", "/etc/netplan"] {
        for f in g.ls(dir).unwrap_or_default() {
            if ["ens192", "ens160", "ens224", "ens256"]
                .iter()
                .any(|n| f.contains(n))
            {
                report.warnings.push(format!(
                    "{dir}/{f} names a VMware NIC; the virtio NIC will be named differently (e.g. enp1s0), review static IP config"
                ));
            }
        }
    }
}

fn repair_initramfs(g: &mut guestkit::Guestfs, report: &mut RepairReport) {
    let modules = VIRTIO_MODULES.join(" ");
    let rebuild = if g.exists("/usr/bin/dracut").unwrap_or(false)
        || g.exists("/sbin/dracut").unwrap_or(false)
    {
        let conf = format!("add_drivers+=\" {modules} \"\n");
        if g.write("/etc/dracut.conf.d/90-fluxvm-virtio.conf", conf.as_bytes())
            .is_err()
        {
            report
                .warnings
                .push("could not write dracut virtio config".into());
            return;
        }
        report
            .actions
            .push("added virtio drivers to dracut config".into());
        "dracut -f --kver \"$K\""
    } else if g.is_dir("/etc/initramfs-tools").unwrap_or(false) {
        let mut existing = g
            .read_file("/etc/initramfs-tools/modules")
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        for m in VIRTIO_MODULES {
            if !existing.lines().any(|l| l.trim() == *m) {
                existing.push_str(m);
                existing.push('\n');
            }
        }
        if g.write("/etc/initramfs-tools/modules", existing.as_bytes())
            .is_err()
        {
            report
                .warnings
                .push("could not write /etc/initramfs-tools/modules".into());
            return;
        }
        report
            .actions
            .push("added virtio modules to /etc/initramfs-tools/modules".into());
        "update-initramfs -u -k \"$K\""
    } else {
        report.warnings.push(
            "no dracut or initramfs-tools found; make sure the initramfs has virtio_blk".into(),
        );
        return;
    };
    // Only the newest kernel is rebuilt (the one grub boots by default),
    // staged in a tmpfs: imported roots are often nearly full. The chroot
    // has no /proc, /sys or /dev, so those are mounted for the rebuild.
    let script = format!(
        "K=$(ls /lib/modules | sort -V | tail -n1); [ -n \"$K\" ] || exit 3; \
         mount -t proc proc /proc 2>/dev/null; mount -t sysfs sys /sys 2>/dev/null; mount -t devtmpfs dev /dev 2>/dev/null; \
         mount -t tmpfs tmpfs /tmp 2>/dev/null; export TMPDIR=/tmp; \
         {rebuild} >/dev/null; rc=$?; umount /tmp /dev /sys /proc 2>/dev/null; echo \"$K\"; exit $rc"
    );
    match g.sh_raw(&script) {
        Ok(out) => report.actions.push(format!(
            "rebuilt initramfs for kernel {}",
            out.trim().lines().last().unwrap_or("?")
        )),
        Err(e) => {
            let detail = e.to_string();
            let tail: String = detail
                .lines()
                .rev()
                .take(3)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join(" | ");
            report.warnings.push(format!(
                "initramfs rebuild failed ({tail}); the virtio config is in place, rebuild the initramfs from a rescue shell if the disk is not found at boot"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_driver_dir_selection() {
        assert_eq!(
            windows_os_dirs(10, 0, "Windows Server 2022 Datacenter"),
            &["2k22", "2k19"]
        );
        assert_eq!(windows_os_dirs(10, 0, "Windows 10 Pro"), &["w10", "w11"]);
        assert_eq!(windows_os_dirs(6, 3, "Windows 8.1 Pro"), &["w8.1"]);

        let tree = tempfile::tempdir().unwrap();
        let w11 = tree.path().join("viostor/w11/amd64");
        let k22 = tree.path().join("viostor/2k22/amd64");
        for d in [&w11, &k22] {
            fs::create_dir_all(d).unwrap();
            fs::write(d.join("viostor.inf"), "").unwrap();
        }
        assert_eq!(
            find_driver_dir(tree.path(), "viostor", &["w10", "w11"]),
            Some(w11)
        );
        assert_eq!(
            find_driver_dir(tree.path(), "viostor", &["2k22"]),
            Some(k22)
        );
        assert_eq!(find_driver_dir(tree.path(), "NetKVM", &["w10"]), None);
    }

    #[test]
    fn rewrites_only_scsi_device_paths() {
        let fstab = "/dev/sda1 / ext4 defaults 0 1\nUUID=abc /boot ext4 defaults 0 2\n/dev/sdb  /data xfs defaults 0 0\n/dev/hda2 swap swap sw 0 0\n/my/dev/sdq x\n";
        let (out, n) = rewrite_scsi_devices(fstab);
        assert_eq!(n, 3);
        assert!(out.contains("/dev/vda1 / ext4"));
        assert!(out.contains("/dev/vdb  /data"));
        assert!(out.contains("/dev/vda2 swap"));
        assert!(out.contains("UUID=abc"));
        assert!(
            out.contains("/my/dev/sdq"),
            "only whole /dev paths are touched"
        );
        let (grub, n) = rewrite_scsi_devices("linux /vmlinuz root=/dev/sda2 ro quiet");
        assert_eq!(
            (grub.as_str(), n),
            ("linux /vmlinuz root=/dev/vda2 ro quiet", 1)
        );
    }

    #[test]
    fn names_and_suggestion() {
        assert!(validate_name("web01_prod").is_ok());
        assert!(validate_name("../x").is_err());
        assert!(validate_name("").is_err());
        let ovf = OvfSummary {
            vcpus: Some(4),
            memory_mib: Some(8192),
            firmware: Some("efi".into()),
            ..Default::default()
        };
        let disks = [PathBuf::from("/a/disk0.raw"), PathBuf::from("/a/disk1.raw")];
        let s = suggested_request(
            "Web_01",
            &disks,
            Some(&ovf),
            Some(Path::new("/ovmf/CODE.fd")),
        );
        assert_eq!(s["vcpus"], 4);
        assert_eq!(s["memory_mib"], 8192);
        assert_eq!(s["firmware"], "/ovmf/CODE.fd");
        assert_eq!(s["name"], "web-01");
        assert_eq!(s["data_disks"][0]["name"], "disk1");
        assert_eq!(s["data_disks"][0]["backing"], "/a/disk1.raw");
        assert!(s["notes"].is_null());
        let s = suggested_request("w", &disks[..1], Some(&ovf), None);
        assert!(s["firmware"].is_null() && s["notes"][0].as_str().unwrap().contains("UEFI"));
    }

    #[tokio::test]
    async fn imports_raw_disk_without_repair() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config {
            state_dir: dir.path().join("state"),
            ..Default::default()
        };
        let src = dir.path().join("disk.raw");
        fs::write(&src, vec![0u8; 4096]).unwrap();
        let req = ImportRequest {
            source: src,
            name: "vm1".into(),
            repair: false,
            remove_vmware_tools: false,
        };
        let res = import_image(&cfg, &req).await.unwrap();
        assert_eq!(fs::metadata(&res.image).unwrap().len(), 4096);
        assert!(res.repair.is_none());
        assert!(
            import_image(&cfg, &req)
                .await
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );

        cfg.policy.allowed_image_dirs = Some(vec![dir.path().join("elsewhere")]);
        let req2 = ImportRequest {
            name: "vm2".into(),
            ..req
        };
        assert!(
            import_image(&cfg, &req2)
                .await
                .unwrap_err()
                .to_string()
                .contains("allowed_image_dirs")
        );
    }
}
