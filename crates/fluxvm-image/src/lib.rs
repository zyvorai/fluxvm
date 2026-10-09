// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

pub mod builtin;
pub mod catalog;
pub mod cloudinit;
pub mod import;
pub mod oci;
pub mod ova;
pub mod qga;
pub mod raw_ext4;
pub mod storage;
mod vmdk;
mod vmdk_descriptor;
pub mod windows;

pub use windows::{FirewallPort, RunOnceEntry, WindowsAgentSpec, WindowsCustomize, WindowsScript};

use anyhow::{Context, Result, bail};
use fluxvm_core::{config::Config, model::BackendKind, process::run_checked};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use tokio::{fs as async_fs, io::AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildImageRequest {
    pub source: String,
    pub output: PathBuf,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub size_gib: Option<u64>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub ssh_key: Option<String>,
    /// Files to place directly into the image (e.g. a compiled
    /// `fluxvm-guest-agent` binary and its systemd unit). Applied via
    /// `guestkit` — a host-side file's permission bits are preserved on
    /// copy, so a binary already marked executable stays executable; no
    /// separate chmod step is needed.
    #[serde(default)]
    pub copy_in: Vec<CopyIn>,
    /// systemd unit names to `systemctl enable` via guestkit's chroot
    /// command exec, in the same session as every other customization step.
    #[serde(default)]
    pub enable_services: Vec<String>,
    /// Offline Windows customization (registry plans + Zyvor/GuestKit agent).
    /// Mutually exclusive with Linux-only fields (`packages`, `commands`,
    /// `enable_services`, `ssh_key`, top-level `hostname`).
    #[serde(default)]
    pub windows: Option<WindowsCustomize>,
}
fn default_format() -> String {
    "qcow2".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyIn {
    pub src: PathBuf,
    pub dest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BuildImageResult {
    pub output: PathBuf,
    pub format: String,
}

pub(crate) async fn fetch_if_needed(cfg: &Config, source: &str) -> Result<PathBuf> {
    if !source.starts_with("http://") && !source.starts_with("https://") {
        return Ok(PathBuf::from(source));
    }
    let downloads = cfg.state_dir.join("downloads");
    fs::create_dir_all(&downloads)?;
    let name = source
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("base.img");
    let dest = downloads.join(name);
    if dest.exists() {
        return Ok(dest);
    }
    let mut resp = Client::new().get(source).send().await?.error_for_status()?;
    let mut f = async_fs::File::create(&dest).await?;
    while let Some(chunk) = resp.chunk().await? {
        f.write_all(&chunk).await?;
    }
    Ok(dest)
}

pub(crate) fn verify_sha256(path: &Path, wanted: &str) -> Result<()> {
    let bytes = fs::read(path)?;
    let got = format!("{:x}", Sha256::digest(&bytes));
    if !got.eq_ignore_ascii_case(wanted) {
        bail!("sha256 mismatch: expected {wanted}, got {got}");
    }
    Ok(())
}

pub async fn build_image(cfg: &Config, req: &BuildImageRequest) -> Result<BuildImageResult> {
    let src = fetch_if_needed(cfg, &req.source).await?;
    if let Some(hash) = &req.sha256 {
        verify_sha256(&src, hash)?;
    }
    if let Some(parent) = req.output.parent() {
        fs::create_dir_all(parent)?;
    }

    convert_image(cfg, &src, &req.output, &req.format).await?;
    if let Some(size) = req.size_gib {
        if req.format == "raw" {
            let new_len = size
                .checked_mul(1024 * 1024 * 1024)
                .context("disk size overflow")?;
            let output = fs::OpenOptions::new().write(true).open(&req.output)?;
            if new_len < output.metadata()?.len() {
                bail!("requested disk size is smaller than the source image");
            }
            output.set_len(new_len)?;
        } else {
            run_checked(
                &cfg.qemu_img_binary,
                &[
                    "resize".into(),
                    req.output.display().to_string(),
                    format!("{}G", size),
                ],
            )
            .await?;
        }
    }

    if let Some(win) = &req.windows {
        validate_windows_vs_linux(req)?;
        if windows_needs_customize(win) {
            let image = req.output.clone();
            let win = win.clone();
            tokio::task::spawn_blocking(move || windows::customize_windows_blocking(&image, &win))
                .await
                .context("windows customize worker thread panicked")??;
        }
    } else {
        let needs_customize = !req.copy_in.is_empty()
            || !req.enable_services.is_empty()
            || req.hostname.is_some()
            || !req.packages.is_empty()
            || !req.commands.is_empty()
            || req.ssh_key.is_some();
        if needs_customize {
            customize_image(req.output.clone(), req.clone()).await?;
        }
    }
    Ok(BuildImageResult {
        output: req.output.clone(),
        format: req.format.clone(),
    })
}

fn windows_needs_customize(win: &WindowsCustomize) -> bool {
    win.hostname.is_some()
        || win.enable_rdp
        || win.enable_winrm
        || !win.firewall_open.is_empty()
        || !win.firewall_close.is_empty()
        || !win.scripts.is_empty()
        || !win.run_once.is_empty()
        || win.password.is_some()
        || win.agent.is_some()
}

fn validate_windows_vs_linux(req: &BuildImageRequest) -> Result<()> {
    let mut bad = Vec::new();
    if req.hostname.is_some() {
        bad.push("hostname (use windows.hostname)");
    }
    if !req.packages.is_empty() {
        bad.push("packages");
    }
    if !req.commands.is_empty() {
        bad.push("commands");
    }
    if !req.enable_services.is_empty() {
        bad.push("enable_services");
    }
    if req.ssh_key.is_some() {
        bad.push("ssh_key");
    }
    if !req.copy_in.is_empty() {
        bad.push("copy_in");
    }
    if !bad.is_empty() {
        bail!(
            "windows{{}} customize cannot be combined with Linux-only fields: {}",
            bad.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod windows_validate_tests {
    use super::*;
    use std::path::PathBuf;

    fn base_req() -> BuildImageRequest {
        BuildImageRequest {
            source: "/tmp/win.qcow2".into(),
            output: PathBuf::from("/tmp/out.qcow2"),
            format: "qcow2".into(),
            size_gib: None,
            sha256: None,
            hostname: None,
            packages: vec![],
            commands: vec![],
            ssh_key: None,
            copy_in: vec![],
            enable_services: vec![],
            windows: Some(WindowsCustomize {
                enable_rdp: true,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn rejects_mixed_linux_fields() {
        let mut req = base_req();
        req.packages = vec!["curl".into()];
        assert!(validate_windows_vs_linux(&req).is_err());
    }

    #[test]
    fn accepts_windows_only() {
        assert!(validate_windows_vs_linux(&base_req()).is_ok());
    }
}

/// Applies every customization field on `req` (`copy_in`, `enable_services`,
/// `hostname`, `packages`, `commands`, `ssh_key`) in one **guestkit** session
/// (`qemu-nbd` mount + chroot). Do **not** use libguestfs / virt-customize /
/// guestfish — FluxVM image work goes through guestkit only. `Guestfs`
/// methods are synchronous/blocking, so this runs on a blocking-pool thread
/// rather than stalling the async runtime for however long the mount+customize
/// takes.
///
/// **Known limitation**: `guestkit::Guestfs::command` chroots without
/// bind-mounting `/proc`, `/sys`, or `/dev` from the host first (unlike a
/// full booted guest). Simple packages install fine; a package whose
/// postinst script depends on `/proc` (common for kernel/systemd-adjacent
/// packages) can fail here. No workaround today beyond passing an equivalent
/// `commands` entry that bind-mounts what a specific package needs before
/// installing it.
async fn customize_image(image: PathBuf, req: BuildImageRequest) -> Result<()> {
    tokio::task::spawn_blocking(move || customize_image_blocking(&image, &req))
        .await
        .context("guestkit worker thread panicked")?
}

/// Orders fstab mountpoints shallowest-first (`/` before `/boot` before
/// `/boot/efi`) so each mount's target directory already exists under an
/// already-mounted parent by the time it's attempted. `HashMap` iteration
/// order is arbitrary, and mounting a nested mountpoint before its parent
/// is mounted read-write fails outright: found live against a stock
/// Ubuntu 24.04 image, where mounting `LABEL=UEFI` at `/boot/efi` before
/// `/` failed `mkdir`ing `/boot/efi` (never pre-created in that image)
/// against a root still mounted read-only from `inspect_get_mountpoints`'s
/// own fstab-reading probe.
fn depth_ordered_mounts(mounts: HashMap<String, String>) -> Vec<(String, String)> {
    let mut mounts: Vec<(String, String)> = mounts.into_iter().collect();
    mounts.sort_by_key(|(mountpoint, _)| mountpoint.split('/').filter(|c| !c.is_empty()).count());
    mounts
}

fn customize_image_blocking(image: &Path, req: &BuildImageRequest) -> Result<()> {
    use guestkit::Guestfs;

    let mut g = Guestfs::new().context("creating guestkit handle")?;
    g.add_drive(image)
        .with_context(|| format!("adding drive {}", image.display()))?;
    g.launch().context("launching guestfs")?;

    let roots = g.inspect_os().context("inspecting guest OS")?;
    let root = roots
        .first()
        .context("no operating system found in image")?
        .clone();
    let mounts = g
        .inspect_get_mountpoints(&root)
        .context("getting mountpoints")?;
    for (mountpoint, device) in &depth_ordered_mounts(mounts) {
        g.mount(device, mountpoint)
            .with_context(|| format!("mounting {device} at {mountpoint}"))?;
    }

    for file in &req.copy_in {
        let src = file
            .src
            .to_str()
            .context("copy_in src path is not valid UTF-8")?;
        g.upload(src, &file.dest)
            .with_context(|| format!("copying {} to {} in image", file.src.display(), file.dest))?;
    }

    if let Some(hostname) = &req.hostname {
        g.write("/etc/hostname", format!("{hostname}\n").as_bytes())
            .context("writing /etc/hostname")?;
    }

    if !req.packages.is_empty() {
        install_packages_with_dns(&mut g, &req.packages)?;
    }

    for cmd in &req.commands {
        g.sh_raw(cmd)
            .with_context(|| format!("running command: {cmd}"))?;
    }

    for service in &req.enable_services {
        g.command(&["systemctl", "enable", service])
            .with_context(|| format!("enabling {service}"))?;
    }

    if let Some(key) = &req.ssh_key {
        inject_ssh_key(&mut g, key)?;
    }

    let _ = g.umount_all();
    g.shutdown().context("shutting down guestfs")?;
    Ok(())
}

/// Installs `packages`, temporarily staging the host's `/etc/resolv.conf`
/// into the guest first. `guestkit`'s chroot exec (see [`install_packages`])
/// runs in the host's network namespace, but every package manager still
/// resolves hostnames using the *guest's own* `/etc/resolv.conf` — and on a
/// stock cloud image that's a symlink to `/run/systemd/resolve/...`, which
/// doesn't exist outside a running systemd instance. Without a real
/// `/etc/resolv.conf` in place, every fetch fails with "Temporary failure
/// resolving" (confirmed against a real Ubuntu 24.04 image) even though
/// networking itself works fine. The staged file is removed afterward
/// (restored, if the guest had a real, non-symlink one of its own) — cloud
/// images regenerate their own resolver config on first boot regardless.
fn install_packages_with_dns(g: &mut guestkit::Guestfs, packages: &[String]) -> Result<()> {
    let original = g.read_file("/etc/resolv.conf").ok();
    let host_resolv = fs::read("/etc/resolv.conf").context("reading host /etc/resolv.conf")?;
    // A stock cloud image's /etc/resolv.conf is typically a *dangling*
    // symlink (e.g. to /run/systemd/resolve/stub-resolv.conf, which doesn't
    // exist outside a running systemd instance). `Guestfs::rm`/`write`
    // resolve the guest path to a host path but then use plain `fs`
    // calls, which follow symlinks — for a dangling one that means ENOENT,
    // and for a non-dangling absolute-target one it would mean writing
    // through the raw target path on the *host*, escaping the mount
    // entirely. Removing it via a chroot `rm -f` first sidesteps both: the
    // chroot resolves the path against the guest root, not the host's.
    let _ = g.command(&["rm", "-f", "/etc/resolv.conf"]);
    g.write("/etc/resolv.conf", &host_resolv)
        .context("staging /etc/resolv.conf for package install")?;

    let result = install_packages(g, packages);

    let _ = g.command(&["rm", "-f", "/etc/resolv.conf"]);
    match &original {
        Some(bytes) => {
            let _ = g.write("/etc/resolv.conf", bytes);
        }
        None => {}
    }
    result
}

/// Installs `packages` via the guest's own package manager. The manager is
/// detected by actually exec'ing `command -v <tool>` inside the chroot
/// (`apt-get`/`tdnf`/`dnf`/`yum`/`pacman`, checked in that order) rather
/// than via `guestkit`'s `inspect_get_package_management`, whose
/// presence-check constructs `<root>/usr/bin/<tool>` from the abstract
/// device-rooted `root` identifier `inspect_os` returns — that string isn't
/// a real filesystem path, so the check always misses even when the binary
/// is genuinely installed (confirmed against a real Ubuntu 24.04 image,
/// which has `/usr/bin/apt` but was reported as `dpkg`). Exec'ing inside
/// the chroot sidesteps that bug entirely.
fn install_packages(g: &mut guestkit::Guestfs, packages: &[String]) -> Result<()> {
    let pkgs: Vec<&str> = packages.iter().map(String::as_str).collect();
    let tool = ["apt-get", "tdnf", "dnf", "yum", "pacman"]
        .into_iter()
        .find(|tool| {
            g.command(&["sh", "-c", &format!("command -v {tool}")])
                .map(|out| !out.trim().is_empty())
                .unwrap_or(false)
        });
    match tool {
        Some("apt-get") => {
            g.command(&["apt-get", "update"])
                .context("apt-get update")?;
            let mut args = vec!["apt-get", "install", "-y"];
            args.extend(pkgs);
            g.command(&args).context("apt-get install")?;
        }
        Some(t @ ("tdnf" | "dnf" | "yum")) => {
            let mut args = vec![t, "install", "-y"];
            args.extend(pkgs);
            g.command(&args).context("package install")?;
        }
        Some("pacman") => {
            // A fresh Arch image ships with an empty pacman keyring, so
            // every install fails signature verification until it's
            // initialized — real, standard Arch chroot bootstrapping, not
            // specific to this bare chroot (confirmed against a real Arch
            // Linux cloud image).
            g.command(&["pacman-key", "--init"])
                .context("pacman-key --init")?;
            g.command(&["pacman-key", "--populate", "archlinux"])
                .context("pacman-key --populate")?;
            let mut args = vec!["pacman", "-Sy", "--noconfirm"];
            args.extend(pkgs);
            let result = with_staged_mtab(g, |g| {
                g.command(&args).context("pacman install").map(|_| ())
            });
            // pacman-key/pacman spawn a gpg-agent that double-forks and
            // detaches, inheriting the chroot's root directory — guestkit's
            // chroot exec only waits on the direct child, so the detached
            // agent leaks with open files under the mount, which blocks
            // the unmount at the end of customize_image_blocking. There's
            // no PID namespace isolation (chroot doesn't create one), so
            // it's a real, host-visible process — reap it with a host-side
            // `pkill`, not `g.command`: a `pkill` run *inside* the chroot
            // needs `/proc` to enumerate processes, which this bare chroot
            // doesn't have (the same limitation noted on
            // `customize_image_blocking`), so it would silently match
            // nothing. Pattern is scoped to pacman-key's specific homedir
            // to avoid touching an unrelated gpg-agent on the host.
            let _ = std::process::Command::new("pkill")
                .args(["-9", "-f", "gpg-agent --homedir /etc/pacman.d/gnupg"])
                .status();
            result?;
        }
        _ => bail!(
            "cannot install packages: no supported package manager found in the guest \
             (checked apt-get/tdnf/dnf/yum/pacman) — install them via an equivalent \
             `commands` entry instead"
        ),
    }
    Ok(())
}

/// Runs `f` with a synthetic `/etc/mtab` in place, restoring/removing it
/// afterward. `pacman` refuses to run at all without a readable
/// `/etc/mtab` (it parses it to work out which filesystem the install
/// target lives on) — on a real Arch system that's a symlink to
/// `/proc/self/mounts`, which this bare chroot doesn't have (no `/proc`
/// bind-mount, the same limitation noted on [`customize_image_blocking`]).
/// A single plausible-looking `rw` entry is enough to satisfy the parse;
/// pacman doesn't need it to reflect the real mount table. Confirmed
/// necessary against a real Arch Linux cloud image (`apt-get`/`dnf` never
/// needed this, so it's scoped to the pacman path only).
fn with_staged_mtab(
    g: &mut guestkit::Guestfs,
    f: impl FnOnce(&mut guestkit::Guestfs) -> Result<()>,
) -> Result<()> {
    let original = g.read_file("/etc/mtab").ok();
    let _ = g.command(&["rm", "-f", "/etc/mtab"]);
    g.write("/etc/mtab", b"rootfs / rootfs rw 0 0\n")
        .context("staging /etc/mtab for pacman")?;

    let result = f(g);

    let _ = g.command(&["rm", "-f", "/etc/mtab"]);
    if let Some(bytes) = &original {
        let _ = g.write("/etc/mtab", bytes);
    }
    result
}

/// Authorizes `key` for root login by appending it to
/// `/root/.ssh/authorized_keys`, creating the file/directory if needed.
/// Inject an SSH public key into the guest's `authorized_keys` via guestkit.
fn inject_ssh_key(g: &mut guestkit::Guestfs, key: &str) -> Result<()> {
    g.command(&["mkdir", "-p", "/root/.ssh"])
        .context("creating /root/.ssh")?;
    g.command(&["chmod", "700", "/root/.ssh"])
        .context("chmod /root/.ssh")?;
    let mut content = g
        .command(&["cat", "/root/.ssh/authorized_keys"])
        .unwrap_or_default();
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(key.trim());
    content.push('\n');
    g.write("/root/.ssh/authorized_keys", content.as_bytes())
        .context("writing authorized_keys")?;
    g.command(&["chmod", "600", "/root/.ssh/authorized_keys"])
        .context("chmod authorized_keys")?;
    Ok(())
}

/// Writes `token` to [`fluxvm_guest_protocol::TOKEN_FILE_PATH`] inside
/// `disk` (an instance's own already-cloned disk — a qcow2 CoW overlay for
/// QEMU, or a full raw clone for Cloud Hypervisor/Firecracker; either way,
/// this never touches the shared base image). Runs before the VM's first
/// boot, so `fluxvm-guest-agent`'s systemd unit sees the token file
/// already in place when it starts. Mode 0600 root-owned — same posture as
/// an SSH host key, since anything able to read it inside the guest could
/// impersonate an authenticated caller.
pub async fn inject_guest_agent_token(disk: &Path, token: &str) -> Result<()> {
    let disk = disk.to_path_buf();
    let token = token.to_string();
    tokio::task::spawn_blocking(move || inject_guest_agent_token_blocking(&disk, &token))
        .await
        .context("guestkit worker thread panicked")?
}

fn inject_guest_agent_token_blocking(disk: &Path, token: &str) -> Result<()> {
    use fluxvm_guest_protocol::TOKEN_FILE_PATH;
    use guestkit::Guestfs;

    let mut g = Guestfs::new().context("creating guestkit handle")?;
    if std::env::var("GUESTKIT_DEBUG").is_ok() {
        g.set_debug(true);
        g.set_trace(true);
    }
    g.add_drive(disk)
        .with_context(|| format!("adding drive {}", disk.display()))?;
    g.launch().context("launching guestfs")?;

    let roots = g.inspect_os().context("inspecting guest OS")?;
    let root = roots
        .first()
        .context("no operating system found in image")?;
    let mounts = g
        .inspect_get_mountpoints(root)
        .context("getting mountpoints")?;
    for (mountpoint, device) in &depth_ordered_mounts(mounts) {
        g.mount(device, mountpoint)
            .with_context(|| format!("mounting {device} at {mountpoint}"))?;
    }

    g.write(TOKEN_FILE_PATH, token.as_bytes())
        .with_context(|| format!("writing {TOKEN_FILE_PATH}"))?;
    g.chmod(0o600, TOKEN_FILE_PATH)
        .context("chmod guest-agent token file")?;
    // Fedora/RHEL enforcing guests reject unlabeled files; restorecon so the
    // guest-agent can read the token and bind AF_VSOCK under SELinux.
    let _ = g.command(&[
        "bash",
        "-c",
        &format!(
            "restorecon -F {TOKEN_FILE_PATH} 2>/dev/null || chcon -t etc_t {TOKEN_FILE_PATH} 2>/dev/null || true"
        ),
    ]);

    let _ = g.umount_all();
    g.shutdown().context("shutting down guestfs")?;
    Ok(())
}

async fn image_format(cfg: &Config, image: &Path) -> Result<String> {
    let mut file =
        fs::File::open(image).with_context(|| format!("opening base image {}", image.display()))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .with_context(|| format!("reading base image {}", image.display()))?;
    if magic == *b"QFI\xfb" {
        return Ok("qcow2".into());
    }
    if magic == *b"KDMV" {
        return Ok("vmdk".into());
    }
    if magic == *b"vhdx" {
        return Ok("vhdx".into());
    }
    let len = file.metadata()?.len();
    if len >= 512 {
        file.seek(SeekFrom::End(-512))?;
        let mut footer = [0u8; 8];
        file.read_exact(&mut footer)?;
        if footer == *b"conectix" {
            return Ok("vpc".into());
        }
    }
    if vmdk_descriptor::is_descriptor(image)? {
        return Ok("vmdk".into());
    }
    // A named raw image can be cloned without installing any QEMU binary.
    // For ambiguous extensions, ask qemu-img instead of silently treating
    // VMDK/VHDX/other formats as raw sectors.
    if matches!(
        image.extension().and_then(|s| s.to_str()),
        Some("raw" | "ext4")
    ) {
        return Ok("raw".into());
    }
    let output = fluxvm_core::process::output_checked(
        &cfg.qemu_img_binary,
        &[
            "info".into(),
            "--output=json".into(),
            image.display().to_string(),
        ],
    )
    .await
    .with_context(|| {
        format!(
            "detecting format of {} (use .raw for a known raw image without qemu-img)",
            image.display()
        )
    })?;
    let parsed: serde_json::Value = serde_json::from_str(&output)?;
    parsed["format"]
        .as_str()
        .map(str::to_owned)
        .context("qemu-img info did not return an image format")
}

/// Import the common uncompressed sparse VMDK layout without a QEMU process.
/// Complex VMDK variants retain qemu-img compatibility until native readers exist.
async fn convert_image(cfg: &Config, src: &Path, out: &Path, format: &str) -> Result<()> {
    if format == "raw" && (vmdk::is_sparse_vmdk(src)? || vmdk_descriptor::is_descriptor(src)?) {
        let source = src.to_owned();
        let target = out.to_owned();
        let result = tokio::task::spawn_blocking(move || {
            if vmdk::is_sparse_vmdk(&source)? {
                vmdk::convert_sparse_to_raw(&source, &target)
            } else {
                vmdk_descriptor::convert_descriptor_to_raw(&source, &target)
            }
        })
        .await
        .context("VMDK conversion worker panicked")?;
        match result {
            Ok(vmdk::ConvertResult::Converted) => return Ok(()),
            Ok(vmdk::ConvertResult::Unsupported) => {}
            Err(err) => return Err(err),
        }
    }
    run_checked(
        &cfg.qemu_img_binary,
        &[
            "convert".into(),
            "-O".into(),
            format.into(),
            src.display().to_string(),
            out.display().to_string(),
        ],
    )
    .await
}

pub async fn clone_for_vm(
    cfg: &Config,
    base: &Path,
    backend: BackendKind,
    out: &Path,
    size_gib: Option<u64>,
) -> Result<()> {
    if backend == BackendKind::FluxVm
        && cfg.fluxvm_engine == fluxvm_core::config::FluxVmEngine::Kvm
        && !matches!(
            base.extension().and_then(|e| e.to_str()),
            Some("raw" | "ext4")
        )
    {
        bail!(
            "native KVM accepts only named .raw or .ext4 images; convert {} to raw before launch",
            base.display()
        );
    }
    let base_fmt = if backend == BackendKind::Vz {
        apple_image_format(base)?
    } else {
        image_format(cfg, base).await?
    };
    if backend == BackendKind::FluxVm
        && cfg.fluxvm_engine == fluxvm_core::config::FluxVmEngine::Kvm
        && base_fmt != "raw"
    {
        bail!(
            "native KVM requires a raw image, but {} contains {base_fmt} data",
            base.display()
        );
    }
    match backend {
        BackendKind::Qemu => {
            // Cheap disposable copy-on-write layer.
            run_checked(
                &cfg.qemu_img_binary,
                &[
                    "create".into(),
                    "-f".into(),
                    "qcow2".into(),
                    "-F".into(),
                    base_fmt,
                    "-b".into(),
                    base.canonicalize()?.display().to_string(),
                    out.display().to_string(),
                ],
            )
            .await?;
        }
        BackendKind::CloudHypervisor | BackendKind::Firecracker | BackendKind::FluxVm => {
            // Firecracker / FluxVm expect a raw block image. Cloud Hypervisor is also kept raw here
            // for a predictable common fast path. Reflink makes raw clones nearly instant on
            // XFS/Btrfs; cp transparently falls back when reflinks are unavailable.
            if base_fmt == "raw" {
                run_checked(
                    "cp",
                    &[
                        "--reflink=auto".into(),
                        "--sparse=always".into(),
                        base.display().to_string(),
                        out.display().to_string(),
                    ],
                )
                .await?;
            } else {
                convert_image(cfg, base, out, "raw").await?;
            }
        }
        BackendKind::Vz if base_fmt == "qcow2" => convert_image(cfg, base, out, "raw")
            .await
            .with_context(|| {
                format!(
                    "converting {} from qcow2 for the vz backend (needs qemu-img: `brew install qemu`)",
                    base.display()
                )
            })?,
        BackendKind::Vz => clone_raw_for_apple(base, out).await?,
        BackendKind::Auto => bail!(
            "VM has an unresolved BackendKind::Auto — this is a bug, backend selection must happen before cloning its disk"
        ),
    }
    if let Some(size) = size_gib {
        let new_len = size
            .checked_mul(1024 * 1024 * 1024)
            .context("disk size overflow")?;
        if backend != BackendKind::Qemu {
            let file = fs::OpenOptions::new().write(true).open(out)?;
            if new_len < file.metadata()?.len() {
                bail!("requested disk size is smaller than the source image");
            }
            file.set_len(new_len)?;
        } else {
            run_checked(
                &cfg.qemu_img_binary,
                &[
                    "resize".into(),
                    out.display().to_string(),
                    format!("{}G", size),
                ],
            )
            .await?;
        }
    }
    Ok(())
}

/// Virtualization.framework boots raw disk images only. macOS has no `qemu-img` by default, so the format is decided
/// from the file header: qcow2 is converted to raw (with `qemu-img`) while cloning, anything else is taken as raw.
fn apple_image_format(base: &Path) -> Result<String> {
    use std::io::Read;
    let mut magic = [0u8; 4];
    let mut f =
        std::fs::File::open(base).with_context(|| format!("opening image {}", base.display()))?;
    if f.read_exact(&mut magic).is_ok() && &magic == b"QFI\xfb" {
        return Ok("qcow2".into());
    }
    Ok("raw".into())
}

/// Instant copy-on-write clone on APFS (`cp -c`), with a plain sparse copy as the fallback elsewhere.
async fn clone_raw_for_apple(base: &Path, out: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let clone = run_checked(
            "cp",
            &[
                "-c".into(),
                base.display().to_string(),
                out.display().to_string(),
            ],
        )
        .await;
        if clone.is_ok() {
            return Ok(());
        }
        run_checked(
            "cp",
            &[base.display().to_string(), out.display().to_string()],
        )
        .await?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        run_checked(
            "cp",
            &[
                "--reflink=auto".into(),
                "--sparse=always".into(),
                base.display().to_string(),
                out.display().to_string(),
            ],
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod qemu_free_raw_tests {
    use super::*;

    #[tokio::test]
    async fn clones_named_raw_image_without_qemu_img() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.raw");
        let dest = dir.path().join("vm.raw");
        fs::write(&base, vec![0x5a; 4096]).unwrap();
        let cfg = Config {
            qemu_img_binary: "/definitely/missing/qemu-img".into(),
            ..Config::default()
        };
        clone_for_vm(&cfg, &base, BackendKind::FluxVm, &dest, None)
            .await
            .unwrap();
        assert_eq!(fs::read(dest).unwrap(), fs::read(base).unwrap());
    }

    #[tokio::test]
    async fn vz_qcow2_without_qemu_img_explains_how_to_get_it() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("disk.img");
        fs::write(&base, b"QFI\xfbpadding").unwrap();
        let cfg = Config {
            qemu_img_binary: "/definitely/missing/qemu-img".into(),
            ..Config::default()
        };
        let err = clone_for_vm(
            &cfg,
            &base,
            BackendKind::Vz,
            &dir.path().join("vm.raw"),
            None,
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("brew install qemu"), "{err:#}");
    }

    #[tokio::test]
    async fn vz_raw_image_clones_without_qemu_img() {
        let dir = tempfile::tempdir().unwrap();
        let (base, dest) = (dir.path().join("base.raw"), dir.path().join("vm.raw"));
        fs::write(&base, vec![7u8; 4096]).unwrap();
        let cfg = Config {
            qemu_img_binary: "/definitely/missing/qemu-img".into(),
            ..Config::default()
        };
        clone_for_vm(&cfg, &base, BackendKind::Vz, &dest, None)
            .await
            .unwrap();
        assert_eq!(fs::read(dest).unwrap(), fs::read(base).unwrap());
    }

    #[tokio::test]
    async fn qcow2_header_takes_precedence_over_raw_extension() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("misnamed.raw");
        fs::write(&base, b"QFI\xfbpadding").unwrap();
        assert_eq!(
            image_format(&Config::default(), &base).await.unwrap(),
            "qcow2"
        );
    }

    #[tokio::test]
    async fn vmdk_header_takes_precedence_over_raw_extension() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("misnamed.raw");
        fs::write(&base, b"KDMVpadding").unwrap();
        assert_eq!(
            image_format(&Config::default(), &base).await.unwrap(),
            "vmdk"
        );
    }

    #[tokio::test]
    async fn vhd_footer_takes_precedence_over_raw_extension() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("misnamed.raw");
        let mut bytes = vec![0u8; 1024];
        bytes[512..520].copy_from_slice(b"conectix");
        fs::write(&base, bytes).unwrap();
        assert_eq!(
            image_format(&Config::default(), &base).await.unwrap(),
            "vpc"
        );
    }

    #[tokio::test]
    async fn native_kvm_rejects_misnamed_vmdk_without_qemu_img() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("vmdk-disguised.raw");
        fs::write(&base, b"KDMVpayload").unwrap();
        let cfg = Config {
            qemu_img_binary: "/definitely/missing/qemu-img".into(),
            fluxvm_engine: fluxvm_core::config::FluxVmEngine::Kvm,
            ..Config::default()
        };
        let err = clone_for_vm(
            &cfg,
            &base,
            BackendKind::FluxVm,
            &dir.path().join("out.raw"),
            None,
        )
        .await
        .unwrap_err();
        assert!(format!("{err:#}").contains("vmdk"));
    }
}
