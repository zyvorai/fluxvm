// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Well-known cloud images that can be requested by name (`"image": "debian-13"`) without a catalog.
//!
//! Each image is downloaded over HTTPS, checked against the vendor's published checksum file, and cached under
//! `state_dir/images`. Images the vendor ships as qcow2 are converted to raw once, so every VM clone is an instant
//! APFS copy. Names resolve only when no file of that name exists, and they never count as catalog images, so
//! `policy.require_catalog_names` still rejects them.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::Config;
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs,
    path::{Path, PathBuf},
};
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sum {
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy)]
pub struct BuiltinImage {
    pub name: &'static str,
    base_url: &'static str,
    /// The file in `base_url`; one `*` matches a version that changes between releases (the highest listed wins).
    file: &'static str,
    sums_file: &'static str,
    sum: Sum,
    /// How the downloaded file becomes a raw disk.
    kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// qcow2, converted once with `qemu-img`.
    Qcow2,
    /// A tarball holding `disk.raw` (Debian's cloud images; about a tenth of the raw download).
    TarDiskRaw,
}

/// ARM64 images, the only guests Virtualization.framework runs on Apple silicon.
pub const BUILTIN_IMAGES: &[BuiltinImage] = &[
    BuiltinImage {
        name: "debian-13",
        base_url: "https://cloud.debian.org/images/cloud/trixie/latest",
        file: "debian-13-generic-arm64.tar.xz",
        sums_file: "SHA512SUMS",
        sum: Sum::Sha512,
        kind: Kind::TarDiskRaw,
    },
    BuiltinImage {
        name: "debian-12",
        base_url: "https://cloud.debian.org/images/cloud/bookworm/latest",
        file: "debian-12-generic-arm64.tar.xz",
        sums_file: "SHA512SUMS",
        sum: Sum::Sha512,
        kind: Kind::TarDiskRaw,
    },
    BuiltinImage {
        name: "ubuntu-24.04",
        base_url: "https://cloud-images.ubuntu.com/releases/24.04/release",
        file: "ubuntu-24.04-server-cloudimg-arm64.img",
        sums_file: "SHA256SUMS",
        sum: Sum::Sha256,
        kind: Kind::Qcow2,
    },
    BuiltinImage {
        name: "ubuntu-26.04",
        base_url: "https://cloud-images.ubuntu.com/releases/26.04/release",
        file: "ubuntu-26.04-server-cloudimg-arm64.img",
        sums_file: "SHA256SUMS",
        sum: Sum::Sha256,
        kind: Kind::Qcow2,
    },
    BuiltinImage {
        name: "fedora-44",
        base_url: "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/aarch64/images",
        file: "Fedora-Cloud-Base-Generic-44-*.aarch64.qcow2",
        sums_file: "Fedora-Cloud-44-1.7-aarch64-CHECKSUM",
        sum: Sum::Sha256,
        kind: Kind::Qcow2,
    },
    BuiltinImage {
        name: "centos-stream-10",
        base_url: "https://cloud.centos.org/centos/10-stream/aarch64/images",
        file: "CentOS-Stream-GenericCloud-10-latest.aarch64.qcow2",
        sums_file: "CentOS-Stream-GenericCloud-10-latest.aarch64.qcow2.SHA256SUM",
        sum: Sum::Sha256,
        kind: Kind::Qcow2,
    },
    BuiltinImage {
        name: "almalinux-10",
        base_url: "https://repo.almalinux.org/almalinux/10/cloud/aarch64/images",
        file: "AlmaLinux-10-GenericCloud-latest.aarch64.qcow2",
        sums_file: "CHECKSUM",
        sum: Sum::Sha256,
        kind: Kind::Qcow2,
    },
    BuiltinImage {
        name: "rocky-10",
        base_url: "https://download.rockylinux.org/pub/rocky/10/images/aarch64",
        file: "Rocky-10-GenericCloud-Base.latest.aarch64.qcow2",
        sums_file: "CHECKSUM",
        sum: Sum::Sha256,
        kind: Kind::Qcow2,
    },
    BuiltinImage {
        name: "kali",
        base_url: "https://kali.download/cloud-images/current",
        file: "kali-linux-*-cloud-genericcloud-arm64.tar.xz",
        sums_file: "SHA256SUMS",
        sum: Sum::Sha256,
        kind: Kind::TarDiskRaw,
    },
];

pub fn find(name: &str) -> Option<&'static BuiltinImage> {
    BUILTIN_IMAGES.iter().find(|i| i.name == name)
}

/// `name` matches `pattern`, where one `*` stands for any run of characters.
fn matches(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        Some((pre, post)) => {
            name.len() >= pre.len() + post.len() && name.starts_with(pre) && name.ends_with(post)
        }
        None => name == pattern,
    }
}

/// The file matching `pattern` and its checksum in a listing, in either `sha*sum` style (`<hex>  <file>`,
/// `<hex> *<file>`) or BSD style (`SHA256 (<file>) = <hex>`); comment and signature lines are skipped. With
/// several matches the highest version wins.
fn checksum_for(listing: &str, pattern: &str) -> Option<(String, String)> {
    listing
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let (name, sum) = if let Some(rest) = l
                .strip_prefix("SHA256 (")
                .or_else(|| l.strip_prefix("SHA512 ("))
            {
                let (name, sum) = rest.split_once(") = ")?;
                (name, sum)
            } else {
                let (sum, name) = l.split_once(char::is_whitespace)?;
                (name.trim().trim_start_matches('*'), sum)
            };
            (sum.len() >= 64
                && sum.bytes().all(|b| b.is_ascii_hexdigit())
                && matches(pattern, name))
            .then(|| (name.to_owned(), sum.to_ascii_lowercase()))
        })
        .max_by(|a, b| version_cmp(&a.0, &b.0))
}

/// Compares names with runs of digits taken as numbers, so `2026.10` sorts after `2026.9`.
fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    fn parts(s: &str) -> Vec<Result<u64, String>> {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut digits = false;
        for c in s.chars() {
            if !cur.is_empty() && c.is_ascii_digit() != digits {
                out.push(if digits {
                    Ok(cur.parse().unwrap_or(u64::MAX))
                } else {
                    Err(std::mem::take(&mut cur))
                });
                cur.clear();
            }
            digits = c.is_ascii_digit();
            cur.push(c);
        }
        if !cur.is_empty() {
            out.push(if digits {
                Ok(cur.parse().unwrap_or(u64::MAX))
            } else {
                Err(cur)
            });
        }
        out
    }
    parts(a).cmp(&parts(b))
}

/// How long a successful look at the vendor's checksum list is trusted before it is fetched again.
const FRESH_FOR: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `<name>.latest` holds `<unix seconds> <checksum>` from the last successful look at the vendor's list.
fn read_latest(dir: &Path, name: &str) -> Option<(u64, String)> {
    let text = fs::read_to_string(dir.join(format!("{name}.latest"))).ok()?;
    let (at, sum) = text.trim().split_once(' ')?;
    Some((at.parse().ok()?, sum.to_owned()))
}

fn raw_path(dir: &Path, name: &str, sum: &str) -> PathBuf {
    dir.join(format!("{name}-{}.raw", &sum[..12.min(sum.len())]))
}

/// The newest ready image already on disk for `name`, for when the vendor cannot be reached.
fn newest_cached(dir: &Path, name: &str) -> Option<PathBuf> {
    let prefix = format!("{name}-");
    fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter(|e| {
            let f = e.file_name().to_string_lossy().into_owned();
            f.starts_with(&prefix) && f.ends_with(".raw")
        })
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
        .map(|e| e.path())
}

/// Identifies the image `name` currently resolves to (the start of the vendor's checksum), without touching the network:
/// `None` when it was never downloaded. It changes when the vendor publishes a new build and `ensure` has noticed.
pub fn current_id(cfg: &Config, name: &str) -> Option<String> {
    let dir = cfg.state_dir.join("images");
    let (_, sum) = read_latest(&dir, name)?;
    raw_path(&dir, name, &sum)
        .exists()
        .then(|| sum[..12.min(sum.len())].to_owned())
}

/// Local path of the ready-to-clone raw image for `name`, downloading and converting it on first use.
///
/// A cached image is used without any network access for a day after the vendor's list was last checked, and
/// whenever the vendor cannot be reached, so creating a VM never waits on a slow or missing connection.
pub async fn ensure(cfg: &Config, img: &BuiltinImage) -> Result<PathBuf> {
    let dir = cfg.state_dir.join("images");
    fs::create_dir_all(&dir)?;
    if let Some((at, sum)) = read_latest(&dir, img.name) {
        let raw = raw_path(&dir, img.name, &sum);
        if raw.exists() && now_secs().saturating_sub(at) < FRESH_FOR.as_secs() {
            return Ok(raw);
        }
    }
    let client = reqwest::Client::builder()
        .user_agent(concat!("fluxvm/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(8))
        .build()?;
    let listing = async {
        client
            .get(format!("{}/{}", img.base_url, img.sums_file))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .and_then(|r| r.error_for_status())?
            .text()
            .await
    }
    .await;
    let listing = match listing {
        Ok(l) => l,
        Err(e) => {
            return match newest_cached(&dir, img.name) {
                Some(raw) => {
                    tracing::warn!(image = img.name, error = %e, "cannot reach the image vendor; using the cached image");
                    Ok(raw)
                }
                None => {
                    Err(e).with_context(|| format!("fetching the checksum list for {}", img.name))
                }
            };
        }
    };
    let (file, want) = checksum_for(&listing, img.file)
        .with_context(|| format!("{} is not listed in {}", img.file, img.sums_file))?;

    // The hash is in the name, so a new upstream "latest" is fetched instead of silently reusing a stale copy.
    let raw = raw_path(&dir, img.name, &want);
    let tag = &want[..12.min(want.len())];
    if raw.exists() {
        let _ = fs::write(
            dir.join(format!("{}.latest", img.name)),
            format!("{} {want}", now_secs()),
        );
        return Ok(raw);
    }
    let download = dir.join(format!("{}-{tag}.download", img.name));
    if !download.exists() {
        fetch_verified(&client, img, &file, &want, &download).await?;
    }
    // Build beside the final name, then rename, so an interrupted step is never mistaken for an image.
    let part = dir.join(format!("{}-{tag}.raw.part", img.name));
    let _ = fs::remove_file(&part);
    match img.kind {
        Kind::Qcow2 => crate::convert_image(cfg, &download, &part, "raw")
            .await
            .with_context(|| {
                format!(
                    "converting {} to raw (needs qemu-img: `brew install qemu`)",
                    img.name
                )
            })?,
        Kind::TarDiskRaw => extract_disk_raw(&download, &part)
            .await
            .with_context(|| format!("unpacking {file}"))?,
    }
    fs::rename(&part, &raw)?;
    let _ = fs::remove_file(&download);
    let _ = fs::write(
        dir.join(format!("{}.latest", img.name)),
        format!("{} {want}", now_secs()),
    );
    Ok(raw)
}

/// Unpacks `disk.raw` from the tarball with the system `tar` (bsdtar on macOS reads xz). All-zero blocks are
/// skipped rather than written, so the image stays sparse even when the tarball stores its zeros (Kali's does).
async fn extract_disk_raw(archive: &Path, out: &Path) -> Result<()> {
    use std::os::unix::fs::FileExt;
    use tokio::io::AsyncReadExt;
    const BLOCK: usize = 1 << 20;
    let file = fs::File::create(out)?;
    let mut child = tokio::process::Command::new("tar")
        .args(["-xOf"])
        .arg(archive)
        .arg("disk.raw")
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("running tar")?;
    let mut stdout = child.stdout.take().context("tar stdout")?;
    let mut buf = vec![0u8; BLOCK];
    let mut offset = 0u64;
    loop {
        let mut filled = 0;
        while filled < BLOCK {
            let n = stdout.read(&mut buf[filled..]).await?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        if buf[..filled].iter().any(|&b| b != 0) {
            file.write_all_at(&buf[..filled], offset)?;
        }
        offset += filled as u64;
    }
    file.set_len(offset)?;
    if !child.wait().await.context("running tar")?.success() {
        bail!("tar could not extract disk.raw from {}", archive.display());
    }
    Ok(())
}

async fn fetch_verified(
    client: &reqwest::Client,
    img: &BuiltinImage,
    file: &str,
    want: &str,
    dest: &Path,
) -> Result<()> {
    let part = dest.with_extension("download.part");
    let mut resp = client
        .get(format!("{}/{file}", img.base_url))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("downloading {file}"))?;
    let mut out = tokio::fs::File::create(&part).await?;
    let (mut h256, mut h512) = (Sha256::new(), Sha512::new());
    while let Some(chunk) = resp.chunk().await? {
        match img.sum {
            Sum::Sha256 => h256.update(&chunk),
            Sum::Sha512 => h512.update(&chunk),
        }
        out.write_all(&chunk).await?;
    }
    out.flush().await?;
    let got = match img.sum {
        Sum::Sha256 => format!("{:x}", h256.finalize()),
        Sum::Sha512 => format!("{:x}", h512.finalize()),
    };
    if got != want {
        let _ = fs::remove_file(&part);
        bail!("{file} failed checksum verification (expected {want}, got {got})");
    }
    fs::rename(&part, dest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_checksum_in_every_listing_style() {
        let (a, b, c) = ("A".repeat(64), "B".repeat(64), "C".repeat(64));
        let l = format!("{a}  other.raw\n{b} *wanted.img\n{c}  wanted.img.sig\n");
        let get = |l: &str, p: &str| checksum_for(l, p).map(|(f, s)| format!("{f}={}", &s[..2]));
        assert_eq!(get(&l, "wanted.img").as_deref(), Some("wanted.img=bb"));
        assert_eq!(get(&l, "other.raw").as_deref(), Some("other.raw=aa"));
        assert_eq!(get(&l, "missing"), None);
        let bsd = format!(
            "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n# F-44-1.7.aarch64.qcow2: 5 bytes\nSHA256 (F-UKI-44-1.7.aarch64.qcow2) = {a}\nSHA256 (F-44-1.7.aarch64.qcow2) = {b}\n"
        );
        assert_eq!(
            get(&bsd, "F-44-*.aarch64.qcow2").as_deref(),
            Some("F-44-1.7.aarch64.qcow2=bb")
        );
    }

    #[test]
    fn a_pattern_picks_the_highest_version() {
        let (a, b, c) = ("A".repeat(64), "B".repeat(64), "C".repeat(64));
        let l = format!(
            "{a}  kali-2026.9-arm64.tar.xz\n{b}  kali-2026.10-arm64.tar.xz\n{c}  kali-2026.10-amd64.tar.xz\n"
        );
        assert_eq!(
            checksum_for(&l, "kali-*-arm64.tar.xz")
                .map(|(f, _)| f)
                .as_deref(),
            Some("kali-2026.10-arm64.tar.xz")
        );
        assert!(!matches("a*b", "ab".get(..1).unwrap()));
        assert!(matches("a*b", "ab"));
    }

    #[test]
    fn a_cached_image_is_found_without_the_network() {
        let dir = tempfile::tempdir().unwrap();
        assert!(newest_cached(dir.path(), "debian-13").is_none());
        fs::write(dir.path().join("debian-13-aaaaaaaaaaaa.raw"), b"x").unwrap();
        fs::write(dir.path().join("debian-12-bbbbbbbbbbbb.raw"), b"x").unwrap();
        fs::write(dir.path().join("debian-13-cccccccccccc.raw.part"), b"x").unwrap();
        assert_eq!(
            newest_cached(dir.path(), "debian-13").unwrap(),
            dir.path().join("debian-13-aaaaaaaaaaaa.raw")
        );
        fs::write(
            dir.path().join("debian-13.latest"),
            format!("{} aaaaaaaaaaaa1234", now_secs()),
        )
        .unwrap();
        let (at, sum) = read_latest(dir.path(), "debian-13").unwrap();
        assert!(now_secs() - at < 5);
        assert_eq!(
            raw_path(dir.path(), "debian-13", &sum),
            dir.path().join("debian-13-aaaaaaaaaaaa.raw")
        );
    }

    #[test]
    fn known_names_resolve() {
        assert!(find("debian-13").is_some());
        assert!(find("ubuntu-24.04").is_some_and(|i| i.kind == Kind::Qcow2));
        for name in [
            "ubuntu-26.04",
            "fedora-44",
            "centos-stream-10",
            "almalinux-10",
            "rocky-10",
            "kali",
        ] {
            assert!(find(name).is_some(), "{name}");
        }
        assert!(find("windows-11").is_none());
    }
}
