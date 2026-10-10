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
];

pub fn find(name: &str) -> Option<&'static BuiltinImage> {
    BUILTIN_IMAGES.iter().find(|i| i.name == name)
}

/// The checksum recorded for `file` in a `sha*sum`-style listing (`<hex>  <file>` or `<hex> *<file>`).
fn checksum_for(listing: &str, file: &str) -> Option<String> {
    listing.lines().find_map(|l| {
        let (sum, name) = l.split_once(char::is_whitespace)?;
        (name.trim().trim_start_matches('*') == file).then(|| sum.to_ascii_lowercase())
    })
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
    let want = checksum_for(&listing, img.file)
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
        fetch_verified(&client, img, &want, &download).await?;
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
            .with_context(|| format!("unpacking {}", img.file))?,
    }
    fs::rename(&part, &raw)?;
    let _ = fs::remove_file(&download);
    let _ = fs::write(
        dir.join(format!("{}.latest", img.name)),
        format!("{} {want}", now_secs()),
    );
    Ok(raw)
}

/// Unpacks `disk.raw` from the tarball with the system `tar` (bsdtar on macOS reads xz).
async fn extract_disk_raw(archive: &Path, out: &Path) -> Result<()> {
    let file = fs::File::create(out)?;
    let status = tokio::process::Command::new("tar")
        .args(["-xOf"])
        .arg(archive)
        .arg("disk.raw")
        .stdout(file)
        .status()
        .await
        .context("running tar")?;
    if !status.success() {
        bail!("tar could not extract disk.raw from {}", archive.display());
    }
    Ok(())
}

async fn fetch_verified(
    client: &reqwest::Client,
    img: &BuiltinImage,
    want: &str,
    dest: &Path,
) -> Result<()> {
    let part = dest.with_extension("download.part");
    let mut resp = client
        .get(format!("{}/{}", img.base_url, img.file))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("downloading {}", img.file))?;
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
        bail!(
            "{} failed checksum verification (expected {want}, got {got})",
            img.file
        );
    }
    fs::rename(&part, dest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_checksum_in_both_listing_styles() {
        let l = "AAAA11  other.raw\nBBBB22 *wanted.img\nCCCC33  wanted.img.sig\n";
        assert_eq!(checksum_for(l, "wanted.img").as_deref(), Some("bbbb22"));
        assert_eq!(checksum_for(l, "other.raw").as_deref(), Some("aaaa11"));
        assert_eq!(checksum_for(l, "missing"), None);
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
        assert!(find("windows-11").is_none());
    }
}
