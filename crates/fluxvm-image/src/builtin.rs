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
    qcow2: bool,
}

/// ARM64 images, the only guests Virtualization.framework runs on Apple silicon.
pub const BUILTIN_IMAGES: &[BuiltinImage] = &[
    BuiltinImage {
        name: "debian-13",
        base_url: "https://cloud.debian.org/images/cloud/trixie/latest",
        file: "debian-13-generic-arm64.raw",
        sums_file: "SHA512SUMS",
        sum: Sum::Sha512,
        qcow2: false,
    },
    BuiltinImage {
        name: "debian-12",
        base_url: "https://cloud.debian.org/images/cloud/bookworm/latest",
        file: "debian-12-generic-arm64.raw",
        sums_file: "SHA512SUMS",
        sum: Sum::Sha512,
        qcow2: false,
    },
    BuiltinImage {
        name: "ubuntu-24.04",
        base_url: "https://cloud-images.ubuntu.com/releases/24.04/release",
        file: "ubuntu-24.04-server-cloudimg-arm64.img",
        sums_file: "SHA256SUMS",
        sum: Sum::Sha256,
        qcow2: true,
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

/// Local path of the ready-to-clone raw image for `name`, downloading and converting it on first use.
pub async fn ensure(cfg: &Config, img: &BuiltinImage) -> Result<PathBuf> {
    let client = reqwest::Client::new();
    let listing = client
        .get(format!("{}/{}", img.base_url, img.sums_file))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("fetching the checksum list for {}", img.name))?
        .text()
        .await?;
    let want = checksum_for(&listing, img.file)
        .with_context(|| format!("{} is not listed in {}", img.file, img.sums_file))?;

    let dir = cfg.state_dir.join("images");
    fs::create_dir_all(&dir)?;
    // The hash is in the name, so a new upstream "latest" is fetched instead of silently reusing a stale copy.
    let tag = &want[..12.min(want.len())];
    let raw = dir.join(format!("{}-{tag}.raw", img.name));
    if raw.exists() {
        return Ok(raw);
    }
    let download = dir.join(format!("{}-{tag}.download", img.name));
    if !download.exists() {
        fetch_verified(&client, img, &want, &download).await?;
    }
    if img.qcow2 {
        // Convert beside the final name, then rename, so an interrupted conversion is never mistaken for an image.
        let part = dir.join(format!("{}-{tag}.raw.part", img.name));
        let _ = fs::remove_file(&part);
        crate::convert_image(cfg, &download, &part, "raw")
            .await
            .with_context(|| {
                format!(
                    "converting {} to raw (needs qemu-img: `brew install qemu`)",
                    img.name
                )
            })?;
        fs::rename(&part, &raw)?;
        let _ = fs::remove_file(&download);
    } else {
        fs::rename(&download, &raw)?;
    }
    Ok(raw)
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
    fn known_names_resolve() {
        assert!(find("debian-13").is_some());
        assert!(find("ubuntu-24.04").is_some_and(|i| i.qcow2));
        assert!(find("windows-11").is_none());
    }
}
