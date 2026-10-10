// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! The macOS restore image (IPSW) behind `image: "macos"` with `apple.install`.
//!
//! Apple publishes no checksum list for an IPSW; the file comes from the HTTPS URL that
//! `VZMacOSRestoreImage.fetchLatestSupported` returns, its length is checked against the response, and the installer
//! itself rejects an image that does not load. It is cached under `state_dir/images` as `macos-<build>.ipsw`.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::Config;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tokio::io::AsyncWriteExt;

/// Name that resolves to the newest restore image.
pub const IMAGE_NAME: &str = "macos";

fn dir(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("images")
}

fn path_for(cfg: &Config, build: &str) -> PathBuf {
    dir(cfg).join(format!("macos-{build}.ipsw"))
}

/// The newest IPSW already downloaded, without touching the network.
pub fn newest_cached(cfg: &Config) -> Option<PathBuf> {
    fs::read_dir(dir(cfg))
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let n = e.file_name();
            let n = n.to_string_lossy();
            n.starts_with("macos-") && n.ends_with(".ipsw")
        })
        .max_by_key(|e| e.metadata().and_then(|m| m.modified()).ok())
        .map(|e| e.path())
}

/// Local path of the IPSW for `build`, downloaded from `url` on first use.
pub async fn ensure(cfg: &Config, url: &str, build: &str) -> Result<PathBuf> {
    if !url.starts_with("https://") {
        bail!("refusing to download a restore image over a non-https URL");
    }
    if build.is_empty() || !build.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("unexpected restore image build {build:?}");
    }
    let dest = path_for(cfg, build);
    if dest.exists() {
        return Ok(dest);
    }
    fs::create_dir_all(dir(cfg))?;
    let part = dest.with_extension("ipsw.part");
    let client = reqwest::Client::builder()
        .user_agent(concat!("fluxvm/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(15))
        .build()?;
    // An interrupted download continues where it stopped (a server that ignores `Range` restarts it).
    let have = fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
    let mut req = client.get(url);
    if have > 0 {
        req = req.header(reqwest::header::RANGE, format!("bytes={have}-"));
    }
    let mut resp = req
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .context("downloading the macOS restore image")?;
    let resuming = have > 0 && resp.status() == reqwest::StatusCode::PARTIAL_CONTENT;
    let start = if resuming { have } else { 0 };
    // `content_length` is what is still to come; the file ends up `start + that` long.
    let total = resp.content_length().map(|n| n + start);
    if let Some(total) = total {
        let free = free_bytes(&dir(cfg));
        let need = total - start;
        if free.is_some_and(|f| f < need + HEADROOM) {
            bail!(
                "not enough disk space for the macOS restore image: it needs {} more GiB in {} and {} GiB are free (the \
                 install then needs about 25 GiB for the guest disk)",
                (need + HEADROOM).div_ceil(1 << 30),
                dir(cfg).display(),
                free.unwrap_or(0) >> 30
            );
        }
    }
    let mut out = if resuming {
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(&part)
            .await?
    } else {
        tokio::fs::File::create(&part).await?
    };
    let mut got = start;
    let copied: Result<()> = async {
        while let Some(chunk) = resp.chunk().await? {
            got += chunk.len() as u64;
            out.write_all(&chunk).await?;
        }
        out.flush().await?;
        Ok(())
    }
    .await;
    // The partial file is kept on a failure so the next attempt resumes; a size mismatch means it is not an image.
    copied.context("downloading the macOS restore image")?;
    if total.is_some_and(|w| w != got) {
        let _ = fs::remove_file(&part);
        bail!(
            "the restore image download has the wrong size ({got} of {} bytes)",
            total.unwrap_or(0)
        );
    }
    fs::rename(&part, &dest)?;
    prune_older(cfg, &dest);
    Ok(dest)
}

/// Space left free beyond the image itself.
const HEADROOM: u64 = 2 << 30;

/// Bytes available to an unprivileged writer on the filesystem holding `path`.
fn free_bytes(path: &Path) -> Option<u64> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut vfs) } != 0 {
        return None;
    }
    Some((vfs.f_bavail as u64).saturating_mul(vfs.f_frsize as u64))
}

/// An IPSW is about 25 GB; keep only the newest.
fn prune_older(cfg: &Config, keep: &Path) {
    let Ok(rd) = fs::read_dir(dir(cfg)) else {
        return;
    };
    for e in rd.filter_map(|e| e.ok()) {
        let p = e.path();
        let n = e.file_name();
        let n = n.to_string_lossy();
        if p != keep && n.starts_with("macos-") && n.ends_with(".ipsw") {
            let _ = fs::remove_file(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &Path) -> Config {
        let mut c = Config::default();
        c.state_dir = dir.to_path_buf();
        c
    }

    #[test]
    fn newest_cached_ignores_partial_downloads() {
        let t = tempfile::tempdir().unwrap();
        let c = cfg(t.path());
        assert!(newest_cached(&c).is_none());
        fs::create_dir_all(t.path().join("images")).unwrap();
        fs::write(t.path().join("images/macos-26A434.ipsw.part"), b"x").unwrap();
        assert!(newest_cached(&c).is_none());
        fs::write(t.path().join("images/macos-26A434.ipsw"), b"x").unwrap();
        assert!(
            newest_cached(&c)
                .unwrap()
                .ends_with("images/macos-26A434.ipsw")
        );
    }

    #[test]
    fn free_bytes_reads_the_filesystem() {
        let t = tempfile::tempdir().unwrap();
        assert!(free_bytes(t.path()).is_some_and(|n| n > 0));
        assert!(free_bytes(Path::new("/definitely/not/here")).is_none());
    }

    #[tokio::test]
    async fn refuses_http_and_odd_builds() {
        let t = tempfile::tempdir().unwrap();
        let c = cfg(t.path());
        assert!(ensure(&c, "http://x/y.ipsw", "26A434").await.is_err());
        assert!(ensure(&c, "https://x/y.ipsw", "../x").await.is_err());
    }
}
