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
    let mut resp = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .context("downloading the macOS restore image")?;
    let want = resp.content_length();
    let mut out = tokio::fs::File::create(&part).await?;
    let mut got = 0u64;
    let copied: Result<()> = async {
        while let Some(chunk) = resp.chunk().await? {
            got += chunk.len() as u64;
            out.write_all(&chunk).await?;
        }
        out.flush().await?;
        Ok(())
    }
    .await;
    if let Err(e) = copied {
        let _ = fs::remove_file(&part);
        return Err(e).context("downloading the macOS restore image");
    }
    if want.is_some_and(|w| w != got) {
        let _ = fs::remove_file(&part);
        bail!(
            "the restore image download was cut short ({got} of {} bytes)",
            want.unwrap_or(0)
        );
    }
    fs::rename(&part, &dest)?;
    prune_older(cfg, &dest);
    Ok(dest)
}

/// An IPSW is about 15 GB; keep only the newest.
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

    #[tokio::test]
    async fn refuses_http_and_odd_builds() {
        let t = tempfile::tempdir().unwrap();
        let c = cfg(t.path());
        assert!(ensure(&c, "http://x/y.ipsw", "26A434").await.is_err());
        assert!(ensure(&c, "https://x/y.ipsw", "../x").await.is_err());
    }
}
