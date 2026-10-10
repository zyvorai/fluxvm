// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Apple's current macOS restore image (IPSW) for this Mac, looked up through the signed runner
//! (`VZMacOSRestoreImage.fetchLatestSupported`). Downloading it is `fluxvm_image::ipsw`.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpswInfo {
    pub url: String,
    pub build_version: String,
    pub os_version: String,
    pub supported: bool,
    #[serde(default)]
    pub min_cpus: Option<u64>,
    #[serde(default)]
    pub min_memory_bytes: Option<u64>,
}

fn parse(stdout: &[u8]) -> Result<IpswInfo> {
    let info: IpswInfo =
        serde_json::from_slice(stdout).context("decoding the latest-ipsw reply")?;
    if !info.url.starts_with("https://") {
        bail!("the restore image URL is not https: {}", info.url);
    }
    if info.build_version.is_empty()
        || !info
            .build_version
            .chars()
            .all(|c| c.is_ascii_alphanumeric())
    {
        bail!("unexpected restore image build {:?}", info.build_version);
    }
    Ok(info)
}

/// The newest restore image Apple offers this Mac. Needs network access; downloads nothing.
pub async fn latest_ipsw() -> Result<IpswInfo> {
    #[cfg(target_os = "macos")]
    {
        let runner = crate::find_runner()?;
        let out = tokio::process::Command::new(&runner)
            .arg("latest-ipsw")
            .kill_on_drop(true)
            .output()
            .await
            .with_context(|| format!("running {} latest-ipsw", runner.display()))?;
        if !out.status.success() {
            bail!(
                "latest-ipsw failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        parse(&out.stdout)
    }
    #[cfg(not(target_os = "macos"))]
    {
        bail!("macOS restore images are only available on a Mac")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_runner_reply() {
        let i = parse(br#"{"url":"https://updates.cdn-apple.com/x/UniversalMac_27.2_28A1_Restore.ipsw","build_version":"28A1","os_version":"27.2.0","supported":true,"min_cpus":4,"min_memory_bytes":8589934592}"#).unwrap();
        assert_eq!(i.build_version, "28A1");
        assert_eq!(i.min_cpus, Some(4));
    }

    #[test]
    fn refuses_plain_http_and_odd_builds() {
        assert!(parse(br#"{"url":"http://x/y.ipsw","build_version":"28A1","os_version":"27","supported":true}"#).is_err());
        assert!(parse(br#"{"url":"https://x/y.ipsw","build_version":"../x","os_version":"27","supported":true}"#).is_err());
    }
}
