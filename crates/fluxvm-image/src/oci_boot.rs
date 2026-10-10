// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Locating the kernel and initramfs that boot OCI sandboxes on `vz` (`apple.oci_kernel`, `apple.oci_initrd`).
//!
//! Each setting is an absolute path, a catalog name (checksum- and, with trusted signers, signature-verified by
//! [`crate::catalog`]), or a file name under `<state_dir>/oci/boot`. A `<file>.sha256` beside a local file, as
//! written by `scripts/build-oci-boot.sh`, is checked too.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::Config;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciBoot {
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub cmdline: String,
}

pub fn boot_dir(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("oci").join("boot")
}

pub async fn resolve(cfg: &Config) -> Result<OciBoot> {
    Ok(OciBoot {
        kernel: resolve_one(cfg, "apple.oci_kernel", &cfg.apple.oci_kernel).await?,
        initrd: resolve_one(cfg, "apple.oci_initrd", &cfg.apple.oci_initrd).await?,
        cmdline: cfg.apple.oci_cmdline.clone(),
    })
}

async fn resolve_one(cfg: &Config, key: &str, value: &str) -> Result<PathBuf> {
    if value.is_empty() {
        bail!("{key} is empty");
    }
    let as_path = Path::new(value);
    if as_path.is_absolute() {
        return check_local(as_path);
    }
    let resolved = crate::catalog::resolve_with_provenance(cfg, as_path).await?;
    if resolved.from_catalog {
        return Ok(resolved.path);
    }
    if value.contains('/') {
        bail!(
            "{key} = {value:?}: use an absolute path, a catalog name, or a file name in {}",
            boot_dir(cfg).display()
        );
    }
    let local = boot_dir(cfg).join(value);
    if !local.is_file() {
        bail!(
            "{key}: no catalog entry named {value:?} and no {} — build the OCI boot artifacts with \
             scripts/build-oci-boot.sh (see docs/oci-sandboxes.md)",
            local.display()
        );
    }
    check_local(&local)
}

fn check_local(path: &Path) -> Result<PathBuf> {
    if !path.is_file() {
        bail!("{} does not exist", path.display());
    }
    let mut sidecar = path.as_os_str().to_owned();
    sidecar.push(".sha256");
    if let Ok(text) = std::fs::read_to_string(&sidecar) {
        let want = text
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let got = format!(
            "{:x}",
            Sha256::digest(
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?
            )
        );
        if want != got {
            bail!(
                "{} does not match its .sha256 (want {want}, got {got})",
                path.display()
            );
        }
    }
    Ok(path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(dir: &Path) -> Config {
        Config {
            state_dir: dir.to_path_buf(),
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn defaults_resolve_from_the_boot_dir_and_check_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        assert!(
            resolve(&c)
                .await
                .unwrap_err()
                .to_string()
                .contains("build-oci-boot.sh")
        );

        let boot = boot_dir(&c);
        std::fs::create_dir_all(&boot).unwrap();
        std::fs::write(boot.join("oci-kernel"), b"kernel").unwrap();
        std::fs::write(boot.join("oci-initrd"), b"initrd").unwrap();
        let sum = format!("{:x}", Sha256::digest(b"kernel"));
        std::fs::write(
            boot.join("oci-kernel.sha256"),
            format!("{sum}  oci-kernel\n"),
        )
        .unwrap();
        let ok = resolve(&c).await.unwrap();
        assert_eq!(ok.kernel, boot.join("oci-kernel"));
        assert_eq!(ok.initrd, boot.join("oci-initrd"));
        assert!(ok.cmdline.contains("console=hvc0"));

        std::fs::write(boot.join("oci-kernel"), b"tampered").unwrap();
        assert!(
            resolve(&c)
                .await
                .unwrap_err()
                .to_string()
                .contains(".sha256")
        );
    }

    #[tokio::test]
    async fn absolute_paths_and_bad_values() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = cfg(dir.path());
        let k = dir.path().join("k");
        let i = dir.path().join("i");
        std::fs::write(&k, b"k").unwrap();
        std::fs::write(&i, b"i").unwrap();
        c.apple.oci_kernel = k.display().to_string();
        c.apple.oci_initrd = i.display().to_string();
        assert_eq!(resolve(&c).await.unwrap().kernel, k);

        c.apple.oci_initrd = "rel/initrd".into();
        assert!(resolve(&c).await.is_err());
        c.apple.oci_initrd = String::new();
        assert!(resolve(&c).await.is_err());
    }
}
