// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use fluxvm_core::{config::Config, model::CloudInitSpec, process::run_checked};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn yaml_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// `static_net`, when `ci.static_network` is set, is `(guest_cidr, gateway)`
/// -- e.g. `("169.254.12.35/28", "169.254.12.33")` -- from
/// `fluxvm_network::netns::NetnsHandle`/`PreparedNetwork`. Callers must
/// run network prep *before* this so that's available; `None` is only
/// valid when `ci.static_network` is false (checked by the caller, not
/// re-validated here, since which networking modes have a known address is
/// this module's caller's concern, not cloud-init seed-building's).
fn write_seed_files(
    dir: &Path,
    ci: &CloudInitSpec,
    static_net: Option<(&str, &str)>,
) -> Result<(PathBuf, PathBuf, Option<PathBuf>)> {
    let user_data = dir.join("user-data");
    let meta_data = dir.join("meta-data");
    let hostname = ci.hostname.clone().unwrap_or_else(|| "fluxvm-vm".into());
    let user = ci.user.clone().unwrap_or_else(|| "cloud".into());

    let mut body = String::from("#cloud-config\n");
    body.push_str(&format!("hostname: {}\n", yaml_quote(&hostname)));
    body.push_str("users:\n");
    body.push_str("  - default\n");
    body.push_str(&format!(
        "  - name: {}\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n",
        yaml_quote(&user)
    ));
    if !ci.ssh_authorized_keys.is_empty() {
        body.push_str("    ssh_authorized_keys:\n");
        for key in &ci.ssh_authorized_keys {
            body.push_str(&format!("      - {}\n", yaml_quote(key)));
        }
    }
    if !ci.packages.is_empty() {
        body.push_str("package_update: true\npackages:\n");
        for p in &ci.packages {
            body.push_str(&format!("  - {}\n", yaml_quote(p)));
        }
    }
    if !ci.runcmd.is_empty() {
        body.push_str("runcmd:\n");
        for cmd in &ci.runcmd {
            body.push_str(&format!("  - [ bash, -lc, {} ]\n", yaml_quote(cmd)));
        }
    }
    if !ci.write_files.is_empty() {
        body.push_str("write_files:\n");
        for f in &ci.write_files {
            body.push_str(&format!("  - path: {}\n", yaml_quote(&f.path)));
            if let Some(perms) = &f.permissions {
                body.push_str(&format!("    permissions: {}\n", yaml_quote(perms)));
            }
            body.push_str("    encoding: b64\n");
            body.push_str(&format!(
                "    content: {}\n",
                yaml_quote(&B64.encode(f.content.as_bytes()))
            ));
        }
    }

    fs::write(&user_data, body).context("writing cloud-init user-data")?;
    fs::write(
        &meta_data,
        format!("instance-id: {}\nlocal-hostname: {}\n", hostname, hostname),
    )?;

    let network_config = dir.join("network-config");
    let network_config = if ci.static_network {
        let (cidr, gateway) = static_net
            .context("static_network is set but no address was prepared -- network prep must run before build_seed")?;
        // `match: {name: en*}` rather than a specific interface name: which
        // predictable name (enp0s1, ens3, eth0, ...) a given kernel/udev
        // combination assigns isn't known ahead of boot, and this is the
        // netplan-supported way to say "whichever the single real NIC is".
        let netcfg = format!(
            "network:\n  version: 2\n  ethernets:\n    guestnet0:\n      match:\n        name: en*\n      dhcp4: false\n      addresses:\n        - {cidr}\n      routes:\n        - to: default\n          via: {gateway}\n"
        );
        fs::write(&network_config, netcfg).context("writing cloud-init network-config")?;
        Some(network_config)
    } else {
        None
    };
    Ok((user_data, meta_data, network_config))
}

pub async fn build_seed(
    cfg: &Config,
    dir: &Path,
    ci: &CloudInitSpec,
    static_net: Option<(&str, &str)>,
) -> Result<PathBuf> {
    let (user_data, meta_data, network_config) = write_seed_files(dir, ci, static_net)?;
    let seed = dir.join("seed.img");
    let mut args = vec!["--disk-format".to_string(), "raw".to_string()];
    if let Some(network_config) = network_config.as_ref() {
        args.push("--network-config".into());
        args.push(network_config.display().to_string());
    }
    args.push(seed.display().to_string());
    args.push(user_data.display().to_string());
    args.push(meta_data.display().to_string());

    #[cfg(target_os = "macos")]
    {
        // `cloud-localds` is a Linux package; macOS builds the same NoCloud ("cidata") ISO with hdiutil.
        let _ = &args;
        return build_seed_hdiutil(dir, &user_data, &meta_data, network_config.as_deref()).await;
    }
    #[cfg(not(target_os = "macos"))]
    {
        run_checked(&cfg.cloud_localds_binary, &args).await?;
        Ok(seed)
    }
}

/// NoCloud seed as an ISO9660/Joliet image labelled `cidata`.
#[cfg(target_os = "macos")]
pub async fn build_seed_hdiutil(
    dir: &Path,
    user_data: &Path,
    meta_data: &Path,
    network_config: Option<&Path>,
) -> Result<PathBuf> {
    let staging = dir.join("seed-src");
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)?;
    fs::copy(user_data, staging.join("user-data"))?;
    fs::copy(meta_data, staging.join("meta-data"))?;
    match network_config {
        Some(nc) => {
            fs::copy(nc, staging.join("network-config"))?;
        }
        // A MAC-based DHCP identity keeps the guest's address stable across network restarts on first boot.
        None => fs::write(
            staging.join("network-config"),
            "version: 2\nethernets:\n  vz-nic:\n    match:\n      name: \"e*\"\n    dhcp4: true\n    dhcp-identifier: mac\n",
        )?,
    }
    let seed = dir.join("seed.img");
    let _ = fs::remove_file(&seed);
    run_checked(
        "hdiutil",
        &[
            "makehybrid".into(), "-quiet".into(), "-iso".into(), "-joliet".into(),
            "-default-volume-name".into(), "cidata".into(),
            "-o".into(), seed.display().to_string(), staging.display().to_string(),
        ],
    )
    .await?;
    // hdiutil may append `.iso`; keep a stable name for the backend.
    let iso = dir.join("seed.img.iso");
    if iso.exists() {
        fs::rename(&iso, &seed)?;
    }
    let _ = fs::remove_dir_all(&staging);
    Ok(seed)
}

/// Seed Cloud-init's NoCloud datasource inside a flat ext4 VM clone.
/// This avoids cloud-localds and a second virtio disk in the native engine.
pub fn inject_nocloud_raw(
    disk: &Path,
    dir: &Path,
    ci: &CloudInitSpec,
    static_net: Option<(&str, &str)>,
) -> Result<()> {
    let (user_data, meta_data, network_config) = write_seed_files(dir, ci, static_net)?;
    let base = "/var/lib/cloud/seed/nocloud";
    crate::raw_ext4::write_file(
        disk,
        &format!("{base}/user-data"),
        &fs::read(user_data)?,
        0o600,
    )?;
    crate::raw_ext4::write_file(
        disk,
        &format!("{base}/meta-data"),
        &fs::read(meta_data)?,
        0o600,
    )?;
    if let Some(network_config) = network_config {
        crate::raw_ext4::write_file(
            disk,
            &format!("{base}/network-config"),
            &fs::read(network_config)?,
            0o600,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn embeds_nocloud_in_flat_ext4_without_cloud_localds() {
        if Command::new("mkfs.ext4").arg("-V").output().is_err()
            || Command::new("debugfs").arg("-V").output().is_err()
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let disk = dir.path().join("root.raw");
        fs::File::create(&disk)
            .unwrap()
            .set_len(16 * 1024 * 1024)
            .unwrap();
        assert!(
            Command::new("mkfs.ext4")
                .args(["-q", "-F"])
                .arg(&disk)
                .status()
                .unwrap()
                .success()
        );
        inject_nocloud_raw(&disk, dir.path(), &CloudInitSpec::default(), None).unwrap();
        let output = Command::new("debugfs")
            .args(["-R", "cat /var/lib/cloud/seed/nocloud/user-data"])
            .arg(&disk)
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&output.stdout).starts_with("#cloud-config"));
    }
}
