// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Offline writes to a stopped, flat ext4 rootfs without QEMU or a loop mount.

use anyhow::{Context, Result, bail};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;

pub fn require_flat_ext4(image: &Path) -> Result<()> {
    let mut f = File::open(image).with_context(|| format!("opening {}", image.display()))?;
    let mut magic = [0u8; 2];
    f.seek(SeekFrom::Start(1024 + 56))?;
    f.read_exact(&mut magic)?;
    if magic != [0x53, 0xef] {
        bail!(
            "{} is not a flat ext4 rootfs; native KVM offline injection cannot edit partitioned or qcow2 images",
            image.display()
        );
    }
    Ok(())
}

fn debugfs(image: &Path, command: &str) -> Result<String> {
    let output = Command::new("debugfs")
        .args(["-w", "-R", command])
        .arg(image)
        .output()
        .context("running debugfs (install e2fsprogs for native KVM image injection)")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success()
        || stderr.contains("File not found")
        || stderr.contains("Could not")
        || stderr.contains("not found by ext2_lookup")
    {
        bail!("debugfs {command}: {stderr}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// `guest_path` is supplied only by fixed in-tree paths, never request input.
pub fn write_file(image: &Path, guest_path: &str, content: &[u8], mode: u16) -> Result<()> {
    require_flat_ext4(image)?;
    let parent = Path::new(guest_path)
        .parent()
        .context("guest path has no parent")?;
    let mut cur = String::new();
    for part in parent.components().skip(1) {
        cur.push('/');
        cur.push_str(&part.as_os_str().to_string_lossy());
        let exists = debugfs(image, &format!("stat {cur}"));
        if exists.is_err() {
            debugfs(image, &format!("mkdir {cur}"))?;
        }
    }
    let mut tmp = tempfile::NamedTempFile::new().context("creating temporary guest file")?;
    tmp.write_all(content)?;
    tmp.flush()?;
    // `debugfs write` refuses to overwrite. Remove the old file from the
    // *cloned* VM disk first, then verify the new content before boot.
    let _ = debugfs(image, &format!("rm {guest_path}"));
    debugfs(
        image,
        &format!("write {} {guest_path}", tmp.path().display()),
    )?;
    // 0100000 (octal) is S_IFREG; debugfs's "mode" field is the raw 16-bit
    // inode mode with no implicit file-type bits, so this must be spelled
    // out in full -- a missing digit here silently turns the file into a
    // FIFO (0010000) instead of a regular file, confirmed against real
    // debugfs 1.47.2 on the lab host before landing this.
    debugfs(image, &format!("sif {guest_path} mode 0100{mode:03o}"))?;
    let stat = debugfs(image, &format!("stat {guest_path}"))?;
    if !stat.contains("Type: regular") || !stat.contains(&format!("Mode:  {mode:04o}")) {
        bail!("debugfs did not set requested permissions for {guest_path}: {stat}");
    }
    let verify = tempfile::NamedTempFile::new()?;
    let dump = Command::new("debugfs")
        .args([
            "-R",
            &format!("dump {guest_path} {}", verify.path().display()),
        ])
        .arg(image)
        .output()?;
    let dump_err = String::from_utf8_lossy(&dump.stderr);
    if !dump.status.success()
        || dump_err.contains("File not found")
        || dump_err.contains("not found by ext2_lookup")
        || fs::read(verify.path())? != content
    {
        bail!("debugfs verification failed for {guest_path}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_into_flat_ext4_when_e2fsprogs_is_available() {
        if Command::new("mkfs.ext4").arg("-V").output().is_err()
            || Command::new("debugfs").arg("-V").output().is_err()
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("root.raw");
        File::create(&image)
            .unwrap()
            .set_len(16 * 1024 * 1024)
            .unwrap();
        assert!(
            Command::new("mkfs.ext4")
                .args(["-q", "-F"])
                .arg(&image)
                .status()
                .unwrap()
                .success()
        );
        write_file(
            &image,
            "/etc/fluxvm-guest-agent.token",
            b"test-token",
            0o600,
        )
        .unwrap();
        write_file(&image, "/etc/fluxvm-guest-agent.token", b"new-token", 0o600).unwrap();
        let output = Command::new("debugfs")
            .args(["-R", "cat /etc/fluxvm-guest-agent.token"])
            .arg(&image)
            .output()
            .unwrap();
        assert_eq!(output.stdout, b"new-token");
    }
}
