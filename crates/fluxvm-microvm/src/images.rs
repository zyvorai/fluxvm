// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Resolve `spec.image`: host path / URL stays as-is; any other name is a
//! GuestImage in the same namespace. HTTP pull is *not* done here — GuestKit
//! stages the file; we only wait until `status.ready` and use `status.path`.

use crate::crd::GuestImage;

pub fn looks_like_direct_image(image: &str) -> bool {
    let s = image.trim();
    s.starts_with('/')
        || s.starts_with('.')
        || s.contains("://")
        || s.ends_with(".qcow2")
        || s.ends_with(".raw")
        || s.ends_with(".ext4")
        || s.ends_with(".img")
}

pub fn guest_image_host_path(img: &GuestImage) -> Option<String> {
    if !img.status.as_ref().map(|s| s.ready).unwrap_or(false) {
        return None;
    }
    img.status
        .as_ref()
        .and_then(|s| s.path.clone())
        .filter(|p| !p.is_empty())
        .or_else(|| {
            let src = img.spec.source.trim();
            looks_like_direct_image(src).then(|| src.to_string())
        })
}

/// Host path to this GuestImage's verified kernel, for a MicroVM to hand
/// straight to `CreateVmRequest.kernel` (direct-kernel boot). `None` unless
/// the catalog entry is Ready *and* named a kernel that was confirmed
/// present on this node -- an entry with no `spec.kernel` simply has no
/// kernel to contribute, same as a backend that boots straight off the disk
/// image (QEMU/Cloud Hypervisor with firmware).
pub fn guest_image_kernel_path(img: &GuestImage) -> Option<String> {
    img.status
        .as_ref()
        .filter(|s| s.ready)
        .and_then(|s| s.kernel_path.clone())
}

pub fn local_source_ready(source: &str) -> Option<String> {
    let src = source.trim();
    if src.starts_with('/') && std::path::Path::new(src).is_file() {
        return Some(src.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::GuestImageStatus;

    #[test]
    fn paths_and_urls_are_direct() {
        assert!(looks_like_direct_image(
            "/var/lib/fluxvm/images/ubuntu.qcow2"
        ));
        assert!(looks_like_direct_image("https://images.zyvor.dev/x.qcow2"));
        assert!(looks_like_direct_image("rootfs.ext4"));
        assert!(!looks_like_direct_image("ubuntu-24-04"));
    }

    fn guest_image() -> GuestImage {
        GuestImage::new("gimg", crate::crd::GuestImageSpec::default())
    }

    #[test]
    fn kernel_path_absent_without_status() {
        let img = guest_image();
        assert_eq!(guest_image_kernel_path(&img), None);
    }

    #[test]
    fn kernel_path_hidden_while_not_ready() {
        let mut img = guest_image();
        img.status = Some(GuestImageStatus {
            ready: false,
            kernel_path: Some("/boot/vmlinux".into()),
            ..Default::default()
        });
        // Even a resolved kernel_path must not leak out while the entry as a
        // whole isn't Ready -- e.g. mid-reconcile after the disk image alone
        // was verified but before the kernel check ran.
        assert_eq!(guest_image_kernel_path(&img), None);
    }

    #[test]
    fn kernel_path_surfaces_once_ready() {
        let mut img = guest_image();
        img.status = Some(GuestImageStatus {
            ready: true,
            kernel_path: Some("/boot/vmlinux".into()),
            ..Default::default()
        });
        assert_eq!(
            guest_image_kernel_path(&img).as_deref(),
            Some("/boot/vmlinux")
        );
    }

    #[test]
    fn no_kernel_named_is_simply_none() {
        let mut img = guest_image();
        img.status = Some(GuestImageStatus {
            ready: true,
            ..Default::default()
        });
        assert_eq!(guest_image_kernel_path(&img), None);
    }
}
