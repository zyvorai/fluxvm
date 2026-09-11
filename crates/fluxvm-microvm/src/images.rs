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

    #[test]
    fn paths_and_urls_are_direct() {
        assert!(looks_like_direct_image(
            "/var/lib/fluxvm/images/ubuntu.qcow2"
        ));
        assert!(looks_like_direct_image("https://images.zyvor.dev/x.qcow2"));
        assert!(looks_like_direct_image("rootfs.ext4"));
        assert!(!looks_like_direct_image("ubuntu-24-04"));
    }
}
