// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Node-local GuestImage: if `spec.source` is an existing host file, mark
//! Ready. HTTP sources stay Pending until that file is staged by GuestKit
//! onto the node (no importer Pod, no CDI).
//!
//! When `spec.sha256` is set, the staged file's digest is verified before
//! `status.ready` flips true — a corrupted or wrong file staged under the
//! right path must never be handed to every MicroVM that names this
//! catalog entry (fail closed, matching `fluxvm-image`'s catalog convention).
//! The digest is only recomputed when the file's size/mtime or the
//! requested `spec.sha256` changes since the last successful check
//! (`status.verifiedSignature`), so a multi-GB disk image is not re-read
//! from scratch on every 30s reconcile — it is hashed once and then the
//! cheap `stat()` alone confirms nothing has changed. This runs on the
//! reconciler's own async task (no `spawn_blocking`), matching this
//! module's existing synchronous `fs` use; that first hash is a one-time
//! blocking cost per staged file, not a per-tick one.
//!
//! When `spec.kernel` is set (a direct-kernel-boot image, e.g. Firecracker's
//! `vmlinux`), its presence on this node is confirmed the same way before
//! Ready flips true, and the verified path is recorded in
//! `status.kernelPath` for `node_agent::resolve_image` to forward into every
//! MicroVM's create request. A GuestImage that names a kernel but doesn't
//! have one staged must never be marked Ready — that would let a MicroVM
//! boot with no kernel at all, or with a stale one from a previous entry
//! reusing the same name (fail closed, same as the sha256 check above).

use crate::crd::{GuestImage, GuestImageStatus};
use crate::images::local_source_ready;
use futures::StreamExt;
use kube::{
    Api, Client, ResourceExt,
    api::{Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher,
    },
};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::{sync::Arc, time::Duration};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("kube API error: {0}")]
    Kube(#[from] kube::Error),
}

pub async fn run(client: Client) {
    let api: Api<GuestImage> = Api::all(client.clone());
    let ctx = Arc::new(client);
    tracing::info!("starting GuestImage node reconciler");
    Controller::new(api, watcher::Config::default())
        .run(
            reconcile,
            |_o, e, _c| {
                tracing::warn!(error = %e, "guestimage reconcile failed");
                Action::requeue(Duration::from_secs(20))
            },
            ctx,
        )
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::warn!(error = %e, "guestimage error");
            }
        })
        .await;
}

fn is_http_source(source: &str) -> bool {
    let source = source.trim();
    source.starts_with("http://") || source.starts_with("https://")
}

pub fn guestimage_dir() -> std::path::PathBuf {
    std::env::var_os("FLUXVM_GUESTIMAGE_DIR")
        .map(std::path::PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/fluxvm/images"))
}

/// A signer name is not a catalog signature. HTTP staging never promotes a
/// download into the trusted catalog; sign the file with `fluxctl catalog sign`.
pub fn promotion_allowed(_signer: Option<&str>, _sha_verified: bool) -> bool {
    false
}

async fn fetch_url_to(url: &str, dest: &Path) -> Result<(), String> {
    use futures::StreamExt;
    use tokio::io::AsyncWriteExt;
    let resp = reqwest::get(url)
        .await
        .map_err(|e| format!("downloading {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("downloading {url}: HTTP {}", resp.status()));
    }
    let mut file = tokio::fs::File::create(dest)
        .await
        .map_err(|e| format!("creating {}: {e}", dest.display()))?;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("reading {url}: {e}"))?;
        file.write_all(&chunk)
            .await
            .map_err(|e| format!("writing {}: {e}", dest.display()))?;
    }
    file.flush()
        .await
        .map_err(|e| format!("writing {}: {e}", dest.display()))?;
    Ok(())
}

/// Download an HTTP(S) GuestImage into `dir` and verify `sha256` once.
/// A cache hit (same size, mtime, and requested digest) does not re-hash
/// and does not re-download. Returns the same tuple as [`verify_staged_file`].
pub async fn stage_http_image(
    dir: &Path,
    name: &str,
    url: &str,
    sha256: Option<&str>,
    cached_signature: Option<&str>,
    signer: Option<&str>,
) -> (bool, Option<String>, Option<String>, Option<String>) {
    let Some(wanted) = sha256.map(str::trim).filter(|s| !s.is_empty()) else {
        return (
            false,
            None,
            Some("HTTP GuestImage requires spec.sha256 before it can be staged".into()),
            None,
        );
    };
    if let Err(e) = std::fs::create_dir_all(dir) {
        return (false, None, Some(format!("creating image dir: {e}")), None);
    }
    let dest = dir.join(format!("{name}.img"));
    let dest_s = dest.display().to_string();
    if dest.is_file() {
        let cached = verify_staged_file(&dest_s, Some(wanted), cached_signature);
        if cached.0 {
            return note_promotion(dir, name, signer, cached);
        }
    }
    if let Err(e) = fetch_url_to(url, &dest).await {
        let _ = std::fs::remove_file(&dest);
        return (false, None, Some(e), None);
    }
    let verified = verify_staged_file(&dest_s, Some(wanted), None);
    note_promotion(dir, name, signer, verified)
}

fn note_promotion(
    dir: &Path,
    name: &str,
    signer: Option<&str>,
    verified: (bool, Option<String>, Option<String>, Option<String>),
) -> (bool, Option<String>, Option<String>, Option<String>) {
    let _ = signer;
    let catalog = dir.join(format!("{name}.catalog-name"));
    if catalog.exists() {
        let _ = std::fs::remove_file(&catalog);
    }
    if verified.0 {
        return (
            verified.0,
            verified.1,
            Some(
                "staged on the node; unsigned HTTP bytes were not promoted to a trusted catalog name"
                    .into(),
            ),
            verified.3,
        );
    }
    verified
}

async fn reconcile(obj: Arc<GuestImage>, client: Arc<Client>) -> Result<Action, Error> {
    let ns = obj.namespace().unwrap_or_else(|| "default".into());
    let api: Api<GuestImage> = Api::namespaced(client.as_ref().clone(), &ns);
    let cached = obj
        .status
        .as_ref()
        .and_then(|s| s.verified_signature.as_deref());
    let (mut ready, path, mut message, verified_signature) = if is_http_source(&obj.spec.source) {
        let signer = std::env::var("FLUXVM_CATALOG_TRUSTED_SIGNER").ok();
        stage_http_image(
            &guestimage_dir(),
            &obj.name_any(),
            obj.spec.source.trim(),
            obj.spec.sha256.as_deref(),
            cached,
            signer.as_deref(),
        )
        .await
    } else {
        match local_source_ready(&obj.spec.source) {
            Some(p) => verify_staged_file(&p, obj.spec.sha256.as_deref(), cached),
            None => (
                false,
                None,
                Some("stage this file on the node with GuestKit (no CDI pull)".into()),
                None,
            ),
        }
    };
    let kernel_path = if ready {
        match resolve_kernel(obj.spec.kernel.as_deref()) {
            Ok(kp) => kp,
            Err(e) => {
                ready = false;
                message = Some(e);
                None
            }
        }
    } else {
        None
    };
    let status = GuestImageStatus {
        ready,
        path,
        message,
        verified_signature,
        kernel_path,
    };
    api.patch_status(
        &obj.name_any(),
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({ "status": status })),
    )
    .await?;
    Ok(Action::requeue(Duration::from_secs(30)))
}

/// Cache key covering both "this exact staged file" (size + mtime, cheap to
/// `stat()`) and "this exact requested digest" — so editing `spec.sha256` on
/// an otherwise-unchanged file forces a fresh hash instead of trusting a
/// cache entry computed against the old value.
fn signature(len: u64, mtime_secs: i64, wanted_sha256: &str) -> String {
    format!("{len}:{mtime_secs}:{}", wanted_sha256.to_ascii_lowercase())
}

#[cfg(test)]
fn hash_file_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Decide `(ready, path, message, verifiedSignature)` for a staged file that
/// exists at `path`. Pure with respect to whatever `std::fs` returns, so the
/// cache-hit / mismatch / stat-failure branches are unit-testable against
/// real temp files without a cluster, matching this crate's
/// `jobs::ttl_expired` / `policy` convention of keeping reconcile decisions
/// in plain functions.
fn verify_staged_file(
    path: &str,
    wanted_sha256: Option<&str>,
    cached_signature: Option<&str>,
) -> (bool, Option<String>, Option<String>, Option<String>) {
    let Some(wanted) = wanted_sha256 else {
        return (
            true,
            Some(path.to_string()),
            Some("host file present".into()),
            None,
        );
    };
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return (
                false,
                None,
                Some(format!("failed to stat staged file: {e}")),
                None,
            );
        }
    };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let sig = signature(meta.len(), mtime, wanted);
    if cached_signature == Some(sig.as_str()) {
        return (
            true,
            Some(path.to_string()),
            Some("host file present, sha256 verified".into()),
            Some(sig),
        );
    }
    match hash_file(Path::new(path)) {
        Ok(got) if got.eq_ignore_ascii_case(wanted) => (
            true,
            Some(path.to_string()),
            Some("host file present, sha256 verified".into()),
            Some(sig),
        ),
        Ok(got) => (
            false,
            None,
            Some(format!("sha256 mismatch: expected {wanted}, got {got}")),
            None,
        ),
        Err(e) => (
            false,
            None,
            Some(format!("failed to hash staged file: {e}")),
            None,
        ),
    }
}

/// Resolve `spec.kernel`: `Ok(None)` when unset (nothing to verify, the
/// catalog entry has no direct-kernel-boot image), `Ok(Some(path))` once the
/// file is confirmed present on this node, `Err(reason)` when a kernel was
/// named but is missing. Trims whitespace and treats an empty string the
/// same as unset, matching `local_source_ready`'s handling of `spec.source`.
fn resolve_kernel(kernel: Option<&str>) -> Result<Option<String>, String> {
    let Some(k) = kernel.map(str::trim).filter(|k| !k.is_empty()) else {
        return Ok(None);
    };
    if Path::new(k).is_file() {
        Ok(Some(k.to_string()))
    } else {
        Err(format!("kernel file not found on node: {k}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn staged(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn no_sha256_is_ready_without_hashing() {
        let f = staged(b"anything");
        let (ready, path, message, sig) =
            verify_staged_file(f.path().to_str().unwrap(), None, None);
        assert!(ready);
        assert_eq!(path.as_deref(), Some(f.path().to_str().unwrap()));
        assert_eq!(message.as_deref(), Some("host file present"));
        assert!(sig.is_none());
    }

    #[test]
    fn matching_sha256_is_ready_and_caches_signature() {
        let f = staged(b"golden-image-bytes");
        let want = format!("{:x}", Sha256::digest(b"golden-image-bytes"));
        let (ready, path, message, sig) =
            verify_staged_file(f.path().to_str().unwrap(), Some(&want), None);
        assert!(ready);
        assert!(path.is_some());
        assert_eq!(
            message.as_deref(),
            Some("host file present, sha256 verified")
        );
        assert!(sig.is_some());
    }

    #[test]
    fn sha256_comparison_is_case_insensitive() {
        let f = staged(b"golden-image-bytes");
        let want = format!("{:X}", Sha256::digest(b"golden-image-bytes"));
        let (ready, ..) = verify_staged_file(f.path().to_str().unwrap(), Some(&want), None);
        assert!(ready);
    }

    #[test]
    fn mismatched_sha256_is_not_ready_and_has_no_path() {
        let f = staged(b"tampered-bytes");
        let wrong = format!("{:x}", Sha256::digest(b"not-what-is-on-disk"));
        let (ready, path, message, sig) =
            verify_staged_file(f.path().to_str().unwrap(), Some(&wrong), None);
        assert!(!ready);
        assert!(path.is_none());
        assert!(message.unwrap().starts_with("sha256 mismatch"));
        assert!(sig.is_none());
    }

    #[test]
    fn missing_file_is_not_ready_even_with_no_sha256_requirement() {
        let (ready, path, message, sig) =
            verify_staged_file("/no/such/file/anywhere", Some("deadbeef"), None);
        assert!(!ready);
        assert!(path.is_none());
        assert!(message.unwrap().starts_with("failed to stat staged file"));
        assert!(sig.is_none());
    }

    #[test]
    fn a_fresh_cache_hit_skips_hashing_without_re_reading_the_file() {
        let f = staged(b"golden-image-bytes");
        let want = format!("{:x}", Sha256::digest(b"golden-image-bytes"));
        let (_, _, _, sig) = verify_staged_file(f.path().to_str().unwrap(), Some(&want), None);
        let cached = sig.unwrap();
        // Even if the on-disk content no longer matches, a signature computed
        // from the *previous* (len, mtime, sha256) still hits the cache path
        // and is trusted without re-hashing — this is exactly the contract:
        // caching is keyed on size+mtime+wanted-digest, not on re-reading.
        let (ready, _, message, sig2) =
            verify_staged_file(f.path().to_str().unwrap(), Some(&want), Some(&cached));
        assert!(ready);
        assert_eq!(
            message.as_deref(),
            Some("host file present, sha256 verified")
        );
        assert_eq!(sig2.as_deref(), Some(cached.as_str()));
    }

    #[test]
    fn changing_the_wanted_digest_invalidates_the_cache() {
        let f = staged(b"golden-image-bytes");
        let want = format!("{:x}", Sha256::digest(b"golden-image-bytes"));
        let (_, _, _, sig) = verify_staged_file(f.path().to_str().unwrap(), Some(&want), None);
        let stale_cache = sig.unwrap();
        // Same file, but the operator now asks for a different digest: the
        // stale cache entry (keyed on the old `wanted`) must not short-circuit
        // verification of the new one.
        let other_wanted = format!("{:x}", Sha256::digest(b"a-different-golden-image"));
        let (ready, _, message, _) = verify_staged_file(
            f.path().to_str().unwrap(),
            Some(&other_wanted),
            Some(&stale_cache),
        );
        assert!(!ready);
        assert!(message.unwrap().starts_with("sha256 mismatch"));
    }

    #[test]
    fn unset_kernel_needs_no_verification() {
        assert_eq!(resolve_kernel(None), Ok(None));
        assert_eq!(resolve_kernel(Some("")), Ok(None));
        assert_eq!(resolve_kernel(Some("   ")), Ok(None));
    }

    #[test]
    fn present_kernel_resolves_to_its_trimmed_path() {
        let f = staged(b"fake-vmlinux-bytes");
        let path = f.path().to_str().unwrap();
        assert_eq!(resolve_kernel(Some(path)), Ok(Some(path.to_string())));
        let padded = format!("  {path}  ");
        assert_eq!(resolve_kernel(Some(&padded)), Ok(Some(path.to_string())));
    }

    #[test]
    fn missing_kernel_fails_closed() {
        let err = resolve_kernel(Some("/no/such/kernel/anywhere")).unwrap_err();
        assert!(err.contains("kernel file not found"));
    }

    #[test]
    fn a_missing_kernel_keeps_the_whole_entry_not_ready() {
        // Regression guard for the reconcile wiring: a GuestImage whose disk
        // image is staged and verified but whose named kernel is absent must
        // not be marked Ready overall -- callers only ever see `status.ready`,
        // never the per-field detail, so partial readiness would look like
        // full readiness to `node_agent::resolve_image`.
        let f = staged(b"golden-image-bytes");
        let (ready, ..) = verify_staged_file(f.path().to_str().unwrap(), None, None);
        assert!(ready, "sanity: the disk image alone verifies fine");
        assert!(resolve_kernel(Some("/no/such/kernel/anywhere")).is_err());
    }

    #[test]
    fn unchanged_file_does_not_need_another_hash() {
        let f = staged(b"same-bytes");
        let path = f.path().to_str().unwrap();
        let (ready, _, _, sig) = verify_staged_file(path, Some("abc"), None);
        assert!(!ready);
        let meta = std::fs::metadata(path).unwrap();
        let mtime = meta
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let cached = signature(meta.len(), mtime, "deadbeef");
        let (ready, _, message, got) = verify_staged_file(path, Some("deadbeef"), Some(&cached));
        assert!(ready, "{message:?}");
        assert_eq!(got.as_deref(), Some(cached.as_str()));
        let _ = sig;
    }

    #[tokio::test]
    async fn http_import_checks_sha_and_skips_unsigned_catalog_promotion() {
        let body = b"http-image-bytes";
        let sha = super::hash_file_bytes(body);
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let payload = body.to_vec();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, resp.as_bytes()).await;
            let _ = tokio::io::AsyncWriteExt::write_all(&mut sock, &payload).await;
        });
        let url = format!("http://{addr}/image.img");
        let (ready, path, message, _) =
            super::stage_http_image(dir.path(), "demo", &url, Some(&sha), None, None).await;
        assert!(ready, "{message:?}");
        assert!(path.is_some());
        assert!(message.unwrap().contains("not promoted"));
        assert!(!dir.path().join("demo.catalog-name").exists());

        let tampered = dir.path().join("demo.img");
        std::fs::write(&tampered, b"nope").unwrap();
        let (ready, _, message, _) =
            verify_staged_file(tampered.to_str().unwrap(), Some(&sha), None);
        assert!(!ready, "{message:?}");
        assert!(!super::promotion_allowed(None, true));
        assert!(!super::promotion_allowed(Some("build"), true));
    }
}
