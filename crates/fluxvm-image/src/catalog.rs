// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Named, checksummed, optionally-signed base images ("`ubuntu-24.04`"
//! instead of a raw path), resolved by [`resolve`] before a VM is created.
//!
//! Signing is a self-contained Ed25519 scheme (`ed25519-dalek`) rather than
//! cosign/Sigstore: those need either a local `cosign` binary or a live
//! Fulcio/Rekor round trip, neither of which this project can verify
//! end-to-end without external network-dependent test infrastructure. A
//! bare keypair signing a small canonical payload is real, offline-capable,
//! and fully testable — "your own signing policy," which the deferred
//! feature list explicitly allowed for.

use crate::{fetch_if_needed, verify_sha256};
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use fluxvm_core::config::Config;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// One entry in a catalog file (a JSON array of these). `sha256` is
/// mandatory here (unlike `BuildImageRequest::sha256`, which is optional) —
/// a catalog exists specifically to pin known-good images, so an unpinned
/// entry defeats the point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    /// Alias a `CreateVmRequest.image` can reference instead of a raw path,
    /// e.g. `"ubuntu-24.04"`.
    pub name: String,
    /// Local path or `http(s)://` URL — same as `BuildImageRequest::source`.
    pub source: String,
    pub sha256: String,
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default)]
    pub distro: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    /// Base64-encoded Ed25519 signature over [`canonical_payload`], from
    /// `fluxvm catalog sign`. Required only when
    /// `Config::catalog.trusted_signers` is non-empty — see [`resolve`].
    #[serde(default)]
    pub signature: Option<String>,
    /// Unix seconds at the moment `fluxvm catalog sign` ran — asserted by
    /// the signer and covered by [`canonical_payload`] itself (so it can't
    /// be back/post-dated after the fact without invalidating the
    /// signature), the tamper-evident half of "when was this vouched for."
    /// `None` for an unsigned entry. **Breaking change**: `canonical_payload`
    /// now covers more fields than it used to (see its own doc comment) --
    /// any entry signed before this existed will fail verification and
    /// needs `fluxvm catalog sign` re-run. There is no dual-format
    /// fallback; see `docs/operations.md`'s "Image catalog & signing"
    /// section for the upgrade note.
    #[serde(default)]
    pub signed_at: Option<i64>,
    /// When `true`, [`remove_entry`]/[`rename_entry`] refuse to act on this
    /// entry — mirrors machinectl's per-image read-only flag, used to
    /// protect a base image other entries are cloned from. Deliberately
    /// NOT covered by [`canonical_payload`] -- it's a mutable operational
    /// setting toggled via a dedicated REST route
    /// (`POST .../read-only`), not provenance data, and signing it would
    /// mean every legitimate toggle silently invalidates the entry's
    /// signature.
    #[serde(default)]
    pub read_only: bool,
    /// The CI pipeline that produced this image's bytes, e.g.
    /// `"github-actions/build-images.yml"` — asserted by whoever ran
    /// `fluxvm catalog sign`, the same honesty posture as [`signed_by`]:
    /// there is no cryptographic attestation chain back to the actual CI
    /// system (that would need something like Sigstore/in-toto, which this
    /// module's own signing scheme deliberately avoids — see the module
    /// doc comment). Once signed, though, it's tamper-evident: covered by
    /// [`canonical_payload`], so it can't be edited in `catalog.json`
    /// afterward without invalidating the signature. `None` when the
    /// signer didn't record one.
    ///
    /// [`signed_by`]: CatalogListEntry::signed_by
    #[serde(default)]
    pub build_pipeline: Option<String>,
    /// The specific run/job id within [`build_pipeline`] that produced this
    /// image, e.g. a GitHub Actions run id — same asserted-not-attested,
    /// tamper-evident-once-signed posture as `build_pipeline`.
    ///
    /// [`build_pipeline`]: CatalogEntry::build_pipeline
    #[serde(default)]
    pub build_run_id: Option<String>,
    /// The source commit SHA the build was triggered from — same
    /// asserted-not-attested, tamper-evident-once-signed posture as
    /// `build_pipeline`.
    #[serde(default)]
    pub build_commit: Option<String>,
}
fn default_format() -> String {
    "qcow2".into()
}

/// The exact bytes a signature is computed over — every field that
/// identifies *what* is being vouched for, so a signature can't be replayed
/// onto an entry with the same name but a different source/checksum.
///
/// Covers `distro`/`version`/`arch`/`signed_at` in addition to the
/// original `name`/`source`/`sha256`/`format` -- previously those first
/// three were present on `CatalogEntry` but excluded from the signed
/// payload entirely, so they could be edited in `catalog.json` post-signing
/// (e.g. relabeling an entry's `arch` to mislead a platform-matching
/// consumer) without invalidating the signature; a real, closed gap, not a
/// new capability. Now also covers `build_pipeline`/`build_run_id`/
/// `build_commit` -- the same reasoning extended to FluxVM's answer to
/// "real build-lineage/CI-provenance recording," previously named as an
/// explicitly open gap: those three fields are asserted by the signer, not
/// independently verified against the actual CI system, but once signed
/// they can no longer be silently relabeled in `catalog.json` (e.g.
/// claiming a different pipeline produced these bytes) without
/// invalidating the signature. `read_only` deliberately stays excluded --
/// see its own doc comment on `CatalogEntry` for why. `Option<String>`
/// fields serialize as an empty segment when `None`, so "unset" and "empty
/// string" are still distinguishable from any *other* field's own value
/// shifting the line count, but not from each other -- acceptable here
/// since an empty `distro`/`version`/`arch`/`build_pipeline`/
/// `build_run_id`/`build_commit` string is not a value worth
/// distinguishing from absent for signing purposes.
fn canonical_payload(entry: &CatalogEntry) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        entry.name,
        entry.source,
        entry.sha256,
        entry.format,
        entry.distro.as_deref().unwrap_or(""),
        entry.version.as_deref().unwrap_or(""),
        entry.arch.as_deref().unwrap_or(""),
        entry.signed_at.map(|t| t.to_string()).unwrap_or_default(),
        entry.build_pipeline.as_deref().unwrap_or(""),
        entry.build_run_id.as_deref().unwrap_or(""),
        entry.build_commit.as_deref().unwrap_or(""),
    )
}

fn load_catalog(path: &Path) -> Result<Vec<CatalogEntry>> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("reading catalog {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing catalog {}", path.display()))
}

fn save_catalog(path: &Path, entries: &[CatalogEntry]) -> Result<()> {
    // Write-then-rename so a reader never observes a half-written file.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(entries)?)
        .with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("renaming into place: {}", path.display()))
}

fn catalog_path(cfg: &Config) -> Result<&Path> {
    cfg.catalog.path.as_deref().context(
        "no catalog.path configured — set [catalog] path in the FluxVM config to use the image catalog",
    )
}

/// Register a new catalog entry — fetches `source` first if it's a URL and
/// computes its sha256 fresh from what actually landed on disk (trusting a
/// caller-supplied hash would just be trusting the caller; this proves
/// what's really there, the same posture `resolve` already takes on every
/// lookup). The entry is unsigned — signing is a separate, deliberately
/// offline step (`fluxvm catalog sign`).
///
/// Replaces machinectl's `pull-raw`/`import-raw` (a URL and a local path
/// are handled identically here, same as everywhere else `source` is used).
pub async fn add_entry(
    cfg: &Config,
    name: String,
    source: String,
    format: String,
) -> Result<CatalogEntry> {
    let path = catalog_path(cfg)?;
    let mut entries = if path.exists() {
        load_catalog(path)?
    } else {
        Vec::new()
    };
    if entries.iter().any(|e| e.name == name) {
        bail!("catalog entry '{name}' already exists");
    }
    let local = fetch_if_needed(cfg, &source)
        .await
        .with_context(|| format!("fetching '{source}'"))?;
    let bytes = fs::read(&local).with_context(|| format!("reading {}", local.display()))?;
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    let entry = CatalogEntry {
        name,
        source,
        sha256,
        format,
        distro: None,
        version: None,
        arch: None,
        signature: None,
        signed_at: None,
        read_only: false,
        build_pipeline: None,
        build_run_id: None,
        build_commit: None,
    };
    entries.push(entry.clone());
    save_catalog(path, &entries)?;
    Ok(entry)
}

/// Replaces machinectl's `remove`. Refuses a `read_only` entry — see
/// [`set_read_only`].
pub fn remove_entry(cfg: &Config, name: &str) -> Result<()> {
    let path = catalog_path(cfg)?;
    let mut entries = load_catalog(path)?;
    if let Some(entry) = entries.iter().find(|e| e.name == name) {
        if entry.read_only {
            bail!("catalog entry '{name}' is read-only; clear it first");
        }
    }
    let before = entries.len();
    entries.retain(|e| e.name != name);
    if entries.len() == before {
        bail!("catalog entry '{name}' not found");
    }
    save_catalog(path, &entries)
}

/// Replaces machinectl's `rename`. Clears any existing signature — a
/// signature covers the entry's name (see `canonical_payload`), so a
/// renamed entry's old signature no longer vouches for it. Refuses a
/// `read_only` entry, same as [`remove_entry`].
pub fn rename_entry(cfg: &Config, name: &str, new_name: &str) -> Result<CatalogEntry> {
    let path = catalog_path(cfg)?;
    let mut entries = load_catalog(path)?;
    if name != new_name && entries.iter().any(|e| e.name == new_name) {
        bail!("catalog entry '{new_name}' already exists");
    }
    let entry = entries
        .iter_mut()
        .find(|e| e.name == name)
        .with_context(|| format!("catalog entry '{name}' not found"))?;
    if entry.read_only {
        bail!("catalog entry '{name}' is read-only; clear it first");
    }
    entry.name = new_name.to_string();
    entry.signature = None;
    entry.signed_at = None;
    let updated = entry.clone();
    save_catalog(path, &entries)?;
    Ok(updated)
}

/// Toggle an entry's `read_only` flag. Replaces machinectl's per-image
/// read-only bit — used to protect a base image other entries are cloned
/// from ([`clone_entry`] itself is unaffected either way, since cloning
/// doesn't mutate the source).
pub fn set_read_only(cfg: &Config, name: &str, read_only: bool) -> Result<CatalogEntry> {
    let path = catalog_path(cfg)?;
    let mut entries = load_catalog(path)?;
    let entry = entries
        .iter_mut()
        .find(|e| e.name == name)
        .with_context(|| format!("catalog entry '{name}' not found"))?;
    entry.read_only = read_only;
    let updated = entry.clone();
    save_catalog(path, &entries)?;
    Ok(updated)
}

/// Replaces machinectl's `clean`: removes cached downloads under
/// `state_dir/downloads` that no current catalog entry's `source` still
/// references by filename — the download cache's only orphans, since
/// entries themselves are never "hidden," unlike machinectl's per-machine
/// image cache. Returns the filenames removed.
pub fn clean_downloads(cfg: &Config) -> Result<Vec<String>> {
    let downloads = cfg.state_dir.join("downloads");
    if !downloads.exists() {
        return Ok(Vec::new());
    }
    let referenced: std::collections::HashSet<String> = match &cfg.catalog.path {
        Some(path) if path.exists() => load_catalog(path)?
            .into_iter()
            .filter_map(|e| {
                e.source
                    .rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
            })
            .collect(),
        _ => std::collections::HashSet::new(),
    };
    let mut removed = Vec::new();
    for entry in
        fs::read_dir(&downloads).with_context(|| format!("reading {}", downloads.display()))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if referenced.contains(&name) {
            continue;
        }
        fs::remove_file(entry.path())
            .with_context(|| format!("removing {}", entry.path().display()))?;
        removed.push(name);
    }
    Ok(removed)
}

/// Replaces machinectl's `clone`. The clone is unsigned, same reasoning as
/// `rename_entry`.
pub fn clone_entry(cfg: &Config, name: &str, target_name: &str) -> Result<CatalogEntry> {
    let path = catalog_path(cfg)?;
    let mut entries = load_catalog(path)?;
    if entries.iter().any(|e| e.name == target_name) {
        bail!("catalog entry '{target_name}' already exists");
    }
    let source_entry = entries
        .iter()
        .find(|e| e.name == name)
        .with_context(|| format!("catalog entry '{name}' not found"))?
        .clone();
    let cloned = CatalogEntry {
        name: target_name.to_string(),
        signature: None,
        signed_at: None,
        ..source_entry
    };
    entries.push(cloned.clone());
    save_catalog(path, &entries)?;
    Ok(cloned)
}

/// Replaces machinectl's `export-raw`: copies the entry's resolved local
/// file (fetching it first if `source` is a URL not yet cached) to `dest`.
pub async fn export_entry(cfg: &Config, name: &str, dest: &Path) -> Result<()> {
    let path = catalog_path(cfg)?;
    let entries = load_catalog(path)?;
    let entry = entries
        .iter()
        .find(|e| e.name == name)
        .with_context(|| format!("catalog entry '{name}' not found"))?;
    let local = fetch_if_needed(cfg, &entry.source).await?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::copy(&local, dest)
        .with_context(|| format!("copying {} to {}", local.display(), dest.display()))?;
    Ok(())
}

fn parse_public_key(b64: &str) -> Result<VerifyingKey> {
    let bytes = B64
        .decode(b64)
        .context("trusted_signers entry is not valid base64")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("public key must be 32 bytes, got {}", v.len()))?;
    VerifyingKey::from_bytes(&arr).context("invalid Ed25519 public key")
}

/// Parses every `[[catalog.trusted_signers]]` entry's own `public_key`
/// once, paired with its `name` -- shared by both `resolve` and
/// `list_with_verification` rather than each re-parsing independently.
fn parse_trusted_signers(
    signers: &[fluxvm_core::config::TrustedSigner],
) -> Result<Vec<(String, VerifyingKey)>> {
    signers
        .iter()
        .map(|s| Ok((s.name.clone(), parse_public_key(&s.public_key)?)))
        .collect::<Result<_>>()
        .context("parsing config.catalog.trusted_signers")
}

/// Verifies `entry`'s signature against every configured trusted signer,
/// returning the **name** of whichever one actually matched on success --
/// real signer identity, derived fresh here from which key verified,
/// never trusted from anything the signed payload itself claims (the
/// payload has no signer-identity field at all, deliberately -- a signer
/// asserting its own name would be trivially forgeable).
fn verify_signature<'a>(
    entry: &CatalogEntry,
    trusted: &'a [(String, VerifyingKey)],
) -> Result<&'a str> {
    let sig_b64 = entry.signature.as_deref().with_context(|| {
        format!(
            "catalog entry '{}' has no signature, but trusted_signers is configured",
            entry.name
        )
    })?;
    let sig_bytes = B64
        .decode(sig_b64)
        .context("signature is not valid base64")?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("signature must be 64 bytes, got {}", v.len()))?;
    let sig = Signature::from_bytes(&sig_arr);
    let payload = canonical_payload(entry);
    trusted
        .iter()
        .find(|(_, key)| key.verify(payload.as_bytes(), &sig).is_ok())
        .map(|(name, _)| name.as_str())
        .with_context(|| {
            format!(
                "catalog entry '{}' signature does not match any configured trusted_signers",
                entry.name
            )
        })
}

/// Resolves `image_ref` against the configured catalog:
/// - No `catalog.path` configured, or `image_ref` doesn't match any entry's
///   `name` there → returned unchanged (a plain path/URL, the pre-catalog
///   behavior — fully backward compatible).
/// - A matching entry, `catalog.trusted_signers` non-empty → the entry
///   *must* carry a valid signature from one of those keys, or this fails
///   closed (no silent fallback to "unsigned is fine").
/// - A matching entry (signature check passed or not required) → fetched
///   (if a URL; cached the same way `build_image` already caches downloads)
///   and its content re-verified against `sha256` — even a local `source`
///   path is re-hashed here, so a file that changed after the catalog was
///   authored is caught rather than silently trusted.
pub async fn resolve(cfg: &Config, image_ref: &Path) -> Result<PathBuf> {
    let Some(catalog_path) = &cfg.catalog.path else {
        return Ok(image_ref.to_path_buf());
    };
    let Some(ref_str) = image_ref.to_str() else {
        return Ok(image_ref.to_path_buf());
    };
    // A configured-but-not-yet-created catalog matches nothing — every
    // image_ref passes through unchanged, same as catalog.path being unset.
    if !catalog_path.exists() {
        return Ok(image_ref.to_path_buf());
    }

    let catalog = load_catalog(catalog_path)?;
    let Some(entry) = catalog.iter().find(|e| e.name == ref_str) else {
        return Ok(image_ref.to_path_buf());
    };

    if !cfg.catalog.trusted_signers.is_empty() {
        let signers = parse_trusted_signers(&cfg.catalog.trusted_signers)?;
        verify_signature(entry, &signers)?;
    }

    let local = fetch_if_needed(cfg, &entry.source)
        .await
        .with_context(|| format!("fetching catalog entry '{}'", entry.name))?;
    verify_sha256(&local, &entry.sha256).with_context(|| {
        format!(
            "catalog entry '{}' failed checksum verification",
            entry.name
        )
    })?;
    if !cfg.catalog.cosign_identities.is_empty() {
        verify_cosign(&local, &cfg.catalog.cosign_identities)
            .with_context(|| format!("cosign verify for catalog entry '{}'", entry.name))?;
    }
    Ok(local)
}

/// Shell out to `cosign verify-blob` when `cosign_identities` is configured.
fn verify_cosign(path: &Path, identities: &[String]) -> Result<()> {
    use std::process::Command;
    for identity in identities {
        let status = Command::new("cosign")
            .args([
                "verify-blob",
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                &path.display().to_string(),
            ])
            .status()
            .context("spawning cosign (install cosign or clear catalog.cosign_identities)")?;
        if status.success() {
            return Ok(());
        }
    }
    bail!(
        "cosign verify-blob failed for {} against identities {:?}",
        path.display(),
        identities
    );
}

#[derive(Debug, Clone, Serialize)]
pub struct CatalogListEntry {
    #[serde(flatten)]
    pub entry: CatalogEntry,
    /// `None` when `trusted_signers` is empty (signatures aren't required,
    /// so this is meaningless); otherwise whether the entry's signature
    /// verified against at least one configured trusted signer.
    pub signature_valid: Option<bool>,
    /// The matched trusted signer's own configured `name` when
    /// `signature_valid == Some(true)`; `None` otherwise (unsigned,
    /// signature didn't match anything, or signatures aren't required at
    /// all) -- real identity derived from which key verified, not
    /// something the entry itself claims about its own signer.
    pub signed_by: Option<String>,
}

/// Backs `GET /v1/images/catalog`: every entry alongside whether its
/// signature actually checks out against the configured trusted signers —
/// lets an operator audit the catalog without re-deriving verification
/// logic client-side.
pub fn list_with_verification(cfg: &Config) -> Result<Vec<CatalogListEntry>> {
    let Some(catalog_path) = &cfg.catalog.path else {
        return Ok(Vec::new());
    };
    // A configured-but-not-yet-created catalog is an empty catalog, not an
    // error — nothing has called add_entry yet.
    if !catalog_path.exists() {
        return Ok(Vec::new());
    }
    let catalog = load_catalog(catalog_path)?;
    let signers = parse_trusted_signers(&cfg.catalog.trusted_signers)?;
    Ok(catalog
        .into_iter()
        .map(|entry| {
            let (signature_valid, signed_by) = if signers.is_empty() {
                (None, None)
            } else {
                match verify_signature(&entry, &signers) {
                    Ok(name) => (Some(true), Some(name.to_string())),
                    Err(_) => (Some(false), None),
                }
            };
            CatalogListEntry {
                entry,
                signature_valid,
                signed_by,
            }
        })
        .collect())
}

/// `fluxvm catalog keygen`: a fresh Ed25519 keypair, both halves
/// base64-encoded. The private key never touches disk here — the caller
/// (CLI) decides where it's stored; this project has no opinion beyond "not
/// silently, not in the catalog file itself."
pub fn generate_keypair() -> (String, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let private_b64 = B64.encode(signing_key.to_bytes());
    let public_b64 = B64.encode(signing_key.verifying_key().to_bytes());
    (private_b64, public_b64)
}

/// `fluxvm catalog sign`: builds a `CatalogEntry` from the given fields
/// and signs it with `private_key_b64` (as produced by
/// [`generate_keypair`]), ready to append to a catalog file's JSON array.
#[allow(clippy::too_many_arguments)]
pub fn sign_entry(
    private_key_b64: &str,
    name: String,
    source: String,
    sha256: String,
    format: String,
    distro: Option<String>,
    version: Option<String>,
    arch: Option<String>,
    build_pipeline: Option<String>,
    build_run_id: Option<String>,
    build_commit: Option<String>,
) -> Result<CatalogEntry> {
    let key_bytes = B64
        .decode(private_key_b64)
        .context("private key is not valid base64")?;
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("private key must be 32 bytes, got {}", v.len()))?;
    let signing_key = SigningKey::from_bytes(&key_arr);

    let mut entry = CatalogEntry {
        name,
        source,
        sha256,
        format,
        distro,
        version,
        arch,
        signature: None,
        // Asserted now, before computing the payload below, so it's
        // covered by the signature itself (tamper-evident) rather than
        // free-form, unverified metadata.
        signed_at: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        ),
        read_only: false,
        build_pipeline,
        build_run_id,
        build_commit,
    };
    let signature = signing_key.sign(canonical_payload(&entry).as_bytes());
    entry.signature = Some(B64.encode(signature.to_bytes()));
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_core::config::{CatalogConfig, Config};
    use sha2::Digest;

    fn cfg_with_catalog(path: &Path, trusted_signer_keys: Vec<String>) -> Config {
        Config {
            catalog: CatalogConfig {
                path: Some(path.to_path_buf()),
                trusted_signers: trusted_signer_keys
                    .into_iter()
                    .enumerate()
                    .map(|(i, public_key)| fluxvm_core::config::TrustedSigner {
                        name: format!("test-signer-{i}"),
                        public_key,
                    })
                    .collect(),
                cosign_identities: vec![],
            },
            ..Config::default()
        }
    }

    fn write_catalog(dir: &Path, entries: &[CatalogEntry]) -> PathBuf {
        let path = dir.join("catalog.json");
        fs::write(&path, serde_json::to_vec_pretty(entries).unwrap()).unwrap();
        path
    }

    #[tokio::test]
    async fn unconfigured_catalog_passes_the_reference_through_unchanged() {
        let cfg = Config::default(); // catalog.path is None
        let resolved = resolve(&cfg, Path::new("/some/literal/path.qcow2"))
            .await
            .unwrap();
        assert_eq!(resolved, PathBuf::from("/some/literal/path.qcow2"));
    }

    #[tokio::test]
    async fn non_matching_reference_passes_through_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let catalog_path = write_catalog(dir.path(), &[]);
        let cfg = cfg_with_catalog(&catalog_path, vec![]);
        let resolved = resolve(&cfg, Path::new("not-in-the-catalog"))
            .await
            .unwrap();
        assert_eq!(resolved, PathBuf::from("not-in-the-catalog"));
    }

    #[tokio::test]
    async fn matching_unsigned_entry_resolves_and_verifies_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let image_path = dir.path().join("base.qcow2");
        fs::write(&image_path, b"fake-image-bytes").unwrap();
        let sha256 = format!("{:x}", sha2::Sha256::digest(b"fake-image-bytes"));

        let catalog_path = write_catalog(
            dir.path(),
            &[CatalogEntry {
                name: "test-image".into(),
                source: image_path.display().to_string(),
                sha256,
                format: "qcow2".into(),
                distro: None,
                version: None,
                arch: None,
                signature: None,
                signed_at: None,
                read_only: false,
                build_pipeline: None,
                build_run_id: None,
                build_commit: None,
            }],
        );
        let cfg = cfg_with_catalog(&catalog_path, vec![]); // no trusted_signers -> signature not required

        let resolved = resolve(&cfg, Path::new("test-image")).await.unwrap();
        assert_eq!(resolved, image_path);
    }

    #[tokio::test]
    async fn tampered_content_fails_checksum_even_though_it_matched_the_catalog_name() {
        let dir = tempfile::tempdir().unwrap();
        let image_path = dir.path().join("base.qcow2");
        fs::write(&image_path, b"original-bytes").unwrap();
        let sha256_of_original = format!("{:x}", sha2::Sha256::digest(b"original-bytes"));

        let catalog_path = write_catalog(
            dir.path(),
            &[CatalogEntry {
                name: "test-image".into(),
                source: image_path.display().to_string(),
                sha256: sha256_of_original,
                format: "qcow2".into(),
                distro: None,
                version: None,
                arch: None,
                signature: None,
                signed_at: None,
                read_only: false,
                build_pipeline: None,
                build_run_id: None,
                build_commit: None,
            }],
        );
        let cfg = cfg_with_catalog(&catalog_path, vec![]);

        fs::write(&image_path, b"tampered-bytes-different-length!!").unwrap();
        let err = resolve(&cfg, Path::new("test-image")).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("checksum"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let (private_b64, public_b64) = generate_keypair();
        let entry = sign_entry(
            &private_b64,
            "ubuntu-24.04".into(),
            "https://example.invalid/ubuntu.qcow2".into(),
            "abc123".into(),
            "qcow2".into(),
            Some("ubuntu".into()),
            Some("24.04".into()),
            Some("x86_64".into()),
            Some("github-actions/build-images.yml".into()),
            Some("123456789".into()),
            Some("deadbeefcafef00d".into()),
        )
        .unwrap();

        let key = parse_public_key(&public_b64).unwrap();
        assert!(verify_signature(&entry, &[("k".to_string(), key)]).is_ok());
        assert_eq!(
            entry.build_pipeline.as_deref(),
            Some("github-actions/build-images.yml")
        );
        assert_eq!(entry.build_run_id.as_deref(), Some("123456789"));
        assert_eq!(entry.build_commit.as_deref(), Some("deadbeefcafef00d"));
    }

    #[test]
    fn verify_rejects_a_signature_from_the_wrong_key() {
        let (private_b64, _public_b64) = generate_keypair();
        let (_other_private, other_public_b64) = generate_keypair();
        let entry = sign_entry(
            &private_b64,
            "n".into(),
            "s".into(),
            "h".into(),
            "qcow2".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

        let wrong_key = parse_public_key(&other_public_b64).unwrap();
        assert!(verify_signature(&entry, &[("k".to_string(), wrong_key)]).is_err());
    }

    #[test]
    fn verify_rejects_a_tampered_field_even_with_a_valid_signature_present() {
        let (private_b64, public_b64) = generate_keypair();
        let mut entry = sign_entry(
            &private_b64,
            "n".into(),
            "s".into(),
            "h".into(),
            "qcow2".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        entry.sha256 = "different-hash-than-what-was-signed".into();

        let key = parse_public_key(&public_b64).unwrap();
        assert!(verify_signature(&entry, &[("k".to_string(), key)]).is_err());
    }

    #[test]
    fn verify_rejects_a_tampered_metadata_field_even_though_it_used_to_be_unsigned() {
        // distro/version/arch are now covered by canonical_payload -- this
        // is the exact gap that closed: previously these could be edited
        // post-signing without invalidating the signature.
        let (private_b64, public_b64) = generate_keypair();
        let mut entry = sign_entry(
            &private_b64,
            "n".into(),
            "s".into(),
            "h".into(),
            "qcow2".into(),
            Some("ubuntu".into()),
            Some("24.04".into()),
            Some("x86_64".into()),
            None,
            None,
            None,
        )
        .unwrap();
        entry.arch = Some("aarch64".into()); // relabeled after signing

        let key = parse_public_key(&public_b64).unwrap();
        assert!(verify_signature(&entry, &[("k".to_string(), key)]).is_err());
    }

    #[test]
    fn verify_rejects_a_relabeled_build_provenance_field() {
        // build_pipeline/build_run_id/build_commit are covered by
        // canonical_payload -- this is the closed gap: claiming a
        // different pipeline/run/commit produced these bytes after the
        // fact must invalidate the signature, the same way relabeling
        // arch does.
        let (private_b64, public_b64) = generate_keypair();
        let mut entry = sign_entry(
            &private_b64,
            "n".into(),
            "s".into(),
            "h".into(),
            "qcow2".into(),
            None,
            None,
            None,
            Some("github-actions/build-images.yml".into()),
            Some("111".into()),
            Some("abc123".into()),
        )
        .unwrap();
        entry.build_run_id = Some("999".into()); // relabeled after signing

        let key = parse_public_key(&public_b64).unwrap();
        assert!(verify_signature(&entry, &[("k".to_string(), key)]).is_err());
    }

    #[test]
    fn verify_rejects_a_backdated_signed_at() {
        let (private_b64, public_b64) = generate_keypair();
        let mut entry = sign_entry(
            &private_b64,
            "n".into(),
            "s".into(),
            "h".into(),
            "qcow2".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        entry.signed_at = entry.signed_at.map(|t| t - 100_000); // backdated after signing

        let key = parse_public_key(&public_b64).unwrap();
        assert!(verify_signature(&entry, &[("k".to_string(), key)]).is_err());
    }

    #[test]
    fn read_only_can_be_toggled_without_invalidating_the_signature() {
        // read_only is deliberately excluded from canonical_payload -- its
        // own dedicated REST route (set_read_only) must keep working on a
        // signed entry without requiring a re-sign.
        let (private_b64, public_b64) = generate_keypair();
        let mut entry = sign_entry(
            &private_b64,
            "n".into(),
            "s".into(),
            "h".into(),
            "qcow2".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let key = parse_public_key(&public_b64).unwrap();
        assert!(verify_signature(&entry, &[("k".to_string(), key)]).is_ok());

        entry.read_only = true;
        assert!(
            verify_signature(&entry, &[("k".to_string(), key)]).is_ok(),
            "toggling read_only must not invalidate the signature"
        );
    }

    #[test]
    fn verify_signature_reports_the_matching_signers_own_name() {
        let (private_b64, public_b64) = generate_keypair();
        let entry = sign_entry(
            &private_b64,
            "n".into(),
            "s".into(),
            "h".into(),
            "qcow2".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let (_other_priv, other_public_b64) = generate_keypair();
        let trusted = vec![
            (
                "decoy".to_string(),
                parse_public_key(&other_public_b64).unwrap(),
            ),
            (
                "release-ci".to_string(),
                parse_public_key(&public_b64).unwrap(),
            ),
        ];
        let matched = verify_signature(&entry, &trusted).unwrap();
        assert_eq!(matched, "release-ci");
    }

    #[test]
    fn sign_entry_stamps_a_recent_signed_at() {
        let (private_b64, _public_b64) = generate_keypair();
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let entry = sign_entry(
            &private_b64,
            "n".into(),
            "s".into(),
            "h".into(),
            "qcow2".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let signed_at = entry.signed_at.expect("sign_entry must set signed_at");
        assert!(
            signed_at >= before && signed_at <= before + 5,
            "expected signed_at ({signed_at}) to be within 5s of {before}"
        );
    }

    #[tokio::test]
    async fn list_with_verification_reports_signed_by_only_when_valid() {
        let dir = tempfile::tempdir().unwrap();
        let (private_b64, public_b64) = generate_keypair();
        let signed = sign_entry(
            &private_b64,
            "signed-image".into(),
            "/irrelevant".into(),
            "irrelevant".into(),
            "qcow2".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let unsigned = CatalogEntry {
            name: "unsigned-image".into(),
            source: "/irrelevant".into(),
            sha256: "irrelevant".into(),
            format: "qcow2".into(),
            distro: None,
            version: None,
            arch: None,
            signature: None,
            signed_at: None,
            read_only: false,
            build_pipeline: None,
            build_run_id: None,
            build_commit: None,
        };
        let catalog_path = write_catalog(dir.path(), &[signed, unsigned]);
        let cfg = cfg_with_catalog(&catalog_path, vec![public_b64]);

        let listed = list_with_verification(&cfg).unwrap();
        let signed_entry = listed
            .iter()
            .find(|e| e.entry.name == "signed-image")
            .unwrap();
        assert_eq!(signed_entry.signature_valid, Some(true));
        assert_eq!(signed_entry.signed_by.as_deref(), Some("test-signer-0"));

        let unsigned_entry = listed
            .iter()
            .find(|e| e.entry.name == "unsigned-image")
            .unwrap();
        assert_eq!(unsigned_entry.signature_valid, Some(false));
        assert_eq!(unsigned_entry.signed_by, None);
    }

    #[test]
    fn clone_and_rename_drop_signed_at_alongside_the_signature() {
        let dir = tempfile::tempdir().unwrap();
        let (private_b64, _public_b64) = generate_keypair();
        let signed = sign_entry(
            &private_b64,
            "base".into(),
            "/irrelevant".into(),
            "irrelevant".into(),
            "qcow2".into(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(signed.signed_at.is_some());
        let catalog_path = write_catalog(dir.path(), &[signed]);
        let cfg = cfg_with_catalog(&catalog_path, vec![]);

        let cloned = clone_entry(&cfg, "base", "base-clone").unwrap();
        assert!(cloned.signature.is_none());
        assert!(cloned.signed_at.is_none());

        let renamed = rename_entry(&cfg, "base", "base-renamed").unwrap();
        assert!(renamed.signature.is_none());
        assert!(renamed.signed_at.is_none());
    }

    #[tokio::test]
    async fn resolve_fails_closed_when_trusted_signers_configured_but_entry_unsigned() {
        let dir = tempfile::tempdir().unwrap();
        let (_priv, public_b64) = generate_keypair();
        let catalog_path = write_catalog(
            dir.path(),
            &[CatalogEntry {
                name: "test-image".into(),
                source: "/irrelevant".into(),
                sha256: "irrelevant".into(),
                format: "qcow2".into(),
                distro: None,
                version: None,
                arch: None,
                signature: None, // unsigned
                signed_at: None,
                read_only: false,
                build_pipeline: None,
                build_run_id: None,
                build_commit: None,
            }],
        );
        let cfg = cfg_with_catalog(&catalog_path, vec![public_b64]);

        let err = resolve(&cfg, Path::new("test-image")).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("no signature"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn read_only_entry_refuses_remove_and_rename() {
        let dir = tempfile::tempdir().unwrap();
        let catalog_path = write_catalog(
            dir.path(),
            &[CatalogEntry {
                name: "base".into(),
                source: "/irrelevant".into(),
                sha256: "irrelevant".into(),
                format: "qcow2".into(),
                distro: None,
                version: None,
                arch: None,
                signature: None,
                signed_at: None,
                read_only: false,
                build_pipeline: None,
                build_run_id: None,
                build_commit: None,
            }],
        );
        let cfg = cfg_with_catalog(&catalog_path, vec![]);

        set_read_only(&cfg, "base", true).unwrap();
        assert!(
            remove_entry(&cfg, "base")
                .unwrap_err()
                .to_string()
                .contains("read-only")
        );
        assert!(
            rename_entry(&cfg, "base", "base2")
                .unwrap_err()
                .to_string()
                .contains("read-only")
        );

        set_read_only(&cfg, "base", false).unwrap();
        remove_entry(&cfg, "base").unwrap();
    }

    #[tokio::test]
    async fn clean_downloads_removes_only_unreferenced_files() {
        let dir = tempfile::tempdir().unwrap();
        let downloads = dir.path().join("downloads");
        fs::create_dir_all(&downloads).unwrap();
        fs::write(downloads.join("kept.qcow2"), b"kept").unwrap();
        fs::write(downloads.join("orphan.qcow2"), b"orphan").unwrap();

        let catalog_path = write_catalog(
            dir.path(),
            &[CatalogEntry {
                name: "kept".into(),
                source: "https://example.invalid/kept.qcow2".into(),
                sha256: "irrelevant".into(),
                format: "qcow2".into(),
                distro: None,
                version: None,
                arch: None,
                signature: None,
                signed_at: None,
                read_only: false,
                build_pipeline: None,
                build_run_id: None,
                build_commit: None,
            }],
        );
        let cfg = Config {
            state_dir: dir.path().to_path_buf(),
            catalog: CatalogConfig {
                path: Some(catalog_path),
                trusted_signers: vec![],
                cosign_identities: vec![],
            },
            ..Config::default()
        };

        let removed = clean_downloads(&cfg).unwrap();
        assert_eq!(removed, vec!["orphan.qcow2".to_string()]);
        assert!(downloads.join("kept.qcow2").exists());
        assert!(!downloads.join("orphan.qcow2").exists());
    }
}
