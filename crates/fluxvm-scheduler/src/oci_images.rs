// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! OCI images for `vz` sandboxes: pull from a registry (pure Rust, digest-verified), then build each platform
//! manifest's ext4 rootfs once in a short-lived builder VM and cache it under `<state_dir>/oci/rootfs/<hex>.ext4`.
//! Sandboxes boot APFS clones of the cached disk, so a second sandbox of the same image costs no copy.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::{Config, OciRegistryCredential};
use fluxvm_image::oci_registry::{
    BlobStore, Credentials, ImageConfig, ImageRef, Layer, PulledImage, Puller,
};
use fluxvm_oci_init::config as init;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

/// VM label naming the manifest digest a sandbox was booted from; `prune` keeps these images.
pub const OCI_LABEL: &str = "fluxvm.oci";
/// Longest a builder VM may run before it is killed.
const BUILD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MIB: u64 = 1024 * 1024;

/// A cached rootfs, as `fluxctl oci ls` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciImageEntry {
    pub manifest_digest: String,
    /// Every reference that resolved to this digest, most recent first.
    pub references: Vec<String>,
    pub config_digest: String,
    pub config: ImageConfig,
    pub layers: Vec<Layer>,
    /// Apparent size of the ext4 image (sparse; see `disk_bytes`).
    pub size_bytes: u64,
    /// Bytes actually allocated on the host.
    #[serde(default)]
    pub disk_bytes: u64,
    pub built_at: u64,
    pub last_used: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciPruneReport {
    pub removed_images: Vec<String>,
    pub removed_blobs: usize,
    pub freed_bytes: u64,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn rootfs_dir(cfg: &Config) -> PathBuf {
    cfg.state_dir.join("oci").join("rootfs")
}

fn digest_hex(digest: &str) -> Result<&str> {
    let hex = digest
        .strip_prefix("sha256:")
        .with_context(|| format!("{digest:?} is not a sha256 digest"))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!("{digest:?} is not a sha256 digest");
    }
    Ok(hex)
}

pub fn rootfs_path(cfg: &Config, manifest_digest: &str) -> Result<PathBuf> {
    Ok(rootfs_dir(cfg).join(format!("{}.ext4", digest_hex(manifest_digest)?)))
}

fn entry_path(cfg: &Config, manifest_digest: &str) -> Result<PathBuf> {
    Ok(rootfs_dir(cfg).join(format!("{}.json", digest_hex(manifest_digest)?)))
}

/// Room for the unpacked layers: compressed size × 4 plus headroom, at least 1 GiB. The file is sparse.
pub fn rootfs_size_bytes(image: &PulledImage) -> u64 {
    let want = image
        .compressed_size()
        .saturating_mul(4)
        .saturating_add(512 * MIB);
    want.max(1024 * MIB).div_ceil(MIB) * MIB
}

/// Pulls `reference` (anonymously, or with a matching `apple.oci_registry_credentials` entry) into the blob store.
pub async fn pull(cfg: &Config, reference: &str) -> Result<PulledImage> {
    let registry = ImageRef::parse(reference)?.registry;
    let creds = match cfg
        .apple
        .oci_registry_credentials
        .iter()
        .find(|c| c.registry == registry)
    {
        Some(c) => Some(Credentials {
            username: c.username.clone(),
            password: registry_password(c).await?,
        }),
        None => None,
    };
    Puller::new(BlobStore::for_state_dir(&cfg.state_dir))?
        .with_credentials(creds)
        .pull(reference)
        .await
        .with_context(|| format!("pulling {reference}"))
}

/// The inline password, or the one stored in the login Keychain under `keychain_service` / `username`.
async fn registry_password(c: &OciRegistryCredential) -> Result<String> {
    let service = match (&c.keychain_service, c.password.is_empty()) {
        (None, _) => return Ok(c.password.clone()),
        (Some(_), false) => bail!(
            "registry credential for {} sets both password and keychain_service",
            c.registry
        ),
        (Some(s), true) => s,
    };
    let out = tokio::process::Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-s",
            service,
            "-a",
            &c.username,
            "-w",
        ])
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .context("running /usr/bin/security")?;
    if !out.status.success() {
        bail!(
            "no Keychain password for service {service:?}, account {:?} ({}); add it with \
             `security add-generic-password -s {service} -a {} -w`",
            c.username,
            String::from_utf8_lossy(&out.stderr).trim(),
            c.username
        );
    }
    let password = String::from_utf8(out.stdout)
        .context("Keychain password is not UTF-8")?
        .trim_end_matches('\n')
        .to_string();
    if password.is_empty() {
        bail!("Keychain item for service {service:?} has an empty password");
    }
    Ok(password)
}

/// One lock per rootfs file, so state dirs (and tests) never share a lock.
static BUILD_LOCKS: LazyLock<Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn build_lock(cfg: &Config, digest: &str) -> Result<Arc<tokio::sync::Mutex<()>>> {
    Ok(BUILD_LOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(rootfs_path(cfg, digest)?)
        .or_default()
        .clone())
}

/// The cached rootfs for `image`, building it first if needed. Concurrent callers for one digest share one build.
pub async fn ensure_rootfs(cfg: &Config, image: &PulledImage) -> Result<PathBuf> {
    let path = rootfs_path(cfg, &image.manifest_digest)?;
    let lock = build_lock(cfg, &image.manifest_digest)?;
    let _held = lock.lock().await;
    if !path.is_file() {
        build_rootfs(cfg, image, &path).await?;
    }
    record_use(cfg, image, &path)?;
    Ok(path)
}

/// Removes a build directory on every exit path.
struct BuildDir(PathBuf);

impl Drop for BuildDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The builder's `config.json`: apply `image`'s layers in order from the blob share.
pub fn unpack_config(image: &PulledImage) -> Result<init::InitConfig> {
    use fluxvm_image::oci_registry::Compression as C;
    let layers = image
        .layers
        .iter()
        .map(|l| {
            Ok(init::UnpackLayer {
                blob: digest_hex(&l.digest)?.to_string(),
                compression: match l.compression {
                    C::None => init::Compression::None,
                    C::Gzip => init::Compression::Gzip,
                    C::Zstd => init::Compression::Zstd,
                },
                diff_id: l.diff_id.clone(),
            })
        })
        .collect::<Result<_>>()?;
    Ok(init::InitConfig::Unpack(init::UnpackConfig { layers }))
}

async fn build_rootfs(cfg: &Config, image: &PulledImage, dest: &Path) -> Result<()> {
    let boot = fluxvm_image::oci_boot::resolve(cfg).await?;
    let store = BlobStore::for_state_dir(&cfg.state_dir);
    for l in &image.layers {
        if !store.has(&l.digest) {
            bail!(
                "layer {} of {} is not in the blob store; pull it again",
                l.digest,
                image.reference
            );
        }
    }
    let hex = digest_hex(&image.manifest_digest)?;
    let work = BuildDir(cfg.state_dir.join("oci").join("build").join(format!(
        "{}-{}",
        &hex[..12],
        uuid::Uuid::new_v4().simple()
    )));
    let meta = work.0.join("meta");
    std::fs::create_dir_all(&meta).with_context(|| format!("creating {}", meta.display()))?;
    std::fs::write(
        meta.join(init::CONFIG_FILE),
        serde_json::to_vec(&unpack_config(image)?)?,
    )?;
    let disk = work.0.join("disk.raw");
    std::fs::File::create(&disk)
        .and_then(|f| f.set_len(rootfs_size_bytes(image)))
        .with_context(|| format!("creating {}", disk.display()))?;

    let vm = fluxvm_apple::OneShotVm {
        workspace: work.0.clone(),
        disk: disk.clone(),
        kernel: boot.kernel,
        initrd: boot.initrd,
        cmdline: boot.cmdline,
        cpus: 2,
        memory_mib: cfg.apple.oci_builder_memory_mib.max(256),
        shares: vec![
            fluxvm_apple::ShareConfig {
                tag: init::META_TAG.into(),
                host_path: meta,
                read_only: true,
            },
            fluxvm_apple::ShareConfig {
                tag: init::BLOBS_TAG.into(),
                host_path: store.blobs_dir(),
                read_only: true,
            },
        ],
    };
    tracing::info!(image = %image.reference, digest = %image.manifest_digest, "building OCI rootfs");
    let serial = vm
        .run(BUILD_TIMEOUT)
        .await
        .context("running the rootfs builder VM")?;
    match init::unpack_result_from_log(&serial) {
        Some(Ok(())) => {}
        Some(Err(reason)) => bail!("building the rootfs for {}: {reason}", image.reference),
        None => bail!(
            "the rootfs builder for {} stopped without a result; console tail: {}",
            image.reference,
            tail(&serial, 8)
        ),
    }
    std::fs::create_dir_all(rootfs_dir(cfg))?;
    std::fs::rename(&disk, dest)
        .with_context(|| format!("moving the rootfs to {}", dest.display()))?;
    Ok(())
}

pub(crate) fn tail(log: &str, lines: usize) -> String {
    let v: Vec<&str> = log.lines().rev().take(lines).collect();
    v.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

fn allocated_bytes(p: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).map_or(0, |m| m.blocks() * 512)
}

fn record_use(cfg: &Config, image: &PulledImage, rootfs: &Path) -> Result<()> {
    let path = entry_path(cfg, &image.manifest_digest)?;
    let t = now();
    let mut entry = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<OciImageEntry>(&b).ok())
        .unwrap_or_else(|| OciImageEntry {
            manifest_digest: image.manifest_digest.clone(),
            references: Vec::new(),
            config_digest: image.config_digest.clone(),
            config: image.config.clone(),
            layers: image.layers.clone(),
            size_bytes: 0,
            disk_bytes: 0,
            built_at: t,
            last_used: t,
        });
    entry.references.retain(|r| r != &image.reference);
    entry.references.insert(0, image.reference.clone());
    entry.last_used = t;
    entry.size_bytes = std::fs::metadata(rootfs).map_or(0, |m| m.len());
    entry.disk_bytes = allocated_bytes(rootfs);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&entry)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Cached images, most recently used first.
pub fn list(cfg: &Config) -> Result<Vec<OciImageEntry>> {
    let dir = rootfs_dir(cfg);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let Ok(entry) = serde_json::from_slice::<OciImageEntry>(&std::fs::read(&p)?) else {
            continue;
        };
        if rootfs_path(cfg, &entry.manifest_digest).is_ok_and(|r| r.is_file()) {
            out.push(entry);
        }
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.last_used));
    Ok(out)
}

/// Finds a cached image by full digest, an unambiguous hex prefix (12+ characters), or a reference it was pulled as.
pub fn find(cfg: &Config, what: &str) -> Result<OciImageEntry> {
    let all = list(cfg)?;
    let prefix = what.strip_prefix("sha256:").unwrap_or(what);
    let hits: Vec<&OciImageEntry> = all
        .iter()
        .filter(|e| {
            e.manifest_digest == what
                || (prefix.len() >= 12 && e.manifest_digest["sha256:".len()..].starts_with(prefix))
                || e.references.iter().any(|r| r == what)
        })
        .collect();
    match hits.as_slice() {
        [one] => Ok((*one).clone()),
        [] => bail!("no cached OCI image matches {what:?}"),
        _ => bail!(
            "{what:?} matches {} cached OCI images; use the full digest",
            hits.len()
        ),
    }
}

fn remove_entry(cfg: &Config, digest: &str) -> Result<u64> {
    let rootfs = rootfs_path(cfg, digest)?;
    let freed = allocated_bytes(&rootfs);
    for p in [rootfs, entry_path(cfg, digest)?] {
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", p.display())),
        }
    }
    Ok(freed)
}

/// Removes one cached rootfs. Running sandboxes keep their own clones and are not affected.
pub fn remove(cfg: &Config, what: &str) -> Result<OciImageEntry> {
    let entry = find(cfg, what)?;
    let lock = build_lock(cfg, &entry.manifest_digest)?;
    let _held = lock
        .try_lock()
        .map_err(|_| anyhow::anyhow!("{what} is being built"))?;
    remove_entry(cfg, &entry.manifest_digest)?;
    Ok(entry)
}

/// Removes every cached rootfs not in `in_use` (digests of existing sandboxes), then every blob no remaining image needs.
pub fn prune(cfg: &Config, in_use: &HashSet<String>) -> Result<OciPruneReport> {
    let mut report = OciPruneReport::default();
    let mut keep_blobs: HashSet<String> = HashSet::new();
    for e in list(cfg)? {
        let lock = build_lock(cfg, &e.manifest_digest)?;
        let busy = lock.try_lock().is_err();
        if in_use.contains(&e.manifest_digest) || busy {
            keep_blobs.insert(e.config_digest.clone());
            keep_blobs.extend(e.layers.iter().map(|l| l.digest.clone()));
            continue;
        }
        report.freed_bytes += remove_entry(cfg, &e.manifest_digest)?;
        report.removed_images.push(e.manifest_digest);
    }
    // A build in progress has no entry yet; its blobs must survive.
    let dir = rootfs_dir(cfg);
    if BUILD_LOCKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|(path, l)| path.starts_with(&dir) && l.try_lock().is_err())
    {
        return Ok(report);
    }
    let store = BlobStore::for_state_dir(&cfg.state_dir);
    if let Ok(rd) = std::fs::read_dir(store.blobs_dir()) {
        for b in rd.flatten() {
            let name = b.file_name().to_string_lossy().into_owned();
            if keep_blobs.contains(&format!("sha256:{name}")) {
                continue;
            }
            report.freed_bytes += allocated_bytes(&b.path());
            std::fs::remove_file(b.path())?;
            report.removed_blobs += 1;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_image::oci_registry::Compression;

    fn digest(c: char) -> String {
        format!("sha256:{}", c.to_string().repeat(64))
    }

    #[tokio::test]
    async fn registry_passwords_come_inline_or_from_one_keychain_item() {
        let parsed: OciRegistryCredential = serde_json::from_str(
            r#"{"registry":"ghcr.io","username":"me","keychain_service":"fluxvm-ghcr"}"#,
        )
        .unwrap();
        assert!(parsed.password.is_empty());
        assert_eq!(parsed.keychain_service.as_deref(), Some("fluxvm-ghcr"));

        let inline = OciRegistryCredential {
            registry: "ghcr.io".into(),
            username: "me".into(),
            password: "tok".into(),
            keychain_service: None,
        };
        assert_eq!(registry_password(&inline).await.unwrap(), "tok");
        let both = OciRegistryCredential {
            keychain_service: Some("fluxvm-ghcr".into()),
            ..inline
        };
        assert!(registry_password(&both).await.is_err());
    }

    fn image(m: char) -> PulledImage {
        PulledImage {
            reference: format!("docker.io/library/test-{m}:latest"),
            manifest_digest: digest(m),
            config_digest: digest('c'),
            config: ImageConfig::default(),
            layers: vec![Layer {
                digest: digest('1'),
                size: 300 * MIB,
                compression: Compression::Gzip,
                diff_id: digest('2'),
            }],
        }
    }

    fn cfg(dir: &Path) -> Config {
        Config {
            state_dir: dir.to_path_buf(),
            ..Config::default()
        }
    }

    fn seed(cfg: &Config, img: &PulledImage) {
        let p = rootfs_path(cfg, &img.manifest_digest).unwrap();
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"ext4").unwrap();
        record_use(cfg, img, &p).unwrap();
    }

    #[test]
    fn digests_and_sizes() {
        assert!(digest_hex(&digest('a')).is_ok());
        for bad in [
            "sha256:abc",
            "sha512:aa",
            &format!("sha256:{}", "A".repeat(64)),
            "sha256:../../x",
        ] {
            assert!(digest_hex(bad).is_err(), "{bad}");
        }
        let i = image('a');
        assert_eq!(rootfs_size_bytes(&i), 1712 * MIB);
        let tiny = PulledImage {
            layers: vec![],
            ..i
        };
        assert_eq!(rootfs_size_bytes(&tiny), 1024 * MIB);
    }

    #[test]
    fn unpack_config_maps_layers() {
        let init::InitConfig::Unpack(u) = unpack_config(&image('a')).unwrap() else {
            panic!()
        };
        assert_eq!(u.layers[0].blob, "1".repeat(64));
        assert_eq!(u.layers[0].compression, init::Compression::Gzip);
        assert_eq!(u.layers[0].diff_id, digest('2'));
    }

    #[test]
    fn list_find_remove() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        assert!(list(&c).unwrap().is_empty());
        seed(&c, &image('a'));
        seed(&c, &image('b'));
        let mut again = image('a');
        again.reference = "alpine:3.22".into();
        seed(&c, &again);

        let all = list(&c).unwrap();
        assert_eq!(all.len(), 2);
        let a = find(&c, "alpine:3.22").unwrap();
        assert_eq!(
            a.references,
            ["alpine:3.22", "docker.io/library/test-a:latest"]
        );
        assert_eq!(
            find(&c, &"a".repeat(12)).unwrap().manifest_digest,
            digest('a')
        );
        assert!(find(&c, "aaaa").is_err());
        assert!(find(&c, "nope:1").is_err());

        remove(&c, &digest('b')).unwrap();
        assert_eq!(list(&c).unwrap().len(), 1);
        assert!(!rootfs_path(&c, &digest('b')).unwrap().exists());
    }

    #[test]
    fn prune_keeps_in_use_images_and_their_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let c = cfg(dir.path());
        let mut a = image('a');
        a.layers[0].digest = digest('3');
        seed(&c, &a);
        seed(&c, &image('b'));
        let blobs = BlobStore::for_state_dir(&c.state_dir).blobs_dir();
        std::fs::create_dir_all(&blobs).unwrap();
        for d in ['1', '3', 'c', 'f'] {
            std::fs::write(blobs.join(d.to_string().repeat(64)), b"x").unwrap();
        }
        let in_use: HashSet<String> = [digest('a')].into();
        let r = prune(&c, &in_use).unwrap();
        assert_eq!(r.removed_images, [digest('b')]);
        assert_eq!(r.removed_blobs, 2);
        let left: HashSet<String> = std::fs::read_dir(&blobs)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, ["3".repeat(64), "c".repeat(64)].into());
    }
}
