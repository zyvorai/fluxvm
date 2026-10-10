// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Pulls OCI / Docker v2 images into a content-addressed blob store (pure Rust: no skopeo or docker).
//!
//! Every manifest, config and layer is checked against its sha256 digest before it is stored or used, so a
//! cached rootfs keyed by manifest digest always matches what the registry served.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

const DOCKER_HUB: &str = "registry-1.docker.io";
const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;
/// Upper bound for one layer blob (compressed).
pub const MAX_LAYER_BYTES: u64 = 16 * 1024 * 1024 * 1024;

const MT_OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const MT_OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const MT_DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const MT_DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

/// `[registry/]repository[:tag|@digest]`, with Docker Hub's defaults applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRef {
    pub registry: String,
    pub repository: String,
    /// A tag, or a `sha256:` digest.
    pub reference: String,
}

impl ImageRef {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty()
            || s.starts_with('-')
            || s.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            bail!("invalid image reference {s:?}");
        }
        let (name, reference) = if let Some((n, d)) = s.split_once('@') {
            validate_digest(d)?;
            (n, d.to_string())
        } else {
            // A colon after the last slash is a tag; one before it is a registry port.
            match s.rfind(':') {
                Some(i) if i > s.rfind('/').unwrap_or(0) && !s[..i].is_empty() => {
                    (&s[..i], s[i + 1..].to_string())
                }
                _ => (s, "latest".to_string()),
            }
        };
        let (registry, repository) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), rest.to_string())
            }
            _ => (DOCKER_HUB.to_string(), name.to_string()),
        };
        let registry = if registry == "docker.io" || registry == "index.docker.io" {
            DOCKER_HUB.to_string()
        } else {
            registry
        };
        let repository = if registry == DOCKER_HUB && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository
        };
        let repo_ok = !repository.is_empty()
            && repository.split('/').all(|c| {
                c.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
                    && c.bytes().all(|b| {
                        b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || matches!(b, b'.' | b'_' | b'-')
                    })
            });
        if !repo_ok {
            bail!("invalid repository {repository:?} in {s:?}");
        }
        if reference.is_empty()
            || reference.len() > 128
            || !reference
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
        {
            bail!("invalid tag or digest {reference:?} in {s:?}");
        }
        Ok(Self {
            registry,
            repository,
            reference,
        })
    }

    fn base_url(&self) -> String {
        // Plain HTTP only for registries on this machine (a local mirror, or tests).
        let local =
            self.registry.starts_with("localhost") || self.registry.starts_with("127.0.0.1");
        format!(
            "{}://{}/v2/{}",
            if local { "http" } else { "https" },
            self.registry,
            self.repository
        )
    }
}

impl std::fmt::Display for ImageRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sep = if self.reference.starts_with("sha256:") {
            '@'
        } else {
            ':'
        };
        write!(
            f,
            "{}/{}{sep}{}",
            self.registry, self.repository, self.reference
        )
    }
}

fn validate_digest(d: &str) -> Result<&str> {
    let hex = d
        .strip_prefix("sha256:")
        .with_context(|| format!("unsupported digest {d:?} (only sha256)"))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!("malformed digest {d:?}");
    }
    Ok(hex)
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Platform {
    pub architecture: String,
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ManifestDoc {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    #[serde(default)]
    manifests: Vec<Descriptor>,
    #[serde(default)]
    config: Option<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

/// The parts of an image config FluxVM runs: the process and its rootfs layers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageConfig {
    #[serde(rename = "Entrypoint", default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd", default)]
    pub cmd: Option<Vec<String>>,
    #[serde(rename = "Env", default)]
    pub env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir", default)]
    pub working_dir: Option<String>,
    #[serde(rename = "User", default)]
    pub user: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConfigDoc {
    #[serde(default)]
    architecture: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    config: Option<ImageConfig>,
    rootfs: RootFs,
}

#[derive(Debug, Deserialize)]
struct RootFs {
    #[serde(default)]
    diff_ids: Vec<String>,
}

/// Layer compression, as the guest-side unpacker needs to know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    None,
    Gzip,
    Zstd,
}

impl Compression {
    pub fn from_media_type(mt: &str) -> Result<Self> {
        Ok(match mt {
            "application/vnd.oci.image.layer.v1.tar" => Self::None,
            "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.docker.image.rootfs.diff.tar.gzip" => Self::Gzip,
            "application/vnd.oci.image.layer.v1.tar+zstd" => Self::Zstd,
            other => bail!("unsupported layer media type {other:?}"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Layer {
    pub digest: String,
    pub size: u64,
    pub compression: Compression,
    /// sha256 of the uncompressed tar, from the image config.
    pub diff_id: String,
}

fn default_architecture() -> String {
    Arch::Arm64.as_str().into()
}

/// A pulled image: everything needed to build its rootfs and start its process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PulledImage {
    pub reference: String,
    /// Digest of the platform manifest: the cache key for the built rootfs.
    pub manifest_digest: String,
    pub config_digest: String,
    pub config: ImageConfig,
    pub layers: Vec<Layer>,
    /// The image's OCI architecture, `arm64` or `amd64`.
    #[serde(default = "default_architecture")]
    pub architecture: String,
}

impl PulledImage {
    pub fn compressed_size(&self) -> u64 {
        self.layers.iter().map(|l| l.size).sum()
    }
}

/// Content-addressed blobs under `root/blobs/sha256/<hex>`.
#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `state_dir/oci`.
    pub fn for_state_dir(state_dir: &Path) -> Self {
        Self::new(state_dir.join("oci"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs").join("sha256")
    }

    pub fn path(&self, digest: &str) -> Result<PathBuf> {
        Ok(self.blobs_dir().join(validate_digest(digest)?))
    }

    pub fn has(&self, digest: &str) -> bool {
        self.path(digest).is_ok_and(|p| p.is_file())
    }

    /// Stores `bytes` after checking they hash to `digest`.
    pub fn put(&self, digest: &str, bytes: &[u8]) -> Result<PathBuf> {
        let got = sha256_digest(bytes);
        if got != digest {
            bail!("digest mismatch: expected {digest}, got {got}");
        }
        let p = self.path(digest)?;
        std::fs::create_dir_all(self.blobs_dir())?;
        let tmp = p.with_extension(format!("part-{}", std::process::id()));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &p)?;
        Ok(p)
    }

    pub fn read(&self, digest: &str) -> Result<Vec<u8>> {
        let p = self.path(digest)?;
        std::fs::read(&p).with_context(|| format!("reading blob {digest}"))
    }
}

/// CPU architecture of a Linux image. `amd64` images run under Rosetta on Apple silicon.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    #[default]
    Arm64,
    Amd64,
}

impl Arch {
    /// `linux/arm64`, `linux/arm64/v8`, `arm64`, `aarch64`, `linux/amd64`, `amd64` or `x86_64`.
    pub fn parse(platform: &str) -> Result<Self> {
        let p = platform.trim().to_ascii_lowercase();
        let rest = p.strip_prefix("linux/").unwrap_or(&p);
        match rest {
            "arm64" | "arm64/v8" | "aarch64" => Ok(Self::Arm64),
            "amd64" | "x86_64" | "x86-64" => Ok(Self::Amd64),
            _ => bail!("platform {platform:?}: use linux/arm64 or linux/amd64"),
        }
    }

    /// The OCI `architecture` value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::Amd64 => "amd64",
        }
    }

    pub fn platform(self) -> String {
        format!("linux/{}", self.as_str())
    }
}

/// Registry credentials (`Basic` to the token endpoint). Anonymous when absent.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

pub struct Puller {
    http: reqwest::Client,
    store: BlobStore,
    creds: Option<Credentials>,
    token: Option<String>,
    /// `architecture`, `os` to select from a multi-platform index.
    platform: (String, String),
}

impl Puller {
    pub fn new(store: BlobStore) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .user_agent(concat!("fluxvm/", env!("CARGO_PKG_VERSION")))
                .connect_timeout(std::time::Duration::from_secs(15))
                .build()?,
            store,
            creds: None,
            token: None,
            platform: ("arm64".into(), "linux".into()),
        })
    }

    pub fn with_credentials(mut self, creds: Option<Credentials>) -> Self {
        self.creds = creds;
        self
    }

    pub fn with_platform(mut self, architecture: &str, os: &str) -> Self {
        self.platform = (architecture.into(), os.into());
        self
    }

    /// Resolves `reference` to a platform manifest, then fetches its config and any layer not already stored.
    pub async fn pull(&mut self, reference: &str) -> Result<PulledImage> {
        let r = ImageRef::parse(reference)?;
        let (mut bytes, mut digest) = self.manifest(&r, &r.reference).await?;
        let mut doc: ManifestDoc = serde_json::from_slice(&bytes).context("parsing manifest")?;
        if doc.media_type == MT_OCI_INDEX
            || doc.media_type == MT_DOCKER_LIST
            || !doc.manifests.is_empty()
        {
            let (arch, os) = &self.platform;
            let pick = doc
                .manifests
                .iter()
                .find(|d| {
                    d.platform.as_ref().is_some_and(|p| {
                        &p.architecture == arch
                            && &p.os == os
                            && (arch != "arm64" || p.variant.as_deref().is_none_or(|v| v == "v8"))
                    })
                })
                .with_context(|| format!("{r} has no {os}/{arch} image"))?
                .digest
                .clone();
            (bytes, digest) = self.manifest(&r, &pick).await?;
            doc = serde_json::from_slice(&bytes).context("parsing platform manifest")?;
        }
        if !doc.media_type.is_empty()
            && doc.media_type != MT_OCI_MANIFEST
            && doc.media_type != MT_DOCKER_MANIFEST
        {
            bail!("unsupported manifest media type {:?}", doc.media_type);
        }
        let cfg_desc = doc.config.context("manifest has no config")?;
        let cfg_bytes = self.blob_bytes(&r, &cfg_desc).await?;
        let cfg: ConfigDoc = serde_json::from_slice(&cfg_bytes).context("parsing image config")?;
        let (arch, os) = &self.platform;
        if (!cfg.architecture.is_empty() && &cfg.architecture != arch)
            || (!cfg.os.is_empty() && &cfg.os != os)
        {
            bail!("{r} is {}/{}, not {os}/{arch}", cfg.os, cfg.architecture);
        }
        if cfg.rootfs.diff_ids.len() != doc.layers.len() {
            bail!(
                "{r}: {} layers but {} diff_ids in the config",
                doc.layers.len(),
                cfg.rootfs.diff_ids.len()
            );
        }
        let mut layers = Vec::with_capacity(doc.layers.len());
        for (l, diff_id) in doc.layers.iter().zip(&cfg.rootfs.diff_ids) {
            validate_digest(diff_id)?;
            let compression = Compression::from_media_type(&l.media_type)?;
            self.layer(&r, l).await?;
            layers.push(Layer {
                digest: l.digest.clone(),
                size: l.size,
                compression,
                diff_id: diff_id.clone(),
            });
        }
        Ok(PulledImage {
            reference: r.to_string(),
            manifest_digest: digest,
            config_digest: cfg_desc.digest,
            config: cfg.config.unwrap_or_default(),
            layers,
            architecture: self.platform.0.clone(),
        })
    }

    async fn get(&mut self, url: &str, accept: &str) -> Result<reqwest::Response> {
        for attempt in 0..2 {
            let mut req = self.http.get(url).header("Accept", accept);
            if let Some(t) = &self.token {
                req = req.bearer_auth(t);
            }
            let resp = req.send().await.with_context(|| format!("GET {url}"))?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                let challenge = resp
                    .headers()
                    .get("www-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                self.token = Some(self.fetch_token(&challenge).await?);
                continue;
            }
            if !resp.status().is_success() {
                bail!("GET {url}: HTTP {}", resp.status());
            }
            return Ok(resp);
        }
        bail!("GET {url}: still unauthorized after a token")
    }

    async fn fetch_token(&self, challenge: &str) -> Result<String> {
        let params = parse_bearer_challenge(challenge)
            .with_context(|| format!("registry asked for unsupported auth: {challenge:?}"))?;
        let realm = params
            .iter()
            .find(|(k, _)| k == "realm")
            .map(|(_, v)| v.clone())
            .context("auth challenge has no realm")?;
        let query: Vec<(String, String)> =
            params.into_iter().filter(|(k, _)| k != "realm").collect();
        let mut req = self.http.get(&realm).query(&query);
        if let Some(c) = &self.creds {
            req = req.basic_auth(&c.username, Some(&c.password));
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("token request to {realm}"))?;
        if !resp.status().is_success() {
            bail!("token request to {realm}: HTTP {}", resp.status());
        }
        #[derive(Deserialize)]
        struct Tok {
            token: Option<String>,
            access_token: Option<String>,
        }
        let t: Tok = resp.json().await.context("parsing token response")?;
        t.token
            .or(t.access_token)
            .context("token response has no token")
    }

    async fn manifest(&mut self, r: &ImageRef, reference: &str) -> Result<(Vec<u8>, String)> {
        let url = format!("{}/manifests/{reference}", r.base_url());
        let accept = [
            MT_OCI_INDEX,
            MT_OCI_MANIFEST,
            MT_DOCKER_LIST,
            MT_DOCKER_MANIFEST,
        ]
        .join(", ");
        let bytes = read_capped(self.get(&url, &accept).await?, MAX_JSON_BYTES as u64).await?;
        let digest = sha256_digest(&bytes);
        if reference.starts_with("sha256:") && digest != reference {
            bail!("manifest digest mismatch: asked for {reference}, got {digest}");
        }
        Ok((bytes, digest))
    }

    async fn blob_bytes(&mut self, r: &ImageRef, d: &Descriptor) -> Result<Vec<u8>> {
        if self.store.has(&d.digest) {
            return self.store.read(&d.digest);
        }
        if d.size > MAX_JSON_BYTES as u64 {
            bail!("config blob {} is {} bytes", d.digest, d.size);
        }
        let url = format!("{}/blobs/{}", r.base_url(), d.digest);
        let bytes = read_capped(self.get(&url, "*/*").await?, MAX_JSON_BYTES as u64).await?;
        self.store.put(&d.digest, &bytes)?;
        Ok(bytes)
    }

    /// Streams a layer to disk, hashing as it goes; the file only appears under its digest once verified.
    async fn layer(&mut self, r: &ImageRef, d: &Descriptor) -> Result<PathBuf> {
        let dest = self.store.path(&d.digest)?;
        if dest.is_file() {
            return Ok(dest);
        }
        if d.size > MAX_LAYER_BYTES {
            bail!(
                "layer {} is {} bytes (limit {MAX_LAYER_BYTES})",
                d.digest,
                d.size
            );
        }
        tokio::fs::create_dir_all(self.store.blobs_dir()).await?;
        let url = format!("{}/blobs/{}", r.base_url(), d.digest);
        let mut resp = self.get(&url, "*/*").await?;
        let tmp = dest.with_extension(format!("part-{}", std::process::id()));
        let mut f = tokio::fs::File::create(&tmp).await?;
        let mut hasher = Sha256::new();
        let mut n: u64 = 0;
        while let Some(chunk) = resp.chunk().await? {
            n += chunk.len() as u64;
            if n > d.size {
                let _ = tokio::fs::remove_file(&tmp).await;
                bail!(
                    "layer {} is larger than its declared {} bytes",
                    d.digest,
                    d.size
                );
            }
            hasher.update(&chunk);
            f.write_all(&chunk).await?;
        }
        f.flush().await?;
        drop(f);
        let got = format!("sha256:{:x}", hasher.finalize());
        if got != d.digest {
            let _ = tokio::fs::remove_file(&tmp).await;
            bail!("layer digest mismatch: expected {}, got {got}", d.digest);
        }
        tokio::fs::rename(&tmp, &dest).await?;
        Ok(dest)
    }
}

async fn read_capped(mut resp: reqwest::Response, cap: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if (out.len() + chunk.len()) as u64 > cap {
            bail!("response larger than {cap} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// `Bearer realm="…",service="…",scope="…"` into its key/value pairs.
fn parse_bearer_challenge(h: &str) -> Option<Vec<(String, String)>> {
    let rest = h
        .trim()
        .strip_prefix("Bearer ")
        .or_else(|| h.trim().strip_prefix("bearer "))?;
    let mut out = Vec::new();
    let mut s = rest.trim();
    while !s.is_empty() {
        let (k, after) = s.split_once('=')?;
        let after = after.trim_start();
        let (v, tail) = if let Some(q) = after.strip_prefix('"') {
            let end = q.find('"')?;
            (&q[..end], &q[end + 1..])
        } else {
            let end = after.find(',').unwrap_or(after.len());
            (&after[..end], &after[end..])
        };
        out.push((k.trim().to_string(), v.to_string()));
        s = tail.trim_start().trim_start_matches(',').trim_start();
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncBufReadExt, BufReader};

    #[test]
    fn references_get_docker_hub_defaults() {
        let cases = [
            ("alpine", DOCKER_HUB, "library/alpine", "latest"),
            ("alpine:3.22", DOCKER_HUB, "library/alpine", "3.22"),
            ("docker.io/user/app:v1", DOCKER_HUB, "user/app", "v1"),
            ("ghcr.io/org/tool", "ghcr.io", "org/tool", "latest"),
            ("localhost:5000/x/y:t", "localhost:5000", "x/y", "t"),
            ("127.0.0.1:5000/a", "127.0.0.1:5000", "a", "latest"),
        ];
        for (s, reg, repo, tag) in cases {
            let r = ImageRef::parse(s).unwrap();
            assert_eq!(
                (
                    r.registry.as_str(),
                    r.repository.as_str(),
                    r.reference.as_str()
                ),
                (reg, repo, tag),
                "{s}"
            );
        }
        let d = format!("sha256:{}", "a".repeat(64));
        let r = ImageRef::parse(&format!("quay.io/a/b@{d}")).unwrap();
        assert_eq!(r.reference, d);
        assert_eq!(r.to_string(), format!("quay.io/a/b@{d}"));
        assert!(
            ImageRef::parse("localhost:5000/a")
                .unwrap()
                .base_url()
                .starts_with("http://")
        );
        assert!(
            ImageRef::parse("alpine")
                .unwrap()
                .base_url()
                .starts_with("https://")
        );
    }

    #[test]
    fn bad_references_are_rejected() {
        for s in [
            "",
            "--privileged",
            "Upper/case",
            "a b",
            "a@sha256:xyz",
            "a@md5:00",
            "a/../b",
            "a//b",
        ] {
            assert!(ImageRef::parse(s).is_err(), "{s}");
        }
    }

    #[test]
    fn bearer_challenge_parses() {
        let p = parse_bearer_challenge(
            r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/alpine:pull""#,
        )
        .unwrap();
        assert_eq!(
            p[0],
            ("realm".into(), "https://auth.docker.io/token".into())
        );
        assert_eq!(p[2].1, "repository:library/alpine:pull");
        assert!(parse_bearer_challenge("Basic realm=x").is_none());
    }

    #[test]
    fn blob_store_refuses_wrong_digest() {
        let d = tempfile::tempdir().unwrap();
        let s = BlobStore::new(d.path());
        let good = sha256_digest(b"hello");
        s.put(&good, b"hello").unwrap();
        assert!(s.has(&good));
        assert!(s.put(&good, b"other").is_err());
        assert!(s.path("sha256:../../etc").is_err());
    }

    /// A tiny registry: anonymous token auth, an index with amd64 and arm64, one gzip layer.
    struct Mock {
        routes: HashMap<String, (String, Vec<u8>)>,
        hits: Arc<Mutex<Vec<String>>>,
    }

    async fn serve(mock: Mock) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let hits = mock.hits.clone();
        let routes = Arc::new(mock.routes);
        let realm = format!("http://{addr}/token");
        tokio::spawn(async move {
            loop {
                let (sock, _) = listener.accept().await.unwrap();
                let routes = routes.clone();
                let hits = mock.hits.clone();
                let realm = realm.clone();
                tokio::spawn(async move {
                    let (rd, mut wr) = sock.into_split();
                    let mut rd = BufReader::new(rd);
                    loop {
                        let mut line = String::new();
                        if rd.read_line(&mut line).await.unwrap_or(0) == 0 {
                            return;
                        }
                        let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                        let mut authed = false;
                        loop {
                            let mut h = String::new();
                            rd.read_line(&mut h).await.unwrap();
                            if h == "\r\n" || h.is_empty() {
                                break;
                            }
                            if h.to_ascii_lowercase()
                                .starts_with("authorization: bearer good")
                            {
                                authed = true;
                            }
                        }
                        hits.lock().unwrap().push(path.clone());
                        let (status, ctype, body, extra) = if path.starts_with("/token") {
                            (
                                "200 OK",
                                "application/json".to_string(),
                                br#"{"token":"good"}"#.to_vec(),
                                String::new(),
                            )
                        } else if !authed {
                            (
                                "401 Unauthorized",
                                "text/plain".to_string(),
                                Vec::new(),
                                format!(
                                    "WWW-Authenticate: Bearer realm=\"{realm}\",service=\"mock\",scope=\"repository:x:pull\"\r\n"
                                ),
                            )
                        } else if let Some((ct, b)) = routes.get(&path) {
                            ("200 OK", ct.clone(), b.clone(), String::new())
                        } else {
                            (
                                "404 Not Found",
                                "text/plain".to_string(),
                                Vec::new(),
                                String::new(),
                            )
                        };
                        let head = format!(
                            "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n{extra}\r\n",
                            body.len()
                        );
                        wr.write_all(head.as_bytes()).await.unwrap();
                        wr.write_all(&body).await.unwrap();
                    }
                });
            }
        });
        (addr, hits)
    }

    fn fixture(tamper_layer: bool) -> (Mock, String) {
        let layer = b"pretend-gzip-layer".to_vec();
        let layer_d = sha256_digest(&layer);
        let diff_id = sha256_digest(b"pretend-tar");
        let config = serde_json::to_vec(&serde_json::json!({
            "architecture": "arm64", "os": "linux",
            "config": {"Entrypoint": ["/bin/app"], "Cmd": ["--serve"], "Env": ["PATH=/bin"], "WorkingDir": "/srv", "User": "1000:1000"},
            "rootfs": {"type": "layers", "diff_ids": [diff_id]}
        }))
        .unwrap();
        let config_d = sha256_digest(&config);
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2, "mediaType": MT_OCI_MANIFEST,
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_d, "size": config.len()},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": layer_d, "size": layer.len()}]
        }))
        .unwrap();
        let manifest_d = sha256_digest(&manifest);
        let index = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2, "mediaType": MT_OCI_INDEX,
            "manifests": [
                {"mediaType": MT_OCI_MANIFEST, "digest": format!("sha256:{}", "0".repeat(64)), "size": 1, "platform": {"architecture": "amd64", "os": "linux"}},
                {"mediaType": MT_OCI_MANIFEST, "digest": manifest_d, "size": manifest.len(), "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"}}
            ]
        }))
        .unwrap();
        let mut routes = HashMap::new();
        routes.insert("/v2/app/manifests/1.0".into(), (MT_OCI_INDEX.into(), index));
        routes.insert(
            format!("/v2/app/manifests/{manifest_d}"),
            (MT_OCI_MANIFEST.into(), manifest),
        );
        routes.insert(
            format!("/v2/app/blobs/{config_d}"),
            ("application/json".into(), config),
        );
        let served = if tamper_layer {
            b"tampered".to_vec()
        } else {
            layer
        };
        routes.insert(
            format!("/v2/app/blobs/{layer_d}"),
            ("application/octet-stream".into(), served),
        );
        (
            Mock {
                routes,
                hits: Arc::new(Mutex::new(Vec::new())),
            },
            manifest_d,
        )
    }

    #[tokio::test]
    async fn pulls_arm64_from_an_index_with_token_auth() {
        let (mock, manifest_d) = fixture(false);
        let (addr, hits) = serve(mock).await;
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::new(dir.path());
        let mut p = Puller::new(store.clone()).unwrap();
        let img = p.pull(&format!("{addr}/app:1.0")).await.unwrap();
        assert_eq!(img.manifest_digest, manifest_d);
        assert_eq!(
            img.config.entrypoint.as_deref(),
            Some(&["/bin/app".to_string()][..])
        );
        assert_eq!(img.config.user.as_deref(), Some("1000:1000"));
        assert_eq!(img.layers.len(), 1);
        assert_eq!(img.layers[0].compression, Compression::Gzip);
        assert_eq!(img.architecture, "arm64");
        assert!(store.has(&img.layers[0].digest));
        assert!(hits.lock().unwrap().iter().any(|h| h.starts_with("/token")));

        // A second pull reuses stored blobs: only manifests are fetched.
        hits.lock().unwrap().clear();
        let again = Puller::new(store)
            .unwrap()
            .pull(&format!("{addr}/app:1.0"))
            .await
            .unwrap();
        assert_eq!(again, img);
        assert!(!hits.lock().unwrap().iter().any(|h| h.contains("/blobs/")));
    }

    #[tokio::test]
    async fn a_tampered_layer_is_not_stored() {
        let (mock, _) = fixture(true);
        let (addr, _) = serve(mock).await;
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::new(dir.path());
        let err = Puller::new(store.clone())
            .unwrap()
            .pull(&format!("{addr}/app:1.0"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("digest mismatch"), "{err}");
        let leftovers: Vec<_> = std::fs::read_dir(store.blobs_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("part"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn platforms_parse_to_an_architecture() {
        for p in [
            "linux/arm64",
            "linux/arm64/v8",
            "arm64",
            "aarch64",
            "LINUX/ARM64",
        ] {
            assert_eq!(Arch::parse(p).unwrap(), Arch::Arm64, "{p}");
        }
        for p in ["linux/amd64", "amd64", "x86_64"] {
            assert_eq!(Arch::parse(p).unwrap(), Arch::Amd64, "{p}");
        }
        for p in ["linux/riscv64", "windows/amd64", "linux/arm/v7", ""] {
            assert!(Arch::parse(p).is_err(), "{p}");
        }
        assert_eq!(Arch::Amd64.platform(), "linux/amd64");
    }

    #[tokio::test]
    async fn amd64_selects_the_amd64_manifest() {
        let (mock, _) = fixture(false);
        let (addr, hits) = serve(mock).await;
        let dir = tempfile::tempdir().unwrap();
        // The fixture's amd64 entry points at a manifest the registry does not have.
        let _ = Puller::new(BlobStore::new(dir.path()))
            .unwrap()
            .with_platform(Arch::Amd64.as_str(), "linux")
            .pull(&format!("{addr}/app:1.0"))
            .await
            .unwrap_err();
        let zero = format!("/v2/app/manifests/sha256:{}", "0".repeat(64));
        assert!(hits.lock().unwrap().contains(&zero));
    }

    #[tokio::test]
    async fn a_missing_platform_is_an_error() {
        let (mock, _) = fixture(false);
        let (addr, _) = serve(mock).await;
        let dir = tempfile::tempdir().unwrap();
        let err = Puller::new(BlobStore::new(dir.path()))
            .unwrap()
            .with_platform("riscv64", "linux")
            .pull(&format!("{addr}/app:1.0"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no linux/riscv64"), "{err}");
    }
}
