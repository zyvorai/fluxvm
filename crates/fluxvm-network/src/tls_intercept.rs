// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! TLS interception for the egress proxy: a persistent CA, per-host leaf
//! certificates minted on demand, and the upstream-address filter.
//!
//! Opt-in only (`sandbox.egress_tls_intercept`). Guests must trust the CA
//! certificate; the CA private key never leaves the host and is written with
//! mode 0600. See `docs/http-acl.md`.

use anyhow::{Context, Result, anyhow, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

pub const DEFAULT_CA_CERT: &str = "/var/lib/fluxvm/egress-ca.crt";
pub const DEFAULT_CA_KEY: &str = "/var/lib/fluxvm/egress-ca.key";

/// Leaf certificates are valid this long; cached configs are refreshed well
/// before they could expire.
const LEAF_VALIDITY_DAYS: i64 = 7;
const LEAF_CACHE_TTL: Duration = Duration::from_secs(24 * 3600);
const LEAF_CACHE_MAX: usize = 256;
const CA_VALIDITY_DAYS: i64 = 3650;

/// The certificate authority that signs per-host leaf certificates.
pub struct InterceptCa {
    /// Issuer object used for signing. When the CA was loaded from disk it is
    /// re-issued from the same subject and key, so leaves chain to the
    /// persisted certificate (validation uses name + key, not the serial).
    issuer: rcgen::Certificate,
    key: KeyPair,
    cert_pem: String,
}

impl InterceptCa {
    /// A fresh self-signed CA.
    pub fn generate() -> Result<Self> {
        let key = KeyPair::generate().context("generating CA key")?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params
            .distinguished_name
            .push(DnType::CommonName, "FluxVM Egress CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Zyvor FluxVM");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(CA_VALIDITY_DAYS);
        let cert = params.self_signed(&key).context("self-signing CA")?;
        let cert_pem = cert.pem();
        Ok(Self {
            issuer: cert,
            key,
            cert_pem,
        })
    }

    /// Load a CA from PEM text (certificate and PKCS#8 private key).
    pub fn from_pems(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = KeyPair::from_pem(key_pem).context("parsing CA private key")?;
        let params =
            CertificateParams::from_ca_cert_pem(cert_pem).context("parsing CA certificate")?;
        if !matches!(params.is_ca, IsCa::Ca(_)) {
            bail!("egress CA certificate is not a CA (basicConstraints CA:TRUE missing)");
        }
        let issuer = params
            .self_signed(&key)
            .context("re-issuing CA for signing")?;
        Ok(Self {
            issuer,
            key,
            cert_pem: cert_pem.to_string(),
        })
    }

    /// Load the CA from `cert_path`/`key_path`, or create and persist a new
    /// one if **both** are absent. Exactly one present is an error: silently
    /// replacing half of a CA would invalidate what guests already trust.
    pub fn load_or_create(cert_path: &Path, key_path: &Path) -> Result<Self> {
        match (cert_path.exists(), key_path.exists()) {
            (true, true) => {
                warn_if_key_is_readable(key_path);
                let cert = std::fs::read_to_string(cert_path)
                    .with_context(|| format!("reading {}", cert_path.display()))?;
                let key = std::fs::read_to_string(key_path)
                    .with_context(|| format!("reading {}", key_path.display()))?;
                Self::from_pems(&cert, &key)
            }
            (false, false) => {
                let ca = Self::generate()?;
                ca.persist(cert_path, key_path)?;
                Ok(ca)
            }
            (true, false) => bail!(
                "egress CA certificate {} exists but key {} does not",
                cert_path.display(),
                key_path.display()
            ),
            (false, true) => bail!(
                "egress CA key {} exists but certificate {} does not",
                key_path.display(),
                cert_path.display()
            ),
        }
    }

    fn persist(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        for p in [cert_path, key_path] {
            if let Some(dir) = p.parent() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
        }
        write_new(key_path, self.key.serialize_pem().as_bytes(), 0o600)?;
        write_new(cert_path, self.cert_pem.as_bytes(), 0o644)?;
        Ok(())
    }

    /// PEM of the CA certificate: this is what guests must trust.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Mint a leaf certificate for `host` (a DNS name or an IP literal).
    pub fn mint(&self, host: &str) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
        let mut params = match host.parse::<IpAddr>() {
            Ok(ip) => {
                let mut p = CertificateParams::new(Vec::<String>::new())?;
                p.subject_alt_names = vec![SanType::IpAddress(ip)];
                p
            }
            Err(_) => {
                validate_dns_name(host)?;
                CertificateParams::new(vec![host.to_string()])
                    .with_context(|| format!("invalid host {host:?} for a certificate"))?
            }
        };
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + time::Duration::days(LEAF_VALIDITY_DAYS);
        let leaf_key = KeyPair::generate().context("generating leaf key")?;
        let cert = params
            .signed_by(&leaf_key, &self.issuer, &self.key)
            .context("signing leaf certificate")?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        Ok((cert.der().clone(), key))
    }
}

fn validate_dns_name(host: &str) -> Result<()> {
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        && !host.starts_with('.')
        && !host.ends_with('.');
    if ok {
        Ok(())
    } else {
        Err(anyhow!("refusing to mint a certificate for {host:?}"))
    }
}

#[cfg(unix)]
fn write_new(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(not(unix))]
fn write_new(path: &Path, data: &[u8], _mode: u32) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(unix)]
fn warn_if_key_is_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path)
        && meta.permissions().mode() & 0o077 != 0
    {
        tracing::warn!(
            path = %path.display(),
            "egress CA key is accessible to group/other; restrict it to mode 0600"
        );
    }
}

#[cfg(not(unix))]
fn warn_if_key_is_readable(_path: &Path) {}

/// A CA plus a bounded cache of ready-to-use rustls server configs, one per
/// intercepted host.
pub struct TlsIntercept {
    ca: InterceptCa,
    cache: Mutex<LeafCache>,
}

#[derive(Default)]
struct LeafCache {
    map: HashMap<String, (Instant, Arc<ServerConfig>)>,
    order: VecDeque<String>,
}

impl TlsIntercept {
    pub fn new(ca: InterceptCa) -> Self {
        Self {
            ca,
            cache: Mutex::new(LeafCache::default()),
        }
    }

    /// Build from the configured paths (empty = the defaults).
    pub fn from_config(cert: &str, key: &str) -> Result<Self> {
        let cert = if cert.is_empty() {
            DEFAULT_CA_CERT
        } else {
            cert
        };
        let key = if key.is_empty() { DEFAULT_CA_KEY } else { key };
        Ok(Self::new(InterceptCa::load_or_create(
            &PathBuf::from(cert),
            &PathBuf::from(key),
        )?))
    }

    pub fn ca(&self) -> &InterceptCa {
        &self.ca
    }

    /// The rustls config presenting a certificate for `host`. ALPN offers `h2`
    /// and `http/1.1`; the proxy serves whichever the client picks.
    pub fn server_config_for(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let host = host.to_ascii_lowercase();
        {
            let cache = self.cache.lock().unwrap();
            if let Some((at, cfg)) = cache.map.get(&host)
                && at.elapsed() < LEAF_CACHE_TTL
            {
                return Ok(cfg.clone());
            }
        }
        let (cert, key) = self.ca.mint(&host)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions")?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .context("building TLS server config")?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);

        let mut cache = self.cache.lock().unwrap();
        if cache
            .map
            .insert(host.clone(), (Instant::now(), cfg.clone()))
            .is_none()
        {
            cache.order.push_back(host);
        }
        while cache.map.len() > LEAF_CACHE_MAX {
            match cache.order.pop_front() {
                Some(old) => {
                    cache.map.remove(&old);
                }
                None => break,
            }
        }
        Ok(cfg)
    }

    #[cfg(test)]
    fn cached_hosts(&self) -> usize {
        self.cache.lock().unwrap().map.len()
    }
}

/// True for addresses an intercepted tunnel may reach by default: anything
/// that is not loopback, private, link-local (including the cloud metadata
/// address), CGNAT, multicast, broadcast or unspecified.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || o[0] == 0
        || o[0] >= 240)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local())
}

/// reqwest resolver that drops non-public addresses (unless allowed), so a
/// hostname that resolves to an internal address cannot be used to reach
/// internal services through the proxy. Filtering happens at connect time, so
/// DNS rebinding between a check and the connection is not possible.
pub struct FilteringResolver {
    pub allow_private: bool,
}

impl reqwest::dns::Resolve for FilteringResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow_private = self.allow_private;
        Box::pin(async move {
            let host = name.as_str().to_string();
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?
                .filter(|a| allow_private || is_public_ip(a.ip()))
                .collect();
            if addrs.is_empty() {
                let msg = format!("{host} resolves only to non-public addresses (refused)");
                return Err(msg.into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_address_classification() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(
                !is_public_ip(ip.parse().unwrap()),
                "{ip} must be non-public"
            );
        }
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "172.32.0.1",
            "100.128.0.1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public_ip(ip.parse().unwrap()), "{ip} must be public");
        }
    }

    #[test]
    fn ca_generation_and_reload_produce_chaining_leaves() {
        let ca = InterceptCa::generate().unwrap();
        let (cert, key) = ca.mint("api.example.com").unwrap();
        assert!(!cert.is_empty());
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
        // Reloading from PEM must keep working with the same key.
        let key_pem = ca.key.serialize_pem();
        let again = InterceptCa::from_pems(ca.cert_pem(), &key_pem).unwrap();
        assert_eq!(again.cert_pem(), ca.cert_pem());
        again.mint("other.example.com").unwrap();
        again.mint("192.0.2.7").unwrap();
    }

    #[test]
    fn a_non_ca_certificate_is_refused_as_the_ca() {
        let ca = InterceptCa::generate().unwrap();
        let mut p = CertificateParams::new(vec!["leaf.example".to_string()]).unwrap();
        p.is_ca = IsCa::NoCa;
        let key = KeyPair::generate().unwrap();
        let leaf = p.self_signed(&key).unwrap();
        assert!(InterceptCa::from_pems(&leaf.pem(), &key.serialize_pem()).is_err());
        drop(ca);
    }

    #[test]
    fn hostile_names_are_not_minted() {
        let ca = InterceptCa::generate().unwrap();
        for bad in [
            "",
            "a b.example",
            "evil.example/../x",
            ".lead",
            "trail.",
            "a\0b",
        ] {
            assert!(ca.mint(bad).is_err(), "{bad:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ca_is_persisted_with_a_private_key_file_and_reloads() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("nested/ca.crt");
        let key = dir.path().join("nested/ca.key");
        let first = InterceptCa::load_or_create(&cert, &key).unwrap();
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "CA key must be 0600");
        let second = InterceptCa::load_or_create(&cert, &key).unwrap();
        assert_eq!(first.cert_pem(), second.cert_pem(), "existing CA is reused");
    }

    #[test]
    fn half_a_ca_is_an_error_not_a_silent_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("ca.crt");
        let key = dir.path().join("ca.key");
        std::fs::write(&cert, "not a real cert").unwrap();
        assert!(InterceptCa::load_or_create(&cert, &key).is_err());
        std::fs::remove_file(&cert).unwrap();
        std::fs::write(&key, "not a real key").unwrap();
        assert!(InterceptCa::load_or_create(&cert, &key).is_err());
    }

    #[test]
    fn leaf_cache_is_bounded_and_reuses_entries() {
        let t = TlsIntercept::new(InterceptCa::generate().unwrap());
        let a = t.server_config_for("Reuse.example").unwrap();
        let b = t.server_config_for("reuse.example").unwrap();
        assert!(Arc::ptr_eq(&a, &b), "case-insensitive reuse");
        for i in 0..(LEAF_CACHE_MAX + 20) {
            t.server_config_for(&format!("h{i}.example")).unwrap();
        }
        assert!(t.cached_hosts() <= LEAF_CACHE_MAX);
        assert_eq!(a.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }
}
