// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Per-sandbox credential grants (the credential broker).
//!
//! A grant lets one sandbox's egress traffic carry a secret `Authorization`
//! header to specific destination hosts until it expires. The guest never sees
//! the secret: the egress proxy injects it after the request is vetted. The
//! global `sandbox.credential_vault` stays as a fallback for traffic that has
//! no matching grant.
//!
//! Secrets live only in memory, behind [`Secret`], which can neither be
//! printed (`Debug` is redacted) nor serialised. API responses use
//! [`GrantInfo`], which has no secret field at all. Grants are not persisted:
//! a daemon restart drops them and callers re-grant.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};

/// Grant lifetime used when the request names none.
pub const DEFAULT_GRANT_TTL_SECS: i64 = 3600;
/// Longest grant lifetime accepted.
pub const MAX_GRANT_TTL_SECS: i64 = 24 * 3600;
/// Most live grants one sandbox may hold.
pub const MAX_GRANTS_PER_SANDBOX: usize = 32;

/// A secret value. Never printed and never serialised.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The raw value. Only the egress proxy's header injection should call this.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Secret)
    }
}

/// Request body for creating a grant. `value` is write-only.
#[derive(Debug, Clone, Deserialize)]
pub struct GrantRequest {
    /// Name of the secret. Without `value`, it is resolved from the host
    /// environment variable `FLUXVM_SECRET_<REF>` (upper-case, non
    /// alphanumerics as `_`).
    pub secret_ref: String,
    /// Full header value to inject (e.g. `Bearer abc`). Optional.
    #[serde(default)]
    pub value: Option<Secret>,
    /// Destination hosts the secret may be sent to (exact or domain suffix).
    pub hosts: Vec<String>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// The public, secret-free view of a grant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GrantInfo {
    pub id: String,
    pub sandbox_id: String,
    pub secret_ref: String,
    pub hosts: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Whether the sandbox's source address is known. A grant without one
    /// cannot match any traffic (fail closed).
    pub bound: bool,
}

#[derive(Clone)]
struct Grant {
    info: GrantInfo,
    value: Secret,
}

/// What the proxy gets back for a matching request.
#[derive(Debug, Clone)]
pub struct Injection {
    pub sandbox_id: String,
    pub grant_id: String,
    pub secret_ref: String,
    pub authorization: Secret,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GrantError {
    Invalid(String),
    TooMany,
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantError::Invalid(m) => write!(f, "{m}"),
            GrantError::TooMany => write!(
                f,
                "sandbox already holds {MAX_GRANTS_PER_SANDBOX} grants; revoke one first"
            ),
        }
    }
}

impl std::error::Error for GrantError {}

#[derive(Default)]
struct Inner {
    grants: HashMap<String, Vec<Grant>>,
    sources: HashMap<IpAddr, String>,
}

#[derive(Default)]
pub struct GrantStore {
    inner: Mutex<Inner>,
}

/// Exact match or domain suffix, like the egress allowlist.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().trim_start_matches('.').to_ascii_lowercase();
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    !p.is_empty() && (h == p || h.ends_with(&format!(".{p}")))
}

/// Environment variable name a `secret_ref` resolves from.
pub fn secret_env_name(secret_ref: &str) -> String {
    let mut out = String::from("FLUXVM_SECRET_");
    for c in secret_ref.chars() {
        out.push(if c.is_ascii_alphanumeric() {
            c.to_ascii_uppercase()
        } else {
            '_'
        });
    }
    out
}

fn normalize_host(h: &str) -> Result<String, GrantError> {
    let h = h.trim().trim_start_matches('.').to_ascii_lowercase();
    if h.is_empty()
        || h.contains(|c: char| c.is_whitespace() || matches!(c, '*' | '/' | ':' | '@' | '?'))
    {
        return Err(GrantError::Invalid(format!(
            "invalid grant host {h:?}: use a bare host name, exact or domain suffix"
        )));
    }
    Ok(h)
}

impl GrantStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Add a grant. `value` must already be resolved. `source_ip` is the
    /// sandbox's guest address, if known.
    pub fn add(
        &self,
        sandbox_id: &str,
        req: &GrantRequest,
        value: Secret,
        source_ip: Option<IpAddr>,
        now: DateTime<Utc>,
    ) -> Result<GrantInfo, GrantError> {
        let secret_ref = req.secret_ref.trim();
        if secret_ref.is_empty() || secret_ref.len() > 128 {
            return Err(GrantError::Invalid("secret_ref must be 1-128 chars".into()));
        }
        if value.expose().is_empty() {
            return Err(GrantError::Invalid("secret value is empty".into()));
        }
        if req.hosts.is_empty() {
            return Err(GrantError::Invalid(
                "a grant needs at least one host".into(),
            ));
        }
        let hosts = req
            .hosts
            .iter()
            .map(|h| normalize_host(h))
            .collect::<Result<Vec<_>, _>>()?;
        let expires_at = match (req.expires_at, req.ttl_seconds) {
            (Some(at), _) => at,
            (None, Some(ttl)) => {
                if ttl <= 0 || ttl > MAX_GRANT_TTL_SECS {
                    return Err(GrantError::Invalid(format!(
                        "ttl_seconds must be between 1 and {MAX_GRANT_TTL_SECS}"
                    )));
                }
                now + Duration::seconds(ttl)
            }
            (None, None) => now + Duration::seconds(DEFAULT_GRANT_TTL_SECS),
        };
        if expires_at <= now {
            return Err(GrantError::Invalid("grant expiry is in the past".into()));
        }
        if expires_at > now + Duration::seconds(MAX_GRANT_TTL_SECS) {
            return Err(GrantError::Invalid(format!(
                "grant lifetime exceeds the {MAX_GRANT_TTL_SECS}s maximum"
            )));
        }

        let mut inner = self.lock();
        let list = inner.grants.entry(sandbox_id.to_string()).or_default();
        list.retain(|g| g.info.expires_at > now);
        if list.len() >= MAX_GRANTS_PER_SANDBOX {
            return Err(GrantError::TooMany);
        }
        let info = GrantInfo {
            id: uuid::Uuid::new_v4().to_string(),
            sandbox_id: sandbox_id.to_string(),
            secret_ref: secret_ref.to_string(),
            hosts,
            created_at: now,
            expires_at,
            bound: source_ip.is_some(),
        };
        list.push(Grant {
            info: info.clone(),
            value,
        });
        if let Some(ip) = source_ip {
            inner.sources.insert(ip, sandbox_id.to_string());
        }
        Ok(info)
    }

    /// Revoke one grant. Returns whether it existed.
    pub fn remove(&self, sandbox_id: &str, grant_id: &str) -> bool {
        let mut inner = self.lock();
        let Some(list) = inner.grants.get_mut(sandbox_id) else {
            return false;
        };
        let before = list.len();
        list.retain(|g| g.info.id != grant_id);
        list.len() != before
    }

    /// Drop every grant (and the source binding) of a sandbox.
    pub fn remove_sandbox(&self, sandbox_id: &str) {
        let mut inner = self.lock();
        inner.grants.remove(sandbox_id);
        inner.sources.retain(|_, s| s != sandbox_id);
    }

    /// Live (unexpired) grants of a sandbox, without secrets.
    pub fn list(&self, sandbox_id: &str, now: DateTime<Utc>) -> Vec<GrantInfo> {
        self.lock()
            .grants
            .get(sandbox_id)
            .map(|l| {
                l.iter()
                    .filter(|g| g.info.expires_at > now)
                    .map(|g| g.info.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find the credential for traffic from `peer` to `host`, if a live grant
    /// of the sandbox that owns `peer` covers that host.
    pub fn resolve(&self, peer: IpAddr, host: &str, now: DateTime<Utc>) -> Option<Injection> {
        let inner = self.lock();
        let sandbox = inner.sources.get(&peer)?;
        inner
            .grants
            .get(sandbox)?
            .iter()
            .filter(|g| g.info.expires_at > now)
            .find(|g| g.info.hosts.iter().any(|p| host_matches(p, host)))
            .map(|g| Injection {
                sandbox_id: g.info.sandbox_id.clone(),
                grant_id: g.info.id.clone(),
                secret_ref: g.info.secret_ref.clone(),
                authorization: g.value.clone(),
            })
    }
}

/// The process-wide store the daemon's API and egress proxy share.
pub fn global() -> &'static GrantStore {
    static STORE: OnceLock<GrantStore> = OnceLock::new();
    STORE.get_or_init(GrantStore::new)
}

/// Where credential-use audit records go. The scheduler registers its own
/// audit sink; without one, records go to stderr.
pub type AuditSink = fn(&str, &[(&str, &str)]);

static AUDIT_SINK: OnceLock<AuditSink> = OnceLock::new();

pub fn set_audit_sink(sink: AuditSink) {
    let _ = AUDIT_SINK.set(sink);
}

/// Record one credential use. Carries the destination and sandbox id, never the secret.
pub fn audit_use(inj: &Injection, destination: &str) {
    let pairs = [
        ("sandbox_id", inj.sandbox_id.as_str()),
        ("grant_id", inj.grant_id.as_str()),
        ("secret_ref", inj.secret_ref.as_str()),
        ("destination", destination),
    ];
    match AUDIT_SINK.get() {
        Some(sink) => sink("credential.use", &pairs),
        None => {
            let record = crate::policy::format_audit_record("credential.use", &pairs);
            eprintln!("fluxvm_audit {record}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(hosts: &[&str]) -> GrantRequest {
        GrantRequest {
            secret_ref: "gh".into(),
            value: None,
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            ttl_seconds: Some(60),
            expires_at: None,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn destination_matching_is_exact_or_suffix() {
        assert!(host_matches("github.com", "github.com"));
        assert!(host_matches(".github.com", "API.github.com."));
        assert!(!host_matches("github.com", "evilgithub.com"));
        assert!(!host_matches("github.com", "github.com.evil.io"));
        assert!(!host_matches("", "anything"));
    }

    #[test]
    fn grant_resolves_only_for_its_sandbox_host_and_time() {
        let s = GrantStore::new();
        let now = Utc::now();
        let info = s
            .add(
                "sb1",
                &req(&["api.github.com"]),
                Secret::new("Bearer abc"),
                Some(ip("10.0.0.2")),
                now,
            )
            .unwrap();
        assert!(info.bound);
        let hit = s.resolve(ip("10.0.0.2"), "api.github.com", now).unwrap();
        assert_eq!(hit.authorization.expose(), "Bearer abc");
        assert_eq!(hit.sandbox_id, "sb1");
        // Other destination, other sandbox, unknown source: no credential.
        assert!(s.resolve(ip("10.0.0.2"), "evil.com", now).is_none());
        assert!(s.resolve(ip("10.0.0.3"), "api.github.com", now).is_none());
        // Expired.
        let later = now + Duration::seconds(61);
        assert!(s.resolve(ip("10.0.0.2"), "api.github.com", later).is_none());
        assert!(s.list("sb1", later).is_empty());
        assert_eq!(s.list("sb1", now).len(), 1);
    }

    #[test]
    fn unbound_grant_never_matches() {
        let s = GrantStore::new();
        let now = Utc::now();
        let info = s
            .add("sb1", &req(&["a.com"]), Secret::new("x"), None, now)
            .unwrap();
        assert!(!info.bound);
        assert!(s.resolve(ip("10.0.0.2"), "a.com", now).is_none());
    }

    #[test]
    fn revoke_and_sandbox_cleanup() {
        let s = GrantStore::new();
        let now = Utc::now();
        let a = s
            .add(
                "sb1",
                &req(&["a.com"]),
                Secret::new("x"),
                Some(ip("10.0.0.2")),
                now,
            )
            .unwrap();
        assert!(s.remove("sb1", &a.id));
        assert!(!s.remove("sb1", &a.id));
        assert!(s.resolve(ip("10.0.0.2"), "a.com", now).is_none());
        s.add(
            "sb1",
            &req(&["a.com"]),
            Secret::new("x"),
            Some(ip("10.0.0.2")),
            now,
        )
        .unwrap();
        s.remove_sandbox("sb1");
        assert!(s.resolve(ip("10.0.0.2"), "a.com", now).is_none());
        assert!(s.list("sb1", now).is_empty());
    }

    #[test]
    fn validation_rejects_bad_grants() {
        let s = GrantStore::new();
        let now = Utc::now();
        let add = |r: &GrantRequest| s.add("sb", r, Secret::new("x"), None, now);
        assert!(add(&req(&[])).is_err());
        assert!(add(&req(&["*"])).is_err());
        assert!(add(&req(&["a.com/x"])).is_err());
        assert!(add(&req(&["a.com:443"])).is_err());
        let mut r = req(&["a.com"]);
        r.ttl_seconds = Some(-5);
        assert!(add(&r).is_err());
        r.ttl_seconds = Some(MAX_GRANT_TTL_SECS + 1);
        assert!(add(&r).is_err());
        r.ttl_seconds = None;
        assert!(add(&r).is_ok());
        assert!(
            s.add("sb", &req(&["a.com"]), Secret::new(""), None, now)
                .is_err()
        );
    }

    #[test]
    fn secrets_are_redacted_everywhere_printable() {
        let secret = Secret::new("hunter2-very-secret");
        assert!(!format!("{secret:?}").contains("hunter2"));
        let mut r = req(&["a.com"]);
        r.value = Some(Secret::new("hunter2-very-secret"));
        assert!(!format!("{r:?}").contains("hunter2"));

        let s = GrantStore::new();
        let info = s
            .add("sb", &r, secret.clone(), Some(ip("10.0.0.9")), Utc::now())
            .unwrap();
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("hunter2"), "{json}");
        let inj = s.resolve(ip("10.0.0.9"), "a.com", Utc::now()).unwrap();
        assert!(!format!("{inj:?}").contains("hunter2"));
    }

    #[test]
    fn secret_env_names_are_sanitised() {
        assert_eq!(secret_env_name("gh-token.1"), "FLUXVM_SECRET_GH_TOKEN_1");
    }
}
