// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! OIDC bearer JWT validation via issuer discovery + JWKS.
//!
//! Static `[[auth.tokens]]` remain first-class. When `auth.oidc_issuer` and
//! `auth.oidc_audience` are set, FluxVM also accepts IdP-issued JWTs after
//! verifying signature (JWKS), `iss`, `aud`, and expiry.
//!
//! Claim mapping (first match wins):
//! - role: `fluxvm_role` | `role` ∈ {`admin`,`read-only`} default `read-only`
//! - tenant: `fluxvm_tenant` | `tenant` | `org`
//! - actor: `preferred_username` | `email` | `sub`

use anyhow::{Context, Result, anyhow};
use fluxvm_core::config::Role;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct OidcIdentity {
    pub role: Role,
    pub actor: String,
    pub tenant: Option<String>,
}

#[derive(Clone)]
pub struct OidcValidator {
    issuer: String,
    audience: String,
    http: reqwest::Client,
    cache: Arc<RwLock<JwksCache>>,
}

struct JwksCache {
    keys: HashMap<String, (Algorithm, DecodingKey)>,
    fetched_at: Option<Instant>,
    jwks_uri: Option<String>,
}

impl OidcValidator {
    pub fn new(issuer: String, audience: String) -> Self {
        Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            audience,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            cache: Arc::new(RwLock::new(JwksCache {
                keys: HashMap::new(),
                fetched_at: None,
                jwks_uri: None,
            })),
        }
    }

    pub async fn validate(&self, token: &str) -> Result<OidcIdentity> {
        let header = decode_header(token).context("OIDC JWT header")?;
        let kid = header.kid.ok_or_else(|| anyhow!("OIDC JWT missing kid"))?;

        let (alg, key) = self.decoding_key(&kid).await?;
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[self.issuer.clone()]);
        validation.set_audience(&[self.audience.clone()]);

        let data = decode::<OidcClaims>(token, &key, &validation).context("OIDC JWT validate")?;
        let claims = data.claims;
        let role = parse_role(claims.fluxvm_role.as_deref().or(claims.role.as_deref()));
        let tenant = claims
            .fluxvm_tenant
            .or(claims.tenant)
            .or(claims.org)
            .filter(|s| !s.is_empty());
        let actor = claims
            .preferred_username
            .or(claims.email)
            .or(claims.sub)
            .unwrap_or_else(|| "oidc".into());
        Ok(OidcIdentity {
            role,
            actor,
            tenant,
        })
    }

    async fn decoding_key(&self, kid: &str) -> Result<(Algorithm, DecodingKey)> {
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.keys.get(kid) {
                if cache
                    .fetched_at
                    .is_some_and(|t| t.elapsed() < Duration::from_secs(3600))
                {
                    return Ok(entry.clone());
                }
            }
        }
        self.refresh_jwks().await?;
        let cache = self.cache.read().await;
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| anyhow!("OIDC JWKS has no key for kid={kid}"))
    }

    async fn refresh_jwks(&self) -> Result<()> {
        let jwks_uri = {
            let cache = self.cache.read().await;
            cache.jwks_uri.clone()
        };
        let jwks_uri = match jwks_uri {
            Some(u) => u,
            None => self.discover_jwks_uri().await?,
        };
        let body = self
            .http
            .get(&jwks_uri)
            .send()
            .await
            .context("fetch JWKS")?
            .error_for_status()
            .context("JWKS HTTP status")?
            .text()
            .await
            .context("JWKS body")?;
        let set: JwkSet = serde_json::from_str(&body).context("parse JWKS")?;

        let mut keys = HashMap::new();
        for jwk in set.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                continue;
            };
            let alg = jwk
                .common
                .key_algorithm
                .map(|a| match a {
                    jsonwebtoken::jwk::KeyAlgorithm::RS256 => Algorithm::RS256,
                    jsonwebtoken::jwk::KeyAlgorithm::RS384 => Algorithm::RS384,
                    jsonwebtoken::jwk::KeyAlgorithm::RS512 => Algorithm::RS512,
                    jsonwebtoken::jwk::KeyAlgorithm::ES256 => Algorithm::ES256,
                    jsonwebtoken::jwk::KeyAlgorithm::ES384 => Algorithm::ES384,
                    _ => Algorithm::RS256,
                })
                .unwrap_or(Algorithm::RS256);
            match DecodingKey::from_jwk(&jwk) {
                Ok(key) => {
                    keys.insert(kid, (alg, key));
                }
                Err(e) => tracing::debug!(kid = %kid, error = %e, "skip JWK"),
            }
        }

        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        cache.jwks_uri = Some(jwks_uri);
        Ok(())
    }

    async fn discover_jwks_uri(&self) -> Result<String> {
        let url = format!("{}/.well-known/openid-configuration", self.issuer);
        #[derive(Deserialize)]
        struct Discovery {
            jwks_uri: String,
        }
        let disc: Discovery = self
            .http
            .get(&url)
            .send()
            .await
            .context("OIDC discovery")?
            .error_for_status()
            .context("OIDC discovery status")?
            .json()
            .await
            .context("OIDC discovery JSON")?;
        Ok(disc.jwks_uri)
    }
}

fn parse_role(raw: Option<&str>) -> Role {
    match raw.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("admin") | Some("administrator") => Role::Admin,
        _ => Role::ReadOnly,
    }
}

#[derive(Debug, Deserialize)]
struct OidcClaims {
    sub: Option<String>,
    preferred_username: Option<String>,
    email: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    fluxvm_role: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    fluxvm_tenant: Option<String>,
    #[serde(default)]
    org: Option<String>,
}
