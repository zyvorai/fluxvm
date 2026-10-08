// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Credential broker: per-sandbox grants {secret ref, destination hosts,
//! expiry} that the egress proxy turns into an injected `Authorization`
//! header. The store itself lives in `fluxvm_core::grants` (the proxy reads
//! it in-process); this module is the scheduler's entry point: it resolves
//! the secret, binds the grant to the sandbox's guest address, and audits.
//! The global `sandbox.credential_vault` keeps working as a fallback.

use crate::VmManager;
use anyhow::{Context, Result, bail};
use fluxvm_core::grants::{self, GrantInfo, GrantRequest, Secret};
use uuid::Uuid;

/// The secret value for a grant: the request's own `value`, else the host
/// environment variable `FLUXVM_SECRET_<REF>`.
pub(crate) fn resolve_secret(
    req: &GrantRequest,
    env: impl Fn(&str) -> Option<String>,
) -> Result<Secret> {
    if let Some(v) = &req.value {
        return Ok(v.clone());
    }
    let name = grants::secret_env_name(req.secret_ref.trim());
    match env(&name).filter(|v| !v.is_empty()) {
        Some(v) => Ok(Secret::new(v)),
        None => bail!(
            "secret_ref {:?} not found: pass `value`, or set {name} in the daemon's environment",
            req.secret_ref
        ),
    }
}

impl VmManager {
    /// Grant sandbox `id` a credential for specific destination hosts.
    pub async fn add_grant(&self, id: Uuid, req: GrantRequest) -> Result<GrantInfo> {
        let vm = self.get(id).await?;
        grants::set_audit_sink(crate::audit_event);
        let value = resolve_secret(&req, |k| std::env::var(k).ok())?;
        let source_ip = vm.guest_ip.as_deref().and_then(|s| s.parse().ok());
        let sandbox_id = id.to_string();
        let info = grants::global()
            .add(&sandbox_id, &req, value, source_ip, chrono::Utc::now())
            .context("creating grant")?;
        crate::audit_event(
            "credential.grant",
            &[
                ("sandbox_id", &sandbox_id),
                ("grant_id", &info.id),
                ("secret_ref", &info.secret_ref),
                ("hosts", &info.hosts.join(",")),
                ("expires_at", &info.expires_at.to_rfc3339()),
            ],
        );
        Ok(info)
    }

    /// Live grants of a sandbox (never includes secrets).
    pub async fn list_grants(&self, id: Uuid) -> Result<Vec<GrantInfo>> {
        self.get(id).await?;
        Ok(grants::global().list(&id.to_string(), chrono::Utc::now()))
    }

    /// Revoke one grant (`Some(grant_id)`) or all of the sandbox's grants
    /// (`None`). Returns whether anything was revoked.
    pub async fn revoke_grant(&self, id: Uuid, grant_id: Option<&str>) -> Result<bool> {
        self.get(id).await?;
        let sandbox_id = id.to_string();
        let store = grants::global();
        let revoked = match grant_id {
            Some(g) => store.remove(&sandbox_id, g),
            None => {
                let any = !store.list(&sandbox_id, chrono::Utc::now()).is_empty();
                store.remove_sandbox(&sandbox_id);
                any
            }
        };
        if revoked {
            crate::audit_event(
                "credential.revoke",
                &[
                    ("sandbox_id", &sandbox_id),
                    ("grant_id", grant_id.unwrap_or("all")),
                ],
            );
        }
        Ok(revoked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(value: Option<&str>) -> GrantRequest {
        GrantRequest {
            secret_ref: "gh-token".into(),
            value: value.map(Secret::new),
            hosts: vec!["api.github.com".into()],
            ttl_seconds: None,
            expires_at: None,
        }
    }

    #[test]
    fn inline_value_wins_over_the_environment() {
        let s = resolve_secret(&req(Some("Bearer inline")), |_| Some("Bearer env".into())).unwrap();
        assert_eq!(s.expose(), "Bearer inline");
    }

    #[test]
    fn ref_resolves_from_the_environment() {
        let s = resolve_secret(&req(None), |k| {
            assert_eq!(k, "FLUXVM_SECRET_GH_TOKEN");
            Some("Bearer env".into())
        })
        .unwrap();
        assert_eq!(s.expose(), "Bearer env");
    }

    #[test]
    fn unresolvable_ref_is_an_error_that_does_not_leak() {
        let e = resolve_secret(&req(None), |_| None).unwrap_err();
        assert!(format!("{e:#}").contains("FLUXVM_SECRET_GH_TOKEN"));
        assert!(resolve_secret(&req(None), |_| Some(String::new())).is_err());
    }
}
