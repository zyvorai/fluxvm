//! Named VM templates: reusable `CreateVmRequest` specs kept in
//! `state_dir/vm-templates.json`, shared by the daemon and local `fluxctl`.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use fluxvm_core::model::CreateVmRequest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmTemplate {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    /// `spec.name` is replaced by the VM name on instantiate.
    pub spec: CreateVmRequest,
}

pub fn path(state_dir: &Path) -> PathBuf {
    state_dir.join("vm-templates.json")
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 63
        || name.starts_with(['-', '.'])
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("invalid template name {name:?}: use 1-63 chars of [A-Za-z0-9._-]");
    }
    Ok(())
}

pub fn load(state_dir: &Path) -> Result<BTreeMap<String, VmTemplate>> {
    let p = path(state_dir);
    match std::fs::read_to_string(&p) {
        Ok(s) => serde_json::from_str(&s).with_context(|| format!("parsing {}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}

pub fn store(state_dir: &Path, all: &BTreeMap<String, VmTemplate>) -> Result<()> {
    let p = path(state_dir);
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(all)?)
        .with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &p).with_context(|| format!("replacing {}", p.display()))?;
    Ok(())
}

/// Parse a template spec; `name` may be omitted (it is set per VM anyway).
pub fn spec_from_json(template: &str, mut spec: serde_json::Value) -> Result<CreateVmRequest> {
    if let Some(obj) = spec.as_object_mut() {
        obj.entry("name")
            .or_insert_with(|| serde_json::Value::from(template));
    }
    serde_json::from_value(spec).context("invalid VM spec for template")
}

/// A VM spec stripped of per-instance fields, ready to store as a template.
pub fn spec_from_request(mut spec: CreateVmRequest) -> CreateVmRequest {
    spec.created_by_token = None;
    spec.loadvm_tag = None;
    if let fluxvm_core::model::NetworkSpec::Tap { mac, .. } = &mut spec.network {
        *mac = None;
    }
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        for ok in ["web", "web-1.small", "a_b"] {
            assert!(validate_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-x", ".x", "a/b", "a b", &"x".repeat(64)] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).unwrap().is_empty());
        let spec = spec_from_json(
            "small",
            serde_json::json!({"backend":"qemu","image":"/i.qcow2","created_by_token":"t","loadvm_tag":"s"}),
        )
        .unwrap();
        assert_eq!(spec.name, "small");
        assert!(spec_from_json("x", serde_json::json!({"backend": 1})).is_err());
        let spec = spec_from_request(spec);
        assert!(spec.created_by_token.is_none() && spec.loadvm_tag.is_none());
        let mut all = BTreeMap::new();
        all.insert(
            "small".to_string(),
            VmTemplate {
                name: "small".into(),
                description: None,
                created_at: Utc::now(),
                spec,
            },
        );
        store(dir.path(), &all).unwrap();
        assert_eq!(
            load(dir.path()).unwrap()["small"].spec.image,
            Path::new("/i.qcow2")
        );
    }
}
