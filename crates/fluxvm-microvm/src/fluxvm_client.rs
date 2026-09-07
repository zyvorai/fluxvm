// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Local `fluxvm serve` client. Same "not-found is a 400 with
//! `VM not found` in the body" contract as `fluxvm-kube`.

use crate::crd::MicroVMSpec;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

#[derive(Clone)]
pub struct FluxVMClient {
    base_url: String,
    token: Option<String>,
    http: reqwest::Client,
}

impl FluxVMClient {
    pub fn new(base_url: String, token: Option<String>) -> Self {
        Self { base_url, token, http: reqwest::Client::new() }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let req = self.http.request(method, format!("{}{}", self.base_url, path));
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    pub async fn create_vm(&self, name: &str, spec: &MicroVMSpec) -> Result<Value> {
        let body = create_body(name, spec)?;
        let resp = self.request(reqwest::Method::POST, "/v1/vms").json(&body).send().await.context("POST /v1/vms")?;
        response_json_or_err(resp).await
    }

    pub async fn get_vm(&self, id: &str) -> Result<Option<Value>> {
        let resp = self.request(reqwest::Method::GET, &format!("/v1/vms/{id}")).send().await.context("GET /v1/vms/{id}")?;
        if resp.status().is_success() {
            return Ok(Some(response_json_or_err(resp).await?));
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if is_not_found(&body) { return Ok(None); }
        bail!("GET /v1/vms/{id} failed: {status}: {body}")
    }

    pub async fn delete_vm(&self, id: &str) -> Result<()> {
        let resp = self.request(reqwest::Method::DELETE, &format!("/v1/vms/{id}")).send().await.context("DELETE /v1/vms/{id}")?;
        if resp.status().is_success() { return Ok(()); }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if is_not_found(&body) { return Ok(()); }
        bail!("DELETE /v1/vms/{id} failed: {status}: {body}")
    }

    pub async fn exec(&self, id: &str, command: &str, timeout: Option<u64>) -> Result<Value> {
        let body = json!({"command": command, "timeout_seconds": timeout});
        let resp = self.request(reqwest::Method::POST, &format!("/v1/vms/{id}/agent")).json(&body).send().await.context("POST agent")?;
        response_json_or_err(resp).await
    }

    pub async fn ensure_pool(&self, name: &str, size: usize, template: &MicroVMSpec) -> Result<Value> {
        let tmpl = create_body(&format!("{name}-tmpl"), template)?;
        let body = json!({"name": name, "size": size, "template": tmpl});
        let resp = self.request(reqwest::Method::POST, "/v1/pools").json(&body).send().await.context("POST /v1/pools")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if status.is_success() {
            return serde_json::from_str(&text).context("parse pool");
        }
        if status.as_u16() == 409 || text.to_lowercase().contains("exist") {
            return Ok(json!({"exists": true}));
        }
        bail!("POST /v1/pools failed: {status}: {text}")
    }

    pub async fn claim_pool(&self, name: &str, vm_name: &str, ttl: Option<u64>) -> Result<Value> {
        let body = json!({"name": vm_name, "ttl_seconds": ttl});
        let resp = self.request(reqwest::Method::POST, &format!("/v1/pools/{name}/claim")).json(&body).send().await.context("claim")?;
        response_json_or_err(resp).await
    }

    pub async fn get_pool(&self, name: &str) -> Result<Option<Value>> {
        let resp = self.request(reqwest::Method::GET, &format!("/v1/pools/{name}")).send().await.context("GET pool")?;
        let status = resp.status();
        if status.is_success() { return Ok(Some(response_json_or_err(resp).await?)); }
        let body = resp.text().await.unwrap_or_default();
        if is_not_found(&body) || status.as_u16() == 404 { return Ok(None); }
        bail!("GET /v1/pools/{name} failed")
    }
}

pub fn create_body(name: &str, spec: &MicroVMSpec) -> Result<Value> {
    let network = match spec.network_mode.as_str() {
        "none" => json!({"mode": "none"}),
        "user" => json!({"mode": "user", "forwards": []}),
        "tap" => json!({"mode": "tap", "tap_name": spec.tap_name, "bridge": spec.bridge, "mac": spec.mac, "netns": spec.netns}),
        "macvtap" => {
            let parent = spec.parent.as_deref().ok_or_else(|| anyhow::anyhow!("networkMode macvtap requires spec.parent"))?;
            json!({"mode": "macvtap", "parent": parent, "macvtap_mode": spec.macvtap_mode, "mac": spec.mac})
        }
        other => bail!("network_mode '{other}' is not supported"),
    };
    Ok(json!({
        "name": name,
        "backend": spec.backend,
        "image": spec.image,
        "vcpus": spec.vcpus,
        "memory_mib": spec.memory_mib,
        "disk_size_gib": spec.disk_size_gib,
        "network": network,
        "storage": spec.storage,
        "ttl_seconds": spec.ttl_seconds,
        "agent": { "enabled": spec.command.is_some() },
    }))
}

pub fn record_id(record: &Value) -> Option<String> {
    record.get("id").and_then(|v| v.as_str()).map(str::to_string)
}
pub fn record_guest_ip(record: &Value) -> Option<String> {
    record.get("guest_ip").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(str::to_string)
}
pub fn record_pid(record: &Value) -> Option<i64> { record.get("pid").and_then(|v| v.as_i64()) }
pub fn record_status(record: &Value) -> String {
    record.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string()
}

fn is_not_found(body: &str) -> bool {
    body.contains("VM not found") || body.contains("not found") || body.contains("NotFound")
}

async fn response_json_or_err(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    let body = resp.text().await.context("reading response body")?;
    if !status.is_success() { bail!("fluxvm API returned {status}: {body}"); }
    serde_json::from_str(&body).with_context(|| format!("parsing fluxvm API response: {body}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spec() -> MicroVMSpec {
        MicroVMSpec {
            backend: "firecracker".into(),
            image: "/var/lib/fluxvm/images/rootfs.ext4".into(),
            vcpus: 2,
            memory_mib: 1024,
            network_mode: "tap".into(),
            bridge: Some("vmbr0".into()),
            netns: true,
            storage: "default".into(),
            command: Some("id".into()),
            ..Default::default()
        }
    }
    #[test]
    fn tap_netns_body() {
        let body = create_body("mvm-ci", &spec()).unwrap();
        assert_eq!(body["backend"], "firecracker");
        assert_eq!(body["network"]["mode"], "tap");
        assert_eq!(body["network"]["netns"], true);
        assert_eq!(body["agent"]["enabled"], true);
    }
    #[test]
    fn macvtap_requires_parent() {
        let mut s = spec();
        s.network_mode = "macvtap".into();
        s.parent = None;
        assert!(create_body("x", &s).is_err());
    }
    #[test]
    fn record_helpers() {
        let rec = json!({"id":"abc","guest_ip":"10.88.0.9","pid":42,"status":"running"});
        assert_eq!(record_id(&rec).as_deref(), Some("abc"));
        assert_eq!(record_guest_ip(&rec).as_deref(), Some("10.88.0.9"));
        assert_eq!(record_pid(&rec), Some(42));
    }
}
