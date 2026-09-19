// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Local `fluxctl serve` client. Same "not-found is a 400 with
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
        Self {
            base_url,
            token,
            http: reqwest::Client::new(),
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let req = self
            .http
            .request(method, format!("{}{}", self.base_url, path));
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    pub async fn create_vm(
        &self,
        name: &str,
        spec: &MicroVMSpec,
        kernel: Option<&str>,
    ) -> Result<Value> {
        let body = create_body(name, spec, kernel)?;
        let resp = self
            .request(reqwest::Method::POST, "/v1/vms")
            .json(&body)
            .send()
            .await
            .context("POST /v1/vms")?;
        response_json_or_err(resp).await
    }

    pub async fn get_vm(&self, id: &str) -> Result<Option<Value>> {
        let resp = self
            .request(reqwest::Method::GET, &format!("/v1/vms/{id}"))
            .send()
            .await
            .context("GET /v1/vms/{id}")?;
        if resp.status().is_success() {
            return Ok(Some(response_json_or_err(resp).await?));
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if is_not_found(&body) {
            return Ok(None);
        }
        bail!("GET /v1/vms/{id} failed: {status}: {body}")
    }

    pub async fn delete_vm(&self, id: &str) -> Result<()> {
        let resp = self
            .request(reqwest::Method::DELETE, &format!("/v1/vms/{id}"))
            .send()
            .await
            .context("DELETE /v1/vms/{id}")?;
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if is_not_found(&body) {
            return Ok(());
        }
        bail!("DELETE /v1/vms/{id} failed: {status}: {body}")
    }

    pub async fn exec(&self, id: &str, command: &str, timeout: Option<u64>) -> Result<Value> {
        let body = json!({"command": command, "timeout_seconds": timeout});
        let resp = self
            .request(reqwest::Method::POST, &format!("/v1/vms/{id}/agent"))
            .json(&body)
            .send()
            .await
            .context("POST agent")?;
        response_json_or_err(resp).await
    }

    pub async fn ensure_pool(
        &self,
        name: &str,
        size: usize,
        template: &MicroVMSpec,
    ) -> Result<Value> {
        // Warm-pool templates aren't resolved against the GuestImage catalog
        // (see `pools::reconcile`), so there's no verified kernel path to
        // forward here -- pool templates must name a direct disk image.
        let tmpl = create_body(&format!("{name}-tmpl"), template, None)?;
        let body = json!({"name": name, "size": size, "template": tmpl});
        let resp = self
            .request(reqwest::Method::POST, "/v1/pools")
            .json(&body)
            .send()
            .await
            .context("POST /v1/pools")?;
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
        let resp = self
            .request(reqwest::Method::POST, &format!("/v1/pools/{name}/claim"))
            .json(&body)
            .send()
            .await
            .context("claim")?;
        response_json_or_err(resp).await
    }

    pub async fn get_pool(&self, name: &str) -> Result<Option<Value>> {
        let resp = self
            .request(reqwest::Method::GET, &format!("/v1/pools/{name}"))
            .send()
            .await
            .context("GET pool")?;
        let status = resp.status();
        if status.is_success() {
            return Ok(Some(response_json_or_err(resp).await?));
        }
        let body = resp.text().await.unwrap_or_default();
        if is_not_found(&body) || status.as_u16() == 404 {
            return Ok(None);
        }
        bail!("GET /v1/pools/{name} failed")
    }
}

/// Build the `POST /v1/vms` (or pool-template) body from a `MicroVMSpec`.
/// `kernel`, when given, is the GuestImage-resolved host path for
/// direct-kernel boot (see `node_agent::resolve_image` /
/// `images::guest_image_kernel_path`) -- `MicroVMSpec` itself carries no
/// kernel field, since a kernel only ever comes from the catalog entry
/// `spec.image` names, never from the MicroVM spec directly.
pub fn create_body(name: &str, spec: &MicroVMSpec, kernel: Option<&str>) -> Result<Value> {
    let network = match spec.network_mode.as_str() {
        "none" => json!({"mode": "none"}),
        "user" => json!({"mode": "user", "forwards": []}),
        "tap" => {
            json!({"mode": "tap", "tap_name": spec.tap_name, "bridge": spec.bridge, "mac": spec.mac, "netns": spec.netns})
        }
        "macvtap" => {
            let parent = spec
                .parent
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("networkMode macvtap requires spec.parent"))?;
            json!({"mode": "macvtap", "parent": parent, "macvtap_mode": spec.macvtap_mode, "mac": spec.mac})
        }
        // Bridge-less tap on a host uplink NIC: no bridge, no macvtap (docs/direct-datapath.md).
        // `parent` names the uplink; `guestIps` lets the LAN discover the guest by ARP.
        "direct" => {
            let uplink = spec.parent.as_deref().ok_or_else(|| {
                anyhow::anyhow!("networkMode direct requires spec.parent (the uplink NIC)")
            })?;
            json!({
                "mode": "tap",
                "tap_name": spec.tap_name,
                "mac": spec.mac,
                "netns": false,
                "direct": {"outer": uplink, "mode": "l2-uplink", "guest_ips": spec.guest_ips}
            })
        }
        other => bail!("network_mode '{other}' is not supported"),
    };
    let mut body = json!({
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
    });
    if let Some(k) = kernel {
        body["kernel"] = json!(k);
    }
    Ok(body)
}

pub fn record_id(record: &Value) -> Option<String> {
    record
        .get("id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}
pub fn record_guest_ip(record: &Value) -> Option<String> {
    record
        .get("guest_ip")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
pub fn record_pid(record: &Value) -> Option<i64> {
    record.get("pid").and_then(|v| v.as_i64())
}
pub fn record_status(record: &Value) -> String {
    record
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string()
}

fn is_not_found(body: &str) -> bool {
    body.contains("VM not found") || body.contains("not found") || body.contains("NotFound")
}

async fn response_json_or_err(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    let body = resp.text().await.context("reading response body")?;
    if !status.is_success() {
        bail!("fluxvm API returned {status}: {body}");
    }
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
        let body = create_body("mvm-ci", &spec(), None).unwrap();
        assert_eq!(body["backend"], "firecracker");
        assert_eq!(body["network"]["mode"], "tap");
        assert_eq!(body["network"]["netns"], true);
        assert_eq!(body["agent"]["enabled"], true);
        assert!(body.get("kernel").is_none());
    }
    #[test]
    fn macvtap_requires_parent() {
        let mut s = spec();
        s.network_mode = "macvtap".into();
        s.parent = None;
        assert!(create_body("x", &s, None).is_err());
    }
    #[test]
    fn direct_maps_to_an_l2_uplink_tap_the_daemon_accepts() {
        let mut s = spec();
        s.network_mode = "direct".into();
        s.parent = Some("enp1s0".into());
        s.mac = Some("02:00:00:00:00:0a".into());
        s.guest_ips = vec!["10.0.0.5".into()];
        let body = create_body("x", &s, None).unwrap();
        assert_eq!(body["network"]["mode"], "tap");
        assert_eq!(body["network"]["netns"], false);
        assert_eq!(body["network"]["direct"]["outer"], "enp1s0");
        assert_eq!(body["network"]["direct"]["mode"], "l2-uplink");
        assert_eq!(body["network"]["direct"]["guest_ips"][0], "10.0.0.5");
        // and the daemon's own model must accept and validate exactly this shape
        let net: fluxvm_core::model::NetworkSpec =
            serde_json::from_value(body["network"].clone()).unwrap();
        net.validate_direct().expect("daemon validation");
    }
    #[test]
    fn direct_requires_the_uplink() {
        let mut s = spec();
        s.network_mode = "direct".into();
        s.parent = None;
        assert!(create_body("x", &s, None).is_err());
    }
    #[test]
    fn resolved_kernel_is_forwarded() {
        let body = create_body("mvm-ci", &spec(), Some("/boot/vmlinux")).unwrap();
        assert_eq!(body["kernel"], "/boot/vmlinux");
    }
    #[test]
    fn record_helpers() {
        let rec = json!({"id":"abc","guest_ip":"10.88.0.9","pid":42,"status":"running"});
        assert_eq!(record_id(&rec).as_deref(), Some("abc"));
        assert_eq!(record_guest_ip(&rec).as_deref(), Some("10.88.0.9"));
        assert_eq!(record_pid(&rec), Some(42));
    }
}
