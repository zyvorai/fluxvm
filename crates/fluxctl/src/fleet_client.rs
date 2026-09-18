// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Thin HTTP client for `fluxvm-agent central`'s `/fleet/*` API, backing
//! the `fluxctl fleet ...` subcommands. Every fleet operation used to mean a
//! raw `curl` call (see docs/operations.md's "Distributed node-agent"
//! section) — this gives it the same CLI-parity treatment
//! `migrate`/`ping`/`copy-to` already gave the per-node REST API, just
//! against the central registry instead of a node's own `fluxctl serve`.
//!
//! Deliberately request/response-untyped (`serde_json::Value` in and out):
//! `fluxvm-agent::central` itself treats `CreateVmRequest`/`VmRecord`
//! bodies as opaque JSON rather than depending on `fluxvm-core` (see that
//! module's own doc comment), and this client sits on the other side of
//! exactly that same boundary — it has no more business assuming a fixed
//! shape than central does.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

fn authed(req: reqwest::RequestBuilder, token: Option<&str>) -> reqwest::RequestBuilder {
    match token {
        Some(t) => req.bearer_auth(t),
        None => req,
    }
}

/// Turns a non-2xx response into an error carrying both the status and the
/// response body, the same "surface, don't hide" posture `central`'s own
/// `AppError` uses server-side — a bare status code alone (e.g. "502 Bad
/// Gateway") tells an operator nothing about *why* the registry rejected
/// the call.
async fn check_success(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    anyhow::bail!("{what} failed ({status}): {body}");
}

/// `GET /fleet/nodes`.
pub async fn list_nodes(central: &str, token: Option<&str>) -> Result<Value> {
    let http = reqwest::Client::new();
    let resp = authed(http.get(format!("{central}/fleet/nodes")), token)
        .send()
        .await
        .context("GET /fleet/nodes")?;
    let resp = check_success(resp, "listing fleet nodes").await?;
    resp.json().await.context("parsing /fleet/nodes response")
}

/// `GET /fleet/nodes/{name}` — one node's own record, the same shape a
/// `GET /fleet/nodes` list entry has, without fetching and filtering the
/// whole fleet just to check one node's `healthy`/`cordoned`/free-capacity
/// state.
pub async fn get_node(central: &str, token: Option<&str>, name: &str) -> Result<Value> {
    let http = reqwest::Client::new();
    let resp = authed(http.get(format!("{central}/fleet/nodes/{name}")), token)
        .send()
        .await
        .with_context(|| format!("GET /fleet/nodes/{name}"))?;
    let resp = check_success(resp, &format!("fetching node '{name}'")).await?;
    resp.json()
        .await
        .with_context(|| format!("parsing /fleet/nodes/{name} response"))
}

async fn set_cordoned(
    central: &str,
    token: Option<&str>,
    name: &str,
    cordon: bool,
) -> Result<Value> {
    let verb = if cordon { "cordon" } else { "uncordon" };
    let http = reqwest::Client::new();
    let resp = authed(
        http.post(format!("{central}/fleet/nodes/{name}/{verb}")),
        token,
    )
    .send()
    .await
    .with_context(|| format!("POST /fleet/nodes/{name}/{verb}"))?;
    let resp = check_success(resp, &format!("{verb}ing node '{name}'")).await?;
    resp.json()
        .await
        .with_context(|| format!("parsing /fleet/nodes/{name}/{verb} response"))
}

/// `POST /fleet/nodes/{name}/cordon`.
pub async fn cordon(central: &str, token: Option<&str>, name: &str) -> Result<Value> {
    set_cordoned(central, token, name, true).await
}

/// `POST /fleet/nodes/{name}/uncordon`.
pub async fn uncordon(central: &str, token: Option<&str>, name: &str) -> Result<Value> {
    set_cordoned(central, token, name, false).await
}

/// `DELETE /fleet/nodes/{name}`.
pub async fn deregister(central: &str, token: Option<&str>, name: &str) -> Result<()> {
    let http = reqwest::Client::new();
    let resp = authed(http.delete(format!("{central}/fleet/nodes/{name}")), token)
        .send()
        .await
        .with_context(|| format!("DELETE /fleet/nodes/{name}"))?;
    check_success(resp, &format!("deregistering node '{name}'")).await?;
    Ok(())
}

/// `GET /fleet/capacity`.
pub async fn capacity(central: &str, token: Option<&str>) -> Result<Value> {
    let http = reqwest::Client::new();
    let resp = authed(http.get(format!("{central}/fleet/capacity")), token)
        .send()
        .await
        .context("GET /fleet/capacity")?;
    let resp = check_success(resp, "fetching fleet capacity").await?;
    resp.json()
        .await
        .context("parsing /fleet/capacity response")
}

/// `POST /fleet/vms`. `node`, when given, is merged into `body` as the
/// top-level `"node"` field central reads to bypass automatic placement —
/// overriding whatever the spec file itself may have set, since an
/// explicit `--node` flag on the command line is the more specific
/// request. `node_selector`, when non-empty, is merged the same way into
/// `body["nodeSelector"]` — one flag's keys overriding a same-named key the
/// spec file's own `"nodeSelector"` object already set, the rest of that
/// object's entries left untouched.
pub async fn create_vm(
    central: &str,
    token: Option<&str>,
    mut body: Value,
    node: Option<String>,
    node_selector: HashMap<String, String>,
) -> Result<Value> {
    let obj = body
        .as_object_mut()
        .context("VM spec must be a JSON object")?;
    if let Some(node) = node {
        obj.insert("node".into(), Value::String(node));
    }
    if !node_selector.is_empty() {
        let existing = obj
            .entry("nodeSelector")
            .or_insert_with(|| Value::Object(serde_json::Map::new()))
            .as_object_mut()
            .context("VM spec's \"nodeSelector\" must be a JSON object")?;
        for (k, v) in node_selector {
            existing.insert(k, Value::String(v));
        }
    }
    let http = reqwest::Client::new();
    let resp = authed(http.post(format!("{central}/fleet/vms")), token)
        .json(&body)
        .send()
        .await
        .context("POST /fleet/vms")?;
    let resp = check_success(resp, "creating VM through fleet").await?;
    resp.json().await.context("parsing /fleet/vms response")
}

/// `GET /fleet/vms`.
pub async fn list_vms(central: &str, token: Option<&str>) -> Result<Value> {
    let http = reqwest::Client::new();
    let resp = authed(http.get(format!("{central}/fleet/vms")), token)
        .send()
        .await
        .context("GET /fleet/vms")?;
    let resp = check_success(resp, "listing fleet-wide VMs").await?;
    resp.json().await.context("parsing /fleet/vms response")
}

/// `GET /fleet/nodes/{name}/vms`.
pub async fn node_vms(central: &str, token: Option<&str>, name: &str) -> Result<Value> {
    let http = reqwest::Client::new();
    let resp = authed(http.get(format!("{central}/fleet/nodes/{name}/vms")), token)
        .send()
        .await
        .with_context(|| format!("GET /fleet/nodes/{name}/vms"))?;
    let resp = check_success(resp, &format!("listing VMs on node '{name}'")).await?;
    resp.json()
        .await
        .with_context(|| format!("parsing /fleet/nodes/{name}/vms response"))
}

/// `DELETE /fleet/vms/{node}/{id}`.
pub async fn delete_vm(central: &str, token: Option<&str>, node: &str, id: Uuid) -> Result<()> {
    let http = reqwest::Client::new();
    let resp = authed(
        http.delete(format!("{central}/fleet/vms/{node}/{id}")),
        token,
    )
    .send()
    .await
    .with_context(|| format!("DELETE /fleet/vms/{node}/{id}"))?;
    check_success(resp, &format!("deleting VM {id} on node '{node}'")).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_agent::central::{CentralConfig, router};
    use serde_json::json;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    /// Spins up a real `fluxvm-agent central` router (no mocking) on an
    /// ephemeral port and returns its base URL — the same "no separate
    /// fake, exercise the real thing" posture `fluxvm-storage`'s own tests
    /// use for `flock` behavior. Backed by a fresh temp dir per test so
    /// runs never share `fleet-nodes.json` state.
    async fn spawn_central(token: Option<&str>) -> (String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let app = router(CentralConfig {
            state_dir: dir.path().to_path_buf(),
            token: token.map(str::to_string),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), dir)
    }

    async fn register_node(central: &str, name: &str, fluxvm_url: &str) {
        register_node_with_labels(central, name, fluxvm_url, &[]).await;
    }

    async fn register_node_with_labels(
        central: &str,
        name: &str,
        fluxvm_url: &str,
        labels: &[(&str, &str)],
    ) {
        let http = reqwest::Client::new();
        let labels: HashMap<String, String> = labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let resp = http
            .post(format!("{central}/fleet/register"))
            .json(&json!({
                "name": name,
                "fluxvm_url": fluxvm_url,
                "vcpus_total": 8,
                "memory_mib_total": 16384,
                "vm_count": 0,
                "labels": labels,
            }))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    #[tokio::test]
    async fn list_nodes_sees_a_registered_node() {
        let (central, _dir) = spawn_central(None).await;
        register_node(&central, "worker-1", "http://worker-1:7788").await;

        let body = list_nodes(&central, None).await.unwrap();
        let items = body["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], "worker-1");
        assert_eq!(items[0]["cordoned"], false);
    }

    #[tokio::test]
    async fn get_node_returns_the_named_node_only() {
        let (central, _dir) = spawn_central(None).await;
        register_node(&central, "worker-1", "http://worker-1:7788").await;
        register_node(&central, "worker-2", "http://worker-2:7788").await;

        let body = get_node(&central, None, "worker-1").await.unwrap();
        assert_eq!(body["name"], "worker-1");
        assert_eq!(body["cordoned"], false);
    }

    #[tokio::test]
    async fn get_node_unknown_name_is_a_readable_not_found_error() {
        let (central, _dir) = spawn_central(None).await;
        let err = get_node(&central, None, "ghost").await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("404"), "expected a 404, got: {msg}");
        assert!(
            msg.contains("ghost"),
            "error should name the unknown node: {msg}"
        );
    }

    #[tokio::test]
    async fn cordon_then_uncordon_round_trips() {
        let (central, _dir) = spawn_central(None).await;
        register_node(&central, "worker-1", "http://worker-1:7788").await;

        let cordoned = cordon(&central, None, "worker-1").await.unwrap();
        assert_eq!(cordoned["cordoned"], true);

        let uncordoned = uncordon(&central, None, "worker-1").await.unwrap();
        assert_eq!(uncordoned["cordoned"], false);
    }

    #[tokio::test]
    async fn cordon_unknown_node_is_a_readable_error() {
        let (central, _dir) = spawn_central(None).await;
        let err = cordon(&central, None, "ghost").await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ghost"),
            "error should name the unknown node: {msg}"
        );
    }

    #[tokio::test]
    async fn deregister_rejects_a_still_healthy_node() {
        let (central, _dir) = spawn_central(None).await;
        register_node(&central, "worker-1", "http://worker-1:7788").await;

        let err = deregister(&central, None, "worker-1").await.unwrap_err();
        assert!(
            err.to_string().contains("409") || err.to_string().to_lowercase().contains("heartbeat"),
            "expected a still-healthy rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn deregister_unknown_node_is_not_found() {
        let (central, _dir) = spawn_central(None).await;
        let err = deregister(&central, None, "ghost").await.unwrap_err();
        assert!(err.to_string().contains("404"));
    }

    #[tokio::test]
    async fn capacity_reflects_a_registered_nodes_totals() {
        let (central, _dir) = spawn_central(None).await;
        register_node(&central, "worker-1", "http://worker-1:7788").await;

        let cap = capacity(&central, None).await.unwrap();
        assert_eq!(cap["nodes_total"], 1);
        assert_eq!(cap["nodes_healthy"], 1);
        assert_eq!(cap["vcpus_total"], 8);
        assert_eq!(cap["memory_mib_total"], 16384);
    }

    #[tokio::test]
    async fn bearer_token_is_required_when_configured() {
        let (central, _dir) = spawn_central(Some("s3cret")).await;

        let unauthed = list_nodes(&central, None).await;
        assert!(unauthed.is_err(), "missing bearer token must be rejected");

        let authed = list_nodes(&central, Some("s3cret")).await;
        assert!(authed.is_ok(), "correct bearer token must be accepted");

        let wrong = list_nodes(&central, Some("nope")).await;
        assert!(wrong.is_err(), "wrong bearer token must be rejected");
    }

    #[tokio::test]
    async fn create_vm_merges_the_node_flag_and_routes_to_it() {
        // Fake a node's own `fluxctl serve` /v1/vms create endpoint so the
        // fleet proxy has somewhere real to forward to.
        let node_app = axum::Router::new().route(
            "/v1/vms",
            axum::routing::post(|axum::Json(body): axum::Json<Value>| async move {
                axum::Json(
                    json!({"id": "11111111-1111-1111-1111-111111111111", "name": body["name"]}),
                )
            }),
        );
        let node_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node_addr = node_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(node_listener, node_app).await.unwrap();
        });
        let node_url = format!("http://{node_addr}");

        let (central, _dir) = spawn_central(None).await;
        register_node(&central, "worker-1", &node_url).await;

        let spec = json!({"name": "test-vm"});
        let result = create_vm(
            &central,
            None,
            spec,
            Some("worker-1".to_string()),
            HashMap::new(),
        )
        .await
        .unwrap();
        assert_eq!(result["node"], "worker-1");
        assert_eq!(result["vm"]["name"], "test-vm");
    }

    #[tokio::test]
    async fn create_vm_with_no_node_and_no_registered_nodes_fails_clearly() {
        let (central, _dir) = spawn_central(None).await;
        let err = create_vm(&central, None, json!({"name": "x"}), None, HashMap::new())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("503") || err.to_string().contains("no healthy"));
    }

    #[tokio::test]
    async fn create_vm_merges_the_node_selector_flag_and_routes_to_a_matching_node() {
        let node_app = axum::Router::new().route(
            "/v1/vms",
            axum::routing::post(|axum::Json(body): axum::Json<Value>| async move {
                axum::Json(
                    json!({"id": "22222222-2222-2222-2222-222222222222", "name": body["name"]}),
                )
            }),
        );
        let node_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node_addr = node_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(node_listener, node_app).await.unwrap();
        });
        let node_url = format!("http://{node_addr}");

        let (central, _dir) = spawn_central(None).await;
        register_node_with_labels(&central, "worker-gpu", &node_url, &[("gpu", "true")]).await;

        let spec = json!({"name": "test-vm"});
        let selector: HashMap<String, String> = [("gpu".to_string(), "true".to_string())]
            .into_iter()
            .collect();
        let result = create_vm(&central, None, spec, None, selector)
            .await
            .unwrap();
        assert_eq!(result["node"], "worker-gpu");
    }

    #[tokio::test]
    async fn create_vm_node_selector_matching_nothing_is_a_readable_error() {
        let (central, _dir) = spawn_central(None).await;
        register_node(&central, "worker-1", "http://worker-1:7788").await;

        let selector: HashMap<String, String> = [("gpu".to_string(), "true".to_string())]
            .into_iter()
            .collect();
        let err = create_vm(&central, None, json!({"name": "x"}), None, selector)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("nodeSelector"),
            "error should name the unmatched selector: {err}"
        );
    }

    #[tokio::test]
    async fn node_vms_and_delete_vm_proxy_to_the_named_node() {
        let node_app = axum::Router::new()
            .route(
                "/v1/vms",
                axum::routing::get(|| async {
                    axum::Json(json!({"items": [{"id": "abc", "name": "on-worker-1"}]}))
                }),
            )
            .route(
                "/v1/vms/{id}",
                axum::routing::delete(|| async { StatusCodeOk }),
            );
        let node_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let node_addr = node_listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(node_listener, node_app).await.unwrap();
        });
        let node_url = format!("http://{node_addr}");

        let (central, _dir) = spawn_central(None).await;
        register_node(&central, "worker-1", &node_url).await;

        let vms = node_vms(&central, None, "worker-1").await.unwrap();
        assert_eq!(vms["items"][0]["name"], "on-worker-1");
        assert_eq!(vms["items"][0]["node"], "worker-1");

        let id = Uuid::new_v4();
        delete_vm(&central, None, "worker-1", id).await.unwrap();
    }

    /// A zero-arg handler that just returns 204, spelled as a unit struct
    /// implementing `IntoResponse` so the route above reads naturally.
    struct StatusCodeOk;
    impl axum::response::IntoResponse for StatusCodeOk {
        fn into_response(self) -> axum::response::Response {
            axum::http::StatusCode::NO_CONTENT.into_response()
        }
    }
}
