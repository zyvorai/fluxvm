// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Self-control for `vz` guests created with `apple.self_control`: an MCP server (streamable HTTP, JSON replies) that
//! software inside the guest reaches at `http://127.0.0.1:7790/mcp`. The guest's relay goes over vsock to the runner,
//! which connects to this daemon's unix socket and first writes `FLUXVM-SELF <vm id>\n`, so the VM is named by the
//! host side and a guest can only ever act on itself. Restore and restart run a moment after the reply is sent, so the
//! answer reaches the guest before it is rewound or rebooted.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use fluxvm_core::model::VmStatus;
use fluxvm_scheduler::VmManager;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use uuid::Uuid;

const PREAMBLE: &str = "FLUXVM-SELF ";
/// How long after replying a deferred operation starts.
const DEFER: Duration = Duration::from_secs(1);

/// The outcome of the last deferred operation per VM, for `self_info` (kept in memory; a daemon restart forgets it).
fn last_ops() -> &'static Mutex<HashMap<Uuid, Value>> {
    static OPS: OnceLock<Mutex<HashMap<Uuid, Value>>> = OnceLock::new();
    OPS.get_or_init(Default::default)
}

/// Binds the self-control socket for this daemon and serves it in the background.
pub fn spawn(m: Arc<VmManager>, state_dir: &Path) {
    let path = match fluxvm_scheduler::vz_screen::self_control_socket_path(state_dir) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "self-control socket directory unavailable");
            return;
        }
    };
    match bind(&path) {
        Ok(listener) => {
            fluxvm_scheduler::vz_screen::set_self_control_socket(path.clone());
            tracing::info!(socket = %path.display(), "serving guest self-control");
            tokio::spawn(accept_loop(m, listener));
        }
        Err(e) => {
            tracing::warn!(error = %e, socket = %path.display(), "cannot serve guest self-control")
        }
    }
}

fn bind(path: &PathBuf) -> std::io::Result<tokio::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    let l = tokio::net::UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

async fn accept_loop(m: Arc<VmManager>, listener: tokio::net::UnixListener) {
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                tracing::warn!(error = %e, "self-control accept failed");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let m = m.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_conn(m, stream).await {
                tracing::debug!(error = %e, "self-control connection ended");
            }
        });
    }
}

async fn serve_conn(m: Arc<VmManager>, stream: tokio::net::UnixStream) -> anyhow::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut limited = (&mut reader).take(128);
        limited.read_line(&mut line).await
    })
    .await??;
    let id: Uuid = line
        .strip_prefix(PREAMBLE)
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| anyhow::anyhow!("bad self-control preamble"))?;
    let vm = m.get(id).await?;
    if !vm.request.apple.as_ref().is_some_and(|a| a.self_control) {
        anyhow::bail!("VM {id} does not have apple.self_control");
    }
    let app = Router::new()
        .route(
            "/mcp",
            post(mcp).get(|| async { StatusCode::METHOD_NOT_ALLOWED }),
        )
        .with_state((m, id));
    let service = hyper_util::service::TowerToHyperService::new(app);
    hyper::server::conn::http1::Builder::new()
        .keep_alive(false)
        .serve_connection(hyper_util::rt::TokioIo::new(reader), service)
        .await?;
    Ok(())
}

type Ctx = (Arc<VmManager>, Uuid);

async fn mcp(State((m, id)): State<Ctx>, Json(msg): Json<Value>) -> Response {
    let Some(rpc_id) = msg.get("id").cloned() else {
        // Notifications (e.g. notifications/initialized) need no answer.
        return StatusCode::ACCEPTED.into_response();
    };
    let method = msg
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": params.get("protocolVersion").cloned().unwrap_or(json!("2025-06-18")),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fluxvm-self", "version": env!("CARGO_PKG_VERSION")},
            "instructions": "Tools that act on the VM you are running in. Take a snapshot before risky changes; \
                self_snapshot_restore rewinds this machine (your own memory included) to that point, and self_restart \
                reboots it. Both start about a second after they answer.",
        })),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({"tools": tools()})),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            Ok(match call(&m, id, name, &args).await {
                Ok(text) => json!({"content": [{"type": "text", "text": text}]}),
                Err(e) => {
                    json!({"content": [{"type": "text", "text": format!("{e:#}")}], "isError": true})
                }
            })
        }
        _ => Err(json!({"code": -32601, "message": format!("method not found: {method}")})),
    };
    let body = match result {
        Ok(r) => json!({"jsonrpc": "2.0", "id": rpc_id, "result": r}),
        Err(e) => json!({"jsonrpc": "2.0", "id": rpc_id, "error": e}),
    };
    let mut resp = Json(body).into_response();
    resp.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    resp
}

fn tools() -> Value {
    let tag = json!({"type": "string", "pattern": "^[A-Za-z0-9._-]{1,64}$"});
    let none = json!({"type": "object", "properties": {}});
    json!([
        {"name": "self_info", "description": "This VM: id, name, status, resources, snapshots, and the outcome of the last snapshot, restore or restart.", "inputSchema": none, "annotations": {"readOnlyHint": true}},
        {"name": "self_snapshot_list", "description": "Snapshots of this VM (tag, time, size).", "inputSchema": none, "annotations": {"readOnlyHint": true}},
        {"name": "self_snapshot", "description": "Snapshot this VM's memory and disk under tag. The guest pauses briefly; it starts about a second after this answers, so check self_info or self_snapshot_list a few seconds later.", "inputSchema": {"type": "object", "properties": {"tag": tag}, "required": ["tag"]}},
        {"name": "self_snapshot_restore", "description": "Rewind this VM to snapshot tag: memory, disk and running programs, including the caller. Starts about a second after this answers; work since the snapshot is lost.", "inputSchema": {"type": "object", "properties": {"tag": tag}, "required": ["tag"]}, "annotations": {"destructiveHint": true}},
        {"name": "self_snapshot_delete", "description": "Delete snapshot tag of this VM.", "inputSchema": {"type": "object", "properties": {"tag": tag}, "required": ["tag"]}, "annotations": {"destructiveHint": true}},
        {"name": "self_restart", "description": "Stop and start this VM (a cold reboot). Starts about a second after this answers.", "inputSchema": none, "annotations": {"destructiveHint": true}},
    ])
}

fn tag_arg(args: &Value) -> anyhow::Result<String> {
    let tag = args.get("tag").and_then(Value::as_str).unwrap_or_default();
    if tag.is_empty()
        || tag.len() > 64
        || !tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        anyhow::bail!("tag must be 1-64 characters of A-Z, a-z, 0-9, '.', '_' or '-'");
    }
    Ok(tag.to_owned())
}

async fn has_snapshot(m: &VmManager, id: Uuid, tag: &str) -> anyhow::Result<bool> {
    Ok(m.list_vm_snapshots(id).await?.iter().any(|s| s.tag == tag))
}

/// Fails while an earlier snapshot, restore or restart of this VM is still pending or running.
fn ensure_idle(id: Uuid) -> anyhow::Result<()> {
    if let Some(op) = last_ops().lock().unwrap().get(&id)
        && op["state"] == "pending"
    {
        anyhow::bail!(
            "{} is still in progress; try again when self_info shows it done",
            op["op"].as_str().unwrap_or("an operation")
        );
    }
    Ok(())
}

/// Runs `op` after [`DEFER`] and records how it went for `self_info`.
fn defer<F>(id: Uuid, what: String, op: F)
where
    F: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
{
    last_ops().lock().unwrap().insert(
        id,
        json!({"op": what, "state": "pending", "at": chrono::Utc::now()}),
    );
    tokio::spawn(async move {
        tokio::time::sleep(DEFER).await;
        let outcome = op.await;
        if let Err(e) = &outcome {
            tracing::warn!(%id, op = %what, error = %e, "guest self-control operation failed");
        }
        fluxvm_scheduler::audit_event(
            "vm.self_control",
            &[("vm_id", &id.to_string()), ("op", &what)],
        );
        last_ops().lock().unwrap().insert(
            id,
            match outcome {
                Ok(()) => json!({"op": what, "state": "done", "at": chrono::Utc::now()}),
                Err(e) => json!({"op": what, "state": "failed", "error": format!("{e:#}"), "at": chrono::Utc::now()}),
            },
        );
    });
}

async fn call(m: &Arc<VmManager>, id: Uuid, name: &str, args: &Value) -> anyhow::Result<String> {
    let pretty = |v: Value| serde_json::to_string_pretty(&v).unwrap_or_default();
    match name {
        "self_info" => {
            let vm = m.get(id).await?;
            let snaps = m.list_vm_snapshots(id).await.unwrap_or_default();
            Ok(pretty(json!({
                "id": id,
                "name": vm.name,
                "status": vm.status,
                "vcpus": vm.request.vcpus,
                "memory_mib": vm.request.memory_mib,
                "guest_ip": vm.guest_ip,
                "snapshots": snaps.iter().map(|s| &s.tag).collect::<Vec<_>>(),
                "last_operation": last_ops().lock().unwrap().get(&id).cloned(),
            })))
        }
        "self_snapshot_list" => Ok(pretty(json!(m.list_vm_snapshots(id).await?))),
        "self_snapshot" => {
            let tag = tag_arg(args)?;
            ensure_idle(id)?;
            if has_snapshot(m, id, &tag).await? {
                anyhow::bail!("snapshot {tag:?} already exists");
            }
            let m2 = m.clone();
            let t = tag.clone();
            defer(id, format!("snapshot {tag}"), async move {
                m2.create_vm_snapshot(id, &t).await
            });
            Ok(format!(
                "Snapshot {tag:?} starts in about a second (the VM pauses while it is taken). Check self_snapshot_list shortly."
            ))
        }
        "self_snapshot_restore" => {
            let tag = tag_arg(args)?;
            ensure_idle(id)?;
            if !has_snapshot(m, id, &tag).await? {
                anyhow::bail!("no snapshot {tag:?}");
            }
            let m2 = m.clone();
            let t = tag.clone();
            defer(id, format!("restore {tag}"), async move {
                // A running vz VM is restored by stopping it and starting it from the saved state.
                if matches!(
                    m2.get(id).await?.status,
                    VmStatus::Running | VmStatus::Paused
                ) {
                    m2.stop(id).await?;
                }
                m2.restore_vm_snapshot(id, &t).await.map(|_| ())
            });
            Ok(format!(
                "Restoring {tag:?} in about a second: this machine, including this program, goes back to that snapshot."
            ))
        }
        "self_snapshot_delete" => {
            let tag = tag_arg(args)?;
            m.delete_vm_snapshot(id, &tag).await?;
            Ok(format!("Deleted snapshot {tag:?}."))
        }
        "self_restart" => {
            ensure_idle(id)?;
            let vm = m.get(id).await?;
            if !matches!(vm.status, VmStatus::Running | VmStatus::Paused) {
                anyhow::bail!("the VM is {:?}", vm.status);
            }
            let m2 = m.clone();
            defer(id, "restart".into(), async move {
                m2.restart(id).await.map(|_| ())
            });
            Ok("Restarting in about a second.".into())
        }
        _ => anyhow::bail!("unknown tool {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_checked_before_anything_is_deferred() {
        assert_eq!(
            tag_arg(&json!({"tag": "before-upgrade.1"})).unwrap(),
            "before-upgrade.1"
        );
        for bad in ["", "a b", "../x", &"x".repeat(65)] {
            assert!(tag_arg(&json!({"tag": bad})).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn every_tool_has_a_schema_and_destructive_ones_say_so() {
        let tools = tools();
        let names: Vec<_> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "self_info",
                "self_snapshot_list",
                "self_snapshot",
                "self_snapshot_restore",
                "self_snapshot_delete",
                "self_restart"
            ]
        );
        for t in tools.as_array().unwrap() {
            assert_eq!(t["inputSchema"]["type"], "object");
        }
        assert_eq!(tools[3]["annotations"]["destructiveHint"], true);
    }
}
