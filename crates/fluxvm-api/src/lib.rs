// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, delete, get, post},
};
use fluxvm_core::{
    config::{Role, constant_time_eq},
    model::{BackendKind, ClaimOverrides, CreateVmRequest, PoolSpec, VmRecord, VmStatus},
};
use fluxvm_image::{self as image, BuildImageRequest};
use fluxvm_scheduler::VmManager;
use serde::Deserialize;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}
impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: format!("{:#}", e.into()),
        }
    }
}
impl ApiError {
    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

/// Bounces a request without a valid bearer token; requests that do have
/// one carry their resolved `Role` (and optional token name) onward.
/// Fail-closed when `auth.must_authenticate(listen)` is true.
async fn auth_middleware(
    State(m): State<Arc<VmManager>>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    if path == "/healthz" {
        return next.run(req).await;
    }
    let must = m.cfg.auth.must_authenticate(&m.cfg.listen);
    let (role, token_name) = if !must && m.cfg.auth.tokens.is_empty() {
        (Some(Role::Admin), Some("anonymous-admin".to_string()))
    } else if m.cfg.auth.tokens.is_empty() && must {
        (None, None)
    } else {
        let presented = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));
        match presented.and_then(|t| {
            m.cfg
                .auth
                .tokens
                .iter()
                .find(|entry| constant_time_eq(&entry.token, t))
        }) {
            Some(entry) => (
                Some(entry.role),
                entry.name.clone().or_else(|| Some("unnamed".into())),
            ),
            None => (None, None),
        }
    };
    match role {
        Some(role) => {
            req.extensions_mut().insert(role);
            if let Some(name) = token_name.clone() {
                req.extensions_mut().insert(AuditActor(name));
            }
            let response = next.run(req).await;
            audit_log(
                token_name.as_deref().unwrap_or("anonymous"),
                role,
                &method,
                &path,
                response.status().as_u16(),
            );
            response
        }
        None => {
            fluxvm_core::metrics::inc_auth_deny();
            audit_log("none", Role::ReadOnly, &method, &path, 401);
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "missing or invalid bearer token"})),
            )
                .into_response()
        }
    }
}

#[derive(Clone, Debug)]
struct AuditActor(pub String);

fn audit_log(actor: &str, role: Role, method: &Method, path: &str, status: u16) {
    let role = match role {
        Role::Admin => "admin",
        Role::ReadOnly => "read-only",
    };
    tracing::info!(
        target: "fluxvm_audit",
        actor = %actor,
        role = %role,
        method = %method,
        path = %path,
        status = status,
        "audit"
    );
}

fn require_admin(role: Role) -> ApiResult<()> {
    if role != Role::Admin {
        return Err(ApiError::forbidden("admin role required"));
    }
    Ok(())
}

pub fn router(manager: Arc<VmManager>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { Json(json!({"ok": true})) }))
        .route("/metrics", get(metrics))
        .route("/v1/vms", post(create_vm).get(list_vms))
        .route("/v1/vms/{id}", get(get_vm).delete(delete_vm))
        .route("/v1/vms/{id}/start", post(start_vm))
        .route(
            "/v1/vms/{id}/start-from-snapshot",
            post(start_vm_from_snapshot),
        )
        .route("/v1/vms/{id}/snapshot", post(snapshot_vm))
        .route("/v1/vms/{id}/stop", post(stop_vm))
        .route("/v1/vms/{id}/pause", post(pause_vm))
        .route("/v1/vms/{id}/resume", post(resume_vm))
        .route("/v1/vms/{id}/resources", post(set_vm_resources))
        .route("/v1/vms/{id}/cpuset", get(vm_cpuset))
        .route("/v1/vms/{id}/freeze", post(freeze_vm))
        .route("/v1/vms/{id}/thaw", post(thaw_vm))
        .route("/v1/vms/{id}/frozen", get(vm_frozen))
        .route("/v1/vms/{id}/stats", get(vm_stats))
        .route("/v1/vms/{id}/network/stats", get(vm_network_stats))
        .route("/v1/vms/{id}/network/flows", get(vm_network_flows))
        .route("/v1/vms/{id}/network/status", get(vm_network_status))
        .route(
            "/v1/vms/{id}/network/policy",
            get(get_vm_network_policy).post(set_vm_network_policy),
        )
        .route("/v1/vms/{id}/pressure", get(vm_pressure))
        .route("/v1/vms/{id}/logs", get(vm_logs))
        .route("/v1/vms/{id}/agent", post(agent_exec))
        .route("/v1/vms/{id}/agent/put-file", post(agent_put_file))
        .route("/v1/vms/{id}/agent/get-file", post(agent_get_file))
        .route("/v1/vms/{id}/console", get(agent_console))
        .route("/v1/vms/{id}/qga/ping", post(qga_ping))
        .route("/v1/vms/{id}/qga/exec", post(qga_exec))
        .route("/v1/vms/{id}/qga/firewall/open", post(qga_firewall_open))
        .route("/v1/vms/{id}/qga/firewall/close", post(qga_firewall_close))
        .route("/v1/sandboxes", post(create_sandbox).get(list_sandboxes))
        .route("/v1/sandboxes/{id}/snapshot", post(snapshot_sandbox))
        .route("/v1/sandboxes/{id}/fs/read", post(sandbox_fs_read))
        .route("/v1/sandboxes/{id}/fs/write", post(sandbox_fs_write))
        .route("/v1/sandboxes/{id}/process", post(sandbox_process))
        .route(
            "/v1/sandboxes/{id}/http/{port}/{*path}",
            any(sandbox_http_proxy),
        )
        .route(
            "/sandbox/{id}/{*path}",
            any(sandbox_http_proxy_default_port),
        )
        .route("/v1/templates", get(list_templates).post(build_template))
        .route("/v1/egress/check", post(egress_check))
        .route("/v1/egress/nftables", get(egress_nftables))
        .route("/console", get(console_ui))
        .route("/console/", get(console_ui))
        .route("/v1/images/build", post(build_image))
        .route("/v1/images/catalog", post(add_catalog_entry))
        .route("/v1/images/catalog/{name}", delete(remove_catalog_entry))
        .route(
            "/v1/images/catalog/{name}/rename",
            post(rename_catalog_entry),
        )
        .route("/v1/images/catalog/{name}/clone", post(clone_catalog_entry))
        .route(
            "/v1/images/catalog/{name}/export",
            post(export_catalog_entry),
        )
        .route(
            "/v1/images/catalog/{name}/read-only",
            post(set_catalog_read_only),
        )
        .route("/v1/images/catalog/clean", post(clean_catalog))
        .route("/v1/images/catalog", get(list_catalog))
        .route("/v1/pools", post(create_pool).get(list_pools))
        .route("/v1/pools/{name}", get(get_pool).delete(delete_pool))
        .route("/v1/pools/{name}/claim", post(claim_pool))
        .layer(middleware::from_fn_with_state(
            manager.clone(),
            auth_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(manager)
}

async fn metrics(State(m): State<Arc<VmManager>>) -> Response {
    let body = render_metrics(&m.list().await);
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Pure text-rendering, kept separate from the handler so it's unit-testable
/// without spinning up a VmManager/axum app.
fn render_metrics(vms: &[VmRecord]) -> String {
    let mut out = String::new();

    out.push_str(
        "# HELP fluxvm_vms_total Number of VMs known to this fluxvm instance, by status.\n",
    );
    out.push_str("# TYPE fluxvm_vms_total gauge\n");
    for status in [
        VmStatus::Creating,
        VmStatus::Running,
        VmStatus::Paused,
        VmStatus::Stopped,
        VmStatus::Failed,
    ] {
        let count = vms.iter().filter(|v| v.status == status).count();
        out.push_str(&format!(
            "fluxvm_vms_total{{status=\"{}\"}} {count}\n",
            status_label(status)
        ));
    }

    out.push_str(
        "# HELP fluxvm_vms_by_backend Number of VMs known to this fluxvm instance, by backend.\n",
    );
    out.push_str("# TYPE fluxvm_vms_by_backend gauge\n");
    for backend in [
        BackendKind::Qemu,
        BackendKind::CloudHypervisor,
        BackendKind::Firecracker,
        BackendKind::FluxVm,
    ] {
        let count = vms.iter().filter(|v| v.backend == backend).count();
        out.push_str(&format!(
            "fluxvm_vms_by_backend{{backend=\"{}\"}} {count}\n",
            backend_label(backend)
        ));
    }

    out.push_str(
        "# HELP fluxvm_vms_agent_enabled Number of VMs with the vsock guest agent enabled.\n",
    );
    out.push_str("# TYPE fluxvm_vms_agent_enabled gauge\n");
    let agent_enabled = vms
        .iter()
        .filter(|v| v.request.agent.as_ref().is_some_and(|a| a.enabled))
        .count();
    out.push_str(&format!("fluxvm_vms_agent_enabled {agent_enabled}\n"));

    out.push_str(
        "# HELP fluxvm_auth_deny_total REST requests rejected for missing or invalid bearer token.\n",
    );
    out.push_str("# TYPE fluxvm_auth_deny_total counter\n");
    out.push_str(&format!(
        "fluxvm_auth_deny_total {}\n",
        fluxvm_core::metrics::auth_deny_total()
    ));

    out.push_str(
        "# HELP fluxvm_egress_deny_total Outbound HTTP(S) requests denied by the L7 egress proxy.\n",
    );
    out.push_str("# TYPE fluxvm_egress_deny_total counter\n");
    out.push_str(&format!(
        "fluxvm_egress_deny_total {}\n",
        fluxvm_core::metrics::egress_deny_total()
    ));

    out.push_str("# HELP fluxvm_vm_create_total VM create operations completed successfully.\n");
    out.push_str("# TYPE fluxvm_vm_create_total counter\n");
    out.push_str(&format!(
        "fluxvm_vm_create_total {}\n",
        fluxvm_core::metrics::vm_create_total()
    ));
    out.push_str(
        "# HELP fluxvm_vm_create_duration_ms_total Cumulative wall time of successful VM creates in milliseconds.\n",
    );
    out.push_str("# TYPE fluxvm_vm_create_duration_ms_total counter\n");
    out.push_str(&format!(
        "fluxvm_vm_create_duration_ms_total {}\n",
        fluxvm_core::metrics::vm_create_duration_ms_total()
    ));

    out.push_str(
        "# HELP fluxvm_vm_start_total VM start (relaunch) operations completed successfully.\n",
    );
    out.push_str("# TYPE fluxvm_vm_start_total counter\n");
    out.push_str(&format!(
        "fluxvm_vm_start_total {}\n",
        fluxvm_core::metrics::vm_start_total()
    ));
    out.push_str(
        "# HELP fluxvm_vm_start_duration_ms_total Cumulative wall time of successful VM starts in milliseconds.\n",
    );
    out.push_str("# TYPE fluxvm_vm_start_duration_ms_total counter\n");
    out.push_str(&format!(
        "fluxvm_vm_start_duration_ms_total {}\n",
        fluxvm_core::metrics::vm_start_duration_ms_total()
    ));

    out
}

fn status_label(s: VmStatus) -> &'static str {
    match s {
        VmStatus::Creating => "creating",
        VmStatus::Running => "running",
        VmStatus::Paused => "paused",
        VmStatus::Stopped => "stopped",
        VmStatus::Failed => "failed",
    }
}

fn backend_label(b: BackendKind) -> &'static str {
    match b {
        BackendKind::Qemu => "qemu",
        BackendKind::CloudHypervisor => "cloud-hypervisor",
        BackendKind::Firecracker => "firecracker",
        BackendKind::FluxVm => "fluxvm",
        BackendKind::Auto => "auto",
    }
}

async fn create_vm(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    actor: Option<Extension<AuditActor>>,
    Json(req): Json<CreateVmRequest>,
) -> ApiResult<impl IntoResponse> {
    require_admin(role)?;
    enforce_token_quotas(&m, actor.as_ref().map(|a| a.0.0.as_str()), &req).await?;
    Ok((StatusCode::CREATED, Json(m.create(req).await?)))
}

async fn enforce_token_quotas(
    m: &VmManager,
    actor: Option<&str>,
    req: &CreateVmRequest,
) -> ApiResult<()> {
    let Some(actor) = actor else {
        return Ok(());
    };
    if actor == "anonymous-admin" || actor == "none" {
        return Ok(());
    }
    let vms = m.list().await;
    // Quotas are global per-token identity stored in labels via name prefix —
    // count all VMs when max_vms_per_token is set (conservative).
    if let Some(max) = m.cfg.auth.max_vms_per_token {
        if vms.len() >= max {
            return Err(ApiError::forbidden(format!(
                "token '{actor}' at max_vms_per_token ({max})"
            )));
        }
    }
    if let Some(max_mem) = m.cfg.auth.max_memory_mib_per_token {
        let used: u64 = vms.iter().map(|v| v.request.memory_mib).sum();
        if used.saturating_add(req.memory_mib) > max_mem {
            return Err(ApiError::forbidden(format!(
                "token '{actor}' would exceed max_memory_mib_per_token ({max_mem})"
            )));
        }
    }
    Ok(())
}

async fn create_sandbox(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(req): Json<fluxvm_scheduler::SandboxCreateRequest>,
) -> ApiResult<impl IntoResponse> {
    require_admin(role)?;
    Ok((StatusCode::CREATED, Json(m.create_sandbox(req).await?)))
}

async fn list_sandboxes(State(m): State<Arc<VmManager>>) -> Json<serde_json::Value> {
    let items: Vec<_> = m
        .list()
        .await
        .into_iter()
        .filter(|v| v.backend == BackendKind::FluxVm)
        .collect();
    Json(json!({ "items": items }))
}

#[derive(Deserialize)]
struct SnapshotBody {
    path: PathBuf,
}

async fn snapshot_sandbox(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(body): Json<SnapshotBody>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.snapshot_sandbox(id, &body.path).await?;
    Ok(Json(json!({ "ok": true, "path": body.path })))
}

#[derive(Deserialize)]
struct FsReadBody {
    path: String,
}

async fn sandbox_fs_read(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(body): Json<FsReadBody>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.ensure_running_for_request(id).await?;
    Ok(Json(json!(m.get_file(id, body.path).await?)))
}

#[derive(Deserialize)]
struct FsWriteBody {
    path: String,
    content_base64: String,
    #[serde(default)]
    mode: Option<u32>,
}

async fn sandbox_fs_write(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(body): Json<FsWriteBody>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.ensure_running_for_request(id).await?;
    Ok(Json(json!(
        m.put_file(id, body.path, body.content_base64, body.mode)
            .await?
    )))
}

#[derive(Deserialize)]
struct ProcessBody {
    command: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

async fn sandbox_process(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(body): Json<ProcessBody>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.ensure_running_for_request(id).await?;
    Ok(Json(json!(
        m.exec(id, body.command, body.timeout_seconds).await?
    )))
}

async fn sandbox_http_proxy_default_port(
    State(m): State<Arc<VmManager>>,
    Path((id, path)): Path<(Uuid, String)>,
    req: Request,
) -> Response {
    let port = match m.get(id).await {
        Ok(vm) => m.sandbox_http_proxy_port(&vm).await,
        Err(_) => m.cfg.sandbox.http_proxy_default_port,
    };
    sandbox_proxy_inner(m, id, port, path, req).await
}

async fn sandbox_http_proxy(
    State(m): State<Arc<VmManager>>,
    Path((id, port, path)): Path<(Uuid, u16, String)>,
    req: Request,
) -> Response {
    sandbox_proxy_inner(m, id, port, path, req).await
}

async fn sandbox_proxy_inner(
    m: Arc<VmManager>,
    id: Uuid,
    port: u16,
    path: String,
    req: Request,
) -> Response {
    let vm = match m.ensure_running_for_request(id).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("resume/get sandbox: {e:#}"),
            )
                .into_response();
        }
    };
    let Some(guest_ip) = vm.guest_ip.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            "sandbox has no guest_ip (use network.mode=tap with netns for HTTP proxy)",
        )
            .into_response();
    };
    let method = req.method().clone();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let url = format!("http://{guest_ip}:{port}/{path}{query}");
    let client = reqwest::Client::new();
    let mut builder = client.request(
        Method::from_bytes(method.as_str().as_bytes()).unwrap_or(Method::GET),
        &url,
    );
    for (k, v) in req.headers().iter() {
        if k == header::HOST {
            continue;
        }
        builder = builder.header(k, v);
    }
    let body = match axum::body::to_bytes(req.into_body(), 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("body: {e}")).into_response(),
    };
    match builder.body(body).send().await {
        Ok(up) => {
            let status =
                StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut response = Response::builder().status(status);
            for (k, v) in up.headers().iter() {
                response = response.header(k, v);
            }
            let bytes = up.bytes().await.unwrap_or_default();
            response
                .body(Body::from(bytes))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e) => (StatusCode::BAD_GATEWAY, format!("guest upstream: {e}")).into_response(),
    }
}

async fn list_templates(State(m): State<Arc<VmManager>>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({ "items": m.list_templates().await? })))
}

#[derive(Deserialize)]
struct BuildTemplateBody {
    name: String,
    image_ref: String,
}

async fn build_template(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(body): Json<BuildTemplateBody>,
) -> ApiResult<impl IntoResponse> {
    require_admin(role)?;
    Ok((
        StatusCode::CREATED,
        Json(m.build_oci_template(&body.name, &body.image_ref).await?),
    ))
}

#[derive(Deserialize)]
struct EgressCheckBody {
    host: String,
}

async fn egress_check(
    State(m): State<Arc<VmManager>>,
    Json(body): Json<EgressCheckBody>,
) -> Json<serde_json::Value> {
    Json(json!(fluxvm_network::egress::decide(
        &m.cfg.sandbox,
        &body.host
    )))
}

async fn egress_nftables() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        fluxvm_network::egress::nftables_redirect_snippet(18080),
    )
}

async fn console_ui() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        CONSOLE_HTML,
    )
}

const CONSOLE_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>FluxVM console</title>
<style>
  :root { --bg:#0f1419; --fg:#e7ecf3; --muted:#8b98a8; --accent:#3d9cfd; }
  body { margin:0; font-family: ui-sans-serif, system-ui, sans-serif; background:var(--bg); color:var(--fg); }
  header { padding:1.25rem 1.5rem; border-bottom:1px solid #243044; }
  h1 { margin:0; font-size:1.25rem; letter-spacing:-0.02em; }
  p { color:var(--muted); margin:0.35rem 0 0; font-size:0.9rem; }
  main { padding:1.5rem; display:grid; gap:1rem; max-width:960px; }
  .card { background:#161d27; border:1px solid #243044; border-radius:10px; padding:1rem 1.1rem; }
  label { display:block; font-size:0.75rem; color:var(--muted); margin-bottom:0.35rem; }
  input, button { font:inherit; }
  input { width:100%; box-sizing:border-box; background:#0f1419; border:1px solid #2c3a4f; color:var(--fg); border-radius:8px; padding:0.55rem 0.7rem; }
  button { background:var(--accent); color:#041018; border:0; border-radius:8px; padding:0.55rem 0.9rem; font-weight:600; cursor:pointer; }
  pre { background:#0b1016; border-radius:8px; padding:0.75rem; overflow:auto; min-height:12rem; font-size:0.8rem; }
</style>
</head>
<body>
<header>
  <h1>FluxVM</h1>
  <p>Sandbox console — list FluxVm sandboxes, templates, and health.</p>
</header>
<main>
  <div class="card">
    <label>API base</label>
    <input id="base" value=""/>
    <div style="margin-top:0.75rem; display:flex; gap:0.5rem;">
      <button id="refresh">Refresh</button>
    </div>
  </div>
  <div class="card"><label>Sandboxes</label><pre id="sandboxes">…</pre></div>
  <div class="card"><label>Templates</label><pre id="templates">…</pre></div>
</main>
<script>
const baseInput = document.getElementById('base');
baseInput.value = location.origin;
async function load() {
  const base = baseInput.value.replace(/\/$/, '');
  const [s, t] = await Promise.all([
    fetch(base + '/v1/sandboxes').then(r => r.json()),
    fetch(base + '/v1/templates').then(r => r.json()),
  ]);
  document.getElementById('sandboxes').textContent = JSON.stringify(s, null, 2);
  document.getElementById('templates').textContent = JSON.stringify(t, null, 2);
}
document.getElementById('refresh').onclick = () => load().catch(e => alert(e));
load().catch(() => {});
</script>
</body>
</html>"#;

#[derive(Deserialize)]
struct ListVmsQuery {
    /// Exact-match filter on `VmRecord.name`. Added for zyvor-fabric's
    /// `FluxVMDriver`, which is keyed by name (systemd-machined's model)
    /// while `VmRecord` is keyed by `Uuid` — this lets the driver resolve a
    /// name to a record server-side instead of pulling the full list on
    /// every lookup.
    #[serde(default)]
    name: Option<String>,
}

async fn list_vms(
    State(m): State<Arc<VmManager>>,
    Query(q): Query<ListVmsQuery>,
) -> Json<serde_json::Value> {
    let mut items = m.list().await;
    if let Some(name) = q.name {
        items.retain(|vm| vm.name == name);
    }
    Json(json!({"items": items}))
}
async fn get_vm(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.get(id).await?)))
}
async fn start_vm(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(m.start(id).await?)))
}
#[derive(Debug, serde::Deserialize)]
struct StartFromSnapshotRequest {
    tag: String,
}
async fn start_vm_from_snapshot(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<StartFromSnapshotRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(m.start_from_snapshot(id, &req.tag).await?)))
}

#[derive(Debug, serde::Deserialize)]
struct VmSnapshotRequest {
    tag: String,
}

async fn snapshot_vm(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<VmSnapshotRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.create_vm_snapshot(id, &req.tag).await?;
    Ok(Json(json!({"ok": true, "tag": req.tag})))
}

async fn stop_vm(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(m.stop(id).await?)))
}
async fn pause_vm(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(m.pause(id).await?)))
}
async fn resume_vm(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(m.resume(id).await?)))
}

async fn set_vm_resources(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(patch): Json<fluxvm_core::model::ResourcePatch>,
) -> ApiResult<StatusCode> {
    require_admin(role)?;
    m.set_resources(id, patch).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn freeze_vm(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    require_admin(role)?;
    m.freeze(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn thaw_vm(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    require_admin(role)?;
    m.thaw(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn vm_frozen(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({"frozen": m.is_frozen(id).await?})))
}

async fn vm_stats(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.metrics(id).await?)))
}

async fn vm_pressure(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.pressure(id).await?)))
}

async fn vm_network_stats(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.network_stats(id).await?)))
}

async fn vm_network_status(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.network_status(id).await?)))
}

#[derive(Debug, Deserialize)]
struct NetworkFlowsQuery {
    #[serde(default = "default_network_flow_limit")]
    limit: usize,
}
fn default_network_flow_limit() -> usize {
    100
}

async fn vm_network_flows(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
    Query(q): Query<NetworkFlowsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({"items": m.network_flows(id, q.limit).await?})))
}

async fn get_vm_network_policy(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.network_policy(id).await?)))
}

async fn set_vm_network_policy(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(policy): Json<fluxvm_network::dataplane::VmNetworkPolicy>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(m.set_network_policy(id, policy).await?)))
}

async fn vm_cpuset(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({"cpus": m.get_cpuset(id).await?})))
}

#[derive(Debug, Deserialize)]
struct LogsQuery {
    #[serde(default)]
    follow: bool,
    #[serde(default = "default_log_lines")]
    lines: usize,
}
fn default_log_lines() -> usize {
    100
}

/// `GET /v1/vms/{id}/logs?lines=N&follow=true` — tail-follow the VM's
/// captured console output (`VmRecord.log_path`) as a plain-text chunked
/// stream, one line per chunk. Raw serial output has no journald-equivalent
/// structure (no per-line priority/unit), so unlike `machinectl-driver`'s
/// `journalctl --output=json` this is deliberately unstructured — the
/// caller (`fluxvm-driver::LogDriver`) assigns a constant priority when
/// wrapping lines into `driver-core::LogEntry`.
async fn vm_logs(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
    Query(q): Query<LogsQuery>,
) -> ApiResult<Response> {
    let record = m.get(id).await?;
    let path = record.log_path;
    let follow = q.follow;
    let lines = q.lines.max(1);

    let stream = async_stream::stream! {
        use std::collections::VecDeque;
        use tokio::io::{AsyncBufReadExt, BufReader};

        let file = match tokio::fs::File::open(&path).await {
            Ok(f) => f,
            Err(e) => {
                yield Ok::<_, std::io::Error>(bytes::Bytes::from(format!("error opening log: {e}\n")));
                return;
            }
        };
        let mut reader = BufReader::new(file);
        let mut line = String::new();

        // First pass: keep only the last `lines` lines already on disk.
        let mut tail: VecDeque<String> = VecDeque::with_capacity(lines);
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    if tail.len() == lines {
                        tail.pop_front();
                    }
                    tail.push_back(std::mem::take(&mut line));
                }
                Err(_) => break,
            }
        }
        for l in tail {
            yield Ok::<_, std::io::Error>(bytes::Bytes::from(l));
        }

        if follow {
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => tokio::time::sleep(std::time::Duration::from_millis(300)).await,
                    Ok(_) => yield Ok::<_, std::io::Error>(bytes::Bytes::from(std::mem::take(&mut line))),
                    Err(_) => break,
                }
            }
        }
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(axum::body::Body::from_stream(stream))
        .unwrap())
}

#[derive(Deserialize)]
struct ExecRequest {
    command: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}
async fn agent_exec(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<ExecRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let response = m.exec(id, req.command, req.timeout_seconds).await?;
    Ok(Json(json!(response)))
}

#[derive(Deserialize)]
struct QgaExecRequest {
    /// Guest executable path (e.g. `powershell.exe`). Ignored when `powershell` is set.
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    /// Convenience: run this string via `powershell.exe -Command`.
    #[serde(default)]
    powershell: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

async fn qga_ping(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.qga_ping(id).await?;
    Ok(Json(json!({"ok": true})))
}

async fn qga_exec(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<QgaExecRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let result = if let Some(ps) = req.powershell {
        m.qga_powershell(id, ps, req.timeout_seconds).await?
    } else {
        let path = req.path.ok_or_else(|| ApiError {
            status: StatusCode::BAD_REQUEST,
            message: "qga exec requires `path` or `powershell`".into(),
        })?;
        m.qga_exec(id, path, req.args, req.timeout_seconds).await?
    };
    Ok(Json(json!(result)))
}

#[derive(Deserialize)]
struct QgaFirewallOpenRequest {
    name: String,
    port: u16,
    #[serde(default = "default_fw_proto")]
    protocol: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}
fn default_fw_proto() -> String {
    "tcp".into()
}

#[derive(Deserialize)]
struct QgaFirewallCloseRequest {
    name: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

async fn qga_firewall_open(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<QgaFirewallOpenRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let result = m
        .qga_firewall_open(id, req.name, req.port, req.protocol, req.timeout_seconds)
        .await?;
    Ok(Json(json!(result)))
}

async fn qga_firewall_close(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<QgaFirewallCloseRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let result = m
        .qga_firewall_close(id, req.name, req.timeout_seconds)
        .await?;
    Ok(Json(json!(result)))
}

#[derive(Deserialize)]
struct PutFileRequest {
    path: String,
    content_base64: String,
    #[serde(default)]
    mode: Option<u32>,
}
async fn agent_put_file(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<PutFileRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let response = m
        .put_file(id, req.path, req.content_base64, req.mode)
        .await?;
    Ok(Json(json!(response)))
}

#[derive(Deserialize)]
struct GetFileRequest {
    path: String,
}
async fn agent_get_file(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<GetFileRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let response = m.get_file(id, req.path).await?;
    Ok(Json(json!(response)))
}
#[derive(Deserialize)]
struct ConsoleQuery {
    #[serde(default = "default_console_cols")]
    cols: u16,
    #[serde(default = "default_console_rows")]
    rows: u16,
}
fn default_console_cols() -> u16 {
    80
}
fn default_console_rows() -> u16 {
    24
}

/// `GET /v1/vms/{id}/console` — upgrades to a WebSocket carrying a live
/// interactive shell (`AgentRequest::OpenShell` under the hood). Once the
/// vsock handshake completes, this is a raw byte relay in both directions
/// — binary WS frames in, binary WS frames out, no further framing on
/// either side.
async fn agent_console(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Query(q): Query<ConsoleQuery>,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> ApiResult<Response> {
    require_admin(role)?;
    // Open the console *before* upgrading, so a failure (agent disabled,
    // guest unreachable, VM not found) comes back as a normal HTTP error
    // instead of a WS connection that opens and then immediately closes
    // with no useful diagnostic on the client side.
    let console = m.open_console(id, q.cols, q.rows).await?;
    Ok(ws.on_upgrade(move |socket| relay_console(socket, console)))
}

async fn relay_console(
    socket: axum::extract::ws::WebSocket,
    console: fluxvm_vsock_client::ConsoleStream,
) {
    use axum::extract::ws::Message;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut ws_tx, mut ws_rx) = socket.split();
    let (mut console_rx, mut console_tx) = tokio::io::split(console);

    let to_console = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            let bytes = match msg {
                Message::Binary(b) => b,
                Message::Text(t) => t.as_bytes().to_vec().into(),
                Message::Close(_) => break,
                _ => continue,
            };
            if console_tx.write_all(&bytes).await.is_err() {
                break;
            }
        }
    };
    let to_ws = async {
        let mut buf = [0u8; 4096];
        loop {
            match console_rx.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    };
    tokio::select! {
        _ = to_console => {}
        _ = to_ws => {}
    }
}

async fn delete_vm(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    require_admin(role)?;
    m.delete(id).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn build_image(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(req): Json<BuildImageRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(image::build_image(&m.cfg, &req).await?)))
}

/// Read-only (no role check beyond a valid token, like other GET routes) —
/// signing itself is a CLI/offline operation (`fluxvm catalog sign`), not
/// exposed here, so private keys never touch this API's surface.
async fn list_catalog(State(m): State<Arc<VmManager>>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(
        json!({"items": image::catalog::list_with_verification(&m.cfg)?}),
    ))
}

#[derive(Deserialize)]
struct AddCatalogEntryRequest {
    name: String,
    /// Local path or `http(s)://` URL — see `CatalogEntry::source`.
    source: String,
    #[serde(default = "default_catalog_format")]
    format: String,
}
fn default_catalog_format() -> String {
    "qcow2".into()
}

async fn add_catalog_entry(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(req): Json<AddCatalogEntryRequest>,
) -> ApiResult<impl IntoResponse> {
    require_admin(role)?;
    let entry = m
        .add_catalog_entry(req.name, req.source, req.format)
        .await?;
    Ok((StatusCode::CREATED, Json(json!(entry))))
}

async fn remove_catalog_entry(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    require_admin(role)?;
    m.remove_catalog_entry(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RenameCatalogEntryRequest {
    new_name: String,
}
async fn rename_catalog_entry(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    Json(req): Json<RenameCatalogEntryRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let entry = m.rename_catalog_entry(&name, &req.new_name).await?;
    Ok(Json(json!(entry)))
}

#[derive(Deserialize)]
struct CloneCatalogEntryRequest {
    target_name: String,
}
async fn clone_catalog_entry(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    Json(req): Json<CloneCatalogEntryRequest>,
) -> ApiResult<impl IntoResponse> {
    require_admin(role)?;
    let entry = m.clone_catalog_entry(&name, &req.target_name).await?;
    Ok((StatusCode::CREATED, Json(json!(entry))))
}

#[derive(Deserialize)]
struct ExportCatalogEntryRequest {
    path: PathBuf,
}
async fn export_catalog_entry(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    Json(req): Json<ExportCatalogEntryRequest>,
) -> ApiResult<StatusCode> {
    require_admin(role)?;
    m.export_catalog_entry(&name, &req.path).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct SetCatalogReadOnlyRequest {
    read_only: bool,
}
async fn set_catalog_read_only(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    Json(req): Json<SetCatalogReadOnlyRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let entry = m.set_catalog_read_only(&name, req.read_only).await?;
    Ok(Json(json!(entry)))
}

async fn clean_catalog(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let removed = m.clean_catalog_downloads().await?;
    Ok(Json(json!({"removed": removed})))
}

async fn create_pool(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(spec): Json<PoolSpec>,
) -> ApiResult<impl IntoResponse> {
    require_admin(role)?;
    Ok((StatusCode::CREATED, Json(m.create_pool(spec).await?)))
}
async fn list_pools(State(m): State<Arc<VmManager>>) -> Json<serde_json::Value> {
    Json(json!({"items": m.list_pools().await}))
}
async fn get_pool(
    State(m): State<Arc<VmManager>>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.get_pool(&name).await?)))
}
async fn delete_pool(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    require_admin(role)?;
    m.delete_pool(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn claim_pool(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    Json(overrides): Json<ClaimOverrides>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(m.claim_from_pool(&name, overrides).await?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_core::model::{AgentSpec, CreateVmRequest, NetworkSpec};
    use std::path::PathBuf;

    fn fixture(backend: BackendKind, status: VmStatus, agent_enabled: bool) -> VmRecord {
        VmRecord {
            id: Uuid::new_v4(),
            name: "fixture".into(),
            backend,
            status,
            pid: None,
            created_at: chrono::Utc::now(),
            expires_at: None,
            workspace: PathBuf::from("/tmp/x"),
            disk: PathBuf::from("/tmp/x/root.qcow2"),
            seed_disk: None,
            tap_name: None,
            control_socket: None,
            log_path: PathBuf::from("/tmp/x/console.log"),
            error: None,
            request: CreateVmRequest {
                name: "fixture".into(),
                backend,
                image: PathBuf::from("/tmp/base.qcow2"),
                vcpus: 1,
                memory_mib: 512,
                max_vcpus: None,
                max_memory_mib: None,
                loadvm_tag: None,
                disk_size_gib: None,
                kernel: None,
                initrd: None,
                firmware: None,
                kernel_args: None,
                network: NetworkSpec::None,
                cloud_init: None,
                ttl_seconds: None,
                extra_args: vec![],
                agent: agent_enabled.then(|| AgentSpec {
                    enabled: true,
                    port: 17777,
                    token: None,
                }),
                qga: None,
                storage: Default::default(),
                shared_folders: vec![],
                numa_node: None,
                cpuset: None,
                hugepages: None,
                vfio_devices: vec![],
            },
            guest_cid: None,
            jail_path: None,
            vsock_socket: None,
            qga_socket: None,
            cgroup_path: None,
            netns: None,
            lvm_lv: None,
            nbd_pid: None,
            virtiofsd_pids: vec![],
            dhcp_leasefile: None,
            guest_ip: None,
        }
    }

    #[test]
    fn counts_by_status_and_backend() {
        let vms = vec![
            fixture(BackendKind::Qemu, VmStatus::Running, true),
            fixture(BackendKind::Qemu, VmStatus::Paused, false),
            fixture(BackendKind::CloudHypervisor, VmStatus::Running, false),
            fixture(BackendKind::Firecracker, VmStatus::Failed, false),
        ];
        let out = render_metrics(&vms);

        assert!(out.contains("fluxvm_vms_total{status=\"running\"} 2"));
        assert!(out.contains("fluxvm_vms_total{status=\"paused\"} 1"));
        assert!(out.contains("fluxvm_vms_total{status=\"stopped\"} 0"));
        assert!(out.contains("fluxvm_vms_total{status=\"failed\"} 1"));

        assert!(out.contains("fluxvm_vms_by_backend{backend=\"qemu\"} 2"));
        assert!(out.contains("fluxvm_vms_by_backend{backend=\"cloud-hypervisor\"} 1"));
        assert!(out.contains("fluxvm_vms_by_backend{backend=\"firecracker\"} 1"));

        assert!(out.contains("fluxvm_vms_agent_enabled 1"));
    }

    #[test]
    fn empty_fleet_still_renders_zeroed_gauges() {
        let out = render_metrics(&[]);
        assert!(out.contains("fluxvm_vms_total{status=\"running\"} 0"));
        assert!(out.contains("fluxvm_vms_agent_enabled 0"));
    }

    mod auth {
        use super::*;
        use axum::body::Body;
        use axum::http::Request;
        use fluxvm_core::config::{ApiToken, AuthConfig, Config};
        use tower::ServiceExt;

        fn manager(auth: AuthConfig) -> Arc<VmManager> {
            let dir = tempfile::tempdir().unwrap();
            // Leak: the tempdir must outlive every VmManager call in the
            // test, and these tests are short-lived processes anyway.
            let dir = Box::leak(Box::new(dir));
            let cfg = Config {
                state_dir: dir.path().join("state"),
                run_dir: dir.path().join("run"),
                auth,
                ..Config::default()
            };
            VmManager::new(cfg).unwrap()
        }

        async fn status_for(
            app: Router,
            method: &str,
            uri: &str,
            bearer: Option<&str>,
        ) -> StatusCode {
            request(app, method, uri, bearer, None).await
        }

        /// `body` is sent as `application/json` when present — needed for
        /// any route whose handler takes a `Json<T>` extractor, since axum
        /// rejects with 415 during extraction (before the handler body, and
        /// so before this module's `require_admin` role check, ever runs)
        /// if the request has no JSON content-type at all.
        async fn request(
            app: Router,
            method: &str,
            uri: &str,
            bearer: Option<&str>,
            body: Option<&str>,
        ) -> StatusCode {
            let mut builder = Request::builder().method(method).uri(uri);
            if let Some(t) = bearer {
                builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
            }
            let body = match body {
                Some(b) => {
                    builder = builder.header(header::CONTENT_TYPE, "application/json");
                    Body::from(b.to_string())
                }
                None => Body::empty(),
            };
            let req = builder.body(body).unwrap();
            app.oneshot(req).await.unwrap().status()
        }

        #[tokio::test]
        async fn auth_disabled_allows_unauthenticated_requests() {
            let app = router(manager(AuthConfig::default()));
            assert_eq!(
                status_for(app, "GET", "/v1/vms", None).await,
                StatusCode::OK
            );
        }

        #[tokio::test]
        async fn missing_token_is_rejected_when_auth_is_enabled() {
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "secret".into(),
                    role: Role::Admin,
                    name: None,
                }],
                ..Default::default()
            };
            let app = router(manager(auth));
            assert_eq!(
                status_for(app, "GET", "/v1/vms", None).await,
                StatusCode::UNAUTHORIZED
            );
        }

        #[tokio::test]
        async fn wrong_token_is_rejected() {
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "secret".into(),
                    role: Role::Admin,
                    name: None,
                }],
                ..Default::default()
            };
            let app = router(manager(auth));
            assert_eq!(
                status_for(app, "GET", "/v1/vms", Some("nope")).await,
                StatusCode::UNAUTHORIZED
            );
        }

        #[tokio::test]
        async fn healthz_is_reachable_without_a_token_even_when_auth_is_enabled() {
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "secret".into(),
                    role: Role::Admin,
                    name: None,
                }],
                ..Default::default()
            };
            let app = router(manager(auth));
            assert_eq!(
                status_for(app, "GET", "/healthz", None).await,
                StatusCode::OK
            );
        }

        const VALID_CREATE_BODY: &str =
            r#"{"name":"t","backend":"qemu","image":"/does/not/exist.qcow2"}"#;

        #[tokio::test]
        async fn readonly_token_can_list_but_not_create() {
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "ro".into(),
                    role: Role::ReadOnly,
                    name: None,
                }],
                ..Default::default()
            };
            let app = router(manager(auth));
            assert_eq!(
                status_for(app.clone(), "GET", "/v1/vms", Some("ro")).await,
                StatusCode::OK
            );
            assert_eq!(
                request(app, "POST", "/v1/vms", Some("ro"), Some(VALID_CREATE_BODY)).await,
                StatusCode::FORBIDDEN
            );
        }

        #[tokio::test]
        async fn admin_token_passes_auth_for_a_mutating_route() {
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "admin".into(),
                    role: Role::Admin,
                    name: None,
                }],
                ..Default::default()
            };
            let app = router(manager(auth));
            // The image path doesn't exist, so this fails downstream with
            // 400 — the point is it's NOT 401/403, i.e. the Admin token
            // cleared the auth layer and reached VmManager::create.
            let status = request(
                app,
                "POST",
                "/v1/vms",
                Some("admin"),
                Some(VALID_CREATE_BODY),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
    }
}
