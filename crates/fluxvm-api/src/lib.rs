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
    model::{
        BackendKind, ClaimOverrides, CreateVmRequest, PoolResizeRequest, PoolSpec, VmRecord,
        VmStatus,
    },
};
use fluxvm_image::{self as image, BuildImageRequest};
use fluxvm_scheduler::VmManager;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::json;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

mod oidc;
mod rate_limit;

#[derive(Clone)]
struct AuthState {
    manager: Arc<VmManager>,
    oidc: Option<Arc<oidc::OidcValidator>>,
}

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
/// Static `[[auth.tokens]]` are tried first; OIDC JWTs when configured.
async fn auth_middleware(State(auth): State<AuthState>, mut req: Request, next: Next) -> Response {
    let m = &auth.manager;
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    // Liveness/readiness probes must work without auth (Kubernetes convention).
    if path == "/healthz" || path == "/readyz" {
        return next.run(req).await;
    }
    let must = m.cfg.auth.must_authenticate(&m.cfg.listen);
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_string);

    let (role, token_name, token_tenant) = if !must && !m.cfg.auth.has_credentials() {
        (Some(Role::Admin), Some("anonymous-admin".to_string()), None)
    } else if let Some(ref t) = presented {
        if let Some(entry) = m
            .cfg
            .auth
            .tokens
            .iter()
            .find(|entry| constant_time_eq(&entry.token, t))
        {
            (
                Some(entry.role),
                entry.name.clone().or_else(|| Some("unnamed".into())),
                entry.tenant.clone(),
            )
        } else if let Some(ref oidc) = auth.oidc {
            match oidc.validate(t).await {
                Ok(id) => (Some(id.role), Some(id.actor), id.tenant),
                Err(e) => {
                    tracing::debug!(error = %e, "OIDC bearer rejected");
                    (None, None, None)
                }
            }
        } else {
            (None, None, None)
        }
    } else if m.cfg.tls.mtls_enabled() {
        // Identity from a verified client cert (this process terminated mTLS)
        // or from a trusted frontend that sets X-Client-Cert-CN only after
        // verify. Role defaults to read-only; X-Client-Cert-Role=admin for writes.
        if let Some(cn) = req
            .headers()
            .get("x-client-cert-cn")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
        {
            let role = match req
                .headers()
                .get("x-client-cert-role")
                .and_then(|v| v.to_str().ok())
            {
                Some("admin") => Role::Admin,
                _ => Role::ReadOnly,
            };
            let tenant = req
                .headers()
                .get("x-client-cert-tenant")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            (Some(role), Some(cn.to_string()), tenant)
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };
    match role {
        Some(role) => {
            req.extensions_mut().insert(role);
            if let Some(name) = token_name.clone() {
                req.extensions_mut().insert(AuditActor(name));
            }
            if let Some(tenant) = token_tenant {
                req.extensions_mut().insert(TokenTenant(tenant));
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

/// Tenant claim carried by the authenticated API token (if any).
#[derive(Clone, Debug)]
struct TokenTenant(pub String);

fn extract_vm_uuid(path: &str) -> Option<Uuid> {
    let rest = path
        .strip_prefix("/v1/vms/")
        .or_else(|| path.strip_prefix("/v1/sandboxes/"))
        // The short-form proxy route ("/sandbox/{id}/{*path}", registered
        // separately from "/v1/sandboxes/{id}/http/{port}/{*path}") matched
        // neither prefix above, so tenant_guard_middleware silently no-op'd
        // for it below -- any authenticated caller who knew or guessed
        // another tenant's sandbox UUID could proxy HTTP traffic straight
        // into that tenant's guest through this route, unscoped, even
        // though the equivalent long-form route was already correctly
        // tenant-checked. See sandbox_id_routes_are_tenant_scoped_like_vm_routes
        // for the long-form route's existing coverage, and
        // short_form_sandbox_proxy_route_is_tenant_scoped below for this fix.
        .or_else(|| path.strip_prefix("/sandbox/"))?;
    let id = rest.split('/').next()?;
    Uuid::parse_str(id).ok()
}

/// When a token carries a tenant, scope all `/v1/vms/{uuid}…`,
/// `/v1/sandboxes/{uuid}…`, and `/sandbox/{uuid}…` access to that tenant --
/// a sandbox is a `VmRecord` like any other (`VmManager::create_sandbox`
/// funnels through the same `create()`), so the same per-record tenant
/// check applies to all three id-bearing path spaces uniformly rather than
/// needing a second copy of this
/// logic.
async fn tenant_guard_middleware(
    State(m): State<Arc<VmManager>>,
    req: Request,
    next: Next,
) -> Response {
    let Some(TokenTenant(tenant)) = req.extensions().get::<TokenTenant>().cloned() else {
        return next.run(req).await;
    };
    let path = req.uri().path().to_string();
    if let Some(id) = extract_vm_uuid(&path) {
        match m.get(id).await {
            Ok(vm) if vm.request.tenant.as_deref() == Some(tenant.as_str()) => {}
            _ => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "VM not found"})),
                )
                    .into_response();
            }
        }
    }
    next.run(req).await
}

/// Rejects a request with 429 (`Retry-After` set) once its authenticated
/// caller has exceeded `Limiter`'s configured rate -- runs after
/// `auth_middleware` so `AuditActor` is present for every request this
/// middleware actually rate-limits. Explicitly bypasses `/healthz`/
/// `/readyz` itself: `auth_middleware` only skips resolving an identity
/// for those two paths, it still calls `next.run` and lets them reach
/// every layer below it -- without this bypass they'd all share one
/// `"unknown"` bucket here, and a caller's own throttling could starve
/// its own liveness/readiness probes. Keyed by the same actor identity
/// `audit_log` already records -- a static token's name, an OIDC
/// subject, an mTLS cert CN, or `"anonymous-admin"` on an unauthenticated
/// loopback deployment -- so distinct real callers behind a shared
/// token/identity share one bucket by design, the same way `audit_log`
/// already attributes them as one actor.
async fn rate_limit_middleware(
    State(limiter): State<Arc<rate_limit::Limiter>>,
    req: Request,
    next: Next,
) -> Response {
    // /healthz and /readyz reach every layer below auth_middleware too --
    // it only skips *resolving an identity* for them, then still calls
    // `next.run(req)` -- so without this explicit check they'd all share
    // one "unknown" bucket here and a real caller's own throttling could
    // starve its own liveness/readiness probes. Caught by
    // healthz_is_never_rate_limited failing before this check existed.
    let path = req.uri().path();
    if path == "/healthz" || path == "/readyz" {
        return next.run(req).await;
    }
    let key = req
        .extensions()
        .get::<AuditActor>()
        .map(|a| a.0.clone())
        .unwrap_or_else(|| "unknown".to_string());
    match limiter.allow(&key) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => {
            tracing::warn!(actor = %key, "fluxvm-api rate limited");
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, (retry_after.as_secs() + 1).to_string())],
                Json(json!({"error": "too many requests; try again later"})),
            )
                .into_response()
        }
    }
}

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
    let oidc = build_oidc(&manager.cfg.auth);
    let mut router = Router::new()
        .route("/healthz", get(|| async { Json(json!({"ok": true})) }))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/v1/runtime/capabilities", get(runtime_capabilities)) // ZYVOR_RUNTIME_BOUNDARY_V1
        .route(
            "/v1/security/capabilities",
            get(security_capabilities),
        )
        .route("/v1/host/gpus", get(list_host_gpus))
        .route("/v1/host/gpus/preflight", get(host_gpu_preflight))
        .route("/v1/host/gpus/bind", post(bind_host_gpu))
        .route("/v1/host/gpus/release", post(release_host_gpu))
        .route("/v1/vms", post(create_vm).get(list_vms))
        .route("/v1/vms/{id}", get(get_vm).delete(delete_vm))
        .route("/v1/vms/{id}/attest", get(get_vm_evidence))
        .route(
            "/v1/vms/{id}/secrets/release",
            post(release_vm_secret),
        )
        .route("/v1/vms/{id}/start", post(start_vm))
        .route(
            "/v1/vms/{id}/start-from-snapshot",
            post(start_vm_from_snapshot),
        )
        .route("/v1/vms/{id}/snapshot", post(snapshot_vm))
        .route("/v1/vms/{id}/migration/start", post(start_migration))
        .route("/v1/vms/{id}/migration/status", get(migration_status))
        .route("/v1/vms/{id}/migration/cancel", post(cancel_migration))
        .route("/v1/vms/{id}/stop", post(stop_vm))
        .route("/v1/vms/{id}/pause", post(pause_vm))
        .route("/v1/vms/{id}/resume", post(resume_vm))
        .route("/v1/vms/{id}/resources", post(set_vm_resources))
        .route("/v1/vms/{id}/hotplug/cpu", post(hotplug_vm_cpu))
        .route("/v1/vms/{id}/hotplug/memory", post(hotplug_vm_memory))
        .route("/v1/vms/{id}/hotplug/nic", post(hotplug_vm_nic))
        .route("/v1/vms/{id}/hotplug/share", post(hotplug_vm_share))
        .route("/v1/vms/{id}/cpuset", get(vm_cpuset))
        .route("/v1/vms/{id}/freeze", post(freeze_vm))
        .route("/v1/vms/{id}/thaw", post(thaw_vm))
        .route("/v1/vms/{id}/frozen", get(vm_frozen))
        .route("/v1/vms/{id}/stats", get(vm_stats))
        .route("/v1/vms/{id}/network/stats", get(vm_network_stats))
        .route("/v1/vms/{id}/network/flows", get(vm_network_flows))
        .route(
            "/v1/vms/{id}/network/drop-reasons",
            get(vm_network_drop_reasons),
        )
        .route("/v1/vms/{id}/network/status", get(vm_network_status))
        .route(
            "/v1/vms/{id}/network/migration/state",
            get(vm_network_migration_state),
        )
        .route(
            "/v1/vms/{id}/network/migration/quiesce",
            post(vm_network_migration_quiesce),
        )
        .route(
            "/v1/vms/{id}/network/migration/export",
            get(vm_network_migration_export),
        )
        .route(
            "/v1/vms/{id}/network/migration/restore",
            post(vm_network_migration_restore),
        )
        .route(
            "/v1/vms/{id}/network/migration/resume",
            post(vm_network_migration_resume),
        )
        .route(
            "/v1/vms/{id}/network/services/stats",
            get(vm_network_service_stats),
        )
        .route(
            "/v1/vms/{id}/network/policy",
            get(get_vm_network_policy).post(set_vm_network_policy),
        )
        .route(
            "/v1/vms/{id}/network/pod-policy",
            get(get_vm_pod_network_policy)
                .post(set_vm_pod_network_policy)
                .delete(clear_vm_pod_network_policy),
        )
        .route(
            "/v1/vms/{id}/network/effective",
            get(get_vm_network_effective),
        )
        .route(
            "/v1/network/groups",
            get(list_network_groups).post(upsert_network_group),
        )
        .route(
            "/v1/network/services",
            get(list_network_services).post(upsert_network_service),
        )
        .route("/v1/network/services/status", get(network_service_status))
        .route("/v1/network/services/stats", get(network_service_stats))
        .route("/v1/network/services/health", get(network_service_health))
        .route(
            "/v1/network/services/health/reconcile",
            post(reconcile_network_service_health),
        )
        .route(
            "/v1/network/services/conntrack/gc",
            post(gc_network_service_conntrack),
        )
        .route(
            "/v1/network/services/pressure/reconcile",
            post(reconcile_network_service_pressure),
        )
        .route(
            "/v1/network/services/advertisements",
            get(network_service_advertisements),
        )
        .route("/v1/network/services/flows", get(network_service_flows))
        .route(
            "/v1/network/services/telemetry/export",
            post(export_network_service_telemetry),
        )
        .route(
            "/v1/network/services/policies",
            get(list_network_service_policies).post(upsert_network_service_policy),
        )
        .route(
            "/v1/network/services/policies/reconcile",
            post(reconcile_network_service_policies),
        )
        .route(
            "/v1/network/services/{name}/policy",
            get(get_network_service_policy).delete(delete_network_service_policy),
        )
        .route(
            "/v1/network/services/{name}/l7/envoy",
            get(network_service_envoy_contract),
        )
        .route(
            "/v1/network/services/{name}/conntrack/export",
            get(export_network_service_conntrack),
        )
        .route(
            "/v1/network/services/{name}/conntrack/import",
            post(import_network_service_conntrack),
        )
        .route(
            "/v1/network/services/{name}/conntrack/delta",
            get(export_network_service_conntrack_delta),
        )
        .route(
            "/v1/network/services/{name}/conntrack/delta/import",
            post(import_network_service_conntrack_delta),
        )
        .route(
            "/v1/network/services/{name}/conntrack/delta/ack",
            post(ack_network_service_conntrack_delta),
        )
        .route(
            "/v1/network/services/{name}",
            get(get_network_service).delete(delete_network_service),
        )
        .route(
            "/v1/network/groups/{name}",
            get(get_network_group).delete(delete_network_group),
        )
        .route("/v1/network/cnp", get(list_cnp).post(apply_cnp))
        .route("/v1/network/cnp/{name}", get(get_cnp).delete(delete_cnp))
        .route("/v1/network/identities", get(list_identities))
        .route("/v1/network/observe", get(network_observe))
        .route("/v1/network/health", get(network_health))
        .route("/v1/network/ipcache", get(network_ipcache))
        .route("/v1/network/ipam", get(network_ipam_status))
        .route("/v1/network/ipcache/remote", post(upsert_remote_ipcache))
        .route(
            "/v1/network/ipcache/remote/{identity}",
            delete(delete_remote_ipcache),
        )
        .route("/v1/network/refresh-dns", post(network_refresh_dns))
        .route("/v1/network/endpoints", get(list_endpoints))
        .route("/v1/network/hubble/flows", get(hubble_flows))
        .route("/v1/network/hubble/flows/text", get(hubble_flows_text))
        .route("/v1/network/hubble/ui", get(hubble_ui))
        .route("/v1/vms/{id}/pressure", get(vm_pressure))
        .route("/v1/vms/{id}/logs", get(vm_logs))
        .route("/v1/vms/{id}/agent", post(agent_exec))
        .route("/v1/vms/{id}/agent/ping", post(agent_ping))
        .route("/v1/vms/{id}/agent/put-file", post(agent_put_file))
        .route("/v1/vms/{id}/agent/get-file", post(agent_get_file))
        .route("/v1/vms/{id}/console", get(agent_console))
        .route("/v1/vms/{id}/qga/ping", post(qga_ping))
        .route(
            "/v1/vms/{id}/qga/network-interfaces",
            get(qga_network_interfaces),
        )
        .route("/v1/vms/{id}/qga/exec", post(qga_exec))
        .route("/v1/vms/{id}/qga/fsfreeze", post(qga_fsfreeze_freeze))
        .route("/v1/vms/{id}/qga/fsthaw", post(qga_fsfreeze_thaw))
        .route("/v1/vms/{id}/qga/fsfreeze-status", get(qga_fsfreeze_status))
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
        .route("/v1/pools/{name}/resize", post(resize_pool))
        .layer(middleware::from_fn_with_state(
            manager.clone(),
            tenant_guard_middleware,
        ));
    // Between tenant_guard (innermost) and auth (below): runs after auth
    // has resolved an AuditActor, before tenant scoping -- see
    // rate_limit_middleware's own doc comment.
    if let Some(limiter) = build_rate_limiter(&manager.cfg.auth) {
        router = router.layer(middleware::from_fn_with_state(
            limiter,
            rate_limit_middleware,
        ));
    }
    router
        .layer(middleware::from_fn_with_state(
            AuthState {
                manager: manager.clone(),
                oidc: oidc.clone(),
            },
            auth_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(manager)
}

/// Builds the REST API rate limiter from `auth.rate_limit_rps`/
/// `.rate_limit_burst` when both are set (`None` = no rate limiting,
/// byte-for-byte the behavior before this existed) -- mirrors
/// `build_oidc`'s own "both fields or neither, warn on a half-set pair"
/// shape.
fn build_rate_limiter(cfg: &fluxvm_core::config::AuthConfig) -> Option<Arc<rate_limit::Limiter>> {
    match cfg.rate_limit_enabled() {
        Some((rps, burst)) => {
            let limiter = Arc::new(rate_limit::Limiter::new(rps, burst));
            // Bounds memory growth from a long-running process seeing many
            // distinct actors over its lifetime (every distinct token name
            // plus, for OIDC, every distinct subject ever seen) -- an idle
            // key's bucket is dropped 10 minutes after its last request,
            // long enough that a real caller's own average rate has fully
            // refilled it anyway.
            let prune_target = limiter.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(60));
                loop {
                    ticker.tick().await;
                    prune_target.prune(Duration::from_secs(600));
                }
            });
            Some(limiter)
        }
        None => {
            if cfg.rate_limit_rps.is_some() != cfg.rate_limit_burst.is_some() {
                tracing::warn!(
                    "auth.rate_limit_rps and auth.rate_limit_burst must both be set — rate limiting disabled"
                );
            }
            None
        }
    }
}

fn build_oidc(cfg: &fluxvm_core::config::AuthConfig) -> Option<Arc<oidc::OidcValidator>> {
    if !cfg.oidc_enabled() {
        if cfg.oidc_issuer.is_some() && cfg.oidc_audience.is_none() {
            tracing::warn!(
                "auth.oidc_issuer is set without auth.oidc_audience — OIDC JWT validation disabled"
            );
        }
        return None;
    }
    let issuer = cfg.oidc_issuer.clone()?;
    let audience = cfg.oidc_audience.clone()?;
    tracing::info!(%issuer, %audience, "OIDC JWT validation enabled (JWKS)");
    Some(Arc::new(oidc::OidcValidator::new(issuer, audience)))
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
    token_tenant: Option<Extension<TokenTenant>>,
    Json(mut req): Json<CreateVmRequest>,
) -> ApiResult<impl IntoResponse> {
    require_admin(role)?;
    // Token tenant is authoritative: inherit when omitted; reject mismatch.
    if let Some(Extension(TokenTenant(t))) = token_tenant {
        if let Some(ref body) = req.tenant {
            if body != &t {
                return Err(ApiError::forbidden(format!(
                    "token tenant '{t}' cannot create VM for tenant '{body}'"
                )));
            }
        }
        req.tenant = Some(t);
    }
    // Server-side only, unconditionally -- unlike `tenant` above,
    // `created_by_token` is always overwritten from the authenticated
    // caller's own identity regardless of what the body claims (see
    // `CreateVmRequest.created_by_token`'s own doc comment for why this is
    // a handler-level overwrite rather than `skip_deserializing`), then
    // used by `enforce_token_quotas` to scope quotas to this token's own
    // VMs instead of every VM on the node.
    let actor_name = actor.as_ref().map(|a| a.0.0.as_str());
    req.created_by_token = actor_name.map(String::from);
    m.enforce_token_quotas(actor_name, &req)
        .await
        .map_err(|e| ApiError::forbidden(e.to_string()))?;
    Ok((StatusCode::CREATED, Json(m.create(req).await?)))
}

async fn create_sandbox(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    actor: Option<Extension<AuditActor>>,
    token_tenant: Option<Extension<TokenTenant>>,
    Json(req): Json<fluxvm_scheduler::SandboxCreateRequest>,
) -> ApiResult<impl IntoResponse> {
    require_admin(role)?;
    let token_tenant = token_tenant.map(|Extension(TokenTenant(t))| t);
    let actor_name = actor.as_ref().map(|a| a.0.0.as_str());
    Ok((
        StatusCode::CREATED,
        Json(
            m.create_sandbox(req, token_tenant.as_deref(), actor_name)
                .await?,
        ),
    ))
}

async fn list_sandboxes(
    State(m): State<Arc<VmManager>>,
    token_tenant: Option<Extension<TokenTenant>>,
) -> Json<serde_json::Value> {
    // Unlike list_vms, this had no tenant filtering at all -- any
    // authenticated caller, tenant-scoped token or not, could see every
    // sandbox across every tenant. tenant_guard_middleware only ever
    // scoped *per-record* access by id (GET/POST .../{id}/...), never a
    // list. Mirrors list_vms's own filtering exactly.
    let items: Vec<_> = m
        .list()
        .await
        .into_iter()
        // QEMU-backed sandboxes (volume templates) are sandboxes too; they are
        // recognised by the marker `create_sandbox` writes into their workspace.
        .filter(|v| {
            v.backend == BackendKind::FluxVm || v.workspace.join("sandbox-proxy.json").exists()
        })
        .filter(|v| match &token_tenant {
            Some(Extension(TokenTenant(t))) => v.request.tenant.as_deref() == Some(t.as_str()),
            None => true,
        })
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

// Admin-only, like every other guest-reaching route (sandbox_fs_read,
// sandbox_process, agent_exec, qga_exec, ...). These two handlers had no
// role check of any kind before -- registered with `any(...)`, a
// `read-only` token could issue arbitrary HTTP methods into a tenant's
// guest through the proxy. They return a bare `Response` rather than an
// `ApiResult<T>`, so the `require_admin` error has to be converted with
// `.into_response()` explicitly instead of `?`.
async fn sandbox_http_proxy_default_port(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path((id, path)): Path<(Uuid, String)>,
    req: Request,
) -> Response {
    if let Err(e) = require_admin(role) {
        return e.into_response();
    }
    let port = match m.get(id).await {
        Ok(vm) => m.sandbox_http_proxy_port(&vm).await,
        Err(_) => m.cfg.sandbox.http_proxy_default_port,
    };
    sandbox_proxy_inner(m, id, port, path, req).await
}

async fn sandbox_http_proxy(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path((id, port, path)): Path<(Uuid, u16, String)>,
    req: Request,
) -> Response {
    if let Err(e) = require_admin(role) {
        return e.into_response();
    }
    sandbox_proxy_inner(m, id, port, path, req).await
}

/// Connects to `addr` from inside the network namespace `pid` is running in,
/// by `setns()`-ing a throwaway OS thread before calling `connect()`. A
/// namespace only governs which sockets a thread's *syscalls* create, not
/// fds it already holds, so the resulting `TcpStream` stays perfectly usable
/// once handed back to the async runtime on any other thread -- only the
/// `connect()` itself needs to happen inside the namespace.
///
/// A `tap`+`netns=true` sandbox's `guest_ip` (assigned by the per-VM dnsmasq
/// on its internal bridge, see `fluxvm_network::netns`) is only routable
/// from inside that namespace: the daemon's own default namespace has no
/// path to it, so a plain `reqwest::Client` (which always connects from the
/// calling thread's ambient namespace) hangs until it times out. That was
/// silently breaking the HTTP proxy for every netns sandbox -- vsock-based
/// guest-agent calls (exec, fs read/write) were unaffected since vsock
/// doesn't route through the guest's network namespace at all, so a booted,
/// working guest still looked completely unreachable over this path.
///
/// Uses a plain `std::thread::spawn`, never `tokio::task::spawn_blocking`:
/// tokio's blocking pool reuses its threads across unrelated work, and
/// `setns()` would leak into whatever that thread runs next. A one-shot
/// thread that exits right after `connect()` has nothing left to leak.
async fn connect_in_netns(
    pid: u32,
    addr: std::net::SocketAddr,
) -> std::io::Result<tokio::net::TcpStream> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let result = (|| -> std::io::Result<std::net::TcpStream> {
            let ns_file = std::fs::File::open(format!("/proc/{pid}/ns/net"))?;
            if unsafe { libc::setns(ns_file.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        })();
        // The receiver only drops early if the whole proxy request was
        // itself abandoned (e.g. the client disconnected) -- nothing to do.
        let _ = tx.send(result);
    });
    let std_stream = rx.await.map_err(|_| {
        std::io::Error::other("netns connect worker thread panicked before replying")
    })??;
    std_stream.set_nonblocking(true)?;
    tokio::net::TcpStream::from_std(std_stream)
}

/// Caps both the request body read from the caller and the response body
/// read back from the guest in `sandbox_proxy_inner`/`proxy_over_tcp`. A
/// compromised or buggy guest can otherwise stream an effectively unbounded
/// response for up to 30s per request (the only prior limit was the
/// timeout, not a size) -- a straightforward host-memory-exhaustion
/// primitive from inside any tenant's own sandbox.
const SANDBOX_PROXY_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// The hyper-client half of the sandbox HTTP proxy: handshake over an
/// already-connected stream to the guest, forward the request, and read
/// back the response (capped at `SANDBOX_PROXY_MAX_BODY_BYTES`). Factored
/// out of `sandbox_proxy_inner` so it's testable directly against a real
/// loopback TCP "guest" -- `sandbox_proxy_inner`'s own connection setup
/// (`connect_in_netns`) needs `CAP_SYS_ADMIN` for `setns()`, unavailable on
/// this project's remote build host, let alone in a normal test run, so
/// there was previously no way to exercise this half of the proxy at all.
async fn proxy_over_tcp(
    tcp: tokio::net::TcpStream,
    method: Method,
    uri: String,
    headers: axum::http::HeaderMap,
    body: bytes::Bytes,
) -> Response {
    let (mut sender, connection) =
        match hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await {
            Ok(pair) => pair,
            Err(e) => {
                return (StatusCode::BAD_GATEWAY, format!("guest upstream: {e}")).into_response();
            }
        };
    // Drives the connection's I/O; must stay alive for `sender` to work at
    // all, but its exit (guest closes the connection) isn't itself an error.
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = hyper::Request::builder().method(method).uri(uri);
    for (k, v) in headers.iter() {
        // host: about the wrong peer once forwarded. content-length: hyper
        // computes and sets its own from the `Full` body below -- forwarding
        // the original value duplicates the header, and on a non-empty body
        // (anything but the plain GETs this path was first exercised with)
        // that framing mismatch left the guest's HTTP server waiting on body
        // bytes that were never coming, hanging the request indefinitely
        // instead of erroring.
        if k == header::HOST || k == header::CONTENT_LENGTH || k == header::TRANSFER_ENCODING {
            continue;
        }
        builder = builder.header(k, v);
    }
    let outgoing = match builder.body(Full::new(body)) {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("building request: {e}")).into_response();
        }
    };

    let up = match tokio::time::timeout(Duration::from_secs(30), sender.send_request(outgoing))
        .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return (StatusCode::BAD_GATEWAY, format!("guest upstream: {e}")).into_response();
        }
        Err(_) => {
            return (StatusCode::BAD_GATEWAY, "guest upstream: request timed out").into_response();
        }
    };
    let status = StatusCode::from_u16(up.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let headers = up.headers().clone();
    let bytes = match tokio::time::timeout(
        Duration::from_secs(30),
        Limited::new(up.into_body(), SANDBOX_PROXY_MAX_BODY_BYTES).collect(),
    )
    .await
    {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(e)) => {
            // Covers both a genuine guest-connection error and a
            // `Limited`-imposed cap violation (`LengthLimitError`) without a
            // separate branch -- `Limited<B>::Error` is `Box<dyn
            // std::error::Error + Send + Sync>`, which both `Display`s
            // through the same `{e}` this arm already used for the
            // unwrapped `hyper::Error` before this body was capped.
            return (
                StatusCode::BAD_GATEWAY,
                format!("guest upstream: reading response body: {e}"),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                "guest upstream: reading response body timed out",
            )
                .into_response();
        }
    };
    let mut response = Response::builder().status(status);
    for (k, v) in headers.iter() {
        // connection/keep-alive describe *this* handler's short-lived,
        // one-shot connection to the guest (which we tear down right after
        // this response regardless of what it says) -- forwarding them onto
        // the outer response tells the caller's connection pool it can
        // reuse this connection to fluxvm-api's own server for a "next
        // request" that has nothing to do with the guest's keep-alive.
        // Harmless when the semantics happen to line up; when they don't,
        // the caller tries to reuse a connection axum's own server settings
        // already closed, and reqwest reports it as a bare "connection
        // closed before message completed" with no indication why.
        if k == header::CONNECTION || k == header::HeaderName::from_static("keep-alive") {
            continue;
        }
        response = response.header(k, v);
    }
    response
        .body(Body::from(bytes))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
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
    let Some(pid) = vm.pid else {
        return (
            StatusCode::BAD_GATEWAY,
            "sandbox has no running process to reach its network namespace through",
        )
            .into_response();
    };
    let addr = match format!("{guest_ip}:{port}").parse::<std::net::SocketAddr>() {
        Ok(a) => a,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("guest_ip: {e}")).into_response(),
    };
    let method = req.method().clone();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let uri = format!("/{path}{query}");
    let headers = req.headers().clone();

    let tcp = match tokio::time::timeout(Duration::from_secs(10), connect_in_netns(pid, addr)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("guest upstream: connecting to {addr}: {e}"),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("guest upstream: connecting to {addr} timed out"),
            )
                .into_response();
        }
    };

    let body = match axum::body::to_bytes(req.into_body(), SANDBOX_PROXY_MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("body: {e}")).into_response(),
    };
    proxy_over_tcp(tcp, method, uri, headers, body).await
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

// Admin-only: a matching host can return `inject_authorization`, a real
// credential-vault secret (see `fluxvm_network::egress::decide`) -- letting
// a `read-only` token call this would hand it a secret only an `admin`
// caller should ever see, contradicting api.md's own "any mutating route
// ... returns 403 [for read-only]" RBAC contract this route had silently
// never enforced (no role check of any kind existed here before).
async fn egress_check(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(body): Json<EgressCheckBody>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(fluxvm_network::egress::decide(
        &m.cfg.sandbox,
        &body.host
    ))))
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

// ZYVOR_RUNTIME_BOUNDARY_V1: stable node-runtime feature discovery for Fabric.
async fn security_capabilities(
    State(m): State<Arc<VmManager>>,
) -> Json<fluxvm_core::security::HostCapabilities> {
    Json(m.host_security_capabilities())
}

async fn get_vm_evidence(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let vm = m.get(id).await?;
    if let Some(ev) = &vm.security_evidence {
        return Ok(Json(json!(ev)));
    }
    Ok(Json(json!(
        fluxvm_core::security::read_evidence(&vm.workspace)?
    )))
}

async fn release_vm_secret(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.release_test_secret(id).await?)))
}

async fn runtime_capabilities() -> Json<fluxvm_core::model::RuntimeCapabilities> {
    use fluxvm_core::model::{
        BackendKind, RuntimeCapabilities, RuntimeMigrationCapability, RuntimeSnapshotCapability,
    };
    Json(RuntimeCapabilities {
        api_version: "runtime.fluxvm.zyvor.io/v1".into(),
        scope: "node-local".into(),
        orchestration_owner: "zyvor-fabric".into(),
        migration: vec![
            RuntimeMigrationCapability {
                backend: BackendKind::Qemu,
                live: true,
                pre_copy: true,
                post_copy: true,
                multifd: true,
                requires_shared_storage: true,
                transports: vec!["tcp".into(), "unix".into()],
                status_pollable: true,
            },
            RuntimeMigrationCapability {
                backend: BackendKind::CloudHypervisor,
                live: true,
                pre_copy: true,
                post_copy: true,
                // `connections` (send-migration's multifd analogue) only
                // over `tcp:` -- verified live it's rejected outright
                // alongside a `unix:` destination.
                multifd: true,
                requires_shared_storage: true,
                transports: vec!["tcp".into(), "unix".into()],
                status_pollable: false,
            },
        ],
        snapshot: vec![
            RuntimeSnapshotCapability {
                backend: BackendKind::Qemu,
                memory: true,
                disk: true,
                portable: false,
            },
            RuntimeSnapshotCapability {
                backend: BackendKind::CloudHypervisor,
                memory: true,
                disk: true,
                portable: false,
            },
            RuntimeSnapshotCapability {
                backend: BackendKind::Firecracker,
                memory: false,
                disk: false,
                portable: false,
            },
            RuntimeSnapshotCapability {
                backend: BackendKind::FluxVm,
                memory: true,
                disk: true,
                portable: false,
            },
        ],
    })
}

fn allocated_vfio_bdfs(vms: &[VmRecord]) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    for vm in vms {
        for bdf in &vm.request.vfio_devices {
            out.insert(bdf.trim().to_ascii_lowercase());
        }
    }
    out
}

async fn list_host_gpus(
    State(m): State<Arc<VmManager>>,
) -> ApiResult<Json<serde_json::Value>> {
    let allocated = allocated_vfio_bdfs(&m.list().await);
    let gpus = fluxvm_core::gpu::list_host_gpus(&m.cfg.state_dir, &allocated)?;
    Ok(Json(json!({ "items": gpus })))
}

async fn host_gpu_preflight(
    State(m): State<Arc<VmManager>>,
) -> ApiResult<Json<fluxvm_core::gpu::GpuPreflight>> {
    Ok(Json(fluxvm_core::gpu::gpu_preflight(&m.cfg.state_dir)?))
}

async fn bind_host_gpu(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(req): Json<fluxvm_core::gpu::GpuBindRequest>,
) -> ApiResult<impl IntoResponse> {
    require_admin(role)?;
    let allocated = allocated_vfio_bdfs(&m.list().await);
    let result = fluxvm_core::gpu::bind_gpu_group(&m.cfg.state_dir, &req, &allocated)?;
    Ok((StatusCode::OK, Json(result)))
}

async fn release_host_gpu(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(req): Json<fluxvm_core::gpu::GpuReleaseRequest>,
) -> ApiResult<Json<fluxvm_core::gpu::HostGpu>> {
    require_admin(role)?;
    let allocated = allocated_vfio_bdfs(&m.list().await);
    Ok(Json(fluxvm_core::gpu::release_gpu_group(
        &m.cfg.state_dir,
        &req,
        &allocated,
    )?))
}

async fn start_migration(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<fluxvm_core::model::MigrationStartRequest>,
) -> ApiResult<Json<fluxvm_core::model::MigrationStatus>> {
    require_admin(role)?;
    Ok(Json(m.start_migration(id, &req).await?))
}

async fn migration_status(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<fluxvm_core::model::MigrationStatus>> {
    Ok(Json(m.migration_status(id).await?))
}

async fn cancel_migration(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<fluxvm_core::model::MigrationStatus>> {
    require_admin(role)?;
    Ok(Json(m.cancel_migration(id).await?))
}

#[derive(Deserialize)]
struct ListVmsQuery {
    /// Exact-match filter on `VmRecord.name`. Added for zyvor-fabric's
    /// `FluxVMDriver`, which is keyed by name (systemd-machined's model)
    /// while `VmRecord` is keyed by `Uuid` — this lets the driver resolve a
    /// name to a record server-side instead of pulling the full list on
    /// every lookup.
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
}

async fn list_vms(
    State(m): State<Arc<VmManager>>,
    token_tenant: Option<Extension<TokenTenant>>,
    Query(q): Query<ListVmsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut items = m.list().await;
    if let Some(name) = q.name {
        items.retain(|vm| vm.name == name);
    }
    // Token tenant forces scope; query ?tenant= must match when both present.
    if let Some(Extension(TokenTenant(t))) = token_tenant {
        if let Some(ref qt) = q.tenant {
            if qt != &t {
                return Err(ApiError::forbidden(format!(
                    "token tenant '{t}' cannot list tenant '{qt}'"
                )));
            }
        }
        items.retain(|vm| vm.request.tenant.as_deref() == Some(t.as_str()));
    } else if let Some(tenant) = q.tenant {
        items.retain(|vm| vm.request.tenant.as_deref() == Some(tenant.as_str()));
    }
    Ok(Json(json!({"items": items})))
}

async fn readyz(State(m): State<Arc<VmManager>>) -> impl IntoResponse {
    let body = match m.readyz().await {
        Ok(v) => v,
        Err(e) => json!({"ok": false, "error": e.to_string()}),
    };
    let ok = body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let status = if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body))
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

async fn hotplug_vm_cpu(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<fluxvm_core::model::HotplugCpuRequest>,
) -> ApiResult<Json<fluxvm_core::model::HotplugCpuResult>> {
    require_admin(role)?;
    let vcpus = m.hotplug_cpu(id, req.add_vcpus).await?;
    Ok(Json(fluxvm_core::model::HotplugCpuResult { vcpus }))
}

async fn hotplug_vm_memory(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<fluxvm_core::model::HotplugMemoryRequest>,
) -> ApiResult<Json<fluxvm_core::model::HotplugMemoryResult>> {
    require_admin(role)?;
    let memory_mib = m.hotplug_memory(id, req.add_memory_mib).await?;
    Ok(Json(fluxvm_core::model::HotplugMemoryResult { memory_mib }))
}

async fn hotplug_vm_nic(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<fluxvm_core::model::HotplugNicRequest>,
) -> ApiResult<StatusCode> {
    require_admin(role)?;
    req.validate().map_err(|e| anyhow::anyhow!(e))?;
    match req.direct {
        Some(direct) => m.hotplug_direct_nic(id, direct, req.mac).await?,
        None => m.hotplug_nic(id, req.bridge, req.mac).await?,
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn hotplug_vm_share(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<fluxvm_core::model::HotplugShareRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    req.validate().map_err(|e| anyhow::anyhow!(e))?;
    let tag = m.hotplug_share(id, req.host_path, req.read_only).await?;
    Ok(Json(json!({"tag": tag})))
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

async fn vm_network_drop_reasons(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
    Query(q): Query<NetworkFlowsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    m.get(id).await?;
    Ok(Json(json!({
        "items": fluxvm_network::ebpf::drop_reasons(&m.cfg.sandbox.dataplane, id, q.limit)?
    })))
}

async fn vm_network_migration_state(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    m.get(id).await?;
    Ok(Json(json!(fluxvm_network::migration_state::status(
        &m.cfg, id
    )?)))
}

async fn vm_network_migration_quiesce(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.get(id).await?;
    Ok(Json(json!(fluxvm_network::migration_state::quiesce(
        &m.cfg, id
    )?)))
}

async fn vm_network_migration_export(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.get(id).await?;
    Ok(Json(json!(
        fluxvm_network::migration_state::export_snapshot(&m.cfg, id)?
    )))
}

async fn vm_network_migration_restore(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(snapshot): Json<fluxvm_network::migration_state::VmNetworkStateSnapshot>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.get(id).await?;
    Ok(Json(json!(
        fluxvm_network::migration_state::restore_snapshot(&m.cfg, id, &snapshot)?
    )))
}

async fn vm_network_migration_resume(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.get(id).await?;
    Ok(Json(json!(fluxvm_network::migration_state::resume(
        &m.cfg, id
    )?)))
}

async fn get_vm_network_policy(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.network_policy(id).await?)))
}

async fn vm_network_service_stats(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(
        json!({"items": fluxvm_network::service::stats_for_vm(&m.cfg, id)?}),
    ))
}

async fn network_service_status(
    State(m): State<Arc<VmManager>>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(fluxvm_network::service::host_status(&m.cfg)?)))
}

async fn network_service_stats(
    State(m): State<Arc<VmManager>>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(
        json!({"interfaces": fluxvm_network::service::host_stats(&m.cfg)?}),
    ))
}

async fn network_service_health(
    State(m): State<Arc<VmManager>>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(fluxvm_network::service::health_report(&m.cfg)?)))
}

async fn reconcile_network_service_health(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(
        fluxvm_network::service::reconcile_health(&m.cfg).await?
    )))
}

async fn gc_network_service_conntrack(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(fluxvm_network::service::gc_conntrack(&m.cfg)?)))
}

async fn reconcile_network_service_pressure(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(fluxvm_network::service_pressure::reconcile(
        &m.cfg
    )?)))
}

async fn network_service_advertisements(
    State(m): State<Arc<VmManager>>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(
        fluxvm_network::service::advertisement_snapshot(&m.cfg)?
    )))
}

#[derive(Debug, Deserialize)]
struct ServiceFlowsQuery {
    #[serde(default = "default_service_flow_limit")]
    limit: usize,
}

fn default_service_flow_limit() -> usize {
    256
}

async fn network_service_flows(
    State(m): State<Arc<VmManager>>,
    Query(q): Query<ServiceFlowsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({
        "items": fluxvm_network::service::service_flows(&m.cfg, q.limit)?
    })))
}

async fn export_network_service_telemetry(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Query(q): Query<ServiceFlowsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(
        fluxvm_network::service::export_otlp(&m.cfg, q.limit).await?
    )))
}

async fn export_network_service_conntrack(
    State(m): State<Arc<VmManager>>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(fluxvm_network::service::export_conntrack(
        &m.cfg, &name
    )?)))
}

async fn import_network_service_conntrack(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    Json(snapshot): Json<fluxvm_network::service::ConntrackSnapshot>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let written = fluxvm_network::service::import_conntrack(&m.cfg, &name, &snapshot)?;
    Ok(Json(json!({"written": written})))
}

#[derive(Debug, Deserialize)]
struct ServiceDeltaQuery {
    after_seq: Option<u64>,
    max_entries: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct ServiceDeltaAck {
    ack_seq: u64,
}

async fn export_network_service_conntrack_delta(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    Query(q): Query<ServiceDeltaQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(
        fluxvm_network::service::export_conntrack_delta(
            &m.cfg,
            &name,
            q.after_seq.unwrap_or(0),
            q.max_entries.unwrap_or(1024),
        )?
    )))
}

async fn import_network_service_conntrack_delta(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    Json(batch): Json<fluxvm_network::service::ConntrackDeltaBatch>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(
        fluxvm_network::service::import_conntrack_delta(&m.cfg, &name, &batch)?
    )))
}

async fn ack_network_service_conntrack_delta(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    Json(req): Json<ServiceDeltaAck>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(fluxvm_network::service::ack_conntrack_delta(
        &m.cfg,
        &name,
        req.ack_seq
    )?)))
}

async fn list_network_services(
    State(m): State<Arc<VmManager>>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(
        json!({"items": fluxvm_network::service::list(&m.cfg)?}),
    ))
}

async fn get_network_service(
    State(m): State<Arc<VmManager>>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    match fluxvm_network::service::get(&m.cfg, &name)? {
        Some(service) => Ok(Json(json!(service))),
        None => Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: format!("service '{name}' not found"),
        }),
    }
}

async fn upsert_network_service(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(service): Json<fluxvm_network::service::ServiceSpec>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(fluxvm_network::service::upsert(
        &m.cfg, service
    )?)))
}

async fn delete_network_service(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let deleted = fluxvm_network::service::delete(&m.cfg, &name)?;
    if !deleted {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: format!("service '{name}' not found"),
        });
    }
    Ok(Json(json!({"deleted": name})))
}

async fn list_network_groups(
    State(m): State<Arc<VmManager>>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({"items": m.list_network_groups().await?})))
}

async fn get_network_group(
    State(m): State<Arc<VmManager>>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.get_network_group(&name).await?)))
}

async fn upsert_network_group(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(group): Json<fluxvm_network::groups::SecurityGroup>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(m.upsert_network_group(group).await?)))
}

async fn delete_network_group(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.delete_network_group(&name).await?;
    Ok(Json(json!({"deleted": name})))
}

async fn list_cnp(State(m): State<Arc<VmManager>>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({"items": m.list_cnp().await?})))
}

async fn get_cnp(
    State(m): State<Arc<VmManager>>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.get_cnp(&name).await?)))
}

async fn apply_cnp(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(policy): Json<fluxvm_network::cnp::CiliumNetworkPolicy>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!(m.apply_cnp(policy).await?)))
}

async fn delete_cnp(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.delete_cnp(&name).await?;
    Ok(Json(json!({"deleted": name})))
}

async fn list_identities(State(m): State<Arc<VmManager>>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({"items": m.list_identities().await?})))
}

async fn network_observe(State(m): State<Arc<VmManager>>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.network_observe().await?)))
}

async fn network_health(State(m): State<Arc<VmManager>>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.network_health().await?)))
}

async fn network_ipcache(State(m): State<Arc<VmManager>>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({"items": m.network_ipcache().await?})))
}

/// Netns-sandbox `/28` IPAM pool utilization — see `fluxvm_network::ipam::IpamStatus`.
async fn network_ipam_status(
    State(m): State<Arc<VmManager>>,
) -> ApiResult<Json<fluxvm_network::ipam::IpamStatus>> {
    Ok(Json(m.network_ipam_status().await?))
}

#[derive(Debug, Deserialize)]
struct RemoteIpcacheUpsert {
    identity: u32,
    #[serde(default)]
    cidrs: Vec<String>,
}

/// Fabric ClusterMesh-like: upsert remote identity CIDRs into local ipcache
/// (nil `vm_id` sentinel). Does not implement full mesh datapath.
async fn upsert_remote_ipcache(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(body): Json<RemoteIpcacheUpsert>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let identity = body.identity;
    let upserted = m.upsert_remote_ipcache(identity, body.cidrs).await?;
    Ok(Json(json!({
        "identity": identity,
        "upserted": upserted,
    })))
}

async fn delete_remote_ipcache(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(identity): Path<u32>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let deleted = m.delete_remote_ipcache(identity).await?;
    Ok(Json(json!({
        "identity": identity,
        "deleted": deleted,
    })))
}

async fn list_endpoints(State(m): State<Arc<VmManager>>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!({"items": m.network_endpoints().await?})))
}

#[derive(Debug, Deserialize)]
struct HubbleFlowsQuery {
    #[serde(default = "default_hubble_limit")]
    limit: usize,
    #[serde(default = "default_all")]
    verdict: String,
    #[serde(default = "default_all")]
    protocol: String,
    /// color | plain | normal | json
    #[serde(default = "default_hubble_output")]
    output: String,
    #[serde(default)]
    detailed: bool,
}
fn default_hubble_limit() -> usize {
    64
}
fn default_all() -> String {
    "all".into()
}
fn default_hubble_output() -> String {
    "json".into()
}

async fn hubble_flows(
    State(m): State<Arc<VmManager>>,
    Query(q): Query<HubbleFlowsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    use fluxvm_network::packetflow::{filter_views, to_hubble_flow};
    let views = filter_views(
        m.hubble_observe_views(q.limit).await?,
        Some(q.verdict.as_str()),
        Some(q.protocol.as_str()),
    );
    let items: Vec<_> = views.iter().map(to_hubble_flow).collect();
    Ok(Json(json!({"items": items})))
}

async fn hubble_flows_text(
    State(m): State<Arc<VmManager>>,
    Query(q): Query<HubbleFlowsQuery>,
) -> impl axum::response::IntoResponse {
    use fluxvm_network::packetflow::{FlowOutput, filter_views, render_flows};
    let views = match m.hubble_observe_views(q.limit).await {
        Ok(v) => filter_views(v, Some(q.verdict.as_str()), Some(q.protocol.as_str())),
        Err(e) => {
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                format!("error: {e:#}\n"),
            );
        }
    };
    let mode = FlowOutput::parse(&q.output);
    let body = render_flows(&views, mode, q.detailed);
    (
        axum::http::StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
}

async fn hubble_ui() -> impl axum::response::IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        HUBBLE_UI_HTML,
    )
}

const HUBBLE_UI_HTML: &str = include_str!("hubble_ui.html");

async fn network_refresh_dns(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!({"refreshed": m.refresh_fqdn_policies().await?})))
}

async fn get_vm_network_effective(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.network_effective(id).await?)))
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

/// Set 6S: `null`/absent when unconfigured, matching `get_vm_network_policy`'s
/// shape but distinguishing "no Pod-scoped policy" from an empty object
/// (which would mean "policy present, everything allowed").
async fn get_vm_pod_network_policy(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.pod_network_policy(id).await?)))
}

async fn set_vm_pod_network_policy(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(policy): Json<fluxvm_network::dataplane::PodNetworkPolicy>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.set_pod_network_policy(id, Some(policy)).await?;
    Ok(Json(json!({"ok": true})))
}

async fn clear_vm_pod_network_policy(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.set_pod_network_policy(id, None).await?;
    Ok(Json(json!({"ok": true})))
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

/// `POST /v1/vms/{id}/agent/ping` — health-checks the vsock guest agent
/// without spending a real `exec` round trip to find out whether it's
/// reachable. Distinct from `/qga/ping` below, which checks the separate
/// QEMU guest-agent (virtio-serial) channel instead. Gated the same as
/// `agent_exec`/`agent_put_file`/`agent_get_file`: it still opens a vsock
/// connection into a specific VM, so it carries the same admin requirement
/// as every other agent operation, even though it changes nothing itself.
async fn agent_ping(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.agent_ping(id).await?;
    Ok(Json(json!({"ok": true})))
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

// A GET query, not a mutation -- read-only tokens can call this like any
// other GET route, same as vm_stats/vm_frozen below.
async fn qga_network_interfaces(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<fluxvm_image::qga::QgaNetworkInterface>>> {
    Ok(Json(m.qga_network_interfaces(id).await?))
}

// Mutating (freezes real guest I/O), so this requires admin like qga_ping
// above -- not a read-only query.
async fn qga_fsfreeze_freeze(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let frozen = m.qga_fsfreeze_freeze(id).await?;
    Ok(Json(json!({"frozen": frozen})))
}

// Deliberately no admin gate weaker than freeze's own -- thaw is the
// recovery half of the same operation, and a caller (Kairon's own
// MachineSnapshot reconcile, in particular) must be able to retry this
// unconditionally until it succeeds without a separate escalation path.
async fn qga_fsfreeze_thaw(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let thawed = m.qga_fsfreeze_thaw(id).await?;
    Ok(Json(json!({"thawed": thawed})))
}

// A GET query, not a mutation -- read-only tokens can call this like any
// other GET route, same as qga_network_interfaces above.
async fn qga_fsfreeze_status(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let status = m.qga_fsfreeze_status(id).await?;
    Ok(Json(json!({"status": status})))
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
/// vsock handshake completes: binary WS frames in are keystrokes, relayed
/// to the guest as `PtyFrame::Data`; binary WS frames out are the guest's
/// raw PTY output, unmodified. Text WS frames in are read as a resize
/// control message instead of data — `{"cols":<u16>,"rows":<u16>}` — and
/// relayed as `PtyFrame::Resize`, so a client (an xterm.js-style terminal
/// reacting to its own container resizing, say) can resize the PTY at any
/// point in the session without reconnecting. A text frame that isn't
/// valid JSON in that shape is silently ignored rather than closing the
/// session — a malformed control message costs the client a missed resize,
/// not the whole interactive shell.
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

/// A console-resize control message sent as a WS *text* frame — see
/// `agent_console`'s doc comment for why text/binary carry different
/// meanings on this route.
#[derive(Deserialize)]
struct ConsoleResizeMessage {
    cols: u16,
    rows: u16,
}

/// Maps one inbound WS message to the `PtyFrame` it should become on the
/// guest connection, or `None` if there's nothing to forward — a
/// ping/pong, or a text frame that isn't valid `ConsoleResizeMessage` JSON
/// (see `agent_console`'s doc comment: a malformed control message is
/// dropped, not treated as an error). `Message::Close` is handled by the
/// caller instead of here since it ends the whole relay loop rather than
/// mapping to a frame. Split out from `relay_console` purely so this
/// mapping is unit-testable without a real WebSocket or vsock connection.
fn ws_message_to_pty_frame(
    msg: &axum::extract::ws::Message,
) -> Option<fluxvm_guest_protocol::PtyFrame> {
    use axum::extract::ws::Message;
    use fluxvm_guest_protocol::PtyFrame;
    match msg {
        Message::Binary(b) => Some(PtyFrame::Data(b.to_vec())),
        Message::Text(t) => serde_json::from_str::<ConsoleResizeMessage>(t)
            .ok()
            .map(|r| PtyFrame::Resize {
                cols: r.cols,
                rows: r.rows,
            }),
        _ => None,
    }
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
            if matches!(msg, Message::Close(_)) {
                break;
            }
            let Some(frame) = ws_message_to_pty_frame(&msg) else {
                continue;
            };
            if console_tx.write_all(&frame.encode()).await.is_err() {
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
    token_tenant: Option<Extension<TokenTenant>>,
    Json(mut spec): Json<PoolSpec>,
) -> ApiResult<impl IntoResponse> {
    require_admin(role)?;
    // Every member ever backfilled from this pool inherits
    // spec.template.tenant unchanged (create()'s own req.clone() into each
    // member's VmRecord) -- enforcing it once here, exactly like
    // create_vm's own token-tenant forcing above, means it's correct for
    // every future member too, not just re-checked per member.
    if let Some(Extension(TokenTenant(t))) = token_tenant {
        if let Some(ref body) = spec.template.tenant {
            if body != &t {
                return Err(ApiError::forbidden(format!(
                    "token tenant '{t}' cannot create a pool for tenant '{body}'"
                )));
            }
        }
        spec.template.tenant = Some(t);
    }
    Ok((
        StatusCode::CREATED,
        Json(fluxvm_core::model::PoolView::from(
            m.create_pool(spec).await?,
        )),
    ))
}
async fn list_pools(
    State(m): State<Arc<VmManager>>,
    token_tenant: Option<Extension<TokenTenant>>,
) -> Json<serde_json::Value> {
    // Mirrors list_vms/list_sandboxes: a tenant-scoped token only ever
    // sees pools whose template.tenant matches its own -- previously
    // every pool, of every tenant, was visible to any authenticated
    // caller regardless of role or tenant.
    let items: Vec<_> = m
        .list_pools()
        .await
        .into_iter()
        .filter(|p| match &token_tenant {
            Some(Extension(TokenTenant(t))) => p.template.tenant.as_deref() == Some(t.as_str()),
            None => true,
        })
        // See PoolView's doc comment: `size`/`members` alone don't say
        // which is the target and which is what's ready right now.
        .map(fluxvm_core::model::PoolView::from)
        .collect();
    Json(json!({ "items": items }))
}

/// Returns `p` only if it's visible to `token_tenant` (no tenant on the
/// token, or an exact match) -- otherwise the generic "not found" every
/// other cross-tenant lookup in this file already returns, never a
/// distinguishable 403 (same reasoning tenant_guard_middleware's own 404
/// already documents: a tenant-scoped caller shouldn't be able to tell
/// "wrong tenant" apart from "doesn't exist" for a resource they have no
/// business seeing either way).
fn pool_visible_to(
    p: &fluxvm_core::model::PoolRecord,
    token_tenant: &Option<Extension<TokenTenant>>,
) -> bool {
    match token_tenant {
        Some(Extension(TokenTenant(t))) => p.template.tenant.as_deref() == Some(t.as_str()),
        None => true,
    }
}

async fn get_pool(
    State(m): State<Arc<VmManager>>,
    Path(name): Path<String>,
    token_tenant: Option<Extension<TokenTenant>>,
) -> ApiResult<Json<serde_json::Value>> {
    let pool = m.get_pool(&name).await?;
    if !pool_visible_to(&pool, &token_tenant) {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: "pool not found".into(),
        });
    }
    Ok(Json(json!(fluxvm_core::model::PoolView::from(pool))))
}
async fn delete_pool(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    token_tenant: Option<Extension<TokenTenant>>,
) -> ApiResult<StatusCode> {
    require_admin(role)?;
    let pool = m.get_pool(&name).await?;
    if !pool_visible_to(&pool, &token_tenant) {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: "pool not found".into(),
        });
    }
    m.delete_pool(&name).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn claim_pool(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    token_tenant: Option<Extension<TokenTenant>>,
    Json(overrides): Json<ClaimOverrides>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let pool = m.get_pool(&name).await?;
    if !pool_visible_to(&pool, &token_tenant) {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: "pool not found".into(),
        });
    }
    let token_tenant = token_tenant.map(|Extension(TokenTenant(t))| t);
    Ok(Json(json!(
        m.claim_from_pool(&name, overrides, token_tenant.as_deref())
            .await?
    )))
}

/// Changes an existing pool's target size without deleting and recreating
/// it from the same spec just to change one number -- see
/// `VmManager::resize_pool`. Admin-only and tenant-scoped exactly like
/// `delete_pool`/`claim_pool` above (a pool is name-keyed, so this needs
/// its own `pool_visible_to` check same as those two).
async fn resize_pool(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
    token_tenant: Option<Extension<TokenTenant>>,
    Json(body): Json<PoolResizeRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let pool = m.get_pool(&name).await?;
    if !pool_visible_to(&pool, &token_tenant) {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: "pool not found".into(),
        });
    }
    Ok(Json(json!(fluxvm_core::model::PoolView::from(
        m.resize_pool(&name, body.size).await?
    ))))
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
                tenant: None,
                created_by_token: None,
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
                shared_memory: false,
                agent: agent_enabled.then(|| AgentSpec {
                    enabled: true,
                    port: 17777,
                    token: None,
                }),
                qga: None,
                hyperv: false,
                storage: Default::default(),
                shared_folders: vec![],
                numa_node: None,
                cpuset: None,
                hugepages: None,
                vfio_devices: vec![],
                pod_uid: None,
                secure_boot: None,
                tpm: None,
                net_mbit_limit: None,
                net_pps_limit: None,
                blk_mbit_limit: None,
                blk_ops_limit: None,
                cpu_template: None,
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
            swtpm_pid: None,
            dhcp_leasefile: None,
            guest_ip: None,
            requested_security_profile: Default::default(),
            achieved_security_profile: Default::default(),
            security_evidence: None,
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
                    tenant: None,
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
                    tenant: None,
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
                    tenant: None,
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
                    tenant: None,
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
        async fn readonly_token_cannot_call_egress_check() {
            // Regression test: egress_check previously had no role check at
            // all, so a read-only token could call this POST route and get
            // back a real credential-vault secret (inject_authorization)
            // that only an admin caller should ever see.
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "ro".into(),
                    role: Role::ReadOnly,
                    name: None,
                    tenant: None,
                }],
                ..Default::default()
            };
            let app = router(manager(auth));
            assert_eq!(
                request(
                    app,
                    "POST",
                    "/v1/egress/check",
                    Some("ro"),
                    Some(r#"{"host":"example.com"}"#),
                )
                .await,
                StatusCode::FORBIDDEN
            );
        }

        #[tokio::test]
        async fn admin_token_can_call_egress_check() {
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "admin".into(),
                    role: Role::Admin,
                    name: None,
                    tenant: None,
                }],
                ..Default::default()
            };
            let app = router(manager(auth));
            assert_eq!(
                request(
                    app,
                    "POST",
                    "/v1/egress/check",
                    Some("admin"),
                    Some(r#"{"host":"example.com"}"#),
                )
                .await,
                StatusCode::OK
            );
        }

        #[tokio::test]
        async fn admin_token_passes_auth_for_a_mutating_route() {
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "admin".into(),
                    role: Role::Admin,
                    name: None,
                    tenant: None,
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

        #[tokio::test]
        async fn per_token_quota_does_not_count_other_tokens_vms() {
            // Regression test: enforce_token_quotas previously called
            // m.list().await -- every VM on the node from every token --
            // and checked that *global* count against each token's own
            // max_vms_per_token. With two tokens both configured (via the
            // one shared max_vms_per_token) with a quota of 1, the first
            // token to reach its quota blocked every OTHER token from
            // creating any VMs at all, not just itself: a quota meant to
            // contain a noisy tenant instead let that tenant deny service
            // to every other tenant. Filtering by created_by_token (see
            // CreateVmRequest's own doc comment) fixes this.
            let auth = AuthConfig {
                tokens: vec![
                    ApiToken {
                        token: "a".into(),
                        role: Role::Admin,
                        name: Some("tokenA".into()),
                        tenant: None,
                    },
                    ApiToken {
                        token: "b".into(),
                        role: Role::Admin,
                        name: Some("tokenB".into()),
                        tenant: None,
                    },
                ],
                max_vms_per_token: Some(1),
                ..Default::default()
            };
            let m = manager(auth);
            // Token A is already at its own quota of 1 -- a real stored VM
            // it created.
            let mut vm = fixture(BackendKind::Qemu, VmStatus::Running, false);
            vm.request.created_by_token = Some("tokenA".into());
            m.store.insert(vm).await.unwrap();

            let app = router(m);
            // Token A: correctly blocked by its own quota.
            assert_eq!(
                request(
                    app.clone(),
                    "POST",
                    "/v1/vms",
                    Some("a"),
                    Some(VALID_CREATE_BODY)
                )
                .await,
                StatusCode::FORBIDDEN
            );
            // Token B: has zero VMs of its own -- must NOT be blocked by
            // token A's quota. May still fail downstream (fake image
            // path, same as admin_token_passes_auth_for_a_mutating_route
            // above), but that's a different, later error, never the 403
            // a full quota gets.
            assert_ne!(
                request(app, "POST", "/v1/vms", Some("b"), Some(VALID_CREATE_BODY)).await,
                StatusCode::FORBIDDEN
            );
        }

        #[tokio::test]
        async fn created_by_token_cannot_be_spoofed_via_the_request_body() {
            // Regression test, behavioral half of the created_by_token
            // guarantee (see model::create_vm_request_tests for the
            // serde-round-trip half): create_vm unconditionally overwrites
            // CreateVmRequest.created_by_token from the authenticated
            // caller's identity right after deserializing, so that stamp
            // must win regardless of what the body claims. Proven here via
            // the same quota mechanism as
            // the test above -- "tokenA" is already at its quota of 1; if
            // the body's "created_by_token":"spoofed" were honored,
            // enforce_token_quotas would filter by "spoofed" instead of
            // the real caller, find zero matching VMs, and let this
            // through. It doesn't: this still hits the same 403 an
            // unspoofed request from "tokenA" would.
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "a".into(),
                    role: Role::Admin,
                    name: Some("tokenA".into()),
                    tenant: None,
                }],
                max_vms_per_token: Some(1),
                ..Default::default()
            };
            let m = manager(auth);
            let mut vm = fixture(BackendKind::Qemu, VmStatus::Running, false);
            vm.request.created_by_token = Some("tokenA".into());
            m.store.insert(vm).await.unwrap();

            let app = router(m);
            let body = r#"{"name":"t","backend":"qemu","image":"/does/not/exist.qcow2","created_by_token":"spoofed"}"#;
            assert_eq!(
                request(app, "POST", "/v1/vms", Some("a"), Some(body)).await,
                StatusCode::FORBIDDEN
            );
        }

        fn token_auth(rps: f64, burst: u32) -> AuthConfig {
            AuthConfig {
                tokens: vec![
                    ApiToken {
                        token: "alice".into(),
                        role: Role::Admin,
                        name: Some("alice".into()),
                        tenant: None,
                    },
                    ApiToken {
                        token: "bob".into(),
                        role: Role::Admin,
                        name: Some("bob".into()),
                        tenant: None,
                    },
                ],
                rate_limit_rps: Some(rps),
                rate_limit_burst: Some(burst),
                ..Default::default()
            }
        }

        #[tokio::test]
        async fn caller_is_throttled_past_burst_with_retry_after_set() {
            let app = router(manager(token_auth(1.0, 2)));
            for _ in 0..2 {
                assert_eq!(
                    status_for(app.clone(), "GET", "/v1/vms", Some("alice")).await,
                    StatusCode::OK
                );
            }
            let req = Request::builder()
                .method("GET")
                .uri("/v1/vms")
                .header(header::AUTHORIZATION, "Bearer alice")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            assert!(resp.headers().get(header::RETRY_AFTER).is_some());
        }

        #[tokio::test]
        async fn distinct_tokens_have_independent_buckets() {
            let app = router(manager(token_auth(1.0, 1)));
            assert_eq!(
                status_for(app.clone(), "GET", "/v1/vms", Some("alice")).await,
                StatusCode::OK
            );
            // alice's single-token burst is spent -- she's throttled now.
            assert_eq!(
                status_for(app.clone(), "GET", "/v1/vms", Some("alice")).await,
                StatusCode::TOO_MANY_REQUESTS
            );
            // bob has never made a request -- his own bucket is untouched.
            assert_eq!(
                status_for(app, "GET", "/v1/vms", Some("bob")).await,
                StatusCode::OK
            );
        }

        #[tokio::test]
        async fn healthz_is_never_rate_limited() {
            let app = router(manager(token_auth(1.0, 1)));
            for _ in 0..5 {
                assert_eq!(
                    status_for(app.clone(), "GET", "/healthz", None).await,
                    StatusCode::OK
                );
            }
        }

        #[tokio::test]
        async fn unset_config_applies_no_rate_limiting_at_all() {
            let app = router(manager(AuthConfig {
                tokens: vec![ApiToken {
                    token: "alice".into(),
                    role: Role::Admin,
                    name: Some("alice".into()),
                    tenant: None,
                }],
                ..Default::default()
            }));
            for _ in 0..10 {
                assert_eq!(
                    status_for(app.clone(), "GET", "/v1/vms", Some("alice")).await,
                    StatusCode::OK
                );
            }
        }

        fn tenant_tokens() -> AuthConfig {
            AuthConfig {
                tokens: vec![
                    ApiToken {
                        token: "acme".into(),
                        role: Role::Admin,
                        name: Some("acme".into()),
                        tenant: Some("acme".into()),
                    },
                    ApiToken {
                        token: "other".into(),
                        role: Role::Admin,
                        name: Some("other".into()),
                        tenant: Some("other".into()),
                    },
                ],
                ..Default::default()
            }
        }

        async fn body_string(resp: Response) -> String {
            let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .unwrap();
            String::from_utf8(bytes.to_vec()).unwrap()
        }

        #[tokio::test]
        async fn list_sandboxes_only_returns_the_callers_own_tenant() {
            // Regression test: list_sandboxes previously had no tenant
            // filtering at all (unlike list_vms), so any authenticated
            // caller -- tenant-scoped or not -- could see every sandbox
            // across every tenant.
            let m = manager(tenant_tokens());
            let mut acme_sandbox = fixture(BackendKind::FluxVm, VmStatus::Running, true);
            acme_sandbox.request.tenant = Some("acme".into());
            let mut other_sandbox = fixture(BackendKind::FluxVm, VmStatus::Running, true);
            other_sandbox.request.tenant = Some("other".into());
            m.store.insert(acme_sandbox.clone()).await.unwrap();
            m.store.insert(other_sandbox).await.unwrap();

            let app = router(m);
            let req = Request::builder()
                .method("GET")
                .uri("/v1/sandboxes")
                .header(header::AUTHORIZATION, "Bearer acme")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_string(resp).await;
            assert!(
                body.contains(&acme_sandbox.id.to_string()),
                "expected acme's own sandbox in:\n{body}"
            );
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                parsed["items"].as_array().unwrap().len(),
                1,
                "expected exactly one sandbox (the caller's own) in:\n{body}"
            );
        }

        #[tokio::test]
        async fn sandbox_id_routes_are_tenant_scoped_like_vm_routes() {
            // tenant_guard_middleware previously only recognized "/v1/vms/"
            // paths -- every "/v1/sandboxes/{id}/..." route (snapshot,
            // fs/read, fs/write, process) was entirely unscoped, so a
            // tenant-scoped admin token could reach any tenant's sandbox by
            // UUID, not just its own.
            let m = manager(tenant_tokens());
            let mut acme_sandbox = fixture(BackendKind::FluxVm, VmStatus::Running, true);
            acme_sandbox.request.tenant = Some("acme".into());
            let id = acme_sandbox.id;
            m.store.insert(acme_sandbox).await.unwrap();

            let app = router(m);
            // The "other" tenant's token gets exactly the same 404 the
            // tenant_guard already returns for a mismatched /v1/vms/{id}.
            assert_eq!(
                request(
                    app.clone(),
                    "POST",
                    &format!("/v1/sandboxes/{id}/process"),
                    Some("other"),
                    Some(r#"{"command":["true"]}"#),
                )
                .await,
                StatusCode::NOT_FOUND
            );
            // The owning tenant's token clears the tenant guard -- it may
            // still fail downstream (no real agent/vsock in this test), but
            // that's a different, later error, never a 404 "not found".
            assert_ne!(
                request(
                    app,
                    "POST",
                    &format!("/v1/sandboxes/{id}/process"),
                    Some("acme"),
                    Some(r#"{"command":["true"]}"#),
                )
                .await,
                StatusCode::NOT_FOUND
            );
        }

        #[tokio::test]
        async fn short_form_sandbox_proxy_route_is_tenant_scoped() {
            // Regression test: extract_vm_uuid only recognized "/v1/vms/"
            // and "/v1/sandboxes/" -- the short-form "/sandbox/{id}/..."
            // proxy route (the one AI-agent callers actually use, per
            // docs/agent-sandbox-gaps.md's "Guest HTTP reverse proxy") never
            // matched either prefix, so tenant_guard_middleware silently
            // no-op'd for it: any tenant-scoped token could proxy HTTP
            // traffic into another tenant's guest by UUID through this
            // specific route, even though the equivalent long-form
            // "/v1/sandboxes/{id}/http/{port}/..." route was already
            // correctly scoped (see the test above).
            let m = manager(tenant_tokens());
            let mut acme_sandbox = fixture(BackendKind::FluxVm, VmStatus::Running, true);
            acme_sandbox.request.tenant = Some("acme".into());
            let id = acme_sandbox.id;
            m.store.insert(acme_sandbox).await.unwrap();

            let app = router(m);
            // Wrong tenant: the same 404 the long-form route already
            // returns for a mismatched sandbox.
            assert_eq!(
                request(
                    app.clone(),
                    "GET",
                    &format!("/sandbox/{id}/x"),
                    Some("other"),
                    None
                )
                .await,
                StatusCode::NOT_FOUND
            );
            // Owning tenant: clears the tenant guard -- may still fail
            // downstream (no real netns/guest in this test), but that's a
            // different, later error, never a 404 "not found".
            assert_ne!(
                request(app, "GET", &format!("/sandbox/{id}/x"), Some("acme"), None).await,
                StatusCode::NOT_FOUND
            );
        }

        #[tokio::test]
        async fn readonly_token_cannot_call_sandbox_proxy() {
            // Regression test: sandbox_http_proxy/sandbox_http_proxy_default_port
            // previously had no role check at all -- registered with
            // `any(...)`, a read-only token could issue arbitrary HTTP
            // methods (not just GET) into a tenant's guest through the
            // proxy, unlike every other guest-reaching route
            // (sandbox_fs_read, sandbox_process, agent_exec, qga_exec,
            // ...), which all gate on Extension<Role> + require_admin.
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "ro".into(),
                    role: Role::ReadOnly,
                    name: None,
                    tenant: None,
                }],
                ..Default::default()
            };
            let m = manager(auth);
            let sandbox = fixture(BackendKind::FluxVm, VmStatus::Running, true);
            let id = sandbox.id;
            m.store.insert(sandbox).await.unwrap();
            let app = router(m);
            assert_eq!(
                request(app, "GET", &format!("/sandbox/{id}/x"), Some("ro"), None).await,
                StatusCode::FORBIDDEN
            );
        }

        #[tokio::test]
        async fn admin_token_can_reach_sandbox_proxy_role_gate() {
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "admin".into(),
                    role: Role::Admin,
                    name: None,
                    tenant: None,
                }],
                ..Default::default()
            };
            let m = manager(auth);
            let sandbox = fixture(BackendKind::FluxVm, VmStatus::Running, true);
            let id = sandbox.id;
            m.store.insert(sandbox).await.unwrap();
            let app = router(m);
            // Clears the role gate -- may still fail downstream (no real
            // netns/guest in this test), but that's a different, later
            // error, never the 403 a read-only token gets above.
            assert_ne!(
                request(app, "GET", &format!("/sandbox/{id}/x"), Some("admin"), None).await,
                StatusCode::FORBIDDEN
            );
        }

        fn pool_fixture(name: &str, tenant: Option<&str>) -> fluxvm_core::model::PoolRecord {
            let mut template = fixture(BackendKind::Qemu, VmStatus::Running, false).request;
            template.tenant = tenant.map(String::from);
            fluxvm_core::model::PoolRecord {
                name: name.into(),
                size: 1,
                template,
                members: vec![],
                claimed_total: 0,
            }
        }

        #[tokio::test]
        async fn list_pools_only_returns_the_callers_own_tenant() {
            // Regression test: list_pools previously had no tenant
            // filtering at all, unlike list_vms/list_sandboxes.
            let m = manager(tenant_tokens());
            m.pools
                .insert(pool_fixture("acme-pool", Some("acme")))
                .await
                .unwrap();
            m.pools
                .insert(pool_fixture("other-pool", Some("other")))
                .await
                .unwrap();
            let app = router(m);
            let req = Request::builder()
                .method("GET")
                .uri("/v1/pools")
                .header(header::AUTHORIZATION, "Bearer acme")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_string(resp).await;
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            let items = parsed["items"].as_array().unwrap();
            assert_eq!(items.len(), 1, "expected exactly one pool in:\n{body}");
            assert_eq!(items[0]["name"], "acme-pool");
        }

        #[tokio::test]
        async fn pool_routes_report_computed_ready_pending_and_claimed_total() {
            // Regression coverage for PoolView: GET /v1/pools and
            // GET /v1/pools/{name} previously returned the raw PoolRecord
            // (`size`/`members` only) -- a caller had no named field for
            // "how many are ready right now" or "how many more are still
            // needed to reach target," and no visibility at all into a
            // pool's lifetime claim history.
            let m = manager(tenant_tokens());
            let mut pool = pool_fixture("acme-pool", Some("acme"));
            pool.size = 5;
            pool.members = vec![Uuid::new_v4(), Uuid::new_v4()];
            pool.claimed_total = 7;
            m.pools.insert(pool).await.unwrap();
            let app = router(m);

            let req = Request::builder()
                .method("GET")
                .uri("/v1/pools/acme-pool")
                .header(header::AUTHORIZATION, "Bearer acme")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_string(resp).await;
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["size"], 5);
            assert_eq!(parsed["ready"], 2);
            assert_eq!(parsed["pending"], 3);
            assert_eq!(parsed["claimed_total"], 7);

            let req = Request::builder()
                .method("GET")
                .uri("/v1/pools")
                .header(header::AUTHORIZATION, "Bearer acme")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let body = body_string(resp).await;
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            let items = parsed["items"].as_array().unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0]["ready"], 2);
            assert_eq!(items[0]["pending"], 3);
            assert_eq!(items[0]["claimed_total"], 7);
        }

        #[tokio::test]
        async fn pool_by_name_routes_are_tenant_scoped() {
            // Regression test: get_pool/delete_pool/claim_pool previously
            // had no tenant check at all -- pools are name-keyed, not
            // UUID-keyed, so tenant_guard_middleware's own generic
            // "/v1/vms/{id}..." extraction never covered them either way.
            let m = manager(tenant_tokens());
            m.pools
                .insert(pool_fixture("acme-pool", Some("acme")))
                .await
                .unwrap();
            let app = router(m);
            assert_eq!(
                status_for(app.clone(), "GET", "/v1/pools/acme-pool", Some("other")).await,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                status_for(app.clone(), "GET", "/v1/pools/acme-pool", Some("acme")).await,
                StatusCode::OK
            );
            assert_eq!(
                request(
                    app,
                    "POST",
                    "/v1/pools/acme-pool/claim",
                    Some("other"),
                    Some("{}"),
                )
                .await,
                StatusCode::NOT_FOUND
            );
        }

        #[tokio::test]
        async fn resize_pool_route_is_tenant_scoped() {
            // Same reasoning as pool_by_name_routes_are_tenant_scoped
            // above -- resize is one more name-keyed pool route that needs
            // its own pool_visible_to check, not tenant_guard_middleware's
            // generic UUID-based one.
            let m = manager(tenant_tokens());
            m.pools
                .insert(pool_fixture("acme-pool", Some("acme")))
                .await
                .unwrap();
            let app = router(m.clone());
            assert_eq!(
                request(
                    app.clone(),
                    "POST",
                    "/v1/pools/acme-pool/resize",
                    Some("other"),
                    Some(r#"{"size":3}"#),
                )
                .await,
                StatusCode::NOT_FOUND
            );
            // Untouched by the rejected cross-tenant attempt.
            assert_eq!(m.get_pool("acme-pool").await.unwrap().size, 1);

            assert_eq!(
                request(
                    app,
                    "POST",
                    "/v1/pools/acme-pool/resize",
                    Some("acme"),
                    Some(r#"{"size":3}"#),
                )
                .await,
                StatusCode::OK
            );
            assert_eq!(m.get_pool("acme-pool").await.unwrap().size, 3);
        }

        #[tokio::test]
        async fn resize_pool_route_requires_admin() {
            let auth = AuthConfig {
                tokens: vec![ApiToken {
                    token: "ro".into(),
                    role: Role::ReadOnly,
                    name: None,
                    tenant: None,
                }],
                ..Default::default()
            };
            let m = manager(auth);
            m.pools.insert(pool_fixture("p", None)).await.unwrap();
            let app = router(m.clone());
            assert_eq!(
                request(
                    app,
                    "POST",
                    "/v1/pools/p/resize",
                    Some("ro"),
                    Some(r#"{"size":3}"#),
                )
                .await,
                StatusCode::FORBIDDEN
            );
            assert_eq!(m.get_pool("p").await.unwrap().size, 1);
        }

        #[tokio::test]
        async fn resize_pool_route_rejects_zero_size() {
            let m = manager(tenant_tokens());
            m.pools
                .insert(pool_fixture("acme-pool", Some("acme")))
                .await
                .unwrap();
            let app = router(m);
            assert_eq!(
                request(
                    app,
                    "POST",
                    "/v1/pools/acme-pool/resize",
                    Some("acme"),
                    Some(r#"{"size":0}"#),
                )
                .await,
                StatusCode::BAD_REQUEST
            );
        }

        const VALID_POOL_BODY: &str = r#"{"name":"p1","size":1,"template":{"name":"t","backend":"qemu","image":"/does/not/exist.qcow2"}}"#;

        #[tokio::test]
        async fn create_pool_forces_the_callers_own_tenant() {
            // Regression test: create_pool previously never forced the
            // caller's own token tenant onto template.tenant the way
            // create_vm already does for a plain VM create -- every
            // member ever backfilled from an untenanted pool would have
            // inherited no tenant at all, making it unreachable via any
            // tenant-scoped route once claimed.
            let m = manager(tenant_tokens());
            let app = router(m.clone());
            assert_eq!(
                request(
                    app,
                    "POST",
                    "/v1/pools",
                    Some("acme"),
                    Some(VALID_POOL_BODY)
                )
                .await,
                StatusCode::CREATED
            );
            let pool = m.get_pool("p1").await.unwrap();
            assert_eq!(pool.template.tenant.as_deref(), Some("acme"));
        }

        #[tokio::test]
        async fn create_pool_rejects_a_template_tenant_mismatch() {
            let m = manager(tenant_tokens());
            let app = router(m);
            let body = r#"{"name":"p2","size":1,"template":{"name":"t","tenant":"other","backend":"qemu","image":"/does/not/exist.qcow2"}}"#;
            assert_eq!(
                request(app, "POST", "/v1/pools", Some("acme"), Some(body)).await,
                StatusCode::FORBIDDEN
            );
        }
    }

    mod console_ws_message_mapping {
        use super::*;
        use axum::extract::ws::Message;
        use fluxvm_guest_protocol::PtyFrame;

        #[test]
        fn binary_message_becomes_a_data_frame() {
            let frame = ws_message_to_pty_frame(&Message::Binary(b"echo hi\n".to_vec().into()));
            assert_eq!(frame, Some(PtyFrame::Data(b"echo hi\n".to_vec())));
        }

        #[test]
        fn valid_resize_text_message_becomes_a_resize_frame() {
            let frame = ws_message_to_pty_frame(&Message::Text(r#"{"cols":120,"rows":40}"#.into()));
            assert_eq!(
                frame,
                Some(PtyFrame::Resize {
                    cols: 120,
                    rows: 40
                })
            );
        }

        #[test]
        fn malformed_text_message_is_dropped_not_forwarded_as_data() {
            // Would previously have been forwarded to the shell as literal
            // keystrokes (`t.as_bytes()`) -- now it's a control channel, so
            // anything that isn't a valid resize message is simply ignored.
            assert_eq!(
                ws_message_to_pty_frame(&Message::Text("not json".into())),
                None
            );
            assert_eq!(
                ws_message_to_pty_frame(&Message::Text(r#"{"cols":120}"#.into())),
                None
            );
        }

        #[test]
        fn ping_pong_messages_are_dropped() {
            assert_eq!(
                ws_message_to_pty_frame(&Message::Ping(Vec::new().into())),
                None
            );
            assert_eq!(
                ws_message_to_pty_frame(&Message::Pong(Vec::new().into())),
                None
            );
        }
    }

    mod sandbox_proxy_body_cap {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        #[tokio::test]
        async fn oversized_guest_response_body_is_rejected_not_fully_buffered() {
            // Regression test for the previously-unbounded response body
            // read in sandbox_proxy_inner: `up.into_body().collect()` had
            // no size cap at all, only the existing 30s timeout -- a
            // compromised/buggy guest could stream an effectively
            // unbounded response for up to 30s per request, a
            // straightforward host-memory-exhaustion primitive from inside
            // any tenant's own sandbox. The full proxy path needs
            // CAP_SYS_ADMIN for connect_in_netns (not available on this
            // project's remote build host either), so this exercises
            // `proxy_over_tcp` -- the send/receive half factored out of
            // `sandbox_proxy_inner` specifically to make this testable --
            // directly against a real loopback TCP listener standing in
            // for the "guest".
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let over_cap = SANDBOX_PROXY_MAX_BODY_BYTES + 4096;
            let guest = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                // Drain the (empty-body GET) request before responding.
                let mut buf = [0u8; 4096];
                loop {
                    let n = sock.read(&mut buf).await.unwrap();
                    if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {over_cap}\r\n\r\n");
                sock.write_all(header.as_bytes()).await.unwrap();
                // A real Content-Length this large, fully written -- proves
                // the cap fires on its own rather than relying on the
                // guest ever running short or the connection erroring out.
                // Errors past this point are expected once the capped
                // client gives up and closes its side; ignored rather than
                // unwrapped so this task always finishes promptly.
                let chunk = vec![0u8; 64 * 1024];
                let mut written = 0usize;
                while written < over_cap {
                    let n = chunk.len().min(over_cap - written);
                    let _ = sock.write_all(&chunk[..n]).await;
                    written += n;
                }
                let _ = sock.shutdown().await;
            });

            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let response = proxy_over_tcp(
                tcp,
                Method::GET,
                "/".to_string(),
                axum::http::HeaderMap::new(),
                bytes::Bytes::new(),
            )
            .await;

            // Without the Limited::new(..., SANDBOX_PROXY_MAX_BODY_BYTES)
            // cap, this would come back 200 OK with the full
            // over-cap-byte body fully buffered (comfortably within the
            // 30s timeout over loopback) -- the point of this test is
            // that it does not.
            assert_ne!(response.status(), StatusCode::OK);

            guest.await.unwrap();
        }
    }
}

// ZYVOR_SERVICE_FABRIC_V6_API
async fn list_network_service_policies(
    State(m): State<Arc<VmManager>>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(
        json!({"items": fluxvm_network::service_policy::list(&m.cfg)?}),
    ))
}

async fn upsert_network_service_policy(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Json(spec): Json<fluxvm_network::service_policy::ServicePolicySpec>,
) -> ApiResult<Json<fluxvm_network::service_policy::ServicePolicyStatus>> {
    require_admin(role)?;
    Ok(Json(fluxvm_network::service_policy::upsert(&m.cfg, spec)?))
}

async fn reconcile_network_service_policies(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(
        json!({"items": fluxvm_network::service_policy::reconcile(&m.cfg)?}),
    ))
}

async fn get_network_service_policy(
    State(m): State<Arc<VmManager>>,
    Path(name): Path<String>,
) -> ApiResult<Json<fluxvm_network::service_policy::ServicePolicySpec>> {
    match fluxvm_network::service_policy::get(&m.cfg, &name)? {
        Some(spec) => Ok(Json(spec)),
        None => Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: format!("service policy '{name}' not found"),
        }),
    }
}

async fn delete_network_service_policy(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(name): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    if !fluxvm_network::service_policy::delete(&m.cfg, &name)? {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: format!("service policy '{name}' not found"),
        });
    }
    Ok(Json(json!({"deleted": name})))
}

async fn network_service_envoy_contract(
    State(m): State<Arc<VmManager>>,
    Path(name): Path<String>,
) -> ApiResult<Json<fluxvm_network::service_policy::EnvoyRedirectContract>> {
    Ok(Json(fluxvm_network::service_policy::envoy_contract(
        &m.cfg, &name,
    )?))
}
