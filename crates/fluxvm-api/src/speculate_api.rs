// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! REST routes for speculative execution (changesets) and memory density
//! (balloon, PSS). Merged into the main router by `router()`.
//!
//! * `POST /v1/sandboxes/{id}/speculate`
//! * `GET  /v1/sandboxes/{id}/changesets`
//! * `GET  /v1/sandboxes/{id}/changesets/{cs}`
//! * `POST /v1/sandboxes/{id}/changesets/{cs}/{approve|reject|apply}`
//! * `GET|POST /v1/vms/{id}/balloon`
//! * `GET  /v1/vms/{id}/memory`

use super::{ApiError, ApiResult, change_error, require_admin};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use fluxvm_core::config::Role;
use fluxvm_scheduler::VmManager;
use fluxvm_scheduler::speculate::{ChangesetError, ChangesetState};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) fn routes() -> Router<Arc<VmManager>> {
    Router::new()
        .route("/v1/sandboxes/{id}/speculate", post(speculate))
        .route("/v1/sandboxes/{id}/changesets", get(list_changesets))
        .route("/v1/sandboxes/{id}/changesets/{cs}", get(get_changeset))
        .route("/v1/sandboxes/{id}/changesets/{cs}/approve", post(approve))
        .route("/v1/sandboxes/{id}/changesets/{cs}/reject", post(reject))
        .route("/v1/sandboxes/{id}/changesets/{cs}/apply", post(apply))
        .route(
            "/v1/vms/{id}/balloon",
            get(balloon_status).post(balloon_set),
        )
        .route("/v1/vms/{id}/memory", get(memory_report))
}

/// Typed changeset failures get precise statuses; everything else falls back
/// to the change-set / procbox mapping.
fn changeset_error(e: anyhow::Error) -> ApiError {
    let status = match e.downcast_ref::<ChangesetError>() {
        Some(ChangesetError::NotFound(_)) => StatusCode::NOT_FOUND,
        Some(
            ChangesetError::InvalidTransition { .. }
            | ChangesetError::Conflict(_)
            | ChangesetError::Expired(_)
            | ChangesetError::Busy(_),
        ) => StatusCode::CONFLICT,
        Some(ChangesetError::NotApplicable(_)) => StatusCode::UNPROCESSABLE_ENTITY,
        None => return change_error(e),
    };
    ApiError {
        status,
        message: format!("{e:#}"),
    }
}

#[derive(Deserialize)]
struct SpeculateBody {
    command: String,
    #[serde(default)]
    timeout_seconds: Option<u64>,
    #[serde(default)]
    paths: Option<Vec<String>>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

/// Run a command in an isolated copy and return the pending changeset.
async fn speculate(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(body): Json<SpeculateBody>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    m.ensure_running_for_request(id).await?;
    let cs = m
        .speculate(
            id,
            body.command,
            body.timeout_seconds,
            body.paths,
            body.ttl_seconds,
        )
        .await
        .map_err(changeset_error)?;
    Ok(Json(json!(cs)))
}

async fn list_changesets(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let items = m.changeset_list(id).await.map_err(changeset_error)?;
    Ok(Json(json!({ "items": items })))
}

async fn get_changeset(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path((id, cs)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let cs = m.changeset_get(id, cs).await.map_err(changeset_error)?;
    Ok(Json(json!(cs)))
}

async fn approve(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path((id, cs)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let cs = m
        .changeset_decide(id, cs, ChangesetState::Approved)
        .await
        .map_err(changeset_error)?;
    Ok(Json(json!(cs)))
}

async fn reject(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path((id, cs)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let cs = m
        .changeset_decide(id, cs, ChangesetState::Rejected)
        .await
        .map_err(changeset_error)?;
    Ok(Json(json!(cs)))
}

async fn apply(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path((id, cs)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let cs = m.changeset_apply(id, cs).await.map_err(changeset_error)?;
    Ok(Json(json!(cs)))
}

#[derive(Deserialize)]
struct BalloonBody {
    /// Memory to take from the guest, in MiB; 0 deflates the balloon.
    balloon_mib: u64,
}

async fn balloon_status(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let status = m.balloon_control(id, None).await?;
    Ok(Json(json!(status)))
}

async fn balloon_set(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(body): Json<BalloonBody>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let status = m.balloon_control(id, Some(body.balloon_mib)).await?;
    Ok(Json(json!(status)))
}

async fn memory_report(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(json!(m.vm_memory_report(id).await?)))
}
