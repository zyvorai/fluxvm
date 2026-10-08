// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Credential broker routes: `POST/GET/DELETE /v1/sandboxes/{id}/grants`.
//! Responses carry [`GrantInfo`] only, which has no secret field.

use super::{ApiError, ApiResult, require_admin};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use fluxvm_core::{config::Role, grants::GrantRequest};
use fluxvm_scheduler::VmManager;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Grants hold credentials: admin only, for every verb (a read-only token must
/// not even learn which secrets a sandbox may use).
pub(super) async fn create_grant(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(req): Json<GrantRequest>,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    require_admin(role)?;
    let info = m.add_grant(id, req).await?;
    Ok((StatusCode::CREATED, Json(json!(info))))
}

pub(super) async fn list_grants(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    Ok(Json(json!({ "grants": m.list_grants(id).await? })))
}

/// `DELETE /v1/sandboxes/{id}/grants`: revoke every grant of the sandbox.
pub(super) async fn delete_grants(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    let revoked = m.revoke_grant(id, None).await?;
    Ok(Json(json!({ "revoked": revoked })))
}

/// `DELETE /v1/sandboxes/{id}/grants/{grant_id}`: revoke one grant.
pub(super) async fn delete_grant(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path((id, grant_id)): Path<(Uuid, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    require_admin(role)?;
    if !m.revoke_grant(id, Some(&grant_id)).await? {
        return Err(ApiError {
            status: StatusCode::NOT_FOUND,
            message: format!("grant {grant_id} not found"),
        });
    }
    Ok(Json(json!({ "revoked": true })))
}
