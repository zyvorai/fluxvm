// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! REST routes for `vz` backend state the runner serves but that had no HTTP surface. Merged into the main router by
//! `router()`.
//!
//! * `GET  /v1/host/apple`
//! * `GET  /v1/vms/{id}/vz/secure-boot`
//! * `GET  /v1/vms/{id}/vz/custom-virtio`
//! * `POST /v1/vms/{id}/vz/custom-virtio/reset`
//! * `GET  /v1/vms/{id}/vz/usb`
//! * `GET|POST /v1/vms/{id}/vz/usb/physical`

use super::{ApiError, ApiResult, require_admin};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use fluxvm_core::config::Role;
use fluxvm_scheduler::VmManager;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) fn routes() -> Router<Arc<VmManager>> {
    Router::new()
        .route("/v1/host/apple", get(host_apple))
        .route("/v1/vms/{id}/vz/secure-boot", get(secure_boot))
        .route("/v1/vms/{id}/vz/custom-virtio", get(custom_virtio))
        .route(
            "/v1/vms/{id}/vz/custom-virtio/reset",
            post(custom_virtio_reset),
        )
        .route("/v1/vms/{id}/vz/usb", get(usb_list))
        .route(
            "/v1/vms/{id}/vz/usb/physical",
            get(usb_physical_list).post(usb_physical_attach),
        )
}

async fn host_apple() -> ApiResult<Json<Value>> {
    let caps = fluxvm_scheduler::vz_devices::apple_host_capabilities()
        .await
        .map_err(|e| ApiError {
            status: StatusCode::NOT_IMPLEMENTED,
            message: format!("{e:#}"),
        })?;
    Ok(Json(caps))
}

async fn secure_boot(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    Ok(Json(m.vz_secure_boot_status(id).await?))
}

async fn custom_virtio(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    Ok(Json(m.vz_custom_virtio_status(id).await?))
}

async fn custom_virtio_reset(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    require_admin(role)?;
    m.vz_custom_virtio_reset(id).await?;
    Ok(Json(json!({"ok": true})))
}

async fn usb_list(State(m): State<Arc<VmManager>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({"items": m.vz_usb_list(id).await?})))
}

async fn usb_physical_list(
    State(m): State<Arc<VmManager>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    Ok(Json(json!({"items": m.vz_usb_physical_list(id).await?})))
}

#[derive(Deserialize)]
struct PhysicalAttach {
    registry_id: u64,
}

async fn usb_physical_attach(
    State(m): State<Arc<VmManager>>,
    Extension(role): Extension<Role>,
    Path(id): Path<Uuid>,
    Json(body): Json<PhysicalAttach>,
) -> ApiResult<Json<Value>> {
    require_admin(role)?;
    let uuid = m.vz_usb_physical_attach(id, body.registry_id).await?;
    Ok(Json(json!({"uuid": uuid})))
}
