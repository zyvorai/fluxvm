// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `Idempotency-Key` support for the mutating VM routes:
//! `POST /v1/vms`, `DELETE /v1/vms/{id}`, `POST /v1/vms/{id}/snapshot` and
//! `POST /v1/vms/{id}/fork`.
//!
//! A request that carries the header is keyed by (tenant or caller, method +
//! path, key). The first successful response is persisted (fsynced, under
//! `<state_dir>/idempotency`, see `fluxvm_scheduler::idempotency`) before it
//! is returned; a retry with the same key and the same request gets that
//! response back with `Idempotent-Replayed: true` instead of running again.
//! The same key with a different method, path or body is rejected with 422;
//! the same key while the first request is still running is rejected with
//! 409. Only 2xx responses are stored, so a failed attempt can be retried
//! under the same key. Records expire after 24 hours.
//!
//! Requests without the header behave exactly as before.

use super::{AuditActor, TokenTenant};
use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use fluxvm_scheduler::{VmManager, idempotency as store};
use serde_json::json;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};
use uuid::Uuid;

pub(crate) const HEADER: &str = "idempotency-key";
const MAX_KEY_LEN: usize = 255;
const MAX_REQUEST_BODY: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_BODY: usize = 8 * 1024 * 1024;

/// The routes that honor the header.
pub(crate) fn is_idempotent_route(method: &Method, path: &str) -> bool {
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    match (method.as_str(), segs.as_slice()) {
        ("POST", ["v1", "vms"]) => true,
        ("DELETE", ["v1", "vms", id]) => Uuid::parse_str(id).is_ok(),
        ("POST", ["v1", "vms", id, "snapshot" | "fork"]) => Uuid::parse_str(id).is_ok(),
        _ => false,
    }
}

/// 1..=255 visible ASCII characters.
pub(crate) fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= MAX_KEY_LEN && key.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

static IN_FLIGHT: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// Held while the first request for a key runs; a concurrent duplicate is
/// refused rather than executed twice.
struct InFlight(String);

impl InFlight {
    fn acquire(hash: &str) -> Option<Self> {
        let set = IN_FLIGHT.get_or_init(|| Mutex::new(HashSet::new()));
        let mut set = set.lock().unwrap_or_else(|p| p.into_inner());
        set.insert(hash.to_string()).then(|| Self(hash.to_string()))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if let Some(set) = IN_FLIGHT.get() {
            set.lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.0);
        }
    }
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

fn replay(stored: &store::Stored) -> Response {
    let mut resp = Response::new(Body::from(stored.body()));
    *resp.status_mut() = StatusCode::from_u16(stored.status).unwrap_or(StatusCode::OK);
    if let Some(ct) = stored
        .content_type
        .as_deref()
        .and_then(|c| HeaderValue::from_str(c).ok())
    {
        resp.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    resp.headers_mut()
        .insert("idempotent-replayed", HeaderValue::from_static("true"));
    resp
}

pub(crate) async fn middleware(
    State(m): State<Arc<VmManager>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let Some(raw_key) = req.headers().get(HEADER).cloned() else {
        return next.run(req).await;
    };
    if !is_idempotent_route(&method, &path) {
        return next.run(req).await;
    }
    let key = match raw_key.to_str() {
        Ok(k) if valid_key(k) => k.to_string(),
        _ => {
            return error(
                StatusCode::BAD_REQUEST,
                "Idempotency-Key must be 1-255 visible ASCII characters",
            );
        }
    };
    let scope = req
        .extensions()
        .get::<TokenTenant>()
        .map(|t| format!("tenant:{}", t.0))
        .or_else(|| {
            req.extensions()
                .get::<AuditActor>()
                .map(|a| format!("actor:{}", a.0))
        })
        .unwrap_or_else(|| "anonymous".to_string());
    let hash = store::key_hash(&scope, &format!("{method} {path}"), &key);

    let (parts, body) = req.into_parts();
    let body = match to_bytes(body, MAX_REQUEST_BODY).await {
        Ok(b) => b,
        Err(_) => return error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"),
    };
    let fingerprint = store::fingerprint(method.as_str(), &path, &body);
    let state_dir = m.cfg.state_dir.clone();

    match store::lookup(&state_dir, &hash, &fingerprint, now_secs()) {
        store::Lookup::Replay(stored) => return replay(&stored),
        store::Lookup::Conflict => {
            return error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Idempotency-Key was already used with a different request",
            );
        }
        store::Lookup::Miss => {}
    }
    let Some(_in_flight) = InFlight::acquire(&hash) else {
        return error(
            StatusCode::CONFLICT,
            "a request with this Idempotency-Key is still in progress",
        );
    };

    let resp = next.run(Request::from_parts(parts, Body::from(body))).await;
    if !resp.status().is_success() {
        return resp;
    }
    let (resp_parts, resp_body) = resp.into_parts();
    let resp_bytes = match to_bytes(resp_body, MAX_RESPONSE_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response too large to record for idempotent replay",
            );
        }
    };
    let content_type = resp_parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let stored = store::Stored::new(
        now_secs(),
        fingerprint,
        resp_parts.status.as_u16(),
        content_type,
        &resp_bytes,
    );
    // Durable before the caller sees the response: if this process dies right
    // after, the retry replays instead of repeating the mutation.
    let written = tokio::task::spawn_blocking(move || store::store(&state_dir, &hash, &stored))
        .await
        .map_err(anyhow::Error::from)
        .and_then(|r| r);
    if let Err(e) = written {
        tracing::warn!(error = %e, "could not persist idempotent response; a retry will re-run the request");
    }
    Response::from_parts(resp_parts, Body::from(resp_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_four_mutating_routes_qualify() {
        let id = Uuid::new_v4();
        let yes = [
            (Method::POST, "/v1/vms".to_string()),
            (Method::POST, "/v1/vms/".to_string()),
            (Method::DELETE, format!("/v1/vms/{id}")),
            (Method::POST, format!("/v1/vms/{id}/snapshot")),
            (Method::POST, format!("/v1/vms/{id}/fork")),
        ];
        for (m, p) in &yes {
            assert!(is_idempotent_route(m, p), "{m} {p}");
        }
        let no = [
            (Method::GET, "/v1/vms".to_string()),
            (Method::GET, format!("/v1/vms/{id}")),
            (Method::DELETE, "/v1/vms".to_string()),
            (Method::DELETE, "/v1/vms/not-a-uuid".to_string()),
            (Method::POST, format!("/v1/vms/{id}")),
            (Method::POST, format!("/v1/vms/{id}/stop")),
            (Method::DELETE, format!("/v1/vms/{id}/snapshot")),
            (Method::POST, "/v1/vmsx".to_string()),
            (Method::POST, "/v1/sandboxes".to_string()),
        ];
        for (m, p) in &no {
            assert!(!is_idempotent_route(m, p), "{m} {p}");
        }
    }

    #[test]
    fn key_must_be_short_visible_ascii() {
        assert!(valid_key("a1b2-c3_d4"));
        assert!(valid_key(&"k".repeat(255)));
        assert!(!valid_key(""));
        assert!(!valid_key(&"k".repeat(256)));
        assert!(!valid_key("has space"));
        assert!(!valid_key("tab\t"));
        assert!(!valid_key("caf\u{e9}"));
    }

    #[test]
    fn a_key_cannot_run_twice_at_once() {
        let first = InFlight::acquire("h-test-1").expect("first acquire");
        assert!(InFlight::acquire("h-test-1").is_none());
        assert!(InFlight::acquire("h-test-2").is_some());
        drop(first);
        assert!(InFlight::acquire("h-test-1").is_some());
    }

    #[test]
    fn replay_restores_status_type_and_marks_itself() {
        let stored = store::Stored::new(
            1,
            "fp".into(),
            201,
            Some("application/json".into()),
            b"{\"id\":1}",
        );
        let resp = replay(&stored);
        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(resp.headers()["content-type"], "application/json");
        assert_eq!(resp.headers()["idempotent-replayed"], "true");
    }
}
