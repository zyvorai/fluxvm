// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Live L7 egress proxy: allowlist + credential injection for FluxVm sandboxes.

use crate::egress::{EgressDecision, decide};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use fluxvm_core::config::SandboxConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Clone)]
struct ProxyState {
    cfg: SandboxConfig,
    client: reqwest::Client,
}

/// Bind an HTTP forward proxy that enforces `sandbox.egress_allow_domains`
/// and injects `sandbox.credential_vault` Authorization headers.
pub async fn serve(listen: SocketAddr, cfg: SandboxConfig) -> anyhow::Result<()> {
    let state = ProxyState {
        cfg,
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
    };
    let app = Router::new()
        .fallback(any(proxy))
        .with_state(Arc::new(state));
    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!(%listen, "FluxVM egress proxy listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn proxy(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();

    let decision: EgressDecision = decide(&state.cfg, &host);
    if !decision.allow {
        fluxvm_core::metrics::inc_egress_deny();
        warn!(%host, reason = %decision.reason, "egress denied");
        return (StatusCode::FORBIDDEN, decision.reason).into_response();
    }

    let method = req.method().clone();
    let uri = req.uri().clone();
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // Absolute-form URI for forward proxy, or reconstruct from Host.
    let url = if uri.scheme().is_some() {
        uri.to_string()
    } else {
        format!("http://{host}{path_and_query}")
    };

    let mut builder = state.client.request(method, &url);
    for (name, value) in req.headers().iter() {
        if name == header::HOST || name == header::AUTHORIZATION {
            continue;
        }
        builder = builder.header(name, value);
    }
    if let Some(auth) = &decision.inject_authorization {
        builder = builder.header(header::AUTHORIZATION, auth);
    }

    let body = req.into_body();
    let bytes = match axum::body::to_bytes(body, 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("body: {e}")).into_response(),
    };
    builder = builder.body(bytes);

    match builder.send().await {
        Ok(upstream) => {
            let status =
                StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut response = Response::builder().status(status);
            for (k, v) in upstream.headers().iter() {
                response = response.header(k, v);
            }
            let body = upstream.bytes().await.unwrap_or_default();
            response
                .body(Body::from(body))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e) => {
            warn!(error = %e, %url, "egress upstream failed");
            (StatusCode::BAD_GATEWAY, format!("upstream: {e}")).into_response()
        }
    }
}
