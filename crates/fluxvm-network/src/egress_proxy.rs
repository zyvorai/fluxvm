// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Live L7 egress proxy: allowlist + credential injection for FluxVm sandboxes.

use crate::egress::{EgressDecision, decide};
use crate::http_acl::{self, HttpAcl, Verdict};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode, Uri, header},
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
    acl: HttpAcl,
}

/// Bind an HTTP forward proxy that enforces `sandbox.egress_allow_domains`
/// and `sandbox.egress_http_rules`, and injects `sandbox.credential_vault`
/// Authorization headers.
pub async fn serve(listen: SocketAddr, cfg: SandboxConfig) -> anyhow::Result<()> {
    // A malformed rule must stop startup: silently dropping a `deny` fails open.
    let acl = HttpAcl::parse(&cfg.egress_http_rules).map_err(|e| anyhow::anyhow!(e))?;
    let state = ProxyState {
        cfg,
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        acl,
    };
    let app = Router::new()
        .fallback(any(proxy))
        .with_state(Arc::new(state));
    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!(%listen, "FluxVM egress proxy listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// What the proxy decided about one request, before any upstream I/O.
#[derive(Debug)]
struct Vetted {
    decision: EgressDecision,
    /// Upstream URL rebuilt from the vetted host and normalized path. Set
    /// only when HTTP rules are active, so the request that is sent is
    /// exactly the request that was judged.
    rebuilt_url: Option<String>,
}

fn deny(reason: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, reason.into())
}

/// Judge a request: host allowlist, HTTP rules, credential lookup.
fn vet_request(
    cfg: &SandboxConfig,
    acl: &HttpAcl,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<Vetted, (StatusCode, String)> {
    let filtering = acl.is_active() || !cfg.egress_allow_domains.is_empty();
    let header_host = headers.get(header::HOST).and_then(|v| v.to_str().ok());

    // Legacy behaviour when nothing is filtered: the Host header, port stripped.
    let mut host = header_host
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();

    if filtering {
        // Ambiguity between what is judged and what is contacted is the way
        // around any host or path filter, so refuse it outright.
        if headers.get_all(header::HOST).iter().count() > 1 {
            return Err(deny("multiple Host headers"));
        }
        host = http_acl::effective_host(uri.host(), header_host).map_err(deny)?;
    }

    let decision = decide(cfg, &host);
    if !decision.allow {
        return Err(deny(decision.reason));
    }

    if !acl.is_active() {
        return Ok(Vetted {
            decision,
            rebuilt_url: None,
        });
    }

    if method == Method::CONNECT {
        return match acl.check_connect(&host) {
            Verdict::Allow => Err((
                StatusCode::NOT_IMPLEMENTED,
                "CONNECT tunnelling is not supported by the egress proxy".into(),
            )),
            Verdict::Deny(reason) => Err(deny(reason)),
        };
    }

    if let Verdict::Deny(reason) = acl.check(method.as_str(), &host, uri.path()) {
        return Err(deny(reason));
    }

    // Send the normalized path: the upstream must not interpret it any
    // differently from the rule engine.
    let path = http_acl::normalize_path(uri.path()).map_err(deny)?;
    let netloc = match uri.host() {
        Some(h) => match uri.port_u16() {
            Some(p) => format!("{h}:{p}"),
            None => h.to_string(),
        },
        None => header_host.unwrap_or_default().trim().to_string(),
    };
    let scheme = uri.scheme_str().unwrap_or("http");
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    Ok(Vetted {
        decision,
        rebuilt_url: Some(format!("{scheme}://{netloc}{path}{query}")),
    })
}

async fn proxy(State(state): State<Arc<ProxyState>>, req: Request<Body>) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let vetted = match vet_request(&state.cfg, &state.acl, &method, &uri, req.headers()) {
        Ok(v) => v,
        Err((status, reason)) => {
            if status == StatusCode::FORBIDDEN {
                fluxvm_core::metrics::inc_egress_deny();
                warn!(%method, %uri, %reason, "egress denied");
            }
            return (status, reason).into_response();
        }
    };
    let decision = vetted.decision;
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // Absolute-form URI for forward proxy, or reconstruct from Host.
    let url = if let Some(u) = vetted.rebuilt_url {
        u
    } else if uri.scheme().is_some() {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(rules: &[&str], domains: &[&str]) -> (SandboxConfig, HttpAcl) {
        let cfg = SandboxConfig {
            egress_allow_domains: domains.iter().map(|s| s.to_string()).collect(),
            egress_http_rules: rules.iter().map(|s| s.to_string()).collect(),
            ..SandboxConfig::default()
        };
        let acl = HttpAcl::parse(&cfg.egress_http_rules).unwrap();
        (cfg, acl)
    }

    fn headers(hosts: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for host in hosts {
            h.append(header::HOST, host.parse().unwrap());
        }
        h
    }

    fn vet(
        c: &(SandboxConfig, HttpAcl),
        method: &str,
        uri: &str,
        hosts: &[&str],
    ) -> Result<Vetted, (StatusCode, String)> {
        vet_request(
            &c.0,
            &c.1,
            &method.parse().unwrap(),
            &uri.parse().unwrap(),
            &headers(hosts),
        )
    }

    #[test]
    fn no_rules_keeps_legacy_behaviour() {
        let c = cfg(&[], &[]);
        let v = vet(&c, "GET", "/anything", &["whatever.example:8080"]).unwrap();
        assert!(v.rebuilt_url.is_none());
        // Legacy: even a mismatched absolute URI is not judged when nothing is filtered.
        assert!(vet(&c, "GET", "http://a.example/x", &["b.example"]).is_ok());
    }

    #[test]
    fn rules_allow_and_deny_by_method_host_path() {
        let c = cfg(
            &[
                "allow GET docs.python.org/*",
                "allow POST api.openai.com/v1/chat/completions",
                "deny * */admin/*",
            ],
            &[],
        );
        assert!(vet(&c, "GET", "/3/library/os.html", &["docs.python.org"]).is_ok());
        assert!(vet(&c, "POST", "/v1/chat/completions", &["api.openai.com"]).is_ok());
        for (m, u, h) in [
            ("POST", "/3/", "docs.python.org"),
            ("GET", "/v1/chat/completions", "api.openai.com"),
            ("GET", "/x", "evil.example"),
            ("GET", "/admin/x", "docs.python.org"),
            ("GET", "/a/../admin/x", "docs.python.org"),
            ("GET", "/%61dmin/x", "docs.python.org"),
            ("GET", "//admin/x", "docs.python.org"),
        ] {
            let e = vet(&c, m, u, &[h]).unwrap_err();
            assert_eq!(e.0, StatusCode::FORBIDDEN, "{m} {u} {h}");
        }
    }

    #[test]
    fn host_and_uri_authority_must_agree() {
        let c = cfg(&["allow GET good.example/*"], &[]);
        let e = vet(&c, "GET", "http://evil.example/x", &["good.example"]).unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        assert!(vet(&c, "GET", "http://good.example/x", &["good.example"]).is_ok());
        assert!(
            vet(
                &c,
                "GET",
                "http://good.example:8080/x",
                &["good.example:8080"]
            )
            .is_ok()
        );
    }

    #[test]
    fn host_mismatch_is_also_refused_for_the_plain_domain_allowlist() {
        // Previously the allowlist judged the Host header while the request
        // went to the absolute-form authority.
        let c = cfg(&[], &["good.example"]);
        let e = vet(&c, "GET", "http://evil.example/x", &["good.example"]).unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn duplicate_host_headers_are_refused() {
        let c = cfg(&["allow GET good.example/*"], &[]);
        let e = vet(&c, "GET", "/x", &["good.example", "evil.example"]).unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn forwarded_url_uses_the_normalized_path_and_keeps_port_and_query() {
        let c = cfg(&["allow GET good.example/*"], &[]);
        let v = vet(&c, "GET", "/a/./b//c?x=1&y=/../z", &["good.example:8080"]).unwrap();
        assert_eq!(
            v.rebuilt_url.as_deref(),
            Some("http://good.example:8080/a/b/c?x=1&y=/../z")
        );
        let v = vet(
            &c,
            "GET",
            "http://good.example:9/%61/x",
            &["good.example:9"],
        )
        .unwrap();
        assert_eq!(v.rebuilt_url.as_deref(), Some("http://good.example:9/a/x"));
    }

    #[test]
    fn connect_is_refused_or_unsupported_never_forwarded() {
        let c = cfg(&["allow GET docs.python.org/*"], &[]);
        let e = vet(
            &c,
            "CONNECT",
            "docs.python.org:443",
            &["docs.python.org:443"],
        )
        .unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
        let c = cfg(&["allow * api.example.com"], &[]);
        let e = vet(
            &c,
            "CONNECT",
            "api.example.com:443",
            &["api.example.com:443"],
        )
        .unwrap_err();
        assert_eq!(e.0, StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn credentials_are_looked_up_on_the_vetted_host() {
        let mut c = cfg(&["allow * vault.example/*"], &[]);
        c.0.credential_vault
            .push(fluxvm_core::config::CredentialInject {
                host: "vault.example".into(),
                authorization: "Bearer t".into(),
            });
        let v = vet(&c, "GET", "/x", &["VAULT.example:443"]).unwrap();
        assert_eq!(v.decision.inject_authorization.as_deref(), Some("Bearer t"));
    }

    #[test]
    fn options_star_is_denied_when_rules_are_active() {
        let c = cfg(&["allow * good.example/*"], &[]);
        let e = vet(&c, "OPTIONS", "*", &["good.example"]).unwrap_err();
        assert_eq!(e.0, StatusCode::FORBIDDEN);
    }
}
