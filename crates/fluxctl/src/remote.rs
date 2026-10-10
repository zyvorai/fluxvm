//! `--server URL` / `FLUXVM_URL`: drive a remote daemon over REST instead of
//! opening the local state directory.

use anyhow::{Context, Result, bail};
use reqwest::Method;
use serde_json::{Value, json};
use uuid::Uuid;

pub struct Remote {
    base: String,
    token: Option<String>,
    http: reqwest::Client,
}

/// `--server`/`--server-token` (or their env vars) read straight from argv,
/// before clap runs, so the VM-name index can come from the server.
pub fn from_argv_env() -> Option<Remote> {
    let args: Vec<String> = std::env::args().collect();
    let flag = |name: &str| {
        args.iter().enumerate().find_map(|(i, a)| {
            a.strip_prefix(&format!("{name}="))
                .map(str::to_string)
                .or_else(|| (a == name).then(|| args.get(i + 1).cloned()).flatten())
        })
    };
    let server = flag("--server").or_else(|| std::env::var("FLUXVM_URL").ok());
    let token = flag("--server-token").or_else(|| std::env::var("FLUXVM_TOKEN").ok());
    let context = flag("--context").or_else(|| std::env::var("FLUXCTL_CONTEXT").ok());
    endpoint(server, token, context.as_deref()).ok().flatten()
}

/// Reserved `--context` value forcing local mode over a current context.
pub const LOCAL_CONTEXT: &str = "local";

/// `--server` wins, then `--context`, then the current context; `None` is local mode.
pub fn endpoint(
    server: Option<String>,
    token: Option<String>,
    context: Option<&str>,
) -> Result<Option<Remote>> {
    if let Some(server) = server {
        return Ok(Some(Remote::new(&server, token)));
    }
    if context == Some(LOCAL_CONTEXT) {
        return Ok(None);
    }
    let Some((name, ep)) = crate::contexts::Contexts::load()?.resolve(context)? else {
        return Ok(None);
    };
    let token = match token {
        Some(t) => Some(t),
        None => ep.resolve_token(&name)?,
    };
    Ok(Some(Remote::new(&ep.server, token)))
}

impl Remote {
    pub fn new(server: &str, token: Option<String>) -> Self {
        let base = if server.starts_with("http://") || server.starts_with("https://") {
            server.trim_end_matches('/').to_string()
        } else {
            format!("http://{}", server.trim_end_matches('/'))
        };
        Self {
            base,
            token: token.filter(|t| !t.is_empty()),
            http: reqwest::Client::new(),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let url = format!("{}{path}", self.base);
        let mut req = self.http.request(method.clone(), &url);
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("{method} {url}"))?;
        let status = resp.status();
        let text = resp.text().await.context("reading response body")?;
        if !status.is_success() {
            let msg = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
                .unwrap_or(text);
            bail!("{method} {path}: {status}: {msg}");
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).with_context(|| format!("decoding {path} response"))
    }

    /// `GET path` returning the status and raw body, for non-JSON routes
    /// (logs, pcap downloads) and callers that handle error statuses.
    pub async fn get_raw(&self, path: &str) -> Result<(reqwest::StatusCode, Vec<u8>)> {
        let url = format!("{}{path}", self.base);
        let mut req = self.http.get(&url);
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        let resp = req.send().await.with_context(|| format!("GET {url}"))?;
        let status = resp.status();
        let body = resp.bytes().await.context("reading response body")?;
        Ok((status, body.to_vec()))
    }

    pub async fn list_vms(&self, selector: Option<&str>) -> Result<Vec<Value>> {
        self.list_vms_all(selector, false).await
    }

    /// [`Self::list_vms`]; `all` includes the container warm pool's waiting VMs.
    pub async fn list_vms_all(&self, selector: Option<&str>, all: bool) -> Result<Vec<Value>> {
        let mut path = match selector {
            Some(s) => format!("/v1/vms?label={}", encode_query(s)),
            None => "/v1/vms".into(),
        };
        if all {
            path.push(if selector.is_some() { '&' } else { '?' });
            path.push_str("all=true");
        }
        let v = self.call(Method::GET, &path, None).await?;
        Ok(v.get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    /// `(id, name)` pairs for resolving VM names and UUID prefixes.
    pub async fn vm_index(&self) -> Vec<(Uuid, String)> {
        self.list_vms(None)
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(|v| {
                let id = v.get("id")?.as_str()?.parse().ok()?;
                let name = v.get("name").and_then(Value::as_str).unwrap_or_default();
                Some((id, name.to_string()))
            })
            .collect()
    }

    pub async fn vm_op(&self, id: Uuid, op: &str) -> Result<Value> {
        match op {
            "delete" => {
                self.call(Method::DELETE, &format!("/v1/vms/{id}"), None)
                    .await?;
                Ok(json!({"id": id, "deleted": true}))
            }
            _ => {
                self.call(Method::POST, &format!("/v1/vms/{id}/{op}"), None)
                    .await
            }
        }
    }
}

impl Remote {
    /// Tail `GET /v1/events/stream` (SSE), calling `on_event` per event until
    /// the server closes the stream.
    pub async fn follow_events(
        &self,
        query: &str,
        mut on_event: impl FnMut(fluxvm_scheduler::events::VmEvent) -> Result<()>,
    ) -> Result<()> {
        let url = format!("{}/v1/events/stream?{query}", self.base);
        let mut req = self.http.get(&url);
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        let mut resp = req.send().await.with_context(|| format!("GET {url}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            bail!(
                "GET {url}: {status}: {}",
                resp.text().await.unwrap_or_default()
            );
        }
        let mut buf = String::new();
        while let Some(chunk) = resp.chunk().await.context("reading event stream")? {
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(end) = buf.find("\n\n") {
                let block: String = buf.drain(..end + 2).collect();
                match parse_sse_block(&block) {
                    Some(SseItem::Event(ev)) => on_event(ev)?,
                    Some(SseItem::Error(e)) => eprintln!("event stream error: {e}"),
                    None => {}
                }
            }
        }
        Ok(())
    }

    /// Websocket to `path` (bearer token in the handshake).
    pub async fn websocket(
        &self,
        path: &str,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    > {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let url = format!(
            "{}{path}",
            self.base
                .replacen("https://", "wss://", 1)
                .replacen("http://", "ws://", 1)
        );
        let mut req = url.as_str().into_client_request()?;
        if let Some(t) = &self.token {
            req.headers_mut()
                .insert("authorization", format!("Bearer {t}").parse()?);
        }
        let (ws, _) = tokio_tungstenite::connect_async(req)
            .await
            .with_context(|| format!("websocket {url}"))?;
        Ok(ws)
    }
}

#[derive(Debug)]
enum SseItem {
    Event(fluxvm_scheduler::events::VmEvent),
    Error(String),
}

fn parse_sse_block(block: &str) -> Option<SseItem> {
    let mut kind = "message";
    let mut data = String::new();
    for line in block.lines() {
        if let Some(v) = line.strip_prefix("event:") {
            kind = v.trim();
        } else if let Some(v) = line.strip_prefix("data:") {
            data.push_str(v.trim_start());
        }
    }
    if data.is_empty() {
        return None;
    }
    if kind == "error" {
        return Some(SseItem::Error(data));
    }
    serde_json::from_str(&data).ok().map(SseItem::Event)
}

pub fn encode_query(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_and_query_encoding() {
        assert_eq!(
            Remote::new("10.0.0.1:7788", None).base,
            "http://10.0.0.1:7788"
        );
        assert_eq!(
            Remote::new("https://h.example/", Some(String::new())).base,
            "https://h.example"
        );
        assert!(Remote::new("h", Some(String::new())).token.is_none());
        assert_eq!(encode_query("env=dev,!tmp"), "env%3Ddev%2C%21tmp");
    }

    #[test]
    fn sse_blocks() {
        assert!(parse_sse_block(": fluxvm events\n\n").is_none());
        let ev = parse_sse_block(
            "event: vm.start\ndata: {\"ts\":\"2026-09-27T00:00:00Z\",\"event\":\"vm.start\"}\n\n",
        );
        assert!(matches!(ev, Some(SseItem::Event(e)) if e.event == "vm.start"));
        assert!(matches!(
            parse_sse_block("event: error\ndata: {\"error\":\"x\"}\n\n"),
            Some(SseItem::Error(_))
        ));
    }
}
