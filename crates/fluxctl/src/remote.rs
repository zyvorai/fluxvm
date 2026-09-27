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
    let server = flag("--server").or_else(|| std::env::var("FLUXVM_URL").ok())?;
    let token = flag("--server-token").or_else(|| std::env::var("FLUXVM_TOKEN").ok());
    Some(Remote::new(&server, token))
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

    pub async fn list_vms(&self, selector: Option<&str>) -> Result<Vec<Value>> {
        let path = match selector {
            Some(s) => format!("/v1/vms?label={}", encode_query(s)),
            None => "/v1/vms".into(),
        };
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

fn encode_query(s: &str) -> String {
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
}
