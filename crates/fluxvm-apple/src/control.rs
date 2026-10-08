// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::{path::Path, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

/// One reply line from the runner's control socket.
#[derive(Debug, Clone)]
pub struct ControlReply(pub serde_json::Value);

impl ControlReply {
    pub fn ok(&self) -> bool {
        self.0.get("ok").and_then(|v| v.as_bool()).unwrap_or(false)
    }
    pub fn state(&self) -> Option<&str> {
        self.0.get("state").and_then(|v| v.as_str())
    }
    pub fn ip(&self) -> Option<&str> {
        self.0.get("ip").and_then(|v| v.as_str())
    }
    pub fn error(&self) -> Option<&str> {
        self.0.get("error").and_then(|v| v.as_str())
    }
}

/// Sends `{"cmd": cmd}` and reads the one-line JSON reply.
pub async fn call(socket: &Path, cmd: &str) -> Result<ControlReply> {
    tokio::time::timeout(Duration::from_secs(35), async {
        let mut s = UnixStream::connect(socket).await.with_context(|| format!("connecting to {}", socket.display()))?;
        s.write_all(format!("{{\"cmd\":\"{cmd}\"}}\n").as_bytes()).await?;
        let mut line = String::new();
        BufReader::new(s).read_line(&mut line).await?;
        Ok(ControlReply(serde_json::from_str(line.trim()).context("the runner sent an invalid reply")?))
    })
    .await
    .context("the runner did not answer in time")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_a_json_line() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("c.sock");
        let l = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut r = BufReader::new(s);
            let mut line = String::new();
            r.read_line(&mut line).await.unwrap();
            assert!(line.contains("\"cmd\":\"status\""));
            r.into_inner().write_all(b"{\"ok\":true,\"state\":\"running\",\"ip\":\"192.168.64.5\"}\n").await.unwrap();
        });
        let reply = call(&sock, "status").await.unwrap();
        assert!(reply.ok());
        assert_eq!(reply.state(), Some("running"));
        assert_eq!(reply.ip(), Some("192.168.64.5"));
    }

    #[tokio::test]
    async fn missing_socket_is_an_error_not_a_hang() {
        assert!(call(Path::new("/nonexistent/c.sock"), "ping").await.is_err());
    }
}
