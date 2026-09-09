// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Container lifecycle protocol spoken between `containerd-shim-fluxvm-v2`
//! on the host and `fluxvm-container-agent` inside a FluxVM guest.
//!
//! The protocol is newline-delimited JSON over AF_VSOCK. Requests carry the
//! same per-VM shared secret used by the existing FluxVM guest agent, but are
//! served on a separate port so the stable guest-agent API remains unchanged.

use serde::{Deserialize, Serialize};

pub const DEFAULT_CONTAINER_AGENT_PORT: u32 = 17778;
pub const DEFAULT_CALL_TIMEOUT_SECS: u64 = 30;
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerStatus {
    Created,
    Running,
    Paused,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContainerIo {
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default)]
    pub stdout: Option<String>,
    #[serde(default)]
    pub stderr: Option<String>,
    #[serde(default)]
    pub terminal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum ContainerRequest {
    Ping,
    Create {
        id: String,
        /// Complete OCI runtime config after host paths have been translated
        /// into paths visible from inside the guest.
        config_json: String,
        io: ContainerIo,
    },
    Start { id: String, #[serde(default)] exec_id: Option<String> },
    State { id: String, #[serde(default)] exec_id: Option<String> },
    Exec {
        id: String,
        exec_id: String,
        /// OCI Process JSON (not a full config.json).
        process_json: String,
        io: ContainerIo,
    },
    Kill {
        id: String,
        #[serde(default)]
        exec_id: Option<String>,
        signal: i32,
        #[serde(default)]
        all: bool,
    },
    Pause { id: String },
    Resume { id: String },
    Wait { id: String, #[serde(default)] exec_id: Option<String> },
    Delete {
        id: String,
        #[serde(default)]
        exec_id: Option<String>,
        #[serde(default)]
        force: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEnvelope {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(flatten)]
    pub request: ContainerRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum ContainerResponse {
    Pong,
    Created { pid: u32 },
    Started { pid: u32 },
    ExecStarted { pid: u32 },
    State {
        id: String,
        #[serde(default)]
        exec_id: Option<String>,
        status: ContainerStatus,
        pid: u32,
        #[serde(default)]
        exit_code: Option<i32>,
        #[serde(default)]
        exited_at_unix_nano: Option<i128>,
    },
    Exited {
        exit_code: i32,
        exited_at_unix_nano: i128,
    },
    Killed,
    Paused,
    Resumed,
    Deleted,
    Error { message: String },
}

pub fn encode_line<T: Serialize>(value: &T) -> serde_json::Result<String> {
    let mut out = serde_json::to_string(value)?;
    out.push('\n');
    Ok(out)
}

pub fn decode_line<T: for<'de> Deserialize<'de>>(line: &str) -> serde_json::Result<T> {
    serde_json::from_str(line.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_round_trip() {
        let req = ContainerEnvelope {
            token: Some("secret".into()),
            request: ContainerRequest::Create {
                id: "c1".into(),
                config_json: "{\"ociVersion\":\"1.1.0\"}".into(),
                io: ContainerIo {
                    stdin: None,
                    stdout: Some("/run/fluxvm/pod/io/c1.out".into()),
                    stderr: Some("/run/fluxvm/pod/io/c1.err".into()),
                    terminal: false,
                },
            },
        };
        let line = encode_line(&req).unwrap();
        let back: ContainerEnvelope = decode_line(&line).unwrap();
        assert_eq!(back.token.as_deref(), Some("secret"));
        assert!(matches!(back.request, ContainerRequest::Create { .. }));
    }

    #[test]
    fn state_response_round_trip() {
        let resp = ContainerResponse::State {
            id: "c1".into(),
            exec_id: None,
            status: ContainerStatus::Running,
            pid: 42,
            exit_code: None,
            exited_at_unix_nano: None,
        };
        let line = encode_line(&resp).unwrap();
        let back: ContainerResponse = decode_line(&line).unwrap();
        assert!(matches!(back, ContainerResponse::State { pid: 42, .. }));
    }
}
