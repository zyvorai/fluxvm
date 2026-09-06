// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ApiRequest {
    Boot(BootConfig),
    Pause,
    Resume,
    Shutdown,
    SnapshotSave { path: PathBuf },
    SnapshotRestore { path: PathBuf },
    Metrics,
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootConfig {
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    #[serde(default)]
    pub initrd: Option<PathBuf>,
    #[serde(default)]
    pub seed: Option<PathBuf>,
    pub memory_mib: u64,
    pub vcpus: u8,
    #[serde(default)]
    pub kernel_args: Option<String>,
    #[serde(default)]
    pub tap: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub vsock_cid: Option<u32>,
    #[serde(default)]
    pub vsock_uds: Option<PathBuf>,
    #[serde(default)]
    pub seccomp: bool,
    /// Guest runner: Firecracker (default) or in-tree KVM.
    #[serde(default)]
    pub engine: FluxVmEngine,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FluxVmEngine {
    #[default]
    Firecracker,
    Kvm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSpec {
    pub memory_path: PathBuf,
    pub disk_path: PathBuf,
    /// Firecracker microVM state file (CPU/device). When present, restore uses
    /// `/snapshot/load` for tens-of-ms bring-up instead of a cold boot.
    #[serde(default)]
    pub vmstate_path: Option<PathBuf>,
    pub boot: BootConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ApiResponse {
    Ok {
        message: String,
    },
    State {
        lifecycle: String,
    },
    Metrics {
        memory_mib: u64,
        vcpus: u8,
        lifecycle: String,
    },
    Error {
        message: String,
    },
}
