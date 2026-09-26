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
    /// H4: export FLUXKVM1 migration bundle directory (vmstate+mem).
    MigrateExport { path: PathBuf },
    /// H4: import FLUXKVM1 migration bundle directory.
    MigrateImport { path: PathBuf },
    /// H4: hot-add `add` vCPUs (requires max_vcpus headroom at boot).
    HotplugCpu { add: u8 },
    /// H4: validate + record a disk hotplug plan (path must exist).
    HotplugDisk { path: PathBuf },
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
    /// Virtio-net bandwidth cap (Mbit/s). `None`/`0` = unlimited.
    /// Applied to Firecracker `rate_limiter` and in-tree KVM token buckets.
    #[serde(default)]
    pub net_mbit_limit: Option<u32>,
    /// Virtio-net ops (packets) per second — Firecracker `rate_limiter.ops` only.
    #[serde(default)]
    pub net_pps_limit: Option<u64>,
    /// Virtio-block bandwidth cap (Mbit/s).
    #[serde(default)]
    pub blk_mbit_limit: Option<u32>,
    /// Virtio-block ops per second — Firecracker `rate_limiter.ops` only.
    #[serde(default)]
    pub blk_ops_limit: Option<u64>,
    /// Firecracker static CPU template (e.g. T2). Only used when engine is Firecracker.
    #[serde(default)]
    pub cpu_template: Option<String>,
    /// H4: max vCPUs reserved for hotplug (`>= vcpus`). Default = vcpus.
    #[serde(default)]
    pub max_vcpus: Option<u8>,
    /// H4: host directories to expose via virtio-fs (tags fs0, fs1, …).
    #[serde(default)]
    pub shared_folders: Vec<PathBuf>,
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
