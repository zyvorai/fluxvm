// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A disposable VM, declared as a Kubernetes custom resource. The operator
/// running on each node (see `crate::controller`) watches these and drives
/// a *local* `fluxvm serve` instance's REST API to create/delete the
/// underlying VM — it never talks to another node's fluxvm, matching the
/// "node-local daemonset" model described in the project README rather
/// than a centralized scheduler that place VMs across a fleet.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[kube(
    group = "fluxvm.zyvor.io",
    version = "v1",
    kind = "DisposableVm",
    plural = "disposablevms",
    shortname = "dvm",
    namespaced,
    status = "DisposableVmStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Node","type":"string","jsonPath":".spec.node"}"#,
    printcolumn = r#"{"name":"VmId","type":"string","jsonPath":".status.vmId"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct DisposableVmSpec {
    /// Node this VM must run on. Optional when a cluster placer
    /// (`fluxvm-kube --enable-placement`) is running — it fills this in.
    /// A `DisposableVm` with no `node` set is ignored by node-local
    /// operators until placement assigns one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// One of "qemu", "cloud-hypervisor", "firecracker", "auto" — passed
    /// straight through to the local fluxvm's `CreateVmRequest.backend`.
    #[serde(default = "default_backend")]
    pub backend: String,
    /// Passed straight through as `CreateVmRequest.image`. No catalog
    /// aliasing awareness beyond whatever the local fluxvm is itself
    /// configured with (see README's "Image catalog & signing").
    pub image: String,
    #[serde(default = "default_vcpus")]
    pub vcpus: u8,
    #[serde(default = "default_memory_mib")]
    pub memory_mib: u64,
    #[serde(default)]
    pub disk_size_gib: Option<u64>,
    /// "none", "user", "tap", or "macvtap". Tap needs optional `bridge`/
    /// `tapName`/`mac`/`netns`; macvtap needs `parent` (+ optional
    /// `macvtapMode`/`mac`).
    #[serde(default = "default_network_mode")]
    pub network_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tap_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default)]
    pub netns: bool,
    /// Parent link for `networkMode: macvtap` (required in that mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macvtap_mode: Option<String>,
    /// One of "default", "lvm-thin", "nbd", "ceph-rbd" — see README's
    /// "Storage backends".
    #[serde(default = "default_storage")]
    pub storage: String,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

fn default_backend() -> String {
    "qemu".into()
}
fn default_vcpus() -> u8 {
    2
}
fn default_memory_mib() -> u64 {
    2048
}
fn default_network_mode() -> String {
    "none".into()
}
fn default_storage() -> String {
    "default".into()
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DisposableVmStatus {
    /// "Pending" (finalizer not yet attached), "Running", or "Failed" —
    /// mirrors `fluxvm_core::model::VmStatus` where they overlap, plus
    /// the CR-lifecycle-only "Pending". "Failed" is momentary in practice:
    /// this CRD is declarative (like a `Deployment`, not a one-shot `Job`)
    /// — if the underlying VM vanishes on its own (its `ttl_seconds`
    /// expired, or something deleted it directly via the REST API) the
    /// *next* reconcile clears `vm_id` and briefly reports "Failed", but
    /// the reconcile immediately after that creates a fresh VM and returns
    /// to "Running". Confirmed on real hardware: deleting a VM out from
    /// under a live CR via `DELETE /v1/vms/{id}` produced a genuinely new
    /// VM (a different id, a different pid) within two reconcile ticks,
    /// with no action needed on the CR itself. Only deleting the
    /// `DisposableVm` object stops this — see `controller::cleanup`.
    #[serde(default)]
    pub phase: String,
    /// The underlying VM's UUID once `POST /v1/vms` has succeeded — `None`
    /// before that, and briefly `None` again if the VM disappeared and is
    /// about to be recreated (see `phase`'s doc comment).
    #[serde(default)]
    pub vm_id: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}
