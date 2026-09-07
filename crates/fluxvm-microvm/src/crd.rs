// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[kube(
    group = "microvm.fluxvm.zyvor.io",
    version = "v1alpha1",
    kind = "MicroVM",
    plural = "microvms",
    shortname = "mvm",
    namespaced,
    status = "MicroVMStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Node","type":"string","jsonPath":".status.runtime.node"}"#,
    printcolumn = r#"{"name":"GuestIP","type":"string","jsonPath":".status.guestIP"}"#,
    printcolumn = r#"{"name":"Backend","type":"string","jsonPath":".spec.backend"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct MicroVMSpec {
    #[serde(default = "default_backend")]
    pub backend: String,
    pub image: String,
    #[serde(default = "default_vcpus")]
    pub vcpus: u8,
    #[serde(default = "default_memory_mib")]
    pub memory_mib: u64,
    #[serde(default)]
    pub disk_size_gib: Option<u64>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macvtap_mode: Option<String>,
    #[serde(default = "default_storage")]
    pub storage: String,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    #[serde(default)]
    pub persist: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default)]
    pub command_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub service: bool,
    #[serde(default)]
    pub service_port: Option<i32>,
}

fn default_backend() -> String { "qemu".into() }
fn default_vcpus() -> u8 { 2 }
fn default_memory_mib() -> u64 { 2048 }
fn default_network_mode() -> String { "none".into() }
fn default_storage() -> String { "default".into() }

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MicroVMStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub runtime: RuntimeStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_exit: Option<i32>,
    #[serde(default)]
    pub command_ran: bool,
}

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[kube(
    group = "microvm.fluxvm.zyvor.io",
    version = "v1alpha1",
    kind = "MicroVMJob",
    plural = "microvmjobs",
    shortname = "mvmj",
    namespaced,
    status = "MicroVMJobStatus",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Succeeded","type":"integer","jsonPath":".status.succeeded"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct MicroVMJobSpec {
    #[serde(default = "default_one")]
    pub completions: u32,
    #[serde(default = "default_one")]
    pub parallelism: u32,
    #[serde(default = "default_backoff")]
    pub backoff_limit: u32,
    #[serde(default)]
    pub ttl_seconds_after_finished: Option<u64>,
    pub template: MicroVMSpec,
}
fn default_one() -> u32 { 1 }
fn default_backoff() -> u32 { 3 }

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MicroVMJobStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub active: u32,
    #[serde(default)]
    pub succeeded: u32,
    #[serde(default)]
    pub failed: u32,
}

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[kube(
    group = "microvm.fluxvm.zyvor.io",
    version = "v1alpha1",
    kind = "MicroVMPool",
    plural = "microvmpools",
    shortname = "mvmp",
    namespaced,
    status = "MicroVMPoolStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct MicroVMPoolSpec {
    #[serde(default = "default_one")]
    pub replicas: u32,
    pub template: MicroVMSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MicroVMPoolStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub ready: u32,
    #[serde(default)]
    pub claimed: u32,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[kube(
    group = "microvm.fluxvm.zyvor.io",
    version = "v1alpha1",
    kind = "GuestImage",
    plural = "guestimages",
    shortname = "gimg",
    namespaced,
    status = "GuestImageStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct GuestImageSpec {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GuestImageStatus {
    #[serde(default)]
    pub ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub const FINALIZER: &str = "microvm.fluxvm.zyvor.io/runtime";
pub const LABEL_MICROVM: &str = "microvm.fluxvm.zyvor.io/microvm";
pub const LABEL_JOB: &str = "microvm.fluxvm.zyvor.io/job";

impl MicroVMSpec {
    pub fn fluxvm_pool_name(namespace: &str, claim: &str) -> String {
        format!("{namespace}-{claim}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pool_name_is_namespaced() {
        assert_eq!(MicroVMSpec::fluxvm_pool_name("ci", "warm"), "ci-warm");
    }
    #[test]
    fn defaults_are_disposable() {
        let spec: MicroVMSpec = serde_json::from_value(serde_json::json!({
            "image": "/var/lib/fluxvm/images/ubuntu.qcow2"
        })).unwrap();
        assert!(!spec.persist);
        assert_eq!(spec.backend, "qemu");
        assert_eq!(spec.vcpus, 2);
    }
}
