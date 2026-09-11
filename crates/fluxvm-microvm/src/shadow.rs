// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Shadow Pod — a capacity ticket for kube-scheduler. It never runs a VMM.

use crate::crd::{LABEL_MICROVM, MicroVM};
use k8s_openapi::api::core::v1::{Container, Pod, PodSpec, ResourceRequirements, Toleration};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::{Resource, ResourceExt};
use std::collections::BTreeMap;

pub const PAUSE_IMAGE: &str = "registry.k8s.io/pause:3.10";
pub const CAPABLE_LABEL: &str = "ragnarok.io/fluxvm-capable";

pub fn shadow_name(vm: &MicroVM) -> String {
    let mut name = format!("mvm-{}", vm.name_any());
    name.truncate(63);
    name.trim_end_matches('-').to_string()
}

pub fn desired_pod(vm: &MicroVM, request_kvm_device: bool) -> Pod {
    let mut labels = BTreeMap::new();
    labels.insert(LABEL_MICROVM.to_string(), vm.name_any());
    labels.insert("app.kubernetes.io/part-of".into(), "fluxvm-microvm".into());
    let mut node_selector = BTreeMap::new();
    node_selector.insert(CAPABLE_LABEL.to_string(), "true".into());
    // Pause-only budget. Guest RAM/CPU live in the host VMM cgroup, not
    // this Pod — requesting spec.memoryMiB here double-counts the node.
    let mut requests = BTreeMap::new();
    requests.insert("cpu".into(), Quantity(crate::policy::SHADOW_CPU.into()));
    requests.insert(
        "memory".into(),
        Quantity(crate::policy::SHADOW_MEMORY.into()),
    );
    if request_kvm_device {
        requests.insert("fluxvm.dev/kvm".into(), Quantity("1".into()));
    }
    let mut spec = PodSpec {
        restart_policy: Some("Never".into()),
        node_selector: Some(node_selector),
        tolerations: Some(vec![Toleration {
            key: Some(CAPABLE_LABEL.into()),
            operator: Some("Exists".into()),
            effect: Some("NoSchedule".into()),
            ..Default::default()
        }]),
        containers: vec![Container {
            name: "shadow".into(),
            image: Some(PAUSE_IMAGE.into()),
            image_pull_policy: Some("IfNotPresent".into()),
            resources: Some(ResourceRequirements {
                requests: Some(requests),
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    if let Some(node) = vm.spec.node_name.as_deref().filter(|n| !n.is_empty()) {
        spec.node_name = Some(node.to_string());
    }
    let mut pod = Pod {
        metadata: kube::api::ObjectMeta {
            name: Some(shadow_name(vm)),
            namespace: vm.namespace(),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(spec),
        ..Default::default()
    };
    if let Some(oref) = vm.controller_owner_ref(&()) {
        pod.owner_references_mut().push(oref);
    }
    pod
}

pub fn bound_node(pod: &Pod) -> Option<String> {
    pod.spec
        .as_ref()
        .and_then(|s| s.node_name.clone())
        .filter(|n| !n.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::MicroVMSpec;
    #[test]
    fn shadow_requests_tiny_budget() {
        let vm = MicroVM::new(
            "sandbox-42",
            MicroVMSpec {
                image: "/img".into(),
                vcpus: 4,
                memory_mib: 4096,
                ..Default::default()
            },
        );
        let pod = desired_pod(&vm, true);
        let req = pod.spec.as_ref().unwrap().containers[0]
            .resources
            .as_ref()
            .unwrap()
            .requests
            .as_ref()
            .unwrap();
        assert_eq!(req.get("cpu").unwrap().0, crate::policy::SHADOW_CPU);
        assert_eq!(req.get("memory").unwrap().0, crate::policy::SHADOW_MEMORY);
        assert_eq!(req.get("fluxvm.dev/kvm").unwrap().0, "1");
        assert_ne!(req.get("memory").unwrap().0, "4096Mi");
    }
}
