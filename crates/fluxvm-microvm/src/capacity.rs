// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Advertise `fluxvm.dev/kvm` on this node so shadow Pods can request a slot.

use k8s_openapi::api::core::v1::Node;
use kube::{
    Api, Client,
    api::{Patch, PatchParams},
};

pub async fn advertise(client: &Client, node_name: &str, slots: u32) -> Result<(), kube::Error> {
    let nodes: Api<Node> = Api::all(client.clone());
    let patch = serde_json::json!({
        "status": {
            "capacity": { "fluxvm.dev/kvm": slots.to_string() },
            "allocatable": { "fluxvm.dev/kvm": slots.to_string() }
        }
    });
    nodes
        .patch_status(node_name, &PatchParams::default(), &Patch::Merge(patch))
        .await?;
    Ok(())
}
