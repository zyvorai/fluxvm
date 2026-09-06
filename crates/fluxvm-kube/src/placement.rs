// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Thin cluster placer: when `DisposableVm.spec.node` is empty, pick a
//! `ragnarok.io/fluxvm-capable=true` node with the fewest DisposableVm
//! objects and patch `spec.node`. Node-local reconciler is unchanged —
//! this only fills the pin field. Enable with `--enable-placement` on
//! exactly one elected instance (use a Lease outside this module if you
//! run multiple placer candidates).

use crate::crd::DisposableVm;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Node;
use kube::{
    Api, Client, ResourceExt,
    api::{Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher,
    },
};
use std::{collections::HashMap, sync::Arc, time::Duration};

const CAPABLE_LABEL: &str = "ragnarok.io/fluxvm-capable";

#[derive(thiserror::Error, Debug)]
pub enum PlaceError {
    #[error("kube API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("{0}")]
    Other(String),
}

pub async fn run(client: Client) {
    let api: Api<DisposableVm> = Api::all(client.clone());
    let ctx = Arc::new(client);
    tracing::info!("starting DisposableVm placement controller");
    Controller::new(api, watcher::Config::default())
        .run(
            reconcile,
            |_obj, _err, _ctx| Action::requeue(Duration::from_secs(15)),
            ctx,
        )
        .for_each(|res| async move {
            match res {
                Ok(_) => tracing::debug!("placement reconciled"),
                Err(e) => tracing::warn!(error = %e, "placement error"),
            }
        })
        .await;
}

async fn reconcile(obj: Arc<DisposableVm>, client: Arc<Client>) -> Result<Action, PlaceError> {
    if obj.spec.node.as_ref().is_some_and(|n| !n.is_empty()) {
        return Ok(Action::await_change());
    }
    let node = pick_node(client.as_ref()).await?;
    let ns = obj.namespace().unwrap_or_else(|| "default".into());
    let name = obj.name_any();
    let api: Api<DisposableVm> = Api::namespaced(client.as_ref().clone(), &ns);
    let patch = serde_json::json!({
        "spec": { "node": node }
    });
    api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    tracing::info!(%name, %ns, %node, "placed DisposableVm");
    Ok(Action::requeue(Duration::from_secs(30)))
}

async fn pick_node(client: &Client) -> Result<String, PlaceError> {
    let nodes: Api<Node> = Api::all(client.clone());
    let capable = nodes
        .list(&Default::default())
        .await?
        .items
        .into_iter()
        .filter(|n| {
            n.metadata
                .labels
                .as_ref()
                .and_then(|l| l.get(CAPABLE_LABEL))
                .map(|v| v == "true")
                .unwrap_or(false)
        })
        .map(|n| n.name_any())
        .collect::<Vec<_>>();
    if capable.is_empty() {
        return Err(PlaceError::Other(
            "no nodes labeled ragnarok.io/fluxvm-capable=true".into(),
        ));
    }

    let dvms: Api<DisposableVm> = Api::all(client.clone());
    let mut counts: HashMap<String, usize> = capable.iter().cloned().map(|n| (n, 0)).collect();
    for dvm in dvms.list(&Default::default()).await?.items {
        if let Some(node) = dvm.spec.node.as_ref().filter(|n| !n.is_empty()) {
            *counts.entry(node.clone()).or_insert(0) += 1;
        }
    }
    capable
        .into_iter()
        .min_by_key(|n| (*counts.get(n).unwrap_or(&0), n.clone()))
        .ok_or_else(|| PlaceError::Other("no capable node".into()))
}
