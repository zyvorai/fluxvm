// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::crd::{MicroVMPool, MicroVMPoolStatus, MicroVMSpec};
use crate::fluxvm_client::FluxVMClient;
use futures::StreamExt;
use kube::{
    Api, Client, ResourceExt,
    api::{Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher,
    },
};
use std::{sync::Arc, time::Duration};

pub struct Context {
    pub client: Client,
    pub fluxvm: FluxVMClient,
    pub node_name: String,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("kube API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("{0}")]
    Flux(String),
}
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self::Flux(format!("{e:#}"))
    }
}

pub async fn run(client: Client, fluxvm: FluxVMClient, node_name: String) {
    let api: Api<MicroVMPool> = Api::all(client.clone());
    let ctx = Arc::new(Context {
        client,
        fluxvm,
        node_name,
    });
    tracing::info!(node = %ctx.node_name, "starting MicroVMPool node reconciler");
    Controller::new(api, watcher::Config::default())
        .run(
            reconcile,
            |_o, e, _c| {
                tracing::warn!(error = %e, "pool failed");
                Action::requeue(Duration::from_secs(15))
            },
            ctx,
        )
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::warn!(error = %e, "pool error");
            }
        })
        .await;
}

async fn reconcile(obj: Arc<MicroVMPool>, ctx: Arc<Context>) -> Result<Action, Error> {
    if let Some(node) = obj.spec.node_name.as_deref() {
        if node != ctx.node_name {
            return Ok(Action::await_change());
        }
    }
    let ns = obj.namespace().unwrap_or_else(|| "default".into());
    let name = MicroVMSpec::fluxvm_pool_name(&ns, &obj.name_any());
    ctx.fluxvm
        .ensure_pool(&name, obj.spec.replicas as usize, &obj.spec.template)
        .await?;
    let ready = ctx
        .fluxvm
        .get_pool(&name)
        .await?
        .and_then(|p| {
            p.get("members")
                .and_then(|m| m.as_array())
                .map(|a| a.len() as u32)
        })
        .unwrap_or(0);
    let api: Api<MicroVMPool> = Api::namespaced(ctx.client.clone(), &ns);
    let status = MicroVMPoolStatus {
        phase: if ready >= obj.spec.replicas {
            "Ready".into()
        } else {
            "Provisioning".into()
        },
        ready,
        claimed: 0,
        message: Some(format!("fluxvm pool {name} on {}", ctx.node_name)),
    };
    api.patch_status(
        &obj.name_any(),
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({ "status": status })),
    )
    .await?;
    Ok(Action::requeue(Duration::from_secs(20)))
}
