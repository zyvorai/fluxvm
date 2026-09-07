// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Node agent: the only process that talks to local `fluxvm serve`.

use crate::crd::{MicroVM, MicroVMStatus};
use crate::fluxvm_client::{FluxVMClient, record_guest_ip, record_id, record_pid, record_status};
use futures::StreamExt;
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{Patch, PatchParams},
    runtime::{controller::{Action, Controller}, watcher},
};
use std::{sync::Arc, time::Duration};

const STEADY: Duration = Duration::from_secs(15);
const ERROR: Duration = Duration::from_secs(10);

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
    fn from(e: anyhow::Error) -> Self { Self::Flux(format!("{e:#}")) }
}

pub async fn run(client: Client, fluxvm: FluxVMClient, node_name: String) {
    let api: Api<MicroVM> = Api::all(client.clone());
    let ctx = Arc::new(Context { client, fluxvm, node_name });
    tracing::info!(node = %ctx.node_name, "starting MicroVM node agent");
    Controller::new(api, watcher::Config::default())
        .run(reconcile, |_o, e, _c| { tracing::warn!(error = %e, "node agent failed"); Action::requeue(ERROR) }, ctx)
        .for_each(|res| async move {
            if let Err(e) = res { tracing::warn!(error = %e, "node agent error"); }
        })
        .await;
}

async fn reconcile(obj: Arc<MicroVM>, ctx: Arc<Context>) -> Result<Action, Error> {
    let mine = obj.status.as_ref().and_then(|s| s.runtime.node.as_deref()) == Some(ctx.node_name.as_str())
        || obj.spec.node_name.as_deref() == Some(ctx.node_name.as_str());
    if !mine { return Ok(Action::await_change()); }
    let ns = obj.namespace().unwrap_or_else(|| "default".into());
    let api: Api<MicroVM> = Api::namespaced(ctx.client.clone(), &ns);
    if obj.meta().deletion_timestamp.is_some() {
        return cleanup(&obj, &api, &ctx).await;
    }
    apply(&obj, &api, &ctx).await
}

async fn cleanup(obj: &MicroVM, api: &Api<MicroVM>, ctx: &Context) -> Result<Action, Error> {
    if let Some(id) = obj.status.as_ref().and_then(|s| s.runtime.uuid.as_deref()) {
        ctx.fluxvm.delete_vm(id).await?;
    }
    let mut status = obj.status.clone().unwrap_or_default();
    status.runtime.uuid = None;
    status.runtime.pid = None;
    status.message = Some("reaped".into());
    patch_status(api, &obj.name_any(), status).await?;
    Ok(Action::await_change())
}

async fn apply(obj: &MicroVM, api: &Api<MicroVM>, ctx: &Context) -> Result<Action, Error> {
    let name = obj.name_any();
    let mut status = obj.status.clone().unwrap_or_default();
    status.runtime.node = Some(ctx.node_name.clone());
    let record = if let Some(id) = status.runtime.uuid.clone() {
        match ctx.fluxvm.get_vm(&id).await? {
            Some(rec) => rec,
            None => {
                if obj.spec.persist {
                    status.phase = "Provisioning".into();
                    status.message = Some("underlying VM gone; recreating (persist=true)".into());
                    status.runtime.uuid = None;
                    patch_status(api, &name, status).await?;
                    return Ok(Action::requeue(Duration::from_secs(2)));
                }
                status.phase = "Succeeded".into();
                status.message = Some("VM expired or deleted; persist=false".into());
                status.runtime.uuid = None;
                patch_status(api, &name, status).await?;
                return Ok(Action::await_change());
            }
        }
    } else if let Some(pool) = obj.spec.claim_from.as_deref() {
        let pool_name = crate::crd::MicroVMSpec::fluxvm_pool_name(
            &obj.namespace().unwrap_or_else(|| "default".into()),
            pool,
        );
        ctx.fluxvm.claim_pool(&pool_name, &name, obj.spec.ttl_seconds).await?
    } else {
        status.phase = "Provisioning".into();
        ctx.fluxvm.create_vm(&name, &obj.spec).await?
    };
    let id = record_id(&record).ok_or_else(|| Error::Flux("create/claim returned no id".into()))?;
    status.runtime.uuid = Some(id.clone());
    status.runtime.pid = record_pid(&record);
    status.runtime.backend = Some(obj.spec.backend.clone());
    status.guest_ip = record_guest_ip(&record);
    status.phase = match record_status(&record).as_str() {
        "running" => "Running".into(),
        "paused" => "Paused".into(),
        "failed" => "Failed".into(),
        "creating" => "Provisioning".into(),
        other => other.to_string(),
    };
    if obj.spec.command.is_some() && status.phase == "Running" && !status.command_ran {
        let cmd = obj.spec.command.as_deref().unwrap();
        match ctx.fluxvm.exec(&id, cmd, obj.spec.command_timeout_seconds).await {
            Ok(out) => {
                status.command_ran = true;
                status.command_exit = out.get("exit_code").and_then(|v| v.as_i64()).map(|i| i as i32);
                if !obj.spec.persist {
                    status.phase = if status.command_exit.unwrap_or(0) == 0 { "Succeeded".into() } else { "Failed".into() };
                    let _ = ctx.fluxvm.delete_vm(&id).await;
                    status.runtime.uuid = None;
                }
            }
            Err(e) => {
                status.message = Some(format!("command failed: {e:#}"));
                status.command_ran = true;
                status.command_exit = Some(1);
                if !obj.spec.persist {
                    status.phase = "Failed".into();
                    let _ = ctx.fluxvm.delete_vm(&id).await;
                    status.runtime.uuid = None;
                }
            }
        }
    }
    patch_status(api, &name, status).await?;
    Ok(Action::requeue(STEADY))
}

async fn patch_status(api: &Api<MicroVM>, name: &str, status: MicroVMStatus) -> Result<(), kube::Error> {
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(serde_json::json!({ "status": status }))).await?;
    Ok(())
}
