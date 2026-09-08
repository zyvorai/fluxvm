// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Node agent: the only process that talks to local `fluxvm serve`.

use crate::crd::{GuestImage, MicroVM, MicroVMStatus};
use crate::fluxvm_client::{FluxVMClient, record_guest_ip, record_id, record_pid, record_status};
use crate::images::{guest_image_host_path, looks_like_direct_image};
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
    if !crate::policy::node_agent_should_drive(obj.meta().annotations.as_ref()) {
        tracing::debug!(vm = %obj.name_any(), "skip: driven by fluxvm-kube");
        return Ok(Action::await_change());
    }
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
    let prev_phase = status.phase.clone();
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
        let mut spec = obj.spec.clone();
        spec.image = resolve_image(&ctx.client, obj.namespace().as_deref(), &spec.image).await?;
        ctx.fluxvm.create_vm(&name, &spec).await?
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
    if status.phase == "Failed" && prev_phase != "Failed" {
        crate::metrics::inc_failed();
    }
    if status.phase == "Running" && prev_phase != "Running" {
        if let Some(created) = obj.meta().creation_timestamp.as_ref() {
            let age = chrono::Utc::now().signed_duration_since(created.0);
            if let Ok(d) = age.to_std() {
                crate::metrics::observe_create_to_running(d);
            }
        }
        if let Some(sched_at) = obj
            .meta()
            .annotations
            .as_ref()
            .and_then(|a| a.get("microvm.fluxvm.zyvor.io/scheduled-at"))
        {
            if let Ok(secs) = sched_at.parse::<i64>() {
                if let Some(then) = chrono::DateTime::from_timestamp(secs, 0) {
                    if let Ok(sd) = chrono::Utc::now().signed_duration_since(then).to_std() {
                        crate::metrics::observe_schedule_to_running(sd);
                    }
                }
            }
        } else if let Some(created) = obj.meta().creation_timestamp.as_ref() {
            // Fallback when annotation missing (agent saw create before controller).
            if let Ok(d) = chrono::Utc::now()
                .signed_duration_since(created.0)
                .to_std()
            {
                crate::metrics::observe_schedule_to_running(d);
            }
        }
    }
    patch_status(api, &name, status).await?;
    Ok(Action::requeue(STEADY))
}

async fn resolve_image(client: &Client, ns: Option<&str>, image: &str) -> Result<String, Error> {
    if looks_like_direct_image(image) {
        return Ok(image.to_string());
    }
    let namespace = ns.unwrap_or("default");
    let api: Api<GuestImage> = Api::namespaced(client.clone(), namespace);
    let img = api.get(image).await.map_err(|e| {
        Error::Flux(format!("GuestImage {namespace}/{image}: {e}"))
    })?;
    guest_image_host_path(&img).ok_or_else(|| {
        Error::Flux(format!(
            "GuestImage {namespace}/{image} is not Ready on this node (stage with GuestKit)"
        ))
    })
}

async fn patch_status(api: &Api<MicroVM>, name: &str, status: MicroVMStatus) -> Result<(), kube::Error> {
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(serde_json::json!({ "status": status }))).await?;
    Ok(())
}
