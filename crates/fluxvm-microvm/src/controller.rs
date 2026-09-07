// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Cluster controller: shadow Pods, Scheduled phase, EndpointSlices.
//! Never talks to FluxVM.

use crate::crd::{FINALIZER, LABEL_MICROVM, MicroVM, MicroVMStatus};
use crate::shadow::{bound_node, desired_pod, shadow_name};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointPort, EndpointSlice};
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{DeleteParams, ObjectMeta, Patch, PatchParams, PostParams},
    runtime::{
        controller::{Action, Controller},
        finalizer::{Event as FinalizerEvent, finalizer},
        watcher,
    },
};
use std::{sync::Arc, time::Duration};

const ERROR_REQUEUE: Duration = Duration::from_secs(15);
const STEADY: Duration = Duration::from_secs(20);

pub struct Context {
    pub client: Client,
    pub request_kvm_device: bool,
}

#[derive(thiserror::Error, Debug)]
pub enum ReconcileError {
    #[error("kube API error: {0}")]
    Kube(#[from] kube::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("finalizer error: {0}")]
    Finalizer(#[from] kube::runtime::finalizer::Error<ReconcileError>),
}

pub async fn run(client: Client, request_kvm_device: bool) {
    let api: Api<MicroVM> = Api::all(client.clone());
    let ctx = Arc::new(Context { client: client.clone(), request_kvm_device });
    tracing::info!("starting MicroVM cluster controller");
    Controller::new(api, watcher::Config::default())
        .owns(Api::<Pod>::all(client), watcher::Config::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res { tracing::warn!(error = %e, "microvm controller error"); }
        })
        .await;
}

async fn reconcile(obj: Arc<MicroVM>, ctx: Arc<Context>) -> Result<Action, Error> {
    let ns = obj.namespace().unwrap_or_else(|| "default".into());
    let api: Api<MicroVM> = Api::namespaced(ctx.client.clone(), &ns);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(obj) => apply(&obj, &api, &ctx).await,
            FinalizerEvent::Cleanup(obj) => cleanup(&obj, &ctx).await,
        }
    }).await.map_err(Error::Finalizer)
}

fn error_policy(_obj: Arc<MicroVM>, err: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!(error = %err, "cluster reconcile failed");
    Action::requeue(ERROR_REQUEUE)
}

async fn apply(obj: &MicroVM, api: &Api<MicroVM>, ctx: &Context) -> Result<Action, ReconcileError> {
    let ns = obj.namespace().unwrap_or_else(|| "default".into());
    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &ns);
    let name = shadow_name(obj);
    if pods.get_opt(&name).await?.is_none() {
        let pod = desired_pod(obj, ctx.request_kvm_device);
        match pods.create(&PostParams::default(), &pod).await {
            Ok(_) => tracing::info!(pod = %name, vm = %obj.name_any(), "created shadow pod"),
            Err(kube::Error::Api(ae)) if ae.code == 409 => {}
            Err(e) => return Err(e.into()),
        }
    }
    let pod = pods.get_opt(&name).await?;
    let scheduled = pod.as_ref().and_then(bound_node);
    let mut status = obj.status.clone().unwrap_or_default();
    if let Some(node) = scheduled {
        if status.runtime.node.as_deref() != Some(node.as_str()) {
            status.runtime.node = Some(node);
        }
        if status.runtime.uuid.is_none() && status.phase != "Provisioning" && status.phase != "Running" {
            status.phase = "Scheduled".into();
            status.message = Some("shadow pod bound; waiting for node agent".into());
        }
    } else if status.runtime.uuid.is_none() {
        let phase = pod.as_ref().and_then(|p| p.status.as_ref()).and_then(|s| s.phase.clone()).unwrap_or_else(|| "Pending".into());
        if phase == "Failed" {
            status.phase = "Unschedulable".into();
            status.message = Some("shadow pod failed to schedule".into());
        } else {
            status.phase = "Pending".into();
            status.message = Some("waiting for kube-scheduler".into());
        }
    }
    if obj.spec.service {
        if let Some(ip) = status.guest_ip.clone() {
            ensure_endpointslice(&ctx.client, obj, &ip).await?;
        }
    }
    patch_status(api, &obj.name_any(), status).await?;
    Ok(Action::requeue(STEADY))
}

async fn cleanup(obj: &MicroVM, ctx: &Context) -> Result<Action, ReconcileError> {
    if obj.status.as_ref().and_then(|s| s.runtime.uuid.as_deref()).is_some() {
        return Ok(Action::requeue(Duration::from_secs(5)));
    }
    let ns = obj.namespace().unwrap_or_else(|| "default".into());
    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &ns);
    let _ = pods.delete(&shadow_name(obj), &DeleteParams::default()).await;
    let slices: Api<EndpointSlice> = Api::namespaced(ctx.client.clone(), &ns);
    let _ = slices.delete(&format!("mvm-{}", obj.name_any()), &DeleteParams::default()).await;
    Ok(Action::await_change())
}

async fn ensure_endpointslice(client: &Client, vm: &MicroVM, ip: &str) -> Result<(), kube::Error> {
    let ns = vm.namespace().unwrap_or_else(|| "default".into());
    let api: Api<EndpointSlice> = Api::namespaced(client.clone(), &ns);
    let port = vm.spec.service_port.unwrap_or(22);
    let mut labels = std::collections::BTreeMap::new();
    labels.insert("kubernetes.io/service-name".into(), vm.name_any());
    labels.insert(LABEL_MICROVM.to_string(), vm.name_any());
    let slice = EndpointSlice {
        metadata: ObjectMeta {
            name: Some(format!("mvm-{}", vm.name_any())),
            namespace: Some(ns),
            labels: Some(labels),
            owner_references: vm.controller_owner_ref(&()).map(|o| vec![o]),
            ..Default::default()
        },
        address_type: "IPv4".into(),
        endpoints: vec![Endpoint { addresses: vec![ip.to_string()], ..Default::default() }],
        ports: Some(vec![EndpointPort {
            port: Some(port),
            protocol: Some("TCP".into()),
            name: Some("guest".into()),
            ..Default::default()
        }]),
    };
    match api.create(&PostParams::default(), &slice).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(ae)) if ae.code == 409 => {
            api.patch(
                &format!("mvm-{}", vm.name_any()),
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({
                    "endpoints": [{"addresses": [ip]}],
                    "ports": [{"port": port, "protocol": "TCP", "name": "guest"}]
                })),
            ).await?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn patch_status(api: &Api<MicroVM>, name: &str, status: MicroVMStatus) -> Result<(), kube::Error> {
    api.patch_status(name, &PatchParams::default(), &Patch::Merge(serde_json::json!({ "status": status }))).await?;
    Ok(())
}
