// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::crd::{LABEL_JOB, MicroVM, MicroVMJob, MicroVMJobStatus};
use futures::StreamExt;
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{ListParams, ObjectMeta, Patch, PatchParams, PostParams},
    runtime::{
        controller::{Action, Controller},
        watcher,
    },
};
use std::{sync::Arc, time::Duration};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("kube API error: {0}")]
    Kube(#[from] kube::Error),
}

pub async fn run(client: Client) {
    let api: Api<MicroVMJob> = Api::all(client.clone());
    let ctx = Arc::new(client);
    tracing::info!("starting MicroVMJob controller");
    Controller::new(api, watcher::Config::default())
        .run(
            reconcile,
            |_o, e, _c| {
                tracing::warn!(error = %e, "job failed");
                Action::requeue(Duration::from_secs(15))
            },
            ctx,
        )
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::warn!(error = %e, "job error");
            }
        })
        .await;
}

async fn reconcile(obj: Arc<MicroVMJob>, client: Arc<Client>) -> Result<Action, Error> {
    if obj.meta().deletion_timestamp.is_some() {
        return Ok(Action::await_change());
    }
    let ns = obj.namespace().unwrap_or_else(|| "default".into());
    let vms: Api<MicroVM> = Api::namespaced(client.as_ref().clone(), &ns);
    let jobs: Api<MicroVMJob> = Api::namespaced(client.as_ref().clone(), &ns);
    let lp = ListParams::default().labels(&format!("{}={}", LABEL_JOB, obj.name_any()));
    let children = vms.list(&lp).await?.items;
    let mut succeeded = 0u32;
    let mut failed = 0u32;
    let mut active = 0u32;
    for c in &children {
        match c.status.as_ref().map(|s| s.phase.as_str()).unwrap_or("") {
            "Succeeded" => succeeded += 1,
            "Failed" => failed += 1,
            _ => active += 1,
        }
    }
    let want = obj.spec.completions.max(1);
    let parallel = obj.spec.parallelism.max(1);
    if succeeded < want && failed <= obj.spec.backoff_limit && active < parallel {
        let child_name = format!("{}-{}", obj.name_any(), children.len());
        if vms.get_opt(&child_name).await?.is_none() {
            let mut spec = obj.spec.template.clone();
            spec.persist = false;
            let mut child = MicroVM::new(&child_name, spec);
            child.metadata = ObjectMeta {
                name: Some(child_name.clone()),
                namespace: Some(ns.clone()),
                labels: Some(
                    [(LABEL_JOB.to_string(), obj.name_any())]
                        .into_iter()
                        .collect(),
                ),
                owner_references: obj.controller_owner_ref(&()).map(|o| vec![o]),
                ..Default::default()
            };
            match vms.create(&PostParams::default(), &child).await {
                Ok(_) => active += 1,
                Err(kube::Error::Api(ae)) if ae.code == 409 => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    let phase = if succeeded >= want {
        "Succeeded"
    } else if failed > obj.spec.backoff_limit {
        "Failed"
    } else {
        "Running"
    };
    jobs.patch_status(
        &obj.name_any(),
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({ "status": MicroVMJobStatus { phase: phase.into(), active, succeeded, failed } })),
    ).await?;
    Ok(Action::requeue(Duration::from_secs(10)))
}
