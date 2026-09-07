// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Node-local GuestImage: if `spec.source` is an existing host file, mark
//! Ready. HTTP sources stay Pending until that file is staged by GuestKit
//! onto the node (no importer Pod, no CDI).

use crate::crd::{GuestImage, GuestImageStatus};
use crate::images::local_source_ready;
use futures::StreamExt;
use kube::{
    Api, Client, ResourceExt,
    api::{Patch, PatchParams},
    runtime::{controller::{Action, Controller}, watcher},
};
use std::{sync::Arc, time::Duration};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("kube API error: {0}")]
    Kube(#[from] kube::Error),
}

pub async fn run(client: Client) {
    let api: Api<GuestImage> = Api::all(client.clone());
    let ctx = Arc::new(client);
    tracing::info!("starting GuestImage node reconciler");
    Controller::new(api, watcher::Config::default())
        .run(
            reconcile,
            |_o, e, _c| {
                tracing::warn!(error = %e, "guestimage reconcile failed");
                Action::requeue(Duration::from_secs(20))
            },
            ctx,
        )
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::warn!(error = %e, "guestimage error");
            }
        })
        .await;
}

async fn reconcile(obj: Arc<GuestImage>, client: Arc<Client>) -> Result<Action, Error> {
    let ns = obj.namespace().unwrap_or_else(|| "default".into());
    let api: Api<GuestImage> = Api::namespaced(client.as_ref().clone(), &ns);
    let (ready, path, message) = if let Some(p) = local_source_ready(&obj.spec.source) {
        (true, Some(p), Some("host file present".into()))
    } else {
        (
            false,
            None,
            Some("stage this file on the node with GuestKit (no CDI pull)".into()),
        )
    };
    let status = GuestImageStatus {
        ready,
        path,
        message,
    };
    api.patch_status(
        &obj.name_any(),
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({ "status": status })),
    )
    .await?;
    Ok(Action::requeue(Duration::from_secs(30)))
}
