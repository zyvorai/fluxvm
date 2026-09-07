// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Dual-running: DisposableVm → MicroVM (persist=true, nodeName copied).

use crate::crd::{MicroVM, MicroVMSpec};
use fluxvm_kube::crd::DisposableVm;
use futures::StreamExt;
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{Patch, PatchParams, PostParams},
    runtime::{controller::{Action, Controller}, watcher},
};
use std::{sync::Arc, time::Duration};

#[derive(thiserror::Error, Debug)]
pub enum ConvertError {
    #[error("kube API error: {0}")]
    Kube(#[from] kube::Error),
}

pub async fn run(client: Client) {
    let api: Api<DisposableVm> = Api::all(client.clone());
    let ctx = Arc::new(client);
    tracing::info!("starting DisposableVm → MicroVM conversion controller");
    Controller::new(api, watcher::Config::default())
        .run(reconcile, |_o, e, _c| {
            tracing::warn!(error = %e, "convert reconcile failed");
            Action::requeue(Duration::from_secs(15))
        }, ctx)
        .for_each(|res| async move {
            if let Err(e) = res { tracing::warn!(error = %e, "convert error"); }
        })
        .await;
}

async fn reconcile(obj: Arc<DisposableVm>, client: Arc<Client>) -> Result<Action, ConvertError> {
    if obj.meta().deletion_timestamp.is_some() {
        return Ok(Action::await_change());
    }
    let ns = obj.namespace().unwrap_or_else(|| "default".into());
    let name = obj.name_any();
    let api: Api<MicroVM> = Api::namespaced(client.as_ref().clone(), &ns);
    if api.get_opt(&name).await?.is_some() {
        return Ok(Action::await_change());
    }
    let mvm = disposable_to_microvm(&obj);
    match api.create(&PostParams::default(), &mvm).await {
        Ok(_) => {
            tracing::info!(%name, %ns, "created MicroVM from DisposableVm");
            let _ = api.patch(&name, &PatchParams::default(), &Patch::Merge(serde_json::json!({
                "metadata": {"annotations": {"microvm.fluxvm.zyvor.io/converted-from": "disposablevm"}}
            }))).await;
            Ok(Action::requeue(Duration::from_secs(60)))
        }
        Err(kube::Error::Api(ae)) if ae.code == 409 => Ok(Action::await_change()),
        Err(e) => Err(e.into()),
    }
}

pub fn disposable_to_microvm(dvm: &DisposableVm) -> MicroVM {
    let spec = MicroVMSpec {
        backend: dvm.spec.backend.clone(),
        image: dvm.spec.image.clone(),
        vcpus: dvm.spec.vcpus,
        memory_mib: dvm.spec.memory_mib,
        disk_size_gib: dvm.spec.disk_size_gib,
        network_mode: dvm.spec.network_mode.clone(),
        bridge: dvm.spec.bridge.clone(),
        tap_name: dvm.spec.tap_name.clone(),
        mac: dvm.spec.mac.clone(),
        netns: dvm.spec.netns,
        parent: dvm.spec.parent.clone(),
        macvtap_mode: dvm.spec.macvtap_mode.clone(),
        storage: dvm.spec.storage.clone(),
        ttl_seconds: dvm.spec.ttl_seconds,
        persist: true,
        node_name: dvm.spec.node.clone(),
        ..Default::default()
    };
    let mut mvm = MicroVM::new(&dvm.name_any(), spec);
    mvm.meta_mut().namespace = dvm.namespace();
    mvm.meta_mut().labels = Some(
        [("microvm.fluxvm.zyvor.io/converted-from".into(), "disposablevm".into())].into_iter().collect(),
    );
    mvm
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxvm_kube::crd::DisposableVmSpec;
    #[test]
    fn copies_node_and_forces_persist() {
        let mut dvm = DisposableVm::new("legacy", DisposableVmSpec {
            node: Some("worker-1".into()),
            backend: "qemu".into(),
            image: "/img.qcow2".into(),
            vcpus: 2,
            memory_mib: 2048,
            disk_size_gib: None,
            network_mode: "none".into(),
            bridge: None,
            tap_name: None,
            mac: None,
            netns: false,
            parent: None,
            macvtap_mode: None,
            storage: "default".into(),
            ttl_seconds: Some(600),
        });
        dvm.meta_mut().namespace = Some("default".into());
        let mvm = disposable_to_microvm(&dvm);
        assert_eq!(mvm.spec.node_name.as_deref(), Some("worker-1"));
        assert!(mvm.spec.persist);
        assert_eq!(mvm.spec.ttl_seconds, Some(600));
    }
}
