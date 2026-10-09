// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! A small pool of warm `vz` sandbox VMs.
//!
//! A saved VM state is tied to the MAC address and machine identifier it was saved with (restoring with others fails), and two
//! VMs restored from one snapshot would share an address on the Mac's NAT. So each warm VM ("slot") is an ordinary stopped VM with
//! its own MAC and its own `warm` snapshot. A default-shaped sandbox claims a free slot by restoring it (about 1.5 s) instead of
//! cold-booting (about 8 s); the slot is then simply the sandbox, and deleting the sandbox deletes it. A background task rebuilds
//! slots up to `sandbox.warm_slots`. If no slot is free, or a restore fails (for example on a locked screen), creation cold-boots.

use crate::VmManager;
use anyhow::{Context, Result, bail};
use fluxvm_core::model::{BackendKind, CreateVmRequest, VmPatch, VmRecord, VmStatus};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;

pub const POOL_LABEL: &str = "fluxvm.pool";
pub const POOL_VALUE: &str = "sandbox";
const WARM_TAG: &str = "warm";
/// Which build of the base image a slot was made from (see `fluxvm_image::builtin::current_id`).
pub const IMAGE_LABEL: &str = "fluxvm.image-id";
const POOL_IMAGE: &str = "debian-13";

/// A slot is stale when the base image has been updated since it was built. Slots made before this label existed count as stale
/// once an image id is known. When no id is known (offline, never downloaded) nothing is stale.
fn is_stale(slot_image: Option<&str>, current: Option<&str>) -> bool {
    current.is_some_and(|c| slot_image != Some(c))
}

/// Serialises claiming, so two creates never restore the same slot.
static CLAIM_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static FILLING: AtomicBool = AtomicBool::new(false);

/// What `POST /v1/sandboxes` creates on a Mac when it is given neither a template nor a spec.
pub(crate) fn default_sandbox_spec() -> serde_json::Value {
    serde_json::json!({
        "name": "", "backend": "auto", "image": "debian-13",
        "vcpus": 2, "memory_mib": 2048, "network": {"mode": "user"},
    })
}

fn is_slot(vm: &VmRecord) -> bool {
    vm.backend == BackendKind::Vz
        && vm.labels.get(POOL_LABEL).map(String::as_str) == Some(POOL_VALUE)
}

impl VmManager {
    fn pool_image_id(&self) -> Option<String> {
        fluxvm_image::builtin::current_id(&self.cfg, POOL_IMAGE)
    }

    fn slot_is_stale(&self, slot: &VmRecord) -> bool {
        is_stale(
            slot.labels.get(IMAGE_LABEL).map(String::as_str),
            self.pool_image_id().as_deref(),
        )
    }

    /// Deletes stopped slots built from an older base image; they would restore a guest with outdated packages.
    async fn remove_stale_slots(self: &Arc<Self>) {
        for slot in self
            .list()
            .await
            .into_iter()
            .filter(|v| is_slot(v) && v.status == VmStatus::Stopped && self.slot_is_stale(v))
        {
            tracing::info!(slot = %slot.id, "removing a warm sandbox built from an older image");
            if let Err(e) = self.delete(slot.id).await {
                tracing::warn!(slot = %slot.id, error = %format!("{e:#}"), "removing a stale warm sandbox failed");
            }
        }
    }

    /// Restores a free warm slot and turns it into the sandbox `name` with the given TTL. `None` means "cold-boot one instead".
    pub(crate) async fn claim_warm_sandbox(
        self: &Arc<Self>,
        name: Option<&str>,
        ttl_seconds: Option<u64>,
        created_by_token: Option<&str>,
    ) -> Result<Option<VmRecord>> {
        if self.cfg.sandbox.warm_slots == 0 {
            return Ok(None);
        }
        let _guard = CLAIM_LOCK.lock().await;
        for slot in self
            .list()
            .await
            .into_iter()
            .filter(|v| is_slot(v) && v.status == VmStatus::Stopped && !self.slot_is_stale(v))
        {
            if !self
                .list_vm_snapshots(slot.id)
                .await?
                .iter()
                .any(|s| s.tag == WARM_TAG)
            {
                continue;
            }
            if let Err(e) = self.start_from_snapshot(slot.id, WARM_TAG).await {
                tracing::warn!(slot = %slot.id, error = %format!("{e:#}"), "restoring a warm sandbox failed; cold-booting instead");
                return Ok(None);
            }
            let name = name
                .map(str::to_owned)
                .unwrap_or_else(|| format!("sandbox-{}", Uuid::new_v4()));
            let patch = VmPatch {
                name: Some(name),
                labels: BTreeMap::from([(POOL_LABEL.to_owned(), None)]),
            };
            let mut vm = self.patch(slot.id, patch).await?;
            vm.expires_at =
                ttl_seconds.map(|t| chrono::Utc::now() + chrono::Duration::seconds(t as i64));
            vm.request.ttl_seconds = ttl_seconds;
            vm.request.created_by_token = created_by_token.map(str::to_owned);
            self.store.update(vm.clone()).await?;
            return Ok(Some(vm));
        }
        Ok(None)
    }

    /// Starts refilling the pool in the background (one filler at a time).
    pub(crate) fn spawn_pool_fill(self: &Arc<Self>) {
        let want = self.cfg.sandbox.warm_slots;
        if want == 0 || FILLING.swap(true, Ordering::SeqCst) {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            // Looks for a newer base image (no network unless the last look is over a day old), then drops slots made from the old one.
            if let Some(img) = fluxvm_image::builtin::find(POOL_IMAGE) {
                if let Err(e) = fluxvm_image::builtin::ensure(&this.cfg, img).await {
                    tracing::debug!(error = %format!("{e:#}"), "checking for a newer base image failed");
                }
            }
            this.remove_stale_slots().await;
            loop {
                let have = this.list().await.iter().filter(|v| is_slot(v)).count();
                if have >= want {
                    break;
                }
                if let Err(e) = this.build_warm_slot().await {
                    tracing::warn!(error = %format!("{e:#}"), "building a warm sandbox failed; not retrying until the next sandbox is created");
                    break;
                }
            }
            FILLING.store(false, Ordering::SeqCst);
        });
    }

    /// Cold-boots a default sandbox VM, waits for first-boot setup to finish, snapshots it, and leaves it stopped.
    async fn build_warm_slot(self: &Arc<Self>) -> Result<()> {
        let name = format!("sandbox-slot-{}", &Uuid::new_v4().simple().to_string()[..8]);
        let mut spec: serde_json::Value = default_sandbox_spec();
        spec["name"] = serde_json::json!(name);
        let mut create: CreateVmRequest = serde_json::from_value(spec)?;
        create.backend = BackendKind::Vz;
        self.prepare_vz_sandbox(&mut create)?;
        let vm = self.create(create).await?;
        let built = async {
            let mut labels = BTreeMap::from([(POOL_LABEL.to_owned(), Some(POOL_VALUE.to_owned()))]);
            labels.insert(IMAGE_LABEL.to_owned(), self.pool_image_id());
            self.patch(vm.id, VmPatch { name: None, labels }).await?;
            let guest = self.wait_vz_guest(vm.id, Duration::from_secs(120)).await?;
            // sshd answers before cloud-init is done; snapshot only once first-boot setup has finished.
            let _ = fluxvm_apple::ssh::exec(
                &guest,
                "sudo cloud-init status --wait || cloud-init status --wait",
                Duration::from_secs(120),
            )
            .await;
            self.create_vm_snapshot(vm.id, WARM_TAG)
                .await
                .context("saving the warm snapshot")?;
            self.stop(vm.id)
                .await
                .context("stopping the warm sandbox")?;
            anyhow::Ok(())
        }
        .await;
        if let Err(e) = built {
            let _ = self.delete(vm.id).await;
            bail!("{e:#}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::is_stale;

    #[test]
    fn a_slot_is_stale_only_when_a_different_image_is_current() {
        assert!(!is_stale(Some("aaa"), Some("aaa")));
        assert!(is_stale(Some("aaa"), Some("bbb")));
        assert!(
            is_stale(None, Some("bbb")),
            "built before the label existed"
        );
        assert!(!is_stale(Some("aaa"), None), "nothing is known to be newer");
        assert!(!is_stale(None, None));
    }
}
