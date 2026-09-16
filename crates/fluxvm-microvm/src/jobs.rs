// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::crd::{LABEL_JOB, MicroVM, MicroVMJob, MicroVMJobStatus};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use kube::{
    Api, Client, Resource, ResourceExt,
    api::{DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PostParams},
    runtime::{
        controller::{Action, Controller},
        watcher,
    },
};
use std::{sync::Arc, time::Duration};

/// Reconcile cadence while a job is still active (no change from before).
const STEADY: Duration = Duration::from_secs(10);
/// Floor on the TTL-driven requeue so a huge `ttlSecondsAfterFinished` never
/// produces an effectively-unbounded sleep, and a tiny one never busy-loops.
const TTL_REQUEUE_MIN: Duration = Duration::from_secs(1);

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("kube API error: {0}")]
    Kube(#[from] kube::Error),
}

/// True once `now` has reached `finished_at + ttl_seconds`. Pure so it is
/// unit-testable without a cluster, matching this crate's `policy`/`capacity`
/// convention.
fn ttl_expired(finished_at: DateTime<Utc>, ttl_seconds: u64, now: DateTime<Utc>) -> bool {
    now >= finished_at + chrono::Duration::seconds(ttl_seconds as i64)
}

/// How long to wait before the next reconcile given an optional TTL clock.
/// Sleeps exactly until the deadline (capped at `STEADY` so an operator
/// change to `ttlSecondsAfterFinished` is still noticed reasonably soon)
/// instead of always polling at the same cadence, so a job with a short TTL
/// gets cleaned up promptly rather than sitting around for a whole `STEADY`
/// window after it expires.
fn next_requeue(
    ttl_seconds: Option<u64>,
    finished_at: Option<&str>,
    now: DateTime<Utc>,
) -> Duration {
    if let (Some(ttl), Some(fin)) = (ttl_seconds, finished_at)
        && let Ok(parsed) = DateTime::parse_from_rfc3339(fin)
    {
        let deadline = parsed.with_timezone(&Utc) + chrono::Duration::seconds(ttl as i64);
        if let Ok(remaining) = deadline.signed_duration_since(now).to_std() {
            return remaining.clamp(TTL_REQUEUE_MIN, STEADY);
        }
    }
    STEADY
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
    let now = Utc::now();
    let terminal = phase == "Succeeded" || phase == "Failed";
    // Set once on the reconcile that first observes a terminal phase, then
    // carried forward unchanged — this is the clock ttlSecondsAfterFinished
    // counts from, so re-reconciling an already-finished Job must not push
    // its deletion out indefinitely.
    let finished_at = if terminal {
        Some(
            obj.status
                .as_ref()
                .and_then(|s| s.finished_at.clone())
                .unwrap_or_else(|| now.to_rfc3339()),
        )
    } else {
        None
    };

    if let (Some(ttl), Some(fin)) = (obj.spec.ttl_seconds_after_finished, finished_at.as_deref())
        && let Ok(parsed) = DateTime::parse_from_rfc3339(fin)
        && ttl_expired(parsed.with_timezone(&Utc), ttl, now)
    {
        tracing::info!(
            job = %obj.name_any(),
            ttl_seconds = ttl,
            "MicroVMJob ttlSecondsAfterFinished elapsed; deleting (owned MicroVMs follow via GC)"
        );
        match jobs.delete(&obj.name_any(), &DeleteParams::default()).await {
            Ok(_) => {}
            Err(kube::Error::Api(ae)) if ae.code == 404 => {}
            Err(e) => return Err(e.into()),
        }
        return Ok(Action::await_change());
    }

    jobs.patch_status(
        &obj.name_any(),
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({
            "status": MicroVMJobStatus { phase: phase.into(), active, succeeded, failed, finished_at: finished_at.clone() }
        })),
    ).await?;
    Ok(Action::requeue(next_requeue(
        obj.spec.ttl_seconds_after_finished,
        finished_at.as_deref(),
        now,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn ttl_not_expired_before_deadline() {
        let finished = t("2026-01-01T00:00:00Z");
        let now = t("2026-01-01T00:00:30Z");
        assert!(!ttl_expired(finished, 60, now));
    }

    #[test]
    fn ttl_expired_at_and_after_deadline() {
        let finished = t("2026-01-01T00:00:00Z");
        assert!(ttl_expired(finished, 60, t("2026-01-01T00:01:00Z")));
        assert!(ttl_expired(finished, 60, t("2026-01-01T00:05:00Z")));
    }

    #[test]
    fn zero_ttl_expires_immediately() {
        let finished = t("2026-01-01T00:00:00Z");
        assert!(ttl_expired(finished, 0, finished));
    }

    #[test]
    fn next_requeue_uses_steady_cadence_without_ttl() {
        let now = t("2026-01-01T00:00:00Z");
        assert_eq!(next_requeue(None, None, now), STEADY);
        assert_eq!(next_requeue(Some(60), None, now), STEADY);
    }

    #[test]
    fn next_requeue_sleeps_until_the_ttl_deadline() {
        let finished = "2026-01-01T00:00:00Z";
        let now = t("2026-01-01T00:00:55Z");
        // 60s TTL, 55s already elapsed -> ~5s left, well under the 10s STEADY cap.
        assert_eq!(
            next_requeue(Some(60), Some(finished), now),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn next_requeue_caps_at_steady_for_a_far_off_ttl() {
        let finished = "2026-01-01T00:00:00Z";
        let now = t("2026-01-01T00:00:00Z");
        assert_eq!(next_requeue(Some(3600), Some(finished), now), STEADY);
    }

    #[test]
    fn next_requeue_floors_at_ttl_requeue_min_when_essentially_due() {
        let finished = "2026-01-01T00:00:00Z";
        let now = t("2026-01-01T00:00:59Z");
        assert_eq!(next_requeue(Some(60), Some(finished), now), TTL_REQUEUE_MIN);
    }
}
