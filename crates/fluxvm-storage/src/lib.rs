// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Every `fluxctl create`/`stop`/`pause`/... invocation is a fresh, one-shot
//! CLI process (not just concurrent tasks inside one `serve` daemon), so an
//! in-memory cache populated once at startup is not enough to stay correct:
//! two such processes racing would each load a stale view, each write back
//! only their own change, and the loser's write — or, more subtly, a value
//! like a vsock CID allocation that depended on seeing the other's write —
//! would silently vanish. Every operation here instead takes an OS-level
//! `flock` on a dedicated lock file and re-reads `vms.json` fresh under that
//! lock before mutating and writing it back, so state is coordinated across
//! processes, not just within one.

use anyhow::{Context, Result, bail};
use fluxvm_core::config::Policy;
use fluxvm_core::model::{PoolRecord, VmRecord};
use fluxvm_core::policy::{
    QuotaLedger, UsageTotals, enforce_host_totals, ledger_for_host_admission, ledger_is_warm,
};
use std::{
    collections::HashMap,
    fs,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub struct Store {
    path: PathBuf,
    lock_path: PathBuf,
}

impl Store {
    pub fn load(state_dir: &Path) -> Result<Self> {
        Ok(Self {
            path: state_dir.join("vms.json"),
            lock_path: state_dir.join("vms.lock"),
        })
    }

    fn read_map(path: &Path) -> Result<HashMap<Uuid, VmRecord>> {
        if !path.exists() {
            return Ok(HashMap::new());
        }
        let raw = fs::read_to_string(path).context("reading VM state")?;
        if raw.trim().is_empty() {
            return Ok(HashMap::new());
        }
        serde_json::from_str(&raw).context("parsing VM state")
    }

    /// Runs `f` against a freshly-read map while holding an exclusive lock,
    /// then persists whatever `f` left the map as.
    async fn with_exclusive<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut HashMap<Uuid, VmRecord>) -> (T, LedgerDelta) + Send + 'static,
        T: Send + 'static,
    {
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        tokio::task::spawn_blocking(move || -> Result<T> {
            let lock_file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(&lock_path)
                .context("opening store lock file")?;
            if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                bail!("locking store: {}", std::io::Error::last_os_error());
            }
            let mut map = Self::read_map(&path)?;
            let len_before = map.len() as u64;
            let (result, delta) = f(&mut map);
            let tmp = path.with_extension("json.tmp");
            fs::write(&tmp, serde_json::to_vec_pretty(&map)?).context("writing VM state")?;
            fs::rename(&tmp, &path).context("renaming VM state")?;
            apply_ledger_delta(&path, &map, len_before, delta)?;
            Ok(result)
        })
        .await
        .context("store worker thread panicked")?
    }

    /// Runs `f` against a freshly-read map while holding a shared (read)
    /// lock — coordinates with concurrent `with_exclusive` writers without
    /// blocking other concurrent readers against each other.
    async fn with_shared<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&HashMap<Uuid, VmRecord>) -> T + Send + 'static,
        T: Send + 'static,
    {
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        tokio::task::spawn_blocking(move || -> Result<T> {
            let lock_file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(&lock_path)
                .context("opening store lock file")?;
            if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_SH) } != 0 {
                bail!("locking store: {}", std::io::Error::last_os_error());
            }
            let map = Self::read_map(&path)?;
            Ok(f(&map))
        })
        .await
        .context("store worker thread panicked")?
    }

    pub async fn insert(&self, vm: VmRecord) -> Result<()> {
        self.with_exclusive(move |m| {
            let sample = quota_sample(&vm);
            m.insert(vm.id, vm);
            ((), LedgerDelta::Ingest(sample))
        })
        .await
    }

    /// Inserts `record`, first assigning it the lowest vsock CID `>= first_cid`
    /// not already used by another stored VM, when `needs_cid` is set — done
    /// under the *same* exclusive lock as the insert itself. Deciding the CID
    /// via `list()` and inserting via a separate `insert()` call would still
    /// race across two concurrent processes (both could read the same "free"
    /// CID before either persists); folding both into one locked operation
    /// closes that window.
    pub async fn insert_with_cid(
        &self,
        mut record: VmRecord,
        needs_cid: bool,
        first_cid: u32,
    ) -> Result<VmRecord> {
        self.with_exclusive(move |m| {
            if needs_cid {
                let used: std::collections::HashSet<u32> =
                    m.values().filter_map(|v| v.guest_cid).collect();
                let mut candidate = first_cid;
                while used.contains(&candidate) {
                    candidate += 1;
                }
                record.guest_cid = Some(candidate);
            }
            let sample = quota_sample(&record);
            m.insert(record.id, record.clone());
            (record, LedgerDelta::Ingest(sample))
        })
        .await
    }

    /// Replaces an existing record; does nothing if it is gone. Creation goes through
    /// [`insert`](Self::insert) / [`insert_with_cid`](Self::insert_with_cid).
    ///
    /// This used to be an upsert, so a slow writer holding a stale copy (a `stop()` still finishing,
    /// the reconcile loop) re-created a record that `delete` had just removed: the API answered 204
    /// and the VM stayed listed as `stopped` forever.
    pub async fn update(&self, vm: VmRecord) -> Result<()> {
        self.with_exclusive(move |m| {
            let Some(slot) = m.get_mut(&vm.id) else {
                return ((), LedgerDelta::Preserve);
            };
            let from = quota_sample(slot);
            let to = quota_sample(&vm);
            *slot = vm;
            let delta = if from == to {
                LedgerDelta::Preserve
            } else {
                LedgerDelta::Replace { from, to }
            };
            ((), delta)
        })
        .await
    }

    pub async fn get(&self, id: Uuid) -> Option<VmRecord> {
        self.with_shared(move |m| m.get(&id).cloned())
            .await
            .ok()
            .flatten()
    }

    pub async fn list(&self) -> Vec<VmRecord> {
        self.with_shared(|m| {
            let mut v: Vec<_> = m.values().cloned().collect();
            v.sort_by_key(|r| r.created_at);
            v
        })
        .await
        .unwrap_or_default()
    }

    pub async fn remove(&self, id: Uuid) -> Result<Option<VmRecord>> {
        self.with_exclusive(move |m| {
            let removed = m.remove(&id);
            let delta = removed
                .as_ref()
                .map(|vm| LedgerDelta::Release(quota_sample(vm)))
                .unwrap_or(LedgerDelta::Preserve);
            (removed, delta)
        })
        .await
    }

    /// O(1) when `quotas.json` matches the store length. Rebuilds from the
    /// map only when the file is missing or the VM count disagrees.
    pub async fn quota_ledger(&self) -> Result<QuotaLedger> {
        let path = self.path.clone();
        self.with_shared(move |m| load_quota_ledger(&path, m)).await
    }

    /// Rewrite the ledger from the current store. Called when `fluxctl serve`
    /// starts so a crash between the VM file and the ledger cannot stick.
    /// Receiver reservations in `untracked_host` are kept.
    pub async fn rebuild_quota_ledger(&self) -> Result<QuotaLedger> {
        self.with_exclusive(|_| ((), LedgerDelta::Rebuild)).await?;
        self.quota_ledger().await
    }

    /// Charge `vcpus` and `memory_mib` against the host cap without adding a
    /// VM record. The check and the write share the store lock.
    pub async fn reserve_untracked_host(
        &self,
        vcpus: u8,
        memory_mib: u64,
        policy: &Policy,
    ) -> Result<()> {
        let policy = policy.clone();
        self.mutate_quota(move |ledger| {
            enforce_host_totals(
                vcpus,
                memory_mib,
                &policy,
                &ledger_for_host_admission(ledger),
            )?;
            ledger.untracked_host.vcpus =
                ledger.untracked_host.vcpus.saturating_add(u64::from(vcpus));
            ledger.untracked_host.memory_mib =
                ledger.untracked_host.memory_mib.saturating_add(memory_mib);
            Ok(())
        })
        .await
    }

    /// Return a reservation taken by [`Self::reserve_untracked_host`].
    pub async fn release_untracked_host(&self, vcpus: u8, memory_mib: u64) -> Result<()> {
        self.mutate_quota(move |ledger| {
            ledger.untracked_host.vcpus =
                ledger.untracked_host.vcpus.saturating_sub(u64::from(vcpus));
            ledger.untracked_host.memory_mib =
                ledger.untracked_host.memory_mib.saturating_sub(memory_mib);
            Ok(())
        })
        .await
    }

    /// Replace receiver reservations with the totals still on disk. Used once
    /// at serve startup, after expired receivers have been removed.
    pub async fn set_untracked_host(&self, vcpus: u64, memory_mib: u64) -> Result<()> {
        self.mutate_quota(move |ledger| {
            ledger.untracked_host.vms = 0;
            ledger.untracked_host.vcpus = vcpus;
            ledger.untracked_host.memory_mib = memory_mib;
            Ok(())
        })
        .await
    }

    async fn mutate_quota<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut QuotaLedger) -> Result<()> + Send + 'static,
    {
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let lock_file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(&lock_path)
                .context("opening store lock file")?;
            if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                bail!("locking store: {}", std::io::Error::last_os_error());
            }
            let map = Self::read_map(&path)?;
            let mut ledger = load_quota_ledger(&path, &map);
            f(&mut ledger)?;
            write_quota_ledger(&path, &ledger)?;
            Ok(())
        })
        .await
        .context("store worker thread panicked")?
    }
}

#[derive(Clone, PartialEq, Eq)]
struct QuotaSample {
    tenant: Option<String>,
    token: Option<String>,
    vcpus: u8,
    memory_mib: u64,
}

enum LedgerDelta {
    /// Status-only write. The ledger totals do not change, so the VM map is
    /// not walked again. The existing `quotas.json` bytes are copied forward
    /// so a newer `vms.json` does not look like a crashed quota update.
    Preserve,
    Ingest(QuotaSample),
    Release(QuotaSample),
    Replace {
        from: QuotaSample,
        to: QuotaSample,
    },
    Rebuild,
}

fn quota_sample(vm: &VmRecord) -> QuotaSample {
    QuotaSample {
        tenant: vm
            .request
            .tenant
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        token: vm
            .request
            .created_by_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        vcpus: vm.request.vcpus,
        memory_mib: vm.request.memory_mib,
    }
}

fn apply_sample(ledger: &mut QuotaLedger, sample: &QuotaSample, release: bool) {
    let tenant = sample.tenant.as_deref();
    let token = sample.token.as_deref();
    if release {
        ledger.release(tenant, token, sample.vcpus, sample.memory_mib);
    } else {
        ledger.ingest(tenant, token, sample.vcpus, sample.memory_mib);
    }
}

fn apply_ledger_delta(
    vms_path: &Path,
    map: &HashMap<Uuid, VmRecord>,
    len_before: u64,
    delta: LedgerDelta,
) -> Result<()> {
    match delta {
        LedgerDelta::Preserve => {
            let quota_path = vms_path.with_file_name("quotas.json");
            if let Ok(bytes) = fs::read(&quota_path) {
                write_quota_bytes(vms_path, &bytes)?;
            }
            Ok(())
        }
        LedgerDelta::Rebuild => {
            let mut ledger = quota_ledger_from(map);
            ledger.untracked_host = read_untracked_host(vms_path);
            write_quota_ledger(vms_path, &ledger)
        }
        other => {
            if let Some(mut ledger) = read_warm_ledger(vms_path, len_before) {
                match other {
                    LedgerDelta::Ingest(sample) => apply_sample(&mut ledger, &sample, false),
                    LedgerDelta::Release(sample) => apply_sample(&mut ledger, &sample, true),
                    LedgerDelta::Replace { from, to } => {
                        apply_sample(&mut ledger, &from, true);
                        apply_sample(&mut ledger, &to, false);
                    }
                    LedgerDelta::Preserve | LedgerDelta::Rebuild => {}
                }
                write_quota_ledger(vms_path, &ledger)
            } else {
                let mut ledger = quota_ledger_from(map);
                ledger.untracked_host = read_untracked_host(vms_path);
                write_quota_ledger(vms_path, &ledger)
            }
        }
    }
}

fn quota_ledger_from(map: &HashMap<Uuid, VmRecord>) -> QuotaLedger {
    let mut ledger = QuotaLedger::default();
    for vm in map.values() {
        ledger.ingest(
            vm.request.tenant.as_deref(),
            vm.request.created_by_token.as_deref(),
            vm.request.vcpus,
            vm.request.memory_mib,
        );
    }
    ledger
}

fn write_quota_bytes(vms_path: &Path, bytes: &[u8]) -> Result<()> {
    let quota_path = vms_path.with_file_name("quotas.json");
    let tmp = quota_path.with_extension("json.tmp");
    fs::write(&tmp, bytes).context("writing quota ledger")?;
    fs::rename(&tmp, &quota_path).context("renaming quota ledger")?;
    Ok(())
}

fn write_quota_ledger(vms_path: &Path, ledger: &QuotaLedger) -> Result<()> {
    write_quota_bytes(vms_path, &serde_json::to_vec(ledger)?)
}

/// A ledger is warm only when its VM count matches the store *and* it was
/// written at least as recently as `vms.json`. A crash between the two
/// renames leaves the VM file newer, and the next admission rebuilds.
fn read_warm_ledger(vms_path: &Path, vm_count: u64) -> Option<QuotaLedger> {
    let quota_path = vms_path.with_file_name("quotas.json");
    let vms_modified = vms_path.metadata().and_then(|m| m.modified()).ok()?;
    let quota_modified = quota_path.metadata().and_then(|m| m.modified()).ok()?;
    if quota_modified < vms_modified {
        return None;
    }
    let raw = fs::read_to_string(&quota_path).ok()?;
    let ledger = serde_json::from_str::<QuotaLedger>(&raw).ok()?;
    ledger_is_warm(ledger.host.vms, vm_count).then_some(ledger)
}

fn read_untracked_host(vms_path: &Path) -> UsageTotals {
    let quota_path = vms_path.with_file_name("quotas.json");
    let Ok(raw) = fs::read_to_string(&quota_path) else {
        return UsageTotals::default();
    };
    serde_json::from_str::<QuotaLedger>(&raw)
        .map(|ledger| ledger.untracked_host)
        .unwrap_or_default()
}

fn load_quota_ledger(vms_path: &Path, map: &HashMap<Uuid, VmRecord>) -> QuotaLedger {
    if let Some(ledger) = read_warm_ledger(vms_path, map.len() as u64) {
        return ledger;
    }
    let mut ledger = quota_ledger_from(map);
    ledger.untracked_host = read_untracked_host(vms_path);
    ledger
}

/// Same flock-per-operation, read-fresh-under-lock discipline as [`Store`]
/// (see the module doc comment for why that matters across separate CLI
/// processes), applied to warm-pool records instead of VM records, keyed by
/// pool name and persisted in its own `pools.json`/`pools.lock` pair. Kept
/// as a separate small type rather than a generic `Store<K, V>` — the two
/// have different enough key types and call sites that a shared abstraction
/// would cost more in indirection than the ~40 lines it'd save.
pub struct PoolStore {
    path: PathBuf,
    lock_path: PathBuf,
}

impl PoolStore {
    pub fn load(state_dir: &Path) -> Result<Self> {
        Ok(Self {
            path: state_dir.join("pools.json"),
            lock_path: state_dir.join("pools.lock"),
        })
    }

    fn read_map(path: &Path) -> Result<HashMap<String, PoolRecord>> {
        if !path.exists() {
            return Ok(HashMap::new());
        }
        let raw = fs::read_to_string(path).context("reading pool state")?;
        if raw.trim().is_empty() {
            return Ok(HashMap::new());
        }
        serde_json::from_str(&raw).context("parsing pool state")
    }

    async fn with_exclusive<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut HashMap<String, PoolRecord>) -> T + Send + 'static,
        T: Send + 'static,
    {
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        tokio::task::spawn_blocking(move || -> Result<T> {
            let lock_file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(&lock_path)
                .context("opening pool store lock file")?;
            if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                bail!("locking pool store: {}", std::io::Error::last_os_error());
            }
            let mut map = Self::read_map(&path)?;
            let result = f(&mut map);
            let tmp = path.with_extension("json.tmp");
            fs::write(&tmp, serde_json::to_vec_pretty(&map)?).context("writing pool state")?;
            fs::rename(&tmp, &path).context("renaming pool state")?;
            Ok(result)
        })
        .await
        .context("pool store worker thread panicked")?
    }

    async fn with_shared<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&HashMap<String, PoolRecord>) -> T + Send + 'static,
        T: Send + 'static,
    {
        let path = self.path.clone();
        let lock_path = self.lock_path.clone();
        tokio::task::spawn_blocking(move || -> Result<T> {
            let lock_file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(&lock_path)
                .context("opening pool store lock file")?;
            if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_SH) } != 0 {
                bail!("locking pool store: {}", std::io::Error::last_os_error());
            }
            let map = Self::read_map(&path)?;
            Ok(f(&map))
        })
        .await
        .context("pool store worker thread panicked")?
    }

    pub async fn insert(&self, pool: PoolRecord) -> Result<()> {
        self.with_exclusive(move |m| {
            m.insert(pool.name.clone(), pool);
        })
        .await
    }

    pub async fn get(&self, name: &str) -> Option<PoolRecord> {
        let name = name.to_string();
        self.with_shared(move |m| m.get(&name).cloned())
            .await
            .ok()
            .flatten()
    }

    pub async fn list(&self) -> Vec<PoolRecord> {
        self.with_shared(|m| {
            let mut v: Vec<_> = m.values().cloned().collect();
            v.sort_by_key(|p| p.name.clone());
            v
        })
        .await
        .unwrap_or_default()
    }

    pub async fn remove(&self, name: &str) -> Result<Option<PoolRecord>> {
        let name = name.to_string();
        self.with_exclusive(move |m| m.remove(&name)).await
    }

    /// Atomically pops one member id off `name`'s pool (so two concurrent
    /// claims can never receive the same VM) and returns it, or `None` if
    /// the pool has no ready members right now.
    pub async fn pop_member(&self, name: &str) -> Result<Option<Uuid>> {
        let name = name.to_string();
        self.with_exclusive(move |m| m.get_mut(&name).and_then(|p| p.members.pop()))
            .await
    }

    /// Atomically appends a freshly-backfilled member id to `name`'s pool.
    /// A no-op (not an error) if the pool was deleted concurrently — the
    /// backfill task that produced `member` should then just clean it up
    /// itself rather than resurrect a deleted pool.
    pub async fn push_member(&self, name: &str, member: Uuid) -> Result<bool> {
        let name = name.to_string();
        self.with_exclusive(move |m| match m.get_mut(&name) {
            Some(p) => {
                p.members.push(member);
                true
            }
            None => false,
        })
        .await
    }

    /// Atomically bumps `name`'s lifetime `claimed_total` by one. A no-op
    /// (not an error) if the pool doesn't exist any more — called from
    /// `VmManager::claim_from_pool` after a claim has already fully
    /// succeeded (member resumed, tenant checked), so a pool deleted in the
    /// narrow window between those two steps should never turn a completed
    /// claim into a hard error over a stats counter that no longer has
    /// anywhere to live.
    pub async fn increment_claimed(&self, name: &str) -> Result<()> {
        let name = name.to_string();
        self.with_exclusive(move |m| {
            if let Some(p) = m.get_mut(&name) {
                p.claimed_total += 1;
            }
        })
        .await
    }

    /// Atomically overwrites `name`'s target `size`, returning the updated
    /// record, or `None` if the pool doesn't exist. Does not touch
    /// `members` at all — the caller (`VmManager::resize_pool`) is
    /// responsible for growing (backfill) or shrinking (pop + delete)
    /// membership afterward to match the new size; this method only ever
    /// changes the *target*, the same "one field, one writer" shape as
    /// `push_member`/`pop_member` each only ever touching `members`.
    pub async fn set_size(&self, name: &str, size: usize) -> Result<Option<PoolRecord>> {
        let name = name.to_string();
        self.with_exclusive(move |m| {
            m.get_mut(&name).map(|p| {
                p.size = size;
                p.clone()
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use fluxvm_core::model::{BackendKind, CreateVmRequest, NetworkSpec, VmStatus};
    use std::collections::HashSet;

    fn fixture_record(name: &str) -> VmRecord {
        let id = Uuid::new_v4();
        VmRecord {
            id,
            name: name.to_string(),
            backend: BackendKind::Qemu,
            status: VmStatus::Creating,
            pid: None,
            created_at: Utc::now(),
            expires_at: None,
            workspace: PathBuf::from("/tmp/does-not-matter"),
            disk: PathBuf::from("/tmp/does-not-matter/root.qcow2"),
            seed_disk: None,
            tap_name: None,
            control_socket: None,
            log_path: PathBuf::from("/tmp/does-not-matter/console.log"),
            error: None,
            request: CreateVmRequest {
                name: name.to_string(),
                tenant: None,
                created_by_token: None,
                backend: BackendKind::Qemu,
                image: PathBuf::from("/tmp/base.qcow2"),
                vcpus: 1,
                memory_mib: 512,
                max_vcpus: None,
                max_memory_mib: None,
                loadvm_tag: None,
                disk_size_gib: None,
                kernel: None,
                initrd: None,
                firmware: None,
                kernel_args: None,
                network: NetworkSpec::None,
                cloud_init: None,
                ttl_seconds: None,
                extra_args: vec![],
                shared_memory: false,
                agent: None,
                qga: None,
                hyperv: false,
                storage: Default::default(),
                shared_folders: vec![],
                numa_node: None,
                cpuset: None,
                hugepages: None,
                vfio_devices: vec![],
                pod_uid: None,
                secure_boot: None,
                tpm: None,
                net_mbit_limit: None,
                net_pps_limit: None,
                blk_mbit_limit: None,
                blk_ops_limit: None,
                cpu_template: None,
                security_profile: Default::default(),
                measurement_policy: None,
            },
            guest_cid: None,
            jail_path: None,
            vsock_socket: None,
            qga_socket: None,
            cgroup_path: None,
            netns: None,
            lvm_lv: None,
            nbd_pid: None,
            virtiofsd_pids: vec![],
            swtpm_pid: None,
            dhcp_leasefile: None,
            guest_ip: None,
            requested_security_profile: Default::default(),
            achieved_security_profile: Default::default(),
            security_evidence: None,
        }
    }

    #[tokio::test]
    async fn insert_get_list_remove_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::load(dir.path()).unwrap();
        let vm = fixture_record("a");
        let id = vm.id;

        store.insert(vm.clone()).await.unwrap();
        assert_eq!(store.get(id).await.unwrap().name, "a");
        assert_eq!(store.list().await.len(), 1);

        let removed = store.remove(id).await.unwrap();
        assert_eq!(removed.unwrap().id, id);
        assert!(store.get(id).await.is_none());
        assert_eq!(store.list().await.len(), 0);
    }

    #[tokio::test]
    async fn a_late_update_does_not_resurrect_a_deleted_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::load(dir.path()).unwrap();
        let vm = fixture_record("doomed");
        let id = vm.id;
        store.insert(vm.clone()).await.unwrap();

        // `delete` removes the record while another task still holds its own copy...
        store.remove(id).await.unwrap();
        // ...and then writes it back (stop() finishing, the reconcile loop, an exit monitor).
        let mut stale = vm;
        stale.status = VmStatus::Stopped;
        store.update(stale).await.unwrap();

        assert!(
            store.get(id).await.is_none(),
            "the deleted VM must stay deleted"
        );
        assert!(store.list().await.is_empty());
    }

    #[tokio::test]
    async fn update_replaces_an_existing_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::load(dir.path()).unwrap();
        let mut vm = fixture_record("live");
        store.insert(vm.clone()).await.unwrap();
        vm.status = VmStatus::Running;
        store.update(vm.clone()).await.unwrap();
        assert_eq!(store.get(vm.id).await.unwrap().status, VmStatus::Running);
    }

    #[tokio::test]
    async fn a_second_store_instance_sees_the_first_ones_writes() {
        // Simulates two separate `fluxvm` CLI processes pointed at the
        // same state_dir: each gets its own Store, loaded independently.
        let dir = tempfile::tempdir().unwrap();
        let store_a = Store::load(dir.path()).unwrap();
        let vm = fixture_record("from-a");
        store_a.insert(vm.clone()).await.unwrap();

        let store_b = Store::load(dir.path()).unwrap();
        let seen = store_b.get(vm.id).await;
        assert!(
            seen.is_some(),
            "a fresh Store instance must see another instance's writes"
        );
        assert_eq!(seen.unwrap().name, "from-a");
    }

    #[tokio::test]
    async fn insert_with_cid_skips_used_cids() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::load(dir.path()).unwrap();

        let mut taken = fixture_record("taken-3");
        taken.guest_cid = Some(3);
        store.insert(taken).await.unwrap();

        let assigned = store
            .insert_with_cid(fixture_record("wants-cid"), true, 3)
            .await
            .unwrap();
        assert_eq!(
            assigned.guest_cid,
            Some(4),
            "CID 3 is taken, so the next VM must get 4"
        );
    }

    #[tokio::test]
    async fn insert_with_cid_is_race_free_across_concurrent_processes() {
        // Regression test for a real bug: allocating a CID via list() and
        // inserting via a separate insert() call let two concurrent
        // processes both compute the same "lowest free" CID before either
        // persisted, so they'd collide (confirmed via a live 4-way
        // concurrent `fluxctl create` stress test before this was fixed).
        // Each spawned task here gets its OWN Store — a fresh `load()`, not
        // a shared handle — to accurately simulate separate OS processes
        // racing on the same vms.json rather than just concurrent tasks
        // sharing one in-process Store.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let mut handles = Vec::new();
        for i in 0..8 {
            let path = path.clone();
            handles.push(tokio::spawn(async move {
                let store = Store::load(&path).unwrap();
                store
                    .insert_with_cid(fixture_record(&format!("race-{i}")), true, 3)
                    .await
                    .unwrap()
            }));
        }

        let mut cids = Vec::new();
        for h in handles {
            cids.push(h.await.unwrap().guest_cid.expect("CID must be assigned"));
        }

        let unique: HashSet<u32> = cids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            cids.len(),
            "all concurrently-assigned CIDs must be distinct: {cids:?}"
        );

        let store = Store::load(&path).unwrap();
        assert_eq!(
            store.list().await.len(),
            8,
            "no concurrent write should have been silently lost"
        );
    }

    fn fixture_pool(name: &str) -> fluxvm_core::model::PoolRecord {
        fluxvm_core::model::PoolRecord {
            name: name.to_string(),
            size: 2,
            template: fixture_record("template").request,
            members: vec![],
            claimed_total: 0,
        }
    }

    #[tokio::test]
    async fn pool_insert_get_list_remove_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = PoolStore::load(dir.path()).unwrap();
        store.insert(fixture_pool("a")).await.unwrap();

        assert_eq!(store.get("a").await.unwrap().size, 2);
        assert_eq!(store.list().await.len(), 1);
        assert!(store.remove("a").await.unwrap().is_some());
        assert!(store.get("a").await.is_none());
    }

    #[tokio::test]
    async fn push_and_pop_member_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = PoolStore::load(dir.path()).unwrap();
        store.insert(fixture_pool("a")).await.unwrap();

        let id = Uuid::new_v4();
        assert!(store.push_member("a", id).await.unwrap());
        assert_eq!(store.get("a").await.unwrap().members, vec![id]);

        let popped = store.pop_member("a").await.unwrap();
        assert_eq!(popped, Some(id));
        assert!(store.get("a").await.unwrap().members.is_empty());
        assert_eq!(
            store.pop_member("a").await.unwrap(),
            None,
            "popping an empty pool must not error"
        );
    }

    #[tokio::test]
    async fn push_member_on_deleted_pool_is_a_harmless_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let store = PoolStore::load(dir.path()).unwrap();
        // No insert — "a" was never created (or was already deleted).
        assert!(!store.push_member("a", Uuid::new_v4()).await.unwrap());
    }

    #[tokio::test]
    async fn set_size_updates_the_stored_record_without_touching_members() {
        let dir = tempfile::tempdir().unwrap();
        let store = PoolStore::load(dir.path()).unwrap();
        store.insert(fixture_pool("a")).await.unwrap();
        let id = Uuid::new_v4();
        store.push_member("a", id).await.unwrap();

        let updated = store.set_size("a", 5).await.unwrap().unwrap();
        assert_eq!(updated.size, 5);
        assert_eq!(updated.members, vec![id], "set_size must not touch members");
        assert_eq!(store.get("a").await.unwrap().size, 5);
    }

    #[tokio::test]
    async fn set_size_on_missing_pool_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = PoolStore::load(dir.path()).unwrap();
        assert!(store.set_size("does-not-exist", 3).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn increment_claimed_bumps_the_counter_each_call() {
        let dir = tempfile::tempdir().unwrap();
        let store = PoolStore::load(dir.path()).unwrap();
        store.insert(fixture_pool("a")).await.unwrap();
        assert_eq!(store.get("a").await.unwrap().claimed_total, 0);

        store.increment_claimed("a").await.unwrap();
        assert_eq!(store.get("a").await.unwrap().claimed_total, 1);

        store.increment_claimed("a").await.unwrap();
        store.increment_claimed("a").await.unwrap();
        assert_eq!(store.get("a").await.unwrap().claimed_total, 3);
    }

    #[tokio::test]
    async fn increment_claimed_on_deleted_pool_is_a_harmless_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let store = PoolStore::load(dir.path()).unwrap();
        // No insert — "a" was never created (or was already deleted between
        // a claim popping its member and the increment that follows).
        store.increment_claimed("a").await.unwrap();
    }

    #[tokio::test]
    async fn pop_member_is_race_free_across_concurrent_processes() {
        // Same regression shape as insert_with_cid_is_race_free_across_concurrent_processes:
        // each task gets its OWN PoolStore (a fresh load(), simulating a
        // separate `fluxctl pool claim` CLI invocation), racing to pop
        // members off a pool pre-seeded with 8 — a real bug here would let
        // two concurrent claims hand out the same VM id.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let store = PoolStore::load(&path).unwrap();
        let mut seeded = fixture_pool("a");
        seeded.members = (0..8).map(|_| Uuid::new_v4()).collect();
        let all_ids: HashSet<Uuid> = seeded.members.iter().copied().collect();
        store.insert(seeded).await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let path = path.clone();
            handles.push(tokio::spawn(async move {
                let store = PoolStore::load(&path).unwrap();
                store.pop_member("a").await.unwrap()
            }));
        }
        let mut popped = Vec::new();
        for h in handles {
            popped.push(
                h.await
                    .unwrap()
                    .expect("every claim should get a member — 8 popped from 8 seeded"),
            );
        }

        let unique: HashSet<Uuid> = popped.iter().copied().collect();
        assert_eq!(
            unique.len(),
            popped.len(),
            "no two concurrent claims may pop the same member: {popped:?}"
        );
        assert_eq!(unique, all_ids);
        assert!(store.get("a").await.unwrap().members.is_empty());
    }

    #[tokio::test]
    async fn warm_quota_ledger_is_not_rebuilt_from_vm_records() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::load(dir.path()).unwrap();
        let mut vm = fixture_record("a");
        vm.request.tenant = Some("acme".into());
        vm.request.created_by_token = Some("tok".into());
        vm.request.vcpus = 2;
        vm.request.memory_mib = 512;
        store.insert(vm).await.unwrap();
        let ledger = store.quota_ledger().await.unwrap();
        assert_eq!(ledger.host.vms, 1);
        assert_eq!(ledger.tenants["acme"].vcpus, 2);
        assert_eq!(ledger.tokens["tok"].memory_mib, 512);

        let path = dir.path().join("quotas.json");
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        raw["host"]["memory_mib"] = serde_json::json!(999);
        std::fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
        let warm = store.quota_ledger().await.unwrap();
        assert_eq!(
            warm.host.memory_mib, 999,
            "a warm ledger is read as-is; create does not rescan VM records"
        );
        let rebuilt = store.rebuild_quota_ledger().await.unwrap();
        assert_eq!(rebuilt.host.memory_mib, 512);
    }

    #[tokio::test]
    async fn status_update_keeps_the_warm_ledger_without_rescanning() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::load(dir.path()).unwrap();
        let mut vm = fixture_record("a");
        vm.request.vcpus = 2;
        vm.request.memory_mib = 512;
        store.insert(vm.clone()).await.unwrap();
        let path = dir.path().join("quotas.json");
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        raw["host"]["memory_mib"] = serde_json::json!(999);
        std::fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
        vm.status = VmStatus::Paused;
        store.update(vm).await.unwrap();
        let warm = store.quota_ledger().await.unwrap();
        assert_eq!(warm.host.memory_mib, 999);
        assert_eq!(warm.host.vcpus, 2);
    }

    #[tokio::test]
    async fn receiver_reservation_counts_against_the_host_cap() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::load(dir.path()).unwrap();
        let mut vm = fixture_record("a");
        vm.request.vcpus = 2;
        vm.request.memory_mib = 512;
        store.insert(vm.clone()).await.unwrap();
        let mut policy = fluxvm_core::config::Policy::default();
        policy.max_vcpus_host = Some(4);
        policy.max_memory_mib_host = Some(1024);
        store.reserve_untracked_host(2, 512, &policy).await.unwrap();
        let ledger = store.quota_ledger().await.unwrap();
        assert_eq!(ledger.host.vms, 1);
        assert_eq!(ledger.host.vcpus, 2);
        assert_eq!(ledger.untracked_host.vcpus, 2);
        assert_eq!(ledger.untracked_host.memory_mib, 512);
        let err = store
            .reserve_untracked_host(1, 64, &policy)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("max_vcpus_host"));
        let rebuilt = store.rebuild_quota_ledger().await.unwrap();
        assert_eq!(rebuilt.untracked_host.vcpus, 2);
        assert_eq!(rebuilt.host.vcpus, 2);
        vm.status = VmStatus::Paused;
        store.update(vm).await.unwrap();
        let warm = store.quota_ledger().await.unwrap();
        assert_eq!(warm.untracked_host.vcpus, 2);
        assert_eq!(warm.host.vms, 1);
        store.release_untracked_host(2, 512).await.unwrap();
        let released = store.quota_ledger().await.unwrap();
        assert_eq!(released.untracked_host.vcpus, 0);
        assert_eq!(released.untracked_host.memory_mib, 0);
        assert_eq!(released.host.vcpus, 2);
    }
}
