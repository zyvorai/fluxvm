// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Safe speculative execution: run a command in an isolated copy of a
//! sandbox, keep what it changed as a *changeset*, and let a caller approve
//! and apply (or reject) it.
//!
//! A changeset moves through a small state machine, persisted under
//! `state_dir/changesets/<id>/`:
//!
//! ```text
//! pending -> approved -> applied
//!    |          |-> failed          (apply started and did not finish)
//!    |-> rejected / expired         (expired is also reachable from approved)
//! ```
//!
//! * Where the command runs: a procbox sandbox runs on a throwaway copy of
//!   its workspace; a flux-vm sandbox runs on a fork (`fork.rs`) when
//!   `check_forkable` passes, otherwise on the snapshot-and-restore path of
//!   the dry-run (`vm_restore.rs`). Either way the real sandbox is untouched.
//! * What is kept: the diff (`changes.rs`), the contents of every added or
//!   modified file (staged beside the changeset, size bounded) and the
//!   manifest of the files the command started from (`base`).
//! * Side effects: the report declares what the speculation could have done
//!   outside the sandbox. File changes are replayable; network effects never
//!   are, and `apply` replays nothing but file changes.
//! * Apply: refuses unless the changeset is approved and the real files still
//!   match `base` exactly (otherwise it is a conflict and nothing is written).

use crate::changes::{ChangeSet, Manifest, diff_manifests, validate_paths};
use crate::procbox_sandbox::{
    ProcboxError, ProcboxSpec, Root, TempTree, files_root, is_procbox, load_spec, run_confined,
};
use crate::{VmManager, audit_event};
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use fluxvm_core::config::ProcboxConfig;
use fluxvm_core::model::{NetworkSpec, VmRecord, VmStatus};
use fluxvm_guest_protocol::AgentResponse;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use uuid::Uuid;

/// Subdirectory of `state_dir` holding changesets.
pub const CHANGESETS_DIR: &str = "changesets";
/// Lifetime of a changeset that is not decided, unless the caller asks less.
pub const DEFAULT_TTL_SECS: u64 = 3600;
/// Longest TTL a caller may request.
pub const MAX_TTL_SECS: u64 = 24 * 3600;
/// How long a finished changeset (applied, rejected, expired, failed) is kept.
pub const TERMINAL_RETENTION_SECS: u64 = 24 * 3600;
/// Largest single file staged for apply.
pub const MAX_STAGED_FILE_BYTES: u64 = 16 << 20;
/// Largest total staged per changeset.
pub const MAX_STAGED_TOTAL_BYTES: u64 = 64 << 20;
/// Captured command output kept in the changeset, per stream.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------- state ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangesetState {
    Pending,
    Approved,
    Applied,
    Rejected,
    Expired,
    /// Apply started and did not complete; the sandbox may hold part of it.
    Failed,
}

impl ChangesetState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Approved)
    }

    pub fn can_transition_to(self, to: Self) -> bool {
        use ChangesetState::*;
        matches!(
            (self, to),
            (Pending, Approved)
                | (Pending, Rejected)
                | (Pending, Expired)
                | (Approved, Applied)
                | (Approved, Rejected)
                | (Approved, Expired)
                | (Approved, Failed)
        )
    }
}

/// Typed failures the API layer maps to HTTP statuses.
#[derive(Debug)]
pub enum ChangesetError {
    NotFound(Uuid),
    InvalidTransition {
        from: ChangesetState,
        to: ChangesetState,
    },
    /// The real files no longer match the changeset's base.
    Conflict(Vec<String>),
    Expired(Uuid),
    /// Another request is working on this changeset.
    Busy(Uuid),
    /// The changeset cannot be applied (for example an unstaged file).
    NotApplicable(String),
}

impl std::fmt::Display for ChangesetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(id) => write!(f, "changeset {id} not found"),
            Self::InvalidTransition { from, to } => write!(
                f,
                "changeset is {}; it cannot become {}",
                from.as_str(),
                to.as_str()
            ),
            Self::Conflict(paths) => {
                let shown: Vec<&str> = paths.iter().take(10).map(String::as_str).collect();
                write!(
                    f,
                    "conflict: {} file(s) changed in the sandbox since the changeset was taken \
                     (nothing was applied): {}{}",
                    paths.len(),
                    shown.join(", "),
                    if paths.len() > shown.len() {
                        ", ..."
                    } else {
                        ""
                    }
                )
            }
            Self::Expired(id) => write!(f, "changeset {id} has expired"),
            Self::Busy(id) => write!(f, "another request is already working on changeset {id}"),
            Self::NotApplicable(why) => write!(f, "changeset cannot be applied: {why}"),
        }
    }
}

impl std::error::Error for ChangesetError {}

/// Move `cs` to `to`, stamping the time. Pure apart from mutating `cs`.
pub fn transition(cs: &mut Changeset, to: ChangesetState, now: u64) -> Result<(), ChangesetError> {
    if !cs.state.can_transition_to(to) {
        return Err(ChangesetError::InvalidTransition { from: cs.state, to });
    }
    cs.state = to;
    cs.updated_at = now;
    Ok(())
}

// ----------------------------------------------------------- side effects ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    /// The speculation had no network.
    Blocked,
    /// Only allow-listed destinations were reachable; they are recorded.
    AllowListed,
    /// Network was not restricted; external effects are unknown.
    Unrestricted,
}

/// What the speculative run could have done outside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SideEffects {
    pub egress: EgressMode,
    /// Allow-listed destinations, recorded when `egress` is `allow_listed`.
    pub destinations: Vec<String>,
    /// Effects `apply` will reproduce: file changes inside the sandbox.
    pub replayable: Vec<String>,
    /// Effects that may have happened for real and are never replayed.
    pub non_replayable: Vec<String>,
}

/// Build the side-effects report. Pure.
pub fn declare_side_effects(
    egress: EgressMode,
    destinations: Vec<String>,
    file_changes: usize,
    paths: &[String],
) -> SideEffects {
    let mut replayable = Vec::new();
    if file_changes > 0 {
        replayable.push(format!(
            "{file_changes} file change(s) under {}",
            paths.join(", ")
        ));
    }
    let non_replayable = match egress {
        EgressMode::Blocked => Vec::new(),
        EgressMode::AllowListed => destinations
            .iter()
            .map(|d| {
                format!(
                    "possible traffic to allow-listed destination {d}: recorded, never replayed"
                )
            })
            .collect(),
        EgressMode::Unrestricted => vec![
            "network egress was not blocked during speculation: external effects are unknown \
             and are never replayed"
                .to_string(),
        ],
    };
    SideEffects {
        egress,
        destinations,
        replayable,
        non_replayable,
    }
}

fn procbox_effects(spec: &ProcboxSpec) -> (EgressMode, Vec<String>) {
    if spec.net_ports.is_empty() {
        (EgressMode::Blocked, Vec::new())
    } else {
        (
            EgressMode::AllowListed,
            spec.net_ports
                .iter()
                .map(|p| format!("tcp/{p} (port allow-list only, any host)"))
                .collect(),
        )
    }
}

fn vm_effects(vm: &VmRecord, allow_domains: &[String]) -> (EgressMode, Vec<String>) {
    let proxied = vm
        .request
        .apple
        .as_ref()
        .map(|a| a.egress_allow.clone())
        .unwrap_or_default();
    if !proxied.is_empty() {
        // A vz sandbox with a card-less, proxied network: only these hosts, enforced by the host.
        (EgressMode::AllowListed, proxied)
    } else if matches!(vm.request.network, NetworkSpec::None) {
        (EgressMode::Blocked, Vec::new())
    } else if !allow_domains.is_empty() {
        (EgressMode::AllowListed, allow_domains.to_vec())
    } else {
        (EgressMode::Unrestricted, Vec::new())
    }
}

// --------------------------------------------------------------- staging ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StagedFile {
    /// File name under the changeset's `blobs/` directory.
    pub blob: String,
    pub mode: u32,
    pub size: u64,
}

/// Whether a file of `size` bytes still fits the staging budget.
pub fn staging_fits(total_so_far: u64, size: u64) -> bool {
    size <= MAX_STAGED_FILE_BYTES && total_so_far.saturating_add(size) <= MAX_STAGED_TOTAL_BYTES
}

/// File contents copied out of the speculative run.
#[derive(Debug, Default)]
pub struct StagedSet {
    pub files: BTreeMap<String, StagedFile>,
    pub blobs: Vec<(String, Vec<u8>)>,
    /// Added or modified files that could not be staged (too large, unreadable).
    pub unstaged: Vec<String>,
    total: u64,
}

impl StagedSet {
    pub fn add(&mut self, path: &str, data: Vec<u8>, mode: u32) {
        let size = data.len() as u64;
        if !staging_fits(self.total, size) {
            self.unstaged.push(path.to_string());
            return;
        }
        let blob = format!("{:06}", self.blobs.len());
        self.total += size;
        self.files.insert(
            path.to_string(),
            StagedFile {
                blob: blob.clone(),
                mode,
                size,
            },
        );
        self.blobs.push((blob, data));
    }
}

/// What a snapshot-path dry-run hands back before the guest is restored.
#[derive(Debug, Default)]
pub struct Captured {
    pub before: Option<Manifest>,
    pub staged: Option<StagedSet>,
}

/// Copy the added and modified files of `changes` out of VM `id`.
pub(crate) async fn stage_files(
    mgr: &VmManager,
    id: Uuid,
    changes: &ChangeSet,
) -> Result<StagedSet> {
    let mut set = StagedSet::default();
    for path in changes.added.iter().chain(changes.modified.iter()) {
        match mgr.get_file(id, path.clone()).await {
            Ok(AgentResponse::FileContent {
                content_base64,
                mode,
            }) => match base64::engine::general_purpose::STANDARD.decode(content_base64.as_bytes())
            {
                Ok(data) => set.add(path, data, mode),
                Err(_) => set.unstaged.push(path.clone()),
            },
            _ => set.unstaged.push(path.clone()),
        }
    }
    Ok(set)
}

// ------------------------------------------------------------- changeset ----

/// One speculative run and its decision state. `base` lives beside it
/// (`base.json`) because it can be large; see [`ChangesetStore::load_base`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Changeset {
    pub id: Uuid,
    pub sandbox_id: Uuid,
    pub state: ChangesetState,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: u64,
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub paths: Vec<String>,
    /// `workspace-copy`, `fork` or `snapshot`.
    pub run_via: String,
    pub changes: ChangeSet,
    pub side_effects: SideEffects,
    pub base_files: usize,
    pub staged: BTreeMap<String, StagedFile>,
    /// Changed files whose contents could not be kept; apply refuses while any.
    pub unstaged: Vec<String>,
    /// Set when apply starts, so an interrupted apply is never retried blindly.
    #[serde(default)]
    pub apply_started_at: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Paths that differ between the changeset's base and the files now. Empty
/// means the changeset still applies cleanly. Pure.
pub fn base_conflicts(base: &Manifest, current: &Manifest) -> Vec<String> {
    match diff_manifests(base, current) {
        Ok(d) => {
            let mut out: Vec<String> = d
                .added
                .into_iter()
                .chain(d.modified)
                .chain(d.deleted)
                .collect();
            out.sort();
            out
        }
        Err(_) => vec!["<fingerprint mode changed>".to_string()],
    }
}

/// Clamp a caller TTL into `1..=MAX_TTL_SECS`, defaulting when absent.
pub fn clamp_ttl(ttl: Option<u64>) -> u64 {
    ttl.unwrap_or(DEFAULT_TTL_SECS).clamp(1, MAX_TTL_SECS)
}

/// Single-quote `s` for `sh -c`.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Cut `s` to at most `max` bytes on a character boundary.
pub fn truncate_output(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[truncated {} bytes]", &s[..end], s.len() - end)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ----------------------------------------------------------------- store ----

/// Durable write: temp file, fsync, rename, fsync of the directory.
fn write_durable(dest: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = dest.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, dest)?;
    if let Some(dir) = dest.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    Ok(())
}

/// Changesets on disk. Cheap to clone.
#[derive(Debug, Clone)]
pub struct ChangesetStore {
    root: PathBuf,
}

impl ChangesetStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            root: state_dir.join(CHANGESETS_DIR),
        }
    }

    fn dir(&self, id: Uuid) -> PathBuf {
        self.root.join(id.to_string())
    }

    /// Write a new changeset: blobs first, then `base.json`, then `meta.json`
    /// last, so a crash never leaves metadata that points at missing contents.
    pub fn create(
        &self,
        cs: &Changeset,
        base: &Manifest,
        blobs: &[(String, Vec<u8>)],
    ) -> Result<()> {
        let dir = self.dir(cs.id);
        create_private_dir(&dir.join("blobs"))?;
        for (name, data) in blobs {
            write_durable(&dir.join("blobs").join(name), data)?;
        }
        write_durable(&dir.join("base.json"), &serde_json::to_vec(base)?)?;
        self.save(cs)
    }

    /// Persist the metadata of `cs` (durably).
    pub fn save(&self, cs: &Changeset) -> Result<()> {
        write_durable(
            &self.dir(cs.id).join("meta.json"),
            &serde_json::to_vec_pretty(cs)?,
        )
    }

    pub fn load(&self, id: Uuid) -> Result<Changeset> {
        match std::fs::read(self.dir(id).join("meta.json")) {
            Ok(raw) => serde_json::from_slice(&raw).context("changeset metadata is corrupt"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ChangesetError::NotFound(id).into())
            }
            Err(e) => Err(e).context("reading changeset"),
        }
    }

    pub fn load_base(&self, id: Uuid) -> Result<Manifest> {
        let raw =
            std::fs::read(self.dir(id).join("base.json")).context("reading changeset base")?;
        serde_json::from_slice(&raw).context("changeset base is corrupt")
    }

    pub fn read_blob(&self, id: Uuid, name: &str) -> Result<Vec<u8>> {
        if name.contains('/') || name.contains("..") {
            bail!("invalid blob name");
        }
        std::fs::read(self.dir(id).join("blobs").join(name))
            .with_context(|| format!("reading staged file {name}"))
    }

    /// Drop the staged file contents (the changeset record stays).
    pub fn remove_blobs(&self, id: Uuid) {
        let _ = std::fs::remove_dir_all(self.dir(id).join("blobs"));
    }

    pub fn remove(&self, id: Uuid) {
        let _ = std::fs::remove_dir_all(self.dir(id));
    }

    /// All changesets, newest first; unreadable ones are skipped.
    pub fn list_all(&self) -> Vec<Changeset> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(&self.root) else {
            return out;
        };
        for entry in rd.flatten() {
            let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|n| Uuid::parse_str(n).ok())
            else {
                continue;
            };
            if let Ok(cs) = self.load(id) {
                out.push(cs);
            }
        }
        out.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        out
    }

    pub fn list(&self, sandbox_id: Uuid) -> Vec<Changeset> {
        self.list_all()
            .into_iter()
            .filter(|c| c.sandbox_id == sandbox_id)
            .collect()
    }

    /// TTL cleanup. Undecided changesets past `expires_at` become `expired` and
    /// lose their staged contents; finished ones older than the retention are
    /// deleted. `skip` protects changesets another request is working on.
    /// Returns the ids that expired in this pass.
    pub fn sweep(&self, now: u64, skip: impl Fn(Uuid) -> bool) -> Vec<(Uuid, Uuid)> {
        let mut expired = Vec::new();
        for mut cs in self.list_all() {
            if skip(cs.id) {
                continue;
            }
            if !cs.state.is_terminal() && now >= cs.expires_at {
                if transition(&mut cs, ChangesetState::Expired, now).is_ok()
                    && self.save(&cs).is_ok()
                {
                    self.remove_blobs(cs.id);
                    expired.push((cs.sandbox_id, cs.id));
                }
            } else if cs.state.is_terminal()
                && now.saturating_sub(cs.updated_at) >= TERMINAL_RETENTION_SECS
            {
                self.remove(cs.id);
            }
        }
        expired
    }
}

// ------------------------------------------------------------- busy guard ----

fn busy_set() -> &'static Mutex<HashSet<Uuid>> {
    static SET: OnceLock<Mutex<HashSet<Uuid>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

fn is_busy(id: Uuid) -> bool {
    busy_set()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&id)
}

/// Held while one request decides or applies a changeset.
struct ChangesetGuard(Uuid);

impl ChangesetGuard {
    fn acquire(id: Uuid) -> Result<Self, ChangesetError> {
        let mut set = busy_set().lock().unwrap_or_else(|e| e.into_inner());
        if !set.insert(id) {
            return Err(ChangesetError::Busy(id));
        }
        Ok(Self(id))
    }
}

impl Drop for ChangesetGuard {
    fn drop(&mut self) {
        busy_set()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
    }
}

// ------------------------------------------------------------------ runs ----

/// Result of the speculative run, before it becomes a changeset.
struct RunOut {
    before: Manifest,
    changes: ChangeSet,
    staged: StagedSet,
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// Run `command` on a throwaway copy of a procbox workspace. Blocking.
fn procbox_speculate_blocking(
    cfg: &ProcboxConfig,
    spec: &ProcboxSpec,
    workspace: &Path,
    root_path: &Path,
    command: &str,
    timeout: Option<u64>,
    paths: &[String],
) -> Result<RunOut> {
    let root = Root::open(root_path)?;
    let cap = cfg.max_workspace_mib << 20;
    let size = root.total_size()?;
    if size > cap {
        return Err(ProcboxError::TooLarge(format!(
            "workspace is {} MiB; speculation copies it and the cap is {} MiB",
            size >> 20,
            cfg.max_workspace_mib
        ))
        .into());
    }
    let copy = workspace.join(format!("speculate-{}", Uuid::new_v4()));
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&copy)?;
    }
    let _guard = TempTree(copy.clone());
    let root = root.with_owner(spec.uid.map(|u| (u, u)));
    root.chown_path(&copy)?;
    root.copy_to(&copy)?;
    let before = Root::open(&copy)?.manifest()?.restrict_to(paths);
    let out = run_confined(cfg, spec, &copy, command, timeout)?;
    let copy_root = Root::open(&copy)?;
    let after = copy_root.manifest()?.restrict_to(paths);
    let changes = diff_manifests(&before, &after)?;
    let mut staged = StagedSet::default();
    for p in changes.added.iter().chain(changes.modified.iter()) {
        let rel = Path::new(p.trim_start_matches('/'));
        match copy_root.read_file(rel, MAX_STAGED_FILE_BYTES as usize) {
            Ok((data, mode)) => staged.add(p, data, mode),
            Err(_) => staged.unstaged.push(p.clone()),
        }
    }
    Ok(RunOut {
        before,
        changes,
        staged,
        exit_code: out.exit_code,
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

fn exec_parts(resp: AgentResponse) -> Result<(i32, String, String)> {
    match resp {
        AgentResponse::Exec {
            exit_code,
            stdout,
            stderr,
            ..
        } => Ok((exit_code, stdout, stderr)),
        AgentResponse::Error { message } => bail!("guest agent error: {message}"),
        other => bail!("unexpected guest response: {other:?}"),
    }
}

impl VmManager {
    fn changeset_store(&self) -> ChangesetStore {
        ChangesetStore::new(&self.cfg.state_dir)
    }

    /// Run `command` in an isolated copy of sandbox `id` and keep the result
    /// as a pending changeset. The sandbox itself is not modified.
    pub async fn speculate(
        self: &Arc<Self>,
        id: Uuid,
        command: String,
        timeout: Option<u64>,
        paths: Option<Vec<String>>,
        ttl_seconds: Option<u64>,
    ) -> Result<Changeset> {
        let vm = self.get(id).await?;
        let _ = self.changeset_sweep().await;
        let ttl = clamp_ttl(ttl_seconds);

        let (run, via, paths, effects) = if let Some(spec) = load_spec(&vm)? {
            let cfg = self.cfg.sandbox.procbox.clone();
            if !cfg.enabled {
                return Err(ProcboxError::Disabled.into());
            }
            let paths = match paths {
                Some(p) => validate_paths(&p)?,
                None => vec!["/".to_string()],
            };
            let effects = procbox_effects(&spec);
            self.touch_activity(id).await;
            let workspace = vm.workspace.clone();
            let root_path = files_root(&vm);
            let (cmd, p) = (command.clone(), paths.clone());
            let run = tokio::task::spawn_blocking(move || {
                procbox_speculate_blocking(&cfg, &spec, &workspace, &root_path, &cmd, timeout, &p)
            })
            .await
            .context("procbox worker panicked")??;
            (run, "workspace-copy", paths, effects)
        } else {
            let paths = match paths {
                Some(p) => validate_paths(&p)?,
                None => bail!(
                    "paths is required for a VM sandbox speculation: the guest root is too large to scan"
                ),
            };
            if vm.backend != fluxvm_core::model::BackendKind::Vz
                && !vm.request.agent.as_ref().is_some_and(|a| a.enabled)
            {
                bail!("speculation needs the guest agent, and this sandbox was created without it");
            }
            let effects = vm_effects(&vm, &self.cfg.sandbox.egress_allow_domains);
            let forked =
                if vm.status == VmStatus::Running && crate::fork::check_forkable(&vm, 1).is_ok() {
                    self.speculate_via_fork(&vm, &command, timeout, &paths)
                        .await?
                } else {
                    None
                };
            match forked {
                Some(run) => (run, "fork", paths, effects),
                None => {
                    let mut cap = Captured::default();
                    let report = self
                        .vm_sandbox_dry_run_capture(
                            id,
                            command.clone(),
                            timeout,
                            Some(paths.clone()),
                            Some(&mut cap),
                        )
                        .await?;
                    let before = cap.before.context("speculation produced no baseline")?;
                    let staged = cap.staged.context("speculation produced no staged files")?;
                    let run = RunOut {
                        before,
                        changes: report.changes,
                        staged,
                        exit_code: report.exit_code,
                        stdout: report.stdout,
                        stderr: report.stderr,
                    };
                    (run, "snapshot", paths, effects)
                }
            }
        };

        let now = now_unix();
        let (egress, destinations) = effects;
        let n_changes =
            run.changes.added.len() + run.changes.modified.len() + run.changes.deleted.len();
        let cs = Changeset {
            id: Uuid::new_v4(),
            sandbox_id: id,
            state: ChangesetState::Pending,
            created_at: now,
            updated_at: now,
            expires_at: now + ttl,
            command,
            exit_code: run.exit_code,
            stdout: truncate_output(run.stdout, MAX_OUTPUT_BYTES),
            stderr: truncate_output(run.stderr, MAX_OUTPUT_BYTES),
            run_via: via.to_string(),
            side_effects: declare_side_effects(egress, destinations, n_changes, &paths),
            paths,
            changes: run.changes,
            base_files: run.before.files.len(),
            staged: run.staged.files,
            unstaged: run.staged.unstaged,
            apply_started_at: None,
            error: None,
        };
        let store = self.changeset_store();
        let (cs2, base, blobs) = (cs.clone(), run.before, run.staged.blobs);
        tokio::task::spawn_blocking(move || store.create(&cs2, &base, &blobs))
            .await
            .context("changeset worker panicked")??;
        audit_event(
            "changeset.create",
            &[
                ("vm_id", &id.to_string()),
                ("changeset", &cs.id.to_string()),
                ("via", via),
                ("changes", &n_changes.to_string()),
            ],
        );
        Ok(cs)
    }

    /// Run on a fork of the sandbox. `Ok(None)` when the fork could not be
    /// created (the caller falls back to snapshot-and-restore); an error once
    /// the child existed and the run itself failed.
    async fn speculate_via_fork(
        self: &Arc<Self>,
        vm: &VmRecord,
        command: &str,
        timeout: Option<u64>,
        paths: &[String],
    ) -> Result<Option<RunOut>> {
        let prefix = format!("spec-{}", &Uuid::new_v4().simple().to_string()[..8]);
        let children = match self.fork_vm(vm.id, 1, Some(prefix), None).await {
            Ok(c) => c,
            Err(e) => {
                tracing::info!(vm = %vm.id, error = %format!("{e:#}"), "fork unavailable; speculating on a snapshot");
                return Ok(None);
            }
        };
        let child = children
            .into_iter()
            .next()
            .context("fork returned no child")?;
        let child_id = child.id;
        let result = self.run_in_child(child_id, command, timeout, paths).await;
        if let Err(e) = self.delete(child_id).await {
            tracing::warn!(child = %child_id, error = %e, "deleting speculation fork failed");
        }
        result.map(Some)
    }

    async fn run_in_child(
        self: &Arc<Self>,
        child: Uuid,
        command: &str,
        timeout: Option<u64>,
        paths: &[String],
    ) -> Result<RunOut> {
        self.wait_for_agent(child).await?;
        let before = self.take_manifest(child, paths).await?;
        let (exit_code, stdout, stderr) =
            exec_parts(self.exec(child, command.to_string(), timeout).await?)?;
        let after = self.take_manifest(child, paths).await?;
        let changes = diff_manifests(&before, &after)?;
        let staged = stage_files(self, child, &changes).await?;
        Ok(RunOut {
            before,
            changes,
            staged,
            exit_code,
            stdout,
            stderr,
        })
    }

    pub async fn changeset_list(&self, sandbox_id: Uuid) -> Result<Vec<Changeset>> {
        self.get(sandbox_id).await?;
        let _ = self.changeset_sweep().await;
        Ok(self.changeset_store().list(sandbox_id))
    }

    pub async fn changeset_get(&self, sandbox_id: Uuid, cs_id: Uuid) -> Result<Changeset> {
        let _ = self.changeset_sweep().await;
        load_for(&self.changeset_store(), sandbox_id, cs_id)
    }

    /// Approve (`Approved`) or reject (`Rejected`) a pending changeset.
    pub async fn changeset_decide(
        &self,
        sandbox_id: Uuid,
        cs_id: Uuid,
        to: ChangesetState,
    ) -> Result<Changeset> {
        if !matches!(to, ChangesetState::Approved | ChangesetState::Rejected) {
            bail!("a changeset is decided by approving or rejecting it");
        }
        let _guard = ChangesetGuard::acquire(cs_id)?;
        let store = self.changeset_store();
        let mut cs = load_for(&store, sandbox_id, cs_id)?;
        let now = now_unix();
        if expire_if_due(&store, &mut cs, now)? {
            return Err(ChangesetError::Expired(cs_id).into());
        }
        transition(&mut cs, to, now)?;
        store.save(&cs)?;
        if to == ChangesetState::Rejected {
            store.remove_blobs(cs_id);
        }
        audit_event(
            &format!("changeset.{}", to.as_str()),
            &[
                ("vm_id", &sandbox_id.to_string()),
                ("changeset", &cs_id.to_string()),
            ],
        );
        Ok(cs)
    }

    /// Promote an approved changeset's file changes into the real sandbox.
    /// Refuses with a conflict, writing nothing, when the real files no longer
    /// match the changeset's base. Network effects are never replayed.
    pub async fn changeset_apply(
        self: &Arc<Self>,
        sandbox_id: Uuid,
        cs_id: Uuid,
    ) -> Result<Changeset> {
        let _guard = ChangesetGuard::acquire(cs_id)?;
        let store = self.changeset_store();
        let mut cs = load_for(&store, sandbox_id, cs_id)?;
        let now = now_unix();
        if expire_if_due(&store, &mut cs, now)? {
            return Err(ChangesetError::Expired(cs_id).into());
        }
        if cs.state != ChangesetState::Approved {
            return Err(ChangesetError::InvalidTransition {
                from: cs.state,
                to: ChangesetState::Applied,
            }
            .into());
        }
        if cs.apply_started_at.is_some() {
            return Err(self
                .fail_changeset(
                    &store,
                    &mut cs,
                    "a previous apply did not finish; the sandbox may hold part of it".into(),
                )
                .into());
        }
        if !cs.unstaged.is_empty() {
            return Err(ChangesetError::NotApplicable(format!(
                "{} changed file(s) could not be kept (too large or unreadable): {}",
                cs.unstaged.len(),
                cs.unstaged.join(", ")
            ))
            .into());
        }
        let vm = self.ensure_running_for_request(sandbox_id).await?;
        let base = store.load_base(cs_id)?;
        let current = self.take_manifest(sandbox_id, &cs.paths).await?;
        let conflicts = base_conflicts(&base, &current);
        if !conflicts.is_empty() {
            audit_event(
                "changeset.conflict",
                &[
                    ("vm_id", &sandbox_id.to_string()),
                    ("changeset", &cs_id.to_string()),
                    ("files", &conflicts.len().to_string()),
                ],
            );
            return Err(ChangesetError::Conflict(conflicts).into());
        }

        cs.apply_started_at = Some(now);
        store.save(&cs)?;
        match self.apply_changes(&vm, &cs, &store).await {
            Ok(()) => {
                transition(&mut cs, ChangesetState::Applied, now_unix())?;
                store.save(&cs)?;
                store.remove_blobs(cs_id);
                audit_event(
                    "changeset.applied",
                    &[
                        ("vm_id", &sandbox_id.to_string()),
                        ("changeset", &cs_id.to_string()),
                    ],
                );
                Ok(cs)
            }
            Err(e) => {
                let _ = self.fail_changeset(&store, &mut cs, format!("{e:#}"));
                Err(e.context("applying the changeset failed; it is now marked failed"))
            }
        }
    }

    /// Record a failed apply: `failed` state, the reason, an audit event.
    fn fail_changeset(
        &self,
        store: &ChangesetStore,
        cs: &mut Changeset,
        reason: String,
    ) -> ChangesetError {
        let now = now_unix();
        let _ = transition(cs, ChangesetState::Failed, now);
        cs.error = Some(reason.clone());
        let _ = store.save(cs);
        audit_event(
            "changeset.failed",
            &[
                ("vm_id", &cs.sandbox_id.to_string()),
                ("changeset", &cs.id.to_string()),
                ("reason", &reason),
            ],
        );
        ChangesetError::NotApplicable(reason)
    }

    async fn apply_changes(
        &self,
        vm: &VmRecord,
        cs: &Changeset,
        store: &ChangesetStore,
    ) -> Result<()> {
        let id = vm.id;
        let procbox = is_procbox(vm);
        // A procbox workspace resolves paths relative to its root.
        let target = |path: &str| -> String {
            if procbox {
                path.trim_start_matches('/').to_string()
            } else {
                path.to_string()
            }
        };
        if !procbox {
            let mut dirs: Vec<String> = cs
                .staged
                .keys()
                .filter_map(|p| Path::new(p).parent())
                .filter_map(|d| d.to_str())
                .filter(|d| !d.is_empty() && *d != "/")
                .map(String::from)
                .collect();
            dirs.sort();
            dirs.dedup();
            for dir in dirs {
                let (code, _, stderr) = exec_parts(
                    self.exec(id, format!("mkdir -p -- {}", shell_quote(&dir)), Some(30))
                        .await?,
                )?;
                if code != 0 {
                    bail!("creating {dir} failed (exit {code}): {}", stderr.trim());
                }
            }
        }
        for (path, file) in &cs.staged {
            let data = store.read_blob(cs.id, &file.blob)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
            match self
                .put_file(id, target(path), b64, Some(file.mode & 0o7777))
                .await?
            {
                AgentResponse::FileWritten => {}
                AgentResponse::Error { message } => bail!("writing {path} failed: {message}"),
                other => bail!("unexpected response writing {path}: {other:?}"),
            }
        }
        for path in &cs.changes.deleted {
            let (code, _, stderr) = exec_parts(
                self.exec(
                    id,
                    format!("rm -f -- {}", shell_quote(&target(path))),
                    Some(30),
                )
                .await?,
            )?;
            if code != 0 {
                bail!("deleting {path} failed (exit {code}): {}", stderr.trim());
            }
        }
        Ok(())
    }

    /// TTL cleanup: expire undecided changesets past their deadline and drop
    /// finished ones past the retention. Returns how many expired.
    pub async fn changeset_sweep(&self) -> Result<usize> {
        let store = self.changeset_store();
        let now = now_unix();
        let expired = tokio::task::spawn_blocking(move || store.sweep(now, is_busy))
            .await
            .context("changeset sweep panicked")?;
        for (sandbox, cs) in &expired {
            audit_event(
                "changeset.expired",
                &[
                    ("vm_id", &sandbox.to_string()),
                    ("changeset", &cs.to_string()),
                ],
            );
        }
        Ok(expired.len())
    }
}

/// Load a changeset that must belong to `sandbox_id`.
fn load_for(store: &ChangesetStore, sandbox_id: Uuid, cs_id: Uuid) -> Result<Changeset> {
    let cs = store.load(cs_id)?;
    if cs.sandbox_id != sandbox_id {
        return Err(ChangesetError::NotFound(cs_id).into());
    }
    Ok(cs)
}

/// Expire `cs` when it is undecided and past its deadline.
fn expire_if_due(store: &ChangesetStore, cs: &mut Changeset, now: u64) -> Result<bool> {
    if cs.state.is_terminal() || now < cs.expires_at {
        return Ok(false);
    }
    transition(cs, ChangesetState::Expired, now)?;
    store.save(cs)?;
    store.remove_blobs(cs.id);
    audit_event(
        "changeset.expired",
        &[
            ("vm_id", &cs.sandbox_id.to_string()),
            ("changeset", &cs.id.to_string()),
        ],
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changes::FingerprintMode;

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn manifest(entries: &[(&str, &str)]) -> Manifest {
        Manifest {
            mode: FingerprintMode::Sha256,
            files: entries
                .iter()
                .map(|(p, f)| (p.to_string(), f.to_string()))
                .collect(),
        }
    }

    fn sample(state: ChangesetState, expires_at: u64, updated_at: u64) -> Changeset {
        Changeset {
            id: Uuid::new_v4(),
            sandbox_id: Uuid::nil(),
            state,
            created_at: updated_at,
            updated_at,
            expires_at,
            command: "true".into(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            paths: vec!["/".into()],
            run_via: "workspace-copy".into(),
            changes: ChangeSet::default(),
            side_effects: declare_side_effects(EgressMode::Blocked, vec![], 0, &["/".into()]),
            base_files: 0,
            staged: BTreeMap::new(),
            unstaged: vec![],
            apply_started_at: None,
            error: None,
        }
    }

    #[test]
    fn state_machine_allows_only_the_documented_edges() {
        use ChangesetState::*;
        let all = [Pending, Approved, Applied, Rejected, Expired, Failed];
        let allowed = [
            (Pending, Approved),
            (Pending, Rejected),
            (Pending, Expired),
            (Approved, Applied),
            (Approved, Rejected),
            (Approved, Expired),
            (Approved, Failed),
        ];
        for from in all {
            for to in all {
                assert_eq!(
                    from.can_transition_to(to),
                    allowed.contains(&(from, to)),
                    "{from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn pending_cannot_be_applied_and_terminal_states_are_final() {
        let mut cs = sample(ChangesetState::Pending, 100, 0);
        let err = transition(&mut cs, ChangesetState::Applied, 1).unwrap_err();
        assert!(matches!(err, ChangesetError::InvalidTransition { .. }));
        assert_eq!(cs.state, ChangesetState::Pending);
        transition(&mut cs, ChangesetState::Approved, 5).unwrap();
        assert_eq!(cs.updated_at, 5);
        transition(&mut cs, ChangesetState::Applied, 6).unwrap();
        assert!(transition(&mut cs, ChangesetState::Rejected, 7).is_err());
        assert!(cs.state.is_terminal());
    }

    #[test]
    fn conflict_detection_reports_every_kind_of_drift() {
        let base = manifest(&[("/a", H1), ("/b", H1)]);
        assert!(base_conflicts(&base, &base.clone()).is_empty());
        let drifted = manifest(&[("/a", H2), ("/c", H1)]);
        assert_eq!(base_conflicts(&base, &drifted), vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn side_effects_mark_anything_but_files_non_replayable() {
        let paths = vec!["/work".to_string()];
        let blocked = declare_side_effects(EgressMode::Blocked, vec![], 3, &paths);
        assert!(blocked.non_replayable.is_empty());
        assert_eq!(blocked.replayable.len(), 1);
        let none = declare_side_effects(EgressMode::Blocked, vec![], 0, &paths);
        assert!(none.replayable.is_empty());
        let listed =
            declare_side_effects(EgressMode::AllowListed, vec!["pypi.org".into()], 1, &paths);
        assert_eq!(listed.non_replayable.len(), 1);
        assert!(listed.non_replayable[0].contains("pypi.org"));
        let open = declare_side_effects(EgressMode::Unrestricted, vec![], 1, &paths);
        assert_eq!(open.non_replayable.len(), 1);
        assert!(open.non_replayable[0].contains("not blocked"));
    }

    #[test]
    fn staging_budget_is_enforced_per_file_and_in_total() {
        assert!(staging_fits(0, MAX_STAGED_FILE_BYTES));
        assert!(!staging_fits(0, MAX_STAGED_FILE_BYTES + 1));
        assert!(!staging_fits(MAX_STAGED_TOTAL_BYTES - 1, 2));
        let mut set = StagedSet::default();
        set.add("/ok", vec![1, 2, 3], 0o644);
        set.add("/big", vec![0; MAX_STAGED_FILE_BYTES as usize + 1], 0o644);
        assert_eq!(set.files.len(), 1);
        assert_eq!(set.files["/ok"].blob, "000000");
        assert_eq!(set.unstaged, vec!["/big".to_string()]);
    }

    #[test]
    fn ttl_is_clamped() {
        assert_eq!(clamp_ttl(None), DEFAULT_TTL_SECS);
        assert_eq!(clamp_ttl(Some(0)), 1);
        assert_eq!(clamp_ttl(Some(u64::MAX)), MAX_TTL_SECS);
        assert_eq!(clamp_ttl(Some(60)), 60);
    }

    #[test]
    fn shell_quote_survives_quotes_and_spaces() {
        assert_eq!(shell_quote("/a b"), "'/a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate_output("short".into(), 10), "short");
        let cut = truncate_output("aé".repeat(10), 4);
        assert!(cut.starts_with("aéa"));
        assert!(cut.contains("[truncated"));
    }

    #[test]
    fn store_round_trips_and_lists_per_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChangesetStore::new(dir.path());
        let mut cs = sample(ChangesetState::Pending, 100, 10);
        cs.staged.insert(
            "/f".into(),
            StagedFile {
                blob: "000000".into(),
                mode: 0o644,
                size: 2,
            },
        );
        let base = manifest(&[("/f", H1)]);
        store
            .create(&cs, &base, &[("000000".to_string(), b"hi".to_vec())])
            .unwrap();
        let loaded = store.load(cs.id).unwrap();
        assert_eq!(loaded.id, cs.id);
        assert_eq!(loaded.state, ChangesetState::Pending);
        assert_eq!(store.load_base(cs.id).unwrap(), base);
        assert_eq!(store.read_blob(cs.id, "000000").unwrap(), b"hi");
        assert!(store.read_blob(cs.id, "../meta.json").is_err());
        assert_eq!(store.list(Uuid::nil()).len(), 1);
        assert!(store.list(Uuid::new_v4()).is_empty());
        let missing = store.load(Uuid::new_v4()).unwrap_err();
        assert!(matches!(
            missing.downcast_ref::<ChangesetError>(),
            Some(ChangesetError::NotFound(_))
        ));
        // No temp files are left behind by the durable writes.
        let leftovers: Vec<_> =
            std::fs::read_dir(dir.path().join(CHANGESETS_DIR).join(cs.id.to_string()))
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
                .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn sweep_expires_undecided_and_prunes_old_finished() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChangesetStore::new(dir.path());
        let base = manifest(&[]);
        let blobs = [("000000".to_string(), b"x".to_vec())];
        let pending = sample(ChangesetState::Pending, 100, 0);
        let approved = sample(ChangesetState::Approved, 100, 0);
        let fresh = sample(ChangesetState::Pending, 200_000, 0);
        let old_done = sample(ChangesetState::Applied, 100, 0);
        let recent_done = sample(ChangesetState::Rejected, 100, 90_000);
        for c in [&pending, &approved, &fresh, &old_done, &recent_done] {
            store.create(c, &base, &blobs).unwrap();
        }
        let now = TERMINAL_RETENTION_SECS + 100;
        let expired = store.sweep(now, |_| false);
        let ids: HashSet<Uuid> = expired.iter().map(|(_, c)| *c).collect();
        assert_eq!(ids, HashSet::from([pending.id, approved.id]));
        assert_eq!(
            store.load(pending.id).unwrap().state,
            ChangesetState::Expired
        );
        assert!(
            store.read_blob(pending.id, "000000").is_err(),
            "blobs dropped"
        );
        assert_eq!(store.load(fresh.id).unwrap().state, ChangesetState::Pending);
        assert!(
            store.load(old_done.id).is_err(),
            "old finished record pruned"
        );
        assert!(store.load(recent_done.id).is_ok());
    }

    #[test]
    fn sweep_skips_changesets_in_use() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChangesetStore::new(dir.path());
        let cs = sample(ChangesetState::Approved, 1, 0);
        store.create(&cs, &manifest(&[]), &[]).unwrap();
        let busy = cs.id;
        assert!(store.sweep(1000, |id| id == busy).is_empty());
        assert_eq!(store.load(cs.id).unwrap().state, ChangesetState::Approved);
    }

    #[test]
    fn expire_if_due_only_touches_undecided_past_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let store = ChangesetStore::new(dir.path());
        let mut cs = sample(ChangesetState::Approved, 50, 0);
        store.create(&cs, &manifest(&[]), &[]).unwrap();
        assert!(!expire_if_due(&store, &mut cs, 49).unwrap());
        assert!(expire_if_due(&store, &mut cs, 50).unwrap());
        assert_eq!(store.load(cs.id).unwrap().state, ChangesetState::Expired);
        assert!(
            !expire_if_due(&store, &mut cs, 99).unwrap(),
            "already final"
        );
    }

    #[test]
    fn only_one_request_may_hold_a_changeset() {
        let id = Uuid::new_v4();
        let first = ChangesetGuard::acquire(id).unwrap();
        assert!(matches!(
            ChangesetGuard::acquire(id).err().unwrap(),
            ChangesetError::Busy(_)
        ));
        drop(first);
        assert!(ChangesetGuard::acquire(id).is_ok());
    }
}
