// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Sandbox file change-set: record a baseline manifest of regular files under
//! some guest directories, later diff a fresh manifest against it.
//!
//! The manifest is produced by a portable POSIX shell script run through the
//! existing guest exec path (no new guest protocol). Records are
//! NUL-terminated `<fingerprint>\t<path>` so any file name, including ones
//! with spaces, tabs or newlines, round-trips. Everything here except
//! [`VmManager::sandbox_baseline`]/[`VmManager::sandbox_changes`] is pure and
//! unit tested.
//!
//! This reports changes; it does not revert them. Roll a sandbox back with
//! the existing snapshot/restore.

use crate::VmManager;
use anyhow::{Context, Result, bail};
use fluxvm_guest_protocol::AgentResponse;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const MAX_PATHS: usize = 64;
pub const MAX_PATH_LEN: usize = 4096;
/// Refuse manifests larger than this many files: a caller should narrow the
/// paths rather than have the API hold and diff an unbounded listing.
pub const MAX_ENTRIES: usize = 200_000;
/// Cap on the raw manifest text returned by the guest.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const GUEST_TIMEOUT_SECS: u64 = 300;
const BASELINE_FILE: &str = "sandbox-baseline.json";
const MODE_RECORD: &str = "#mode";
const UNREADABLE: &str = "unreadable";
/// Guest exit code used when a requested path is not a directory.
const EXIT_NOT_A_DIR: i32 = 3;

/// How file contents were fingerprinted in a manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FingerprintMode {
    /// `sha256sum` of the content.
    Sha256,
    /// `size:mtime` fallback when the guest has no `sha256sum`. Detects
    /// changes that alter size or mtime, not same-size rewrites that keep
    /// the mtime.
    Stat,
}

impl FingerprintMode {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "sha256" => Some(Self::Sha256),
            "stat" => Some(Self::Stat),
            _ => None,
        }
    }
}

/// Typed failures the API layer maps to HTTP statuses.
#[derive(Debug, PartialEq, Eq)]
pub enum ChangeError {
    /// No baseline has been recorded for this sandbox.
    NoBaseline,
    /// Baseline and current manifest used different fingerprint modes, so
    /// they are not comparable (e.g. `sha256sum` disappeared in between).
    ModeMismatch {
        baseline: FingerprintMode,
        current: FingerprintMode,
    },
}

impl std::fmt::Display for ChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoBaseline => write!(
                f,
                "no baseline recorded for this sandbox; POST /v1/sandboxes/{{id}}/baseline first"
            ),
            Self::ModeMismatch { baseline, current } => write!(
                f,
                "baseline was fingerprinted with {baseline:?} but the guest now yields {current:?}; take a new baseline"
            ),
        }
    }
}

impl std::error::Error for ChangeError {}

/// A listing of regular files (path -> fingerprint).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub mode: FingerprintMode,
    pub files: BTreeMap<String, String>,
}

/// Result of comparing a current manifest to a baseline. Paths are sorted.
/// A rename shows up as one deletion plus one addition.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ChangeSet {
    pub added: Vec<String>,
    pub modified: Vec<String>,
    pub deleted: Vec<String>,
    pub unchanged: usize,
}

impl Manifest {
    /// Keep only files at or under one of `roots` (already normalized).
    pub fn restrict_to(&self, roots: &[String]) -> Manifest {
        let files = self
            .files
            .iter()
            .filter(|(p, _)| roots.iter().any(|r| is_under(p, r)))
            .map(|(p, f)| (p.clone(), f.clone()))
            .collect();
        Manifest {
            mode: self.mode,
            files,
        }
    }
}

fn is_under(path: &str, root: &str) -> bool {
    root == "/"
        || path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Compare `current` against `baseline`.
pub fn diff_manifests(baseline: &Manifest, current: &Manifest) -> Result<ChangeSet, ChangeError> {
    if baseline.mode != current.mode {
        return Err(ChangeError::ModeMismatch {
            baseline: baseline.mode,
            current: current.mode,
        });
    }
    let mut out = ChangeSet::default();
    for (path, fp) in &current.files {
        match baseline.files.get(path) {
            None => out.added.push(path.clone()),
            Some(old) if old != fp => out.modified.push(path.clone()),
            Some(_) => out.unchanged += 1,
        }
    }
    for path in baseline.files.keys() {
        if !current.files.contains_key(path) {
            out.deleted.push(path.clone());
        }
    }
    Ok(out)
}

/// Validate and normalize caller-supplied directories: absolute, no `..`,
/// no control characters, bounded count and length. Trailing and repeated
/// slashes and `.` components are dropped; duplicates removed.
pub fn validate_paths(paths: &[String]) -> Result<Vec<String>> {
    if paths.is_empty() {
        bail!("paths must not be empty");
    }
    if paths.len() > MAX_PATHS {
        bail!("at most {MAX_PATHS} paths are allowed");
    }
    let mut out = BTreeSet::new();
    for p in paths {
        if p.len() > MAX_PATH_LEN {
            bail!("path longer than {MAX_PATH_LEN} bytes");
        }
        if !p.starts_with('/') {
            bail!("path must be absolute: {p:?}");
        }
        if p.chars().any(|c| c.is_control()) {
            bail!("path contains a control character: {p:?}");
        }
        let mut comps = Vec::new();
        for c in p.split('/') {
            match c {
                "" | "." => {}
                ".." => bail!("path must not contain '..': {p:?}"),
                other => comps.push(other),
            }
        }
        out.insert(format!("/{}", comps.join("/")));
    }
    Ok(out.into_iter().collect())
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Note: GNU `sha256sum` prefixes its output with a backslash when the file
/// name contains a newline or backslash, so backslashes are stripped before
/// taking the 64-character hash.
///
/// The guest command that prints the manifest for `paths` (which must have
/// passed [`validate_paths`]). Fails (non-zero) if any path is not a
/// directory or any part of the walk errors, so a partial listing is never
/// mistaken for a complete one.
pub fn manifest_command(paths: &[String]) -> String {
    let dirs = paths
        .iter()
        .map(|p| shell_quote(p))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"if command -v sha256sum >/dev/null 2>&1; then M=sha256; else M=stat; fi
printf '{MODE_RECORD}\t%s\0' "$M"
rc=0
for d in {dirs}; do
  if [ ! -d "$d" ]; then echo "not a directory: $d" >&2; exit {EXIT_NOT_A_DIR}; fi
  find "$d" -xdev -type f -exec sh -c 'M=$1; shift; for f; do
    if [ "$M" = sha256 ]; then
      h=$(sha256sum -- "$f" 2>/dev/null | tr -d "\\" | cut -c1-64); [ -n "$h" ] || h={UNREADABLE}
    else
      h=$(stat -c %s:%Y -- "$f" 2>/dev/null) || h={UNREADABLE}
    fi
    printf "%s\t%s\0" "$h" "$f"
  done' sh "$M" {{}} + || rc=$?
done
exit $rc"#
    )
}

fn valid_fingerprint(mode: FingerprintMode, fp: &str) -> bool {
    if fp == UNREADABLE {
        return true;
    }
    match mode {
        FingerprintMode::Sha256 => fp.len() == 64 && fp.bytes().all(|b| b.is_ascii_hexdigit()),
        FingerprintMode::Stat => fp
            .split_once(':')
            .is_some_and(|(a, b)| is_digits(a) && is_digits(b)),
    }
}

fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Parse the guest's NUL-delimited manifest output.
pub fn parse_manifest(output: &str) -> Result<Manifest> {
    if output.len() > MAX_OUTPUT_BYTES {
        bail!("manifest output exceeds {MAX_OUTPUT_BYTES} bytes; narrow the paths");
    }
    let mut records = output.split('\0');
    let header = records.next().unwrap_or_default();
    let mode = header
        .strip_prefix(MODE_RECORD)
        .and_then(|r| r.strip_prefix('\t'))
        .and_then(FingerprintMode::parse)
        .context("guest manifest is missing its mode header")?;
    let mut files = BTreeMap::new();
    for rec in records {
        if rec.is_empty() {
            continue;
        }
        let (fp, path) = rec
            .split_once('\t')
            .with_context(|| format!("malformed manifest record: {rec:?}"))?;
        if !path.starts_with('/') {
            bail!("manifest path is not absolute: {path:?}");
        }
        if !valid_fingerprint(mode, fp) {
            bail!("bad {mode:?} fingerprint {fp:?} for {path:?}");
        }
        files.insert(path.to_string(), fp.to_string());
        if files.len() > MAX_ENTRIES {
            bail!("more than {MAX_ENTRIES} files; narrow the paths");
        }
    }
    Ok(Manifest { mode, files })
}

#[derive(Serialize, Deserialize)]
struct StoredBaseline {
    taken_at_unix: u64,
    paths: Vec<String>,
    manifest: Manifest,
}

/// Summary returned when a baseline is recorded.
#[derive(Debug, Serialize)]
pub struct BaselineSummary {
    pub ok: bool,
    pub files: usize,
    pub mode: FingerprintMode,
    pub paths: Vec<String>,
}

/// Result of a change query.
#[derive(Debug, Serialize)]
pub struct ChangesReport {
    #[serde(flatten)]
    pub changes: ChangeSet,
    pub mode: FingerprintMode,
    pub paths: Vec<String>,
    pub baseline_taken_at_unix: u64,
}

impl VmManager {
    async fn take_manifest(&self, id: Uuid, paths: &[String]) -> Result<Manifest> {
        let vm = self.get(id).await?;
        if crate::procbox_sandbox::is_procbox(&vm) {
            // No guest to ask: walk the host workspace directly.
            let paths = paths.to_vec();
            return tokio::task::spawn_blocking(move || {
                crate::procbox_sandbox::take_manifest(&vm, &paths)
            })
            .await
            .context("manifest worker panicked")?;
        }
        let resp = self
            .exec(id, manifest_command(paths), Some(GUEST_TIMEOUT_SECS))
            .await?;
        match resp {
            AgentResponse::Exec {
                exit_code: 0,
                stdout,
                ..
            } => parse_manifest(&stdout),
            AgentResponse::Exec {
                exit_code, stderr, ..
            } if exit_code == EXIT_NOT_A_DIR => bail!("{}", stderr.trim()),
            AgentResponse::Exec {
                exit_code, stderr, ..
            } => bail!(
                "guest manifest command failed (exit {exit_code}): {}",
                stderr.trim()
            ),
            AgentResponse::Error { message } => bail!("guest agent error: {message}"),
            other => bail!("unexpected guest response: {other:?}"),
        }
    }

    /// Record the current state of regular files under `paths` as the
    /// sandbox's baseline, replacing any previous one.
    pub async fn sandbox_baseline(&self, id: Uuid, paths: Vec<String>) -> Result<BaselineSummary> {
        let paths = validate_paths(&paths)?;
        let vm = self.get(id).await?;
        let manifest = self.take_manifest(id, &paths).await?;
        let stored = StoredBaseline {
            taken_at_unix: now_unix(),
            paths: paths.clone(),
            manifest,
        };
        let file = vm.workspace.join(BASELINE_FILE);
        let tmp = vm.workspace.join(format!("{BASELINE_FILE}.tmp"));
        tokio::fs::write(&tmp, serde_json::to_vec(&stored)?)
            .await
            .context("writing baseline")?;
        tokio::fs::rename(&tmp, &file)
            .await
            .context("committing baseline")?;
        Ok(BaselineSummary {
            ok: true,
            files: stored.manifest.files.len(),
            mode: stored.manifest.mode,
            paths,
        })
    }

    /// Diff the sandbox's files against its baseline. `paths` narrows the
    /// comparison to a subset of the baseline's directories; when omitted the
    /// baseline's own directories are used.
    pub async fn sandbox_changes(
        &self,
        id: Uuid,
        paths: Option<Vec<String>>,
    ) -> Result<ChangesReport> {
        let vm = self.get(id).await?;
        let raw = match tokio::fs::read(vm.workspace.join(BASELINE_FILE)).await {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ChangeError::NoBaseline.into());
            }
            Err(e) => return Err(e).context("reading baseline"),
        };
        let stored: StoredBaseline =
            serde_json::from_slice(&raw).context("baseline file is corrupt; take a new one")?;
        let paths = match paths {
            Some(p) => validate_paths(&p)?,
            None => stored.paths.clone(),
        };
        let baseline = stored.manifest.restrict_to(&paths);
        let current = self.take_manifest(id, &paths).await?;
        let changes = diff_manifests(&baseline, &current)?;
        Ok(ChangesReport {
            changes,
            mode: current.mode,
            paths,
            baseline_taken_at_unix: stored.taken_at_unix,
        })
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(mode: FingerprintMode, entries: &[(&str, &str)]) -> Manifest {
        Manifest {
            mode,
            files: entries
                .iter()
                .map(|(p, f)| (p.to_string(), f.to_string()))
                .collect(),
        }
    }

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn diff_reports_added_modified_deleted_and_counts_unchanged() {
        let base = m(
            FingerprintMode::Sha256,
            &[("/w/keep", H1), ("/w/edit", H1), ("/w/gone", H1)],
        );
        let cur = m(
            FingerprintMode::Sha256,
            &[("/w/keep", H1), ("/w/edit", H2), ("/w/new", H1)],
        );
        let d = diff_manifests(&base, &cur).unwrap();
        assert_eq!(d.added, vec!["/w/new"]);
        assert_eq!(d.modified, vec!["/w/edit"]);
        assert_eq!(d.deleted, vec!["/w/gone"]);
        assert_eq!(d.unchanged, 1);
    }

    #[test]
    fn identical_and_empty_manifests_have_no_changes() {
        let a = m(FingerprintMode::Sha256, &[("/w/a", H1)]);
        assert_eq!(diff_manifests(&a, &a).unwrap().unchanged, 1);
        let e = m(FingerprintMode::Sha256, &[]);
        let d = diff_manifests(&e, &e).unwrap();
        assert_eq!(d, ChangeSet::default());
    }

    #[test]
    fn rename_is_a_deletion_plus_an_addition() {
        let base = m(FingerprintMode::Sha256, &[("/w/old", H1)]);
        let cur = m(FingerprintMode::Sha256, &[("/w/new", H1)]);
        let d = diff_manifests(&base, &cur).unwrap();
        assert_eq!(d.deleted, vec!["/w/old"]);
        assert_eq!(d.added, vec!["/w/new"]);
        assert!(d.modified.is_empty());
    }

    #[test]
    fn everything_deleted_and_everything_added() {
        let base = m(FingerprintMode::Sha256, &[("/w/a", H1), ("/w/b", H1)]);
        let empty = m(FingerprintMode::Sha256, &[]);
        assert_eq!(diff_manifests(&base, &empty).unwrap().deleted.len(), 2);
        assert_eq!(diff_manifests(&empty, &base).unwrap().added.len(), 2);
    }

    #[test]
    fn mismatched_modes_are_refused_not_guessed() {
        let a = m(FingerprintMode::Sha256, &[("/w/a", H1)]);
        let b = m(FingerprintMode::Stat, &[("/w/a", "1:2")]);
        assert_eq!(
            diff_manifests(&a, &b),
            Err(ChangeError::ModeMismatch {
                baseline: FingerprintMode::Sha256,
                current: FingerprintMode::Stat
            })
        );
    }

    #[test]
    fn unreadable_only_equals_unreadable() {
        let base = m(
            FingerprintMode::Sha256,
            &[("/w/a", UNREADABLE), ("/w/b", H1)],
        );
        let cur = m(
            FingerprintMode::Sha256,
            &[("/w/a", UNREADABLE), ("/w/b", UNREADABLE)],
        );
        let d = diff_manifests(&base, &cur).unwrap();
        assert_eq!(d.modified, vec!["/w/b"]);
        assert_eq!(d.unchanged, 1);
    }

    #[test]
    fn stat_mode_detects_size_or_mtime_change() {
        let base = m(
            FingerprintMode::Stat,
            &[("/w/a", "10:100"), ("/w/b", "5:100")],
        );
        let cur = m(
            FingerprintMode::Stat,
            &[("/w/a", "11:100"), ("/w/b", "5:101")],
        );
        let d = diff_manifests(&base, &cur).unwrap();
        assert_eq!(d.modified, vec!["/w/a", "/w/b"]);
    }

    #[test]
    fn parse_handles_spaces_tabs_newlines_and_unicode_in_names() {
        let out = format!(
            "#mode\tsha256\0{H1}\t/w/a b\0{H2}\t/w/tab\there\0{H1}\t/w/new\nline\0{H2}\t/w/ünï/ćode\0"
        );
        let man = parse_manifest(&out).unwrap();
        assert_eq!(man.mode, FingerprintMode::Sha256);
        assert_eq!(man.files.len(), 4);
        assert_eq!(man.files["/w/a b"], H1);
        assert_eq!(man.files["/w/tab\there"], H2);
        assert_eq!(man.files["/w/new\nline"], H1);
        assert!(man.files.contains_key("/w/ünï/ćode"));
    }

    #[test]
    fn parse_empty_directory_gives_empty_manifest() {
        let man = parse_manifest("#mode\tstat\0").unwrap();
        assert_eq!(man.mode, FingerprintMode::Stat);
        assert!(man.files.is_empty());
    }

    #[test]
    fn parse_rejects_malformed_output() {
        assert!(parse_manifest("").is_err(), "no header");
        assert!(parse_manifest("garbage\0").is_err(), "bad header");
        assert!(parse_manifest("#mode\tmd5\0").is_err(), "unknown mode");
        assert!(
            parse_manifest(&format!("#mode\tsha256\0{H1}/w/a\0")).is_err(),
            "no tab"
        );
        assert!(parse_manifest(&format!("#mode\tsha256\0{H1}\trelative\0")).is_err());
        assert!(
            parse_manifest("#mode\tsha256\0zz\t/w/a\0").is_err(),
            "short hash"
        );
        assert!(
            parse_manifest("#mode\tstat\0abc:1\t/w/a\0").is_err(),
            "non numeric"
        );
        assert!(
            parse_manifest(&format!("#mode\tstat\0{H1}\t/w/a\0")).is_err(),
            "hash in stat mode"
        );
    }

    #[test]
    fn parse_accepts_unreadable_marker() {
        let man = parse_manifest("#mode\tsha256\0unreadable\t/w/secret\0").unwrap();
        assert_eq!(man.files["/w/secret"], UNREADABLE);
    }

    #[test]
    fn parse_enforces_entry_and_size_caps() {
        let mut out = String::from("#mode\tstat\0");
        for i in 0..=MAX_ENTRIES {
            out.push_str(&format!("1:1\t/w/{i}\0"));
        }
        assert!(
            parse_manifest(&out)
                .unwrap_err()
                .to_string()
                .contains("narrow")
        );
        let huge = format!("#mode\tstat\0{}", "x".repeat(MAX_OUTPUT_BYTES));
        assert!(parse_manifest(&huge).is_err());
    }

    #[test]
    fn diff_scales_to_many_files() {
        let mut base = BTreeMap::new();
        let mut cur = BTreeMap::new();
        for i in 0..100_000 {
            base.insert(format!("/w/{i}"), H1.to_string());
            cur.insert(
                format!("/w/{i}"),
                if i % 1000 == 0 { H2 } else { H1 }.to_string(),
            );
        }
        let d = diff_manifests(
            &Manifest {
                mode: FingerprintMode::Sha256,
                files: base,
            },
            &Manifest {
                mode: FingerprintMode::Sha256,
                files: cur,
            },
        )
        .unwrap();
        assert_eq!(d.modified.len(), 100);
        assert_eq!(d.unchanged, 99_900);
    }

    #[test]
    fn validate_paths_normalizes_and_rejects_bad_input() {
        assert_eq!(
            validate_paths(&["/w//x/./".into(), "/w/x".into(), "/".into()]).unwrap(),
            vec!["/", "/w/x"]
        );
        assert!(validate_paths(&[]).is_err());
        assert!(validate_paths(&["relative".into()]).is_err());
        assert!(validate_paths(&["/w/../etc".into()]).is_err());
        assert!(validate_paths(&["/w/..".into()]).is_err());
        assert!(validate_paths(&["/w/a\nb".into()]).is_err());
        assert!(validate_paths(&["/w/a\0b".into()]).is_err());
        assert!(validate_paths(&["".into()]).is_err());
        let long = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert!(validate_paths(&[long]).is_err());
        let many: Vec<String> = (0..=MAX_PATHS).map(|i| format!("/p{i}")).collect();
        assert!(validate_paths(&many).is_err());
        // A dotted name is not a parent reference.
        assert!(validate_paths(&["/w/..hidden".into()]).is_ok());
    }

    #[test]
    fn restrict_to_respects_path_boundaries() {
        let man = m(
            FingerprintMode::Sha256,
            &[("/w/a", H1), ("/w2/a", H1), ("/w", H1), ("/x/y", H1)],
        );
        let r = man.restrict_to(&["/w".to_string()]);
        assert_eq!(r.files.keys().collect::<Vec<_>>(), vec!["/w", "/w/a"]);
        assert_eq!(man.restrict_to(&["/".to_string()]).files.len(), 4);
    }

    #[test]
    fn shell_quote_neutralizes_single_quotes_and_metacharacters() {
        assert_eq!(shell_quote("/a b"), "'/a b'");
        assert_eq!(shell_quote("/it's"), r#"'/it'\''s'"#);
        let cmd = manifest_command(&["/w; rm -rf /".to_string()]);
        assert!(cmd.contains("'/w; rm -rf /'"));
    }

    #[test]
    fn change_error_messages_are_actionable() {
        assert!(ChangeError::NoBaseline.to_string().contains("baseline"));
    }

    /// Runs the real generated script against a real directory tree: odd
    /// names, empty dir, symlink (excluded), then diffs before/after edits.
    #[cfg(target_os = "linux")]
    #[test]
    fn script_round_trips_odd_names_and_detects_edits() {
        use std::fs;
        use std::process::Command;
        let root = std::env::temp_dir().join(format!("fluxvm-changes-{}", Uuid::new_v4()));
        let w = root.join("w");
        fs::create_dir_all(w.join("empty")).unwrap();
        fs::create_dir_all(w.join("sub dir")).unwrap();
        fs::write(w.join("plain"), "one").unwrap();
        fs::write(w.join("sub dir/with space"), "two").unwrap();
        fs::write(w.join("new\nline"), "three").unwrap();
        fs::write(w.join("tab\tname"), "four").unwrap();
        fs::write(w.join("quo'te"), "five").unwrap();
        fs::write(w.join("zero"), "").unwrap();
        std::os::unix::fs::symlink(w.join("plain"), w.join("link")).unwrap();
        let wp = w.to_string_lossy().to_string();
        let paths = validate_paths(std::slice::from_ref(&wp)).unwrap();

        let run = |paths: &[String]| -> (i32, String) {
            let out = Command::new("sh")
                .arg("-c")
                .arg(manifest_command(paths))
                .output()
                .unwrap();
            (
                out.status.code().unwrap(),
                String::from_utf8(out.stdout).unwrap(),
            )
        };

        let (rc, stdout) = run(&paths);
        assert_eq!(rc, 0);
        let before = parse_manifest(&stdout).unwrap();
        assert_eq!(before.mode, FingerprintMode::Sha256);
        assert_eq!(
            before.files.len(),
            6,
            "symlink and empty dir excluded: {:?}",
            before.files
        );
        assert!(before.files.contains_key(&format!("{wp}/new\nline")));
        assert!(before.files.contains_key(&format!("{wp}/tab\tname")));
        assert!(before.files.contains_key(&format!("{wp}/quo'te")));
        assert_eq!(
            before.files[&format!("{wp}/zero")],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        fs::write(w.join("plain"), "ONE").unwrap();
        fs::remove_file(w.join("sub dir/with space")).unwrap();
        fs::write(w.join("added"), "x").unwrap();
        fs::rename(w.join("zero"), w.join("renamed")).unwrap();

        let (rc, stdout) = run(&paths);
        assert_eq!(rc, 0);
        let after = parse_manifest(&stdout).unwrap();
        let d = diff_manifests(&before, &after).unwrap();
        assert_eq!(d.modified, vec![format!("{wp}/plain")]);
        assert_eq!(
            d.deleted,
            vec![format!("{wp}/sub dir/with space"), format!("{wp}/zero")]
        );
        assert_eq!(
            d.added,
            vec![format!("{wp}/added"), format!("{wp}/renamed")]
        );

        // A non-directory path is reported, never treated as empty.
        let (rc, _) = run(&[format!("{wp}/plain")]);
        assert_eq!(rc, EXIT_NOT_A_DIR);
        let (rc, _) = run(&[format!("{wp}/does-not-exist")]);
        assert_eq!(rc, EXIT_NOT_A_DIR);

        // A hostile directory name is data, not code.
        let evil = root.join("x'; touch PWNED; '");
        fs::create_dir_all(&evil).unwrap();
        fs::write(evil.join("f"), "1").unwrap();
        let evil_paths = validate_paths(&[evil.to_string_lossy().to_string()]).unwrap();
        let (rc, stdout) = run(&evil_paths);
        assert_eq!(rc, 0);
        assert_eq!(parse_manifest(&stdout).unwrap().files.len(), 1);
        assert!(!std::path::Path::new("PWNED").exists());

        fs::remove_dir_all(&root).unwrap();
    }

    /// With no `sha256sum` on PATH the script falls back to size:mtime.
    #[cfg(target_os = "linux")]
    #[test]
    fn script_falls_back_to_stat_without_sha256sum() {
        use std::fs;
        use std::process::Command;
        let root = std::env::temp_dir().join(format!("fluxvm-changes-stat-{}", Uuid::new_v4()));
        let bin = root.join("bin");
        let w = root.join("w");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&w).unwrap();
        for tool in ["sh", "find", "stat", "cut", "tr"] {
            let found = ["/usr/bin", "/bin"]
                .iter()
                .map(|d| std::path::PathBuf::from(d).join(tool))
                .find(|p| p.exists())
                .unwrap_or_else(|| panic!("{tool} not found"));
            std::os::unix::fs::symlink(found, bin.join(tool)).unwrap();
        }
        fs::write(w.join("a b"), "12345").unwrap();
        let wp = w.to_string_lossy().to_string();
        let paths = validate_paths(std::slice::from_ref(&wp)).unwrap();
        let run = || {
            let out = Command::new(bin.join("sh"))
                .arg("-c")
                .arg(manifest_command(&paths))
                .env("PATH", &bin)
                .output()
                .unwrap();
            assert_eq!(
                out.status.code(),
                Some(0),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            parse_manifest(&String::from_utf8(out.stdout).unwrap()).unwrap()
        };
        let before = run();
        assert_eq!(before.mode, FingerprintMode::Stat);
        assert!(before.files[&format!("{wp}/a b")].starts_with("5:"));
        fs::write(w.join("a b"), "123456789").unwrap();
        let d = diff_manifests(&before, &run()).unwrap();
        assert_eq!(d.modified, vec![format!("{wp}/a b")]);
        fs::remove_dir_all(&root).unwrap();
    }
}
