// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Append-only VM event log (`<state_dir>/events.jsonl`).
//!
//! The file, not an in-memory ring, is the source of truth: `fluxctl` runs
//! local-mode verbs in its own process, so the daemon and every CLI
//! invocation append to the same file and `GET /v1/events` / `fluxctl events`
//! see all of them.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

/// Rotate to `events.jsonl.1` once the live file passes this size.
const MAX_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VmEvent {
    pub ts: DateTime<Utc>,
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventFilter {
    #[serde(default)]
    pub vm: Option<Uuid>,
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
    /// Prefix match on the event name (`vm.` matches `vm.start`, `vm.stop`, ...).
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

impl EventFilter {
    pub fn matches(&self, e: &VmEvent) -> bool {
        if let Some(vm) = self.vm {
            if e.vm_id != Some(vm) {
                return false;
            }
        }
        if let Some(since) = self.since {
            if e.ts <= since {
                return false;
            }
        }
        if let Some(prefix) = &self.event {
            if !e.event.starts_with(prefix.as_str()) {
                return false;
            }
        }
        true
    }
}

pub struct EventLog {
    path: PathBuf,
    write_lock: Mutex<()>,
}

static GLOBAL: OnceLock<EventLog> = OnceLock::new();

/// Install the process-wide log (first caller wins).
pub fn init(state_dir: &Path) {
    let _ = GLOBAL.set(EventLog::new(state_dir));
}

pub fn global() -> Option<&'static EventLog> {
    GLOBAL.get()
}

/// Record into the global log, if initialised. Never fails the caller.
pub fn record(event: &str, pairs: &[(&str, &str)]) {
    let Some(log) = global() else {
        return;
    };
    let mut fields = BTreeMap::new();
    let mut vm_id = None;
    for (k, v) in pairs {
        if *k == "vm_id" {
            vm_id = v.parse().ok();
        } else if !v.is_empty() {
            fields.insert((*k).to_string(), (*v).to_string());
        }
    }
    let ev = VmEvent {
        ts: Utc::now(),
        event: event.to_string(),
        vm_id,
        fields,
    };
    if let Err(e) = log.append(&ev) {
        tracing::warn!(error = %e, "failed to append VM event");
    }
}

impl EventLog {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("events.jsonl"),
            write_lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, ev: &VmEvent) -> Result<()> {
        let _g = self.write_lock.lock().unwrap_or_else(|p| p.into_inner());
        if let Ok(meta) = std::fs::metadata(&self.path) {
            if meta.len() > MAX_BYTES {
                let _ = std::fs::rename(&self.path, self.path.with_extension("jsonl.1"));
            }
        }
        let mut line = serde_json::to_vec(ev)?;
        line.push(b'\n');
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening {}", self.path.display()))?;
        f.write_all(&line)?;
        Ok(())
    }

    /// Matching events, oldest first; `limit` keeps the newest N.
    pub fn list(&self, filter: &EventFilter) -> Result<Vec<VmEvent>> {
        let file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("opening {}", self.path.display())),
        };
        let mut out: Vec<VmEvent> = BufReader::new(file)
            .lines()
            .map_while(|l| l.ok())
            .filter_map(|l| serde_json::from_str::<VmEvent>(&l).ok())
            .filter(|e| filter.matches(e))
            .collect();
        if let Some(limit) = filter.limit {
            if out.len() > limit {
                out.drain(..out.len() - limit);
            }
        }
        Ok(out)
    }

    /// Current end offset, for `read_from` tailing.
    pub fn end_offset(&self) -> u64 {
        std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }

    /// Events appended at or after byte `offset`; returns the new offset.
    /// A shrunken file (rotation) restarts from 0.
    pub fn read_from(&self, offset: u64, filter: &EventFilter) -> Result<(Vec<VmEvent>, u64)> {
        let mut file = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
            Err(e) => return Err(e.into()),
        };
        let len = file.metadata()?.len();
        let start = if len < offset { 0 } else { offset };
        file.seek(SeekFrom::Start(start))?;
        let mut reader = BufReader::new(file);
        let mut pos = start;
        let mut out = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 || !line.ends_with('\n') {
                break;
            }
            pos += n as u64;
            if let Ok(ev) = serde_json::from_str::<VmEvent>(line.trim_end()) {
                if filter.matches(&ev) {
                    out.push(ev);
                }
            }
        }
        Ok((out, pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(name: &str, vm: Option<Uuid>) -> VmEvent {
        VmEvent {
            ts: Utc::now(),
            event: name.into(),
            vm_id: vm,
            fields: BTreeMap::new(),
        }
    }

    #[test]
    fn append_list_filter_and_tail() {
        let dir = std::env::temp_dir().join(format!("fluxvm-events-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = EventLog::new(&dir);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        log.append(&ev("vm.start", Some(a))).unwrap();
        log.append(&ev("vm.stop", Some(b))).unwrap();
        log.append(&ev("quota.deny", None)).unwrap();

        assert_eq!(log.list(&EventFilter::default()).unwrap().len(), 3);
        let only_a = log
            .list(&EventFilter {
                vm: Some(a),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(only_a.len(), 1);
        assert_eq!(only_a[0].event, "vm.start");
        let vm_prefix = log
            .list(&EventFilter {
                event: Some("vm.".into()),
                limit: Some(1),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(vm_prefix.len(), 1);
        assert_eq!(vm_prefix[0].event, "vm.stop");

        let off = log.end_offset();
        log.append(&ev("vm.restart", Some(a))).unwrap();
        let (tail, next) = log.read_from(off, &EventFilter::default()).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].event, "vm.restart");
        assert_eq!(next, log.end_offset());
        std::fs::remove_dir_all(&dir).ok();
    }
}
