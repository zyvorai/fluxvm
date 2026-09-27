// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `-o json|table|wide` rendering and VM name/prefix resolution.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::OnceLock;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Json,
    Table,
    Wide,
}

/// One table column: header, JSON pointer into each item, shown only in `wide`.
pub struct Column {
    pub header: &'static str,
    pub pointer: &'static str,
    pub wide_only: bool,
}

pub const fn col(header: &'static str, pointer: &'static str) -> Column {
    Column {
        header,
        pointer,
        wide_only: false,
    }
}

pub const fn wide(header: &'static str, pointer: &'static str) -> Column {
    Column {
        header,
        pointer,
        wide_only: true,
    }
}

pub const VM_COLUMNS: &[Column] = &[
    col("ID", "/id"),
    col("NAME", "/name"),
    col("STATUS", "/status"),
    col("BACKEND", "/backend"),
    col("IP", "/guest_ip"),
    wide("VCPUS", "/request/vcpus"),
    wide("MEMORY_MIB", "/request/memory_mib"),
    wide("TENANT", "/request/tenant"),
    wide("LABELS", "/labels"),
    wide("CREATED", "/created_at"),
];

pub const IMAGE_COLUMNS: &[Column] = &[
    col("NAME", "/name"),
    col("FORMAT", "/format"),
    col("SIGNED_BY", "/signed_by"),
    col("READ_ONLY", "/read_only"),
    wide("DISTRO", "/distro"),
    wide("VERSION", "/version"),
    wide("SHA256", "/sha256"),
    wide("SOURCE", "/source"),
];

pub const SNAPSHOT_COLUMNS: &[Column] = &[
    col("TAG", "/tag"),
    col("CREATED", "/created_at"),
    col("SIZE_BYTES", "/size_bytes"),
];

pub const EVENT_COLUMNS: &[Column] = &[
    col("TIME", "/ts"),
    col("EVENT", "/event"),
    col("VM", "/vm_id"),
    wide("FIELDS", "/fields"),
];

fn cell(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "-".into(),
        Some(Value::String(s)) if s.is_empty() => "-".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Object(m)) if m.is_empty() => "-".into(),
        Some(Value::Object(m)) => m
            .iter()
            .map(|(k, v)| match v {
                Value::String(s) => format!("{k}={s}"),
                other => format!("{k}={other}"),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(other) => other.to_string(),
    }
}

/// Render `items` (a JSON array) as an aligned table.
pub fn render_table(items: &Value, columns: &[Column], wide_mode: bool) -> String {
    let cols: Vec<&Column> = columns
        .iter()
        .filter(|c| wide_mode || !c.wide_only)
        .collect();
    let rows: Vec<Vec<String>> = items
        .as_array()
        .map(|a| a.as_slice())
        .unwrap_or_default()
        .iter()
        .map(|item| cols.iter().map(|c| cell(item.pointer(c.pointer))).collect())
        .collect();
    let mut widths: Vec<usize> = cols.iter().map(|c| c.header.len()).collect();
    for row in &rows {
        for (w, v) in widths.iter_mut().zip(row) {
            *w = (*w).max(v.chars().count());
        }
    }
    let fmt_row = |cells: Vec<&str>| {
        let last = cells.len().saturating_sub(1);
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i == last {
                    c.to_string()
                } else {
                    format!("{c:<width$}", width = widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
    };
    let mut out = fmt_row(cols.iter().map(|c| c.header).collect());
    out.push('\n');
    for row in &rows {
        out.push_str(&fmt_row(row.iter().map(String::as_str).collect()));
        out.push('\n');
    }
    out
}

/// Print a list result as JSON (unchanged legacy shape) or as a table.
pub fn print_list<T: Serialize>(format: OutputFormat, items: &T, columns: &[Column]) -> Result<()> {
    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(items)?),
        OutputFormat::Table | OutputFormat::Wide => {
            let v = serde_json::to_value(items)?;
            print!(
                "{}",
                render_table(&v, columns, format == OutputFormat::Wide)
            );
        }
    }
    Ok(())
}

/// `(id, name)` for every stored VM, read once per process from
/// `<state_dir>/vms.json` so clap can resolve names while parsing.
static VM_INDEX: OnceLock<Vec<(Uuid, String)>> = OnceLock::new();

fn config_path_from_args() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--config" {
            return args.next().map(PathBuf::from);
        }
        if let Some(v) = a.strip_prefix("--config=") {
            return Some(PathBuf::from(v));
        }
    }
    std::env::var_os("FLUXVM_CONFIG").map(PathBuf::from)
}

fn load_vm_index() -> Vec<(Uuid, String)> {
    let Ok(cfg) = fluxvm_core::config::Config::load(config_path_from_args().as_deref()) else {
        return Vec::new();
    };
    let Ok(raw) = std::fs::read_to_string(cfg.state_dir.join("vms.json")) else {
        return Vec::new();
    };
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&raw) else {
        return Vec::new();
    };
    map.iter()
        .filter_map(|(k, v)| {
            let id = k.parse().ok()?;
            let name = v.get("name").and_then(Value::as_str).unwrap_or_default();
            Some((id, name.to_string()))
        })
        .collect()
}

/// Resolve a UUID, exact VM name, or unique UUID prefix (>= 4 chars).
pub fn resolve_in(index: &[(Uuid, String)], s: &str) -> Result<Uuid, String> {
    if let Ok(id) = s.parse::<Uuid>() {
        return Ok(id);
    }
    let by_name: Vec<Uuid> = index
        .iter()
        .filter(|(_, n)| n == s)
        .map(|(id, _)| *id)
        .collect();
    match by_name.len() {
        1 => return Ok(by_name[0]),
        n if n > 1 => {
            let ids: Vec<String> = by_name.iter().map(Uuid::to_string).collect();
            return Err(format!(
                "VM name {s:?} is ambiguous ({n} matches: {}); use the id",
                ids.join(", ")
            ));
        }
        _ => {}
    }
    let lower = s.to_ascii_lowercase();
    if lower.len() >= 4 && lower.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        let by_prefix: Vec<Uuid> = index
            .iter()
            .filter(|(id, _)| id.to_string().starts_with(&lower))
            .map(|(id, _)| *id)
            .collect();
        match by_prefix.len() {
            1 => return Ok(by_prefix[0]),
            n if n > 1 => {
                return Err(format!(
                    "id prefix {s:?} is ambiguous ({n} matches); type more characters"
                ));
            }
            _ => {}
        }
    }
    Err(format!("no VM with id, name, or id prefix {s:?}"))
}

/// clap value parser for every VM-id argument.
pub fn parse_vm_ref(s: &str) -> Result<Uuid, String> {
    if let Ok(id) = s.parse::<Uuid>() {
        return Ok(id);
    }
    resolve_in(VM_INDEX.get_or_init(load_vm_index), s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_uuid_name_and_prefix() {
        let a: Uuid = "aaaa1111-0000-0000-0000-000000000001".parse().unwrap();
        let b: Uuid = "aaaa2222-0000-0000-0000-000000000002".parse().unwrap();
        let idx = vec![(a, "web".to_string()), (b, "db".to_string())];
        assert_eq!(resolve_in(&idx, &a.to_string()), Ok(a));
        assert_eq!(resolve_in(&idx, "db"), Ok(b));
        assert_eq!(resolve_in(&idx, "aaaa1"), Ok(a));
        assert!(resolve_in(&idx, "aaaa").unwrap_err().contains("ambiguous"));
        assert!(resolve_in(&idx, "nope").unwrap_err().contains("no VM"));
        let dup = vec![(a, "x".to_string()), (b, "x".to_string())];
        assert!(resolve_in(&dup, "x").unwrap_err().contains("ambiguous"));
    }

    #[test]
    fn table_hides_wide_columns_and_formats_cells() {
        let items = json!([
            {"id": "1", "name": "web", "status": "running", "backend": "qemu",
             "guest_ip": null, "labels": {"env": "prod"}, "request": {"vcpus": 2}}
        ]);
        let t = render_table(&items, VM_COLUMNS, false);
        assert!(t.starts_with("ID"));
        assert!(t.contains("running"));
        assert!(!t.contains("VCPUS"));
        let w = render_table(&items, VM_COLUMNS, true);
        assert!(w.contains("VCPUS"));
        assert!(w.contains("env=prod"));
    }
}
