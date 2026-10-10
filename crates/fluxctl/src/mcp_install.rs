// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `fluxctl mcp install|uninstall|status`: registers `fluxctl mcp serve` with an MCP client by editing that
//! client's own config file, leaving every other entry (and, for TOML, comments and layout) as it was.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Client {
    ClaudeCode,
    Cursor,
    ClaudeDesktop,
    Codex,
    Vscode,
    Windsurf,
    Gemini,
}

impl Client {
    pub const ALL: [Client; 7] = [
        Client::ClaudeCode,
        Client::Cursor,
        Client::ClaudeDesktop,
        Client::Codex,
        Client::Vscode,
        Client::Windsurf,
        Client::Gemini,
    ];

    fn id(self) -> &'static str {
        match self {
            Client::ClaudeCode => "claude-code",
            Client::Cursor => "cursor",
            Client::ClaudeDesktop => "claude-desktop",
            Client::Codex => "codex",
            Client::Vscode => "vscode",
            Client::Windsurf => "windsurf",
            Client::Gemini => "gemini",
        }
    }

    fn format(self) -> Format {
        match self {
            Client::Codex => Format::CodexToml,
            Client::Vscode => Format::VscodeJson,
            _ => Format::McpServersJson,
        }
    }

    /// The config file for `project` (a directory) or, when `None`, the user-wide one.
    fn path(self, home: &Path, project: Option<&Path>) -> Result<PathBuf> {
        Ok(match (self, project) {
            (Client::ClaudeCode, None) => home.join(".claude.json"),
            (Client::ClaudeCode, Some(p)) => p.join(".mcp.json"),
            (Client::Cursor, None) => home.join(".cursor/mcp.json"),
            (Client::Cursor, Some(p)) => p.join(".cursor/mcp.json"),
            (Client::ClaudeDesktop, None) if cfg!(target_os = "macos") => {
                home.join("Library/Application Support/Claude/claude_desktop_config.json")
            }
            (Client::ClaudeDesktop, None) => home.join(".config/Claude/claude_desktop_config.json"),
            (Client::Codex, None) => home.join(".codex/config.toml"),
            (Client::Codex, Some(p)) => p.join(".codex/config.toml"),
            (Client::Vscode, Some(p)) => p.join(".vscode/mcp.json"),
            (Client::Windsurf, None) => home.join(".codeium/windsurf/mcp_config.json"),
            (Client::Gemini, None) => home.join(".gemini/settings.json"),
            (Client::Gemini, Some(p)) => p.join(".gemini/settings.json"),
            (Client::ClaudeDesktop | Client::Windsurf, Some(_)) => {
                bail!(
                    "{} has no per-project MCP config; drop --project",
                    self.id()
                )
            }
            (Client::Vscode, None) => {
                bail!(
                    "vscode keeps user-wide MCP servers in its profile; use --project (writes .vscode/mcp.json)"
                )
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// `{"mcpServers": {name: {command, args, env}}}`
    McpServersJson,
    /// `{"servers": {name: {type: "stdio", command, args, env}}}`
    VscodeJson,
    /// `[mcp_servers.<name>]` with `command`, `args` and `[mcp_servers.<name>.env]`.
    CodexToml,
}

/// What the client should launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub command: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

impl Entry {
    fn json(&self, format: Format) -> Value {
        let mut v = Map::new();
        if format == Format::VscodeJson {
            v.insert("type".into(), json!("stdio"));
        }
        v.insert("command".into(), json!(self.command));
        v.insert("args".into(), json!(self.args));
        if !self.env.is_empty() {
            let env: Map<String, Value> = self
                .env
                .iter()
                .map(|(k, val)| (k.clone(), json!(val)))
                .collect();
            v.insert("env".into(), Value::Object(env));
        }
        Value::Object(v)
    }
}

fn servers_key(format: Format) -> &'static str {
    if format == Format::VscodeJson {
        "servers"
    } else {
        "mcpServers"
    }
}

fn parse_json(existing: Option<&str>, path: &Path) -> Result<Map<String, Value>> {
    match existing.map(str::trim) {
        None | Some("") => Ok(Map::new()),
        Some(text) => match serde_json::from_str(text) {
            Ok(Value::Object(m)) => Ok(m),
            Ok(_) => bail!("{} is not a JSON object", path.display()),
            Err(e) => bail!(
                "{} is not plain JSON ({e}); add the entry by hand (see `fluxctl mcp install --dry-run`)",
                path.display()
            ),
        },
    }
}

/// The new file contents, or `None` when nothing changes.
fn set_entry(
    format: Format,
    existing: Option<&str>,
    path: &Path,
    name: &str,
    entry: Option<&Entry>,
) -> Result<Option<String>> {
    if format == Format::CodexToml {
        let mut doc: toml_edit::DocumentMut = existing
            .unwrap_or_default()
            .parse()
            .with_context(|| format!("parsing {}", path.display()))?;
        let before = doc.to_string();
        match entry {
            Some(e) => {
                let servers = doc
                    .entry("mcp_servers")
                    .or_insert_with(|| {
                        let mut t = toml_edit::Table::new();
                        t.set_implicit(true);
                        toml_edit::Item::Table(t)
                    })
                    .as_table_mut()
                    .context("mcp_servers is not a table")?;
                let mut t = toml_edit::Table::new();
                t["command"] = toml_edit::value(e.command.as_str());
                t["args"] = toml_edit::value(
                    e.args
                        .iter()
                        .map(String::as_str)
                        .collect::<toml_edit::Array>(),
                );
                if !e.env.is_empty() {
                    let mut env = toml_edit::Table::new();
                    for (k, v) in &e.env {
                        env[k.as_str()] = toml_edit::value(v.as_str());
                    }
                    t["env"] = toml_edit::Item::Table(env);
                }
                servers[name] = toml_edit::Item::Table(t);
            }
            None => {
                if let Some(servers) = doc.get_mut("mcp_servers").and_then(|s| s.as_table_mut()) {
                    servers.remove(name);
                }
            }
        }
        let after = doc.to_string();
        return Ok((after != before).then_some(after));
    }
    let mut root = parse_json(existing, path)?;
    let key = servers_key(format);
    let changed = match entry {
        Some(e) => {
            let servers = root
                .entry(key)
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .with_context(|| format!("{key} in {} is not an object", path.display()))?;
            let new = e.json(format);
            servers.insert(name.to_owned(), new.clone()) != Some(new)
        }
        None => root
            .get_mut(key)
            .and_then(Value::as_object_mut)
            .is_some_and(|s| s.remove(name).is_some()),
    };
    Ok(changed.then(|| serde_json::to_string_pretty(&Value::Object(root)).unwrap() + "\n"))
}

/// Whether the file has an entry called `name`, and its command line.
fn read_entry(format: Format, text: &str, name: &str) -> Option<String> {
    let (command, args): (String, Vec<String>) = if format == Format::CodexToml {
        let doc: toml_edit::DocumentMut = text.parse().ok()?;
        let t = doc.get("mcp_servers")?.get(name)?;
        let args = t.get("args").and_then(|a| a.as_array());
        (
            t.get("command")?.as_str()?.to_owned(),
            args.map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        )
    } else {
        let v: Value = serde_json::from_str(text).ok()?;
        let e = v.get(servers_key(format))?.get(name)?;
        let args = e.get("args").and_then(Value::as_array);
        (
            e.get("command")?.as_str()?.to_owned(),
            args.map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
        )
    };
    Some(
        std::iter::once(command)
            .chain(args)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn home() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("HOME").context("HOME is not set")?,
    ))
}

fn project_dir(project: bool) -> Result<Option<PathBuf>> {
    project
        .then(std::env::current_dir)
        .transpose()
        .map_err(Into::into)
}

/// Writes beside the target, then renames, so a client never reads a half-written config.
fn write_atomic(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension(format!("fluxvm-{}.tmp", std::process::id()));
    fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    if let Ok(meta) = fs::metadata(path) {
        let _ = fs::set_permissions(&tmp, meta.permissions());
    }
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

pub fn install(
    client: Client,
    project: bool,
    name: &str,
    entry: &Entry,
    dry_run: bool,
) -> Result<Value> {
    let path = client.path(&home()?, project_dir(project)?.as_deref())?;
    let existing = fs::read_to_string(&path).ok();
    let format = client.format();
    let new = set_entry(format, existing.as_deref(), &path, name, Some(entry))?;
    if dry_run {
        let snippet = if format == Format::CodexToml {
            set_entry(format, None, &path, name, Some(entry))?.unwrap_or_default()
        } else {
            serde_json::to_string_pretty(&json!({servers_key(format): {name: entry.json(format)}}))?
        };
        return Ok(
            json!({"client": client.id(), "path": path, "would_change": new.is_some(), "entry": snippet}),
        );
    }
    if let Some(text) = &new {
        write_atomic(&path, text)?;
    }
    Ok(json!({
        "client": client.id(),
        "path": path,
        "name": name,
        "command": std::iter::once(entry.command.clone()).chain(entry.args.clone()).collect::<Vec<_>>().join(" "),
        "changed": new.is_some(),
        "next": "restart the client (or reload its MCP servers) to pick up the change",
    }))
}

pub fn uninstall(client: Client, project: bool, name: &str) -> Result<Value> {
    let path = client.path(&home()?, project_dir(project)?.as_deref())?;
    let Ok(existing) = fs::read_to_string(&path) else {
        return Ok(json!({"client": client.id(), "path": path, "removed": false}));
    };
    let new = set_entry(client.format(), Some(&existing), &path, name, None)?;
    if let Some(text) = &new {
        write_atomic(&path, text)?;
    }
    Ok(json!({"client": client.id(), "path": path, "removed": new.is_some()}))
}

pub fn status(project: bool, name: &str) -> Result<Value> {
    let home = home()?;
    let project = project_dir(project)?;
    let rows = Client::ALL
        .iter()
        .filter_map(|&c| {
            let path = c.path(&home, project.as_deref()).ok()?;
            let entry = fs::read_to_string(&path).ok().and_then(|t| read_entry(c.format(), &t, name));
            Some(json!({"client": c.id(), "path": path, "installed": entry.is_some(), "command": entry}))
        })
        .collect::<Vec<_>>();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            command: "/opt/fluxctl".into(),
            args: vec!["mcp".into(), "serve".into()],
            env: vec![("FLUXVM_URL".into(), "http://127.0.0.1:7788".into())],
        }
    }

    #[test]
    fn json_install_keeps_other_servers_and_settings() {
        let p = Path::new("x.json");
        let before = r#"{"theme": "dark", "mcpServers": {"other": {"command": "o"}}}"#;
        let after = set_entry(
            Format::McpServersJson,
            Some(before),
            p,
            "fluxvm",
            Some(&entry()),
        )
        .unwrap()
        .unwrap();
        let v: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["mcpServers"]["other"]["command"], "o");
        assert_eq!(v["mcpServers"]["fluxvm"]["args"], json!(["mcp", "serve"]));
        assert_eq!(
            v["mcpServers"]["fluxvm"]["env"]["FLUXVM_URL"],
            "http://127.0.0.1:7788"
        );
        assert!(
            set_entry(
                Format::McpServersJson,
                Some(&after),
                p,
                "fluxvm",
                Some(&entry())
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            read_entry(Format::McpServersJson, &after, "fluxvm").as_deref(),
            Some("/opt/fluxctl mcp serve")
        );
        let removed = set_entry(Format::McpServersJson, Some(&after), p, "fluxvm", None)
            .unwrap()
            .unwrap();
        assert!(read_entry(Format::McpServersJson, &removed, "fluxvm").is_none());
        assert!(removed.contains("\"other\""));
    }

    #[test]
    fn vscode_uses_servers_with_a_stdio_type() {
        let after = set_entry(
            Format::VscodeJson,
            None,
            Path::new("m.json"),
            "fluxvm",
            Some(&entry()),
        )
        .unwrap()
        .unwrap();
        let v: Value = serde_json::from_str(&after).unwrap();
        assert_eq!(v["servers"]["fluxvm"]["type"], "stdio");
        assert!(v.get("mcpServers").is_none());
    }

    #[test]
    fn codex_toml_keeps_comments_and_other_tables() {
        let p = Path::new("config.toml");
        let before = "# my settings\nmodel = \"o3\"\n\n[mcp_servers.other]\ncommand = \"o\"\n";
        let after = set_entry(Format::CodexToml, Some(before), p, "fluxvm", Some(&entry()))
            .unwrap()
            .unwrap();
        assert!(after.starts_with("# my settings\nmodel = \"o3\""));
        assert!(after.contains("[mcp_servers.other]"));
        assert!(after.contains("[mcp_servers.fluxvm]"));
        assert!(after.contains("args = [\"mcp\", \"serve\"]"));
        assert!(after.contains("[mcp_servers.fluxvm.env]"));
        assert_eq!(
            read_entry(Format::CodexToml, &after, "fluxvm").as_deref(),
            Some("/opt/fluxctl mcp serve")
        );
        assert!(
            set_entry(Format::CodexToml, Some(&after), p, "fluxvm", Some(&entry()))
                .unwrap()
                .is_none()
        );
        let removed = set_entry(Format::CodexToml, Some(&after), p, "fluxvm", None)
            .unwrap()
            .unwrap();
        assert!(!removed.contains("fluxvm"));
        assert!(removed.contains("[mcp_servers.other]"));
    }

    #[test]
    fn comments_in_json_are_refused_rather_than_dropped() {
        let err = set_entry(
            Format::VscodeJson,
            Some("// c\n{}"),
            Path::new("m.json"),
            "fluxvm",
            Some(&entry()),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not plain JSON"), "{err}");
    }

    #[test]
    fn paths_per_client_and_scope() {
        let home = Path::new("/h");
        let proj = Path::new("/p");
        assert_eq!(
            Client::ClaudeCode.path(home, None).unwrap(),
            Path::new("/h/.claude.json")
        );
        assert_eq!(
            Client::ClaudeCode.path(home, Some(proj)).unwrap(),
            Path::new("/p/.mcp.json")
        );
        assert_eq!(
            Client::Cursor.path(home, None).unwrap(),
            Path::new("/h/.cursor/mcp.json")
        );
        assert_eq!(
            Client::Codex.path(home, None).unwrap(),
            Path::new("/h/.codex/config.toml")
        );
        assert_eq!(
            Client::Vscode.path(home, Some(proj)).unwrap(),
            Path::new("/p/.vscode/mcp.json")
        );
        assert!(Client::Vscode.path(home, None).is_err());
        assert!(Client::ClaudeDesktop.path(home, Some(proj)).is_err());
    }
}
