// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `fluxctl import-compose`: a `docker-compose.yml` as a `fluxvm.toml` of container services. Only what maps onto a
//! container sandbox is carried over; everything else is reported so nothing is dropped silently.

use anyhow::{Context, Result, bail};
use serde_yaml::Value as Yaml;
use std::collections::BTreeMap;
use toml::{Table, Value as Toml};

/// The converted file and what could not be carried over.
pub struct Converted {
    pub toml: String,
    pub warnings: Vec<String>,
}

/// Service keys that need no translation and lose nothing when dropped.
const QUIETLY_IGNORED: &[&str] = &[
    "container_name",
    "hostname",
    "networks",
    "labels",
    "stdin_open",
    "tty",
];

pub fn convert(yaml: &str, stack_name: &str) -> Result<Converted> {
    let doc: Yaml = serde_yaml::from_str(yaml).context("reading the compose file")?;
    let services = doc
        .get("services")
        .and_then(Yaml::as_mapping)
        .context("the compose file has no services")?;
    let mut warnings = Vec::new();
    let mut out = Table::new();
    for (key, svc) in services {
        let original = key.as_str().context("service names must be strings")?;
        let name = service_name(original)?;
        let svc = svc
            .as_mapping()
            .with_context(|| format!("service {original} is not a mapping"))?;
        let mut t = Table::new();
        let mut warn = |msg: String| warnings.push(format!("service {original}: {msg}"));
        for (k, v) in svc {
            let k = k.as_str().unwrap_or_default();
            match k {
                "image" => {
                    t.insert("container".into(), Toml::String(scalar(v, k)?));
                }
                "build" => bail!(
                    "service {original}: build is not supported; build and push the image, then use image"
                ),
                "command" | "entrypoint" => {
                    t.insert(k.into(), strings(&argv(v, k)?));
                }
                "environment" => {
                    t.insert("env".into(), strings(&environment(v)?));
                }
                "ports" => {
                    let mut ports = Vec::new();
                    for p in v.as_sequence().context("ports must be a list")? {
                        match port(p) {
                            Ok(s) => ports.push(s),
                            Err(e) => warn(format!("port skipped: {e:#}")),
                        }
                    }
                    t.insert("ports".into(), strings(&ports));
                }
                "expose" => {
                    let mut exposed = Vec::new();
                    for p in v.as_sequence().context("expose must be a list")? {
                        let s = scalar(p, k)?;
                        match s.split('/').next().unwrap_or_default().parse::<u16>() {
                            Ok(n) if n >= 1024 => exposed.push(Toml::Integer(n.into())),
                            _ => warn(format!(
                                "expose {s} skipped: only TCP ports 1024 and up can be relayed between services"
                            )),
                        }
                    }
                    t.insert("expose".into(), Toml::Array(exposed));
                }
                "volumes" => {
                    let mut vols = Vec::new();
                    for vol in v.as_sequence().context("volumes must be a list")? {
                        match volume(vol) {
                            Ok(s) => vols.push(s),
                            Err(e) => warn(format!("volume skipped: {e:#}")),
                        }
                    }
                    t.insert("volumes".into(), strings(&vols));
                }
                "depends_on" => {
                    let names: Vec<String> = match v {
                        Yaml::Sequence(s) => {
                            s.iter().map(|d| scalar(d, k)).collect::<Result<_>>()?
                        }
                        Yaml::Mapping(m) => {
                            m.keys().map(|d| scalar(d, k)).collect::<Result<_>>()?
                        }
                        _ => bail!("service {original}: depends_on must be a list or a mapping"),
                    };
                    let names = names
                        .iter()
                        .map(|n| service_name(n))
                        .collect::<Result<Vec<_>>>()?;
                    t.insert("depends_on".into(), strings(&names));
                }
                "restart" => {
                    let r = scalar(v, k)?;
                    let policy = match r.split(':').next().unwrap_or_default() {
                        "no" => "no",
                        "on-failure" => "on-failure",
                        "always" | "unless-stopped" => "always",
                        other => bail!("service {original}: unknown restart policy {other:?}"),
                    };
                    if r.contains(':') {
                        warn(format!("restart {r}: the retry count is dropped"));
                    }
                    t.insert("restart".into(), Toml::String(policy.into()));
                }
                "healthcheck" => {
                    if let Some(cmd) = health_command(v)? {
                        t.insert("ready".into(), Toml::String(cmd));
                    }
                }
                "cpus" => {
                    let n = match v {
                        Yaml::Number(n) => n.as_f64(),
                        Yaml::String(s) => s.parse().ok(),
                        _ => None,
                    }
                    .context("cpus must be a number")?;
                    t.insert(
                        "cpus".into(),
                        Toml::Integer((n.ceil() as i64).clamp(1, 255)),
                    );
                }
                "mem_limit" => {
                    t.insert(
                        "memory_mib".into(),
                        Toml::Integer(mebibytes(&scalar(v, k)?)? as i64),
                    );
                }
                k if QUIETLY_IGNORED.contains(&k) => {}
                other => warn(format!("{other} is not supported and was dropped")),
            }
        }
        t.retain(|_, v| !matches!(v, Toml::Array(a) if a.is_empty()));
        if !t.contains_key("container") {
            bail!("service {original} has no image");
        }
        if name != original {
            warnings.push(format!("service {original} was renamed {name}"));
        }
        out.insert(name, Toml::Table(t));
    }
    let mut file = Table::new();
    file.insert("name".into(), Toml::String(stack_name.into()));
    file.insert("service".into(), Toml::Table(out));
    let toml = toml::to_string_pretty(&file)?;
    crate::stack::parse(&toml).context("the converted file is not a valid stack")?;
    Ok(Converted { toml, warnings })
}

/// Compose allows `_` and capitals; stack service names are `a-z0-9-`.
fn service_name(s: &str) -> Result<String> {
    let n = s.to_ascii_lowercase().replace(['_', '.'], "-");
    if n.is_empty()
        || n.len() > 32
        || n.starts_with('-')
        || n.ends_with('-')
        || !n
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("service name {s:?} cannot be turned into a stack service name");
    }
    Ok(n)
}

fn scalar(v: &Yaml, what: &str) -> Result<String> {
    match v {
        Yaml::String(s) => Ok(s.clone()),
        Yaml::Number(n) => Ok(n.to_string()),
        Yaml::Bool(b) => Ok(b.to_string()),
        _ => bail!("{what} must be a string or a number"),
    }
}

fn strings(v: &[String]) -> Toml {
    Toml::Array(v.iter().cloned().map(Toml::String).collect())
}

/// A list stays as is; a string is split like a shell would, without expansion.
fn argv(v: &Yaml, what: &str) -> Result<Vec<String>> {
    match v {
        Yaml::Sequence(s) => s.iter().map(|a| scalar(a, what)).collect(),
        Yaml::String(s) => split_words(s),
        _ => bail!("{what} must be a string or a list"),
    }
}

fn split_words(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some('"'), '\\') => cur.extend(chars.next()),
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                in_word = true;
            }
            (None, '\\') => {
                cur.extend(chars.next());
                in_word = true;
            }
            (None, c) if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            (None, c) => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if quote.is_some() {
        bail!("unbalanced quote in {s:?}");
    }
    if in_word {
        out.push(cur);
    }
    Ok(out)
}

fn environment(v: &Yaml) -> Result<Vec<String>> {
    match v {
        Yaml::Sequence(s) => s.iter().map(|e| scalar(e, "environment")).collect(),
        Yaml::Mapping(m) => m
            .iter()
            .map(|(k, v)| {
                let k = scalar(k, "environment")?;
                Ok(match v {
                    Yaml::Null => k,
                    v => format!("{k}={}", scalar(v, "environment")?),
                })
            })
            .collect(),
        _ => bail!("environment must be a list or a mapping"),
    }
}

/// `"8080:80"`, `"127.0.0.1:8080:80"`, `8080`, or `{target: 80, published: 8080}` → `HOST:CONTAINER`.
fn port(v: &Yaml) -> Result<String> {
    let (host, target, proto) = match v {
        Yaml::Mapping(m) => {
            let get = |k: &str| m.get(k).map(|v| scalar(v, k)).transpose();
            let target = get("target")?.context("a long-syntax port needs target")?;
            (
                get("published")?.unwrap_or_else(|| target.clone()),
                target,
                get("protocol")?.unwrap_or_else(|| "tcp".into()),
            )
        }
        v => {
            let s = scalar(v, "port")?;
            let (s, proto) = s.split_once('/').unwrap_or((s.as_str(), "tcp"));
            let parts: Vec<&str> = s.split(':').collect();
            let (host, target) = match parts[..] {
                [p] => (p, p),
                [h, c] => (h, c),
                ["127.0.0.1" | "localhost", h, c] => (h, c),
                [ip, _, _] => {
                    bail!("{s}: ports are published on the Mac's 127.0.0.1 only, not {ip}")
                }
                _ => bail!("{s}: not a port mapping"),
            };
            (host.into(), target.into(), proto.into())
        }
    };
    if proto != "tcp" {
        bail!("{host}:{target}/{proto}: only tcp can be published");
    }
    if host.contains('-') || target.contains('-') {
        bail!("{host}:{target}: port ranges are not supported");
    }
    let spec = format!("{host}:{target}");
    fluxvm_scheduler::oci_sandbox::parse_port(&spec)?;
    Ok(spec)
}

/// Named volumes only: `name:/path[:ro]` (or the long syntax with `type: volume`). Bind mounts have no equivalent.
fn volume(v: &Yaml) -> Result<String> {
    let (source, target, read_only) = match v {
        Yaml::Mapping(m) => {
            let get = |k: &str| m.get(k).and_then(Yaml::as_str).map(str::to_owned);
            if get("type").as_deref().is_some_and(|t| t != "volume") {
                bail!("only named volumes are supported");
            }
            (
                get("source").context("a long-syntax volume needs source")?,
                get("target").context("a long-syntax volume needs target")?,
                m.get("read_only").and_then(Yaml::as_bool).unwrap_or(false),
            )
        }
        v => {
            let s = scalar(v, "volume")?;
            let mut parts = s.splitn(3, ':');
            let (Some(src), Some(dst)) = (parts.next(), parts.next()) else {
                bail!("{s}: anonymous volumes are not supported; name it, NAME:/path");
            };
            let opts = parts.next().unwrap_or_default();
            (src.into(), dst.into(), opts.split(',').any(|o| o == "ro"))
        }
    };
    if source.starts_with(['.', '/', '~']) {
        bail!(
            "{source}:{target}: bind mounts are not supported for container services; use a named volume"
        );
    }
    Ok(if read_only {
        format!("{source}:{target}:ro")
    } else {
        format!("{source}:{target}")
    })
}

/// The health check's command as one shell line, or `None` for `disable: true` / `["NONE"]`.
fn health_command(v: &Yaml) -> Result<Option<String>> {
    if v.get("disable").and_then(Yaml::as_bool) == Some(true) {
        return Ok(None);
    }
    let Some(test) = v.get("test") else {
        return Ok(None);
    };
    let words = match test {
        Yaml::String(s) => return Ok(Some(s.clone())),
        Yaml::Sequence(s) => s
            .iter()
            .map(|w| scalar(w, "healthcheck.test"))
            .collect::<Result<Vec<_>>>()?,
        _ => bail!("healthcheck.test must be a string or a list"),
    };
    match words.split_first() {
        Some((kind, rest)) if kind == "CMD-SHELL" => Ok(Some(rest.join(" "))),
        Some((kind, rest)) if kind == "CMD" => Ok(Some(
            rest.iter()
                .map(|w| shell_quote(w))
                .collect::<Vec<_>>()
                .join(" "),
        )),
        Some((kind, _)) if kind == "NONE" => Ok(None),
        _ => bail!("healthcheck.test must start with CMD, CMD-SHELL or NONE"),
    }
}

fn shell_quote(w: &str) -> String {
    if !w.is_empty()
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c))
    {
        w.into()
    } else {
        format!("'{}'", w.replace('\'', r"'\''"))
    }
}

/// `512m`, `1g`, `1.5gb`, `268435456` (bytes) → MiB, at least 64.
fn mebibytes(s: &str) -> Result<u64> {
    let lower = s.trim().to_ascii_lowercase();
    let units: BTreeMap<&str, f64> = BTreeMap::from([
        ("k", 1.0 / 1024.0),
        ("kb", 1.0 / 1024.0),
        ("m", 1.0),
        ("mb", 1.0),
        ("g", 1024.0),
        ("gb", 1024.0),
    ]);
    let split = lower
        .find(|c: char| c.is_ascii_alphabetic())
        .unwrap_or(lower.len());
    let (num, unit) = lower.split_at(split);
    let n: f64 = num.parse().with_context(|| format!("mem_limit {s:?}"))?;
    let mib = match unit {
        "" | "b" => n / (1024.0 * 1024.0),
        u => {
            n * units
                .get(u)
                .with_context(|| format!("mem_limit {s:?}: unknown unit"))?
        }
    };
    Ok((mib.ceil() as u64).max(64))
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPOSE: &str = r#"
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_PASSWORD: dev
      POSTGRES_DB: shop
    expose: ["5432"]
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "postgres"]
      interval: 5s
    restart: unless-stopped
  web_app:
    image: ghcr.io/acme/web:1
    command: python -m http.server "8000"
    ports:
      - "127.0.0.1:8000:8000"
      - "53:53/udp"
    volumes:
      - ./src:/app
    depends_on:
      db:
        condition: service_healthy
    mem_limit: 1g
    cpus: 1.5
    networks: [default]
    privileged: true
volumes:
  pgdata: {}
"#;

    #[test]
    fn compose_services_become_container_services() {
        let c = convert(COMPOSE, "shop").unwrap();
        let f = crate::stack::parse(&c.toml).unwrap();
        let db = &f.service["db"];
        assert_eq!(db.container.as_deref(), Some("postgres:17"));
        assert_eq!(db.env, ["POSTGRES_PASSWORD=dev", "POSTGRES_DB=shop"]);
        assert_eq!(db.expose, [5432]);
        assert_eq!(db.volumes, ["pgdata:/var/lib/postgresql/data"]);
        assert_eq!(db.ready.as_deref(), Some("pg_isready -U postgres"));
        assert_eq!(db.restart.as_deref(), Some("always"));
        let web = &f.service["web-app"];
        assert_eq!(
            web.command.as_deref().unwrap(),
            ["python", "-m", "http.server", "8000"]
        );
        assert_eq!(web.ports, ["8000:8000"]);
        assert!(web.volumes.is_empty());
        assert_eq!(web.depends_on, ["db"]);
        assert_eq!((web.memory_mib, web.cpus), (Some(1024), Some(2)));
        let w = c.warnings.join("\n");
        for needle in ["53:53/udp", "bind mounts", "privileged", "renamed web-app"] {
            assert!(w.contains(needle), "{needle}: {w}");
        }
        assert!(!w.contains("networks"), "{w}");
    }

    #[test]
    fn unsupported_compose_is_refused_with_a_reason() {
        for (yaml, needle) in [
            ("services:\n  a:\n    build: .\n", "build is not supported"),
            ("services:\n  a:\n    command: x\n", "has no image"),
            ("version: '3'\n", "no services"),
            (
                "services:\n  a:\n    image: x\n    restart: sometimes\n",
                "restart policy",
            ),
        ] {
            let err = format!("{:#}", convert(yaml, "s").err().unwrap());
            assert!(err.contains(needle), "{yaml}: {err}");
        }
    }

    #[test]
    fn small_parsers() {
        assert_eq!(
            split_words(r#"sh -c 'echo "hi there"' a\ b"#).unwrap(),
            ["sh", "-c", "echo \"hi there\"", "a b"]
        );
        assert!(split_words("'open").is_err());
        assert_eq!(mebibytes("512m").unwrap(), 512);
        assert_eq!(mebibytes("1.5GB").unwrap(), 1536);
        assert_eq!(mebibytes("268435456").unwrap(), 256);
        assert_eq!(mebibytes("1k").unwrap(), 64);
        assert!(mebibytes("12parsecs").is_err());
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(service_name("Web_App").unwrap(), "web-app");
        assert!(service_name("_x").is_err());
    }
}
