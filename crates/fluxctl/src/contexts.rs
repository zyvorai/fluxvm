//! Named remote endpoints (`fluxctl context ...`), kubeconfig-style.
//! Stored as JSON (mode 0600, it holds tokens) at `$FLUXCTL_CONTEXTS`, else
//! `$XDG_CONFIG_HOME/fluxctl/contexts.json`, else `~/.config/fluxctl/contexts.json`.

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Endpoint {
    pub server: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Keychain generic-password service holding the token (account: the context name), instead of `token`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_keychain: Option<String>,
}

impl Endpoint {
    /// The stored token, or the one read from the Keychain item for context `name`.
    pub fn resolve_token(&self, name: &str) -> Result<Option<String>> {
        match (&self.token, &self.token_keychain) {
            (Some(_), Some(_)) => bail!("context {name:?} sets both token and token_keychain"),
            (Some(t), None) => Ok(Some(t.clone())),
            (None, Some(service)) => fluxvm_core::keychain::read_password(service, name)
                .map(Some)
                .with_context(|| format!("context {name:?}")),
            (None, None) => Ok(None),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Contexts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(default)]
    pub contexts: BTreeMap<String, Endpoint>,
}

pub fn path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("FLUXCTL_CONTEXTS") {
        return Some(PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("fluxctl").join("contexts.json"))
}

impl Contexts {
    pub fn load() -> Result<Self> {
        let Some(p) = path() else {
            return Ok(Self::default());
        };
        match std::fs::read_to_string(&p) {
            Ok(s) => serde_json::from_str(&s).with_context(|| format!("parsing {}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let p = path().context("no HOME/XDG_CONFIG_HOME to store contexts in")?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = p.with_extension("json.tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }

    /// The endpoint for `name`, else the current context, else none (local mode).
    pub fn resolve(&self, name: Option<&str>) -> Result<Option<(String, Endpoint)>> {
        let Some(name) = name.or(self.current.as_deref()) else {
            return Ok(None);
        };
        match self.contexts.get(name) {
            Some(ep) => Ok(Some((name.to_string(), ep.clone()))),
            None => bail!("unknown fluxctl context {name:?} (see `fluxctl context list`)"),
        }
    }

    pub fn add(&mut self, name: &str, ep: Endpoint) -> Result<()> {
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            bail!("invalid context name {name:?}: use [A-Za-z0-9._-]");
        }
        self.contexts.insert(name.to_string(), ep);
        Ok(())
    }

    pub fn use_context(&mut self, name: &str) -> Result<()> {
        if !self.contexts.contains_key(name) {
            bail!("unknown fluxctl context {name:?}");
        }
        self.current = Some(name.to_string());
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> Result<()> {
        if self.contexts.remove(name).is_none() {
            bail!("unknown fluxctl context {name:?}");
        }
        if self.current.as_deref() == Some(name) {
            self.current = None;
        }
        Ok(())
    }

    /// Listing without tokens.
    pub fn summary(&self) -> Vec<serde_json::Value> {
        self.contexts
            .iter()
            .map(|(name, ep)| {
                serde_json::json!({
                    "name": name,
                    "server": ep.server,
                    "token": ep.token.is_some() || ep.token_keychain.is_some(),
                    "token_keychain": ep.token_keychain,
                    "current": self.current.as_deref() == Some(name),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> Endpoint {
        Endpoint {
            server: s.into(),
            token: None,
            token_keychain: None,
        }
    }

    #[test]
    fn a_token_comes_from_the_file_or_the_keychain_not_both() {
        let mut e = ep("https://lab");
        assert_eq!(e.resolve_token("lab").unwrap(), None);
        e.token = Some("t".into());
        assert_eq!(e.resolve_token("lab").unwrap().as_deref(), Some("t"));
        e.token_keychain = Some("fluxvm-lab".into());
        assert!(e.resolve_token("lab").is_err());
        e.token = None;
        let parsed: Endpoint =
            serde_json::from_str(r#"{"server":"https://lab","token_keychain":"fluxvm-lab"}"#)
                .unwrap();
        assert_eq!(parsed, e);
    }

    #[test]
    fn add_use_resolve_remove() {
        let mut c = Contexts::default();
        assert!(c.resolve(None).unwrap().is_none());
        c.add("lab", ep("http://lab:7788")).unwrap();
        c.add("prod", ep("https://prod")).unwrap();
        assert!(c.add("bad name", ep("x")).is_err());
        assert!(c.use_context("nope").is_err());
        c.use_context("lab").unwrap();
        assert_eq!(
            c.resolve(None).unwrap().unwrap().1.server,
            "http://lab:7788"
        );
        assert_eq!(c.resolve(Some("prod")).unwrap().unwrap().0, "prod");
        assert!(c.resolve(Some("nope")).is_err());
        c.remove("lab").unwrap();
        assert!(c.current.is_none());
        assert_eq!(c.summary().len(), 1);
    }

    #[test]
    fn save_load_roundtrip_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ctx.json");
        // SAFETY: test-only; no other test reads FLUXCTL_CONTEXTS.
        unsafe { std::env::set_var("FLUXCTL_CONTEXTS", &file) };
        let mut c = Contexts::default();
        c.add(
            "lab",
            Endpoint {
                server: "http://lab".into(),
                token: Some("s3cret".into()),
                token_keychain: None,
            },
        )
        .unwrap();
        c.use_context("lab").unwrap();
        c.save().unwrap();
        assert_eq!(Contexts::load().unwrap(), c);
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            !serde_json::to_string(&c.summary())
                .unwrap()
                .contains("s3cret")
        );
        unsafe { std::env::remove_var("FLUXCTL_CONTEXTS") };
    }
}
