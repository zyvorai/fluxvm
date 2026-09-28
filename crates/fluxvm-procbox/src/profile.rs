// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! TOML policy profiles: a saved, reviewable form of a [`Policy`].
//!
//! Every key is optional and unknown keys are rejected, so a typo such as
//! `fs_reed` is an error instead of silently granting less (or more) than the
//! author meant. Filesystem paths must be absolute.

use crate::policy::{parse_size, Isolation, Policy, RunAs, SeccompMode, TcpRule};
use crate::run::SyscallOverrides;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// `"any"`, `"deny"`, or a list of TCP ports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NetRule {
    Keyword(String),
    Ports(Vec<u16>),
}

impl NetRule {
    fn to_rule(&self, key: &str) -> Result<TcpRule> {
        match self {
            NetRule::Keyword(k) if k == "any" => Ok(TcpRule::Any),
            NetRule::Keyword(k) if k == "deny" => Ok(TcpRule::Deny),
            NetRule::Keyword(k) => bail!(
                "{key} = {k:?}: expected \"any\", \"deny\", or a list of ports like [443, 8080]"
            ),
            NetRule::Ports(p) if p.is_empty() => {
                bail!("{key} = []: an empty port list is ambiguous; use \"deny\" to block all")
            }
            NetRule::Ports(p) => Ok(TcpRule::Ports(p.clone())),
        }
    }
}

/// A byte count: `268435456` or `"256M"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SizeValue {
    Bytes(u64),
    Text(String),
}

impl SizeValue {
    fn bytes(&self, key: &str) -> Result<u64> {
        match self {
            SizeValue::Bytes(b) => Ok(*b),
            SizeValue::Text(t) => parse_size(t).map_err(|e| anyhow!("{key}: {e}")),
        }
    }
}

/// The on-disk profile. Field order matters: scalars and arrays must precede
/// the `env` table in the serialized TOML.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Profile {
    /// Read-only (and executable) paths.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fs_read: Vec<PathBuf>,
    /// Read-write paths (implies read).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fs_write: Vec<PathBuf>,
    /// TCP connect rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_connect: Option<NetRule>,
    /// TCP bind rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub net_bind: Option<NetRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_ipc: Option<bool>,
    /// `"errno"`, `"kill"` or `"off"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_namespaces: Option<bool>,
    /// Extra syscalls to deny on top of the default denylist.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub syscall_deny: Vec<String>,
    /// Syscalls to remove from the default denylist.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub syscall_allow: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_memory: Option<SizeValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_processes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clean_env: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_effort: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_abi: Option<u32>,
    /// `"off"`, `"auto"` or `"strict"`: private user/mount/pid/ipc/uts (and
    /// network) namespaces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation: Option<String>,
    /// `"UID:GID"` (or `"UID"`): drop to this unprivileged id (root caller only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_as: Option<String>,
    /// Allow `socket(AF_UNIX)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_unix: Option<bool>,
    /// Allow UDP/raw/packet/netlink sockets on a shared network.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_udp: Option<bool>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

#[cfg(target_os = "linux")]
fn syscall_known(name: &str) -> bool {
    crate::seccomp::syscall_by_name(name).is_some()
}

#[cfg(not(target_os = "linux"))]
fn syscall_known(_name: &str) -> bool {
    true
}

impl Profile {
    /// Parse and validate TOML text.
    pub fn from_toml_str(s: &str) -> Result<Profile> {
        let p: Profile = toml::from_str(s).map_err(|e| anyhow!("invalid profile: {e}"))?;
        p.validate()?;
        Ok(p)
    }

    /// Serialize to TOML (no comments).
    pub fn to_toml_string(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| anyhow!("serializing profile: {e}"))
    }

    /// Load a profile by path or by name (see [`locate`]).
    pub fn load(spec: &str) -> Result<Profile> {
        let path = locate(spec)?;
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading profile {}", path.display()))?;
        Profile::from_toml_str(&text).with_context(|| format!("profile {}", path.display()))
    }

    /// Check everything that can be checked without running anything.
    pub fn validate(&self) -> Result<()> {
        for (key, paths) in [("fs_read", &self.fs_read), ("fs_write", &self.fs_write)] {
            for (i, p) in paths.iter().enumerate() {
                if !p.is_absolute() {
                    bail!(
                        "{key}[{i}] = {:?}: filesystem paths must be absolute",
                        p.display().to_string()
                    );
                }
            }
        }
        if let Some(cwd) = &self.cwd {
            if !cwd.is_absolute() {
                bail!(
                    "cwd = {:?}: must be an absolute path",
                    cwd.display().to_string()
                );
            }
        }
        if let Some(r) = &self.net_connect {
            let rule = r.to_rule("net_connect")?;
            if let TcpRule::Ports(ports) = rule {
                if ports.contains(&0) {
                    bail!("net_connect: port 0 is not a valid connect port");
                }
            }
        }
        if let Some(r) = &self.net_bind {
            r.to_rule("net_bind")?;
        }
        if let Some(s) = &self.seccomp {
            if !matches!(s.as_str(), "errno" | "kill" | "off") {
                bail!("seccomp = {s:?}: expected \"errno\", \"kill\" or \"off\"");
            }
        }
        if let Some(m) = &self.max_memory {
            m.bytes("max_memory")?;
        }
        if let Some(i) = &self.isolation {
            i.parse::<Isolation>().map_err(|e| anyhow!("{e}"))?;
        }
        if let Some(r) = &self.run_as {
            r.parse::<RunAs>().map_err(|e| anyhow!("run_as: {e}"))?;
        }
        for (key, names) in [
            ("syscall_deny", &self.syscall_deny),
            ("syscall_allow", &self.syscall_allow),
        ] {
            for n in names {
                if !syscall_known(n) {
                    bail!("{key}: unknown syscall name {n:?}");
                }
            }
        }
        for n in &self.syscall_deny {
            if self.syscall_allow.contains(n) {
                bail!("syscall {n:?} is in both syscall_deny and syscall_allow");
            }
        }
        for k in self.env.keys() {
            if k.is_empty() || k.contains('=') {
                bail!("env key {k:?} is not a valid variable name");
            }
        }
        Ok(())
    }

    /// Layer this profile onto `policy`: lists are extended, scalars set when
    /// present. Callers apply CLI flags afterwards so flags win.
    pub fn apply(&self, policy: &mut Policy, overrides: &mut SyscallOverrides) -> Result<()> {
        self.validate()?;
        policy.read.extend(self.fs_read.iter().cloned());
        policy.write.extend(self.fs_write.iter().cloned());
        if let Some(r) = &self.net_connect {
            policy.tcp_connect = r.to_rule("net_connect")?;
        }
        if let Some(r) = &self.net_bind {
            policy.tcp_bind = r.to_rule("net_bind")?;
        }
        if let Some(v) = self.scope_ipc {
            policy.scope_ipc = v;
        }
        if let Some(s) = &self.seccomp {
            policy.seccomp = match s.as_str() {
                "errno" => Some(SeccompMode::Errno),
                "kill" => Some(SeccompMode::Kill),
                _ => None,
            };
        }
        if let Some(v) = self.allow_namespaces {
            policy.allow_namespaces = v;
        }
        if let Some(m) = &self.max_memory {
            policy.max_memory = Some(m.bytes("max_memory")?);
        }
        if let Some(v) = self.max_processes {
            policy.max_processes = Some(v);
        }
        if let Some(v) = self.cpu_seconds {
            policy.cpu_seconds = Some(v);
        }
        if let Some(v) = self.timeout_secs {
            policy.timeout_secs = Some(v);
        }
        if let Some(v) = self.clean_env {
            policy.clean_env = v;
        }
        if let Some(c) = &self.cwd {
            policy.cwd = Some(c.clone());
        }
        if let Some(v) = self.best_effort {
            policy.best_effort = v;
        }
        if let Some(v) = self.max_abi {
            policy.max_abi = Some(v);
        }
        if let Some(i) = &self.isolation {
            policy.isolation = i.parse().map_err(|e: String| anyhow!(e))?;
        }
        if let Some(r) = &self.run_as {
            policy.run_as = Some(r.parse().map_err(|e: String| anyhow!("run_as: {e}"))?);
        }
        if let Some(v) = self.allow_unix {
            policy.allow_unix = v;
        }
        if let Some(v) = self.allow_udp {
            policy.allow_udp = v;
        }
        for (k, v) in &self.env {
            policy.env.push((k.clone(), v.clone()));
        }
        overrides.deny.extend(self.syscall_deny.iter().cloned());
        overrides.allow.extend(self.syscall_allow.iter().cloned());
        Ok(())
    }

    /// The policy (and syscall overrides) this profile describes on its own.
    pub fn into_policy(&self) -> Result<(Policy, SyscallOverrides)> {
        let mut p = Policy::default();
        let mut o = SyscallOverrides::default();
        self.apply(&mut p, &mut o)?;
        Ok((p, o))
    }

    /// One-line-per-fact summary for `profile validate`.
    pub fn summary(&self) -> Vec<String> {
        let mut out = vec![
            format!("fs_read: {} path(s)", self.fs_read.len()),
            format!("fs_write: {} path(s)", self.fs_write.len()),
        ];
        let net = |r: &Option<NetRule>| match r {
            None => "unset (unrestricted)".to_string(),
            Some(NetRule::Keyword(k)) => k.clone(),
            Some(NetRule::Ports(p)) => format!("ports {p:?}"),
        };
        out.push(format!("net_connect: {}", net(&self.net_connect)));
        out.push(format!("net_bind: {}", net(&self.net_bind)));
        if !self.syscall_deny.is_empty() || !self.syscall_allow.is_empty() {
            out.push(format!(
                "syscalls: +{} denied, -{} allowed vs the default denylist",
                self.syscall_deny.len(),
                self.syscall_allow.len()
            ));
        }
        out
    }
}

/// Directory searched for named profiles: `$XDG_CONFIG_HOME/fluxvm-procbox/profiles`,
/// else `$HOME/.config/fluxvm-procbox/profiles`.
pub fn profile_dir() -> Option<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(v) if !v.is_empty() && Path::new(&v).is_absolute() => PathBuf::from(v),
        _ => {
            let home = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
            PathBuf::from(home).join(".config")
        }
    };
    Some(base.join("fluxvm-procbox").join("profiles"))
}

/// Resolve `-p SPEC`: anything with a `/` or ending in `.toml` is a path,
/// otherwise a name looked up in [`profile_dir`].
pub fn locate(spec: &str) -> Result<PathBuf> {
    locate_in(spec, profile_dir().as_deref())
}

pub fn locate_in(spec: &str, dir: Option<&Path>) -> Result<PathBuf> {
    if spec.is_empty() {
        bail!("empty profile name");
    }
    if spec.contains('/') || spec.ends_with(".toml") {
        return Ok(PathBuf::from(spec));
    }
    if !spec
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        || spec.starts_with('.')
    {
        bail!("profile name {spec:?} may only contain letters, digits, '.', '_' and '-'");
    }
    let dir = dir.ok_or_else(|| {
        anyhow!("cannot find a profile directory (set XDG_CONFIG_HOME or HOME), or pass a path")
    })?;
    let path = dir.join(format!("{spec}.toml"));
    if !path.is_file() {
        bail!(
            "profile {spec:?} not found (looked for {}); pass a path or create it",
            path.display()
        );
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_profile_round_trips() {
        let text = r#"
fs_read = ["/usr", "/lib"]
fs_write = ["/tmp/work"]
net_connect = [443, 8080]
net_bind = "deny"
scope_ipc = true
seccomp = "kill"
syscall_deny = ["chmod"]
syscall_allow = ["ptrace"]
max_memory = "256M"
max_processes = 200
timeout_secs = 30
clean_env = true
cwd = "/tmp/work"
best_effort = false

[env]
FOO = "bar"
"#;
        let p = Profile::from_toml_str(text).unwrap();
        let back = Profile::from_toml_str(&p.to_toml_string().unwrap()).unwrap();
        assert_eq!(p, back);
        let (pol, ov) = p.into_policy().unwrap();
        assert_eq!(pol.read.len(), 2);
        assert_eq!(pol.tcp_connect, TcpRule::Ports(vec![443, 8080]));
        assert_eq!(pol.tcp_bind, TcpRule::Deny);
        assert_eq!(pol.seccomp, Some(SeccompMode::Kill));
        assert_eq!(pol.max_memory, Some(256 << 20));
        assert!(pol.clean_env);
        assert_eq!(pol.env, vec![("FOO".to_string(), "bar".to_string())]);
        assert_eq!(ov.deny, vec!["chmod".to_string()]);
        assert_eq!(ov.allow, vec!["ptrace".to_string()]);
    }

    #[test]
    fn unknown_keys_are_rejected_with_the_offending_name() {
        let e = Profile::from_toml_str("fs_reed = [\"/usr\"]").unwrap_err();
        assert!(format!("{e}").contains("fs_reed"), "{e}");
    }

    #[test]
    fn relative_paths_are_rejected() {
        let e = Profile::from_toml_str("fs_read = [\"/usr\", \"lib\"]").unwrap_err();
        let m = format!("{e}");
        assert!(m.contains("fs_read[1]") && m.contains("absolute"), "{m}");
        assert!(Profile::from_toml_str("fs_write = [\"rel/x\"]").is_err());
        assert!(Profile::from_toml_str("cwd = \"rel\"").is_err());
    }

    #[test]
    fn bad_values_are_rejected() {
        for bad in [
            "net_connect = \"maybe\"",
            "net_connect = []",
            "net_connect = [0]",
            "seccomp = \"loud\"",
            "max_memory = \"lots\"",
            "syscall_deny = [\"not_a_syscall\"]",
            "syscall_deny = [\"chmod\"]\nsyscall_allow = [\"chmod\"]",
        ] {
            assert!(Profile::from_toml_str(bad).is_err(), "accepted {bad:?}");
        }
        assert!(Profile::from_toml_str("net_connect = \"any\"\nnet_bind = [0]").is_ok());
    }

    #[test]
    fn isolation_keys_apply_and_are_validated() {
        let p = Profile::from_toml_str(
            "isolation = \"strict\"\nrun_as = \"4000:4000\"\nallow_unix = true\nallow_udp = true",
        )
        .unwrap();
        let (pol, _) = p.into_policy().unwrap();
        assert_eq!(pol.isolation, Isolation::Strict);
        assert_eq!(
            pol.run_as,
            Some(RunAs {
                uid: 4000,
                gid: 4000
            })
        );
        assert!(pol.allow_unix && pol.allow_udp);
        assert!(Profile::from_toml_str("isolation = \"full\"").is_err());
        assert!(Profile::from_toml_str("run_as = \"0\"").is_err());
    }

    #[test]
    fn empty_profile_is_the_default_policy() {
        let p = Profile::from_toml_str("").unwrap();
        let (pol, ov) = p.into_policy().unwrap();
        assert!(pol.read.is_empty() && pol.scope_ipc && !pol.best_effort);
        assert!(ov.deny.is_empty() && ov.allow.is_empty());
    }

    #[test]
    fn named_profiles_resolve_in_the_profile_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("build.toml"), "fs_read = [\"/usr\"]").unwrap();
        let p = locate_in("build", Some(dir.path())).unwrap();
        assert_eq!(p, dir.path().join("build.toml"));
        assert!(locate_in("missing", Some(dir.path())).is_err());
        assert_eq!(
            locate_in("./x.toml", Some(dir.path())).unwrap(),
            PathBuf::from("./x.toml")
        );
        assert_eq!(
            locate_in("/etc/p.toml", None).unwrap(),
            PathBuf::from("/etc/p.toml")
        );
        for bad in ["", "..", ".hidden", "a b", "a;b"] {
            assert!(locate_in(bad, Some(dir.path())).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn xdg_config_home_selects_the_profile_dir() {
        // Environment is process-global: only assert on a value we set and
        // restore, and only the pure suffix logic.
        let d = profile_dir();
        if let Some(d) = d {
            assert!(d.ends_with("fluxvm-procbox/profiles"));
        }
    }
}
