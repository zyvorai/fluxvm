// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `fluxctl run`: boot a throwaway VM, SSH into it, and delete it when the session ends.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub struct RunOptions {
    pub image: Option<String>,
    pub name: Option<String>,
    pub cpus: u8,
    pub memory_mib: u64,
    pub ports: Vec<String>,
    pub volumes: Vec<String>,
    pub user: Option<String>,
    pub keep: bool,
    pub command: Vec<String>,
}

/// The three VM operations `run` needs, so one flow serves both the local state dir and `--server`.
pub trait VmApi {
    async fn create(&self, spec: Value) -> Result<Uuid>;
    async fn guest_ip(&self, id: Uuid) -> Result<Option<String>>;
    async fn delete(&self, id: Uuid) -> Result<()>;
}

pub struct Local<'a>(pub &'a std::sync::Arc<fluxvm_scheduler::VmManager>);

impl VmApi for Local<'_> {
    async fn create(&self, spec: Value) -> Result<Uuid> {
        Ok(self.0.create(serde_json::from_value(spec)?).await?.id)
    }
    async fn guest_ip(&self, id: Uuid) -> Result<Option<String>> {
        Ok(self.0.get(id).await?.guest_ip.clone())
    }
    async fn delete(&self, id: Uuid) -> Result<()> {
        self.0.delete(id).await
    }
}

impl VmApi for crate::remote::Remote {
    async fn create(&self, spec: Value) -> Result<Uuid> {
        let v = self
            .call(reqwest::Method::POST, "/v1/vms", Some(spec))
            .await?;
        v["id"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .context("the daemon's create response has no id")
    }
    async fn guest_ip(&self, id: Uuid) -> Result<Option<String>> {
        let v = self
            .call(reqwest::Method::GET, &format!("/v1/vms/{id}"), None)
            .await?;
        Ok(v["guest_ip"].as_str().map(str::to_owned))
    }
    async fn delete(&self, id: Uuid) -> Result<()> {
        self.vm_op(id, "delete").await.map(drop)
    }
}

/// `8080:80` -> a TCP forward from 127.0.0.1:8080 to guest port 80.
pub fn parse_port(s: &str) -> Result<Value> {
    let (h, g) = s
        .split_once(':')
        .with_context(|| format!("port {s:?} must be HOST:GUEST"))?;
    let (h, g): (u16, u16) = (
        h.parse()
            .with_context(|| format!("bad host port in {s:?}"))?,
        g.parse()
            .with_context(|| format!("bad guest port in {s:?}"))?,
    );
    Ok(json!({"host_port": h, "guest_port": g}))
}

/// `~/src:/mnt/src` or `./dir:/mnt/dir:ro` -> a shared folder. The host side may be relative or start with `~`.
pub fn parse_volume(s: &str, cwd: &Path, home: Option<&Path>) -> Result<Value> {
    let (rest, read_only) = match s.strip_suffix(":ro") {
        Some(r) => (r, true),
        None => (s.strip_suffix(":rw").unwrap_or(s), false),
    };
    let (host, guest) = rest
        .split_once(':')
        .with_context(|| format!("volume {s:?} must be HOST:GUEST[:ro]"))?;
    if !guest.starts_with('/') {
        bail!("volume {s:?}: the guest path must be absolute");
    }
    let host = match (host.strip_prefix("~/"), home) {
        (Some(r), Some(h)) => h.join(r),
        _ if host == "~" && home.is_some() => home.unwrap().to_path_buf(),
        _ => PathBuf::from(host),
    };
    let host = cwd.join(host);
    let host = host
        .canonicalize()
        .with_context(|| format!("volume {s:?}: {} does not exist", host.display()))?;
    Ok(json!({"host_path": host, "guest_path": guest, "read_only": read_only}))
}

/// The user's first SSH public key, or a new `~/.ssh/fluxvm_ed25519` pair. Returns the key text and, for a
/// generated key, the private key `ssh` must be told to use.
fn ssh_key(home: &Path) -> Result<(String, Option<PathBuf>)> {
    let ssh = home.join(".ssh");
    for n in ["id_ed25519", "id_ecdsa", "id_rsa"] {
        if let Ok(k) = std::fs::read_to_string(ssh.join(format!("{n}.pub"))) {
            return Ok((k.trim().to_owned(), None));
        }
    }
    let key = ssh.join("fluxvm_ed25519");
    if !key.exists() {
        std::fs::create_dir_all(&ssh)?;
        let ok = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "fluxvm", "-f"])
            .arg(&key)
            .status()
            .context("running ssh-keygen")?
            .success();
        if !ok {
            bail!("ssh-keygen failed");
        }
    }
    let k = std::fs::read_to_string(key.with_extension("pub"))
        .or_else(|_| std::fs::read_to_string(format!("{}.pub", key.display())))?;
    Ok((k.trim().to_owned(), Some(key)))
}

fn ssh_base(ip: &str, user: &str, key: &Option<PathBuf>) -> std::process::Command {
    let mut c = std::process::Command::new("ssh");
    c.args([
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
    ]);
    if let Some(k) = key {
        c.arg("-i").arg(k);
    }
    c.arg(format!("{user}@{ip}"));
    c
}

pub fn build_spec(
    o: &RunOptions,
    name: &str,
    user: &str,
    key: &str,
    volumes: Vec<Value>,
) -> Result<Value> {
    let image = o.image.clone().unwrap_or_else(|| "debian-13".into());
    let forwards = o
        .ports
        .iter()
        .map(|p| parse_port(p))
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({
        "name": name,
        "backend": "auto",
        "image": image,
        "vcpus": o.cpus,
        "memory_mib": o.memory_mib,
        "network": {"mode": "user", "forwards": forwards},
        "shared_folders": volumes,
        "cloud_init": {"hostname": name, "user": user, "ssh_authorized_keys": [key]},
    }))
}

/// Returns the exit code `fluxctl` should finish with.
pub async fn run<A: VmApi>(api: &A, o: RunOptions) -> Result<i32> {
    if o.image.is_none() && !cfg!(target_os = "macos") {
        bail!("pass an image: the built-in default `debian-13` is only available on macOS");
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")?;
    let cwd = std::env::current_dir()?;
    let user = o
        .user
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "fluxvm".into());
    let name = o
        .name
        .clone()
        .unwrap_or_else(|| format!("run-{}", &Uuid::new_v4().simple().to_string()[..6]));
    let volumes = o
        .volumes
        .iter()
        .map(|v| parse_volume(v, &cwd, Some(&home)))
        .collect::<Result<Vec<_>>>()?;
    let (pubkey, identity) = ssh_key(&home)?;
    let spec = build_spec(&o, &name, &user, &pubkey, volumes)?;

    eprintln!(
        "creating {name} from {}…",
        spec["image"].as_str().unwrap_or("")
    );
    let id = api.create(spec).await.context("creating the VM")?;
    let session = async {
        let deadline = Instant::now() + Duration::from_secs(180);
        let ip = loop {
            if let Some(ip) = api.guest_ip(id).await? {
                break ip;
            }
            if Instant::now() > deadline {
                bail!("the VM did not report an address within 180s");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        };
        eprintln!("waiting for ssh on {ip}…");
        loop {
            let ready = tokio::process::Command::from(ssh_base(&ip, &user, &identity))
                .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "true"])
                .stdin(std::process::Stdio::null())
                .status()
                .await
                .context("running ssh (is the OpenSSH client installed?)")?
                .success();
            if ready {
                break;
            }
            if Instant::now() > deadline {
                bail!("ssh did not come up within 180s");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let mut c = tokio::process::Command::from(ssh_base(&ip, &user, &identity));
        if o.command.is_empty() {
            c.arg("-tt");
        }
        let status = c.args(&o.command).status().await.context("running ssh")?;
        Ok::<i32, anyhow::Error>(status.code().unwrap_or(1))
    };
    let result = tokio::select! {
        r = session => r,
        _ = tokio::signal::ctrl_c() => Ok(130),
    };
    if o.keep {
        eprintln!("kept {name} ({id}); remove it with `fluxctl delete {name}`");
    } else {
        eprintln!("deleting {name}…");
        if let Err(e) = api.delete(id).await {
            eprintln!("warning: could not delete {id}: {e:#}");
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_parse_as_host_guest() {
        assert_eq!(
            parse_port("8080:80").unwrap(),
            json!({"host_port": 8080, "guest_port": 80})
        );
        assert!(parse_port("80").is_err());
        assert!(parse_port("a:80").is_err());
        assert!(parse_port("8080:99999").is_err());
    }

    #[test]
    fn volumes_resolve_relative_tilde_and_ro() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        let root = dir.path().canonicalize().unwrap();
        let v = parse_volume("src:/mnt/src:ro", &root, None).unwrap();
        assert_eq!(v["host_path"], json!(root.join("src")));
        assert_eq!(v["guest_path"], "/mnt/src");
        assert_eq!(v["read_only"], true);
        let v = parse_volume("~/src:/mnt/s", Path::new("/nowhere"), Some(&root)).unwrap();
        assert_eq!(v["host_path"], json!(root.join("src")));
        assert_eq!(v["read_only"], false);
        assert!(parse_volume("src:mnt", &root, None).is_err());
        assert!(parse_volume("missing:/mnt/x", &root, None).is_err());
        assert!(parse_volume("src", &root, None).is_err());
    }

    #[test]
    fn spec_defaults_to_debian_13_on_the_auto_backend() {
        let o = RunOptions {
            image: None,
            name: None,
            cpus: 2,
            memory_mib: 2048,
            ports: vec!["2222:22".into()],
            volumes: vec![],
            user: None,
            keep: false,
            command: vec![],
        };
        let s = build_spec(&o, "run-abc", "dev", "ssh-ed25519 AAA", vec![]).unwrap();
        assert_eq!(s["image"], "debian-13");
        assert_eq!(s["backend"], "auto");
        assert_eq!(s["network"]["forwards"][0]["guest_port"], 22);
        assert_eq!(s["cloud_init"]["user"], "dev");
    }
}
