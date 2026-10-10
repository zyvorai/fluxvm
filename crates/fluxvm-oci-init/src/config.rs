// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! The host-to-guest contract: `config.json` in the meta share, and the markers init prints on the console.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// virtiofs tag of the read-only share holding [`CONFIG_FILE`] and [`TOKEN_FILE`].
pub const META_TAG: &str = "fluxvm-meta";
/// virtiofs tag of the read-only blob store share (builder VM only).
pub const BLOBS_TAG: &str = "fluxvm-blobs";
pub const CONFIG_FILE: &str = "config.json";
pub const TOKEN_FILE: &str = "agent.token";
/// Where the initramfs tools are visible inside the container after the root switch.
pub const TOOLS_DIR: &str = "/.fluxvm";
/// virtiofs tags of persistent volumes: `fluxvm-vol0`, `fluxvm-vol1`, …
pub const VOLUME_TAG_PREFIX: &str = "fluxvm-vol";

/// Console lines the host parses from the serial log.
pub const UNPACK_OK: &str = "FLUXVM-UNPACK-OK";
pub const UNPACK_ERR: &str = "FLUXVM-UNPACK-ERR";
pub const EXIT_MARKER: &str = "FLUXVM-EXIT";
/// Init could not start the container (bad rootfs, unknown user, missing binary); the reason follows.
pub const INIT_ERR: &str = "FLUXVM-INIT-ERR";
/// The guest's DHCP address; the runner parses it to know where published ports go (same line as cloud-init guests).
pub const GUEST_IP_MARKER: &str = "VELORA-IP";

/// Tells the guest agent that `Shutdown` means "signal PID 1" (SIGUSR2), not the image's shutdown(8).
pub const POWEROFF_VIA_INIT_ENV: &str = "FLUXVM_POWEROFF_VIA_INIT";
pub const EGRESS_PROXY_PORT: u16 = 3128;
pub const EGRESS_PROXY_URL: &str = "http://127.0.0.1:3128";

pub const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// The process runs as `nobody` unless the image or the request names a user.
pub const DEFAULT_USER: &str = "65534:65534";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum InitConfig {
    Boot(BootConfig),
    Unpack(UnpackConfig),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootConfig {
    pub hostname: String,
    pub process: ProcessSpec,
    /// Image root stays read-only (an overlay with a tmpfs upper, remounted read-only); `/tmp` and `/run` are tmpfs.
    #[serde(default)]
    pub read_only_root: bool,
    #[serde(default)]
    pub network: NetworkMode,
    /// Relay `127.0.0.1:3128` to the host's allow-listed egress proxy on vsock port 3128.
    #[serde(default)]
    pub egress_proxy: bool,
    #[serde(default)]
    pub exit_policy: ExitPolicy,
    #[serde(default = "default_agent_port")]
    pub agent_port: u32,
    #[serde(default)]
    pub restart: crate::supervise::RestartPolicy,
    /// Stop restarting after this many restarts (unlimited when absent).
    #[serde(default)]
    pub max_restarts: Option<u32>,
    #[serde(default)]
    pub healthcheck: Option<crate::supervise::HealthCheck>,
    /// Persistent volumes: virtiofs shares mounted into the root before the process starts.
    #[serde(default)]
    pub mounts: Vec<VolumeMount>,
}

/// A virtiofs share (tag `fluxvm-vol<N>`) mounted at `target` in the container's root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeMount {
    pub tag: String,
    pub target: String,
    #[serde(default)]
    pub read_only: bool,
}

/// The tag of the `index`th volume share.
pub fn volume_tag(index: usize) -> String {
    format!("{VOLUME_TAG_PREFIX}{index}")
}

impl VolumeMount {
    /// An absolute path below the root (not `/` itself, no `.` or `..` parts) and a `fluxvm-vol<N>` tag.
    pub fn validate(&self) -> Result<()> {
        let n = self
            .tag
            .strip_prefix(VOLUME_TAG_PREFIX)
            .context("volume tag must start with fluxvm-vol")?;
        if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
            bail!("bad volume tag {:?}", self.tag);
        }
        let rel = self
            .target
            .strip_prefix('/')
            .with_context(|| format!("volume target {:?} must be absolute", self.target))?;
        if rel.is_empty()
            || rel
                .split('/')
                .any(|c| c.is_empty() || c == "." || c == "..")
        {
            bail!("bad volume target {:?}", self.target);
        }
        Ok(())
    }
}

fn default_agent_port() -> u32 {
    17777
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    #[default]
    Dhcp,
    None,
}

/// What happens when the main process exits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExitPolicy {
    /// Keep the VM (and the agent) up for exec and file access.
    #[default]
    Keep,
    /// Power off; the exit code is on the console as `FLUXVM-EXIT <code>`.
    Poweroff,
}

/// The container process, already resolved from the image config and the request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSpec {
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    /// OCI `User`: `uid`, `uid:gid`, `name` or `name:group`, resolved inside the guest against the image's
    /// `/etc/passwd` and `/etc/group`.
    pub user: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpackConfig {
    pub layers: Vec<UnpackLayer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpackLayer {
    /// File name in the blob share (the sha256 hex of the compressed blob).
    pub blob: String,
    pub compression: Compression,
    /// `sha256:` of the uncompressed tar.
    pub diff_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    None,
    Gzip,
    Zstd,
}

/// Overrides a request may apply on top of the image config.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessOverrides {
    /// Replaces the image `Entrypoint` (and, as with `docker run --entrypoint`, drops its `Cmd`).
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    /// Replaces the image `Cmd`.
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// `KEY=value`, added to or replacing the image's entries.
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub workdir: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
}

/// Image config fields that decide the process (OCI `config` object).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageProcess {
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
}

/// Docker/OCI rules: argv is Entrypoint + Cmd; overrides win; `PATH` always set; user defaults to nobody.
pub fn resolve_process(image: &ImageProcess, o: &ProcessOverrides) -> Result<ProcessSpec> {
    let entrypoint = o
        .entrypoint
        .clone()
        .or_else(|| image.entrypoint.clone())
        .unwrap_or_default();
    let cmd = match (&o.command, &o.entrypoint) {
        (Some(c), _) => c.clone(),
        (None, Some(_)) => Vec::new(),
        (None, None) => image.cmd.clone().unwrap_or_default(),
    };
    let argv: Vec<String> = entrypoint.into_iter().chain(cmd).collect();
    if argv.first().is_none_or(|a| a.is_empty()) {
        bail!("the image has no Entrypoint or Cmd; give a command");
    }
    if argv.iter().any(|a| a.contains('\0')) {
        bail!("command arguments cannot contain NUL");
    }
    let mut env: Vec<String> = Vec::new();
    for e in image.env.iter().flatten().chain(o.env.iter()) {
        let Some((k, _)) = e.split_once('=') else {
            bail!("environment entry {e:?} is not KEY=value");
        };
        if k.is_empty() || e.contains('\0') {
            bail!("environment entry {e:?} is invalid");
        }
        env.retain(|x| x.split_once('=').map(|(xk, _)| xk) != Some(k));
        env.push(e.clone());
    }
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push(format!("PATH={DEFAULT_PATH}"));
    }
    let cwd = o
        .workdir
        .clone()
        .or_else(|| image.working_dir.clone().filter(|w| !w.is_empty()))
        .unwrap_or_else(|| "/".into());
    if !cwd.starts_with('/') {
        bail!("working directory {cwd:?} must be absolute");
    }
    let user = o
        .user
        .clone()
        .or_else(|| image.user.clone().filter(|u| !u.is_empty()))
        .unwrap_or_else(|| DEFAULT_USER.into());
    Ok(ProcessSpec {
        argv,
        env,
        cwd,
        user,
    })
}

/// The exit code from a console log, if the main process has exited.
pub fn exit_code_from_log(log: &str) -> Option<i32> {
    log.lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix(EXIT_MARKER)?.trim().parse().ok())
}

/// Why init gave up before the process ran, if it did.
pub fn init_error_from_log(log: &str) -> Option<String> {
    log.lines().rev().find_map(|l| {
        l.trim()
            .strip_prefix(INIT_ERR)
            .map(|r| r.trim().to_string())
    })
}

/// The builder VM's verdict from its console log: `Some(Ok)`, `Some(Err(reason))`, or `None` if it has not finished.
pub fn unpack_result_from_log(log: &str) -> Option<Result<(), String>> {
    log.lines().rev().find_map(|l| {
        let l = l.trim();
        if l == UNPACK_OK {
            Some(Ok(()))
        } else {
            l.strip_prefix(UNPACK_ERR)
                .map(|r| Err(r.trim().to_string()))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_mounts_stay_inside_the_root() {
        let m = |tag: &str, target: &str| VolumeMount {
            tag: tag.into(),
            target: target.into(),
            read_only: false,
        };
        assert!(m(&volume_tag(0), "/data").validate().is_ok());
        assert!(m("fluxvm-vol12", "/srv/app/cache").validate().is_ok());
        for (tag, target) in [
            ("fluxvm-vol0", "/"),
            ("fluxvm-vol0", "data"),
            ("fluxvm-vol0", "/data/../etc"),
            ("fluxvm-vol0", "/data//x"),
            ("fluxvm-volx", "/data"),
            ("fluxvm-meta", "/data"),
        ] {
            assert!(m(tag, target).validate().is_err(), "{tag} {target}");
        }
    }

    #[test]
    fn older_boot_configs_still_parse() {
        let b: BootConfig = serde_json::from_value(serde_json::json!({
            "hostname": "h",
            "process": {"argv": ["/bin/true"], "env": [], "cwd": "/", "user": "0:0"},
        }))
        .unwrap();
        assert_eq!(b.restart, crate::supervise::RestartPolicy::No);
        assert!(b.healthcheck.is_none() && b.mounts.is_empty() && b.max_restarts.is_none());
    }

    fn image() -> ImageProcess {
        ImageProcess {
            entrypoint: Some(vec!["/docker-entrypoint.sh".into()]),
            cmd: Some(vec!["nginx".into(), "-g".into(), "daemon off;".into()]),
            env: Some(vec![
                "PATH=/usr/bin:/bin".into(),
                "NGINX_VERSION=1.27".into(),
            ]),
            working_dir: Some(String::new()),
            user: None,
        }
    }

    #[test]
    fn entrypoint_plus_cmd_with_defaults() {
        let p = resolve_process(&image(), &ProcessOverrides::default()).unwrap();
        assert_eq!(
            p.argv,
            ["/docker-entrypoint.sh", "nginx", "-g", "daemon off;"]
        );
        assert_eq!(p.cwd, "/");
        assert_eq!(p.user, DEFAULT_USER);
        assert!(p.env.contains(&"PATH=/usr/bin:/bin".to_string()));
    }

    #[test]
    fn overrides_follow_docker_rules() {
        let cmd = ProcessOverrides {
            command: Some(vec!["sh".into(), "-c".into(), "exit 7".into()]),
            env: vec!["NGINX_VERSION=2".into(), "A=b=c".into()],
            workdir: Some("/srv".into()),
            user: Some("0".into()),
            ..Default::default()
        };
        let p = resolve_process(&image(), &cmd).unwrap();
        assert_eq!(p.argv, ["/docker-entrypoint.sh", "sh", "-c", "exit 7"]);
        assert_eq!(
            p.env
                .iter()
                .filter(|e| e.starts_with("NGINX_VERSION="))
                .count(),
            1
        );
        assert!(p.env.contains(&"NGINX_VERSION=2".to_string()));
        assert!(p.env.contains(&"A=b=c".to_string()));
        assert_eq!((p.cwd.as_str(), p.user.as_str()), ("/srv", "0"));

        let ep = ProcessOverrides {
            entrypoint: Some(vec!["/bin/true".into()]),
            ..Default::default()
        };
        assert_eq!(resolve_process(&image(), &ep).unwrap().argv, ["/bin/true"]);
    }

    #[test]
    fn path_is_always_set_and_bad_input_is_refused() {
        let bare = ImageProcess {
            cmd: Some(vec!["/app".into()]),
            ..Default::default()
        };
        let p = resolve_process(&bare, &ProcessOverrides::default()).unwrap();
        assert!(p.env.contains(&format!("PATH={DEFAULT_PATH}")));
        assert!(resolve_process(&ImageProcess::default(), &ProcessOverrides::default()).is_err());
        for o in [
            ProcessOverrides {
                env: vec!["NOVALUE".into()],
                ..Default::default()
            },
            ProcessOverrides {
                workdir: Some("rel".into()),
                ..Default::default()
            },
        ] {
            assert!(resolve_process(&bare, &o).is_err(), "{o:?}");
        }
    }

    #[test]
    fn config_round_trips_with_defaults() {
        let j = r#"{"mode":"boot","hostname":"h","process":{"argv":["/a"],"env":[],"cwd":"/","user":"0"}}"#;
        let InitConfig::Boot(b) = serde_json::from_str(j).unwrap() else {
            panic!()
        };
        assert_eq!(
            (b.network, b.exit_policy, b.agent_port, b.read_only_root),
            (NetworkMode::Dhcp, ExitPolicy::Keep, 17777, false)
        );
        let u = InitConfig::Unpack(UnpackConfig {
            layers: vec![UnpackLayer {
                blob: "ab".into(),
                compression: Compression::Zstd,
                diff_id: "sha256:cd".into(),
            }],
        });
        let s = serde_json::to_string(&u).unwrap();
        assert!(s.contains(r#""mode":"unpack""#) && s.contains(r#""compression":"zstd""#));
        assert_eq!(serde_json::from_str::<InitConfig>(&s).unwrap(), u);
    }

    #[test]
    fn console_markers_parse() {
        assert_eq!(exit_code_from_log("boot\nFLUXVM-EXIT 7\n"), Some(7));
        assert_eq!(
            exit_code_from_log("FLUXVM-EXIT 1\nFLUXVM-EXIT 0\n"),
            Some(0)
        );
        assert_eq!(exit_code_from_log("still running"), None);
        assert_eq!(
            unpack_result_from_log("x\nFLUXVM-UNPACK-OK\n"),
            Some(Ok(()))
        );
        assert_eq!(
            unpack_result_from_log("FLUXVM-UNPACK-ERR layer 2: diff_id mismatch"),
            Some(Err("layer 2: diff_id mismatch".into()))
        );
        assert_eq!(unpack_result_from_log("booting"), None);
        assert_eq!(
            init_error_from_log("FLUXVM-INIT-ERR user \"app\" is not in the image's /etc/passwd\n"),
            Some("user \"app\" is not in the image's /etc/passwd".into())
        );
    }
}
