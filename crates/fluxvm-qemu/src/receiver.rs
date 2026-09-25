// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! QEMU `-incoming defer` receiver. Disk copy, destination pick, and fencing
//! stay outside this runtime primitive.

use crate::qmp;
use anyhow::{Context, Result, bail};
use fluxvm_core::backend::path_arg;
use fluxvm_core::config::Config;
use fluxvm_core::model::MigrationTlsSpec;
use std::path::{Path, PathBuf};
use std::time::Duration;

const ACTIVATE_TIMEOUT: Duration = Duration::from_secs(30);

pub fn validate_receiver(cpu_model: &str, machine: &str, disk: &Path) -> Result<()> {
    if !cpu_model.is_empty() && cpu_model != "host" {
        bail!("migration receiver cpu_model must be \"host\" (got {cpu_model:?})");
    }
    if !machine.is_empty() && !machine.starts_with("q35") {
        bail!("migration receiver machine must be q35 (got {machine:?})");
    }
    if !disk.is_file() {
        bail!(
            "migration receiver disk must already exist on shared storage ({}); the runtime does not copy disks",
            disk.display()
        );
    }
    Ok(())
}

pub fn normalize_disk_format(format: &str) -> Result<&'static str> {
    match format {
        "" | "raw" => Ok("raw"),
        "qcow2" => Ok("qcow2"),
        other => bail!("disk_format must be raw or qcow2 (got {other:?})"),
    }
}

fn is_wildcard(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::" | "[::]")
}

/// `(dial_uri, listen_uri)`. The source cannot connect to a wildcard, so a
/// wildcard bind requires `advertise_host`.
pub fn advertised_uri(
    listen_host: &str,
    advertise_host: &str,
    port: u16,
) -> Result<(String, String)> {
    let listen_uri = format!("tcp:{listen_host}:{port}");
    let dial = if !advertise_host.is_empty() {
        advertise_host
    } else if !is_wildcard(listen_host) {
        listen_host
    } else {
        bail!("advertise_host is required when the receiver listens on {listen_host}");
    };
    if is_wildcard(dial) {
        bail!("migration source cannot dial wildcard address {dial}");
    }
    Ok((format!("tcp:{dial}:{port}"), listen_uri))
}

/// Bind `host:port` (`port == 0` is ephemeral) and return the chosen port.
/// The socket is closed before QEMU starts, so a short reuse race remains.
pub fn reserve_tcp_port(host: &str, port: u16) -> Result<u16> {
    let addr = if host == "::" || host == "[::]" {
        format!("[::]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let listener = std::net::TcpListener::bind(&addr)
        .with_context(|| format!("binding migration receiver on {addr}"))?;
    let chosen = listener
        .local_addr()
        .context("reading migration receiver port")?
        .port();
    drop(listener);
    Ok(chosen)
}

pub fn incoming_argv(
    disk: &Path,
    disk_format: &str,
    vcpus: u8,
    memory_mib: u64,
    qmp: &Path,
) -> Vec<String> {
    vec![
        "-enable-kvm".into(),
        "-machine".into(),
        "q35,accel=kvm".into(),
        "-cpu".into(),
        "host".into(),
        "-smp".into(),
        vcpus.to_string(),
        "-m".into(),
        format!("{memory_mib}M"),
        "-nodefaults".into(),
        "-display".into(),
        "none".into(),
        "-drive".into(),
        format!(
            "file={},if=virtio,format={disk_format},cache=writeback",
            path_arg(disk)
        ),
        "-incoming".into(),
        "defer".into(),
        "-qmp".into(),
        format!("unix:{},server=on,wait=off", qmp.display()),
    ]
}

pub struct LaunchedReceiver {
    pub pid: u32,
    pub qmp_socket: PathBuf,
    /// Address the source dials.
    pub uri: String,
    /// Address QMP `migrate-incoming` listens on. May be a wildcard.
    pub listen_uri: String,
}

#[allow(clippy::too_many_arguments)]
pub async fn launch(
    cfg: &Config,
    workspace: &Path,
    disk: &Path,
    disk_format: &str,
    vcpus: u8,
    memory_mib: u64,
    listen_host: &str,
    advertise_host: &str,
    listen_port: u16,
) -> Result<LaunchedReceiver> {
    let disk_format = normalize_disk_format(disk_format)?;
    validate_receiver("host", "q35", disk)?;
    std::fs::create_dir_all(workspace)
        .with_context(|| format!("creating receiver workspace {}", workspace.display()))?;
    let qmp = workspace.join("qmp.sock");
    let log = workspace.join("console.log");
    let port = reserve_tcp_port(listen_host, listen_port)?;
    let (uri, listen_uri) = advertised_uri(listen_host, advertise_host, port)?;
    let args = incoming_argv(disk, disk_format, vcpus, memory_mib, &qmp);
    let mut child = fluxvm_core::process::spawn_vmm(&cfg.qemu_binary, &args, &log, None).await?;
    let pid = match child.id() {
        Some(pid) => pid,
        None => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            bail!("QEMU receiver exited before it had a pid");
        }
    };
    if let Err(e) = fluxvm_core::process::wait_for_socket_ready(
        pid,
        &qmp,
        Duration::from_secs(15),
        "QEMU migration receiver",
        &log,
    )
    .await
    {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(e);
    }
    // Dropping the handle does not kill the process. The scheduler owns the pid.
    drop(child);
    Ok(LaunchedReceiver {
        pid,
        qmp_socket: qmp,
        uri,
        listen_uri,
    })
}

pub async fn activate(qmp_socket: &Path, uri: &str, tls: Option<&MigrationTlsSpec>) -> Result<()> {
    if !uri.starts_with("tcp:") && !uri.starts_with("unix:") {
        bail!("migration receiver uri must be tcp: or unix: (got {uri})");
    }
    if let Some(tls) = tls {
        let workspace = qmp_socket
            .parent()
            .context("qmp socket path has no parent workspace directory")?;
        let dir = qmp::materialize_tls_dir(workspace, tls, "server")
            .context("materializing migration TLS server credentials")?;
        qmp::set_migration_tls(qmp_socket, "migtls", &dir, "server", None, ACTIVATE_TIMEOUT)
            .await?;
    }
    qmp::execute(
        qmp_socket,
        "migrate-incoming",
        Some(serde_json::json!({ "uri": uri })),
        ACTIVATE_TIMEOUT,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_defers_incoming_and_does_not_copy_the_disk() {
        let args = incoming_argv(
            Path::new("/srv/shared/root.raw"),
            "raw",
            2,
            512,
            Path::new("/run/fluxvm/qmp.sock"),
        );
        assert!(args.windows(2).any(|w| w == ["-incoming", "defer"]));
        assert!(args.iter().any(|a| a.contains("/srv/shared/root.raw")));
        assert!(!args.iter().any(|a| a.contains("qemu-img")));
    }

    #[test]
    fn missing_disk_is_rejected() {
        let err = validate_receiver("host", "q35", Path::new("/no/such/disk.raw")).unwrap_err();
        assert!(err.to_string().contains("shared storage"));
    }

    #[test]
    fn non_host_cpu_is_rejected() {
        let dir = std::env::temp_dir().join(format!("fluxvm-recv-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let disk = dir.join("disk.raw");
        std::fs::write(&disk, b"x").unwrap();
        assert!(validate_receiver("EPYC", "q35", &disk).is_err());
        assert!(validate_receiver("host", "pc", &disk).is_err());
        assert!(validate_receiver("", "", &disk).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn disk_format_allows_only_raw_and_qcow2() {
        assert_eq!(normalize_disk_format("").unwrap(), "raw");
        assert_eq!(normalize_disk_format("raw").unwrap(), "raw");
        assert_eq!(normalize_disk_format("qcow2").unwrap(), "qcow2");
        assert!(normalize_disk_format("vmdk").is_err());
    }

    #[test]
    fn wildcard_listen_needs_an_advertised_address() {
        let err = advertised_uri("0.0.0.0", "", 4444).unwrap_err();
        assert!(err.to_string().contains("advertise_host"));
        let (dial, listen) = advertised_uri("0.0.0.0", "hyper-b.example.net", 4444).unwrap();
        assert_eq!(dial, "tcp:hyper-b.example.net:4444");
        assert_eq!(listen, "tcp:0.0.0.0:4444");
        let (dial, listen) = advertised_uri("10.1.2.3", "", 9).unwrap();
        assert_eq!(dial, "tcp:10.1.2.3:9");
        assert_eq!(listen, "tcp:10.1.2.3:9");
    }

    #[test]
    fn ephemeral_port_is_not_a_fixed_default() {
        let port = reserve_tcp_port("127.0.0.1", 0).unwrap();
        assert_ne!(port, 0);
    }
}
