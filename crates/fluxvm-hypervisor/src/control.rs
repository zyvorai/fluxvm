// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::api::{ApiRequest, ApiResponse, BootConfig};
use crate::guest;
use crate::kvm_snap;
use crate::seccomp;
use crate::snapshot;
use crate::state::{VmLifecycle, VmState};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Default bound for a one-shot [`request`] against a running hypervisor API
/// socket. Covers Ping/Pause/Resume/Shutdown/Metrics: each is already
/// internally bounded where it talks to Firecracker (see `guest.rs`'s
/// `FC_API_TIMEOUT`), but this timeout is what actually protects the caller
/// if the fluxvm-hypervisor process itself has wedged (a stuck vCPU thread
/// holding the `VmState` lock, a hung KVM ioctl, etc.) and never gets around
/// to writing a response line at all.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// `SnapshotSave`/`SnapshotRestore` chain guest-pause + the actual
/// snapshot I/O + guest-resume inside a single `dispatch()` call -- each
/// step already individually bounded, but three of them in sequence can
/// legitimately exceed `DEFAULT_REQUEST_TIMEOUT` even when nothing is
/// actually stuck. Give these two request kinds more headroom.
const SNAPSHOT_REQUEST_TIMEOUT: Duration = Duration::from_secs(45);

/// Short, stable label for a request kind, used only in timeout/error
/// messages -- deliberately not the full `Debug` output, which for `Boot`
/// would dump the entire `BootConfig`.
fn request_kind(req: &ApiRequest) -> &'static str {
    match req {
        ApiRequest::Boot(_) => "boot",
        ApiRequest::Pause => "pause",
        ApiRequest::Resume => "resume",
        ApiRequest::Shutdown => "shutdown",
        ApiRequest::SnapshotSave { .. } => "snapshot_save",
        ApiRequest::SnapshotRestore { .. } => "snapshot_restore",
        ApiRequest::MigrateExport { .. } => "migrate_export",
        ApiRequest::MigrateImport { .. } => "migrate_import",
        ApiRequest::HotplugCpu { .. } => "hotplug_cpu",
        ApiRequest::HotplugDisk { .. } => "hotplug_disk",
        ApiRequest::Metrics => "metrics",
        ApiRequest::Ping => "ping",
    }
}

/// Serve JSON-line requests on `api_sock` until shutdown.
pub async fn serve(
    api_sock: PathBuf,
    initial: Option<BootConfig>,
    workspace: PathBuf,
) -> Result<()> {
    let _ = std::fs::remove_file(&api_sock);
    if let Some(parent) = api_sock.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(&api_sock)
        .with_context(|| format!("binding API socket {}", api_sock.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&api_sock, std::fs::Permissions::from_mode(0o600));
    }
    info!(path = %api_sock.display(), "fluxvm-hypervisor API listening");

    let state = Arc::new(Mutex::new(VmState::new()));

    // Accept connections (including Ping) while the initial boot runs. The
    // control-plane waits on Ping with a short timeout and must not block on
    // Firecracker/KVM bring-up completing first.
    if let Some(boot) = initial {
        let state_boot = Arc::clone(&state);
        let workspace_boot = workspace.clone();
        tokio::spawn(async move {
            let mut st = state_boot.lock().await;
            if let Err(e) = boot_inner(&mut st, boot, &workspace_boot).await {
                warn!(error = %e, "initial boot_config failed");
            }
        });
    }

    loop {
        let (stream, _) = listener.accept().await?;
        let state = Arc::clone(&state);
        let workspace = workspace.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, state, workspace).await {
                warn!("API client error: {e:#}");
            }
        });
    }
}

async fn handle_client(
    stream: UnixStream,
    state: Arc<Mutex<VmState>>,
    workspace: PathBuf,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: ApiRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ApiResponse::Error {
                    message: format!("bad request: {e}"),
                };
                writer
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };
        let resp = dispatch(state.clone(), req, &workspace).await;
        writer
            .write_all(serde_json::to_string(&resp)?.as_bytes())
            .await?;
        writer.write_all(b"\n").await?;
    }
    Ok(())
}

async fn dispatch(state: Arc<Mutex<VmState>>, req: ApiRequest, workspace: &Path) -> ApiResponse {
    match req {
        ApiRequest::Ping => ApiResponse::Ok {
            message: "pong".into(),
        },
        ApiRequest::Boot(cfg) => {
            let mut st = state.lock().await;
            match boot_inner(&mut st, cfg, workspace).await {
                Ok(()) => ApiResponse::Ok {
                    message: "booted".into(),
                },
                Err(e) => ApiResponse::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        ApiRequest::Pause => {
            let mut st = state.lock().await;
            if let Some(g) = &st.guest {
                if let Err(e) = g.pause().await {
                    return ApiResponse::Error {
                        message: format!("{e:#}"),
                    };
                }
            }
            match st.pause() {
                Ok(()) => ApiResponse::State {
                    lifecycle: st.lifecycle.as_str().into(),
                },
                Err(e) => ApiResponse::Error { message: e },
            }
        }
        ApiRequest::Resume => {
            let mut st = state.lock().await;
            if let Some(g) = &st.guest {
                if let Err(e) = g.resume().await {
                    return ApiResponse::Error {
                        message: format!("{e:#}"),
                    };
                }
            }
            match st.resume() {
                Ok(()) => ApiResponse::State {
                    lifecycle: st.lifecycle.as_str().into(),
                },
                Err(e) => ApiResponse::Error { message: e },
            }
        }
        ApiRequest::Shutdown => {
            let mut st = state.lock().await;
            st.shutdown_guest().await;
            ApiResponse::Ok {
                message: "shutdown".into(),
            }
        }
        ApiRequest::SnapshotSave { path } => {
            let st = state.lock().await;
            if let Some(g) = &st.guest {
                let _ = g.pause().await;
            }
            let result = snapshot::save(&st, &path).await;
            if st.lifecycle == VmLifecycle::Running {
                if let Some(g) = &st.guest {
                    let _ = g.resume().await;
                }
            }
            match result {
                Ok(()) => ApiResponse::Ok {
                    message: format!("saved {}", path.display()),
                },
                Err(e) => ApiResponse::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        ApiRequest::SnapshotRestore { path } => {
            let mut st = state.lock().await;
            st.shutdown_guest().await;
            match snapshot::restore_meta(&mut st, &path).await {
                Ok(spec) => {
                    // Fast path: Firecracker memory snapshot load, or in-tree
                    // KVM FLUXKVM1 when the vmstate magic matches / engine=kvm.
                    if let (Some(vmstate), mem) = (spec.vmstate_path.as_ref(), &spec.memory_path) {
                        let vsock = spec.boot.vsock_uds.as_deref();
                        let kvm_fmt = kvm_snap::is_flux_kvm_vmstate(vmstate)
                            || matches!(spec.boot.engine, crate::api::FluxVmEngine::Kvm);
                        let loaded = if kvm_fmt {
                            guest::start_kvm_from_snapshot(&spec.boot, workspace, vmstate, mem)
                                .await
                        } else {
                            guest::start_from_snapshot(workspace, vmstate, mem, vsock).await
                        };
                        match loaded {
                            Ok(handle) => {
                                st.guest = Some(handle);
                                st.boot = Some(spec.boot);
                                st.lifecycle = VmLifecycle::Running;
                                st.touch();
                                return ApiResponse::Ok {
                                    message: format!(
                                        "restored (memory snapshot) {}",
                                        path.display()
                                    ),
                                };
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "memory snapshot load failed; falling back to cold boot");
                            }
                        }
                    }
                    // Fallback: cold boot from snapshotted rootfs.
                    match boot_inner(&mut st, spec.boot, workspace).await {
                        Ok(()) => ApiResponse::Ok {
                            message: format!("restored (cold boot) {}", path.display()),
                        },
                        Err(e) => ApiResponse::Error {
                            message: format!("{e:#}"),
                        },
                    }
                }
                Err(e) => ApiResponse::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        // H4: migrate export/import reuse the snapshot directory shape but
        // require an explicit migration bundle (vmstate+mem names).
        ApiRequest::MigrateExport { path } => {
            match crate::migration::export_state_path(&path) {
                Ok(()) => {
                    // Prefer full SnapshotSave when a guest is live (inline to
                    // avoid async recursion through dispatch).
                    let st = state.lock().await;
                    if st.guest.is_some() {
                        if let Some(g) = &st.guest {
                            let _ = g.pause().await;
                        }
                        let result = snapshot::save(&st, &path).await;
                        if st.lifecycle == VmLifecycle::Running {
                            if let Some(g) = &st.guest {
                                let _ = g.resume().await;
                            }
                        }
                        return match result {
                            Ok(()) => ApiResponse::Ok {
                                message: format!("migrated out {}", path.display()),
                            },
                            Err(e) => ApiResponse::Error {
                                message: format!("{e:#}"),
                            },
                        };
                    }
                    ApiResponse::Ok {
                        message: format!("migration dir ready {}", path.display()),
                    }
                }
                Err(e) => ApiResponse::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        ApiRequest::MigrateImport { path } => {
            match crate::migration::import_state_path(&path) {
                Ok(()) => {
                    // Inline SnapshotRestore path (no async recursion).
                    let mut st = state.lock().await;
                    st.shutdown_guest().await;
                    match snapshot::restore_meta(&mut st, &path).await {
                        Ok(spec) => {
                            if let (Some(vmstate), mem) =
                                (spec.vmstate_path.as_ref(), &spec.memory_path)
                            {
                                let vsock = spec.boot.vsock_uds.as_deref();
                                let kvm_fmt = kvm_snap::is_flux_kvm_vmstate(vmstate)
                                    || matches!(
                                        spec.boot.engine,
                                        crate::api::FluxVmEngine::Kvm
                                    );
                                let loaded = if kvm_fmt {
                                    guest::start_kvm_from_snapshot(
                                        &spec.boot, workspace, vmstate, mem,
                                    )
                                    .await
                                } else {
                                    guest::start_from_snapshot(workspace, vmstate, mem, vsock)
                                        .await
                                };
                                match loaded {
                                    Ok(handle) => {
                                        st.guest = Some(handle);
                                        st.boot = Some(spec.boot);
                                        st.lifecycle = VmLifecycle::Running;
                                        st.touch();
                                        return ApiResponse::Ok {
                                            message: format!(
                                                "migrated in {}",
                                                path.display()
                                            ),
                                        };
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "migrate import snapshot load failed; cold boot");
                                    }
                                }
                            }
                            match boot_inner(&mut st, spec.boot, workspace).await {
                                Ok(()) => ApiResponse::Ok {
                                    message: format!("migrated in (cold) {}", path.display()),
                                },
                                Err(e) => ApiResponse::Error {
                                    message: format!("{e:#}"),
                                },
                            }
                        }
                        Err(e) => ApiResponse::Error {
                            message: format!("{e:#}"),
                        },
                    }
                }
                Err(e) => ApiResponse::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        ApiRequest::HotplugCpu { add } => {
            let st = state.lock().await;
            let current = st.boot.as_ref().map(|b| b.vcpus).unwrap_or(0);
            let max = st
                .boot
                .as_ref()
                .and_then(|b| b.max_vcpus)
                .unwrap_or(current);
            match crate::hotplug::plan_add_vcpu(current, max, add) {
                Ok(plan) => ApiResponse::Ok {
                    message: format!(
                        "cpu hotplug planned: +{} ({}→{}), next_id={}",
                        plan.add,
                        plan.current,
                        plan.current + plan.add,
                        plan.next_id
                    ),
                },
                Err(e) => ApiResponse::Error {
                    message: format!("{e:#}"),
                },
            }
        }
        ApiRequest::HotplugDisk { path } => match crate::hotplug::hotplug_disk_path(&path, false)
        {
            Ok(plan) => ApiResponse::Ok {
                message: format!(
                    "disk hotplug ok path={} ro={}",
                    plan.path.display(),
                    plan.read_only
                ),
            },
            Err(e) => ApiResponse::Error {
                message: format!("{e:#}"),
            },
        }
        ApiRequest::Metrics => {
            let st = state.lock().await;
            ApiResponse::Metrics {
                memory_mib: st.boot.as_ref().map(|b| b.memory_mib).unwrap_or(0),
                vcpus: st.boot.as_ref().map(|b| b.vcpus).unwrap_or(0),
                lifecycle: st.lifecycle.as_str().into(),
            }
        }
    }
}

async fn boot_inner(st: &mut VmState, cfg: BootConfig, workspace: &Path) -> Result<()> {
    if st.lifecycle != VmLifecycle::Stopped && st.lifecycle != VmLifecycle::Created {
        bail!("cannot boot from state {:?}", st.lifecycle);
    }
    if !cfg.kernel.exists() {
        bail!("kernel not found: {}", cfg.kernel.display());
    }
    if !cfg.rootfs.exists() {
        bail!("rootfs not found: {}", cfg.rootfs.display());
    }
    if cfg.seccomp {
        seccomp::apply_minimal().context("applying seccomp")?;
    }

    // Firecracker (default) or pure in-tree KVM when `cfg.engine` requests it.
    let handle = match cfg.engine {
        crate::api::FluxVmEngine::Firecracker => guest::start(&cfg, workspace).await?,
        crate::api::FluxVmEngine::Kvm => guest::start_kvm(&cfg, workspace).await?,
    };
    st.guest = Some(handle);
    st.boot = Some(cfg);
    st.lifecycle = VmLifecycle::Running;
    st.touch();
    if let Some(boot) = &st.boot {
        let marker = boot.rootfs.with_extension("fluxvm-running");
        let _ = std::fs::write(&marker, format!("pid={}\n", std::process::id()));
        st.marker = Some(marker);
    }
    Ok(())
}

/// One-shot JSON request against a running hypervisor API socket, bounded by
/// [`DEFAULT_REQUEST_TIMEOUT`] (or [`SNAPSHOT_REQUEST_TIMEOUT`] for the two
/// snapshot request kinds). Use [`request_with_timeout`] to override.
///
/// Before this bound existed, a wedged fluxvm-hypervisor child (a stuck vCPU
/// thread still holding the `VmState` lock, a hung KVM ioctl inside
/// `dispatch()`) left this call's `next_line().await` blocked forever --
/// the same class of "no timeout on I/O to something outside this process's
/// control" bug already fixed three times over in fluxvm-api's sandbox proxy
/// path (see `f5dfbd6`, `869b6dd`), just one layer down: here the peer is
/// the hypervisor subprocess itself, not a guest.
pub async fn request(api_sock: &Path, req: &ApiRequest) -> Result<ApiResponse> {
    request_with_timeout(api_sock, req, timeout_for(req)).await
}

/// Which of [`DEFAULT_REQUEST_TIMEOUT`]/[`SNAPSHOT_REQUEST_TIMEOUT`] applies
/// to a given request kind. Split out from [`request`] as a small pure
/// function so the choice itself is directly unit-testable without needing
/// to actually wait out a 45s timeout in a test.
fn timeout_for(req: &ApiRequest) -> Duration {
    match req {
        ApiRequest::SnapshotSave { .. }
        | ApiRequest::SnapshotRestore { .. }
        | ApiRequest::MigrateExport { .. }
        | ApiRequest::MigrateImport { .. } => SNAPSHOT_REQUEST_TIMEOUT,
        _ => DEFAULT_REQUEST_TIMEOUT,
    }
}

/// [`request`] with an explicit timeout, for callers that know their
/// request kind needs a different bound than the default.
pub async fn request_with_timeout(
    api_sock: &Path,
    req: &ApiRequest,
    timeout: Duration,
) -> Result<ApiResponse> {
    tokio::time::timeout(timeout, request_inner(api_sock, req))
        .await
        .with_context(|| {
            format!(
                "hypervisor control request '{}' to {} timed out after {timeout:?}",
                request_kind(req),
                api_sock.display()
            )
        })?
}

async fn request_inner(api_sock: &Path, req: &ApiRequest) -> Result<ApiResponse> {
    let stream = UnixStream::connect(api_sock)
        .await
        .with_context(|| format!("connecting to {}", api_sock.display()))?;
    let (reader, mut writer) = stream.into_split();
    writer
        .write_all(serde_json::to_string(req)?.as_bytes())
        .await?;
    writer.write_all(b"\n").await?;
    writer.shutdown().await.ok();
    let mut lines = BufReader::new(reader).lines();
    let line = lines.next_line().await?.context("empty API response")?;
    Ok(serde_json::from_str(&line)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_for_uses_the_longer_bound_for_snapshot_requests() {
        assert_eq!(
            timeout_for(&ApiRequest::SnapshotSave {
                path: PathBuf::from("/tmp/x")
            }),
            SNAPSHOT_REQUEST_TIMEOUT,
        );
        assert_eq!(
            timeout_for(&ApiRequest::SnapshotRestore {
                path: PathBuf::from("/tmp/x")
            }),
            SNAPSHOT_REQUEST_TIMEOUT,
        );
        for req in [
            ApiRequest::Ping,
            ApiRequest::Pause,
            ApiRequest::Resume,
            ApiRequest::Shutdown,
            ApiRequest::Metrics,
        ] {
            assert_eq!(timeout_for(&req), DEFAULT_REQUEST_TIMEOUT);
        }
    }

    #[tokio::test]
    async fn request_returns_the_response_when_the_hypervisor_answers_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();
            let line = lines.next_line().await.unwrap().unwrap();
            let req: ApiRequest = serde_json::from_str(&line).unwrap();
            assert!(matches!(req, ApiRequest::Ping));
            let resp = ApiResponse::Ok {
                message: "pong".into(),
            };
            writer
                .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
                .await
                .unwrap();
            writer.write_all(b"\n").await.unwrap();
        });

        let resp = request(&sock, &ApiRequest::Ping).await.unwrap();
        assert!(matches!(resp, ApiResponse::Ok { message } if message == "pong"));
        server.await.unwrap();
    }

    /// Regression test for the exact bug this module now guards against:
    /// before `request`/`request_with_timeout` existed, a fluxvm-hypervisor
    /// child that accepted the connection and read the request but then
    /// wedged (a stuck vCPU thread still holding `VmState`'s lock, a hung
    /// KVM ioctl inside `dispatch()`) left `next_line().await` blocked
    /// forever -- the caller (a `pause`/`resume`/`snapshot` request from
    /// fluxvm-scheduler or fluxvm-hypervisor's own backend) hung
    /// indefinitely too, with no way to notice or recover. This simulates
    /// that exact wedge: the server accepts and reads the request, then
    /// simply never writes a response.
    #[tokio::test]
    async fn request_times_out_instead_of_hanging_forever_when_the_hypervisor_never_answers() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, _writer) = stream.into_split();
            // Read the request so the client's write side doesn't itself
            // block, then simply never respond -- and hold the connection
            // open (don't drop it) so the client can't mistake this for a
            // clean EOF either.
            let mut lines = BufReader::new(reader).lines();
            let _ = lines.next_line().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let start = tokio::time::Instant::now();
        let result =
            request_with_timeout(&sock, &ApiRequest::Pause, Duration::from_millis(200)).await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "expected a timeout error, got {result:?}");
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("timed out"),
            "expected a 'timed out' error, got: {msg}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "request_with_timeout took {elapsed:?}, should have given up almost immediately \
             after its 200ms bound instead of hanging"
        );

        server.abort();
    }

    #[tokio::test]
    async fn request_reports_connect_failure_promptly_when_no_one_is_listening() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("nobody-here.sock"); // never bound

        let start = tokio::time::Instant::now();
        let result = request(&sock, &ApiRequest::Ping).await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        assert!(
            elapsed < Duration::from_secs(1),
            "connecting to a socket nobody bound should fail immediately, took {elapsed:?}"
        );
    }
}
