// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::api::{ApiRequest, ApiResponse, BootConfig};
use crate::guest;
use crate::seccomp;
use crate::snapshot;
use crate::state::{VmLifecycle, VmState};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

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
                    // Fast path: Firecracker memory snapshot load.
                    if let (Some(vmstate), mem) = (spec.vmstate_path.as_ref(), &spec.memory_path) {
                        let vsock = spec.boot.vsock_uds.as_deref();
                        match guest::start_from_snapshot(workspace, vmstate, mem, vsock).await {
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

/// One-shot JSON request against a running hypervisor API socket.
pub async fn request(api_sock: &Path, req: &ApiRequest) -> Result<ApiResponse> {
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
