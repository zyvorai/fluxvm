// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! containerd runtime-v2 shim for FluxVM secure containers.
//!
//! Secure Containers contract through Set 5:
//! * one FluxVM QEMU VM per containerd shim group / Kubernetes Pod sandbox;
//! * OCI snapshot rootfs is copied into the Pod's virtiofs share;
//! * Kubernetes Pod volumes are passed through write-through with Pod-scoped virtiofs exports;
//! * other bind mounts (ConfigMap/Secret/host inputs) remain snapshotted by default;
//! * process lifecycle is executed by `fluxvm-container-agent` over VSOCK 17778;
//! * stdin/stdout/stderr stream over authenticated VSOCK 17779;
//! * terminal init/exec processes use a real guest PTY with ResizePty;
//! * no host kernel is shared with the workload.
//!
//! The copy/snapshot approach is intentionally conservative. It gives a
//! deterministic implementation without requiring dynamic virtiofs hotplug for
//! ordinary bind inputs. Broader hostPath passthrough and full OCI namespace
//! parity remain explicit follow-ups rather than silently pretending to work.

use anyhow::{Context, Result as AnyResult, bail};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use containerd_shim::{
    Config, Error, Flags, StartOpts, TtrpcResult,
    api::{
        CreateTaskRequest, CreateTaskResponse, DeleteRequest, Empty, ExecProcessRequest,
        KillRequest, PauseRequest, ResumeRequest, ShutdownRequest, StartRequest, StartResponse,
        StateRequest, StateResponse, Status, WaitRequest, WaitResponse,
    },
    asynchronous::{ExitSignal, Shim, run, spawn},
    event::Event,
    publisher::RemotePublisher,
    util::convert_to_any,
};
use containerd_shim_protos::{
    api::{CloseIORequest, ConnectRequest, ConnectResponse, DeleteResponse, PidsRequest, PidsResponse,
          ProcessInfo, ResizePtyRequest, StatsRequest, StatsResponse, UpdateTaskRequest},
    cgroups::metrics::{CPUStat, CPUUsage, MemoryEntry, MemoryStat, Metrics, PidsStat},
    events::task::{
        TaskCreate, TaskDelete, TaskExecAdded, TaskExecStarted, TaskExit, TaskIO, TaskPaused,
        TaskResumed, TaskStart,
    },
    protobuf::{EnumOrUnknown, MessageDyn},
    shim_async::Task,
    ttrpc::{self, r#async::TtrpcContext},
};
use fluxvm_container_protocol::{
    ContainerIo, ContainerRequest, ContainerResponse, ContainerStats, ContainerStatus, ResourceLimits,
    IoStreamAttach, IoStreamKind,
};
use fluxvm_core::model::{VmRecord, VmStatus};
use fluxvm_guest_protocol::{AgentRequest, AgentResponse};
use log::warn;
use reqwest::{Client, Method};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex, RwLock,
    },
};

const RUNTIME_ID: &str = "io.containerd.fluxvm.v2";
const GUEST_SHARE: &str = "/run/fluxvm/pod";

type EventMessage = (String, Box<dyn MessageDyn>);
type EventSender = Sender<EventMessage>;
type EventReceiver = Receiver<EventMessage>;

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
struct RuntimeConfig {
    api_url: String,
    api_token: Option<String>,
    guest_image: PathBuf,
    container_agent_binary: PathBuf,
    state_dir: PathBuf,
    vcpus: u8,
    memory_mib: u64,
    vm_overhead_mib: u64,
    boot_timeout_secs: u64,
    cni_interface: String,
    cni_enabled: bool,
    streaming_stdio: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            api_url: std::env::var("FLUXVM_API_URL").unwrap_or_else(|_| "http://127.0.0.1:7788".into()),
            api_token: std::env::var("FLUXVM_API_TOKEN").ok(),
            guest_image: std::env::var_os("FLUXVM_CONTAINER_GUEST_IMAGE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/fluxvm/images/secure-container.qcow2")),
            container_agent_binary: std::env::var_os("FLUXVM_CONTAINER_AGENT_BINARY")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/usr/local/libexec/fluxvm-container-agent")),
            state_dir: std::env::var_os("FLUXVM_CONTAINERD_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/run/fluxvm/containerd")),
            vcpus: std::env::var("FLUXVM_CONTAINER_VCPUS").ok().and_then(|v| v.parse().ok()).unwrap_or(2),
            memory_mib: std::env::var("FLUXVM_CONTAINER_MEMORY_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(1024),
            vm_overhead_mib: std::env::var("FLUXVM_CONTAINER_VM_OVERHEAD_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(256),
            boot_timeout_secs: std::env::var("FLUXVM_CONTAINER_BOOT_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(90),
            cni_interface: std::env::var("FLUXVM_CONTAINER_CNI_INTERFACE").unwrap_or_else(|_| "eth0".into()),
            cni_enabled: std::env::var("FLUXVM_CONTAINER_CNI").ok().map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off")).unwrap_or(true),
            streaming_stdio: std::env::var("FLUXVM_CONTAINER_STREAMING_STDIO").ok().map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off")).unwrap_or(true),
        }
    }
}

#[derive(Clone, Debug)]
struct TaskMeta {
    bundle: String,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    pid: u32,
    /// Host-side virtiofs stdio directory for this init/exec process.
    io_dir: Option<PathBuf>,
    streaming: bool,
}

#[derive(Debug)]
struct Sandbox {
    vm: VmRecord,
    share_dir: PathBuf,
    cni: Option<CniBridge>,
}

#[derive(Clone, Debug)]
struct CniRoute {
    destination: Option<(Ipv4Addr, u8)>, // None = default
    gateway: Option<Ipv4Addr>,
}

#[derive(Clone, Debug)]
struct CniNetwork {
    pod_ip: Ipv4Addr,
    prefix_len: u8,
    mac: String,
    routes: Vec<CniRoute>,
}

#[derive(Clone, Debug)]
struct CniBridge {
    netns_alias: String,
    netns_mount: PathBuf,
    host_bridge: String,
    host_veth: String,
    cni_bridge: String,
    cni_veth: String,
    interface: String,
    network: CniNetwork,
}

#[derive(Clone, Debug, Default)]
struct SandboxHints {
    resources: ResourceLimits,
    netns_path: Option<PathBuf>,
    /// Kubernetes Pod UID from CRI annotations. Used to scope write-through
    /// virtiofs exports to this Pod only.
    pod_uid: Option<String>,
}

#[derive(Clone)]
struct Service {
    exit: Arc<ExitSignal>,
    namespace: String,
    group: String,
    cfg: RuntimeConfig,
    http: Client,
    sandbox: Arc<Mutex<Option<Sandbox>>>,
    tasks: Arc<RwLock<HashMap<String, TaskMeta>>>,
    execs: Arc<RwLock<HashMap<String, TaskMeta>>>,
    event_tx: EventSender,
    event_rx: Arc<Mutex<Option<EventReceiver>>>,
    exit_events: Arc<Mutex<HashSet<String>>>,
    stream_pending: Arc<Mutex<HashMap<String, usize>>>,
}

#[async_trait]
impl Shim for Service {
    type T = Service;

    async fn new(_runtime_id: &str, args: &Flags, _config: &mut Config) -> Self {
        let group = pod_group_from_bundle(&args.bundle).await.unwrap_or_else(|| args.id.clone());
        let (event_tx, event_rx) = channel(128);
        Self {
            exit: Arc::new(ExitSignal::default()),
            namespace: args.namespace.clone(),
            group,
            cfg: RuntimeConfig::default(),
            http: Client::new(),
            sandbox: Arc::new(Mutex::new(None)),
            tasks: Arc::new(RwLock::new(HashMap::new())),
            execs: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            event_rx: Arc::new(Mutex::new(Some(event_rx))),
            exit_events: Arc::new(Mutex::new(HashSet::new())),
            stream_pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn start_shim(&mut self, opts: StartOpts) -> Result<String, Error> {
        let address = spawn(opts, &self.group, Vec::new()).await?;
        Ok(address)
    }

    async fn delete_shim(&mut self) -> Result<DeleteResponse, Error> {
        let _ = self.destroy_sandbox().await;
        Ok(DeleteResponse::new())
    }

    async fn wait(&mut self) {
        self.exit.wait().await;
    }

    async fn create_task_service(&self, publisher: RemotePublisher) -> Self::T {
        if let Some(rx) = self.event_rx.lock().await.take() {
            forward_events(publisher, self.namespace.clone(), rx);
        }
        self.clone()
    }
}

impl Service {
    async fn api(&self, method: Method, path: &str, body: Option<Value>) -> AnyResult<reqwest::Response> {
        let url = format!("{}{}", self.cfg.api_url.trim_end_matches('/'), path);
        let mut req = self.http.request(method, &url);
        if let Some(token) = &self.cfg.api_token { req = req.bearer_auth(token); }
        if let Some(body) = body { req = req.json(&body); }
        let resp = req.send().await.with_context(|| format!("calling FluxVM {url}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("FluxVM API {url} returned {status}: {text}");
        }
        Ok(resp)
    }

    /// Deterministic Pod-share directory for this shim's group — a pure
    /// function of config/namespace/group, never of whether the sandbox VM
    /// has actually been created yet. Set 7R relies on that: it lets
    /// `stage_rootfs_and_config` compute a container's staging paths and
    /// start the host-side rootfs copy *before* `ensure_sandbox`'s VM
    /// boot/wait completes, instead of only after.
    fn share_dir(&self) -> PathBuf {
        self.cfg
            .state_dir
            .join(&self.namespace)
            .join(&self.group)
            .join("share")
    }

    async fn ensure_sandbox(&self, hints: Option<&SandboxHints>) -> AnyResult<VmRecord> {
        let mut guard = self.sandbox.lock().await;
        if let Some(s) = guard.as_ref() {
            return Ok(s.vm.clone());
        }

        if !self.cfg.guest_image.exists() {
            bail!(
                "secure-container guest image does not exist: {}",
                self.cfg.guest_image.display()
            );
        }
        if !self.cfg.container_agent_binary.exists() {
            bail!(
                "fluxvm-container-agent binary does not exist: {}",
                self.cfg.container_agent_binary.display()
            );
        }

        let hints = hints.cloned().unwrap_or_default();
        let share_dir = self.share_dir();
        tokio::fs::create_dir_all(&share_dir).await?;

        let (vcpus, memory_mib) = vm_shape(
            self.cfg.vcpus,
            self.cfg.memory_mib,
            self.cfg.vm_overhead_mib,
            &hints.resources,
        );

        // Kubernetes has already asked CNI to populate the Pod network
        // namespace before it creates the runtime sandbox. Instead of NATing
        // a second VM-private address onto that Pod IP, Set 2 turns the CNI
        // endpoint into a transparent L2 path and gives the *actual* CNI Pod
        // IP + MAC to the VM guest. The host bridge must exist before FluxVM
        // creates its QEMU TAP, so this preparation intentionally happens
        // before POST /v1/vms.
        let cni = if self.cfg.cni_enabled {
            if let Some(path) = hints.netns_path.as_ref() {
                Some(
                    prepare_cni_l2(&self.group, path, &self.cfg.cni_interface)
                        .await
                        .context("preparing CNI L2 attachment")?,
                )
            } else {
                None
            }
        } else {
            None
        };

        let network = if let Some(cni) = cni.as_ref() {
            json!({
                "mode": "tap",
                "tap_name": null,
                "bridge": cni.host_bridge,
                "mac": cni.network.mac,
                "netns": false
            })
        } else {
            json!({"mode": "user", "forwards": []})
        };

        // fs0 is always the Pod staging share. For Kubernetes Pods, add only
        // the current Pod's kubelet volume roots as extra virtiofs exports.
        // This preserves PVC/emptyDir writes without exposing other Pods.
        let mut shared_folders = vec![json!({
            "host_path": share_dir,
            "guest_path": GUEST_SHARE,
            "read_only": false
        })];
        let mut kubelet_mounts: Vec<(String, String)> = Vec::new();
        if let Some(uid) = hints.pod_uid.as_deref() {
            let pod_root = PathBuf::from("/var/lib/kubelet/pods").join(uid);
            if pod_root.exists() {
                // SubPath bind targets can be materialized later during the
                // same SyncPod. Create only the two bounded Pod directories
                // up front so the virtiofs tags remain stable (fs1/fs2).
                for (host, guest) in [
                    (pod_root.join("volumes"), "/run/fluxvm/kubelet/volumes"),
                    (pod_root.join("volume-subpaths"), "/run/fluxvm/kubelet/volume-subpaths"),
                ] {
                    tokio::fs::create_dir_all(&host).await
                        .with_context(|| format!("preparing Pod volume export {}", host.display()))?;
                    shared_folders.push(json!({
                        "host_path": host,
                        "guest_path": guest,
                        "read_only": false
                    }));
                    kubelet_mounts.push((format!("fs{}", shared_folders.len() - 1), guest.to_string()));
                }
            }
        }

        let create = json!({
            "name": format!("ctr-{}", safe_name(&self.group)),
            "backend": "qemu",
            "image": self.cfg.guest_image,
            "vcpus": vcpus,
            "memory_mib": memory_mib,
            "network": network,
            "agent": {"enabled": true},
            "shared_folders": shared_folders,
            "pod_uid": hints.pod_uid
        });

        let mut vm: VmRecord = match self
            .api(Method::POST, "/v1/vms", Some(create))
            .await
        {
            Ok(resp) => match resp.json().await {
                Ok(vm) => vm,
                Err(e) => {
                    if let Some(cni) = cni.as_ref() {
                        cleanup_cni_bridge(cni).await;
                    }
                    return Err(e).context("decoding FluxVM VM create response");
                }
            },
            Err(e) => {
                if let Some(cni) = cni.as_ref() {
                    cleanup_cni_bridge(cni).await;
                }
                return Err(e);
            }
        };

        let setup: AnyResult<()> = async {
            let deadline =
                tokio::time::Instant::now() + Duration::from_secs(self.cfg.boot_timeout_secs);
            loop {
                if vm.status == VmStatus::Running
                    && fluxvm_vsock_client::ping(&vm, Duration::from_secs(2))
                        .await
                        .is_ok()
                {
                    break;
                }
                if vm.status == VmStatus::Failed {
                    bail!(
                        "FluxVM sandbox failed: {}",
                        vm.error.as_deref().unwrap_or("unknown error")
                    );
                }
                if tokio::time::Instant::now() >= deadline {
                    bail!("timed out waiting for FluxVM sandbox {}", vm.id);
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
                vm = self
                    .api(Method::GET, &format!("/v1/vms/{}", vm.id), None)
                    .await?
                    .json()
                    .await?;
            }

            if let Some(cni) = cni.as_ref() {
                self.configure_guest_cni(&vm, cni).await?;
            }

            // Cloud-init mounts virtiofs asynchronously; explicitly ensure
            // the Pod share is available before rootfs/stdio staging.
            self.ensure_guest_shares_mounted(&vm, &kubelet_mounts).await?;

            self.bootstrap_container_agent(&vm).await?;
            match self
                .call_agent_direct(
                    &vm,
                    ContainerRequest::ConfigureSandboxResources {
                        resources: hints.resources.clone(),
                    },
                )
                .await?
            {
                ContainerResponse::SandboxResourcesConfigured => {}
                other => bail!("unexpected sandbox-resource response: {other:?}"),
            }
            Ok(())
        }
        .await;

        if let Err(e) = setup {
            let _ = self
                .api(Method::DELETE, &format!("/v1/vms/{}", vm.id), None)
                .await;
            if let Some(cni) = cni.as_ref() {
                cleanup_cni_bridge(cni).await;
            }
            return Err(e);
        }

        *guard = Some(Sandbox {
            vm: vm.clone(),
            share_dir,
            cni,
        });
        Ok(vm)
    }

    async fn configure_guest_cni(&self, vm: &VmRecord, cni: &CniBridge) -> AnyResult<()> {
        let command = guest_network_command(&cni.network)?;
        match fluxvm_vsock_client::call(
            vm,
            AgentRequest::Exec {
                command,
                timeout_seconds: Some(15),
            },
            Duration::from_secs(20),
        )
        .await?
        {
            AgentResponse::Exec {
                exit_code: 0, ..
            } => Ok(()),
            AgentResponse::Exec {
                exit_code,
                stdout,
                stderr,
            } => bail!(
                "configuring guest CNI network failed exit={exit_code}: stdout={stdout:?} stderr={stderr:?}"
            ),
            AgentResponse::Error { message } => {
                bail!("configuring guest CNI network: {message}")
            }
            other => bail!("unexpected guest network response: {other:?}"),
        }
    }

    /// Ensure fs0 and the optional Pod-scoped kubelet volume exports are
    /// mounted before container create. Cloud-init is intentionally not a
    /// correctness dependency for secure containers.
    async fn ensure_guest_shares_mounted(&self, vm: &VmRecord, extras: &[(String, String)]) -> AnyResult<()> {
        let mut commands = vec![format!(
            "mkdir -p {GUEST_SHARE}; if ! mountpoint -q {GUEST_SHARE}; then mount -t virtiofs fs0 {GUEST_SHARE}; fi; mountpoint -q {GUEST_SHARE}"
        )];
        for (tag, guest) in extras {
            commands.push(format!(
                "mkdir -p {guest}; if ! mountpoint -q {guest}; then mount -t virtiofs {tag} {guest}; fi; mountpoint -q {guest}"
            ));
        }
        let probe = format!("bash -lc '{}'", commands.join("; "));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            match fluxvm_vsock_client::call(
                vm,
                AgentRequest::Exec { command: probe.clone(), timeout_seconds: Some(10) },
                Duration::from_secs(15),
            )
            .await?
            {
                AgentResponse::Exec { exit_code: 0, .. } => return Ok(()),
                AgentResponse::Exec { exit_code, stdout, stderr } => {
                    if tokio::time::Instant::now() >= deadline {
                        bail!(
                            "guest virtiofs shares not mounted after retries \
                             (exit={exit_code} stdout={stdout:?} stderr={stderr:?})"
                        );
                    }
                }
                AgentResponse::Error { message } => {
                    if tokio::time::Instant::now() >= deadline {
                        bail!("guest virtiofs share mount: {message}");
                    }
                }
                other => bail!("unexpected guest share mount response: {other:?}"),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn bootstrap_container_agent(&self, vm: &VmRecord) -> AnyResult<()> {
        if fluxvm_container_client::ping(vm, Duration::from_millis(300)).await.is_ok() {
            return Ok(());
        }
        let bytes = tokio::fs::read(&self.cfg.container_agent_binary).await?;
        if bytes.len() > fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES {
            bail!("container-agent binary is larger than FluxVM guest-agent transfer limit");
        }
        match fluxvm_vsock_client::call(
            vm,
            AgentRequest::PutFile {
                path: "/usr/local/bin/fluxvm-container-agent".into(),
                content_base64: B64.encode(bytes),
                mode: Some(0o755),
            },
            Duration::from_secs(20),
        ).await? {
            AgentResponse::FileWritten => {}
            AgentResponse::Error { message } => bail!("installing container agent: {message}"),
            other => bail!("unexpected guest-agent response: {other:?}"),
        }
        match fluxvm_vsock_client::call(
            vm,
            AgentRequest::Exec {
                command: "nohup /usr/local/bin/fluxvm-container-agent >/var/log/fluxvm-container-agent.log 2>&1 </dev/null &".into(),
                timeout_seconds: Some(5),
            },
            Duration::from_secs(10),
        ).await? {
            AgentResponse::Exec { exit_code: 0, .. } => {}
            AgentResponse::Error { message } => bail!("starting container agent: {message}"),
            other => bail!("starting container agent returned {other:?}"),
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if fluxvm_container_client::ping(vm, Duration::from_millis(500)).await.is_ok() { return Ok(()); }
            if tokio::time::Instant::now() >= deadline { bail!("container agent did not become ready"); }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn sandbox_paths(&self, id: &str, hints: Option<&SandboxHints>) -> AnyResult<(VmRecord, PathBuf, String)> {
        let vm = self.ensure_sandbox(hints).await?;
        let guard = self.sandbox.lock().await;
        let sandbox = guard.as_ref().context("sandbox disappeared")?;
        let host = sandbox.share_dir.join("containers").join(safe_name(id));
        let guest = format!("{GUEST_SHARE}/containers/{}", safe_name(id));
        Ok((vm, host, guest))
    }

    /// Set 7R: the VM boot this depends on (`ensure_sandbox`, a fresh QEMU
    /// cold-boot for the first container in a group) and the host-side
    /// rootfs mount+copy below have no data dependency on each other until
    /// both are done — the copy only needs a deterministic staging path
    /// (`share_dir()`/`safe_name(id)`, computable with no VM involved at
    /// all), and the guest only reads that path via virtiofs later, once
    /// the container-agent actually starts the container. Through Set 6,
    /// these ran strictly sequentially (the full VM boot, then the copy);
    /// running them concurrently removes the smaller of the two costs from
    /// the Pod's critical path entirely instead of just shrinking it.
    async fn stage_rootfs_and_config(&self, req: &CreateTaskRequest) -> AnyResult<(VmRecord, String, ContainerIo, Option<PathBuf>)> {
        let config_path = Path::new(&req.bundle).join("config.json");
        let text = tokio::fs::read_to_string(&config_path)
            .await
            .with_context(|| format!("reading {}", config_path.display()))?;
        let mut spec: Value = serde_json::from_str(&text)?;
        let hints = sandbox_hints_from_spec(&spec);

        let host_ctr = self.share_dir().join("containers").join(safe_name(&req.id));
        let guest_ctr = format!("{GUEST_SHARE}/containers/{}", safe_name(&req.id));
        let rootfs = host_ctr.join("rootfs");
        let mountpoint = self.cfg.state_dir.join(&self.namespace).join(&self.group).join("mounts").join(safe_name(&req.id));

        let stage_rootfs = async {
            // A failed/retried CreateTask must never inherit files or FIFOs
            // from a previous attempt.
            let _ = tokio::fs::remove_dir_all(&host_ctr).await;
            let _ = tokio::fs::remove_dir_all(&mountpoint).await;
            tokio::fs::create_dir_all(&rootfs).await?;
            tokio::fs::create_dir_all(&mountpoint).await?;
            for m in &req.rootfs {
                containerd_shim::asynchronous::util::mount_rootfs(m, &mountpoint)
                    .await
                    .map_err(|e| anyhow::anyhow!("mounting containerd rootfs: {e}"))?;
            }
            let copy_result = copy_contents(&mountpoint, &rootfs).await;
            let _ = tokio::process::Command::new("umount").args(["-l", mountpoint.to_string_lossy().as_ref()]).status().await;
            let _ = tokio::fs::remove_dir_all(&mountpoint).await;
            copy_result
        };

        let (vm, ()) = tokio::try_join!(self.ensure_sandbox(Some(&hints)), stage_rootfs)?;

        spec["root"]["path"] = Value::String(format!("{guest_ctr}/rootfs"));
        stage_bind_mounts(&mut spec, &host_ctr, &guest_ctr, hints.pod_uid.as_deref()).await?;
        let (io, io_dir) = self.prepare_io(&req.id, &req.stdin, &req.stdout, &req.stderr, req.terminal, &host_ctr, &guest_ctr).await?;
        Ok((vm, serde_json::to_string(&spec)?, io, io_dir))
    }

    async fn prepare_io(&self, id: &str, stdin: &str, stdout: &str, stderr: &str, terminal: bool, host_ctr: &Path, guest_ctr: &str) -> AnyResult<(ContainerIo, Option<PathBuf>)> {
        if self.cfg.streaming_stdio {
            // Set 5: presence markers only. No stdio bytes traverse virtiofs;
            // the guest agent binds real pipes/PTYs and the shim attaches to
            // them over the dedicated VSOCK stream endpoint.
            let mut guest = ContainerIo {
                stdin: (!stdin.is_empty()).then(|| "vsock".into()),
                stdout: None,
                stderr: None,
                terminal,
                streaming: true,
            };
            if terminal {
                if !stdout.is_empty() || !stderr.is_empty() {
                    guest.stdout = Some("vsock".into());
                }
            } else {
                guest.stdout = (!stdout.is_empty()).then(|| "vsock".into());
                guest.stderr = (!stderr.is_empty()).then(|| "vsock".into());
            }
            return Ok((guest, None));
        }

        if terminal { bail!("TTY requires FLUXVM_CONTAINER_STREAMING_STDIO=1"); }
        let io_key = safe_name(id);
        let io_dir = host_ctr.join("io").join(&io_key);
        let guest_io_dir = format!("{guest_ctr}/io/{io_key}");
        tokio::fs::create_dir_all(&io_dir).await?;
        let mut guest = ContainerIo::default();
        if !stdout.is_empty() {
            let p = io_dir.join("stdout.log"); create_stdio_file(&p)?;
            guest.stdout = Some(format!("{guest_io_dir}/stdout.log"));
            spawn_stdio_relay(p, PathBuf::from(stdout), format!("{id}:stdout"), true);
        }
        if !stderr.is_empty() {
            let p = io_dir.join("stderr.log"); create_stdio_file(&p)?;
            guest.stderr = Some(format!("{guest_io_dir}/stderr.log"));
            spawn_stdio_relay(p, PathBuf::from(stderr), format!("{id}:stderr"), true);
        }
        if !stdin.is_empty() {
            let p = io_dir.join("stdin.log"); create_stdio_file(&p)?;
            guest.stdin = Some(format!("{guest_io_dir}/stdin.log"));
            spawn_stdio_relay(PathBuf::from(stdin), p, format!("{id}:stdin"), false);
        }
        Ok((guest, Some(io_dir)))
    }

    async fn attach_stream_relays(
        &self,
        vm: &VmRecord,
        id: &str,
        exec_id: Option<&str>,
        stdin: &str,
        stdout: &str,
        stderr: &str,
        terminal: bool,
    ) -> AnyResult<()> {
        if !self.cfg.streaming_stdio { return Ok(()); }

        // Validate containerd-owned endpoints before consuming a one-shot guest
        // stream attachment. Opening the guest side first and then discovering
        // a missing FIFO/file would permanently consume stdout/stderr for the
        // process and make a retry impossible.
        for (name, path) in [("stdin", stdin), ("stdout", stdout), ("stderr", stderr)] {
            if !path.is_empty() && !Path::new(path).exists() {
                bail!("containerd {name} endpoint does not exist: {path}");
            }
        }

        let mut relays = Vec::new();
        let attach = |kind| IoStreamAttach {
            token: None,
            id: id.to_string(),
            exec_id: exec_id.map(str::to_string),
            stream: kind,
        };

        if !stdin.is_empty() {
            let stream = fluxvm_container_client::open_stream(vm, attach(IoStreamKind::Stdin), Duration::from_secs(10)).await?;
            relays.push((IoStreamKind::Stdin, stream, PathBuf::from(stdin)));
        }
        if terminal {
            let output = if !stdout.is_empty() { stdout } else { stderr };
            if !output.is_empty() {
                let stream = fluxvm_container_client::open_stream(vm, attach(IoStreamKind::Stdout), Duration::from_secs(10)).await?;
                relays.push((IoStreamKind::Stdout, stream, PathBuf::from(output)));
            }
        } else {
            if !stdout.is_empty() {
                let stream = fluxvm_container_client::open_stream(vm, attach(IoStreamKind::Stdout), Duration::from_secs(10)).await?;
                relays.push((IoStreamKind::Stdout, stream, PathBuf::from(stdout)));
            }
            if !stderr.is_empty() {
                let stream = fluxvm_container_client::open_stream(vm, attach(IoStreamKind::Stderr), Duration::from_secs(10)).await?;
                relays.push((IoStreamKind::Stderr, stream, PathBuf::from(stderr)));
            }
        }

        let key = process_key(id, exec_id);
        let output_count = relays.iter().filter(|(kind, _, _)| *kind != IoStreamKind::Stdin).count();
        if output_count > 0 {
            self.stream_pending.lock().await.insert(key.clone(), output_count);
        }
        for (kind, mut stream, host_path) in relays {
            let pending = self.stream_pending.clone();
            let relay_key = key.clone();
            tokio::spawn(async move {
                let is_output = kind != IoStreamKind::Stdin;
                let result = tokio::task::spawn_blocking(move || -> AnyResult<()> {
                    match kind {
                        IoStreamKind::Stdin => {
                            let mut host = std::fs::OpenOptions::new().read(true).open(&host_path)
                                .with_context(|| format!("opening containerd stdin {}", host_path.display()))?;
                            std::io::copy(&mut host, &mut stream)?;
                            use std::io::Write as _;
                            stream.flush()?;
                        }
                        IoStreamKind::Stdout | IoStreamKind::Stderr => {
                            let mut host = std::fs::OpenOptions::new().write(true).open(&host_path)
                                .with_context(|| format!("opening containerd output {}", host_path.display()))?;
                            std::io::copy(&mut stream, &mut host)?;
                            use std::io::Write as _;
                            host.flush()?;
                        }
                    }
                    Ok(())
                }).await;
                if is_output {
                    let mut map = pending.lock().await;
                    if let Some(count) = map.get_mut(&relay_key) {
                        *count = count.saturating_sub(1);
                        if *count == 0 { map.remove(&relay_key); }
                    }
                }
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => warn!("VSOCK stdio relay {relay_key:?}/{kind:?} stopped: {e:#}"),
                    Err(e) => warn!("VSOCK stdio relay {relay_key:?}/{kind:?} panicked: {e}"),
                }
            });
        }
        Ok(())
    }

    /// Wait for the selected process's virtiofs stdout/stderr files to stop
    /// growing, then give the host relay a final beat before publishing exit.
    async fn flush_stdio_after_exit(&self, id: &str, exec_id: Option<&str>) {
        let key = process_key(id, exec_id);
        let streaming = if let Some(exec_id) = exec_id {
            self.execs.read().await.get(&key).is_some_and(|m| m.streaming)
        } else {
            self.tasks.read().await.get(id).is_some_and(|m| m.streaming)
        };
        if streaming {
            for _ in 0..200 {
                if !self.stream_pending.lock().await.contains_key(&key) { return; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            warn!("timed out waiting for VSOCK stdio drain for {key:?}");
            return;
        }
        let io_dir = if let Some(exec_id) = exec_id {
            self.execs
                .read()
                .await
                .get(&process_key(id, Some(exec_id)))
                .and_then(|m| m.io_dir.clone())
        } else {
            self.tasks.read().await.get(id).and_then(|m| m.io_dir.clone())
        };
        let Some(io_dir) = io_dir else {
            tokio::time::sleep(Duration::from_millis(250)).await;
            return;
        };
        for name in ["stdout.log", "stderr.log"] {
            let path = io_dir.join(name);
            let mut last = None;
            let mut stable = 0u32;
            for _ in 0..80 {
                let size = tokio::fs::metadata(&path).await.map(|m| m.len()).unwrap_or(0);
                if Some(size) == last {
                    stable += 1;
                    if stable >= 4 { break; }
                } else {
                    stable = 0;
                    last = Some(size);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }

    async fn call_agent_direct(&self, vm: &VmRecord, req: ContainerRequest) -> AnyResult<ContainerResponse> {
        match fluxvm_container_client::call(vm, req, Duration::from_secs(60)).await? {
            ContainerResponse::Error { message } => bail!("guest container-agent: {message}"),
            response => Ok(response),
        }
    }

    async fn call_agent(&self, vm: &VmRecord, req: ContainerRequest) -> AnyResult<ContainerResponse> {
        self.call_agent_direct(vm, req).await
    }

    async fn send_event<E>(&self, event: E)
    where
        E: Event + 'static,
    {
        let topic = event.topic();
        if let Err(e) = self.event_tx.send((topic.clone(), Box::new(event))).await {
            warn!("sending {topic} event to publisher queue failed: {e}");
        }
    }

    async fn publish_exit_once(
        &self,
        container_id: String,
        exec_id: Option<String>,
        pid: u32,
        exit_code: i32,
        exited_at_unix_nano: i64,
    ) {
        let key = process_key(&container_id, exec_id.as_deref());
        let should_publish = {
            let mut exits = self.exit_events.lock().await;
            exits.insert(key)
        };
        if !should_publish {
            return;
        }
        self.send_event(TaskExit {
            container_id,
            id: exec_id.unwrap_or_default(),
            pid,
            exit_status: exit_code as u32,
            exited_at: Some(timestamp_from_nanos(exited_at_unix_nano)).into(),
            ..Default::default()
        })
        .await;
    }

    fn spawn_exit_watch(&self, vm: VmRecord, container_id: String, exec_id: Option<String>, pid: u32) {
        let service = self.clone();
        tokio::spawn(async move {
            let request = ContainerRequest::Wait {
                id: container_id.clone(),
                exec_id: exec_id.clone(),
            };
            match service.call_agent_direct(&vm, request).await {
                Ok(ContainerResponse::Exited { exit_code, exited_at_unix_nano }) => {
                    service.flush_stdio_after_exit(&container_id, exec_id.as_deref()).await;
                    service
                        .publish_exit_once(container_id, exec_id, pid, exit_code, exited_at_unix_nano)
                        .await;
                }
                Ok(other) => warn!("unexpected background wait response: {other:?}"),
                Err(e) => warn!("background FluxVM container wait failed: {e:#}"),
            }
        });
    }

    async fn cleanup_process_staging(&self, id: &str, exec_id: Option<&str>) {
        self.stream_pending.lock().await.remove(&process_key(id, exec_id));
        let share_dir = {
            let guard = self.sandbox.lock().await;
            guard.as_ref().map(|s| s.share_dir.clone())
        }
        .unwrap_or_else(|| {
            self.cfg
                .state_dir
                .join(&self.namespace)
                .join(&self.group)
                .join("share")
        });
        let host_ctr = share_dir.join("containers").join(safe_name(id));
        if let Some(exec_id) = exec_id {
            let key = safe_name(&format!("{id}-{exec_id}"));
            let _ = tokio::fs::remove_dir_all(host_ctr.join("io").join(key)).await;
        } else {
            let _ = tokio::fs::remove_dir_all(host_ctr).await;
        }
    }

    async fn destroy_sandbox(&self) -> AnyResult<()> {
        let mut guard = self.sandbox.lock().await;
        if let Some(s) = guard.take() {
            let _ = self.api(Method::DELETE, &format!("/v1/vms/{}", s.vm.id), None).await;
            if let Some(cni) = s.cni.as_ref() {
                cleanup_cni_bridge(cni).await;
            }
            let root = self.cfg.state_dir.join(&self.namespace).join(&self.group);
            let _ = tokio::fs::remove_dir_all(root).await;
        }
        Ok(())
    }
}

#[async_trait]
impl Task for Service {
    async fn create(&self, _ctx: &TtrpcContext, req: CreateTaskRequest) -> TtrpcResult<CreateTaskResponse> {
        let (vm, config_json, io, io_dir) = match self.stage_rootfs_and_config(&req).await {
            Ok(staged) => staged,
            Err(e) => {
                self.cleanup_process_staging(&req.id, None).await;
                return Err(rpc_other(e));
            }
        };
        let is_sandbox = req.id == self.group;
        let share_process_namespace = config_requests_shared_pid_ns(&config_json);
        let response = match self
            .call_agent(
                &vm,
                ContainerRequest::Create {
                    id: req.id.clone(),
                    config_json,
                    io,
                    is_sandbox,
                    share_process_namespace,
                    // Set 8S: not yet wired to fetch the Pod's Set 6S
                    // network policy and mirror it per-container (see
                    // docs/secure-containers-set8s.md) -- every container
                    // still gets Set 8S's fail-closed-by-default enforcement
                    // attached, just with an empty (deny-non-loopback)
                    // policy until that wiring lands.
                    network_policy: None,
                },
            )
            .await
        {
            Ok(response) => response,
            Err(e) => {
                self.cleanup_process_staging(&req.id, None).await;
                return Err(rpc_other(e));
            }
        };
        let pid = match response {
            ContainerResponse::Created { pid } => pid,
            other => {
                self.cleanup_process_staging(&req.id, None).await;
                return Err(rpc_other(format!("unexpected create response: {other:?}")));
            }
        };
        if let Err(e) = self.attach_stream_relays(
            &vm, &req.id, None, &req.stdin, &req.stdout, &req.stderr, req.terminal
        ).await {
            let _ = self.call_agent(&vm, ContainerRequest::Delete {
                id: req.id.clone(), exec_id: None, force: true
            }).await;
            self.cleanup_process_staging(&req.id, None).await;
            return Err(rpc_other(format!("attaching VSOCK stdio: {e:#}")));
        }
        {
            let mut exits = self.exit_events.lock().await;
            let prefix = format!("{}\0", req.id);
            exits.retain(|key| key != &req.id && !key.starts_with(&prefix));
        }
        self.tasks.write().await.insert(req.id.clone(), TaskMeta {
            bundle: req.bundle.clone(), stdin: req.stdin.clone(), stdout: req.stdout.clone(), stderr: req.stderr.clone(), terminal: req.terminal, pid,
            io_dir,
            streaming: self.cfg.streaming_stdio,
        });
        self.send_event(TaskCreate {
            container_id: req.id.clone(),
            bundle: req.bundle.clone(),
            rootfs: req.rootfs.clone(),
            io: Some(TaskIO {
                stdin: req.stdin.clone(),
                stdout: req.stdout.clone(),
                stderr: req.stderr.clone(),
                terminal: req.terminal,
                ..Default::default()
            }).into(),
            checkpoint: req.checkpoint.clone(),
            pid,
            ..Default::default()
        }).await;
        Ok(CreateTaskResponse { pid, ..Default::default() })
    }

    async fn start(&self, _ctx: &TtrpcContext, req: StartRequest) -> TtrpcResult<StartResponse> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id.clone()) };
        let response = self.call_agent(&vm, ContainerRequest::Start { id: req.id.clone(), exec_id: exec_id.clone() }).await.map_err(rpc_other)?;
        let pid = match response {
            ContainerResponse::Started { pid } => pid,
            other => return Err(rpc_other(format!("unexpected start response: {other:?}"))),
        };
        if let Some(exec_id_value) = exec_id.as_ref() {
            self.send_event(TaskExecStarted {
                container_id: req.id.clone(),
                exec_id: exec_id_value.clone(),
                pid,
                ..Default::default()
            }).await;
        } else {
            self.send_event(TaskStart {
                container_id: req.id.clone(),
                pid,
                ..Default::default()
            }).await;
        }
        self.spawn_exit_watch(vm, req.id.clone(), exec_id, pid);
        Ok(StartResponse { pid, ..Default::default() })
    }

    async fn state(&self, _ctx: &TtrpcContext, req: StateRequest) -> TtrpcResult<StateResponse> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id.clone()) };
        let response = self.call_agent(&vm, ContainerRequest::State { id: req.id.clone(), exec_id: exec_id.clone() }).await.map_err(rpc_other)?;
        let (status, pid, exit_code, exited_at) = match response {
            ContainerResponse::State { status, pid, exit_code, exited_at_unix_nano, .. } => (status, pid, exit_code, exited_at_unix_nano),
            other => return Err(rpc_other(format!("unexpected state response: {other:?}"))),
        };
        let meta = if let Some(exec_id) = exec_id.as_deref() {
            self.execs.read().await.get(&process_key(&req.id, Some(exec_id))).cloned()
        } else {
            self.tasks.read().await.get(&req.id).cloned()
        };
        let mut out = StateResponse {
            id: req.id,
            bundle: meta.as_ref().map(|m| m.bundle.clone()).unwrap_or_default(),
            pid,
            status: EnumOrUnknown::new(map_status(status)),
            stdin: meta.as_ref().map(|m| m.stdin.clone()).unwrap_or_default(),
            stdout: meta.as_ref().map(|m| m.stdout.clone()).unwrap_or_default(),
            stderr: meta.as_ref().map(|m| m.stderr.clone()).unwrap_or_default(),
            terminal: meta.as_ref().is_some_and(|m| m.terminal),
            exit_status: exit_code.unwrap_or_default() as u32,
            ..Default::default()
        };
        if let Some(ns) = exited_at { out.exited_at = Some(timestamp_from_nanos(ns)).into(); }
        Ok(out)
    }

    async fn wait(&self, _ctx: &TtrpcContext, req: WaitRequest) -> TtrpcResult<WaitResponse> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id.clone()) };
        let response = self.call_agent(&vm, ContainerRequest::Wait { id: req.id.clone(), exec_id: exec_id.clone() }).await.map_err(rpc_other)?;
        match response {
            ContainerResponse::Exited { exit_code, exited_at_unix_nano } => {
                self.flush_stdio_after_exit(&req.id, exec_id.as_deref()).await;
                let pid = if let Some(exec) = exec_id.as_deref() {
                    self.execs.read().await.get(&process_key(&req.id, Some(exec))).map(|m| m.pid).unwrap_or(0)
                } else {
                    self.tasks.read().await.get(&req.id).map(|m| m.pid).unwrap_or(0)
                };
                self.publish_exit_once(req.id.clone(), exec_id, pid, exit_code, exited_at_unix_nano).await;
                let mut out = WaitResponse::new();
                out.exit_status = exit_code as u32;
                out.exited_at = Some(timestamp_from_nanos(exited_at_unix_nano)).into();
                Ok(out)
            }
            other => Err(rpc_other(format!("unexpected wait response: {other:?}"))),
        }
    }

    async fn kill(&self, _ctx: &TtrpcContext, req: KillRequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id) };
        self.call_agent(&vm, ContainerRequest::Kill { id: req.id, exec_id, signal: req.signal as i32, all: req.all }).await.map_err(rpc_other)?;
        Ok(Empty::new())
    }

    async fn pause(&self, _ctx: &TtrpcContext, req: PauseRequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        self.call_agent(&vm, ContainerRequest::Pause { id: req.id.clone() }).await.map_err(rpc_other)?;
        self.send_event(TaskPaused { container_id: req.id, ..Default::default() }).await;
        Ok(Empty::new())
    }

    async fn resume(&self, _ctx: &TtrpcContext, req: ResumeRequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        self.call_agent(&vm, ContainerRequest::Resume { id: req.id.clone() }).await.map_err(rpc_other)?;
        self.send_event(TaskResumed { container_id: req.id, ..Default::default() }).await;
        Ok(Empty::new())
    }

    async fn delete(&self, _ctx: &TtrpcContext, req: DeleteRequest) -> TtrpcResult<DeleteResponse> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id.clone()) };
        let response = self
            .call_agent(
                &vm,
                ContainerRequest::Delete {
                    id: req.id.clone(),
                    exec_id: exec_id.clone(),
                    force: true,
                },
            )
            .await
            .map_err(rpc_other)?;
        let (pid, code, ns) = match response {
            ContainerResponse::Deleted { pid, exit_code, exited_at_unix_nano } => {
                (pid, exit_code, exited_at_unix_nano)
            }
            other => return Err(rpc_other(format!("unexpected delete response: {other:?}"))),
        };

        // containerd expects stdio to be drained and exit to precede delete.
        // The background WaitTask watcher races with force-delete, so this
        // path uses a de-duplicated publisher to avoid duplicate exit events.
        self.flush_stdio_after_exit(&req.id, exec_id.as_deref()).await;
        self.publish_exit_once(req.id.clone(), exec_id.clone(), pid, code, ns).await;
        self.cleanup_process_staging(&req.id, exec_id.as_deref()).await;

        if let Some(exec_id_value) = exec_id.as_deref() {
            self.execs.write().await.remove(&process_key(&req.id, Some(exec_id_value)));
        } else {
            self.tasks.write().await.remove(&req.id);
            self.execs.write().await.retain(|key, _| !key.starts_with(&format!("{}\0", req.id)));
        }

        self.send_event(TaskDelete {
            container_id: req.id.clone(),
            pid,
            exit_status: code as u32,
            exited_at: Some(timestamp_from_nanos(ns)).into(),
            ..Default::default()
        }).await;

        let mut out = DeleteResponse::new();
        out.pid = pid;
        out.exit_status = code as u32;
        out.exited_at = Some(timestamp_from_nanos(ns)).into();
        Ok(out)
    }

    async fn exec(&self, _ctx: &TtrpcContext, req: ExecProcessRequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let bytes = req.spec.as_ref().map(|a| a.value.clone()).unwrap_or_default();
        if bytes.is_empty() { return Err(rpc_invalid("ExecProcessRequest.spec is empty")); }
        let process_json = String::from_utf8(bytes).map_err(|e| rpc_invalid(e.to_string()))?;
        let (_, host_ctr, guest_ctr) = self.sandbox_paths(&req.id, None).await.map_err(rpc_other)?;
        let io_id = format!("{}-{}", req.id, req.exec_id);
        let (io, io_dir) = self.prepare_io(&io_id, &req.stdin, &req.stdout, &req.stderr, req.terminal, &host_ctr, &guest_ctr).await.map_err(rpc_other)?;
        let response = self.call_agent(&vm, ContainerRequest::Exec {
            id: req.id.clone(),
            exec_id: req.exec_id.clone(),
            process_json,
            io,
        }).await.map_err(rpc_other)?;
        let pid = match response {
            ContainerResponse::ExecStarted { pid } => pid,
            other => return Err(rpc_other(format!("unexpected exec response: {other:?}"))),
        };
        if let Err(e) = self.attach_stream_relays(
            &vm, &req.id, Some(&req.exec_id), &req.stdin, &req.stdout, &req.stderr, req.terminal
        ).await {
            let _ = self.call_agent(&vm, ContainerRequest::Delete {
                id: req.id.clone(), exec_id: Some(req.exec_id.clone()), force: true
            }).await;
            self.cleanup_process_staging(&req.id, Some(&req.exec_id)).await;
            return Err(rpc_other(format!("attaching exec VSOCK stdio: {e:#}")));
        }
        let bundle = self.tasks.read().await.get(&req.id).map(|m| m.bundle.clone()).unwrap_or_default();
        self.exit_events.lock().await.remove(&process_key(&req.id, Some(&req.exec_id)));
        self.execs.write().await.insert(process_key(&req.id, Some(&req.exec_id)), TaskMeta {
            bundle,
            stdin: req.stdin.clone(),
            stdout: req.stdout.clone(),
            stderr: req.stderr.clone(),
            terminal: req.terminal,
            pid,
            io_dir,
            streaming: self.cfg.streaming_stdio,
        });
        self.send_event(TaskExecAdded {
            container_id: req.id,
            exec_id: req.exec_id,
            ..Default::default()
        }).await;
        Ok(Empty::new())
    }

    async fn connect(&self, _ctx: &TtrpcContext, req: ConnectRequest) -> TtrpcResult<ConnectResponse> {
        let pid = self.tasks.read().await.get(&req.id).map(|m| m.pid).unwrap_or(0);
        Ok(ConnectResponse { shim_pid: std::process::id(), task_pid: pid, version: env!("CARGO_PKG_VERSION").into(), ..Default::default() })
    }

    async fn shutdown(&self, _ctx: &TtrpcContext, _req: ShutdownRequest) -> TtrpcResult<Empty> {
        if self.tasks.read().await.is_empty() && self.execs.read().await.is_empty() {
            let _ = self.destroy_sandbox().await;
            self.exit.signal();
        }
        Ok(Empty::new())
    }

    async fn resize_pty(&self, _ctx: &TtrpcContext, req: ResizePtyRequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id) };
        match self.call_agent(&vm, ContainerRequest::ResizePty {
            id: req.id, exec_id, width: req.width, height: req.height
        }).await.map_err(rpc_other)? {
            ContainerResponse::PtyResized => Ok(Empty::new()),
            other => Err(rpc_other(format!("unexpected resize response: {other:?}"))),
        }
    }

    async fn close_io(&self, _ctx: &TtrpcContext, req: CloseIORequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id) };
        match self.call_agent(&vm, ContainerRequest::CloseIo { id: req.id, exec_id }).await.map_err(rpc_other)? {
            ContainerResponse::IoClosed => Ok(Empty::new()),
            other => Err(rpc_other(format!("unexpected close-io response: {other:?}"))),
        }
    }

    async fn pids(&self, _ctx: &TtrpcContext, req: PidsRequest) -> TtrpcResult<PidsResponse> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        match self.call_agent(&vm, ContainerRequest::Pids { id: req.id }).await.map_err(rpc_other)? {
            ContainerResponse::Pids { pids } => Ok(PidsResponse {
                processes: pids.into_iter().map(|pid| ProcessInfo { pid, ..Default::default() }).collect(),
                ..Default::default()
            }),
            other => Err(rpc_other(format!("unexpected pids response: {other:?}"))),
        }
    }

    async fn stats(&self, _ctx: &TtrpcContext, req: StatsRequest) -> TtrpcResult<StatsResponse> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let response = self.call_agent(&vm, ContainerRequest::Stats { id: req.id }).await.map_err(rpc_other)?;
        let stats = match response {
            ContainerResponse::Stats { stats } => stats,
            other => return Err(rpc_other(format!("unexpected stats response: {other:?}"))),
        };
        let metrics = stats_to_metrics(&stats);
        let mut out = StatsResponse::new();
        out.set_stats(convert_to_any(Box::new(metrics)).map_err(rpc_other)?);
        Ok(out)
    }

    async fn update(&self, _ctx: &TtrpcContext, req: UpdateTaskRequest) -> TtrpcResult<Empty> {
        let bytes = req.resources.as_ref().map(|any| any.value.clone()).unwrap_or_default();
        if bytes.is_empty() {
            return Err(rpc_invalid("UpdateTaskRequest.resources is empty"));
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| rpc_invalid(format!("invalid LinuxResources JSON: {e}")))?;
        let resources = resource_limits_from_linux_resources(&value);
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        match self.call_agent(&vm, ContainerRequest::UpdateResources { id: req.id, resources }).await.map_err(rpc_other)? {
            ContainerResponse::ResourcesUpdated => Ok(Empty::new()),
            other => Err(rpc_other(format!("unexpected update response: {other:?}"))),
        }
    }
}

fn forward_events(publisher: RemotePublisher, namespace: String, mut rx: EventReceiver) {
    tokio::spawn(async move {
        while let Some((topic, event)) = rx.recv().await {
            if let Err(e) = publisher
                .publish(ttrpc::context::Context::default(), &topic, &namespace, event)
                .await
            {
                warn!("publishing {topic} to containerd failed: {e}");
            }
        }
    });
}

fn process_key(id: &str, exec_id: Option<&str>) -> String {
    match exec_id {
        Some(exec_id) => format!("{id}\0{exec_id}"),
        None => id.to_string(),
    }
}

fn map_status(status: ContainerStatus) -> Status {
    match status {
        ContainerStatus::Created => Status::CREATED,
        ContainerStatus::Running => Status::RUNNING,
        ContainerStatus::Paused => Status::PAUSED,
        ContainerStatus::Stopped => Status::STOPPED,
    }
}

fn timestamp_from_nanos(ns: i64) -> containerd_shim_protos::protobuf::well_known_types::timestamp::Timestamp {
    let mut ts = containerd_shim_protos::protobuf::well_known_types::timestamp::Timestamp::new();
    ts.seconds = ns.div_euclid(1_000_000_000) as i64;
    ts.nanos = ns.rem_euclid(1_000_000_000) as i32;
    ts
}


fn stats_to_metrics(stats: &ContainerStats) -> Metrics {
    let mut usage = CPUUsage::new();
    usage.set_total(stats.cpu_usage_usec);
    usage.set_user(stats.cpu_user_usec);
    usage.set_kernel(stats.cpu_system_usec);
    let mut cpu = CPUStat::new();
    cpu.set_usage(usage);

    let mut mem_usage = MemoryEntry::new();
    mem_usage.set_usage(stats.memory_usage_bytes);
    let mut memory = MemoryStat::new();
    memory.set_usage(mem_usage);
    memory.set_total_inactive_file(stats.memory_total_inactive_file_bytes);

    let mut pids = PidsStat::new();
    pids.set_current(stats.pids_current);
    pids.set_limit(stats.pids_limit);

    let mut metrics = Metrics::new();
    metrics.set_cpu(cpu);
    metrics.set_memory(memory);
    metrics.set_pids(pids);
    metrics
}

fn resource_limits_from_linux_resources(value: &Value) -> ResourceLimits {
    ResourceLimits {
        cpu_quota: value.pointer("/cpu/quota").and_then(Value::as_i64),
        cpu_period: value.pointer("/cpu/period").and_then(Value::as_u64),
        cpu_shares: value.pointer("/cpu/shares").and_then(Value::as_u64),
        cpuset_cpus: value.pointer("/cpu/cpus").and_then(Value::as_str).map(str::to_string),
        cpuset_mems: value.pointer("/cpu/mems").and_then(Value::as_str).map(str::to_string),
        memory_limit_bytes: value.pointer("/memory/limit").and_then(Value::as_i64),
        pids_limit: value.pointer("/pids/limit").and_then(Value::as_i64),
    }
}

fn sandbox_hints_from_spec(spec: &Value) -> SandboxHints {
    let mut resources = resource_limits_from_linux_resources(
        spec.pointer("/linux/resources").unwrap_or(&Value::Null),
    );
    let pod_uid = spec
        .get("annotations")
        .and_then(Value::as_object)
        .and_then(|annotations| {
            let parse_i64 = |key: &str| annotations.get(key).and_then(Value::as_str).and_then(|v| v.parse::<i64>().ok());
            let parse_u64 = |key: &str| annotations.get(key).and_then(Value::as_str).and_then(|v| v.parse::<u64>().ok());
            if let Some(v) = parse_i64("io.kubernetes.cri.sandbox-cpu-quota") { resources.cpu_quota = Some(v); }
            if let Some(v) = parse_u64("io.kubernetes.cri.sandbox-cpu-period") { resources.cpu_period = Some(v); }
            if let Some(v) = parse_u64("io.kubernetes.cri.sandbox-cpu-shares") { resources.cpu_shares = Some(v); }
            if let Some(v) = parse_i64("io.kubernetes.cri.sandbox-memory") { resources.memory_limit_bytes = Some(v); }
            annotations
                .get("io.kubernetes.cri.sandbox-uid")
                .and_then(Value::as_str)
                .filter(|uid| !uid.is_empty() && uid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
                .map(str::to_string)
        });
    let netns_path = spec
        .pointer("/linux/namespaces")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                let ty = item.get("type").and_then(Value::as_str)?;
                if ty != "network" { return None; }
                item.get("path")
                    .and_then(Value::as_str)
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from)
            })
        });
    SandboxHints { resources, netns_path, pod_uid }
}

fn vm_shape(default_vcpus: u8, default_memory_mib: u64, overhead_mib: u64, resources: &ResourceLimits) -> (u8, u64) {
    let requested_vcpus = match (resources.cpu_quota, resources.cpu_period) {
        (Some(quota), Some(period)) if quota > 0 && period > 0 => {
            let quota = quota as u64;
            quota.saturating_add(period - 1).saturating_div(period).clamp(1, 254) as u8
        }
        _ => 0,
    };
    let requested_memory = resources
        .memory_limit_bytes
        .filter(|v| *v > 0)
        .map(|bytes| {
            let bytes = bytes as u64;
            bytes.saturating_add((1024 * 1024) - 1) / (1024 * 1024)
        })
        .unwrap_or(0)
        .saturating_add(if resources.memory_limit_bytes.is_some_and(|v| v > 0) { overhead_mib } else { 0 });
    (
        default_vcpus.max(requested_vcpus),
        default_memory_mib.max(requested_memory),
    )
}

fn stable_hash(value: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn stable_mac(value: &str) -> String {
    let h = stable_hash(value).to_be_bytes();
    format!("02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", h[3], h[4], h[5], h[6], h[7])
}

fn cni_suffix(group: &str) -> String {
    format!("{:016x}", stable_hash(group))[..6].to_string()
}

fn valid_iface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

async fn run_command(program: &str, args: &[String]) -> AnyResult<()> {
    let out = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("starting {program}"))?;
    if !out.status.success() {
        bail!(
            "{} {} failed ({}): {}",
            program,
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

async fn run_command_best_effort(program: &str, args: &[String]) {
    let _ = tokio::process::Command::new(program).args(args).output().await;
}

async fn command_output(program: &str, args: &[String]) -> AnyResult<String> {
    let out = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .with_context(|| format!("starting {program}"))?;
    if !out.status.success() {
        bail!(
            "{} {} failed ({}): {}",
            program,
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn parse_mac(raw: &str) -> AnyResult<String> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 6
        || parts
            .iter()
            .any(|p| p.len() != 2 || u8::from_str_radix(p, 16).is_err())
    {
        bail!("invalid CNI MAC address {raw:?}");
    }
    Ok(parts.join(":").to_ascii_lowercase())
}

fn parse_ipv4_destination(raw: &str) -> AnyResult<Option<(Ipv4Addr, u8)>> {
    if raw == "default" || raw.is_empty() {
        return Ok(None);
    }
    let (address, prefix) = raw.split_once('/').unwrap_or((raw, "32"));
    let address = address
        .parse::<Ipv4Addr>()
        .with_context(|| format!("invalid IPv4 route destination {raw:?}"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid IPv4 route prefix {raw:?}"))?;
    if prefix > 32 {
        bail!("invalid IPv4 route prefix {raw:?}");
    }
    Ok(Some((address, prefix)))
}

async fn capture_cni_network(netns_path: &Path, interface: &str) -> AnyResult<CniNetwork> {
    if !netns_path.exists() {
        bail!("CRI network namespace does not exist: {}", netns_path.display());
    }
    if !valid_iface_name(interface) {
        bail!("invalid CNI interface name {interface:?}");
    }

    let addr_args = vec![
        format!("--net={}", netns_path.display()),
        "--".into(),
        "ip".into(),
        "-4".into(),
        "-j".into(),
        "addr".into(),
        "show".into(),
        "dev".into(),
        interface.into(),
    ];
    let addr_text = command_output("nsenter", &addr_args).await?;
    let addr_json: Value =
        serde_json::from_str(&addr_text).context("parsing CNI ip -j addr output")?;
    let link = addr_json
        .as_array()
        .and_then(|links| links.first())
        .context("CNI interface was not returned by ip -j addr")?;
    let mac = parse_mac(
        link.get("address")
            .and_then(Value::as_str)
            .context("CNI interface has no MAC address")?,
    )?;
    let addr_info = link
        .get("addr_info")
        .and_then(Value::as_array)
        .context("CNI interface has no addr_info")?;
    let ipv4 = addr_info
        .iter()
        .find(|info| info.get("family").and_then(Value::as_str) == Some("inet"))
        .context("CNI namespace has no IPv4 address on the primary interface")?;
    let pod_ip = ipv4
        .get("local")
        .and_then(Value::as_str)
        .context("CNI IPv4 entry has no local address")?
        .parse::<Ipv4Addr>()
        .context("parsing CNI Pod IPv4 address")?;
    let prefix_len = ipv4
        .get("prefixlen")
        .and_then(Value::as_u64)
        .context("CNI IPv4 entry has no prefixlen")? as u8;
    if prefix_len > 32 {
        bail!("CNI IPv4 prefix length {prefix_len} is invalid");
    }

    let route_args = vec![
        format!("--net={}", netns_path.display()),
        "--".into(),
        "ip".into(),
        "-4".into(),
        "-j".into(),
        "route".into(),
        "show".into(),
    ];
    let route_text = command_output("nsenter", &route_args).await?;
    let route_json: Value =
        serde_json::from_str(&route_text).context("parsing CNI ip -j route output")?;
    let mut routes = Vec::new();
    for route in route_json.as_array().into_iter().flatten() {
        if route.get("dev").and_then(Value::as_str) != Some(interface) {
            continue;
        }
        let route_type = route.get("type").and_then(Value::as_str).unwrap_or("unicast");
        if route_type != "unicast" {
            continue;
        }
        let destination = parse_ipv4_destination(
            route.get("dst").and_then(Value::as_str).unwrap_or("default"),
        )?;
        let gateway = route
            .get("gateway")
            .and_then(Value::as_str)
            .map(|v| v.parse::<Ipv4Addr>())
            .transpose()
            .context("parsing CNI route gateway")?;
        routes.push(CniRoute {
            destination,
            gateway,
        });
    }
    // Link/local routes must exist before a default route that points through
    // them (Calico commonly uses a link-local next hop), so default goes last.
    routes.sort_by_key(|route| route.destination.is_none());

    Ok(CniNetwork {
        pod_ip,
        prefix_len,
        mac,
        routes,
    })
}

fn route_command(route: &CniRoute, interface: &str) -> String {
    let destination = route
        .destination
        .map(|(ip, prefix)| format!("{ip}/{prefix}"))
        .unwrap_or_else(|| "default".into());
    match route.gateway {
        Some(gateway) => format!(
            "ip -4 route replace {destination} via {gateway} dev \"$IFACE\""
        ),
        None => format!("ip -4 route replace {destination} dev \"$IFACE\""),
    }
}

fn guest_network_command(network: &CniNetwork) -> AnyResult<String> {
    parse_mac(&network.mac)?;
    if network.prefix_len > 32 {
        bail!("invalid Pod prefix length {}", network.prefix_len);
    }
    let mut lines = vec![
        "set -eu".to_string(),
        "IFACE=\"$(for p in /sys/class/net/*; do n=${p##*/}; [ \"$n\" = lo ] && continue; echo \"$n\"; break; done)\"".into(),
        "[ -n \"$IFACE\" ]".into(),
        "ip link set dev \"$IFACE\" up".into(),
        "ip -4 addr flush dev \"$IFACE\" || true".into(),
        "ip -4 route flush dev \"$IFACE\" || true".into(),
        format!(
            "ip -4 addr add {}/{} dev \"$IFACE\"",
            network.pod_ip, network.prefix_len
        ),
    ];
    for route in &network.routes {
        lines.push(route_command(route, "$IFACE"));
    }
    lines.push("ip -4 addr show dev \"$IFACE\"".into());
    lines.push("ip -4 route show".into());
    Ok(lines.join("\n"))
}

async fn bind_netns_alias(netns_path: &Path, alias: &str) -> AnyResult<PathBuf> {
    if !alias
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("invalid network namespace alias {alias:?}");
    }
    let dir = PathBuf::from("/run/netns");
    tokio::fs::create_dir_all(&dir).await?;
    let target = dir.join(alias);
    run_command_best_effort(
        "umount",
        &["-l".into(), target.to_string_lossy().into_owned()],
    )
    .await;
    let _ = tokio::fs::remove_file(&target).await;
    tokio::fs::File::create(&target).await?;
    if let Err(e) = run_command(
        "mount",
        &[
            "--bind".into(),
            netns_path.to_string_lossy().into_owned(),
            target.to_string_lossy().into_owned(),
        ],
    )
    .await
    {
        let _ = tokio::fs::remove_file(&target).await;
        return Err(e).context("binding CRI network namespace into /run/netns");
    }
    Ok(target)
}

async fn run_netns(alias: &str, program: &str, args: &[String]) -> AnyResult<()> {
    let mut full = vec!["netns".into(), "exec".into(), alias.into(), program.into()];
    full.extend_from_slice(args);
    run_command("ip", &full).await
}

async fn run_netns_best_effort(alias: &str, program: &str, args: &[String]) {
    let mut full = vec!["netns".into(), "exec".into(), alias.into(), program.into()];
    full.extend_from_slice(args);
    run_command_best_effort("ip", &full).await;
}

async fn prepare_cni_l2(group: &str, netns_path: &Path, interface: &str) -> AnyResult<CniBridge> {
    let network = capture_cni_network(netns_path, interface).await?;
    let suffix = cni_suffix(group);
    let alias = format!("fvcni-{suffix}");
    let host_bridge = format!("fvbh{suffix}");
    let host_veth = format!("fvh{suffix}");
    let cni_bridge = format!("fvcb{suffix}");
    let cni_veth = format!("fvn{suffix}");
    let netns_mount = bind_netns_alias(netns_path, &alias).await?;
    let bridge = CniBridge {
        netns_alias: alias.clone(),
        netns_mount,
        host_bridge: host_bridge.clone(),
        host_veth: host_veth.clone(),
        cni_bridge: cni_bridge.clone(),
        cni_veth: cni_veth.clone(),
        interface: interface.to_string(),
        network: network.clone(),
    };

    let port_mac = stable_mac(&format!("{group}:cni-port"));
    let result: AnyResult<()> = async {
        run_command_best_effort("ip", &["link".into(), "delete".into(), host_veth.clone()]).await;
        run_command_best_effort("ip", &["link".into(), "delete".into(), host_bridge.clone()]).await;
        run_netns_best_effort(&alias, "ip", &["link".into(), "delete".into(), cni_bridge.clone()]).await;

        run_command(
            "ip",
            &["link".into(), "add".into(), host_bridge.clone(), "type".into(), "bridge".into()],
        )
        .await?;
        run_command("ip", &["link".into(), "set".into(), host_bridge.clone(), "up".into()]).await?;
        run_command(
            "ip",
            &[
                "link".into(), "add".into(), host_veth.clone(), "type".into(), "veth".into(),
                "peer".into(), "name".into(), cni_veth.clone(),
            ],
        )
        .await?;
        run_command(
            "ip",
            &["link".into(), "set".into(), host_veth.clone(), "master".into(), host_bridge.clone()],
        )
        .await?;
        run_command("ip", &["link".into(), "set".into(), host_veth.clone(), "up".into()]).await?;
        run_command(
            "ip",
            &["link".into(), "set".into(), cni_veth.clone(), "netns".into(), alias.clone()],
        )
        .await?;

        run_netns(
            &alias,
            "ip",
            &["link".into(), "add".into(), cni_bridge.clone(), "type".into(), "bridge".into()],
        )
        .await?;
        run_netns(&alias, "ip", &["link".into(), "set".into(), cni_bridge.clone(), "up".into()]).await?;
        run_netns(
            &alias,
            "ip",
            &["link".into(), "set".into(), cni_veth.clone(), "master".into(), cni_bridge.clone()],
        )
        .await?;
        run_netns(&alias, "ip", &["link".into(), "set".into(), cni_veth.clone(), "up".into()]).await?;

        // The guest takes over the CNI-assigned Pod IP and original endpoint
        // MAC. Keep the veth as a pure bridge port and give the port itself a
        // different local MAC so the bridge does not have a permanent local
        // FDB entry that collides with frames sourced by the guest's MAC.
        run_netns(
            &alias,
            "ip",
            &["link".into(), "set".into(), interface.into(), "master".into(), cni_bridge.clone()],
        )
        .await?;
        run_netns(&alias, "ip", &["-4".into(), "addr".into(), "flush".into(), "dev".into(), interface.into()]).await?;
        run_netns_best_effort(&alias, "ip", &["-4".into(), "route".into(), "flush".into(), "dev".into(), interface.into()]).await;
        run_netns_best_effort(&alias, "ip", &["link".into(), "set".into(), interface.into(), "down".into()]).await;
        run_netns(&alias, "ip", &["link".into(), "set".into(), interface.into(), "address".into(), port_mac]).await?;
        run_netns(&alias, "ip", &["link".into(), "set".into(), interface.into(), "up".into()]).await?;
        Ok(())
    }
    .await;

    if let Err(e) = result {
        cleanup_cni_bridge(&bridge).await;
        return Err(e);
    }
    Ok(bridge)
}

async fn restore_cni_network(bridge: &CniBridge) {
    let alias = &bridge.netns_alias;
    let interface = &bridge.interface;
    run_netns_best_effort(alias, "ip", &["link".into(), "set".into(), interface.clone(), "nomaster".into()]).await;
    run_netns_best_effort(alias, "ip", &["link".into(), "set".into(), interface.clone(), "down".into()]).await;
    run_netns_best_effort(
        alias,
        "ip",
        &["link".into(), "set".into(), interface.clone(), "address".into(), bridge.network.mac.clone()],
    )
    .await;
    run_netns_best_effort(alias, "ip", &["link".into(), "set".into(), interface.clone(), "up".into()]).await;
    run_netns_best_effort(alias, "ip", &["-4".into(), "addr".into(), "flush".into(), "dev".into(), interface.clone()]).await;
    run_netns_best_effort(
        alias,
        "ip",
        &[
            "-4".into(), "addr".into(), "add".into(),
            format!("{}/{}", bridge.network.pod_ip, bridge.network.prefix_len),
            "dev".into(), interface.clone(),
        ],
    )
    .await;
    for route in &bridge.network.routes {
        let destination = route
            .destination
            .map(|(ip, prefix)| format!("{ip}/{prefix}"))
            .unwrap_or_else(|| "default".into());
        let mut args = vec!["-4".into(), "route".into(), "replace".into(), destination];
        if let Some(gateway) = route.gateway {
            args.extend(["via".into(), gateway.to_string()]);
        }
        args.extend(["dev".into(), interface.clone()]);
        run_netns_best_effort(alias, "ip", &args).await;
    }
}

async fn cleanup_cni_bridge(bridge: &CniBridge) {
    restore_cni_network(bridge).await;
    run_netns_best_effort(
        &bridge.netns_alias,
        "ip",
        &["link".into(), "delete".into(), bridge.cni_bridge.clone()],
    )
    .await;
    run_command_best_effort("ip", &["link".into(), "delete".into(), bridge.host_veth.clone()]).await;
    run_command_best_effort("ip", &["link".into(), "delete".into(), bridge.host_bridge.clone()]).await;
    run_command_best_effort(
        "umount",
        &["-l".into(), bridge.netns_mount.to_string_lossy().into_owned()],
    )
    .await;
    let _ = tokio::fs::remove_file(&bridge.netns_mount).await;
}

fn rpc_status(code: ttrpc::Code, message: impl Into<String>) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(code, message.into()))
}
fn rpc_other(e: impl std::fmt::Display) -> ttrpc::Error { rpc_status(ttrpc::Code::UNKNOWN, e.to_string()) }
fn rpc_invalid(e: impl Into<String>) -> ttrpc::Error { rpc_status(ttrpc::Code::INVALID_ARGUMENT, e) }

async fn pod_group_from_bundle(bundle: &str) -> Option<String> {
    if bundle.is_empty() { return None; }
    let text = tokio::fs::read_to_string(Path::new(bundle).join("config.json")).await.ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let ann = v.get("annotations")?.as_object()?;
    for key in ["io.containerd.runc.v2.group", "io.kubernetes.cri.sandbox-id"] {
        if let Some(group) = ann.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            return Some(group.to_string());
        }
    }
    None
}

/// Set 6: detects Kubernetes `shareProcessNamespace: true` the same
/// cross-runtime way Kata/runc do — containerd's CRI plugin only sets a
/// (host-meaningless, from FluxVM's guest-side perspective) `path` on the
/// OCI `linux.namespaces` PID entry when the Pod requested a shared PID
/// namespace; an unset/empty path means "give this container its own". We
/// only care about presence, never the path's value, since the shared
/// namespace itself is tracked guest-side by `fluxvm-container-agent`.
fn config_requests_shared_pid_ns(config_json: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(config_json) else { return false };
    let Some(namespaces) = v.pointer("/linux/namespaces").and_then(Value::as_array) else {
        return false;
    };
    namespaces.iter().any(|ns| {
        ns.get("type").and_then(Value::as_str) == Some("pid")
            && ns.get("path").and_then(Value::as_str).is_some_and(|p| !p.is_empty())
    })
}

fn safe_name(s: &str) -> String {
    let mut out: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    if out.len() > 63 { out.truncate(63); }
    if out.is_empty() { "sandbox".into() } else { out }
}

async fn copy_contents(src: &Path, dst: &Path) -> AnyResult<()> {
    let status = tokio::process::Command::new("cp")
        .arg("-a")
        .arg("--reflink=auto")
        .arg(src.join("."))
        .arg(dst)
        .status().await.context("running cp for container rootfs")?;
    if !status.success() { bail!("copying container rootfs failed with {status}"); }
    Ok(())
}

fn kubelet_guest_source(source: &Path, pod_uid: &str) -> Option<PathBuf> {
    let root = PathBuf::from("/var/lib/kubelet/pods").join(pod_uid);
    for (host_base, guest_base) in [
        (root.join("volumes"), "/run/fluxvm/kubelet/volumes"),
        (root.join("volume-subpaths"), "/run/fluxvm/kubelet/volume-subpaths"),
    ] {
        if let Ok(rel) = source.strip_prefix(host_base) {
            return Some(Path::new(guest_base).join(rel));
        }
    }
    None
}

async fn stage_bind_mounts(
    spec: &mut Value,
    host_ctr: &Path,
    guest_ctr: &str,
    pod_uid: Option<&str>,
) -> AnyResult<()> {
    let Some(mounts) = spec.get_mut("mounts").and_then(Value::as_array_mut) else { return Ok(()); };
    for (idx, mount) in mounts.iter_mut().enumerate() {
        let is_bind = mount.get("type").and_then(Value::as_str) == Some("bind")
            || mount.get("options").and_then(Value::as_array).is_some_and(|o| o.iter().any(|v| v.as_str() == Some("bind") || v.as_str() == Some("rbind")));
        if !is_bind { continue; }
        let Some(source) = mount.get("source").and_then(Value::as_str).map(str::to_string) else { continue; };
        let source_path = PathBuf::from(&source);
        if !source_path.exists() { continue; }

        // Kubernetes PVC/CSI/emptyDir/projected volume sources are already
        // mounted by kubelet before runtime SyncPod. Keep them write-through
        // by translating only paths under this Pod's bounded volume roots.
        if let Some(uid) = pod_uid {
            if let Some(guest) = kubelet_guest_source(&source_path, uid) {
                mount["source"] = Value::String(guest.to_string_lossy().into_owned());
                continue;
            }
        }

        // Non-Pod-scoped bind sources stay snapshot-based. This avoids
        // exposing arbitrary hostPath content to the guest by accident.
        let host = host_ctr.join("mounts").join(idx.to_string());
        if source_path.is_dir() {
            tokio::fs::create_dir_all(&host).await?;
            copy_contents(&source_path, &host).await?;
        } else {
            if let Some(parent) = host.parent() { tokio::fs::create_dir_all(parent).await?; }
            tokio::fs::copy(&source_path, &host).await?;
        }
        mount["source"] = Value::String(format!("{guest_ctr}/mounts/{idx}"));
    }
    Ok(())
}

fn create_stdio_file(path: &Path) -> AnyResult<()> {
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    std::fs::File::create(path)
        .with_context(|| format!("creating stdio file {}", path.display()))?;
    Ok(())
}

/// Copy bytes from `source` to `destination`.
/// When `poll_eof` is true (guest log -> containerd), EOF is transient because
/// a virtiofs regular file can grow after a short read.
fn spawn_stdio_relay(source: PathBuf, destination: PathBuf, label: String, poll_eof: bool) {
    tokio::spawn(async move {
        let result: AnyResult<()> = async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            while tokio::time::Instant::now() < deadline {
                if source.exists() && destination.exists() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let mut src = tokio::fs::OpenOptions::new()
                .read(true)
                .open(&source)
                .await
                .with_context(|| format!("opening relay source {}", source.display()))?;
            let mut dst = tokio::fs::OpenOptions::new()
                .write(true)
                .open(&destination)
                .await
                .with_context(|| format!("opening relay destination {}", destination.display()))?;
            let mut buf = [0u8; 32 * 1024];
            let mut idle_rounds = 0u32;
            loop {
                let n = src.read(&mut buf).await?;
                if n == 0 {
                    if !poll_eof {
                        break;
                    }
                    idle_rounds += 1;
                    if idle_rounds > 12_000 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
                idle_rounds = 0;
                dst.write_all(&buf[..n]).await?;
                dst.flush().await?;
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            warn!("stdio relay {label} stopped: {e:#}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_keys_separate_init_and_exec() {
        assert_eq!(process_key("c1", None), "c1");
        assert_eq!(process_key("c1", Some("e1")), "c1\0e1");
        assert_ne!(process_key("c1", None), process_key("c1", Some("e1")));
    }

    #[test]
    fn kubelet_volume_source_maps_only_current_pod() {
        let uid = "11111111-2222-3333-4444-555555555555";
        let src = Path::new("/var/lib/kubelet/pods/11111111-2222-3333-4444-555555555555/volumes/kubernetes.io~empty-dir/data/file");
        assert_eq!(
            kubelet_guest_source(src, uid).unwrap(),
            PathBuf::from("/run/fluxvm/kubelet/volumes/kubernetes.io~empty-dir/data/file")
        );
        let other = Path::new("/var/lib/kubelet/pods/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/volumes/x");
        assert!(kubelet_guest_source(other, uid).is_none());
    }

    #[test]
    fn safe_names_are_filesystem_safe() {
        assert_eq!(safe_name("pod/one:abc"), "pod-one-abc");
        assert_eq!(safe_name(""), "sandbox");
    }

    #[tokio::test]
    async fn grouping_reads_kubernetes_sandbox_annotation() {
        let td = std::env::temp_dir().join(format!("fluxvm-shim-test-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&td).await;
        tokio::fs::create_dir_all(&td).await.unwrap();
        tokio::fs::write(td.join("config.json"), r#"{"annotations":{"io.kubernetes.cri.sandbox-id":"pod123"}}"#).await.unwrap();
        assert_eq!(pod_group_from_bundle(td.to_str().unwrap()).await.as_deref(), Some("pod123"));
        let _ = tokio::fs::remove_dir_all(td).await;
    }

    #[tokio::test]
    async fn stages_bind_mount_source() {
        let td = std::env::temp_dir().join(format!("fluxvm-bind-test-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&td).await;
        tokio::fs::create_dir_all(&td).await.unwrap();
        let source = td.join("source");
        tokio::fs::write(&source, "hello").await.unwrap();
        let mut spec = json!({"mounts":[{"type":"bind","source":source,"destination":"/etc/x","options":["bind","ro"]}]});
        stage_bind_mounts(&mut spec, &td.join("ctr"), "/run/fluxvm/pod/containers/c", None).await.unwrap();
        assert_eq!(spec["mounts"][0]["source"], "/run/fluxvm/pod/containers/c/mounts/0");
        assert_eq!(tokio::fs::read_to_string(td.join("ctr/mounts/0")).await.unwrap(), "hello");
        let _ = tokio::fs::remove_dir_all(td).await;
    }
}

#[tokio::main]
async fn main() {
    run::<Service>(RUNTIME_ID, None).await;
}
