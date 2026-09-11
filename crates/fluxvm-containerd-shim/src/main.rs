// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! containerd runtime-v2 shim for FluxVM secure containers.
//!
//! Secure Containers contract through Set 11:
//! * one FluxVM QEMU VM per containerd shim group / Kubernetes Pod sandbox;
//! * OCI snapshot rootfs is copied into the Pod's virtiofs share;
//! * Kubernetes Pod volumes are passed through write-through with Pod-scoped virtiofs exports;
//! * other bind mounts (ConfigMap/Secret/host inputs) remain snapshotted by default;
//! * process lifecycle is executed by `fluxvm-container-agent` over VSOCK 17778;
//! * stdin/stdout/stderr stream over authenticated VSOCK 17779;
//! * terminal init/exec processes use a real guest PTY with ResizePty;
//! * cgroup-v2 memory.events drive containerd TaskOOM events;
//! * stats expose CPU throttling and detailed memory accounting;
//! * Pod-scoped raw block volumes are hotplugged into QEMU over QMP;
//! * explicitly allowlisted VFIO PCI devices can be passed through for device-plugin workloads;
//! * Set 9 reference-counts device ownership, verifies IOMMU groups, and hot-unplugs unused devices;
//! * Set 10 enforces seccomp argument filters, process LSM labels, and cgroup-device BPF;
//! * Set 11 supervises explicit seccomp NOTIFY rules and reports guest security counters;
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
    api::{
        CloseIORequest, ConnectRequest, ConnectResponse, DeleteResponse, PidsRequest, PidsResponse,
        ProcessInfo, ResizePtyRequest, StatsRequest, StatsResponse, UpdateTaskRequest,
    },
    cgroups::metrics::{
        CPUStat, CPUUsage, MemoryEntry, MemoryOomControl, MemoryStat, Metrics, PidsStat, Throttle,
    },
    events::task::{
        TaskCreate, TaskDelete, TaskExecAdded, TaskExecStarted, TaskExit, TaskIO, TaskOOM,
        TaskPaused, TaskResumed, TaskStart,
    },
    protobuf::{EnumOrUnknown, MessageDyn},
    shim_async::Task,
    ttrpc::{self, r#async::TtrpcContext},
};
use fluxvm_container_protocol::{
    ContainerIo, ContainerNetworkPolicy, ContainerNetworkRule, ContainerRequest, ContainerResponse,
    ContainerStats, ContainerStatus, IoStreamAttach, IoStreamKind, ResourceLimits,
};
use fluxvm_core::model::{VmRecord, VmStatus};
use fluxvm_guest_protocol::{AgentRequest, AgentResponse};
use log::{info, warn};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::{
        Mutex, RwLock,
        mpsc::{Receiver, Sender, channel},
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
    cni_strict_multi_interface: bool,
    streaming_stdio: bool,
    recovery_enabled: bool,
    oom_poll_ms: u64,
    device_passthrough: bool,
    block_allow_prefixes: Vec<PathBuf>,
    vfio_allow: Vec<String>,
    vfio_require_iommu_group: bool,
    guest_device_allow: Vec<String>,
    device_unplug_timeout_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Default)]
struct PodPolicyWire {
    #[serde(default)]
    schema_version: u32,
    #[serde(default)]
    default_deny: bool,
    #[serde(default)]
    audit_mode: bool,
    #[serde(default)]
    allow_addresses: Vec<IpAddr>,
    #[serde(default)]
    deny_addresses: Vec<IpAddr>,
    #[serde(default)]
    egress_isolated: bool,
    #[serde(default)]
    ingress_isolated: bool,
    #[serde(default)]
    rules: Vec<PodRuleWire>,
}
#[derive(Clone, Debug, Deserialize)]
struct PodRuleWire {
    direction: String,
    cidr: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            api_url: std::env::var("FLUXVM_API_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:7788".into()),
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
            vcpus: std::env::var("FLUXVM_CONTAINER_VCPUS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(2),
            memory_mib: std::env::var("FLUXVM_CONTAINER_MEMORY_MIB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1024),
            vm_overhead_mib: std::env::var("FLUXVM_CONTAINER_VM_OVERHEAD_MIB")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(256),
            boot_timeout_secs: std::env::var("FLUXVM_CONTAINER_BOOT_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                // Secure-container guest images often spend >90s reaching
                // multi-user + fluxvm-guest-agent (cloud-init, virtiofs
                // mounts, networkd). 90s left pods stuck in ContainerCreating
                // with "timed out waiting for FluxVM sandbox" despite a
                // healthy later vsock ping.
                .unwrap_or(300),
            cni_interface: std::env::var("FLUXVM_CONTAINER_CNI_INTERFACE")
                .unwrap_or_else(|_| "eth0".into()),
            cni_enabled: std::env::var("FLUXVM_CONTAINER_CNI")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off"))
                .unwrap_or(true),
            cni_strict_multi_interface: std::env::var(
                "FLUXVM_CONTAINER_CNI_STRICT_MULTI_INTERFACE",
            )
            .ok()
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off"))
            .unwrap_or(true),
            streaming_stdio: std::env::var("FLUXVM_CONTAINER_STREAMING_STDIO")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off"))
                .unwrap_or(true),
            recovery_enabled: std::env::var("FLUXVM_CONTAINER_RECOVER")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off"))
                .unwrap_or(true),
            oom_poll_ms: std::env::var("FLUXVM_CONTAINER_OOM_POLL_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1000)
                .clamp(100, 60_000),
            device_passthrough: std::env::var("FLUXVM_CONTAINER_DEVICE_PASSTHROUGH")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off"))
                .unwrap_or(true),
            block_allow_prefixes: std::env::var("FLUXVM_CONTAINER_BLOCK_ALLOW_PREFIXES")
                .ok()
                .map(|v| {
                    v.split(':')
                        .filter(|s| !s.is_empty())
                        .map(PathBuf::from)
                        .collect()
                })
                .unwrap_or_default(),
            vfio_allow: std::env::var("FLUXVM_CONTAINER_VFIO_ALLOW")
                .ok()
                .map(|v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_ascii_lowercase())
                        .collect()
                })
                .unwrap_or_default(),
            vfio_require_iommu_group: std::env::var("FLUXVM_CONTAINER_VFIO_REQUIRE_IOMMU_GROUP")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off"))
                .unwrap_or(true),
            guest_device_allow: std::env::var("FLUXVM_CONTAINER_GUEST_DEVICE_ALLOW")
                .ok()
                .map(|v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| s.starts_with("/dev/") && !s.contains(".."))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            device_unplug_timeout_secs: std::env::var(
                "FLUXVM_CONTAINER_DEVICE_UNPLUG_TIMEOUT_SECS",
            )
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10)
            .clamp(1, 120),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TaskMeta {
    bundle: String,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    pid: u32,
    /// Host-side virtiofs stdio directory for this init/exec process.
    #[serde(default)]
    io_dir: Option<PathBuf>,
    #[serde(default)]
    streaming: bool,
    /// Last guest memory.events oom_kill counter published to containerd.
    /// Persisted so a replacement shim can surface OOMs that occurred while
    /// the previous shim was unavailable.
    #[serde(default)]
    oom_kill_seen: u64,
    /// Set 9 device attachment keys claimed by this container. Empty for
    /// legacy Set 8 journals; those attachments stay pinned until sandbox delete.
    #[serde(default)]
    device_claims: Vec<String>,
    /// Set 9S: stable in-guest container identity for correlating a guest
    /// LSM denial event back to this container. `0` when the guest kernel
    /// lacks Set 9S support (see ContainerResponse::Created).
    #[serde(default)]
    container_identity: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum DeviceAttachment {
    Block {
        host_path: PathBuf,
        serial: String,
        node_name: String,
        device_id: String,
        #[serde(default)]
        host_major: Option<u64>,
        #[serde(default)]
        host_minor: Option<u64>,
        /// None means a Set 8/legacy attachment whose ownership is unknown;
        /// it is deliberately pinned until the whole sandbox is destroyed.
        #[serde(default)]
        owners: Option<Vec<String>>,
    },
    Vfio {
        bdf: String,
        guest_path: String,
        device_id: String,
        #[serde(default)]
        iommu_group: Option<u32>,
        #[serde(default)]
        owners: Option<Vec<String>>,
    },
}

impl DeviceAttachment {
    fn key(&self) -> String {
        match self {
            Self::Block { host_path, .. } => format!("block:{}", host_path.display()),
            Self::Vfio { bdf, .. } => format!("vfio:{bdf}"),
        }
    }

    fn device_id(&self) -> &str {
        match self {
            Self::Block { device_id, .. } | Self::Vfio { device_id, .. } => device_id,
        }
    }

    fn owners(&self) -> Option<&Vec<String>> {
        match self {
            Self::Block { owners, .. } | Self::Vfio { owners, .. } => owners.as_ref(),
        }
    }

    fn owners_mut(&mut self) -> Option<&mut Vec<String>> {
        match self {
            Self::Block { owners, .. } | Self::Vfio { owners, .. } => owners.as_mut(),
        }
    }

    fn add_owner(&mut self, owner: &str) -> bool {
        let Some(owners) = self.owners_mut() else {
            return false;
        };
        if owners.iter().any(|v| v == owner) {
            return false;
        }
        owners.push(owner.to_string());
        owners.sort();
        true
    }

    fn remove_owner(&mut self, owner: &str) -> bool {
        let Some(owners) = self.owners_mut() else {
            return false;
        };
        let before = owners.len();
        owners.retain(|v| v != owner);
        owners.len() != before
    }

    fn is_releasable(&self) -> bool {
        self.owners().is_some_and(Vec::is_empty)
    }
}

#[derive(Clone, Debug)]
struct Sandbox {
    vm: VmRecord,
    share_dir: PathBuf,
    cni: Option<CniBridge>,
    kubelet_mounts: Vec<(String, String)>,
    devices: Vec<DeviceAttachment>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum CniFamily {
    Ipv4,
    Ipv6,
}

impl CniFamily {
    fn ip_flag(self) -> &'static str {
        match self {
            Self::Ipv4 => "-4",
            Self::Ipv6 => "-6",
        }
    }
    fn max_prefix(self) -> u8 {
        match self {
            Self::Ipv4 => 32,
            Self::Ipv6 => 128,
        }
    }
    fn matches(self, addr: IpAddr) -> bool {
        matches!(
            (self, addr),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CniAddress {
    family: CniFamily,
    address: IpAddr,
    prefix_len: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CniRoute {
    family: CniFamily,
    destination: Option<(IpAddr, u8)>, // None = default
    gateway: Option<IpAddr>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CniNetwork {
    addresses: Vec<CniAddress>,
    mac: String,
    routes: Vec<CniRoute>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

const RUNTIME_STATE_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SandboxJournal {
    vm_id: String,
    vm_name: String,
    #[serde(default)]
    ready: bool,
    share_dir: PathBuf,
    #[serde(default)]
    cni: Option<CniBridge>,
    #[serde(default)]
    kubelet_mounts: Vec<(String, String)>,
    #[serde(default)]
    devices: Vec<DeviceAttachment>,
}

impl SandboxJournal {
    fn from_sandbox(sandbox: &Sandbox) -> Self {
        Self {
            vm_id: sandbox.vm.id.to_string(),
            vm_name: sandbox.vm.name.clone(),
            ready: true,
            share_dir: sandbox.share_dir.clone(),
            cni: sandbox.cni.clone(),
            kubelet_mounts: sandbox.kubelet_mounts.clone(),
            devices: sandbox.devices.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct DeviceStats {
    #[serde(default)]
    attach_total: u64,
    #[serde(default)]
    detach_total: u64,
    #[serde(default)]
    unplug_failures: u64,
    #[serde(default)]
    recovery_checks: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RuntimeStateJournal {
    version: u32,
    #[serde(default)]
    sandbox: Option<SandboxJournal>,
    #[serde(default)]
    tasks: HashMap<String, TaskMeta>,
    #[serde(default)]
    execs: HashMap<String, TaskMeta>,
    #[serde(default)]
    device_stats: DeviceStats,
}

impl Default for RuntimeStateJournal {
    fn default() -> Self {
        Self {
            version: RUNTIME_STATE_VERSION,
            sandbox: None,
            tasks: HashMap::new(),
            execs: HashMap::new(),
            device_stats: DeviceStats::default(),
        }
    }
}

fn runtime_state_root(cfg: &RuntimeConfig, namespace: &str, group: &str) -> PathBuf {
    cfg.state_dir.join(namespace).join(group)
}

fn runtime_state_path(cfg: &RuntimeConfig, namespace: &str, group: &str) -> PathBuf {
    runtime_state_root(cfg, namespace, group).join("runtime-state.json")
}

async fn load_runtime_state(
    cfg: &RuntimeConfig,
    namespace: &str,
    group: &str,
) -> AnyResult<RuntimeStateJournal> {
    let path = runtime_state_path(cfg, namespace, group);
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RuntimeStateJournal::default());
        }
        Err(e) => {
            return Err(e).with_context(|| format!("reading recovery journal {}", path.display()));
        }
    };
    let state: RuntimeStateJournal = serde_json::from_slice(&bytes)
        .with_context(|| format!("decoding recovery journal {}", path.display()))?;
    if state.version != RUNTIME_STATE_VERSION {
        bail!(
            "unsupported recovery journal version {} (expected {})",
            state.version,
            RUNTIME_STATE_VERSION
        );
    }
    Ok(state)
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
    oom_monitors: Arc<Mutex<HashSet<String>>>,
    stream_pending: Arc<Mutex<HashMap<String, usize>>>,
    journal_sandbox: Arc<Mutex<Option<SandboxJournal>>>,
    journal_lock: Arc<Mutex<()>>,
    recovery_error: Arc<Mutex<Option<String>>>,
    /// Serializes QMP attach/detach and journal ownership transitions.
    device_op_lock: Arc<Mutex<()>>,
    device_stats: Arc<Mutex<DeviceStats>>,
}

#[async_trait]
impl Shim for Service {
    type T = Service;

    async fn new(_runtime_id: &str, args: &Flags, _config: &mut Config) -> Self {
        // containerd's `shim start` usually omits `-bundle` and uses the
        // container bundle as cwd. Without reading cwd, grouping falls back to
        // `args.id` and every Pod container gets its own shim/socket — then
        // Create cold-starts a second VM against `/proc/<guest-pid>/ns/net`.
        let bundle = if args.bundle.is_empty() {
            std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            args.bundle.clone()
        };
        let group = pod_group_from_bundle(&bundle)
            .await
            .unwrap_or_else(|| args.id.clone());
        let (event_tx, event_rx) = channel(128);
        let cfg = RuntimeConfig::default();
        let (recovered, recovery_error) = if cfg.recovery_enabled {
            match load_runtime_state(&cfg, &args.namespace, &group).await {
                Ok(state) => (state, None),
                Err(e) => (RuntimeStateJournal::default(), Some(format!("{e:#}"))),
            }
        } else {
            (RuntimeStateJournal::default(), None)
        };
        Self {
            exit: Arc::new(ExitSignal::default()),
            namespace: args.namespace.clone(),
            group,
            cfg,
            http: Client::new(),
            sandbox: Arc::new(Mutex::new(None)),
            tasks: Arc::new(RwLock::new(recovered.tasks)),
            execs: Arc::new(RwLock::new(recovered.execs)),
            event_tx,
            event_rx: Arc::new(Mutex::new(Some(event_rx))),
            exit_events: Arc::new(Mutex::new(HashSet::new())),
            oom_monitors: Arc::new(Mutex::new(HashSet::new())),
            stream_pending: Arc::new(Mutex::new(HashMap::new())),
            journal_sandbox: Arc::new(Mutex::new(recovered.sandbox)),
            journal_lock: Arc::new(Mutex::new(())),
            recovery_error: Arc::new(Mutex::new(recovery_error)),
            device_op_lock: Arc::new(Mutex::new(())),
            device_stats: Arc::new(Mutex::new(recovered.device_stats)),
        }
    }

    async fn start_shim(&mut self, opts: StartOpts) -> Result<String, Error> {
        // Ensure the child shim inherits TTRPC_ADDRESS (containerd ≥ 2.3 may
        // omit it from the parent environment when using BootstrapParams).
        let ttrpc = opts.ttrpc_address.clone();
        let vars = vec![("TTRPC_ADDRESS", ttrpc.as_str())];
        let address = spawn(opts, &self.group, vars).await?;
        Ok(address)
    }

    async fn delete_shim(&mut self) -> Result<DeleteResponse, Error> {
        self.destroy_sandbox()
            .await
            .map_err(|e| Error::Other(format!("destroying secure-container sandbox: {e:#}")))?;
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
    async fn api(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> AnyResult<reqwest::Response> {
        let url = format!("{}{}", self.cfg.api_url.trim_end_matches('/'), path);
        let mut req = self.http.request(method, &url);
        if let Some(token) = &self.cfg.api_token {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("calling FluxVM {url}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            bail!("FluxVM API {url} returned {status}: {text}");
        }
        Ok(resp)
    }

    async fn persist_runtime_state(&self) -> AnyResult<()> {
        if !self.cfg.recovery_enabled {
            return Ok(());
        }
        let _guard = self.journal_lock.lock().await;
        let state = RuntimeStateJournal {
            version: RUNTIME_STATE_VERSION,
            sandbox: self.journal_sandbox.lock().await.clone(),
            tasks: self.tasks.read().await.clone(),
            execs: self.execs.read().await.clone(),
            device_stats: self.device_stats.lock().await.clone(),
        };
        let root = runtime_state_root(&self.cfg, &self.namespace, &self.group);
        tokio::fs::create_dir_all(&root).await?;
        let path = runtime_state_path(&self.cfg, &self.namespace, &self.group);
        let tmp = path.with_extension(format!("json.tmp-{}", std::process::id()));
        tokio::fs::write(&tmp, serde_json::to_vec_pretty(&state)?).await?;
        tokio::fs::rename(&tmp, &path)
            .await
            .with_context(|| format!("committing recovery journal {}", path.display()))?;
        Ok(())
    }

    async fn clear_runtime_state_file(&self) {
        let _guard = self.journal_lock.lock().await;
        let path = runtime_state_path(&self.cfg, &self.namespace, &self.group);
        let _ = tokio::fs::remove_file(path).await;
    }

    async fn recovery_vm(&self, id: &str) -> AnyResult<Option<VmRecord>> {
        let url = format!("{}/v1/vms/{id}", self.cfg.api_url.trim_end_matches('/'));
        let mut req = self.http.get(&url);
        if let Some(token) = &self.cfg.api_token {
            req = req.bearer_auth(token);
        }
        let response = req
            .send()
            .await
            .with_context(|| format!("recovering FluxVM VM {id}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            bail!("FluxVM recovery GET {url} returned {status}: {body}");
        }
        Ok(Some(
            response
                .json()
                .await
                .context("decoding recovered FluxVM VM")?,
        ))
    }

    async fn recovery_cni_ready(&self, cni: &CniBridge) -> bool {
        if !cni.netns_mount.exists()
            || !Path::new("/sys/class/net").join(&cni.host_bridge).exists()
            || !Path::new("/sys/class/net").join(&cni.host_veth).exists()
        {
            return false;
        }
        for iface in [&cni.cni_bridge, &cni.cni_veth, &cni.interface] {
            let mut args = vec![
                "netns".to_string(),
                "exec".to_string(),
                cni.netns_alias.clone(),
                "ip".to_string(),
                "link".to_string(),
                "show".to_string(),
                iface.clone(),
            ];
            let ok = tokio::process::Command::new("ip")
                .args(args.drain(..))
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !ok {
                return false;
            }
        }
        true
    }

    async fn attach_recovered_streams(&self, vm: &VmRecord) {
        if !self.cfg.streaming_stdio {
            return;
        }
        let tasks: Vec<(String, TaskMeta)> = self
            .tasks
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (id, meta) in tasks {
            if !meta.streaming {
                continue;
            }
            if let Err(e) = self
                .attach_stream_relays(
                    vm,
                    &id,
                    None,
                    &meta.stdin,
                    &meta.stdout,
                    &meta.stderr,
                    meta.terminal,
                )
                .await
            {
                warn!("recovery stdio attach failed for {id}: {e:#}");
            }
        }
        let execs: Vec<(String, TaskMeta)> = self
            .execs
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (key, meta) in execs {
            if !meta.streaming {
                continue;
            }
            let Some((id, exec_id)) = key.split_once('\0') else {
                continue;
            };
            if let Err(e) = self
                .attach_stream_relays(
                    vm,
                    id,
                    Some(exec_id),
                    &meta.stdin,
                    &meta.stdout,
                    &meta.stderr,
                    meta.terminal,
                )
                .await
            {
                warn!("recovery exec stdio attach failed for {id}/{exec_id}: {e:#}");
            }
        }
    }

    async fn restore_recovered_processes(&self, vm: &VmRecord) -> AnyResult<()> {
        let tasks: Vec<(String, TaskMeta)> = self
            .tasks
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (id, meta) in tasks {
            let response = self
                .call_agent_direct(
                    vm,
                    ContainerRequest::State {
                        id: id.clone(),
                        exec_id: None,
                    },
                )
                .await
                .with_context(|| format!("checking recovered task {id}"))?;
            match response {
                ContainerResponse::State {
                    status: ContainerStatus::Running | ContainerStatus::Paused,
                    pid,
                    ..
                } => {
                    self.spawn_exit_watch(
                        vm.clone(),
                        id.clone(),
                        None,
                        if pid == 0 { meta.pid } else { pid },
                    );
                }
                ContainerResponse::State {
                    status: ContainerStatus::Created,
                    ..
                } => {}
                ContainerResponse::State {
                    status: ContainerStatus::Stopped,
                    exit_code,
                    exited_at_unix_nano,
                    pid,
                    ..
                } => {
                    if let (Some(code), Some(at)) = (exit_code, exited_at_unix_nano) {
                        self.publish_exit_once(id.clone(), None, pid, code, at)
                            .await;
                    }
                }
                other => bail!("unexpected recovered task state: {other:?}"),
            }
            self.spawn_oom_watch(vm.clone(), id);
        }

        let execs: Vec<(String, TaskMeta)> = self
            .execs
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (key, meta) in execs {
            let Some((id, exec_id)) = key.split_once('\0') else {
                continue;
            };
            let response = self
                .call_agent_direct(
                    vm,
                    ContainerRequest::State {
                        id: id.to_string(),
                        exec_id: Some(exec_id.to_string()),
                    },
                )
                .await
                .with_context(|| format!("checking recovered exec {id}/{exec_id}"))?;
            match response {
                ContainerResponse::State {
                    status: ContainerStatus::Running | ContainerStatus::Paused,
                    pid,
                    ..
                } => {
                    self.spawn_exit_watch(
                        vm.clone(),
                        id.to_string(),
                        Some(exec_id.to_string()),
                        if pid == 0 { meta.pid } else { pid },
                    );
                }
                ContainerResponse::State {
                    status: ContainerStatus::Created,
                    ..
                } => {}
                ContainerResponse::State {
                    status: ContainerStatus::Stopped,
                    exit_code,
                    exited_at_unix_nano,
                    pid,
                    ..
                } => {
                    if let (Some(code), Some(at)) = (exit_code, exited_at_unix_nano) {
                        self.publish_exit_once(
                            id.to_string(),
                            Some(exec_id.to_string()),
                            pid,
                            code,
                            at,
                        )
                        .await;
                    }
                }
                other => bail!("unexpected recovered exec state: {other:?}"),
            }
        }
        self.attach_recovered_streams(vm).await;
        Ok(())
    }

    async fn recover_sandbox_from_journal(&self, journal: &SandboxJournal) -> AnyResult<Sandbox> {
        if !journal.ready {
            bail!("recovery journal records a provisional, not-ready sandbox");
        }
        let started = tokio::time::Instant::now();
        let mut vm = self
            .recovery_vm(&journal.vm_id)
            .await?
            .with_context(|| format!("journal-owned VM {} no longer exists", journal.vm_id))?;
        if vm.name != journal.vm_name {
            bail!(
                "journal VM identity mismatch: expected name {:?}, got {:?}",
                journal.vm_name,
                vm.name
            );
        }
        if let Some(cni) = journal.cni.as_ref() {
            if !self.recovery_cni_ready(cni).await {
                bail!("journal-owned CNI bridge/netns topology is incomplete");
            }
        }
        if vm.status == VmStatus::Paused {
            self.api(Method::POST, &format!("/v1/vms/{}/resume", vm.id), None)
                .await?;
            vm = self
                .api(Method::GET, &format!("/v1/vms/{}", vm.id), None)
                .await?
                .json()
                .await?;
        }
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
                    "journal-owned sandbox VM is failed: {}",
                    vm.error.as_deref().unwrap_or("unknown")
                );
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("timed out recovering journal-owned VM {}", vm.id);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            vm = self
                .api(Method::GET, &format!("/v1/vms/{}", vm.id), None)
                .await?
                .json()
                .await?;
        }
        self.ensure_guest_shares_mounted(&vm, &journal.kubelet_mounts)
            .await?;
        if fluxvm_container_client::ping(&vm, Duration::from_millis(750))
            .await
            .is_err()
        {
            if self.tasks.read().await.is_empty() && self.execs.read().await.is_empty() {
                self.bootstrap_container_agent(&vm).await?;
            } else {
                bail!("container agent unavailable while live task metadata exists");
            }
        }
        self.reconcile_device_attachments(&vm).await?;
        let recovered_devices = self
            .journal_sandbox
            .lock()
            .await
            .as_ref()
            .map(|j| j.devices.clone())
            .unwrap_or_default();
        self.restore_recovered_processes(&vm).await?;
        info!(
            "secure-container sandbox recovered vm={} group={} elapsed_ms={}",
            vm.id,
            self.group,
            started.elapsed().as_millis()
        );
        Ok(Sandbox {
            vm,
            share_dir: journal.share_dir.clone(),
            cni: journal.cni.clone(),
            kubelet_mounts: journal.kubelet_mounts.clone(),
            devices: recovered_devices,
        })
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

        if let Some(error) = self.recovery_error.lock().await.clone() {
            bail!(
                "secure-container recovery journal is unreadable or unsupported: {error};                  refusing a cold start that could duplicate the Pod VM"
            );
        }

        if self.cfg.recovery_enabled {
            if let Some(journal) = self.journal_sandbox.lock().await.clone() {
                let has_processes =
                    !self.tasks.read().await.is_empty() || !self.execs.read().await.is_empty();

                if journal.ready {
                    match self.recover_sandbox_from_journal(&journal).await {
                        Ok(recovered) => {
                            let vm = recovered.vm.clone();
                            *guard = Some(recovered);
                            return Ok(vm);
                        }
                        Err(e) if has_processes => {
                            bail!(
                                "failed to recover live secure-container sandbox: {e:#};                                  refusing to cold-create a duplicate VM"
                            );
                        }
                        Err(e) => {
                            warn!(
                                "discarding stale empty sandbox journal after recovery failure: {e:#}"
                            );
                        }
                    }
                } else if has_processes {
                    bail!(
                        "recovery journal owns provisional VM {} while task metadata exists;                          refusing duplicate sandbox creation",
                        journal.vm_id
                    );
                }

                // Empty/provisional ownership can be reclaimed. The VM ID was
                // persisted as soon as create returned, so even a crash during
                // guest boot is cleaned up before a new sandbox is attempted.
                if let Ok(Some(vm)) = self.recovery_vm(&journal.vm_id).await {
                    let _ = self
                        .api(Method::DELETE, &format!("/v1/vms/{}", vm.id), None)
                        .await;
                }
                if let Some(cni) = journal.cni.as_ref() {
                    cleanup_cni_bridge(cni).await;
                }
                *self.journal_sandbox.lock().await = None;
                self.clear_runtime_state_file().await;
            }
        }

        let cold_started = tokio::time::Instant::now();

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
                if self.cfg.cni_strict_multi_interface {
                    let extras =
                        detect_additional_cni_interfaces(path, &self.cfg.cni_interface).await?;
                    if !extras.is_empty() {
                        bail!(
                            "CNI namespace has additional routable interfaces {:?};                              FluxVM Set 6 refuses silent partial Multus/multi-interface configuration.                              Set FLUXVM_CONTAINER_CNI_STRICT_MULTI_INTERFACE=0 only for controlled testing",
                            extras
                        );
                    }
                }
                Some(
                    prepare_cni_l2(&self.group, path, &self.cfg.cni_interface)
                        .await
                        .map_err(|e| {
                            let msg = format!("preparing CNI L2 attachment: {e:#}");
                            warn!("{msg}");
                            if let Ok(mut f) = std::fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("/tmp/fluxvm-shim-errors.log")
                            {
                                use std::io::Write;
                                let _ = writeln!(f, "{msg}");
                            }
                            anyhow::anyhow!(msg)
                        })?,
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
                    (
                        pod_root.join("volume-subpaths"),
                        "/run/fluxvm/kubelet/volume-subpaths",
                    ),
                ] {
                    tokio::fs::create_dir_all(&host).await.with_context(|| {
                        format!("preparing Pod volume export {}", host.display())
                    })?;
                    shared_folders.push(json!({
                        "host_path": host,
                        "guest_path": guest,
                        "read_only": false
                    }));
                    kubelet_mounts
                        .push((format!("fs{}", shared_folders.len() - 1), guest.to_string()));
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

        let mut vm: VmRecord = match self.api(Method::POST, "/v1/vms", Some(create)).await {
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

        if self.cfg.recovery_enabled {
            let provisional = SandboxJournal {
                vm_id: vm.id.to_string(),
                vm_name: vm.name.clone(),
                ready: false,
                share_dir: share_dir.clone(),
                cni: cni.clone(),
                kubelet_mounts: kubelet_mounts.clone(),
                devices: Vec::new(),
            };
            *self.journal_sandbox.lock().await = Some(provisional);
            if let Err(e) = self.persist_runtime_state().await {
                let _ = self
                    .api(Method::DELETE, &format!("/v1/vms/{}", vm.id), None)
                    .await;
                if let Some(cni) = cni.as_ref() {
                    cleanup_cni_bridge(cni).await;
                }
                *self.journal_sandbox.lock().await = None;
                return Err(e).context("persisting provisional VM ownership");
            }
        }

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
            self.ensure_guest_shares_mounted(&vm, &kubelet_mounts)
                .await?;

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
            *self.journal_sandbox.lock().await = None;
            self.clear_runtime_state_file().await;
            return Err(e);
        }

        let sandbox = Sandbox {
            vm: vm.clone(),
            share_dir,
            cni,
            kubelet_mounts,
            devices: Vec::new(),
        };
        *self.journal_sandbox.lock().await = Some(SandboxJournal::from_sandbox(&sandbox));
        *guard = Some(sandbox);
        self.persist_runtime_state().await?;
        info!(
            "secure-container sandbox cold-started vm={} group={} elapsed_ms={}",
            vm.id,
            self.group,
            cold_started.elapsed().as_millis()
        );
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
            AgentResponse::Exec { exit_code: 0, .. } => Ok(()),
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
    async fn ensure_guest_shares_mounted(
        &self,
        vm: &VmRecord,
        extras: &[(String, String)],
    ) -> AnyResult<()> {
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
                AgentRequest::Exec {
                    command: probe.clone(),
                    timeout_seconds: Some(10),
                },
                Duration::from_secs(15),
            )
            .await?
            {
                AgentResponse::Exec { exit_code: 0, .. } => return Ok(()),
                AgentResponse::Exec {
                    exit_code,
                    stdout,
                    stderr,
                } => {
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
        if fluxvm_container_client::ping(vm, Duration::from_millis(300))
            .await
            .is_ok()
        {
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
        )
        .await?
        {
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
            if fluxvm_container_client::ping(vm, Duration::from_millis(500))
                .await
                .is_ok()
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("container agent did not become ready");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn qmp_execute(
        &self,
        vm: &VmRecord,
        command: &str,
        args: Option<Value>,
    ) -> AnyResult<Value> {
        let socket = vm.workspace.join("qmp.sock");
        let stream = tokio::time::timeout(Duration::from_secs(10), UnixStream::connect(&socket))
            .await
            .context("timing out connecting QMP")??;
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            bail!("QMP closed before greeting");
        }
        let greeting: Value = serde_json::from_str(&line).context("decoding QMP greeting")?;
        if greeting.get("QMP").is_none() {
            bail!("invalid QMP greeting from {}", socket.display());
        }
        write_half
            .write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
            .await?;
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            bail!("QMP closed during capabilities");
        }
        let caps: Value = serde_json::from_str(&line)?;
        if let Some(e) = caps.get("error") {
            bail!("QMP capabilities failed: {e}");
        }
        let mut request = json!({"execute": command});
        if let Some(args) = args {
            request["arguments"] = args;
        }
        write_half
            .write_all(format!("{request}\n").as_bytes())
            .await?;
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                bail!("QMP closed while waiting for {command}");
            }
            let reply: Value = serde_json::from_str(&line)?;
            if reply.get("event").is_some() {
                continue;
            }
            if let Some(e) = reply.get("error") {
                bail!("QMP {command} failed: {e}");
            }
            return Ok(reply.get("return").cloned().unwrap_or(Value::Null));
        }
    }

    async fn qmp_device_del_wait(&self, vm: &VmRecord, device_id: &str) -> AnyResult<()> {
        let socket = vm.workspace.join("qmp.sock");
        let stream = tokio::time::timeout(Duration::from_secs(10), UnixStream::connect(&socket))
            .await
            .context("timing out connecting QMP for device_del")??;
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            bail!("QMP closed before greeting");
        }
        let greeting: Value = serde_json::from_str(&line).context("decoding QMP greeting")?;
        if greeting.get("QMP").is_none() {
            bail!("invalid QMP greeting from {}", socket.display());
        }
        write_half
            .write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
            .await?;
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            bail!("QMP closed during capabilities");
        }
        let caps: Value = serde_json::from_str(&line)?;
        if let Some(e) = caps.get("error") {
            bail!("QMP capabilities failed: {e}");
        }

        let request_id = format!("fluxvm-device-del-{device_id}");
        write_half
            .write_all(
                format!(
                    "{}\n",
                    json!({"execute":"device_del","arguments":{"id":device_id},"id":request_id})
                )
                .as_bytes(),
            )
            .await?;

        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(self.cfg.device_unplug_timeout_secs);
        let mut accepted = false;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                bail!("timed out waiting for QEMU DEVICE_DELETED for {device_id}");
            }
            line.clear();
            let read = tokio::time::timeout(remaining, reader.read_line(&mut line))
                .await
                .context("timed out reading QMP device_del event")??;
            if read == 0 {
                bail!("QMP closed while waiting for device removal {device_id}");
            }
            let reply: Value = serde_json::from_str(&line)?;
            if reply.get("id").and_then(Value::as_str) == Some(request_id.as_str()) {
                if let Some(e) = reply.get("error") {
                    bail!("QMP device_del {device_id} failed: {e}");
                }
                accepted = true;
                continue;
            }
            match reply.get("event").and_then(Value::as_str) {
                Some("DEVICE_DELETED")
                    if reply.pointer("/data/device").and_then(Value::as_str) == Some(device_id)
                        || reply
                            .pointer("/data/path")
                            .and_then(Value::as_str)
                            .is_some_and(|path| path.ends_with(&format!("/{device_id}"))) =>
                {
                    if !accepted {
                        warn!(
                            "QEMU reported DEVICE_DELETED for {device_id} before command response"
                        );
                    }
                    return Ok(());
                }
                Some("DEVICE_UNPLUG_GUEST_ERROR")
                    if reply.pointer("/data/device").and_then(Value::as_str) == Some(device_id)
                        || reply
                            .pointer("/data/path")
                            .and_then(Value::as_str)
                            .is_some_and(|path| path.ends_with(&format!("/{device_id}"))) =>
                {
                    bail!("guest rejected hot-unplug of QEMU device {device_id}");
                }
                _ => {}
            }
        }
    }

    async fn qmp_device_present(&self, vm: &VmRecord, device_id: &str) -> bool {
        self.qmp_execute(
            vm,
            "qom-list",
            Some(json!({"path": format!("/machine/peripheral/{device_id}")})),
        )
        .await
        .is_ok()
    }

    fn canonical_block_source(&self, source: &Path, pod_uid: Option<&str>) -> AnyResult<PathBuf> {
        // Kubernetes raw-block Pod paths are intentionally symlinks into the
        // plugin's global device map. Authorize the kubelet-owned *link path*
        // first, then canonicalize to the actual host block device. Checking
        // the canonical target against volumeDevices would incorrectly reject
        // every valid CSI raw-block mapping.
        let mut allowed_origin = false;
        if let Some(uid) = pod_uid {
            let pod_devices = PathBuf::from("/var/lib/kubelet/pods")
                .join(uid)
                .join("volumeDevices");
            allowed_origin |= source.starts_with(&pod_devices);
        }
        allowed_origin |= self
            .cfg
            .block_allow_prefixes
            .iter()
            .any(|p| source.starts_with(p));
        if !allowed_origin {
            bail!(
                "raw block source {} is outside the Pod volumeDevices tree and FLUXVM_CONTAINER_BLOCK_ALLOW_PREFIXES",
                source.display()
            );
        }
        let canonical = std::fs::canonicalize(source)
            .with_context(|| format!("canonicalizing raw block source {}", source.display()))?;
        let meta = std::fs::metadata(&canonical)
            .with_context(|| format!("stat raw block source {}", canonical.display()))?;
        if !meta.file_type().is_block_device() {
            bail!(
                "{} resolves to {}, which is not a block device",
                source.display(),
                canonical.display()
            );
        }
        Ok(canonical)
    }

    fn pod_block_source_for_rdev(
        &self,
        pod_uid: Option<&str>,
        major: u64,
        minor: u64,
    ) -> Option<PathBuf> {
        let uid = pod_uid?;
        let root = PathBuf::from("/var/lib/kubelet/pods")
            .join(uid)
            .join("volumeDevices");
        find_block_rdev_under(&root, major, minor, 8)
    }

    fn guest_driver_companion_allowed(&self, path: &str) -> bool {
        let builtin = matches!(
            path,
            "/dev/nvidiactl"
                | "/dev/nvidia-uvm"
                | "/dev/nvidia-uvm-tools"
                | "/dev/nvidia-modeset"
                | "/dev/kfd"
        );
        let nvidia_cap = path
            .strip_prefix("/dev/nvidia-caps/nvidia-cap")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()));
        builtin || nvidia_cap || self.cfg.guest_device_allow.iter().any(|v| v == path)
    }

    fn validate_vfio_group(&self, bdf: &str) -> AnyResult<Option<u32>> {
        if !valid_pci_bdf(bdf) {
            bail!("invalid PCI BDF {bdf:?}");
        }
        if !self.cfg.vfio_allow.iter().any(|v| v == bdf) {
            bail!("VFIO device {bdf} is not in FLUXVM_CONTAINER_VFIO_ALLOW");
        }
        let driver = pci_driver_name(bdf);
        if driver.as_deref() != Some("vfio-pci") {
            bail!(
                "VFIO device {bdf} must already be bound to vfio-pci (found {:?})",
                driver
            );
        }
        let group = iommu_group_info(bdf)?;
        if self.cfg.vfio_require_iommu_group {
            let (group_id, members) = group.as_ref().with_context(|| {
                format!("VFIO device {bdf} has no IOMMU group; disable FLUXVM_CONTAINER_VFIO_REQUIRE_IOMMU_GROUP only for an isolated lab")
            })?;
            for member in members {
                if !self.cfg.vfio_allow.iter().any(|v| v == member) {
                    bail!("IOMMU group {group_id} member {member} is not explicitly allowlisted");
                }
                if pci_driver_name(member).as_deref() != Some("vfio-pci") {
                    bail!("IOMMU group {group_id} member {member} is not bound to vfio-pci");
                }
            }
        }
        Ok(group.map(|(id, _)| id))
    }

    async fn persist_attachment_owner(&self, key: &str, owner: &str) -> AnyResult<()> {
        let mut changed = false;
        if let Some(sandbox) = self.sandbox.lock().await.as_mut() {
            if let Some(item) = sandbox.devices.iter_mut().find(|d| d.key() == key) {
                changed |= item.add_owner(owner);
            }
        }
        if let Some(journal) = self.journal_sandbox.lock().await.as_mut() {
            if let Some(item) = journal.devices.iter_mut().find(|d| d.key() == key) {
                changed |= item.add_owner(owner);
            }
        }
        if changed {
            self.persist_runtime_state().await?;
        }
        Ok(())
    }

    async fn remember_device(&self, attachment: DeviceAttachment) -> AnyResult<()> {
        let key = attachment.key();
        if let Some(sandbox) = self.sandbox.lock().await.as_mut() {
            if let Some(existing) = sandbox.devices.iter_mut().find(|d| d.key() == key) {
                *existing = attachment.clone();
            } else {
                sandbox.devices.push(attachment.clone());
            }
        }
        if let Some(journal) = self.journal_sandbox.lock().await.as_mut() {
            if let Some(existing) = journal.devices.iter_mut().find(|d| d.key() == key) {
                *existing = attachment.clone();
            } else {
                journal.devices.push(attachment);
            }
        }
        self.persist_runtime_state().await
    }

    async fn ensure_block_hotplug(
        &self,
        vm: &VmRecord,
        source: &Path,
        pod_uid: Option<&str>,
        owner: &str,
    ) -> AnyResult<(String, String)> {
        if !self.cfg.device_passthrough {
            bail!("raw block passthrough is disabled by FLUXVM_CONTAINER_DEVICE_PASSTHROUGH=0");
        }
        let _op = self.device_op_lock.lock().await;
        let source = self.canonical_block_source(source, pod_uid)?;
        let meta = std::fs::metadata(&source)?;
        let rdev = meta.rdev();
        let host_major = libc::major(rdev) as u64;
        let host_minor = libc::minor(rdev) as u64;
        let key = format!("block:{}", source.display());

        let existing = self.journal_sandbox.lock().await.as_ref().and_then(|j| {
            j.devices
                .iter()
                .find(|d| match d {
                    DeviceAttachment::Block {
                        host_path,
                        host_major: old_major,
                        host_minor: old_minor,
                        ..
                    } => {
                        host_path == &source
                            || std::fs::canonicalize(host_path).ok().as_ref() == Some(&source)
                            || (old_major == &Some(host_major) && old_minor == &Some(host_minor))
                    }
                    _ => false,
                })
                .cloned()
        });
        if let Some(existing) = existing {
            let serial = match &existing {
                DeviceAttachment::Block {
                    serial,
                    host_major: old_major,
                    host_minor: old_minor,
                    ..
                } => {
                    if old_major.is_some_and(|v| v != host_major)
                        || old_minor.is_some_and(|v| v != host_minor)
                    {
                        bail!(
                            "raw block identity drift for {}: journal {:?}:{:?}, host {host_major}:{host_minor}",
                            source.display(),
                            old_major,
                            old_minor
                        );
                    }
                    serial.clone()
                }
                _ => unreachable!(),
            };
            if !self.qmp_device_present(vm, existing.device_id()).await {
                bail!(
                    "journal owns {key} but QEMU device {} is missing; refusing duplicate attach",
                    existing.device_id()
                );
            }
            let existing_key = existing.key();
            self.persist_attachment_owner(&existing_key, owner).await?;
            return Ok((serial, existing_key));
        }

        // Retry any previously deferred zero-owner unplug before consuming
        // another QEMU device slot.
        let _ = self.reap_unowned_devices_locked(vm).await;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        source.hash(&mut hasher);
        let suffix = format!("{:016x}", hasher.finish());
        let serial = format!("fluxvm-{suffix}");
        let node_name = format!("fvblk{suffix}");
        let device_id = format!("fvdev{suffix}");
        self.qmp_execute(
            vm,
            "blockdev-add",
            Some(json!({
                "node-name": node_name, "driver": "host_device", "filename": source,
                "cache": {"direct": true, "no-flush": false}
            })),
        )
        .await
        .with_context(|| format!("hotplug blockdev-add {}", source.display()))?;
        if let Err(e) = self
            .qmp_execute(
                vm,
                "device_add",
                Some(json!({
                    "driver": "scsi-hd", "drive": node_name, "id": device_id,
                    "bus": "scsi0.0", "serial": serial
                })),
            )
            .await
        {
            let _ = self
                .qmp_execute(vm, "blockdev-del", Some(json!({"node-name": node_name})))
                .await;
            return Err(e)
                .with_context(|| format!("attaching raw block {} to guest", source.display()));
        }
        let attachment = DeviceAttachment::Block {
            host_path: source,
            serial: serial.clone(),
            node_name,
            device_id,
            host_major: Some(host_major),
            host_minor: Some(host_minor),
            owners: Some(vec![owner.to_string()]),
        };
        if let Err(e) = self.remember_device(attachment.clone()).await {
            let _ = self.detach_device(vm, &attachment).await;
            let _ = self.remove_attachment_from_state(&key).await;
            return Err(e).context("persisting raw-block attachment ownership");
        }
        {
            let mut stats = self.device_stats.lock().await;
            stats.attach_total = stats.attach_total.saturating_add(1);
        }
        self.persist_runtime_state().await?;
        Ok((serial, key))
    }

    async fn ensure_vfio_hotplug(
        &self,
        vm: &VmRecord,
        bdf: &str,
        guest_path: &str,
        owner: &str,
    ) -> AnyResult<String> {
        if !self.cfg.device_passthrough {
            bail!("VFIO passthrough is disabled");
        }
        let _op = self.device_op_lock.lock().await;
        let iommu_group = self.validate_vfio_group(bdf)?;
        let key = format!("vfio:{bdf}");
        let existing = self
            .journal_sandbox
            .lock()
            .await
            .as_ref()
            .and_then(|j| j.devices.iter().find(|d| d.key() == key).cloned());
        if let Some(existing) = existing {
            if let DeviceAttachment::Vfio {
                iommu_group: old_group,
                ..
            } = &existing
            {
                if old_group.is_some() && *old_group != iommu_group {
                    bail!(
                        "VFIO IOMMU-group drift for {bdf}: journal {old_group:?}, host {iommu_group:?}"
                    );
                }
            }
            if !self.qmp_device_present(vm, existing.device_id()).await {
                bail!(
                    "journal owns {key} but QEMU device {} is missing; refusing duplicate attach",
                    existing.device_id()
                );
            }
            self.persist_attachment_owner(&key, owner).await?;
            return Ok(key);
        }

        let _ = self.reap_unowned_devices_locked(vm).await;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        bdf.hash(&mut hasher);
        let suffix = format!("{:016x}", hasher.finish());
        let device_id = format!("fvvfio{}", &suffix[..12]);
        let mut last = None;
        for port in 0..4u8 {
            let args = json!({"driver":"vfio-pci","host":bdf,"id":device_id,"bus":format!("hotplug-pcie-{port}")});
            match self.qmp_execute(vm, "device_add", Some(args)).await {
                Ok(_) => {
                    let attachment = DeviceAttachment::Vfio {
                        bdf: bdf.to_string(),
                        guest_path: guest_path.to_string(),
                        device_id,
                        iommu_group,
                        owners: Some(vec![owner.to_string()]),
                    };
                    if let Err(e) = self.remember_device(attachment.clone()).await {
                        let _ = self.detach_device(vm, &attachment).await;
                        let _ = self.remove_attachment_from_state(&key).await;
                        return Err(e).context("persisting VFIO attachment ownership");
                    }
                    {
                        let mut stats = self.device_stats.lock().await;
                        stats.attach_total = stats.attach_total.saturating_add(1);
                    }
                    self.persist_runtime_state().await?;
                    return Ok(key);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("no QEMU PCIe hotplug port available")))
            .with_context(|| format!("attaching VFIO PCI device {bdf}"))
    }

    async fn detach_device(&self, vm: &VmRecord, attachment: &DeviceAttachment) -> AnyResult<()> {
        self.qmp_device_del_wait(vm, attachment.device_id()).await?;
        if let DeviceAttachment::Block { node_name, .. } = attachment {
            self.qmp_execute(vm, "blockdev-del", Some(json!({"node-name": node_name})))
                .await
                .with_context(|| format!("deleting QEMU block node {node_name}"))?;
        }
        {
            let mut stats = self.device_stats.lock().await;
            stats.detach_total = stats.detach_total.saturating_add(1);
        }
        info!(
            "secure-container device detached key={} qdev={}",
            attachment.key(),
            attachment.device_id()
        );
        Ok(())
    }

    async fn remove_attachment_from_state(&self, key: &str) -> AnyResult<()> {
        if let Some(sandbox) = self.sandbox.lock().await.as_mut() {
            sandbox.devices.retain(|d| d.key() != key);
        }
        if let Some(journal) = self.journal_sandbox.lock().await.as_mut() {
            journal.devices.retain(|d| d.key() != key);
        }
        self.persist_runtime_state().await
    }

    async fn reap_unowned_devices_locked(&self, vm: &VmRecord) -> AnyResult<()> {
        let candidates: Vec<DeviceAttachment> = self
            .journal_sandbox
            .lock()
            .await
            .as_ref()
            .map(|j| {
                j.devices
                    .iter()
                    .filter(|d| d.is_releasable())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let mut failures = Vec::new();
        for attachment in candidates {
            match self.detach_device(vm, &attachment).await {
                Ok(_) => self.remove_attachment_from_state(&attachment.key()).await?,
                Err(e) => {
                    warn!("hot-unplug deferred for {}: {e:#}", attachment.key());
                    failures.push(format!("{}: {e:#}", attachment.key()));
                    let mut stats = self.device_stats.lock().await;
                    stats.unplug_failures = stats.unplug_failures.saturating_add(1);
                }
            }
        }
        if !failures.is_empty() {
            let _ = self.persist_runtime_state().await;
            bail!(
                "one or more device hot-unplugs remain pending: {}",
                failures.join("; ")
            );
        }
        Ok(())
    }

    async fn release_device_claims(&self, vm: &VmRecord, owner: &str, claims: &[String]) {
        if claims.is_empty() {
            return;
        }
        let _op = self.device_op_lock.lock().await;
        let claim_set: HashSet<&str> = claims.iter().map(String::as_str).collect();
        let mut changed = false;
        if let Some(sandbox) = self.sandbox.lock().await.as_mut() {
            for item in &mut sandbox.devices {
                if claim_set.contains(item.key().as_str()) {
                    changed |= item.remove_owner(owner);
                }
            }
        }
        if let Some(journal) = self.journal_sandbox.lock().await.as_mut() {
            for item in &mut journal.devices {
                if claim_set.contains(item.key().as_str()) {
                    changed |= item.remove_owner(owner);
                }
            }
        }
        if changed {
            if let Err(e) = self.persist_runtime_state().await {
                warn!("persisting released device claims for {owner} failed: {e:#}");
            }
        }
        if let Err(e) = self.reap_unowned_devices_locked(vm).await {
            // Container deletion must remain successful once the guest process
            // is gone. Keep the zero-owner attachment in the journal and retry
            // on the next device operation/recovery or at sandbox destruction.
            warn!("device cleanup after container {owner} is pending: {e:#}");
        }
    }

    async fn reconcile_device_attachments(&self, vm: &VmRecord) -> AnyResult<()> {
        let _op = self.device_op_lock.lock().await;
        {
            let mut stats = self.device_stats.lock().await;
            stats.recovery_checks = stats.recovery_checks.saturating_add(1);
        }
        let attachments = self
            .journal_sandbox
            .lock()
            .await
            .as_ref()
            .map(|j| j.devices.clone())
            .unwrap_or_default();
        for attachment in &attachments {
            match attachment {
                DeviceAttachment::Block {
                    host_path,
                    host_major,
                    host_minor,
                    ..
                } => {
                    let meta = std::fs::metadata(host_path).with_context(|| {
                        format!("recovery block device {} disappeared", host_path.display())
                    })?;
                    if !meta.file_type().is_block_device() {
                        bail!(
                            "recovery device {} is no longer block-special",
                            host_path.display()
                        );
                    }
                    let rdev = meta.rdev();
                    let major = libc::major(rdev) as u64;
                    let minor = libc::minor(rdev) as u64;
                    if host_major.is_some_and(|v| v != major)
                        || host_minor.is_some_and(|v| v != minor)
                    {
                        bail!("recovery block identity drift for {}", host_path.display());
                    }
                }
                DeviceAttachment::Vfio {
                    bdf, iommu_group, ..
                } => {
                    let current = self.validate_vfio_group(bdf)?;
                    if iommu_group.is_some() && *iommu_group != current {
                        bail!(
                            "recovery VFIO IOMMU-group drift for {bdf}: journal {iommu_group:?}, host {current:?}"
                        );
                    }
                }
            }
            if !self.qmp_device_present(vm, attachment.device_id()).await {
                bail!(
                    "recovery journal device {} ({}) is missing from QEMU",
                    attachment.key(),
                    attachment.device_id()
                );
            }
        }
        // Set 9-owned devices whose containers were deleted immediately
        // before a shim crash can be left with zero owners. Retry unplug now.
        let _ = self.reap_unowned_devices_locked(vm).await;
        self.persist_runtime_state().await?;
        Ok(())
    }

    async fn rollback_prepared_device_claims(
        &self,
        vm: &VmRecord,
        owner: &str,
        claims: &[String],
        error: anyhow::Error,
    ) -> AnyResult<Vec<String>> {
        self.release_device_claims(vm, owner, claims).await;
        Err(error)
    }

    async fn prepare_hotplug_devices(
        &self,
        vm: &VmRecord,
        spec: &mut Value,
        pod_uid: Option<&str>,
        owner: &str,
    ) -> AnyResult<Vec<String>> {
        let mut claims = Vec::new();
        if let Some(mounts) = spec.get_mut("mounts").and_then(Value::as_array_mut) {
            for mount in mounts.iter_mut() {
                let is_bind = mount.get("type").and_then(Value::as_str) == Some("bind")
                    || mount
                        .get("options")
                        .and_then(Value::as_array)
                        .is_some_and(|o| {
                            o.iter()
                                .any(|v| matches!(v.as_str(), Some("bind" | "rbind")))
                        });
                if !is_bind {
                    continue;
                }
                let Some(source) = mount
                    .get("source")
                    .and_then(Value::as_str)
                    .map(PathBuf::from)
                else {
                    continue;
                };
                let Ok(meta) = std::fs::metadata(&source) else {
                    continue;
                };
                if meta.file_type().is_block_device() {
                    let (serial, key) =
                        match self.ensure_block_hotplug(vm, &source, pod_uid, owner).await {
                            Ok(value) => value,
                            Err(e) => {
                                return self
                                    .rollback_prepared_device_claims(vm, owner, &claims, e)
                                    .await;
                            }
                        };
                    mount["source"] = Value::String(format!("fluxvm-block://{serial}"));
                    if !claims.contains(&key) {
                        claims.push(key);
                    }
                }
            }
        }
        if let Some(devices) = spec
            .pointer_mut("/linux/devices")
            .and_then(Value::as_array_mut)
        {
            for dev in devices.iter_mut() {
                let kind = dev.get("type").and_then(Value::as_str).unwrap_or("");
                let Some(path) = dev.get("path").and_then(Value::as_str).map(str::to_string) else {
                    continue;
                };
                let Some(major) = dev.get("major").and_then(Value::as_i64) else {
                    continue;
                };
                let Some(minor) = dev.get("minor").and_then(Value::as_i64) else {
                    continue;
                };
                if major < 0 || minor < 0 {
                    continue;
                }

                if kind == "b" {
                    let Some(source) = self
                        .pod_block_source_for_rdev(pod_uid, major as u64, minor as u64)
                        .or_else(|| host_block_path_for_rdev(major as u64, minor as u64))
                    else {
                        let e = anyhow::anyhow!(
                            "OCI block device {path} ({major}:{minor}) is not owned by this Pod volumeDevices tree or an explicit block allowlist"
                        );
                        return self
                            .rollback_prepared_device_claims(vm, owner, &claims, e)
                            .await;
                    };
                    let (serial, key) =
                        match self.ensure_block_hotplug(vm, &source, pod_uid, owner).await {
                            Ok(value) => value,
                            Err(e) => {
                                return self
                                    .rollback_prepared_device_claims(vm, owner, &claims, e)
                                    .await;
                            }
                        };
                    dev["major"] = Value::from(-2);
                    dev["minor"] = Value::from(-2);
                    dev["fluxvmBlockSerial"] = Value::String(serial);
                    if !claims.contains(&key) {
                        claims.push(key);
                    }
                    continue;
                }

                if !matches!(kind, "c" | "u") {
                    continue;
                }
                if is_builtin_guest_char_device(&path) {
                    continue;
                }
                let Some(bdf) = pci_bdf_for_host_device(major as u64, minor as u64) else {
                    if self.guest_driver_companion_allowed(&path) {
                        // Global control nodes (e.g. nvidiactl/UVM, AMD KFD)
                        // are created by the guest driver after the actual PCI
                        // function is attached. Mark them guest-resolved only;
                        // never recreate the host major/minor in the VM.
                        dev["major"] = Value::from(-1);
                        dev["minor"] = Value::from(-1);
                        dev["fluxvmGuestCompanion"] = Value::Bool(true);
                        continue;
                    }
                    let e = anyhow::anyhow!(
                        "OCI device {path} ({major}:{minor}) has no PCI parent eligible for VFIO and is not an allowed guest-driver companion"
                    );
                    return self
                        .rollback_prepared_device_claims(vm, owner, &claims, e)
                        .await;
                };
                let key = match self.ensure_vfio_hotplug(vm, &bdf, &path, owner).await {
                    Ok(key) => key,
                    Err(e) => {
                        return self
                            .rollback_prepared_device_claims(vm, owner, &claims, e)
                            .await;
                    }
                };
                dev["major"] = Value::from(-1);
                dev["minor"] = Value::from(-1);
                if !claims.contains(&key) {
                    claims.push(key);
                }
            }
        }
        claims.sort();
        Ok(claims)
    }

    async fn sandbox_paths(
        &self,
        id: &str,
        hints: Option<&SandboxHints>,
    ) -> AnyResult<(VmRecord, PathBuf, String)> {
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
    async fn stage_rootfs_and_config(
        &self,
        req: &CreateTaskRequest,
    ) -> AnyResult<(VmRecord, String, ContainerIo, Option<PathBuf>, Vec<String>)> {
        let config_path = Path::new(&req.bundle).join("config.json");
        let text = tokio::fs::read_to_string(&config_path)
            .await
            .with_context(|| format!("reading {}", config_path.display()))?;
        let mut spec: Value = serde_json::from_str(&text)?;
        let hints = sandbox_hints_from_spec(&spec);

        let host_ctr = self.share_dir().join("containers").join(safe_name(&req.id));
        let guest_ctr = format!("{GUEST_SHARE}/containers/{}", safe_name(&req.id));
        let rootfs = host_ctr.join("rootfs");
        let mountpoint = self
            .cfg
            .state_dir
            .join(&self.namespace)
            .join(&self.group)
            .join("mounts")
            .join(safe_name(&req.id));

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
            let _ = tokio::process::Command::new("umount")
                .args(["-l", mountpoint.to_string_lossy().as_ref()])
                .status()
                .await;
            let _ = tokio::fs::remove_dir_all(&mountpoint).await;
            copy_result
        };

        let (vm, ()) = tokio::try_join!(self.ensure_sandbox(Some(&hints)), stage_rootfs)?;

        spec["root"]["path"] = Value::String(format!("{guest_ctr}/rootfs"));
        let device_claims = self
            .prepare_hotplug_devices(&vm, &mut spec, hints.pod_uid.as_deref(), &req.id)
            .await?;
        if let Err(e) =
            stage_bind_mounts(&mut spec, &host_ctr, &guest_ctr, hints.pod_uid.as_deref()).await
        {
            self.release_device_claims(&vm, &req.id, &device_claims)
                .await;
            return Err(e);
        }
        let (io, io_dir) = match self
            .prepare_io(
                &req.id,
                &req.stdin,
                &req.stdout,
                &req.stderr,
                req.terminal,
                &host_ctr,
                &guest_ctr,
            )
            .await
        {
            Ok(io) => io,
            Err(e) => {
                self.release_device_claims(&vm, &req.id, &device_claims)
                    .await;
                return Err(e);
            }
        };
        Ok((vm, serde_json::to_string(&spec)?, io, io_dir, device_claims))
    }

    async fn prepare_io(
        &self,
        id: &str,
        stdin: &str,
        stdout: &str,
        stderr: &str,
        terminal: bool,
        host_ctr: &Path,
        guest_ctr: &str,
    ) -> AnyResult<(ContainerIo, Option<PathBuf>)> {
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

        if terminal {
            bail!("TTY requires FLUXVM_CONTAINER_STREAMING_STDIO=1");
        }
        let io_key = safe_name(id);
        let io_dir = host_ctr.join("io").join(&io_key);
        let guest_io_dir = format!("{guest_ctr}/io/{io_key}");
        tokio::fs::create_dir_all(&io_dir).await?;
        let mut guest = ContainerIo::default();
        if !stdout.is_empty() {
            let p = io_dir.join("stdout.log");
            create_stdio_file(&p)?;
            guest.stdout = Some(format!("{guest_io_dir}/stdout.log"));
            spawn_stdio_relay(p, PathBuf::from(stdout), format!("{id}:stdout"), true);
        }
        if !stderr.is_empty() {
            let p = io_dir.join("stderr.log");
            create_stdio_file(&p)?;
            guest.stderr = Some(format!("{guest_io_dir}/stderr.log"));
            spawn_stdio_relay(p, PathBuf::from(stderr), format!("{id}:stderr"), true);
        }
        if !stdin.is_empty() {
            let p = io_dir.join("stdin.log");
            create_stdio_file(&p)?;
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
        if !self.cfg.streaming_stdio {
            return Ok(());
        }

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
            let stream = fluxvm_container_client::open_stream(
                vm,
                attach(IoStreamKind::Stdin),
                Duration::from_secs(10),
            )
            .await?;
            relays.push((IoStreamKind::Stdin, stream, PathBuf::from(stdin)));
        }
        if terminal {
            let output = if !stdout.is_empty() { stdout } else { stderr };
            if !output.is_empty() {
                let stream = fluxvm_container_client::open_stream(
                    vm,
                    attach(IoStreamKind::Stdout),
                    Duration::from_secs(10),
                )
                .await?;
                relays.push((IoStreamKind::Stdout, stream, PathBuf::from(output)));
            }
        } else {
            if !stdout.is_empty() {
                let stream = fluxvm_container_client::open_stream(
                    vm,
                    attach(IoStreamKind::Stdout),
                    Duration::from_secs(10),
                )
                .await?;
                relays.push((IoStreamKind::Stdout, stream, PathBuf::from(stdout)));
            }
            if !stderr.is_empty() {
                let stream = fluxvm_container_client::open_stream(
                    vm,
                    attach(IoStreamKind::Stderr),
                    Duration::from_secs(10),
                )
                .await?;
                relays.push((IoStreamKind::Stderr, stream, PathBuf::from(stderr)));
            }
        }

        let key = process_key(id, exec_id);
        let output_count = relays
            .iter()
            .filter(|(kind, _, _)| *kind != IoStreamKind::Stdin)
            .count();
        if output_count > 0 {
            self.stream_pending
                .lock()
                .await
                .insert(key.clone(), output_count);
        }
        for (kind, mut stream, host_path) in relays {
            let pending = self.stream_pending.clone();
            let relay_key = key.clone();
            tokio::spawn(async move {
                let is_output = kind != IoStreamKind::Stdin;
                let result = tokio::task::spawn_blocking(move || -> AnyResult<()> {
                    match kind {
                        IoStreamKind::Stdin => {
                            let mut host = std::fs::OpenOptions::new()
                                .read(true)
                                .open(&host_path)
                                .with_context(|| {
                                    format!("opening containerd stdin {}", host_path.display())
                                })?;
                            std::io::copy(&mut host, &mut stream)?;
                            use std::io::Write as _;
                            stream.flush()?;
                        }
                        IoStreamKind::Stdout | IoStreamKind::Stderr => {
                            let mut host = std::fs::OpenOptions::new()
                                .write(true)
                                .open(&host_path)
                                .with_context(|| {
                                    format!("opening containerd output {}", host_path.display())
                                })?;
                            std::io::copy(&mut stream, &mut host)?;
                            use std::io::Write as _;
                            host.flush()?;
                        }
                    }
                    Ok(())
                })
                .await;
                if is_output {
                    let mut map = pending.lock().await;
                    if let Some(count) = map.get_mut(&relay_key) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            map.remove(&relay_key);
                        }
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
            self.execs
                .read()
                .await
                .get(&key)
                .is_some_and(|m| m.streaming)
        } else {
            self.tasks.read().await.get(id).is_some_and(|m| m.streaming)
        };
        if streaming {
            for _ in 0..200 {
                if !self.stream_pending.lock().await.contains_key(&key) {
                    return;
                }
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
            self.tasks
                .read()
                .await
                .get(id)
                .and_then(|m| m.io_dir.clone())
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
                let size = tokio::fs::metadata(&path)
                    .await
                    .map(|m| m.len())
                    .unwrap_or(0);
                if Some(size) == last {
                    stable += 1;
                    if stable >= 4 {
                        break;
                    }
                } else {
                    stable = 0;
                    last = Some(size);
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
    }

    async fn guest_network_policy(
        &self,
        vm: &VmRecord,
    ) -> AnyResult<Option<ContainerNetworkPolicy>> {
        let url = format!(
            "{}/v1/vms/{}/network/pod-policy",
            self.cfg.api_url.trim_end_matches('/'),
            vm.id
        );
        let mut req = self.http.get(url);
        if let Some(token) = &self.cfg.api_token {
            req = req.bearer_auth(token);
        }
        let response = req
            .send()
            .await
            .context("fetching Pod policy for guest mirror")?;
        if !response.status().is_success() {
            bail!("Pod-policy GET returned {}", response.status());
        }
        let Some(p) = response.json::<Option<PodPolicyWire>>().await? else {
            return Ok(Some(ContainerNetworkPolicy {
                default_allow: true,
                audit_mode: false,
                allow_addresses: Vec::new(),
                deny_addresses: Vec::new(),
                schema_version: 2,
                ingress_isolated: false,
                egress_isolated: false,
                rules: Vec::new(),
            }));
        };
        let mut rules = Vec::new();
        for r in p.rules {
            if !rules
                .iter()
                .any(|x: &ContainerNetworkRule| x.direction == r.direction && x.cidr == r.cidr)
            {
                rules.push(ContainerNetworkRule {
                    direction: r.direction,
                    cidr: r.cidr,
                });
            }
        }
        Ok(Some(ContainerNetworkPolicy {
            default_allow: !p.default_deny,
            audit_mode: p.audit_mode,
            allow_addresses: p.allow_addresses,
            deny_addresses: p.deny_addresses,
            schema_version: p.schema_version,
            ingress_isolated: p.ingress_isolated,
            egress_isolated: p.egress_isolated,
            rules,
        }))
    }

    fn spawn_network_policy_watch(&self, vm: VmRecord, id: String) {
        let service = self.clone();
        tokio::spawn(async move {
            let mut last: Option<ContainerNetworkPolicy> = None;
            loop {
                if !service.tasks.read().await.contains_key(&id) {
                    break;
                }
                match service.guest_network_policy(&vm).await {
                    Ok(Some(policy)) if last.as_ref() != Some(&policy) => {
                        match service
                            .call_agent_direct(
                                &vm,
                                ContainerRequest::UpdateNetworkPolicy {
                                    id: id.clone(),
                                    policy: policy.clone(),
                                },
                            )
                            .await
                        {
                            Ok(ContainerResponse::NetworkPolicyUpdated) => last = Some(policy),
                            Ok(other) => {
                                warn!("unexpected guest network-policy response: {other:?}")
                            }
                            Err(e) => warn!("guest network-policy sync failed for {id}: {e:#}"),
                        }
                    }
                    Ok(_) => {}
                    Err(e) => warn!("Pod-policy mirror fetch failed for {id}: {e:#}"),
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
    }

    async fn call_agent_direct(
        &self,
        vm: &VmRecord,
        req: ContainerRequest,
    ) -> AnyResult<ContainerResponse> {
        // `Wait` blocks in the guest until the container exits, which is
        // inherently unbounded (anywhere from milliseconds to days
        // depending on the workload) -- it gets a generous timeout of its
        // own rather than the short budget every other, normally-quick RPC
        // (Create/Start/Stats/Kill/...) uses.
        let timeout = if matches!(req, ContainerRequest::Wait { .. }) {
            Duration::from_secs(7 * 24 * 60 * 60)
        } else {
            Duration::from_secs(60)
        };
        match fluxvm_container_client::call(vm, req, timeout).await? {
            ContainerResponse::Error { message } => bail!("guest container-agent: {message}"),
            response => Ok(response),
        }
    }

    async fn call_agent(
        &self,
        vm: &VmRecord,
        req: ContainerRequest,
    ) -> AnyResult<ContainerResponse> {
        self.call_agent_direct(vm, req).await
    }

    async fn log_guest_security_stats(&self, vm: &VmRecord) {
        match self
            .call_agent_direct(vm, ContainerRequest::SecurityStats)
            .await
        {
            Ok(ContainerResponse::SecurityStats { stats }) => info!(
                "FluxVM guest security stats: notify_received={} notify_denied={} notify_continued={} notify_errors={} selinux_mounts_labeled={} lsm_preflight_failures={}",
                stats.seccomp_notify_received,
                stats.seccomp_notify_denied,
                stats.seccomp_notify_continued,
                stats.seccomp_notify_errors,
                stats.selinux_mounts_labeled,
                stats.lsm_apply_failures,
            ),
            Ok(other) => warn!("unexpected guest security stats response: {other:?}"),
            Err(e) => warn!("reading guest security stats failed: {e:#}"),
        }
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
        shim_diag(format!(
            "publish TaskExit id={container_id} exec={exec_id:?} pid={pid} code={exit_code}"
        ));
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

    fn spawn_exit_watch(
        &self,
        vm: VmRecord,
        container_id: String,
        exec_id: Option<String>,
        pid: u32,
    ) {
        let service = self.clone();
        tokio::spawn(async move {
            let request = ContainerRequest::Wait {
                id: container_id.clone(),
                exec_id: exec_id.clone(),
            };
            match service.call_agent_direct(&vm, request).await {
                Ok(ContainerResponse::Exited {
                    exit_code,
                    exited_at_unix_nano,
                }) => {
                    service
                        .flush_stdio_after_exit(&container_id, exec_id.as_deref())
                        .await;
                    service
                        .publish_exit_once(
                            container_id,
                            exec_id,
                            pid,
                            exit_code,
                            exited_at_unix_nano,
                        )
                        .await;
                }
                Ok(other) => warn!("unexpected background wait response: {other:?}"),
                Err(e) => warn!("background FluxVM container wait failed: {e:#}"),
            }
        });
    }

    fn spawn_oom_watch(&self, vm: VmRecord, id: String) {
        let service = self.clone();
        tokio::spawn(async move {
            {
                let mut active = service.oom_monitors.lock().await;
                if !active.insert(id.clone()) {
                    return;
                }
            }

            let mut consecutive_errors = 0u32;
            loop {
                if !service.tasks.read().await.contains_key(&id) {
                    break;
                }
                match service
                    .call_agent_direct(&vm, ContainerRequest::CgroupEvents { id: id.clone() })
                    .await
                {
                    Ok(ContainerResponse::CgroupEvents { events }) => {
                        consecutive_errors = 0;
                        let seen = service
                            .tasks
                            .read()
                            .await
                            .get(&id)
                            .map(|m| m.oom_kill_seen)
                            .unwrap_or(events.oom_kill);
                        if events.oom_kill > seen {
                            service
                                .send_event(TaskOOM {
                                    container_id: id.clone(),
                                    ..Default::default()
                                })
                                .await;
                            if let Some(meta) = service.tasks.write().await.get_mut(&id) {
                                meta.oom_kill_seen = events.oom_kill;
                            }
                            if let Err(e) = service.persist_runtime_state().await {
                                warn!("persisting OOM counter for {id} failed: {e:#}");
                            }
                            info!(
                                "secure-container OOM id={} oom={} oom_kill={} max_events={}",
                                id, events.oom, events.oom_kill, events.max
                            );
                        }
                    }
                    Ok(other) => {
                        consecutive_errors += 1;
                        if consecutive_errors == 1 || consecutive_errors % 20 == 0 {
                            warn!("unexpected cgroup-events response for {id}: {other:?}");
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        if consecutive_errors == 1 || consecutive_errors % 20 == 0 {
                            warn!("OOM monitor query failed for {id}: {e:#}");
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(service.cfg.oom_poll_ms)).await;
            }
            service.oom_monitors.lock().await.remove(&id);
        });
    }

    async fn delete_fluxvm_vm_idempotent(&self, vm_id: &str) -> AnyResult<()> {
        let url = format!("{}/v1/vms/{vm_id}", self.cfg.api_url.trim_end_matches('/'));
        let mut req = self.http.request(Method::DELETE, &url);
        if let Some(token) = &self.cfg.api_token {
            req = req.bearer_auth(token);
        }
        let response = req
            .send()
            .await
            .with_context(|| format!("deleting journal-owned FluxVM VM {vm_id}"))?;
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        bail!("FluxVM DELETE {url} returned {status}: {body}");
    }

    async fn cleanup_process_staging(&self, id: &str, exec_id: Option<&str>) {
        self.stream_pending
            .lock()
            .await
            .remove(&process_key(id, exec_id));
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
        // Never drop the recovery journal before VM deletion is confirmed.
        // If the FluxVM API is temporarily unavailable, returning an error
        // leaves authoritative ownership in place for containerd's retry and
        // prevents an orphaned VM from becoming invisible to the runtime.
        let live = self.sandbox.lock().await.clone();
        let journal = self.journal_sandbox.lock().await.clone();
        let vm_id = live
            .as_ref()
            .map(|s| s.vm.id.to_string())
            .or_else(|| journal.as_ref().map(|j| j.vm_id.clone()));
        if let Some(vm_id) = vm_id.as_deref() {
            self.delete_fluxvm_vm_idempotent(vm_id).await?;
        }

        if let Some(cni) = live.as_ref().and_then(|s| s.cni.as_ref()) {
            cleanup_cni_bridge(cni).await;
        } else if let Some(cni) = journal.as_ref().and_then(|j| j.cni.as_ref()) {
            cleanup_cni_bridge(cni).await;
        }

        *self.sandbox.lock().await = None;
        *self.journal_sandbox.lock().await = None;
        self.tasks.write().await.clear();
        self.execs.write().await.clear();
        self.oom_monitors.lock().await.clear();
        let root = runtime_state_root(&self.cfg, &self.namespace, &self.group);
        let _ = tokio::fs::remove_dir_all(root).await;
        Ok(())
    }
}

fn shim_diag(msg: impl AsRef<str>) {
    let msg = msg.as_ref();
    warn!("{msg}");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/fluxvm-shim-create.log")
    {
        use std::io::Write;
        let _ = writeln!(f, "{} {msg}", chrono_like_now());
    }
}

fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("ts={secs}")
}

#[async_trait]
impl Task for Service {
    async fn create(
        &self,
        _ctx: &TtrpcContext,
        req: CreateTaskRequest,
    ) -> TtrpcResult<CreateTaskResponse> {
        shim_diag(format!(
            "create begin id={} group={} bundle={}",
            req.id, self.group, req.bundle
        ));
        let (vm, config_json, io, io_dir, device_claims) =
            match self.stage_rootfs_and_config(&req).await {
                Ok(staged) => staged,
                Err(e) => {
                    shim_diag(format!("create stage_rootfs_and_config failed id={}: {e:#}", req.id));
                    self.cleanup_process_staging(&req.id, None).await;
                    return Err(rpc_other(e));
                }
            };
        let is_sandbox = req.id == self.group;
        shim_diag(format!(
            "create staged id={} is_sandbox={} vm={}",
            req.id, is_sandbox, vm.id
        ));
        let share_process_namespace = config_requests_shared_pid_ns(&config_json);
        // Set 19: fetch the current host Pod policy before Create. Failure is
        // fail-closed because None keeps Set 8S's deny-non-loopback default.
        let guest_network_policy = self.guest_network_policy(&vm).await.unwrap_or(None);
        let response = match self
            .call_agent(
                &vm,
                ContainerRequest::Create {
                    id: req.id.clone(),
                    config_json,
                    io,
                    is_sandbox,
                    share_process_namespace,
                    // FLUXVM_SECURE_CONTAINERS_SET19: initial guest mirror.
                    network_policy: guest_network_policy,
                },
            )
            .await
        {
            Ok(response) => response,
            Err(e) => {
                shim_diag(format!("create call_agent failed id={}: {e:#}", req.id));
                self.release_device_claims(&vm, &req.id, &device_claims)
                    .await;
                self.cleanup_process_staging(&req.id, None).await;
                return Err(rpc_other(e));
            }
        };
        let (pid, container_identity) = match response {
            ContainerResponse::Created {
                pid,
                container_identity,
            } => (pid, container_identity),
            other => {
                shim_diag(format!(
                    "create unexpected agent response id={}: {other:?}",
                    req.id
                ));
                self.release_device_claims(&vm, &req.id, &device_claims)
                    .await;
                self.cleanup_process_staging(&req.id, None).await;
                return Err(rpc_other(format!("unexpected create response: {other:?}")));
            }
        };
        if let Err(e) = self
            .attach_stream_relays(
                &vm,
                &req.id,
                None,
                &req.stdin,
                &req.stdout,
                &req.stderr,
                req.terminal,
            )
            .await
        {
            shim_diag(format!("create attach_stream_relays failed id={}: {e:#}", req.id));
            let _ = self
                .call_agent(
                    &vm,
                    ContainerRequest::Delete {
                        id: req.id.clone(),
                        exec_id: None,
                        force: true,
                    },
                )
                .await;
            self.release_device_claims(&vm, &req.id, &device_claims)
                .await;
            self.cleanup_process_staging(&req.id, None).await;
            return Err(rpc_other(format!("attaching VSOCK stdio: {e:#}")));
        }
        {
            let mut exits = self.exit_events.lock().await;
            let prefix = format!("{}\0", req.id);
            exits.retain(|key| key != &req.id && !key.starts_with(&prefix));
        }
        self.tasks.write().await.insert(
            req.id.clone(),
            TaskMeta {
                bundle: req.bundle.clone(),
                stdin: req.stdin.clone(),
                stdout: req.stdout.clone(),
                stderr: req.stderr.clone(),
                terminal: req.terminal,
                pid,
                io_dir,
                streaming: self.cfg.streaming_stdio,
                oom_kill_seen: 0,
                device_claims,
                container_identity,
            },
        );
        self.persist_runtime_state().await.map_err(rpc_other)?;
        self.spawn_oom_watch(vm.clone(), req.id.clone());
        self.spawn_network_policy_watch(vm.clone(), req.id.clone());
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
            })
            .into(),
            checkpoint: req.checkpoint.clone(),
            pid,
            ..Default::default()
        })
        .await;
        shim_diag(format!("create ok id={} pid={}", req.id, pid));
        Ok(CreateTaskResponse {
            pid,
            ..Default::default()
        })
    }

    async fn start(&self, _ctx: &TtrpcContext, req: StartRequest) -> TtrpcResult<StartResponse> {
        shim_diag(format!(
            "start begin id={} exec_id={:?}",
            req.id, req.exec_id
        ));
        let vm = self.ensure_sandbox(None).await.map_err(|e| {
            shim_diag(format!("start ensure_sandbox failed id={}: {e:#}", req.id));
            rpc_other(e)
        })?;
        let exec_id = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id.clone())
        };
        let response = self
            .call_agent(
                &vm,
                ContainerRequest::Start {
                    id: req.id.clone(),
                    exec_id: exec_id.clone(),
                },
            )
            .await
            .map_err(|e| {
                shim_diag(format!("start call_agent failed id={}: {e:#}", req.id));
                rpc_other(e)
            })?;
        let pid = match response {
            ContainerResponse::Started { pid } => pid,
            other => {
                shim_diag(format!("start unexpected response id={}: {other:?}", req.id));
                return Err(rpc_other(format!("unexpected start response: {other:?}")));
            }
        };
        if let Some(exec_id_value) = exec_id.as_ref() {
            self.send_event(TaskExecStarted {
                container_id: req.id.clone(),
                exec_id: exec_id_value.clone(),
                pid,
                ..Default::default()
            })
            .await;
        } else {
            self.send_event(TaskStart {
                container_id: req.id.clone(),
                pid,
                ..Default::default()
            })
            .await;
        }
        self.spawn_exit_watch(vm, req.id.clone(), exec_id, pid);
        shim_diag(format!("start ok id={} pid={}", req.id, pid));
        Ok(StartResponse {
            pid,
            ..Default::default()
        })
    }

    async fn state(&self, _ctx: &TtrpcContext, req: StateRequest) -> TtrpcResult<StateResponse> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id.clone())
        };
        let response = self
            .call_agent(
                &vm,
                ContainerRequest::State {
                    id: req.id.clone(),
                    exec_id: exec_id.clone(),
                },
            )
            .await
            .map_err(rpc_other)?;
        let (status, pid, exit_code, exited_at) = match response {
            ContainerResponse::State {
                status,
                pid,
                exit_code,
                exited_at_unix_nano,
                ..
            } => (status, pid, exit_code, exited_at_unix_nano),
            other => return Err(rpc_other(format!("unexpected state response: {other:?}"))),
        };
        let meta = if let Some(exec_id) = exec_id.as_deref() {
            self.execs
                .read()
                .await
                .get(&process_key(&req.id, Some(exec_id)))
                .cloned()
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
        if let Some(ns) = exited_at {
            out.exited_at = Some(timestamp_from_nanos(ns)).into();
        }
        Ok(out)
    }

    async fn wait(&self, _ctx: &TtrpcContext, req: WaitRequest) -> TtrpcResult<WaitResponse> {
        shim_diag(format!(
            "wait begin id={} exec_id={:?}",
            req.id, req.exec_id
        ));
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id.clone())
        };
        let response = self
            .call_agent(
                &vm,
                ContainerRequest::Wait {
                    id: req.id.clone(),
                    exec_id: exec_id.clone(),
                },
            )
            .await
            .map_err(rpc_other)?;
        match response {
            ContainerResponse::Exited {
                exit_code,
                exited_at_unix_nano,
            } => {
                shim_diag(format!(
                    "wait exited id={} code={}",
                    req.id, exit_code
                ));
                self.flush_stdio_after_exit(&req.id, exec_id.as_deref())
                    .await;
                let pid = if let Some(exec) = exec_id.as_deref() {
                    self.execs
                        .read()
                        .await
                        .get(&process_key(&req.id, Some(exec)))
                        .map(|m| m.pid)
                        .unwrap_or(0)
                } else {
                    self.tasks
                        .read()
                        .await
                        .get(&req.id)
                        .map(|m| m.pid)
                        .unwrap_or(0)
                };
                self.publish_exit_once(
                    req.id.clone(),
                    exec_id,
                    pid,
                    exit_code,
                    exited_at_unix_nano,
                )
                .await;
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
        let exec_id = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id)
        };
        self.call_agent(
            &vm,
            ContainerRequest::Kill {
                id: req.id,
                exec_id,
                signal: req.signal as i32,
                all: req.all,
            },
        )
        .await
        .map_err(rpc_other)?;
        Ok(Empty::new())
    }

    async fn pause(&self, _ctx: &TtrpcContext, req: PauseRequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        self.call_agent(&vm, ContainerRequest::Pause { id: req.id.clone() })
            .await
            .map_err(rpc_other)?;
        self.send_event(TaskPaused {
            container_id: req.id,
            ..Default::default()
        })
        .await;
        Ok(Empty::new())
    }

    async fn resume(&self, _ctx: &TtrpcContext, req: ResumeRequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        self.call_agent(&vm, ContainerRequest::Resume { id: req.id.clone() })
            .await
            .map_err(rpc_other)?;
        self.send_event(TaskResumed {
            container_id: req.id,
            ..Default::default()
        })
        .await;
        Ok(Empty::new())
    }

    async fn delete(&self, _ctx: &TtrpcContext, req: DeleteRequest) -> TtrpcResult<DeleteResponse> {
        shim_diag(format!(
            "delete begin id={} exec_id={:?}",
            req.id, req.exec_id
        ));
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id.clone())
        };
        let device_claims = if exec_id.is_none() {
            self.tasks
                .read()
                .await
                .get(&req.id)
                .map(|m| m.device_claims.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
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
            ContainerResponse::Deleted {
                pid,
                exit_code,
                exited_at_unix_nano,
            } => (pid, exit_code, exited_at_unix_nano),
            other => return Err(rpc_other(format!("unexpected delete response: {other:?}"))),
        };

        if exec_id.is_none() {
            self.log_guest_security_stats(&vm).await;
        }

        // containerd expects stdio to be drained and exit to precede delete.
        // The background WaitTask watcher races with force-delete, so this
        // path uses a de-duplicated publisher to avoid duplicate exit events.
        self.flush_stdio_after_exit(&req.id, exec_id.as_deref())
            .await;
        self.publish_exit_once(req.id.clone(), exec_id.clone(), pid, code, ns)
            .await;
        self.cleanup_process_staging(&req.id, exec_id.as_deref())
            .await;

        if let Some(exec_id_value) = exec_id.as_deref() {
            self.execs
                .write()
                .await
                .remove(&process_key(&req.id, Some(exec_id_value)));
        } else {
            self.tasks.write().await.remove(&req.id);
            self.execs
                .write()
                .await
                .retain(|key, _| !key.starts_with(&format!("{}\0", req.id)));
        }
        self.persist_runtime_state().await.map_err(rpc_other)?;
        if exec_id.is_none() {
            self.release_device_claims(&vm, &req.id, &device_claims)
                .await;
        }

        self.send_event(TaskDelete {
            container_id: req.id.clone(),
            pid,
            exit_status: code as u32,
            exited_at: Some(timestamp_from_nanos(ns)).into(),
            ..Default::default()
        })
        .await;

        let mut out = DeleteResponse::new();
        out.pid = pid;
        out.exit_status = code as u32;
        out.exited_at = Some(timestamp_from_nanos(ns)).into();
        Ok(out)
    }

    async fn exec(&self, _ctx: &TtrpcContext, req: ExecProcessRequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let bytes = req
            .spec
            .as_ref()
            .map(|a| a.value.clone())
            .unwrap_or_default();
        if bytes.is_empty() {
            return Err(rpc_invalid("ExecProcessRequest.spec is empty"));
        }
        let process_json = String::from_utf8(bytes).map_err(|e| rpc_invalid(e.to_string()))?;
        let (_, host_ctr, guest_ctr) =
            self.sandbox_paths(&req.id, None).await.map_err(rpc_other)?;
        let io_id = format!("{}-{}", req.id, req.exec_id);
        let (io, io_dir) = self
            .prepare_io(
                &io_id,
                &req.stdin,
                &req.stdout,
                &req.stderr,
                req.terminal,
                &host_ctr,
                &guest_ctr,
            )
            .await
            .map_err(rpc_other)?;
        let response = self
            .call_agent(
                &vm,
                ContainerRequest::Exec {
                    id: req.id.clone(),
                    exec_id: req.exec_id.clone(),
                    process_json,
                    io,
                },
            )
            .await
            .map_err(rpc_other)?;
        let pid = match response {
            ContainerResponse::ExecStarted { pid } => pid,
            other => return Err(rpc_other(format!("unexpected exec response: {other:?}"))),
        };
        if let Err(e) = self
            .attach_stream_relays(
                &vm,
                &req.id,
                Some(&req.exec_id),
                &req.stdin,
                &req.stdout,
                &req.stderr,
                req.terminal,
            )
            .await
        {
            let _ = self
                .call_agent(
                    &vm,
                    ContainerRequest::Delete {
                        id: req.id.clone(),
                        exec_id: Some(req.exec_id.clone()),
                        force: true,
                    },
                )
                .await;
            self.cleanup_process_staging(&req.id, Some(&req.exec_id))
                .await;
            return Err(rpc_other(format!("attaching exec VSOCK stdio: {e:#}")));
        }
        let (bundle, container_identity) = {
            let tasks = self.tasks.read().await;
            let parent = tasks.get(&req.id);
            (
                parent.map(|m| m.bundle.clone()).unwrap_or_default(),
                parent.map(|m| m.container_identity).unwrap_or(0),
            )
        };
        self.exit_events
            .lock()
            .await
            .remove(&process_key(&req.id, Some(&req.exec_id)));
        self.execs.write().await.insert(
            process_key(&req.id, Some(&req.exec_id)),
            TaskMeta {
                bundle,
                stdin: req.stdin.clone(),
                stdout: req.stdout.clone(),
                stderr: req.stderr.clone(),
                terminal: req.terminal,
                pid,
                io_dir,
                streaming: self.cfg.streaming_stdio,
                oom_kill_seen: 0,
                device_claims: Vec::new(),
                container_identity,
            },
        );
        self.persist_runtime_state().await.map_err(rpc_other)?;
        self.send_event(TaskExecAdded {
            container_id: req.id,
            exec_id: req.exec_id,
            ..Default::default()
        })
        .await;
        Ok(Empty::new())
    }

    async fn connect(
        &self,
        _ctx: &TtrpcContext,
        req: ConnectRequest,
    ) -> TtrpcResult<ConnectResponse> {
        let pid = self
            .tasks
            .read()
            .await
            .get(&req.id)
            .map(|m| m.pid)
            .unwrap_or(0);
        Ok(ConnectResponse {
            shim_pid: std::process::id(),
            task_pid: pid,
            version: env!("CARGO_PKG_VERSION").into(),
            ..Default::default()
        })
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
        let exec_id = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id)
        };
        match self
            .call_agent(
                &vm,
                ContainerRequest::ResizePty {
                    id: req.id,
                    exec_id,
                    width: req.width,
                    height: req.height,
                },
            )
            .await
            .map_err(rpc_other)?
        {
            ContainerResponse::PtyResized => Ok(Empty::new()),
            other => Err(rpc_other(format!("unexpected resize response: {other:?}"))),
        }
    }

    async fn close_io(&self, _ctx: &TtrpcContext, req: CloseIORequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() {
            None
        } else {
            Some(req.exec_id)
        };
        match self
            .call_agent(
                &vm,
                ContainerRequest::CloseIo {
                    id: req.id,
                    exec_id,
                },
            )
            .await
            .map_err(rpc_other)?
        {
            ContainerResponse::IoClosed => Ok(Empty::new()),
            other => Err(rpc_other(format!(
                "unexpected close-io response: {other:?}"
            ))),
        }
    }

    async fn pids(&self, _ctx: &TtrpcContext, req: PidsRequest) -> TtrpcResult<PidsResponse> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        match self
            .call_agent(&vm, ContainerRequest::Pids { id: req.id })
            .await
            .map_err(rpc_other)?
        {
            ContainerResponse::Pids { pids } => Ok(PidsResponse {
                processes: pids
                    .into_iter()
                    .map(|pid| ProcessInfo {
                        pid,
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            }),
            other => Err(rpc_other(format!("unexpected pids response: {other:?}"))),
        }
    }

    async fn stats(&self, _ctx: &TtrpcContext, req: StatsRequest) -> TtrpcResult<StatsResponse> {
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        let response = self
            .call_agent(&vm, ContainerRequest::Stats { id: req.id })
            .await
            .map_err(rpc_other)?;
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
        let bytes = req
            .resources
            .as_ref()
            .map(|any| any.value.clone())
            .unwrap_or_default();
        if bytes.is_empty() {
            return Err(rpc_invalid("UpdateTaskRequest.resources is empty"));
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|e| rpc_invalid(format!("invalid LinuxResources JSON: {e}")))?;
        let resources = resource_limits_from_linux_resources(&value);
        let vm = self.ensure_sandbox(None).await.map_err(rpc_other)?;
        match self
            .call_agent(
                &vm,
                ContainerRequest::UpdateResources {
                    id: req.id,
                    resources,
                },
            )
            .await
            .map_err(rpc_other)?
        {
            ContainerResponse::ResourcesUpdated => Ok(Empty::new()),
            other => Err(rpc_other(format!("unexpected update response: {other:?}"))),
        }
    }
}

fn forward_events(publisher: RemotePublisher, namespace: String, mut rx: EventReceiver) {
    tokio::spawn(async move {
        while let Some((topic, event)) = rx.recv().await {
            if let Err(e) = publisher
                .publish(
                    ttrpc::context::Context::default(),
                    &topic,
                    &namespace,
                    event,
                )
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

fn timestamp_from_nanos(
    ns: i64,
) -> containerd_shim_protos::protobuf::well_known_types::timestamp::Timestamp {
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
    let mut throttle = Throttle::new();
    throttle.set_periods(stats.cpu_nr_periods);
    throttle.set_throttled_periods(stats.cpu_nr_throttled);
    throttle.set_throttled_time(stats.cpu_throttled_usec);
    let mut cpu = CPUStat::new();
    cpu.set_usage(usage);
    cpu.set_throttling(throttle);

    let mut mem_usage = MemoryEntry::new();
    mem_usage.set_limit(stats.memory_limit_bytes);
    mem_usage.set_usage(stats.memory_usage_bytes);
    mem_usage.set_max(stats.memory_peak_bytes);
    mem_usage.set_failcnt(stats.memory_events_max);
    let mut swap = MemoryEntry::new();
    let swap_usage = stats
        .memory_usage_bytes
        .saturating_add(stats.memory_swap_usage_bytes);
    let swap_limit = if stats.memory_limit_bytes == 0 || stats.memory_swap_limit_bytes == 0 {
        0
    } else {
        stats
            .memory_limit_bytes
            .saturating_add(stats.memory_swap_limit_bytes)
    };
    swap.set_limit(swap_limit);
    swap.set_usage(swap_usage);
    let mut memory = MemoryStat::new();
    memory.set_usage(mem_usage);
    memory.set_swap(swap);
    memory.set_cache(stats.memory_file_bytes);
    memory.set_rss(stats.memory_anon_bytes);
    memory.set_rss_huge(stats.memory_anon_thp_bytes);
    memory.set_mapped_file(stats.memory_file_mapped_bytes);
    memory.set_dirty(stats.memory_dirty_bytes);
    memory.set_writeback(stats.memory_writeback_bytes);
    memory.set_pg_fault(stats.memory_pgfault);
    memory.set_pg_maj_fault(stats.memory_pgmajfault);
    memory.set_inactive_anon(stats.memory_inactive_anon_bytes);
    memory.set_active_anon(stats.memory_active_anon_bytes);
    memory.set_inactive_file(stats.memory_total_inactive_file_bytes);
    memory.set_active_file(stats.memory_active_file_bytes);
    memory.set_unevictable(stats.memory_unevictable_bytes);
    // cgroup-v2 already reports hierarchical totals for this cgroup, so map
    // the same counters into containerd's legacy total_* fields as runc does.
    memory.set_total_cache(stats.memory_file_bytes);
    memory.set_total_rss(stats.memory_anon_bytes);
    memory.set_total_rss_huge(stats.memory_anon_thp_bytes);
    memory.set_total_mapped_file(stats.memory_file_mapped_bytes);
    memory.set_total_dirty(stats.memory_dirty_bytes);
    memory.set_total_writeback(stats.memory_writeback_bytes);
    memory.set_total_pg_fault(stats.memory_pgfault);
    memory.set_total_pg_maj_fault(stats.memory_pgmajfault);
    memory.set_total_inactive_anon(stats.memory_inactive_anon_bytes);
    memory.set_total_active_anon(stats.memory_active_anon_bytes);
    memory.set_total_inactive_file(stats.memory_total_inactive_file_bytes);
    memory.set_total_active_file(stats.memory_active_file_bytes);
    memory.set_total_unevictable(stats.memory_unevictable_bytes);

    let mut pids = PidsStat::new();
    pids.set_current(stats.pids_current);
    pids.set_limit(stats.pids_limit);

    let mut oom = MemoryOomControl::new();
    oom.set_oom_kill(stats.memory_events_oom_kill);

    let mut metrics = Metrics::new();
    metrics.set_cpu(cpu);
    metrics.set_memory(memory);
    metrics.set_pids(pids);
    metrics.set_memory_oom_control(oom);
    metrics
}

fn resource_limits_from_linux_resources(value: &Value) -> ResourceLimits {
    let unified = value
        .get("unified")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    ResourceLimits {
        cpu_quota: value.pointer("/cpu/quota").and_then(Value::as_i64),
        cpu_period: value.pointer("/cpu/period").and_then(Value::as_u64),
        cpu_shares: value.pointer("/cpu/shares").and_then(Value::as_u64),
        cpuset_cpus: value
            .pointer("/cpu/cpus")
            .and_then(Value::as_str)
            .map(str::to_string),
        cpuset_mems: value
            .pointer("/cpu/mems")
            .and_then(Value::as_str)
            .map(str::to_string),
        memory_limit_bytes: value.pointer("/memory/limit").and_then(Value::as_i64),
        memory_reservation_bytes: value.pointer("/memory/reservation").and_then(Value::as_i64),
        memory_swap_bytes: value.pointer("/memory/swap").and_then(Value::as_i64),
        pids_limit: value.pointer("/pids/limit").and_then(Value::as_i64),
        unified,
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
            let parse_i64 = |key: &str| {
                annotations
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(|v| v.parse::<i64>().ok())
            };
            let parse_u64 = |key: &str| {
                annotations
                    .get(key)
                    .and_then(Value::as_str)
                    .and_then(|v| v.parse::<u64>().ok())
            };
            if let Some(v) = parse_i64("io.kubernetes.cri.sandbox-cpu-quota") {
                resources.cpu_quota = Some(v);
            }
            if let Some(v) = parse_u64("io.kubernetes.cri.sandbox-cpu-period") {
                resources.cpu_period = Some(v);
            }
            if let Some(v) = parse_u64("io.kubernetes.cri.sandbox-cpu-shares") {
                resources.cpu_shares = Some(v);
            }
            if let Some(v) = parse_i64("io.kubernetes.cri.sandbox-memory") {
                resources.memory_limit_bytes = Some(v);
            }
            annotations
                .get("io.kubernetes.cri.sandbox-uid")
                .and_then(Value::as_str)
                .filter(|uid| {
                    !uid.is_empty() && uid.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                })
                .map(str::to_string)
        });
    let netns_path = spec
        .pointer("/linux/namespaces")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                let ty = item.get("type").and_then(Value::as_str)?;
                if ty != "network" {
                    return None;
                }
                item.get("path")
                    .and_then(Value::as_str)
                    .filter(|path| !path.is_empty())
                    .map(PathBuf::from)
            })
        });
    SandboxHints {
        resources,
        netns_path,
        pod_uid,
    }
}

fn vm_shape(
    default_vcpus: u8,
    default_memory_mib: u64,
    overhead_mib: u64,
    resources: &ResourceLimits,
) -> (u8, u64) {
    let requested_vcpus = match (resources.cpu_quota, resources.cpu_period) {
        (Some(quota), Some(period)) if quota > 0 && period > 0 => {
            let quota = quota as u64;
            quota
                .saturating_add(period - 1)
                .saturating_div(period)
                .clamp(1, 254) as u8
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
        .saturating_add(if resources.memory_limit_bytes.is_some_and(|v| v > 0) {
            overhead_mib
        } else {
            0
        });
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
    format!(
        "02:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        h[3], h[4], h[5], h[6], h[7]
    )
}

fn cni_suffix(group: &str) -> String {
    format!("{:016x}", stable_hash(group))[..6].to_string()
}

fn valid_iface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

async fn run_command(program: &str, args: &[String]) -> AnyResult<()> {
    let bin = resolve_host_bin(program);
    let out = tokio::process::Command::new(&bin)
        .args(args)
        .output()
        .await
        .with_context(|| format!("starting {bin} ({program})"))?;
    if !out.status.success() {
        bail!(
            "{} {} failed ({}): {}",
            bin,
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

async fn run_command_best_effort(program: &str, args: &[String]) {
    let bin = resolve_host_bin(program);
    let _ = tokio::process::Command::new(&bin).args(args).output().await;
}

async fn command_output(program: &str, args: &[String]) -> AnyResult<String> {
    let bin = resolve_host_bin(program);
    let out = tokio::process::Command::new(&bin)
        .args(args)
        .output()
        .await
        .with_context(|| format!("starting {bin} ({program})"))?;
    if !out.status.success() {
        bail!(
            "{} {} failed ({}): {}",
            bin,
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Prefer absolute host paths so k3s's trimmed PATH / busybox tooling cannot
/// make `nsenter`/`ip` spawn fail with a bare "starting nsenter" error.
fn resolve_host_bin(program: &str) -> String {
    for dir in [
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
        "/var/lib/rancher/k3s/data/current/bin",
    ] {
        let candidate = format!("{dir}/{program}");
        if std::path::Path::new(&candidate).exists() {
            return candidate;
        }
    }
    program.to_string()
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

fn parse_ip_destination(raw: &str, family: CniFamily) -> AnyResult<Option<(IpAddr, u8)>> {
    if raw == "default" || raw.is_empty() {
        return Ok(None);
    }
    let default_prefix = match family {
        CniFamily::Ipv4 => "32",
        CniFamily::Ipv6 => "128",
    };
    let (address, prefix) = raw.split_once('/').unwrap_or((raw, default_prefix));
    let address = address
        .parse::<IpAddr>()
        .with_context(|| format!("invalid {:?} route destination {raw:?}", family))?;
    if !family.matches(address) {
        bail!("route destination {address} does not match family {family:?}");
    }
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("invalid route prefix {raw:?}"))?;
    if prefix > family.max_prefix() {
        bail!("invalid {:?} route prefix {raw:?}", family);
    }
    Ok(Some((address, prefix)))
}

fn address_is_routable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_loopback() && !v4.is_link_local(),
        IpAddr::V6(v6) => {
            !v6.is_unspecified() && !v6.is_loopback() && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

async fn detect_additional_cni_interfaces(
    netns_path: &Path,
    primary: &str,
) -> AnyResult<Vec<String>> {
    let args = vec![
        format!("--net={}", netns_path.display()),
        "--".into(),
        "ip".into(),
        "-j".into(),
        "addr".into(),
        "show".into(),
    ];
    let text = command_output("nsenter", &args).await?;
    let links: Value = serde_json::from_str(&text).context("parsing CNI interface inventory")?;
    let mut extras = Vec::new();
    for link in links.as_array().into_iter().flatten() {
        let Some(name) = link.get("ifname").and_then(Value::as_str) else {
            continue;
        };
        if name == "lo" || name == primary {
            continue;
        }
        let routable = link
            .get("addr_info")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|info| {
                if info.get("scope").and_then(Value::as_str) == Some("link") {
                    return false;
                }
                info.get("local")
                    .and_then(Value::as_str)
                    .and_then(|v| v.parse::<IpAddr>().ok())
                    .is_some_and(address_is_routable)
            });
        if routable {
            extras.push(name.to_string());
        }
    }
    extras.sort();
    extras.dedup();
    Ok(extras)
}

async fn capture_cni_network(netns_path: &Path, interface: &str) -> AnyResult<CniNetwork> {
    if !netns_path.exists() {
        bail!(
            "CRI network namespace does not exist: {}",
            netns_path.display()
        );
    }
    if !valid_iface_name(interface) {
        bail!("invalid CNI interface name {interface:?}");
    }

    let addr_args = vec![
        format!("--net={}", netns_path.display()),
        "--".into(),
        "ip".into(),
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

    let mut addresses = Vec::new();
    for info in addr_info {
        let family = match info.get("family").and_then(Value::as_str) {
            Some("inet") => CniFamily::Ipv4,
            Some("inet6") => CniFamily::Ipv6,
            _ => continue,
        };
        if info.get("scope").and_then(Value::as_str) == Some("link") {
            continue;
        }
        let Some(raw) = info.get("local").and_then(Value::as_str) else {
            continue;
        };
        let address = raw
            .parse::<IpAddr>()
            .with_context(|| format!("parsing CNI address {raw:?}"))?;
        if !address_is_routable(address) || !family.matches(address) {
            continue;
        }
        let prefix_len = info
            .get("prefixlen")
            .and_then(Value::as_u64)
            .context("CNI address entry has no prefixlen")? as u8;
        if prefix_len > family.max_prefix() {
            bail!("CNI {family:?} prefix length {prefix_len} is invalid");
        }
        addresses.push(CniAddress {
            family,
            address,
            prefix_len,
        });
    }
    if addresses.is_empty() {
        bail!("CNI namespace has no routable IPv4/IPv6 address on {interface}");
    }
    addresses.sort_by_key(|a| (a.family, a.address));

    let mut routes = Vec::new();
    for family in [CniFamily::Ipv4, CniFamily::Ipv6] {
        let route_args = vec![
            format!("--net={}", netns_path.display()),
            "--".into(),
            "ip".into(),
            family.ip_flag().into(),
            "-j".into(),
            "route".into(),
            "show".into(),
        ];
        let route_text = command_output("nsenter", &route_args).await?;
        let route_json: Value = serde_json::from_str(&route_text)
            .with_context(|| format!("parsing CNI {:?} route output", family))?;
        for route in route_json.as_array().into_iter().flatten() {
            if route.get("dev").and_then(Value::as_str) != Some(interface) {
                continue;
            }
            let route_type = route
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("unicast");
            if route_type != "unicast" {
                continue;
            }
            let destination = parse_ip_destination(
                route
                    .get("dst")
                    .and_then(Value::as_str)
                    .unwrap_or("default"),
                family,
            )?;
            let gateway = route
                .get("gateway")
                .and_then(Value::as_str)
                .map(|v| v.parse::<IpAddr>())
                .transpose()
                .context("parsing CNI route gateway")?;
            if gateway.is_some_and(|gateway| !family.matches(gateway)) {
                bail!("CNI gateway family does not match route family {family:?}");
            }
            routes.push(CniRoute {
                family,
                destination,
                gateway,
            });
        }
    }
    // Link/local routes before defaults, with IPv4 first only for deterministic
    // logs/tests. The families themselves are configured independently.
    routes.sort_by_key(|route| (route.family, route.destination.is_none()));

    Ok(CniNetwork {
        addresses,
        mac,
        routes,
    })
}

fn route_command(route: &CniRoute) -> String {
    let destination = route
        .destination
        .map(|(ip, prefix)| format!("{ip}/{prefix}"))
        .unwrap_or_else(|| "default".into());
    let flag = route.family.ip_flag();
    match route.gateway {
        Some(gateway) => {
            format!("ip {flag} route replace {destination} via {gateway} dev \"$IFACE\"")
        }
        None => format!("ip {flag} route replace {destination} dev \"$IFACE\""),
    }
}

fn guest_network_command(network: &CniNetwork) -> AnyResult<String> {
    parse_mac(&network.mac)?;
    if network.addresses.is_empty() {
        bail!("CNI network contains no guest addresses");
    }
    let mut lines = vec![
        "set -eu".to_string(),
        "IFACE=\"$(for p in /sys/class/net/*; do n=${p##*/}; [ \"$n\" = lo ] && continue; echo \"$n\"; break; done)\"".into(),
        "[ -n \"$IFACE\" ]".into(),
        "ip link set dev \"$IFACE\" up".into(),
        "ip -4 addr flush dev \"$IFACE\" || true".into(),
        "ip -6 addr flush dev \"$IFACE\" scope global || true".into(),
        "ip -4 route flush dev \"$IFACE\" || true".into(),
        "ip -6 route flush dev \"$IFACE\" || true".into(),
    ];
    for address in &network.addresses {
        if !address.family.matches(address.address)
            || address.prefix_len > address.family.max_prefix()
        {
            bail!("invalid CNI address {:?}", address);
        }
        match address.family {
            CniFamily::Ipv4 => lines.push(format!(
                "ip -4 addr add {}/{} dev \"$IFACE\"",
                address.address, address.prefix_len
            )),
            CniFamily::Ipv6 => lines.push(format!(
                "ip -6 addr add {}/{} dev \"$IFACE\" nodad",
                address.address, address.prefix_len
            )),
        }
    }
    for route in &network.routes {
        lines.push(route_command(route));
    }
    lines.push("ip -4 addr show dev \"$IFACE\" || true".into());
    lines.push("ip -6 addr show dev \"$IFACE\" || true".into());
    lines.push("ip -4 route show || true".into());
    lines.push("ip -6 route show || true".into());
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
        run_netns_best_effort(
            &alias,
            "ip",
            &["link".into(), "delete".into(), cni_bridge.clone()],
        )
        .await;

        run_command(
            "ip",
            &[
                "link".into(),
                "add".into(),
                host_bridge.clone(),
                "type".into(),
                "bridge".into(),
            ],
        )
        .await?;
        run_command(
            "ip",
            &[
                "link".into(),
                "set".into(),
                host_bridge.clone(),
                "up".into(),
            ],
        )
        .await?;
        run_command(
            "ip",
            &[
                "link".into(),
                "add".into(),
                host_veth.clone(),
                "type".into(),
                "veth".into(),
                "peer".into(),
                "name".into(),
                cni_veth.clone(),
            ],
        )
        .await?;
        run_command(
            "ip",
            &[
                "link".into(),
                "set".into(),
                host_veth.clone(),
                "master".into(),
                host_bridge.clone(),
            ],
        )
        .await?;
        run_command(
            "ip",
            &["link".into(), "set".into(), host_veth.clone(), "up".into()],
        )
        .await?;
        run_command(
            "ip",
            &[
                "link".into(),
                "set".into(),
                cni_veth.clone(),
                "netns".into(),
                alias.clone(),
            ],
        )
        .await?;

        run_netns(
            &alias,
            "ip",
            &[
                "link".into(),
                "add".into(),
                cni_bridge.clone(),
                "type".into(),
                "bridge".into(),
            ],
        )
        .await?;
        run_netns(
            &alias,
            "ip",
            &["link".into(), "set".into(), cni_bridge.clone(), "up".into()],
        )
        .await?;
        run_netns(
            &alias,
            "ip",
            &[
                "link".into(),
                "set".into(),
                cni_veth.clone(),
                "master".into(),
                cni_bridge.clone(),
            ],
        )
        .await?;
        run_netns(
            &alias,
            "ip",
            &["link".into(), "set".into(), cni_veth.clone(), "up".into()],
        )
        .await?;

        // The guest takes over the CNI-assigned Pod IP and original endpoint
        // MAC. Keep the veth as a pure bridge port and give the port itself a
        // different local MAC so the bridge does not have a permanent local
        // FDB entry that collides with frames sourced by the guest's MAC.
        run_netns(
            &alias,
            "ip",
            &[
                "link".into(),
                "set".into(),
                interface.into(),
                "master".into(),
                cni_bridge.clone(),
            ],
        )
        .await?;
        run_netns(
            &alias,
            "ip",
            &[
                "-4".into(),
                "addr".into(),
                "flush".into(),
                "dev".into(),
                interface.into(),
            ],
        )
        .await?;
        run_netns_best_effort(
            &alias,
            "ip",
            &[
                "-6".into(),
                "addr".into(),
                "flush".into(),
                "dev".into(),
                interface.into(),
                "scope".into(),
                "global".into(),
            ],
        )
        .await;
        run_netns_best_effort(
            &alias,
            "ip",
            &[
                "-4".into(),
                "route".into(),
                "flush".into(),
                "dev".into(),
                interface.into(),
            ],
        )
        .await;
        run_netns_best_effort(
            &alias,
            "ip",
            &[
                "-6".into(),
                "route".into(),
                "flush".into(),
                "dev".into(),
                interface.into(),
            ],
        )
        .await;
        run_netns_best_effort(
            &alias,
            "ip",
            &["link".into(), "set".into(), interface.into(), "down".into()],
        )
        .await;
        run_netns(
            &alias,
            "ip",
            &[
                "link".into(),
                "set".into(),
                interface.into(),
                "address".into(),
                port_mac,
            ],
        )
        .await?;
        run_netns(
            &alias,
            "ip",
            &["link".into(), "set".into(), interface.into(), "up".into()],
        )
        .await?;
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
    run_netns_best_effort(
        alias,
        "ip",
        &[
            "link".into(),
            "set".into(),
            interface.clone(),
            "nomaster".into(),
        ],
    )
    .await;
    run_netns_best_effort(
        alias,
        "ip",
        &[
            "link".into(),
            "set".into(),
            interface.clone(),
            "down".into(),
        ],
    )
    .await;
    run_netns_best_effort(
        alias,
        "ip",
        &[
            "link".into(),
            "set".into(),
            interface.clone(),
            "address".into(),
            bridge.network.mac.clone(),
        ],
    )
    .await;
    run_netns_best_effort(
        alias,
        "ip",
        &["link".into(), "set".into(), interface.clone(), "up".into()],
    )
    .await;
    run_netns_best_effort(
        alias,
        "ip",
        &[
            "-4".into(),
            "addr".into(),
            "flush".into(),
            "dev".into(),
            interface.clone(),
        ],
    )
    .await;
    run_netns_best_effort(
        alias,
        "ip",
        &[
            "-6".into(),
            "addr".into(),
            "flush".into(),
            "dev".into(),
            interface.clone(),
            "scope".into(),
            "global".into(),
        ],
    )
    .await;
    run_netns_best_effort(
        alias,
        "ip",
        &[
            "-4".into(),
            "route".into(),
            "flush".into(),
            "dev".into(),
            interface.clone(),
        ],
    )
    .await;
    run_netns_best_effort(
        alias,
        "ip",
        &[
            "-6".into(),
            "route".into(),
            "flush".into(),
            "dev".into(),
            interface.clone(),
        ],
    )
    .await;

    for address in &bridge.network.addresses {
        let mut args = vec![
            address.family.ip_flag().into(),
            "addr".into(),
            "add".into(),
            format!("{}/{}", address.address, address.prefix_len),
            "dev".into(),
            interface.clone(),
        ];
        if address.family == CniFamily::Ipv6 {
            args.push("nodad".into());
        }
        run_netns_best_effort(alias, "ip", &args).await;
    }

    for route in &bridge.network.routes {
        let destination = route
            .destination
            .map(|(ip, prefix)| format!("{ip}/{prefix}"))
            .unwrap_or_else(|| "default".into());
        let mut args = vec![
            route.family.ip_flag().into(),
            "route".into(),
            "replace".into(),
            destination,
        ];
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
    run_command_best_effort(
        "ip",
        &["link".into(), "delete".into(), bridge.host_veth.clone()],
    )
    .await;
    run_command_best_effort(
        "ip",
        &["link".into(), "delete".into(), bridge.host_bridge.clone()],
    )
    .await;
    run_command_best_effort(
        "umount",
        &[
            "-l".into(),
            bridge.netns_mount.to_string_lossy().into_owned(),
        ],
    )
    .await;
    let _ = tokio::fs::remove_file(&bridge.netns_mount).await;
}

fn find_block_rdev_under(root: &Path, major: u64, minor: u64, depth: usize) -> Option<PathBuf> {
    if depth == 0 {
        return None;
    }
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.file_type().is_block_device() {
            let rdev = meta.rdev();
            if libc::major(rdev as libc::dev_t) as u64 == major
                && libc::minor(rdev as libc::dev_t) as u64 == minor
            {
                return Some(path);
            }
        } else if meta.is_dir() {
            if let Some(found) = find_block_rdev_under(&path, major, minor, depth - 1) {
                return Some(found);
            }
        }
    }
    None
}

fn host_block_path_for_rdev(major: u64, minor: u64) -> Option<PathBuf> {
    let text = std::fs::read_to_string(format!("/sys/dev/block/{major}:{minor}/uevent")).ok()?;
    let devname = text
        .lines()
        .find_map(|line| line.strip_prefix("DEVNAME="))?;
    let path = PathBuf::from("/dev").join(devname);
    std::fs::metadata(&path)
        .ok()
        .filter(|m| m.file_type().is_block_device())
        .map(|_| path)
}

fn is_builtin_guest_char_device(path: &str) -> bool {
    matches!(
        path,
        "/dev/null"
            | "/dev/zero"
            | "/dev/full"
            | "/dev/random"
            | "/dev/urandom"
            | "/dev/tty"
            | "/dev/console"
            | "/dev/ptmx"
    )
}

fn looks_like_pci_bdf(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 12
        && b[4] == b':'
        && b[7] == b':'
        && b[10] == b'.'
        && b.iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 4 | 7 | 10) || c.is_ascii_hexdigit())
}

fn valid_pci_bdf(name: &str) -> bool {
    if !looks_like_pci_bdf(name) {
        return false;
    }
    let Ok(_domain) = u16::from_str_radix(&name[0..4], 16) else {
        return false;
    };
    let Ok(_bus) = u8::from_str_radix(&name[5..7], 16) else {
        return false;
    };
    let Ok(slot) = u8::from_str_radix(&name[8..10], 16) else {
        return false;
    };
    let Ok(function) = u8::from_str_radix(&name[11..12], 16) else {
        return false;
    };
    slot <= 0x1f && function <= 7
}

fn pci_driver_name(bdf: &str) -> Option<String> {
    if !valid_pci_bdf(bdf) {
        return None;
    }
    std::fs::canonicalize(format!("/sys/bus/pci/devices/{bdf}/driver"))
        .ok()
        .and_then(|p| p.file_name().map(|v| v.to_string_lossy().into_owned()))
}

fn iommu_group_info(bdf: &str) -> AnyResult<Option<(u32, Vec<String>)>> {
    if !valid_pci_bdf(bdf) {
        bail!("invalid PCI BDF {bdf:?}");
    }
    let group_link = PathBuf::from(format!("/sys/bus/pci/devices/{bdf}/iommu_group"));
    let group_path = match std::fs::canonicalize(&group_link) {
        Ok(path) => path,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("resolving IOMMU group for {bdf}")),
    };
    let group_id = group_path
        .file_name()
        .and_then(|v| v.to_str())
        .context("IOMMU group path has no numeric basename")?
        .parse::<u32>()
        .context("parsing IOMMU group id")?;
    let mut members = Vec::new();
    for entry in std::fs::read_dir(group_path.join("devices"))
        .with_context(|| format!("reading IOMMU group {group_id} members"))?
    {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if valid_pci_bdf(&name) {
            members.push(name);
        }
    }
    members.sort();
    members.dedup();
    if !members.iter().any(|v| v == bdf) {
        bail!("IOMMU group {group_id} does not contain requested function {bdf}");
    }
    Ok(Some((group_id, members)))
}

fn pci_bdf_for_host_device(major: u64, minor: u64) -> Option<String> {
    let path = std::fs::canonicalize(format!("/sys/dev/char/{major}:{minor}/device")).ok()?;
    for component in path.components().rev() {
        let name = component.as_os_str().to_string_lossy();
        if valid_pci_bdf(&name) {
            return Some(name.into_owned().to_ascii_lowercase());
        }
    }
    None
}

fn rpc_status(code: ttrpc::Code, message: impl Into<String>) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(code, message.into()))
}
fn rpc_other(e: impl std::fmt::Display) -> ttrpc::Error {
    rpc_status(ttrpc::Code::UNKNOWN, e.to_string())
}
fn rpc_invalid(e: impl Into<String>) -> ttrpc::Error {
    rpc_status(ttrpc::Code::INVALID_ARGUMENT, e)
}

async fn pod_group_from_bundle(bundle: &str) -> Option<String> {
    if bundle.is_empty() {
        return None;
    }
    let text = tokio::fs::read_to_string(Path::new(bundle).join("config.json"))
        .await
        .ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    let ann = v.get("annotations")?.as_object()?;
    for key in [
        "io.containerd.runc.v2.group",
        "io.kubernetes.cri.sandbox-id",
    ] {
        if let Some(group) = ann
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
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
    let Ok(v) = serde_json::from_str::<Value>(config_json) else {
        return false;
    };
    let Some(namespaces) = v.pointer("/linux/namespaces").and_then(Value::as_array) else {
        return false;
    };
    namespaces.iter().any(|ns| {
        ns.get("type").and_then(Value::as_str) == Some("pid")
            && ns
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|p| !p.is_empty())
    })
}

fn safe_name(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if out.len() > 63 {
        out.truncate(63);
    }
    if out.is_empty() {
        "sandbox".into()
    } else {
        out
    }
}

async fn copy_contents(src: &Path, dst: &Path) -> AnyResult<()> {
    let status = tokio::process::Command::new("cp")
        .arg("-a")
        .arg("--reflink=auto")
        .arg(src.join("."))
        .arg(dst)
        .status()
        .await
        .context("running cp for container rootfs")?;
    if !status.success() {
        bail!("copying container rootfs failed with {status}");
    }
    Ok(())
}

fn kubelet_guest_source(source: &Path, pod_uid: &str) -> Option<PathBuf> {
    let root = PathBuf::from("/var/lib/kubelet/pods").join(pod_uid);
    for (host_base, guest_base) in [
        (root.join("volumes"), "/run/fluxvm/kubelet/volumes"),
        (
            root.join("volume-subpaths"),
            "/run/fluxvm/kubelet/volume-subpaths",
        ),
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
    let Some(mounts) = spec.get_mut("mounts").and_then(Value::as_array_mut) else {
        return Ok(());
    };
    for (idx, mount) in mounts.iter_mut().enumerate() {
        let is_bind = mount.get("type").and_then(Value::as_str) == Some("bind")
            || mount
                .get("options")
                .and_then(Value::as_array)
                .is_some_and(|o| {
                    o.iter()
                        .any(|v| v.as_str() == Some("bind") || v.as_str() == Some("rbind"))
                });
        if !is_bind {
            continue;
        }
        let Some(source) = mount
            .get("source")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            continue;
        };
        let source_path = PathBuf::from(&source);
        if !source_path.exists() {
            continue;
        }
        let meta = std::fs::metadata(&source_path)
            .with_context(|| format!("inspecting OCI bind source {}", source_path.display()))?;
        let kind = meta.file_type();
        if kind.is_block_device() {
            bail!(
                "OCI bind source {} is a raw block device; FluxVM secure containers require VMM block-device hotplug for raw block volumes",
                source_path.display()
            );
        }
        if kind.is_char_device() || kind.is_fifo() || kind.is_socket() {
            bail!(
                "OCI bind source {} is a special host file and cannot be snapshotted safely into the FluxVM guest",
                source_path.display()
            );
        }

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
            if let Some(parent) = host.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
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
    fn dual_stack_route_and_address_rendering() {
        let network = CniNetwork {
            addresses: vec![
                CniAddress {
                    family: CniFamily::Ipv4,
                    address: IpAddr::V4(Ipv4Addr::new(10, 244, 1, 9)),
                    prefix_len: 24,
                },
                CniAddress {
                    family: CniFamily::Ipv6,
                    address: IpAddr::V6("fd00::9".parse::<Ipv6Addr>().unwrap()),
                    prefix_len: 64,
                },
            ],
            mac: "02:11:22:33:44:55".into(),
            routes: vec![
                CniRoute {
                    family: CniFamily::Ipv4,
                    destination: None,
                    gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 244, 1, 1))),
                },
                CniRoute {
                    family: CniFamily::Ipv6,
                    destination: None,
                    gateway: Some(IpAddr::V6("fd00::1".parse::<Ipv6Addr>().unwrap())),
                },
            ],
        };
        let command = guest_network_command(&network).unwrap();
        assert!(command.contains("ip -4 addr add 10.244.1.9/24"));
        assert!(command.contains("ip -6 addr add fd00::9/64"));
        assert!(command.contains("ip -4 route replace default via 10.244.1.1"));
        assert!(command.contains("ip -6 route replace default via fd00::1"));
    }

    #[test]
    fn route_parser_rejects_family_mismatch() {
        assert!(parse_ip_destination("10.0.0.0/24", CniFamily::Ipv6).is_err());
        assert!(parse_ip_destination("fd00::/64", CniFamily::Ipv4).is_err());
    }

    #[test]
    fn recovery_journal_rejects_unknown_version_shape() {
        let text = r#"{"version":99,"sandbox":null,"tasks":{},"execs":{}}"#;
        let state: RuntimeStateJournal = serde_json::from_str(text).unwrap();
        assert_eq!(state.version, 99);
        assert_ne!(state.version, RUNTIME_STATE_VERSION);
    }

    #[test]
    fn process_keys_separate_init_and_exec() {
        assert_eq!(process_key("c1", None), "c1");
        assert_eq!(process_key("c1", Some("e1")), "c1\0e1");
        assert_ne!(process_key("c1", None), process_key("c1", Some("e1")));
    }

    #[test]
    fn kubelet_volume_source_maps_only_current_pod() {
        let uid = "11111111-2222-3333-4444-555555555555";
        let src = Path::new(
            "/var/lib/kubelet/pods/11111111-2222-3333-4444-555555555555/volumes/kubernetes.io~empty-dir/data/file",
        );
        assert_eq!(
            kubelet_guest_source(src, uid).unwrap(),
            PathBuf::from("/run/fluxvm/kubelet/volumes/kubernetes.io~empty-dir/data/file")
        );
        let other =
            Path::new("/var/lib/kubelet/pods/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/volumes/x");
        assert!(kubelet_guest_source(other, uid).is_none());
    }

    #[test]
    fn resource_update_parser_keeps_swap_reservation_and_unified() {
        let value = json!({
            "memory": {"limit": 256, "reservation": 128, "swap": 512},
            "unified": {"memory.high": "192", "memory.oom.group": "1"}
        });
        let r = resource_limits_from_linux_resources(&value);
        assert_eq!(r.memory_limit_bytes, Some(256));
        assert_eq!(r.memory_reservation_bytes, Some(128));
        assert_eq!(r.memory_swap_bytes, Some(512));
        assert_eq!(
            r.unified.get("memory.high").map(String::as_str),
            Some("192")
        );
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
        tokio::fs::write(
            td.join("config.json"),
            r#"{"annotations":{"io.kubernetes.cri.sandbox-id":"pod123"}}"#,
        )
        .await
        .unwrap();
        assert_eq!(
            pod_group_from_bundle(td.to_str().unwrap()).await.as_deref(),
            Some("pod123")
        );
        let _ = tokio::fs::remove_dir_all(td).await;
    }

    #[tokio::test]
    async fn grouping_reads_runc_v2_group_annotation() {
        let td = std::env::temp_dir().join(format!("fluxvm-shim-group-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&td).await;
        tokio::fs::create_dir_all(&td).await.unwrap();
        tokio::fs::write(
            td.join("config.json"),
            r#"{"annotations":{"io.containerd.runc.v2.group":"sandbox-abc","io.kubernetes.cri.sandbox-id":"other"}}"#,
        )
        .await
        .unwrap();
        assert_eq!(
            pod_group_from_bundle(td.to_str().unwrap()).await.as_deref(),
            Some("sandbox-abc")
        );
        let _ = tokio::fs::remove_dir_all(td).await;
    }

    #[tokio::test]
    async fn rejects_special_host_bind_sources() {
        let td =
            std::env::temp_dir().join(format!("fluxvm-special-bind-test-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&td).await;
        tokio::fs::create_dir_all(&td).await.unwrap();
        let socket = td.join("host.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let mut spec = json!({"mounts":[{"type":"bind","source":socket,"destination":"/run/host.sock","options":["bind"]}]});
        let error = stage_bind_mounts(
            &mut spec,
            &td.join("ctr"),
            "/run/fluxvm/pod/containers/c",
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains("special host file"));
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
        stage_bind_mounts(
            &mut spec,
            &td.join("ctr"),
            "/run/fluxvm/pod/containers/c",
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            spec["mounts"][0]["source"],
            "/run/fluxvm/pod/containers/c/mounts/0"
        );
        assert_eq!(
            tokio::fs::read_to_string(td.join("ctr/mounts/0"))
                .await
                .unwrap(),
            "hello"
        );
        let _ = tokio::fs::remove_dir_all(td).await;
    }
}

#[tokio::main]
async fn main() {
    // Secure Containers run workloads inside a FluxVM guest, not as host
    // children of this shim. The default containerd-shim SIGCHLD reaper
    // waitpid(-1) races with tokio::process (and CNI helpers), surfacing as
    // "No child processes (os error 10)" when spawning `ip`/`nsenter`.
    let cfg = Config {
        no_reaper: true,
        ..Config::default()
    };
    run::<Service>(RUNTIME_ID, Some(cfg)).await;
}

#[cfg(test)]
mod set8_device_tests {
    use super::*;
    #[test]
    fn pci_bdf_shape_is_strict() {
        assert!(looks_like_pci_bdf("0000:65:00.0"));
        assert!(looks_like_pci_bdf("abcd:ef:12.3"));
        assert!(!looks_like_pci_bdf("65:00.0"));
        assert!(!looks_like_pci_bdf("0000:gg:00.0"));
    }
    #[test]
    fn builtin_guest_devices_are_not_vfio_candidates() {
        assert!(is_builtin_guest_char_device("/dev/null"));
        assert!(!is_builtin_guest_char_device("/dev/nvidia0"));
    }
}

#[cfg(test)]
mod set9_device_lifecycle_tests {
    use super::*;

    #[test]
    fn strict_bdf_parser_rejects_out_of_range_slot_and_function() {
        assert!(valid_pci_bdf("0000:65:1f.7"));
        assert!(!valid_pci_bdf("0000:65:20.0"));
        assert!(!valid_pci_bdf("0000:65:00.8"));
        assert!(!valid_pci_bdf("../0:65:00.0"));
    }

    #[test]
    fn device_owner_reference_counting_is_deterministic() {
        let mut d = DeviceAttachment::Vfio {
            bdf: "0000:65:00.0".into(),
            guest_path: "/dev/nvidia0".into(),
            device_id: "fvvfio123".into(),
            iommu_group: Some(42),
            owners: Some(vec!["container-a".into()]),
        };
        assert!(d.add_owner("container-b"));
        assert!(!d.add_owner("container-b"));
        assert_eq!(
            d.owners().unwrap(),
            &vec!["container-a".to_string(), "container-b".to_string()]
        );
        assert!(d.remove_owner("container-a"));
        assert!(!d.is_releasable());
        assert!(d.remove_owner("container-b"));
        assert!(d.is_releasable());
    }

    #[test]
    fn legacy_set8_attachment_without_owners_stays_pinned() {
        let mut d = DeviceAttachment::Block {
            host_path: "/dev/mapper/example".into(),
            serial: "fluxvm-test".into(),
            node_name: "fvblktest".into(),
            device_id: "fvdevtest".into(),
            host_major: None,
            host_minor: None,
            owners: None,
        };
        assert!(!d.add_owner("new-container"));
        assert!(!d.remove_owner("new-container"));
        assert!(!d.is_releasable());
    }
}

#[cfg(test)]
mod set9_journal_compat_tests {
    use super::*;

    #[test]
    fn set8_journal_without_owner_or_stats_fields_deserializes_pinned() {
        let text = r#"{
          "version":1,
          "sandbox":{
            "vm_id":"00000000-0000-0000-0000-000000000001",
            "vm_name":"pod",
            "ready":true,
            "share_dir":"/run/fluxvm/containerd/share",
            "cni":null,
            "kubelet_mounts":[],
            "devices":[{
              "kind":"block",
              "host_path":"/dev/mapper/example",
              "serial":"fluxvm-old",
              "node_name":"fvblkold",
              "device_id":"fvdevold"
            }]
          },
          "tasks":{},
          "execs":{}
        }"#;
        let state: RuntimeStateJournal = serde_json::from_str(text).unwrap();
        assert_eq!(state.device_stats.attach_total, 0);
        let d = &state.sandbox.unwrap().devices[0];
        assert!(d.owners().is_none());
        assert!(!d.is_releasable());
    }
}
