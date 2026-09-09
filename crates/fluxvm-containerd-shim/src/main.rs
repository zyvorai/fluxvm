// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! containerd runtime-v2 shim for FluxVM secure containers.
//!
//! v0.1 contract:
//! * one FluxVM QEMU VM per containerd shim group / Kubernetes Pod sandbox;
//! * OCI snapshot rootfs is copied into the Pod's virtiofs share;
//! * bind mounts (ConfigMap/Secret/etc.) are snapshotted into that share;
//! * process lifecycle is executed by `fluxvm-container-agent` over VSOCK;
//! * no host kernel is shared with the workload.
//!
//! The copy/snapshot approach is intentionally conservative. It gives a
//! deterministic first implementation without requiring dynamic virtiofs
//! hotplug. PVC write-through, CNI plumbing, TTY and full OCI security parity
//! are documented follow-ups rather than silently pretending to work.

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
    publisher::RemotePublisher,
};
use containerd_shim_protos::{
    api::{CloseIORequest, ConnectRequest, ConnectResponse, DeleteResponse, PidsRequest, PidsResponse,
          ResizePtyRequest, StatsRequest, StatsResponse, UpdateTaskRequest},
    protobuf::EnumOrUnknown,
    shim_async::Task,
    ttrpc::{self, r#async::TtrpcContext},
};
use fluxvm_container_protocol::{ContainerIo, ContainerRequest, ContainerResponse, ContainerStatus};
use fluxvm_core::model::{VmRecord, VmStatus};
use fluxvm_guest_protocol::{AgentRequest, AgentResponse};
use log::warn;
use reqwest::{Client, Method};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::{Mutex, RwLock}};

const RUNTIME_ID: &str = "io.containerd.fluxvm.v2";
const GUEST_SHARE: &str = "/run/fluxvm/pod";

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
    boot_timeout_secs: u64,
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
            boot_timeout_secs: std::env::var("FLUXVM_CONTAINER_BOOT_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(90),
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
}

#[derive(Debug)]
struct Sandbox {
    vm: VmRecord,
    share_dir: PathBuf,
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
}

#[async_trait]
impl Shim for Service {
    type T = Service;

    async fn new(_runtime_id: &str, args: &Flags, _config: &mut Config) -> Self {
        let group = pod_group_from_bundle(&args.bundle).await.unwrap_or_else(|| args.id.clone());
        Self {
            exit: Arc::new(ExitSignal::default()),
            namespace: args.namespace.clone(),
            group,
            cfg: RuntimeConfig::default(),
            http: Client::new(),
            sandbox: Arc::new(Mutex::new(None)),
            tasks: Arc::new(RwLock::new(HashMap::new())),
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

    async fn create_task_service(&self, _publisher: RemotePublisher) -> Self::T {
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

    async fn ensure_sandbox(&self) -> AnyResult<VmRecord> {
        let mut guard = self.sandbox.lock().await;
        if let Some(s) = guard.as_ref() { return Ok(s.vm.clone()); }

        if !self.cfg.guest_image.exists() {
            bail!("secure-container guest image does not exist: {}", self.cfg.guest_image.display());
        }
        if !self.cfg.container_agent_binary.exists() {
            bail!("fluxvm-container-agent binary does not exist: {}", self.cfg.container_agent_binary.display());
        }
        let share_dir = self.cfg.state_dir.join(&self.namespace).join(&self.group).join("share");
        tokio::fs::create_dir_all(&share_dir).await?;
        let create = json!({
            "name": format!("ctr-{}", safe_name(&self.group)),
            "backend": "qemu",
            "image": self.cfg.guest_image,
            "vcpus": self.cfg.vcpus,
            "memory_mib": self.cfg.memory_mib,
            "network": {"mode": "user", "forwards": []},
            "cloud_init": {},
            "agent": {"enabled": true},
            "shared_folders": [{
                "host_path": share_dir,
                "guest_path": GUEST_SHARE,
                "read_only": false
            }]
        });
        let mut vm: VmRecord = self.api(Method::POST, "/v1/vms", Some(create)).await?.json().await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(self.cfg.boot_timeout_secs);
        loop {
            if vm.status == VmStatus::Running && fluxvm_vsock_client::ping(&vm, Duration::from_secs(2)).await.is_ok() {
                break;
            }
            if vm.status == VmStatus::Failed {
                bail!("FluxVM sandbox failed: {}", vm.error.as_deref().unwrap_or("unknown error"));
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("timed out waiting for FluxVM sandbox {}", vm.id);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            vm = self.api(Method::GET, &format!("/v1/vms/{}", vm.id), None).await?.json().await?;
        }
        self.bootstrap_container_agent(&vm).await?;
        *guard = Some(Sandbox { vm: vm.clone(), share_dir });
        Ok(vm)
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

    async fn sandbox_paths(&self, id: &str) -> AnyResult<(VmRecord, PathBuf, String)> {
        let vm = self.ensure_sandbox().await?;
        let guard = self.sandbox.lock().await;
        let sandbox = guard.as_ref().context("sandbox disappeared")?;
        let host = sandbox.share_dir.join("containers").join(safe_name(id));
        let guest = format!("{GUEST_SHARE}/containers/{}", safe_name(id));
        Ok((vm, host, guest))
    }

    async fn stage_rootfs_and_config(&self, req: &CreateTaskRequest) -> AnyResult<(VmRecord, String, ContainerIo)> {
        let (vm, host_ctr, guest_ctr) = self.sandbox_paths(&req.id).await?;
        let rootfs = host_ctr.join("rootfs");
        let mountpoint = self.cfg.state_dir.join(&self.namespace).join(&self.group).join("mounts").join(safe_name(&req.id));
        tokio::fs::create_dir_all(&rootfs).await?;
        tokio::fs::create_dir_all(&mountpoint).await?;
        for m in &req.rootfs {
            containerd_shim::asynchronous::util::mount_rootfs(m, &mountpoint)
                .await
                .map_err(|e| anyhow::anyhow!("mounting containerd rootfs: {e}"))?;
        }
        let copy_result = copy_contents(&mountpoint, &rootfs).await;
        let _ = tokio::process::Command::new("umount").args(["-l", mountpoint.to_string_lossy().as_ref()]).status().await;
        copy_result?;

        let config_path = Path::new(&req.bundle).join("config.json");
        let text = tokio::fs::read_to_string(&config_path).await.with_context(|| format!("reading {}", config_path.display()))?;
        let mut spec: Value = serde_json::from_str(&text)?;
        spec["root"]["path"] = Value::String(format!("{guest_ctr}/rootfs"));
        stage_bind_mounts(&mut spec, &host_ctr, &guest_ctr).await?;
        let io = self.prepare_io(&req.id, &req.stdin, &req.stdout, &req.stderr, req.terminal, &host_ctr, &guest_ctr).await?;
        Ok((vm, serde_json::to_string(&spec)?, io))
    }

    async fn prepare_io(&self, id: &str, stdin: &str, stdout: &str, stderr: &str, terminal: bool, host_ctr: &Path, guest_ctr: &str) -> AnyResult<ContainerIo> {
        if terminal { bail!("TTY containers are not supported by secure-containers v0.1"); }
        let io_dir = host_ctr.join("io");
        tokio::fs::create_dir_all(&io_dir).await?;
        let mut guest = ContainerIo::default();
        if !stdout.is_empty() {
            let p = io_dir.join("stdout.fifo"); mkfifo(&p)?;
            guest.stdout = Some(format!("{guest_ctr}/io/stdout.fifo"));
            spawn_fifo_to_fifo(p, PathBuf::from(stdout), format!("{id}:stdout"));
        }
        if !stderr.is_empty() {
            let p = io_dir.join("stderr.fifo"); mkfifo(&p)?;
            guest.stderr = Some(format!("{guest_ctr}/io/stderr.fifo"));
            spawn_fifo_to_fifo(p, PathBuf::from(stderr), format!("{id}:stderr"));
        }
        if !stdin.is_empty() {
            let p = io_dir.join("stdin.fifo"); mkfifo(&p)?;
            guest.stdin = Some(format!("{guest_ctr}/io/stdin.fifo"));
            spawn_fifo_to_fifo(PathBuf::from(stdin), p, format!("{id}:stdin"));
        }
        Ok(guest)
    }

    async fn call_agent(&self, vm: &VmRecord, req: ContainerRequest) -> AnyResult<ContainerResponse> {
        match fluxvm_container_client::call(vm, req, Duration::from_secs(60)).await? {
            ContainerResponse::Error { message } => bail!("guest container-agent: {message}"),
            response => Ok(response),
        }
    }

    async fn destroy_sandbox(&self) -> AnyResult<()> {
        let mut guard = self.sandbox.lock().await;
        if let Some(s) = guard.take() {
            let _ = self.api(Method::DELETE, &format!("/v1/vms/{}", s.vm.id), None).await;
            let root = self.cfg.state_dir.join(&self.namespace).join(&self.group);
            let _ = tokio::fs::remove_dir_all(root).await;
        }
        Ok(())
    }
}

#[async_trait]
impl Task for Service {
    async fn create(&self, _ctx: &TtrpcContext, req: CreateTaskRequest) -> TtrpcResult<CreateTaskResponse> {
        let (vm, config_json, io) = self.stage_rootfs_and_config(&req).await.map_err(rpc_other)?;
        let response = self.call_agent(&vm, ContainerRequest::Create { id: req.id.clone(), config_json, io }).await.map_err(rpc_other)?;
        let pid = match response { ContainerResponse::Created { pid } => pid, other => return Err(rpc_other(format!("unexpected create response: {other:?}"))) };
        self.tasks.write().await.insert(req.id.clone(), TaskMeta {
            bundle: req.bundle.clone(), stdin: req.stdin.clone(), stdout: req.stdout.clone(), stderr: req.stderr.clone(), terminal: req.terminal, pid,
        });
        Ok(CreateTaskResponse { pid, ..Default::default() })
    }

    async fn start(&self, _ctx: &TtrpcContext, req: StartRequest) -> TtrpcResult<StartResponse> {
        let vm = self.ensure_sandbox().await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id.clone()) };
        let response = self.call_agent(&vm, ContainerRequest::Start { id: req.id.clone(), exec_id }).await.map_err(rpc_other)?;
        let pid = match response { ContainerResponse::Started { pid } => pid, other => return Err(rpc_other(format!("unexpected start response: {other:?}"))) };
        Ok(StartResponse { pid, ..Default::default() })
    }

    async fn state(&self, _ctx: &TtrpcContext, req: StateRequest) -> TtrpcResult<StateResponse> {
        let vm = self.ensure_sandbox().await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id.clone()) };
        let response = self.call_agent(&vm, ContainerRequest::State { id: req.id.clone(), exec_id }).await.map_err(rpc_other)?;
        let (status, pid, exit_code, exited_at) = match response {
            ContainerResponse::State { status, pid, exit_code, exited_at_unix_nano, .. } => (status, pid, exit_code, exited_at_unix_nano),
            other => return Err(rpc_other(format!("unexpected state response: {other:?}"))),
        };
        let meta = self.tasks.read().await.get(&req.id).cloned();
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
        let vm = self.ensure_sandbox().await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id.clone()) };
        let response = self.call_agent(&vm, ContainerRequest::Wait { id: req.id, exec_id }).await.map_err(rpc_other)?;
        match response {
            ContainerResponse::Exited { exit_code, exited_at_unix_nano } => {
                let mut out = WaitResponse::new();
                out.exit_status = exit_code as u32;
                out.exited_at = Some(timestamp_from_nanos(exited_at_unix_nano)).into();
                Ok(out)
            }
            other => Err(rpc_other(format!("unexpected wait response: {other:?}"))),
        }
    }

    async fn kill(&self, _ctx: &TtrpcContext, req: KillRequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox().await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id) };
        self.call_agent(&vm, ContainerRequest::Kill { id: req.id, exec_id, signal: req.signal as i32, all: req.all }).await.map_err(rpc_other)?;
        Ok(Empty::new())
    }

    async fn pause(&self, _ctx: &TtrpcContext, req: PauseRequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox().await.map_err(rpc_other)?;
        self.call_agent(&vm, ContainerRequest::Pause { id: req.id }).await.map_err(rpc_other)?;
        Ok(Empty::new())
    }

    async fn resume(&self, _ctx: &TtrpcContext, req: ResumeRequest) -> TtrpcResult<Empty> {
        let vm = self.ensure_sandbox().await.map_err(rpc_other)?;
        self.call_agent(&vm, ContainerRequest::Resume { id: req.id }).await.map_err(rpc_other)?;
        Ok(Empty::new())
    }

    async fn delete(&self, _ctx: &TtrpcContext, req: DeleteRequest) -> TtrpcResult<DeleteResponse> {
        let vm = self.ensure_sandbox().await.map_err(rpc_other)?;
        let exec_id = if req.exec_id.is_empty() { None } else { Some(req.exec_id.clone()) };
        let state = self.call_agent(&vm, ContainerRequest::State { id: req.id.clone(), exec_id: exec_id.clone() }).await.ok();
        let _ = self.call_agent(&vm, ContainerRequest::Delete { id: req.id.clone(), exec_id: exec_id.clone(), force: true }).await;
        if exec_id.is_none() { self.tasks.write().await.remove(&req.id); }
        let (pid, code, ns) = match state {
            Some(ContainerResponse::State { pid, exit_code, exited_at_unix_nano, .. }) => (pid, exit_code.unwrap_or(0), exited_at_unix_nano.unwrap_or(0)),
            _ => (0, 0, 0),
        };
        let mut out = DeleteResponse::new();
        out.pid = pid;
        out.exit_status = code as u32;
        if ns > 0 { out.exited_at = Some(timestamp_from_nanos(ns)).into(); }
        Ok(out)
    }

    async fn exec(&self, _ctx: &TtrpcContext, req: ExecProcessRequest) -> TtrpcResult<Empty> {
        if req.terminal { return Err(rpc_unimplemented("TTY exec is not supported by secure-containers v0.1")); }
        let vm = self.ensure_sandbox().await.map_err(rpc_other)?;
        let bytes = req.spec.as_ref().map(|a| a.value.clone()).unwrap_or_default();
        if bytes.is_empty() { return Err(rpc_invalid("ExecProcessRequest.spec is empty")); }
        let process_json = String::from_utf8(bytes).map_err(|e| rpc_invalid(e.to_string()))?;
        let (_, host_ctr, guest_ctr) = self.sandbox_paths(&req.id).await.map_err(rpc_other)?;
        let io = self.prepare_io(&format!("{}-{}", req.id, req.exec_id), &req.stdin, &req.stdout, &req.stderr, false, &host_ctr, &guest_ctr).await.map_err(rpc_other)?;
        self.call_agent(&vm, ContainerRequest::Exec { id: req.id, exec_id: req.exec_id, process_json, io }).await.map_err(rpc_other)?;
        Ok(Empty::new())
    }

    async fn connect(&self, _ctx: &TtrpcContext, req: ConnectRequest) -> TtrpcResult<ConnectResponse> {
        let pid = self.tasks.read().await.get(&req.id).map(|m| m.pid).unwrap_or(0);
        Ok(ConnectResponse { shim_pid: std::process::id(), task_pid: pid, version: env!("CARGO_PKG_VERSION").into(), ..Default::default() })
    }

    async fn shutdown(&self, _ctx: &TtrpcContext, _req: ShutdownRequest) -> TtrpcResult<Empty> {
        if self.tasks.read().await.is_empty() {
            let _ = self.destroy_sandbox().await;
            self.exit.signal();
        }
        Ok(Empty::new())
    }

    async fn resize_pty(&self, _ctx: &TtrpcContext, _req: ResizePtyRequest) -> TtrpcResult<Empty> { Err(rpc_unimplemented("TTY is not supported")) }
    async fn close_io(&self, _ctx: &TtrpcContext, _req: CloseIORequest) -> TtrpcResult<Empty> { Ok(Empty::new()) }
    async fn pids(&self, _ctx: &TtrpcContext, _req: PidsRequest) -> TtrpcResult<PidsResponse> { Ok(PidsResponse::new()) }
    async fn stats(&self, _ctx: &TtrpcContext, _req: StatsRequest) -> TtrpcResult<StatsResponse> { Err(rpc_unimplemented("container stats are not implemented in v0.1")) }
    async fn update(&self, _ctx: &TtrpcContext, _req: UpdateTaskRequest) -> TtrpcResult<Empty> { Err(rpc_unimplemented("live container resource updates are not implemented in v0.1")) }
}

fn map_status(status: ContainerStatus) -> Status {
    match status {
        ContainerStatus::Created => Status::CREATED,
        ContainerStatus::Running => Status::RUNNING,
        ContainerStatus::Paused => Status::PAUSED,
        ContainerStatus::Stopped => Status::STOPPED,
    }
}

fn timestamp_from_nanos(ns: i128) -> containerd_shim_protos::protobuf::well_known_types::timestamp::Timestamp {
    let mut ts = containerd_shim_protos::protobuf::well_known_types::timestamp::Timestamp::new();
    ts.seconds = ns.div_euclid(1_000_000_000) as i64;
    ts.nanos = ns.rem_euclid(1_000_000_000) as i32;
    ts
}

fn rpc_status(code: ttrpc::Code, message: impl Into<String>) -> ttrpc::Error {
    ttrpc::Error::RpcStatus(ttrpc::get_status(code, message.into()))
}
fn rpc_other(e: impl std::fmt::Display) -> ttrpc::Error { rpc_status(ttrpc::Code::UNKNOWN, e.to_string()) }
fn rpc_invalid(e: impl Into<String>) -> ttrpc::Error { rpc_status(ttrpc::Code::INVALID_ARGUMENT, e) }
fn rpc_unimplemented(e: impl Into<String>) -> ttrpc::Error { rpc_status(ttrpc::Code::UNIMPLEMENTED, e) }

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

async fn stage_bind_mounts(spec: &mut Value, host_ctr: &Path, guest_ctr: &str) -> AnyResult<()> {
    let Some(mounts) = spec.get_mut("mounts").and_then(Value::as_array_mut) else { return Ok(()); };
    for (idx, mount) in mounts.iter_mut().enumerate() {
        let is_bind = mount.get("type").and_then(Value::as_str) == Some("bind")
            || mount.get("options").and_then(Value::as_array).is_some_and(|o| o.iter().any(|v| v.as_str() == Some("bind") || v.as_str() == Some("rbind")));
        if !is_bind { continue; }
        let Some(source) = mount.get("source").and_then(Value::as_str).map(str::to_string) else { continue; };
        let source_path = PathBuf::from(&source);
        if !source_path.exists() { continue; }
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

fn mkfifo(path: &Path) -> AnyResult<()> {
    if path.exists() { let _ = std::fs::remove_file(path); }
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
        bail!("mkfifo {}: {}", path.display(), std::io::Error::last_os_error());
    }
    Ok(())
}

fn spawn_fifo_to_fifo(source: PathBuf, destination: PathBuf, label: String) {
    tokio::spawn(async move {
        let result: AnyResult<()> = async {
            let mut src = tokio::fs::OpenOptions::new().read(true).open(&source).await
                .with_context(|| format!("opening relay source {}", source.display()))?;
            let mut dst = tokio::fs::OpenOptions::new().write(true).open(&destination).await
                .with_context(|| format!("opening relay destination {}", destination.display()))?;
            let mut buf = [0u8; 32 * 1024];
            loop {
                let n = src.read(&mut buf).await?;
                if n == 0 { break; }
                dst.write_all(&buf[..n]).await?;
                dst.flush().await?;
            }
            Ok(())
        }.await;
        if let Err(e) = result { warn!("stdio relay {label} stopped: {e:#}"); }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

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
        stage_bind_mounts(&mut spec, &td.join("ctr"), "/run/fluxvm/pod/containers/c").await.unwrap();
        assert_eq!(spec["mounts"][0]["source"], "/run/fluxvm/pod/containers/c/mounts/0");
        assert_eq!(tokio::fs::read_to_string(td.join("ctr/mounts/0")).await.unwrap(), "hello");
        let _ = tokio::fs::remove_dir_all(td).await;
    }
}

#[tokio::main]
async fn main() {
    run::<Service>(RUNTIME_ID, None).await;
}
