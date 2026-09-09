// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Minimal in-guest OCI process supervisor for FluxVM's containerd runtime.
//!
//! Security boundary: the entire Kubernetes Pod/container sandbox runs inside
//! a hardware VM. This agent intentionally does not pretend to be a complete
//! runc replacement yet; it implements process lifecycle, chroot, uid/gid,
//! environment, cwd, signals and stdio inside the guest. Set 3 additionally
//! enforces supplementary groups, umask, rlimits and noNewPrivileges. OCI
//! Set 4 adds read-only/masked paths, read-only rootfs, OCI devices, Pod-scoped
//! sysctls and seccomp filters. Namespace creation and full device-cgroup parity
//! remain explicit follow-up hardening items in docs/secure-containers.md.

use anyhow::{Context, Result, bail};
use clap::Parser;
use fluxvm_container_protocol::{
    ContainerEnvelope, ContainerIo, ContainerRequest, ContainerResponse, ContainerStats,
    ContainerStatus, ResourceLimits, DEFAULT_CONTAINER_AGENT_PORT, MAX_MESSAGE_BYTES, decode_line,
    encode_line,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::fd::{AsRawFd, FromRawFd, RawFd},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

const TOKEN_FILE_PATH: &str = "/etc/fluxvm-guest-agent.token";
const CGROUP_ROOT: &str = "/sys/fs/cgroup/fluxvm-containers";

#[derive(Parser, Debug)]
#[command(name = "fluxvm-container-agent", version)]
struct Cli {
    #[arg(long, default_value_t = DEFAULT_CONTAINER_AGENT_PORT)]
    port: u32,
}

#[derive(Clone, Debug)]
struct ProcessRlimit {
    resource: u32,
    soft: libc::rlim_t,
    hard: libc::rlim_t,
}

#[derive(Clone, Debug, Default)]
struct CapabilitySets {
    bounding: u64,
    effective: u64,
    inheritable: u64,
    permitted: u64,
    ambient: u64,
}

#[derive(Clone, Debug)]
struct SeccompRule {
    action: u32,
    names: Vec<String>,
}

#[derive(Clone, Debug)]
struct SeccompProfile {
    default_action: u32,
    rules: Vec<SeccompRule>,
}

#[derive(Clone, Debug)]
struct ProcessSpec {
    rootfs: PathBuf,
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: String,
    uid: u32,
    gid: u32,
    additional_gids: Vec<u32>,
    no_new_privileges: bool,
    umask: Option<u32>,
    rlimits: Vec<ProcessRlimit>,
    capabilities: Option<CapabilitySets>,
    seccomp: Option<SeccompProfile>,
}

#[derive(Clone, Debug)]
struct ProcSnapshot {
    status: ContainerStatus,
    pid: u32,
    exit_code: Option<i32>,
    exited_at_unix_nano: Option<i64>,
    gate_fd: Option<RawFd>,
}

#[derive(Debug)]
struct ProcHandle {
    inner: Mutex<ProcSnapshot>,
    changed: Condvar,
}

impl ProcHandle {
    fn new_created(pid: u32, gate_fd: RawFd) -> Self {
        Self {
            inner: Mutex::new(ProcSnapshot {
                status: ContainerStatus::Created,
                pid,
                exit_code: None,
                exited_at_unix_nano: None,
                gate_fd: Some(gate_fd),
            }),
            changed: Condvar::new(),
        }
    }

    fn snapshot(&self) -> ProcSnapshot {
        self.inner.lock().expect("process state poisoned").clone()
    }

    fn start(&self) -> Result<u32> {
        let mut state = self.inner.lock().expect("process state poisoned");
        if state.status == ContainerStatus::Stopped {
            bail!("process already exited");
        }
        if state.status == ContainerStatus::Running || state.status == ContainerStatus::Paused {
            return Ok(state.pid);
        }
        let gate = state.gate_fd.take().context("process start gate is missing")?;
        let one = [1u8; 1];
        let rc = unsafe { libc::write(gate, one.as_ptr().cast(), one.len()) };
        unsafe { libc::close(gate) };
        if rc != 1 {
            bail!("releasing process start gate failed: {}", std::io::Error::last_os_error());
        }
        state.status = ContainerStatus::Running;
        self.changed.notify_all();
        Ok(state.pid)
    }

    fn signal(&self, signal: i32, process_group: bool) -> Result<()> {
        let state = self.inner.lock().expect("process state poisoned");
        if state.status == ContainerStatus::Stopped {
            return Ok(());
        }
        let target = if process_group { -(state.pid as i32) } else { state.pid as i32 };
        let rc = unsafe { libc::kill(target, signal) };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ESRCH) {
                return Err(e).context("sending signal to container process");
            }
        }
        Ok(())
    }

    fn set_status(&self, status: ContainerStatus) {
        let mut state = self.inner.lock().expect("process state poisoned");
        if state.status != ContainerStatus::Stopped {
            state.status = status;
            self.changed.notify_all();
        }
    }

    fn mark_exited(&self, code: i32) {
        let mut state = self.inner.lock().expect("process state poisoned");
        if let Some(fd) = state.gate_fd.take() {
            unsafe { libc::close(fd) };
        }
        state.status = ContainerStatus::Stopped;
        state.exit_code = Some(code);
        state.exited_at_unix_nano = Some(now_unix_nanos());
        self.changed.notify_all();
    }

    fn wait(&self) -> ProcSnapshot {
        let mut state = self.inner.lock().expect("process state poisoned");
        while state.status != ContainerStatus::Stopped {
            state = self.changed.wait(state).expect("process state poisoned");
        }
        state.clone()
    }
}

#[derive(Debug)]
struct ContainerEntry {
    rootfs: PathBuf,
    mounts: Vec<PathBuf>,
    cgroup_path: PathBuf,
    seccomp: Option<SeccompProfile>,
    init: Arc<ProcHandle>,
    execs: HashMap<String, Arc<ProcHandle>>,
}

type Registry = Arc<Mutex<HashMap<String, ContainerEntry>>>;
static REGISTRY: OnceLock<Registry> = OnceLock::new();

fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    run_server(cli.port)
}

fn run_server(port: u32) -> Result<()> {
    let expected_token = std::fs::read_to_string(TOKEN_FILE_PATH)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let listener_fd = unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            bail!("socket(AF_VSOCK): {}", std::io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        addr.svm_port = port;
        if libc::bind(
            fd,
            (&addr as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        ) != 0
        {
            libc::close(fd);
            bail!("bind(vsock:{port}): {}", std::io::Error::last_os_error());
        }
        if libc::listen(fd, 128) != 0 {
            libc::close(fd);
            bail!("listen(vsock:{port}): {}", std::io::Error::last_os_error());
        }
        set_cloexec(fd);
        fd
    };

    eprintln!("fluxvm-container-agent listening on vsock port {port}");
    loop {
        let fd = unsafe { libc::accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if fd < 0 {
            eprintln!("accept failed: {}", std::io::Error::last_os_error());
            continue;
        }
        let token = expected_token.clone();
        std::thread::spawn(move || {
            let file = unsafe { File::from_raw_fd(fd) };
            if let Err(e) = handle_connection(file, token.as_deref()) {
                eprintln!("container-agent request failed: {e:#}");
            }
        });
    }
}

fn handle_connection(file: File, expected_token: Option<&str>) -> Result<()> {
    let mut writer = file.try_clone()?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .context("reading container request")?;
    if n == 0 {
        return Ok(());
    }
    if line.len() > MAX_MESSAGE_BYTES {
        write_response(&mut writer, ContainerResponse::Error {
            message: format!("request exceeds {MAX_MESSAGE_BYTES} bytes"),
        })?;
        return Ok(());
    }
    let envelope: ContainerEnvelope = decode_line(&line).context("decoding container request")?;
    if let Some(expected) = expected_token {
        let ok = envelope
            .token
            .as_deref()
            .is_some_and(|actual| constant_time_eq(expected, actual));
        if !ok {
            write_response(&mut writer, ContainerResponse::Error {
                message: "unauthorized: missing or incorrect VM token".into(),
            })?;
            return Ok(());
        }
    }
    let response = dispatch(envelope.request).unwrap_or_else(|e| ContainerResponse::Error {
        message: format!("{e:#}"),
    });
    write_response(&mut writer, response)
}

fn write_response(writer: &mut File, response: ContainerResponse) -> Result<()> {
    writer.write_all(encode_line(&response)?.as_bytes())?;
    writer.flush()?;
    Ok(())
}

fn dispatch(request: ContainerRequest) -> Result<ContainerResponse> {
    match request {
        ContainerRequest::Ping => Ok(ContainerResponse::Pong),
        ContainerRequest::ConfigureSandboxResources { resources } => {
            configure_sandbox_resources(&resources)?;
            Ok(ContainerResponse::SandboxResourcesConfigured)
        }
        ContainerRequest::Create { id, config_json, io } => create_container(id, &config_json, io),
        ContainerRequest::Start { id, exec_id } => start_process(&id, exec_id.as_deref()),
        ContainerRequest::State { id, exec_id } => state_process(&id, exec_id.as_deref()),
        ContainerRequest::Exec { id, exec_id, process_json, io } => {
            create_exec(&id, exec_id, &process_json, io)
        }
        ContainerRequest::Kill { id, exec_id, signal, all } => {
            if all && exec_id.is_none() {
                signal_container_cgroup(&id, signal)?;
            } else {
                let handle = find_process(&id, exec_id.as_deref())?;
                handle.signal(signal, all)?;
            }
            Ok(ContainerResponse::Killed)
        }
        ContainerRequest::Pause { id } => {
            freeze_container(&id, true)?;
            find_process(&id, None)?.set_status(ContainerStatus::Paused);
            Ok(ContainerResponse::Paused)
        }
        ContainerRequest::Resume { id } => {
            freeze_container(&id, false)?;
            find_process(&id, None)?.set_status(ContainerStatus::Running);
            Ok(ContainerResponse::Resumed)
        }
        ContainerRequest::Wait { id, exec_id } => {
            let state = find_process(&id, exec_id.as_deref())?.wait();
            Ok(ContainerResponse::Exited {
                exit_code: state.exit_code.unwrap_or(255),
                exited_at_unix_nano: state.exited_at_unix_nano.unwrap_or_else(now_unix_nanos),
            })
        }
        ContainerRequest::Pids { id } => Ok(ContainerResponse::Pids { pids: container_pids(&id)? }),
        ContainerRequest::Stats { id } => Ok(ContainerResponse::Stats { stats: container_stats(&id)? }),
        ContainerRequest::UpdateResources { id, resources } => {
            update_container_resources(&id, &resources)?;
            Ok(ContainerResponse::ResourcesUpdated)
        }
        ContainerRequest::Delete { id, exec_id, force } => delete_process(&id, exec_id.as_deref(), force),
    }
}

fn create_container(id: String, config_json: &str, io: ContainerIo) -> Result<ContainerResponse> {
    if io.terminal {
        bail!("TTY containers are not supported by FluxVM secure-containers v0.1");
    }
    let (spec, mounts, resources) = parse_oci_config(config_json)?;
    {
        let reg = registry().lock().expect("registry poisoned");
        if reg.contains_key(&id) {
            bail!("container {id:?} already exists");
        }
    }
    let cgroup_path = match create_container_cgroup(&id, &resources) {
        Ok(path) => path,
        Err(e) => { cleanup_mounts(&mounts); return Err(e); }
    };
    let mut reg = registry().lock().expect("registry poisoned");
    if reg.contains_key(&id) {
        cleanup_container_cgroup(&cgroup_path);
        bail!("container {id:?} already exists");
    }
    let init = match spawn_gated(&id, None, &spec, &io) {
        Ok(handle) => handle,
        Err(e) => {
            cleanup_mounts(&mounts);
            let _ = std::fs::remove_dir(&cgroup_path);
            return Err(e);
        }
    };
    let pid = init.snapshot().pid;
    if let Err(e) = add_pid_to_cgroup(&cgroup_path, pid) {
        let _ = init.signal(libc::SIGKILL, true);
        cleanup_mounts(&mounts);
        let _ = std::fs::remove_dir(&cgroup_path);
        return Err(e);
    }
    reg.insert(
        id,
        ContainerEntry {
            rootfs: spec.rootfs.clone(),
            mounts,
            cgroup_path,
            seccomp: spec.seccomp.clone(),
            init,
            execs: HashMap::new(),
        },
    );
    Ok(ContainerResponse::Created { pid })
}

fn create_exec(id: &str, exec_id: String, process_json: &str, io: ContainerIo) -> Result<ContainerResponse> {
    if io.terminal {
        bail!("TTY exec is not supported by FluxVM secure-containers v0.1");
    }
    let mut reg = registry().lock().expect("registry poisoned");
    let container = reg.get_mut(id).with_context(|| format!("container {id:?} not found"))?;
    if container.execs.contains_key(&exec_id) {
        bail!("exec {exec_id:?} already exists in container {id:?}");
    }
    let mut spec = parse_oci_process(process_json, container.rootfs.clone())?;
    spec.rootfs = container.rootfs.clone();
    spec.seccomp = container.seccomp.clone();
    let handle = spawn_gated(id, Some(&exec_id), &spec, &io)?;
    let pid = handle.snapshot().pid;
    if let Err(e) = add_pid_to_cgroup(&container.cgroup_path, pid) {
        let _ = handle.signal(libc::SIGKILL, true);
        return Err(e);
    }
    container.execs.insert(exec_id, handle);
    Ok(ContainerResponse::ExecStarted { pid })
}

fn start_process(id: &str, exec_id: Option<&str>) -> Result<ContainerResponse> {
    let handle = find_process(id, exec_id)?;
    let pid = handle.start()?;
    Ok(ContainerResponse::Started { pid })
}

fn state_process(id: &str, exec_id: Option<&str>) -> Result<ContainerResponse> {
    let state = find_process(id, exec_id)?.snapshot();
    Ok(ContainerResponse::State {
        id: id.to_string(),
        exec_id: exec_id.map(str::to_string),
        status: state.status,
        pid: state.pid,
        exit_code: state.exit_code,
        exited_at_unix_nano: state.exited_at_unix_nano,
    })
}

fn delete_process(id: &str, exec_id: Option<&str>, force: bool) -> Result<ContainerResponse> {
    let mut reg = registry().lock().expect("registry poisoned");
    let container = reg.get_mut(id).with_context(|| format!("container {id:?} not found"))?;

    let final_state = if let Some(exec_id) = exec_id {
        let handle = container
            .execs
            .get(exec_id)
            .with_context(|| format!("exec {exec_id:?} not found"))?
            .clone();
        let state = handle.snapshot();
        if state.status != ContainerStatus::Stopped {
            if !force {
                bail!("exec {exec_id:?} is still running");
            }
            handle.signal(libc::SIGKILL, true)?;
        }
        let final_state = handle.wait();
        container.execs.remove(exec_id);
        final_state
    } else {
        let handle = container.init.clone();
        let state = handle.snapshot();
        if state.status != ContainerStatus::Stopped {
            if !force {
                bail!("container {id:?} is still running");
            }
            // Kill every process in the container cgroup first, then wait for
            // init so DeleteTask can return a definitive exit status instead
            // of the pre-kill state.
            let _ = signal_cgroup_path(&container.cgroup_path, libc::SIGKILL);
            handle.signal(libc::SIGKILL, true)?;
        }
        let final_state = handle.wait();
        if let Some(entry) = reg.remove(id) {
            cleanup_mounts(&entry.mounts);
            cleanup_container_cgroup(&entry.cgroup_path);
        }
        final_state
    };

    Ok(ContainerResponse::Deleted {
        pid: final_state.pid,
        exit_code: final_state.exit_code.unwrap_or_default(),
        exited_at_unix_nano: final_state.exited_at_unix_nano.unwrap_or_else(now_unix_nanos),
    })
}

fn find_process(id: &str, exec_id: Option<&str>) -> Result<Arc<ProcHandle>> {
    let reg = registry().lock().expect("registry poisoned");
    let container = reg.get(id).with_context(|| format!("container {id:?} not found"))?;
    match exec_id {
        None => Ok(container.init.clone()),
        Some(exec_id) => container
            .execs
            .get(exec_id)
            .cloned()
            .with_context(|| format!("exec {exec_id:?} not found in container {id:?}")),
    }
}

fn parse_oci_config(json: &str) -> Result<(ProcessSpec, Vec<PathBuf>, ResourceLimits)> {
    let v: Value = serde_json::from_str(json).context("parsing OCI config.json")?;
    let root = v
        .pointer("/root/path")
        .and_then(Value::as_str)
        .context("OCI root.path is required")?;
    let rootfs = PathBuf::from(root);
    let mut mounts = apply_oci_mounts(&v, &rootfs)?;
    let parsed = (|| -> Result<(ProcessSpec, ResourceLimits)> {
        create_oci_devices(&v, &rootfs)?;
        apply_oci_sysctls(&v)?;
        apply_oci_path_security(&v, &rootfs, &mut mounts)?;
        let process = v.get("process").context("OCI process is required")?;
        let resources = resource_limits_from_oci(&v);
        let mut spec = parse_process_value(process, rootfs.clone())?;
        spec.seccomp = parse_seccomp_profile(&v)?;
        Ok((spec, resources))
    })();
    match parsed {
        Ok((spec, resources)) => Ok((spec, mounts, resources)),
        Err(e) => {
            cleanup_mounts(&mounts);
            Err(e)
        }
    }
}


fn apply_oci_mounts(config: &Value, rootfs: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut mounted = Vec::new();
    let Some(items) = config.get("mounts").and_then(Value::as_array) else {
        return Ok(mounted);
    };
    for item in items {
        let destination = item
            .get("destination")
            .and_then(Value::as_str)
            .context("OCI mount destination is required")?;
        let relative = safe_guest_destination(destination)?;
        let target = rootfs.join(relative);
        let fs_type = item.get("type").and_then(Value::as_str).unwrap_or("");
        let source = item.get("source").and_then(Value::as_str).unwrap_or(fs_type);
        let options: Vec<String> = item
            .get("options")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        let is_bind = fs_type == "bind" || options.iter().any(|o| o == "bind" || o == "rbind");

        if is_bind {
            let source_path = PathBuf::from(source);
            if source_path.is_dir() {
                std::fs::create_dir_all(&target)?;
            } else {
                if let Some(parent) = target.parent() { std::fs::create_dir_all(parent)?; }
                if !target.exists() { File::create(&target)?; }
            }
        } else {
            std::fs::create_dir_all(&target)?;
        }

        let (flags, data) = mount_options(&options, is_bind);
        let mount_result = mount_one(
            source,
            &target,
            if is_bind { None } else { Some(fs_type) },
            flags,
            data.as_deref(),
        );
        if let Err(first) = mount_result {
            if fs_type == "cgroup" {
                mount_one("cgroup2", &target, Some("cgroup2"), flags, data.as_deref())
                    .with_context(|| format!("mounting cgroup/cgroup2 on {} after {first:#}", target.display()))?;
            } else {
                return Err(first).with_context(|| format!("mounting {source:?} on {}", target.display()));
            }
        }

        if is_bind && options.iter().any(|o| o == "ro") {
            mount_one(
                source,
                &target,
                None,
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                None,
            )
            .with_context(|| format!("remounting bind read-only on {}", target.display()))?;
        }

        if destination == "/dev" && fs_type == "tmpfs" {
            create_minimal_devices(&target);
        }
        mounted.push(target);
    }
    Ok(mounted)
}

fn apply_oci_path_security(config: &Value, rootfs: &PathBuf, mounted: &mut Vec<PathBuf>) -> Result<()> {
    let masked = config
        .pointer("/linux/maskedPaths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    for path in masked {
        let target = rootfs.join(safe_guest_destination(path)?);
        if !target.exists() { continue; }
        if target.is_dir() {
            mount_one("tmpfs", &target, Some("tmpfs"), libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, Some("size=0"))?;
        } else {
            mount_one("/dev/null", &target, None, libc::MS_BIND, None)?;
            mount_one("/dev/null", &target, None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY, None)?;
        }
        mounted.push(target);
    }

    let readonly = config
        .pointer("/linux/readonlyPaths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    for path in readonly {
        let target = rootfs.join(safe_guest_destination(path)?);
        if !target.exists() { continue; }
        let source = target.to_string_lossy().into_owned();
        mount_one(&source, &target, None, libc::MS_BIND | libc::MS_REC, None)?;
        mount_one(&source, &target, None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC, None)?;
        mounted.push(target);
    }

    if config.pointer("/root/readonly").and_then(Value::as_bool).unwrap_or(false) {
        let source = rootfs.to_string_lossy().into_owned();
        mount_one(&source, rootfs, None, libc::MS_BIND | libc::MS_REC, None)?;
        mount_one(&source, rootfs, None, libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC, None)?;
        mounted.push(rootfs.clone());
    }
    Ok(())
}

fn create_oci_devices(config: &Value, rootfs: &PathBuf) -> Result<()> {
    let Some(devices) = config.pointer("/linux/devices").and_then(Value::as_array) else { return Ok(()); };
    for dev in devices {
        let path = dev.get("path").and_then(Value::as_str).context("OCI device.path is required")?;
        let relative = safe_guest_destination(path)?;
        let target = rootfs.join(relative);
        if let Some(parent) = target.parent() { std::fs::create_dir_all(parent)?; }
        let kind = dev.get("type").and_then(Value::as_str).context("OCI device.type is required")?;
        let file_mode = dev.get("fileMode").and_then(Value::as_u64).unwrap_or(0o666) as libc::mode_t;
        let mode = match kind {
            "c" | "u" => libc::S_IFCHR | file_mode,
            "b" => libc::S_IFBLK | file_mode,
            "p" => libc::S_IFIFO | file_mode,
            other => bail!("unsupported OCI device type {other:?}"),
        };
        let major = dev.get("major").and_then(Value::as_i64).unwrap_or(0) as u64;
        let minor = dev.get("minor").and_then(Value::as_i64).unwrap_or(0) as u64;
        let c = CString::new(target.as_os_str().as_bytes())?;
        let _ = std::fs::remove_file(&target);
        let rc = unsafe { libc::mknod(c.as_ptr(), mode, libc::makedev(major as _, minor as _)) };
        if rc != 0 { return Err(std::io::Error::last_os_error()).with_context(|| format!("creating OCI device {}", target.display())); }
        let uid = dev.get("uid").and_then(Value::as_u64).unwrap_or(0) as libc::uid_t;
        let gid = dev.get("gid").and_then(Value::as_u64).unwrap_or(0) as libc::gid_t;
        unsafe { libc::chown(c.as_ptr(), uid, gid); }
    }
    Ok(())
}

fn apply_oci_sysctls(config: &Value) -> Result<()> {
    let Some(sysctls) = config.pointer("/linux/sysctl").and_then(Value::as_object) else { return Ok(()); };
    for (key, value) in sysctls {
        let value = value.as_str().context("OCI sysctl value must be a string")?;
        if key.contains('/') || key.contains("..") { bail!("unsafe OCI sysctl key {key:?}"); }
        let path = PathBuf::from("/proc/sys").join(key.replace('.', "/"));
        std::fs::write(&path, value).with_context(|| format!("applying OCI sysctl {key}={value}"))?;
    }
    Ok(())
}

const SCMP_ACT_KILL_PROCESS: u32 = 0x8000_0000;
const SCMP_ACT_KILL_THREAD: u32 = 0x0000_0000;
const SCMP_ACT_TRAP: u32 = 0x0003_0000;
const SCMP_ACT_ERRNO: u32 = 0x0005_0000;
const SCMP_ACT_LOG: u32 = 0x7ffc_0000;
const SCMP_ACT_ALLOW: u32 = 0x7fff_0000;

fn seccomp_action(raw: &str, errno_ret: Option<u32>) -> Result<u32> {
    Ok(match raw {
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_THREAD" => SCMP_ACT_KILL_THREAD,
        "SCMP_ACT_KILL_PROCESS" => SCMP_ACT_KILL_PROCESS,
        "SCMP_ACT_TRAP" => SCMP_ACT_TRAP,
        "SCMP_ACT_ERRNO" => SCMP_ACT_ERRNO | (errno_ret.unwrap_or(libc::EPERM as u32) & 0xffff),
        "SCMP_ACT_LOG" => SCMP_ACT_LOG,
        "SCMP_ACT_ALLOW" => SCMP_ACT_ALLOW,
        other => bail!("unsupported OCI seccomp action {other:?}"),
    })
}

fn parse_seccomp_profile(config: &Value) -> Result<Option<SeccompProfile>> {
    let Some(seccomp) = config.pointer("/linux/seccomp") else { return Ok(None); };
    if let Some(arches) = seccomp.get("architectures").and_then(Value::as_array) {
        for arch in arches.iter().filter_map(Value::as_str) {
            if arch != "SCMP_ARCH_X86_64" {
                bail!("unsupported OCI seccomp architecture {arch:?}; Set 4 enforces native x86_64 only");
            }
        }
    }
    let default_action = seccomp_action(
        seccomp.get("defaultAction").and_then(Value::as_str).context("OCI seccomp.defaultAction is required")?,
        seccomp.get("defaultErrnoRet").and_then(Value::as_u64).map(|v| v as u32),
    )?;
    let mut rules = Vec::new();
    if let Some(items) = seccomp.get("syscalls").and_then(Value::as_array) {
        for item in items {
            if item.get("args").and_then(Value::as_array).is_some_and(|v| !v.is_empty()) {
                bail!("OCI seccomp argument filters are not yet supported by FluxVM Set 4");
            }
            let action = seccomp_action(
                item.get("action").and_then(Value::as_str).context("OCI seccomp syscall action is required")?,
                item.get("errnoRet").and_then(Value::as_u64).map(|v| v as u32),
            )?;
            let names = item.get("names").and_then(Value::as_array).context("OCI seccomp syscall names are required")?
                .iter().map(|v| v.as_str().map(str::to_string).context("seccomp syscall name must be a string"))
                .collect::<Result<Vec<_>>>()?;
            rules.push(SeccompRule { action, names });
        }
    }
    Ok(Some(SeccompProfile { default_action, rules }))
}

unsafe fn dlsym_required<T: Copy>(handle: *mut libc::c_void, name: &[u8]) -> Result<T> {
    let ptr = unsafe { libc::dlsym(handle, name.as_ptr().cast()) };
    if ptr.is_null() { bail!("libseccomp symbol {} is missing", String::from_utf8_lossy(&name[..name.len()-1])); }
    Ok(unsafe { std::mem::transmute_copy(&ptr) })
}

fn apply_seccomp(profile: &SeccompProfile) -> Result<()> {
    type Init = unsafe extern "C" fn(u32) -> *mut libc::c_void;
    type Release = unsafe extern "C" fn(*mut libc::c_void);
    type Resolve = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;
    type RuleAdd = unsafe extern "C" fn(*mut libc::c_void, u32, libc::c_int, u32, ...) -> libc::c_int;
    type Load = unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int;
    let name = CString::new("libseccomp.so.2")?;
    let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() { bail!("OCI seccomp requested but libseccomp.so.2 is not installed in the guest"); }
    let result = (|| -> Result<()> {
        let init: Init = unsafe { dlsym_required(handle, b"seccomp_init\0")? };
        let release: Release = unsafe { dlsym_required(handle, b"seccomp_release\0")? };
        let resolve: Resolve = unsafe { dlsym_required(handle, b"seccomp_syscall_resolve_name\0")? };
        let rule_add: RuleAdd = unsafe { dlsym_required(handle, b"seccomp_rule_add\0")? };
        let load: Load = unsafe { dlsym_required(handle, b"seccomp_load\0")? };
        let ctx = unsafe { init(profile.default_action) };
        if ctx.is_null() { bail!("seccomp_init failed"); }
        let apply = (|| -> Result<()> {
            for rule in &profile.rules {
                for name in &rule.names {
                    let c = CString::new(name.as_bytes())?;
                    let nr = unsafe { resolve(c.as_ptr()) };
                    if nr < 0 { bail!("unknown seccomp syscall {name:?}"); }
                    let rc = unsafe { rule_add(ctx, rule.action, nr, 0) };
                    if rc != 0 { bail!("seccomp_rule_add({name}) failed: {rc}"); }
                }
            }
            let rc = unsafe { load(ctx) };
            if rc != 0 { bail!("seccomp_load failed: {rc}"); }
            Ok(())
        })();
        unsafe { release(ctx); }
        apply
    })();
    unsafe { libc::dlclose(handle); }
    result
}

fn safe_guest_destination(destination: &str) -> Result<PathBuf> {
    let path = std::path::Path::new(destination);
    if !path.is_absolute() { bail!("OCI mount destination must be absolute: {destination}"); }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(v) => out.push(v),
            _ => bail!("unsafe OCI mount destination: {destination}"),
        }
    }
    Ok(out)
}

fn mount_options(options: &[String], is_bind: bool) -> (libc::c_ulong, Option<String>) {
    let mut flags = if is_bind { libc::MS_BIND } else { 0 };
    let mut data = Vec::new();
    for opt in options {
        match opt.as_str() {
            "bind" => flags |= libc::MS_BIND,
            "rbind" => flags |= libc::MS_BIND | libc::MS_REC,
            "ro" => flags |= libc::MS_RDONLY,
            "rw" => flags &= !libc::MS_RDONLY,
            "nosuid" => flags |= libc::MS_NOSUID,
            "nodev" => flags |= libc::MS_NODEV,
            "noexec" => flags |= libc::MS_NOEXEC,
            "noatime" => flags |= libc::MS_NOATIME,
            "nodiratime" => flags |= libc::MS_NODIRATIME,
            "relatime" => flags |= libc::MS_RELATIME,
            "strictatime" => flags |= libc::MS_STRICTATIME,
            "rec" => flags |= libc::MS_REC,
            other if !matches!(other, "remount" | "private" | "rprivate" | "slave" | "rslave" | "shared" | "rshared") => data.push(other.to_string()),
            _ => {}
        }
    }
    (flags, (!data.is_empty()).then(|| data.join(",")))
}

fn mount_one(source: &str, target: &PathBuf, fs_type: Option<&str>, flags: libc::c_ulong, data: Option<&str>) -> Result<()> {
    let source = CString::new(source.as_bytes())?;
    let target = CString::new(target.as_os_str().as_bytes())?;
    let fs_type = fs_type.filter(|s| !s.is_empty()).map(|s| CString::new(s.as_bytes())).transpose()?;
    let data = data.map(|s| CString::new(s.as_bytes())).transpose()?;
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fs_type.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
            flags,
            data.as_ref().map_or(std::ptr::null(), |v| v.as_ptr().cast()),
        )
    };
    if rc != 0 { bail!("mount: {}", std::io::Error::last_os_error()); }
    Ok(())
}

fn create_minimal_devices(dev: &PathBuf) {
    for (name, major, minor, mode) in [
        ("null", 1, 3, 0o666), ("zero", 1, 5, 0o666), ("full", 1, 7, 0o666),
        ("random", 1, 8, 0o666), ("urandom", 1, 9, 0o666), ("tty", 5, 0, 0o666),
    ] {
        let path = dev.join(name);
        if let Ok(c) = CString::new(path.as_os_str().as_bytes()) {
            unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR | mode, libc::makedev(major, minor)); }
        }
    }
    let _ = std::fs::create_dir_all(dev.join("pts"));
    let _ = std::fs::create_dir_all(dev.join("shm"));
    let _ = std::fs::create_dir_all(dev.join("mqueue"));
}

fn cleanup_mounts(mounts: &[PathBuf]) {
    for target in mounts.iter().rev() {
        if let Ok(c) = CString::new(target.as_os_str().as_bytes()) {
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH); }
        }
    }
}


fn resource_limits_from_oci(config: &Value) -> ResourceLimits {
    ResourceLimits {
        cpu_quota: config.pointer("/linux/resources/cpu/quota").and_then(Value::as_i64),
        cpu_period: config.pointer("/linux/resources/cpu/period").and_then(Value::as_u64),
        cpu_shares: config.pointer("/linux/resources/cpu/shares").and_then(Value::as_u64),
        cpuset_cpus: config.pointer("/linux/resources/cpu/cpus").and_then(Value::as_str).map(str::to_string),
        cpuset_mems: config.pointer("/linux/resources/cpu/mems").and_then(Value::as_str).map(str::to_string),
        memory_limit_bytes: config.pointer("/linux/resources/memory/limit").and_then(Value::as_i64),
        pids_limit: config.pointer("/linux/resources/pids/limit").and_then(Value::as_i64),
    }
}

fn cgroup_root() -> PathBuf {
    PathBuf::from(CGROUP_ROOT)
}

fn enable_controllers(parent: &std::path::Path) -> Result<()> {
    let controllers_path = parent.join("cgroup.controllers");
    if !controllers_path.exists() {
        bail!("cgroup v2 is required ({} is missing)", controllers_path.display());
    }
    let controllers = std::fs::read_to_string(&controllers_path)?;
    let wanted: Vec<String> = ["cpu", "memory", "pids", "cpuset"]
        .into_iter()
        .filter(|name| controllers.split_whitespace().any(|available| available == *name))
        .map(|name| format!("+{name}"))
        .collect();
    if !wanted.is_empty() {
        std::fs::write(parent.join("cgroup.subtree_control"), wanted.join(" "))
            .with_context(|| format!("enabling cgroup controllers under {}", parent.display()))?;
    }
    Ok(())
}

fn ensure_cgroup_root() -> Result<PathBuf> {
    let sys = PathBuf::from("/sys/fs/cgroup");
    enable_controllers(&sys)?;
    let root = cgroup_root();
    std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
    enable_controllers(&root)?;
    Ok(root)
}

fn cgroup_component(id: &str) -> String {
    let mut out: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '-' })
        .collect();
    if out.len() > 96 { out.truncate(96); }
    if out.is_empty() { "container".into() } else { out }
}

fn configure_sandbox_resources(resources: &ResourceLimits) -> Result<()> {
    let root = ensure_cgroup_root()?;
    apply_resource_limits(&root, resources)
}

fn create_container_cgroup(id: &str, resources: &ResourceLimits) -> Result<PathBuf> {
    let root = ensure_cgroup_root()?;
    let path = root.join(cgroup_component(id));
    std::fs::create_dir_all(&path).with_context(|| format!("creating container cgroup {}", path.display()))?;
    apply_resource_limits(&path, resources)?;
    Ok(path)
}

fn container_cgroup(id: &str) -> Result<PathBuf> {
    let reg = registry().lock().expect("registry poisoned");
    reg.get(id)
        .map(|entry| entry.cgroup_path.clone())
        .with_context(|| format!("container {id:?} not found"))
}

fn add_pid_to_cgroup(path: &std::path::Path, pid: u32) -> Result<()> {
    std::fs::write(path.join("cgroup.procs"), pid.to_string())
        .with_context(|| format!("moving pid {pid} into {}", path.display()))
}

fn apply_resource_limits(path: &std::path::Path, resources: &ResourceLimits) -> Result<()> {
    if resources.cpu_quota.is_some() || resources.cpu_period.is_some() {
        let current = std::fs::read_to_string(path.join("cpu.max")).unwrap_or_else(|_| "max 100000".into());
        let mut parts = current.split_whitespace();
        let current_quota = parts.next().unwrap_or("max");
        let current_period = parts.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(100_000);
        let quota = match resources.cpu_quota {
            Some(v) if v > 0 => v.to_string(),
            Some(_) => "max".into(),
            None => current_quota.to_string(),
        };
        let period = resources.cpu_period.filter(|v| *v > 0).unwrap_or(current_period);
        std::fs::write(path.join("cpu.max"), format!("{quota} {period}"))?;
    }
    if let Some(shares) = resources.cpu_shares {
        if shares > 0 {
            let clamped = shares.clamp(2, 262_144);
            let weight = 1 + ((clamped - 2) * 9_999 / 262_142);
            std::fs::write(path.join("cpu.weight"), weight.to_string())?;
        }
    }
    if let Some(limit) = resources.memory_limit_bytes {
        let value = if limit > 0 { limit.to_string() } else { "max".into() };
        std::fs::write(path.join("memory.max"), value)?;
    }
    if let Some(limit) = resources.pids_limit {
        let value = if limit > 0 { limit.to_string() } else { "max".into() };
        std::fs::write(path.join("pids.max"), value)?;
    }
    if let Some(mems) = resources.cpuset_mems.as_deref().filter(|v| !v.is_empty()) {
        std::fs::write(path.join("cpuset.mems"), mems)?;
    } else if path.join("cpuset.mems").exists() {
        let parent = path.parent().unwrap_or(path);
        let effective = std::fs::read_to_string(parent.join("cpuset.mems.effective")).unwrap_or_default();
        if !effective.trim().is_empty() {
            let _ = std::fs::write(path.join("cpuset.mems"), effective.trim());
        }
    }
    if let Some(cpus) = resources.cpuset_cpus.as_deref().filter(|v| !v.is_empty()) {
        std::fs::write(path.join("cpuset.cpus"), cpus)?;
    }
    Ok(())
}

fn update_container_resources(id: &str, resources: &ResourceLimits) -> Result<()> {
    apply_resource_limits(&container_cgroup(id)?, resources)
}

fn container_pids(id: &str) -> Result<Vec<u32>> {
    pids_from_cgroup(&container_cgroup(id)?)
}

fn pids_from_cgroup(path: &std::path::Path) -> Result<Vec<u32>> {
    let procs = path.join("cgroup.procs");
    let text = std::fs::read_to_string(&procs).with_context(|| format!("reading {}", procs.display()))?;
    Ok(text.lines().filter_map(|line| line.trim().parse::<u32>().ok()).collect())
}

fn signal_cgroup_path(path: &std::path::Path, signal: i32) -> Result<()> {
    for pid in pids_from_cgroup(path)? {
        let rc = unsafe { libc::kill(pid as i32, signal) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ESRCH) { return Err(err.into()); }
        }
    }
    Ok(())
}

fn signal_container_cgroup(id: &str, signal: i32) -> Result<()> {
    signal_cgroup_path(&container_cgroup(id)?, signal)
}

fn freeze_container(id: &str, freeze: bool) -> Result<()> {
    let path = container_cgroup(id)?;
    let freeze_file = path.join("cgroup.freeze");
    if freeze_file.exists() {
        std::fs::write(&freeze_file, if freeze { "1" } else { "0" })
            .with_context(|| format!("writing {}", freeze_file.display()))?;
        return Ok(());
    }
    signal_container_cgroup(id, if freeze { libc::SIGSTOP } else { libc::SIGCONT })
}

fn parse_u64_field(path: &std::path::Path, key: &str) -> u64 {
    std::fs::read_to_string(path).ok().and_then(|text| {
        text.lines().find_map(|line| {
            let (name, value) = line.split_once(' ')?;
            (name == key).then(|| value.trim().parse::<u64>().ok()).flatten()
        })
    }).unwrap_or(0)
}

fn container_stats(id: &str) -> Result<ContainerStats> {
    let path = container_cgroup(id)?;
    let pids_max = std::fs::read_to_string(path.join("pids.max")).unwrap_or_default();
    Ok(ContainerStats {
        cpu_usage_usec: parse_u64_field(&path.join("cpu.stat"), "usage_usec"),
        cpu_user_usec: parse_u64_field(&path.join("cpu.stat"), "user_usec"),
        cpu_system_usec: parse_u64_field(&path.join("cpu.stat"), "system_usec"),
        memory_usage_bytes: std::fs::read_to_string(path.join("memory.current")).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(0),
        memory_total_inactive_file_bytes: parse_u64_field(&path.join("memory.stat"), "inactive_file"),
        pids_current: std::fs::read_to_string(path.join("pids.current")).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(0),
        pids_limit: if pids_max.trim() == "max" { 0 } else { pids_max.trim().parse().unwrap_or(0) },
    })
}

fn cleanup_container_cgroup(path: &std::path::Path) {
    let _ = std::fs::write(path.join("cgroup.kill"), "1");
    for _ in 0..20 {
        match std::fs::remove_dir(path) {
            Ok(()) => return,
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) || e.raw_os_error() == Some(libc::ENOTEMPTY) => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(_) => return,
        }
    }
}

fn parse_oci_process(json: &str, rootfs: PathBuf) -> Result<ProcessSpec> {
    let v: Value = serde_json::from_str(json).context("parsing OCI Process")?;
    parse_process_value(&v, rootfs)
}

fn parse_process_value(process: &Value, rootfs: PathBuf) -> Result<ProcessSpec> {
    let args = process
        .get("args")
        .and_then(Value::as_array)
        .context("OCI process.args is required")?
        .iter()
        .map(|v| v.as_str().map(str::to_string).context("process arg must be a string"))
        .collect::<Result<Vec<_>>>()?;
    if args.is_empty() {
        bail!("OCI process.args must not be empty");
    }
    let env = process
        .get("env")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|entry| {
                    let (k, v) = entry.split_once('=').unwrap_or((entry, ""));
                    (k.to_string(), v.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    let cwd = process.get("cwd").and_then(Value::as_str).unwrap_or("/").to_string();
    let uid = process.pointer("/user/uid").and_then(Value::as_u64).unwrap_or(0) as u32;
    let gid = process.pointer("/user/gid").and_then(Value::as_u64).unwrap_or(0) as u32;
    let additional_gids = process
        .pointer("/user/additionalGids")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_u64).map(|v| v as u32).collect())
        .unwrap_or_default();
    let no_new_privileges = process
        .get("noNewPrivileges")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let umask = process
        .pointer("/user/umask")
        .and_then(Value::as_u64)
        .map(|v| v as u32);
    let rlimits = parse_process_rlimits(process)?;
    let capabilities = parse_capability_sets(process)?;
    Ok(ProcessSpec {
        rootfs,
        args,
        env,
        cwd,
        uid,
        gid,
        additional_gids,
        no_new_privileges,
        umask,
        rlimits,
        capabilities,
        seccomp: None,
    })
}

fn parse_capability_sets(process: &Value) -> Result<Option<CapabilitySets>> {
    let Some(caps) = process.get("capabilities") else {
        return Ok(None);
    };
    let parse = |name: &str| -> Result<u64> {
        let Some(items) = caps.get(name).and_then(Value::as_array) else {
            return Ok(0);
        };
        let mut mask = 0u64;
        for item in items {
            let name = item.as_str().context("OCI capability must be a string")?;
            let bit = capability_number(name)
                .with_context(|| format!("unsupported Linux capability {name:?}"))?;
            mask |= 1u64 << bit;
        }
        Ok(mask)
    };
    let sets = CapabilitySets {
        bounding: parse("bounding")?,
        effective: parse("effective")?,
        inheritable: parse("inheritable")?,
        permitted: parse("permitted")?,
        ambient: parse("ambient")?,
    };
    if sets.effective & !sets.permitted != 0 {
        bail!("OCI effective capabilities must be a subset of permitted");
    }
    if sets.ambient & !sets.permitted != 0 || sets.ambient & !sets.inheritable != 0 {
        bail!("OCI ambient capabilities must be present in permitted and inheritable");
    }
    if sets.permitted & !sets.bounding != 0 {
        bail!("OCI permitted capabilities must be a subset of bounding");
    }
    Ok(Some(sets))
}

fn capability_number(name: &str) -> Option<u32> {
    let upper = name.to_ascii_uppercase();
    Some(match upper.strip_prefix("CAP_").unwrap_or(&upper) {
        "CHOWN" => 0,
        "DAC_OVERRIDE" => 1,
        "DAC_READ_SEARCH" => 2,
        "FOWNER" => 3,
        "FSETID" => 4,
        "KILL" => 5,
        "SETGID" => 6,
        "SETUID" => 7,
        "SETPCAP" => 8,
        "LINUX_IMMUTABLE" => 9,
        "NET_BIND_SERVICE" => 10,
        "NET_BROADCAST" => 11,
        "NET_ADMIN" => 12,
        "NET_RAW" => 13,
        "IPC_LOCK" => 14,
        "IPC_OWNER" => 15,
        "SYS_MODULE" => 16,
        "SYS_RAWIO" => 17,
        "SYS_CHROOT" => 18,
        "SYS_PTRACE" => 19,
        "SYS_PACCT" => 20,
        "SYS_ADMIN" => 21,
        "SYS_BOOT" => 22,
        "SYS_NICE" => 23,
        "SYS_RESOURCE" => 24,
        "SYS_TIME" => 25,
        "SYS_TTY_CONFIG" => 26,
        "MKNOD" => 27,
        "LEASE" => 28,
        "AUDIT_WRITE" => 29,
        "AUDIT_CONTROL" => 30,
        "SETFCAP" => 31,
        "MAC_OVERRIDE" => 32,
        "MAC_ADMIN" => 33,
        "SYSLOG" => 34,
        "WAKE_ALARM" => 35,
        "BLOCK_SUSPEND" => 36,
        "AUDIT_READ" => 37,
        "PERFMON" => 38,
        "BPF" => 39,
        "CHECKPOINT_RESTORE" => 40,
        _ => return None,
    })
}

#[repr(C)]
struct LinuxCapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct LinuxCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_RAISE: libc::c_ulong = 2;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;

fn drop_bounding_capabilities(caps: &CapabilitySets) -> Result<()> {
    let last_cap = std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(40)
        .min(63);
    for cap in 0..=last_cap {
        if caps.bounding & (1u64 << cap) != 0 {
            continue;
        }
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("dropping capability {cap} from bounding set"));
        }
    }
    Ok(())
}

fn set_process_capabilities(caps: &CapabilitySets) -> Result<()> {
    let mut header = LinuxCapHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let data = [
        LinuxCapData {
            effective: caps.effective as u32,
            permitted: caps.permitted as u32,
            inheritable: caps.inheritable as u32,
        },
        LinuxCapData {
            effective: (caps.effective >> 32) as u32,
            permitted: (caps.permitted >> 32) as u32,
            inheritable: (caps.inheritable >> 32) as u32,
        },
    ];
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            (&mut header as *mut LinuxCapHeader).cast::<libc::c_void>(),
            data.as_ptr().cast::<libc::c_void>(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("capset");
    }

    let rc = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        // Linux < 4.3 does not implement ambient capabilities. An empty OCI
        // ambient set remains representable there; a non-empty set must fail.
        if err.raw_os_error() != Some(libc::EINVAL) || caps.ambient != 0 {
            return Err(err).context("clearing ambient capabilities");
        }
    }
    for cap in 0..64u32 {
        if caps.ambient & (1u64 << cap) == 0 {
            continue;
        }
        let rc = unsafe {
            libc::prctl(
                PR_CAP_AMBIENT,
                PR_CAP_AMBIENT_RAISE,
                cap as libc::c_ulong,
                0,
                0,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("raising ambient capability {cap}"));
        }
    }
    Ok(())
}

fn parse_process_rlimits(process: &Value) -> Result<Vec<ProcessRlimit>> {
    let Some(items) = process.get("rlimits").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .map(|item| {
            let kind = item
                .get("type")
                .and_then(Value::as_str)
                .context("OCI rlimit.type is required")?;
            let resource = rlimit_resource(kind)
                .with_context(|| format!("unsupported OCI rlimit type {kind:?}"))?;
            let soft = item
                .get("soft")
                .and_then(Value::as_u64)
                .context("OCI rlimit.soft is required")? as libc::rlim_t;
            let hard = item
                .get("hard")
                .and_then(Value::as_u64)
                .context("OCI rlimit.hard is required")? as libc::rlim_t;
            if soft > hard {
                bail!("OCI rlimit {kind} has soft > hard");
            }
            Ok(ProcessRlimit { resource, soft, hard })
        })
        .collect()
}

fn rlimit_resource(kind: &str) -> Option<u32> {
    Some(match kind {
        "RLIMIT_AS" => libc::RLIMIT_AS as u32,
        "RLIMIT_CORE" => libc::RLIMIT_CORE as u32,
        "RLIMIT_CPU" => libc::RLIMIT_CPU as u32,
        "RLIMIT_DATA" => libc::RLIMIT_DATA as u32,
        "RLIMIT_FSIZE" => libc::RLIMIT_FSIZE as u32,
        "RLIMIT_LOCKS" => libc::RLIMIT_LOCKS as u32,
        "RLIMIT_MEMLOCK" => libc::RLIMIT_MEMLOCK as u32,
        "RLIMIT_MSGQUEUE" => libc::RLIMIT_MSGQUEUE as u32,
        "RLIMIT_NICE" => libc::RLIMIT_NICE as u32,
        "RLIMIT_NOFILE" => libc::RLIMIT_NOFILE as u32,
        "RLIMIT_NPROC" => libc::RLIMIT_NPROC as u32,
        "RLIMIT_RSS" => libc::RLIMIT_RSS as u32,
        "RLIMIT_RTPRIO" => libc::RLIMIT_RTPRIO as u32,
        "RLIMIT_RTTIME" => libc::RLIMIT_RTTIME as u32,
        "RLIMIT_SIGPENDING" => libc::RLIMIT_SIGPENDING as u32,
        "RLIMIT_STACK" => libc::RLIMIT_STACK as u32,
        _ => return None,
    })
}

fn resolve_executable(spec: &ProcessSpec) -> Result<String> {
    let arg0 = &spec.args[0];
    if arg0.contains('/') {
        return Ok(arg0.clone());
    }
    let path = spec
        .env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.as_str())
        .unwrap_or("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    for dir in path.split(':') {
        let guest = if dir.is_empty() { format!("/{arg0}") } else { format!("{}/{}", dir.trim_end_matches('/'), arg0) };
        let host = spec.rootfs.join(guest.trim_start_matches('/'));
        if host.is_file() { return Ok(guest); }
    }
    bail!("executable {arg0:?} was not found in OCI PATH")
}

fn spawn_gated(container_id: &str, exec_id: Option<&str>, spec: &ProcessSpec, io: &ContainerIo) -> Result<Arc<ProcHandle>> {
    let rootfs = CString::new(spec.rootfs.as_os_str().as_bytes()).context("rootfs contains NUL")?;
    let cwd = CString::new(spec.cwd.as_bytes()).context("cwd contains NUL")?;
    let executable = resolve_executable(spec)?;
    let executable = CString::new(executable.as_bytes()).context("executable contains NUL")?;
    let argv = spec
        .args
        .iter()
        .map(|a| CString::new(a.as_bytes()).context("argv contains NUL"))
        .collect::<Result<Vec<_>>>()?;
    let envv = spec
        .env
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).context("environment contains NUL"))
        .collect::<Result<Vec<_>>>()?;
    let stdin = open_input(io.stdin.as_deref())?;
    let stdout = open_output(io.stdout.as_deref())?;
    let stderr = open_output(io.stderr.as_deref())?;

    let mut gate = [0; 2];
    if unsafe { libc::pipe2(gate.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe2: {}", std::io::Error::last_os_error());
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(gate[0]);
            libc::close(gate[1]);
        }
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            libc::close(gate[1]);
            libc::setpgid(0, 0);
            if let Some(ref file) = stdin { libc::dup2(file.as_raw_fd(), libc::STDIN_FILENO); }
            if let Some(ref file) = stdout { libc::dup2(file.as_raw_fd(), libc::STDOUT_FILENO); }
            if let Some(ref file) = stderr { libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO); }
            let mut byte = [0u8; 1];
            if libc::read(gate[0], byte.as_mut_ptr().cast(), 1) != 1 { libc::_exit(126); }
            libc::close(gate[0]);
            if libc::chroot(rootfs.as_ptr()) != 0 { libc::_exit(126); }
            if libc::chdir(cwd.as_ptr()) != 0 { libc::_exit(126); }

            if let Some(mask) = spec.umask {
                libc::umask(mask as libc::mode_t);
            }
            for limit in &spec.rlimits {
                let value = libc::rlimit {
                    rlim_cur: limit.soft,
                    rlim_max: limit.hard,
                };
                if libc::setrlimit(limit.resource as _, &value) != 0 { libc::_exit(126); }
            }

            // Supplementary groups and the capability bounding set must be
            // configured while the child still has privilege.
            let groups: Vec<libc::gid_t> = spec.additional_gids.iter().map(|v| *v as libc::gid_t).collect();
            let group_ptr = if groups.is_empty() { std::ptr::null() } else { groups.as_ptr() };
            if libc::setgroups(groups.len(), group_ptr) != 0 { libc::_exit(126); }
            if let Some(caps) = spec.capabilities.as_ref() {
                if drop_bounding_capabilities(caps).is_err() { libc::_exit(126); }
                // Preserve the requested permitted set across a non-root UID
                // transition, then immediately replace it with OCI's exact
                // sets below.
                if spec.uid != 0 && (caps.permitted != 0 || caps.effective != 0 || caps.ambient != 0)
                    && libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0
                {
                    libc::_exit(126);
                }
            }
            if libc::setgid(spec.gid) != 0 { libc::_exit(126); }
            if libc::setuid(spec.uid) != 0 { libc::_exit(126); }
            if let Some(caps) = spec.capabilities.as_ref() {
                if set_process_capabilities(caps).is_err() { libc::_exit(126); }
                let _ = libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0);
            }
            if spec.no_new_privileges
                && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                libc::_exit(126);
            }
            if let Some(profile) = spec.seccomp.as_ref() {
                // A seccomp filter must never be silently skipped. Force
                // no-new-privileges before loading the guest-local filter.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || apply_seccomp(profile).is_err()
                {
                    libc::_exit(126);
                }
            }

            let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|v| v.as_ptr()).collect();
            argv_ptrs.push(std::ptr::null());
            let mut env_ptrs: Vec<*const libc::c_char> = envv.iter().map(|v| v.as_ptr()).collect();
            env_ptrs.push(std::ptr::null());
            libc::execve(executable.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
            libc::_exit(127);
        }
    }

    unsafe { libc::close(gate[0]) };
    drop(stdin);
    drop(stdout);
    drop(stderr);
    let handle = Arc::new(ProcHandle::new_created(pid as u32, gate[1]));
    let waiter = handle.clone();
    let label = format!("{container_id}/{}", exec_id.unwrap_or("init"));
    std::thread::spawn(move || {
        let mut status = 0i32;
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        let code = if rc < 0 {
            255
        } else if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            255
        };
        eprintln!("container process {label} pid={pid} exited code={code}");
        waiter.mark_exited(code);
    });
    Ok(handle)
}

fn open_input(path: Option<&str>) -> Result<Option<File>> {
    path.filter(|p| !p.is_empty())
        .map(|p| {
            match OpenOptions::new().read(true).open(p) {
                Ok(f) => Ok(f),
                // Virtiofs metadata may lag host-side creation. Non-interactive
                // tasks should still be able to start when stdin is absent.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    OpenOptions::new().read(true).open("/dev/null")
                }
                Err(e) => Err(e),
            }
            .with_context(|| format!("opening stdin {p}"))
        })
        .transpose()
}

fn open_output(path: Option<&str>) -> Result<Option<File>> {
    path.filter(|p| !p.is_empty())
        .map(|p| {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(p)
                .with_context(|| format!("opening output {p}"))
        })
        .transpose()
}

fn set_cloexec(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC); }
    }
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) { diff |= x ^ y; }
    diff == 0
}

fn now_unix_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_oci_config() {
        let (spec, mounts, resources) = parse_oci_config(r#"{
          "root":{"path":"/run/rootfs"},
          "process":{"args":["/bin/echo","hi"],"cwd":"/","env":["A=B"],"user":{"uid":1000,"gid":1001}}
        }"#).unwrap();
        assert!(mounts.is_empty());
        assert_eq!(resources, ResourceLimits::default());
        assert_eq!(spec.rootfs, PathBuf::from("/run/rootfs"));
        assert_eq!(spec.args[0], "/bin/echo");
        assert_eq!(spec.uid, 1000);
        assert_eq!(spec.gid, 1001);
        assert_eq!(spec.env, vec![("A".into(), "B".into())]);
    }

    #[test]
    fn parses_process_security_controls() {
        let (spec, _, _) = parse_oci_config(r#"{
          "root":{"path":"/run/rootfs"},
          "process":{
            "args":["/bin/sh"],
            "cwd":"/",
            "noNewPrivileges":true,
            "user":{"uid":1000,"gid":1000,"additionalGids":[10,20],"umask":18},
            "rlimits":[{"type":"RLIMIT_NOFILE","soft":1024,"hard":2048}],
            "capabilities":{
              "bounding":["CAP_CHOWN","CAP_NET_BIND_SERVICE"],
              "effective":["CAP_NET_BIND_SERVICE"],
              "inheritable":["CAP_NET_BIND_SERVICE"],
              "permitted":["CAP_NET_BIND_SERVICE"],
              "ambient":["CAP_NET_BIND_SERVICE"]
            }
          }
        }"#).unwrap();
        assert_eq!(spec.additional_gids, vec![10, 20]);
        assert!(spec.no_new_privileges);
        assert_eq!(spec.umask, Some(18));
        assert_eq!(spec.rlimits.len(), 1);
        assert_eq!(spec.rlimits[0].soft, 1024);
        assert_eq!(spec.rlimits[0].hard, 2048);
        let caps = spec.capabilities.unwrap();
        assert_ne!(caps.bounding & (1 << 0), 0);
        assert_ne!(caps.bounding & (1 << 10), 0);
        assert_eq!(caps.effective, 1 << 10);
        assert_eq!(caps.ambient, 1 << 10);
    }

    #[test]
    fn rejects_unknown_capability() {
        assert!(parse_oci_config(r#"{
          "root":{"path":"/r"},
          "process":{
            "args":["/bin/true"],
            "capabilities":{"effective":["CAP_NOT_REAL"]}
          }
        }"#).is_err());
    }

    #[test]
    fn rejects_unknown_rlimit() {
        assert!(parse_oci_config(r#"{
          "root":{"path":"/r"},
          "process":{"args":["/bin/true"],"rlimits":[{"type":"RLIMIT_FAKE","soft":1,"hard":1}]}
        }"#).is_err());
    }

    #[test]
    fn rejects_empty_args() {
        assert!(parse_oci_config(r#"{"root":{"path":"/r"},"process":{"args":[]}}"#).is_err());
    }

    #[test]
    fn parses_seccomp_without_argument_filters() {
        let (spec, _, _) = parse_oci_config(r#"{
          "root":{"path":"/run/rootfs"},
          "process":{"args":["/bin/true"]},
          "linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["ptrace"],"action":"SCMP_ACT_ERRNO","errnoRet":1}]}}
        }"#).unwrap();
        let seccomp = spec.seccomp.unwrap();
        assert_eq!(seccomp.rules.len(), 1);
        assert_eq!(seccomp.rules[0].names, vec!["ptrace"]);
    }

    #[test]
    fn rejects_seccomp_argument_filters_instead_of_ignoring_them() {
        assert!(parse_oci_config(r#"{
          "root":{"path":"/run/rootfs"},
          "process":{"args":["/bin/true"]},
          "linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["clone"],"action":"SCMP_ACT_ERRNO","args":[{"index":0,"value":1,"op":"SCMP_CMP_EQ"}]}]}}
        }"#).is_err());
    }

    #[test]
    fn token_compare() {
        assert!(constant_time_eq("same", "same"));
        assert!(!constant_time_eq("same", "diff"));
        assert!(!constant_time_eq("same", "same2"));
    }
}
