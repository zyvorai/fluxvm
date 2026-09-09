// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Minimal in-guest OCI process supervisor for FluxVM's containerd runtime.
//!
//! Security boundary: the entire Kubernetes Pod/container sandbox runs inside
//! a hardware VM. This agent intentionally does not pretend to be a complete
//! runc replacement yet; it implements process lifecycle, chroot, uid/gid,
//! environment, cwd, signals and stdio inside the guest. OCI namespace,
//! capability, seccomp, device and cgroup parity are tracked as follow-up
//! hardening items in docs/secure-containers.md.

use anyhow::{Context, Result, bail};
use clap::Parser;
use fluxvm_container_protocol::{
    ContainerEnvelope, ContainerIo, ContainerRequest, ContainerResponse, ContainerStatus,
    DEFAULT_CONTAINER_AGENT_PORT, MAX_MESSAGE_BYTES, decode_line, encode_line,
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

#[derive(Parser, Debug)]
#[command(name = "fluxvm-container-agent", version)]
struct Cli {
    #[arg(long, default_value_t = DEFAULT_CONTAINER_AGENT_PORT)]
    port: u32,
}

#[derive(Clone, Debug)]
struct ProcessSpec {
    rootfs: PathBuf,
    args: Vec<String>,
    env: Vec<(String, String)>,
    cwd: String,
    uid: u32,
    gid: u32,
}

#[derive(Clone, Debug)]
struct ProcSnapshot {
    status: ContainerStatus,
    pid: u32,
    exit_code: Option<i32>,
    exited_at_unix_nano: Option<i128>,
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
        ContainerRequest::Create { id, config_json, io } => create_container(id, &config_json, io),
        ContainerRequest::Start { id, exec_id } => start_process(&id, exec_id.as_deref()),
        ContainerRequest::State { id, exec_id } => state_process(&id, exec_id.as_deref()),
        ContainerRequest::Exec { id, exec_id, process_json, io } => {
            create_exec(&id, exec_id, &process_json, io)
        }
        ContainerRequest::Kill { id, exec_id, signal, all } => {
            let handle = find_process(&id, exec_id.as_deref())?;
            handle.signal(signal, all)?;
            Ok(ContainerResponse::Killed)
        }
        ContainerRequest::Pause { id } => {
            let handle = find_process(&id, None)?;
            handle.signal(libc::SIGSTOP, true)?;
            handle.set_status(ContainerStatus::Paused);
            Ok(ContainerResponse::Paused)
        }
        ContainerRequest::Resume { id } => {
            let handle = find_process(&id, None)?;
            handle.signal(libc::SIGCONT, true)?;
            handle.set_status(ContainerStatus::Running);
            Ok(ContainerResponse::Resumed)
        }
        ContainerRequest::Wait { id, exec_id } => {
            let state = find_process(&id, exec_id.as_deref())?.wait();
            Ok(ContainerResponse::Exited {
                exit_code: state.exit_code.unwrap_or(255),
                exited_at_unix_nano: state.exited_at_unix_nano.unwrap_or_else(now_unix_nanos),
            })
        }
        ContainerRequest::Delete { id, exec_id, force } => delete_process(&id, exec_id.as_deref(), force),
    }
}

fn create_container(id: String, config_json: &str, io: ContainerIo) -> Result<ContainerResponse> {
    if io.terminal {
        bail!("TTY containers are not supported by FluxVM secure-containers v0.1");
    }
    let (spec, mounts) = parse_oci_config(config_json)?;
    let mut reg = registry().lock().expect("registry poisoned");
    if reg.contains_key(&id) {
        bail!("container {id:?} already exists");
    }
    let init = spawn_gated(&id, None, &spec, &io)?;
    let pid = init.snapshot().pid;
    reg.insert(
        id,
        ContainerEntry {
            rootfs: spec.rootfs.clone(),
            mounts,
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
    let handle = spawn_gated(id, Some(&exec_id), &spec, &io)?;
    let pid = handle.snapshot().pid;
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
    if let Some(exec_id) = exec_id {
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
        container.execs.remove(exec_id);
    } else {
        let state = container.init.snapshot();
        if state.status != ContainerStatus::Stopped {
            if !force {
                bail!("container {id:?} is still running");
            }
            container.init.signal(libc::SIGKILL, true)?;
        }
        if let Some(entry) = reg.remove(id) {
            cleanup_mounts(&entry.mounts);
        }
    }
    Ok(ContainerResponse::Deleted)
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

fn parse_oci_config(json: &str) -> Result<(ProcessSpec, Vec<PathBuf>)> {
    let v: Value = serde_json::from_str(json).context("parsing OCI config.json")?;
    let root = v
        .pointer("/root/path")
        .and_then(Value::as_str)
        .context("OCI root.path is required")?;
    let rootfs = PathBuf::from(root);
    let mounts = apply_oci_mounts(&v, &rootfs)?;
    let process = v.get("process").context("OCI process is required")?;
    Ok((parse_process_value(process, rootfs)?, mounts))
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
    Ok(ProcessSpec { rootfs, args, env, cwd, uid, gid })
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
            if libc::setgid(spec.gid) != 0 { libc::_exit(126); }
            if libc::setuid(spec.uid) != 0 { libc::_exit(126); }

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
        .map(|p| OpenOptions::new().read(true).open(p).with_context(|| format!("opening stdin {p}")))
        .transpose()
}

fn open_output(path: Option<&str>) -> Result<Option<File>> {
    path.filter(|p| !p.is_empty())
        .map(|p| {
            OpenOptions::new()
                .write(true)
                .create(false)
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

fn now_unix_nanos() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as i128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_oci_config() {
        let (spec, mounts) = parse_oci_config(r#"{
          "root":{"path":"/run/rootfs"},
          "process":{"args":["/bin/echo","hi"],"cwd":"/","env":["A=B"],"user":{"uid":1000,"gid":1001}}
        }"#).unwrap();
        assert!(mounts.is_empty());
        assert_eq!(spec.rootfs, PathBuf::from("/run/rootfs"));
        assert_eq!(spec.args[0], "/bin/echo");
        assert_eq!(spec.uid, 1000);
        assert_eq!(spec.gid, 1001);
        assert_eq!(spec.env, vec![("A".into(), "B".into())]);
    }

    #[test]
    fn rejects_empty_args() {
        assert!(parse_oci_config(r#"{"root":{"path":"/r"},"process":{"args":[]}}"#).is_err());
    }

    #[test]
    fn token_compare() {
        assert!(constant_time_eq("same", "same"));
        assert!(!constant_time_eq("same", "diff"));
        assert!(!constant_time_eq("same", "same2"));
    }
}
