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
//! sysctls and seccomp filters. Set 5 adds dedicated VSOCK stdio streams plus
//! guest PTY/resize support. Set 6 adds per-container PID/mount/IPC/UTS
//! namespace isolation (`pivot_root` replacing bare `chroot`, an opt-in
//! `CLONE_NEWUSER`) so containers in one Pod VM are no longer isolated from
//! each other by the VM boundary alone — see docs/secure-containers-set6r.md.
//! Set 7 adds cgroup-v2 OOM counters, richer metrics, correct OCI swap translation,
//! safe unified updates, and fail-closed handling for unattached host devices.
//! Full device-cgroup parity remains an explicit follow-up hardening item in
//! docs/secure-containers.md.

use anyhow::{Context, Result, bail};
use clap::Parser;
use fluxvm_container_protocol::{
    CgroupEvents, ContainerEnvelope, ContainerIo, ContainerRequest, ContainerResponse, ContainerStats,
    ContainerStatus, ResourceLimits, IoStreamAck, IoStreamAttach, IoStreamKind,
    DEFAULT_CONTAINER_AGENT_PORT, DEFAULT_CONTAINER_STREAM_PORT, MAX_MESSAGE_BYTES, decode_line,
    encode_line,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

const TOKEN_FILE_PATH: &str = "/etc/fluxvm-guest-agent.token";
const CGROUP_ROOT: &str = "/sys/fs/cgroup/fluxvm-containers";
/// Set 6: env var gating `CLONE_NEWUSER`. Off by default — see
/// docs/secure-containers-set6r.md for the rationale (virtiofs uid/gid ACL
/// interaction, and sequencing with the in-guest LSM identity model).
const USERNS_ENV: &str = "FLUXVM_CONTAINER_USERNS";

/// Set 6: per-container Linux namespace file descriptors, recorded so
/// sibling containers (sandbox-sharing) and later `Exec` calls can join
/// them via `setns(2)`. `-1` means "no namespace recorded" (not created, or
/// intentionally not shared). These are `O_CLOEXEC` fds owned by the agent
/// process for the lifetime of the container; closed on container delete.
#[derive(Clone, Copy, Debug)]
struct ContainerNamespaces {
    mnt: RawFd,
    pid: RawFd,
    ipc: RawFd,
    uts: RawFd,
    user: RawFd,
}

impl Default for ContainerNamespaces {
    fn default() -> Self {
        Self { mnt: -1, pid: -1, ipc: -1, uts: -1, user: -1 }
    }
}

impl ContainerNamespaces {
    fn close(&mut self) {
        for fd in [&mut self.mnt, &mut self.pid, &mut self.ipc, &mut self.uts, &mut self.user] {
            if *fd >= 0 {
                unsafe { libc::close(*fd) };
                *fd = -1;
            }
        }
    }
}

/// Set 6: which namespaces to create fresh vs. join for one `spawn_gated`
/// call. `Create` covers both a Pod's sandbox container (fresh IPC/UTS/PID,
/// optionally shared onward) and an ordinary container joining (or not
/// finding) a sandbox. `Exec` always joins the target container's own
/// namespaces so `ps`/`nsenter`-style introspection inside an exec sees the
/// same process tree and filesystem as the container's init process.
enum NsRequest {
    Create { is_sandbox: bool, share_process_namespace: bool },
    Exec { target: ContainerNamespaces },
}

/// Set 6: one shared sandbox (CRI pause-container-equivalent) per agent
/// process. Every `fluxvm-container-agent` supervises exactly one Pod VM, so
/// there is at most one sandbox container to track — no keying needed.
static SANDBOX_NAMESPACES: OnceLock<Mutex<Option<ContainerNamespaces>>> = OnceLock::new();

fn sandbox_namespaces() -> &'static Mutex<Option<ContainerNamespaces>> {
    SANDBOX_NAMESPACES.get_or_init(|| Mutex::new(None))
}

fn userns_enabled() -> bool {
    std::env::var(USERNS_ENV).map(|v| v == "1").unwrap_or(false)
}

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

#[derive(Debug)]
enum ProcIo {
    Legacy,
    Pipes {
        stdin_write: Option<RawFd>,
        stdin_attached: bool,
        stdout_read: Option<RawFd>,
        stdout_attached: bool,
        stderr_read: Option<RawFd>,
        stderr_attached: bool,
    },
    Pty {
        master_fd: RawFd,
        stdin_attached: bool,
        stdout_attached: bool,
    },
}

impl Drop for ProcIo {
    fn drop(&mut self) {
        unsafe {
            match self {
                ProcIo::Legacy => {}
                ProcIo::Pipes { stdin_write, stdout_read, stderr_read, .. } => {
                    for fd in [stdin_write.take(), stdout_read.take(), stderr_read.take()].into_iter().flatten() {
                        libc::close(fd);
                    }
                }
                ProcIo::Pty { master_fd, .. } => {
                    if *master_fd >= 0 { libc::close(*master_fd); }
                    *master_fd = -1;
                }
            }
        }
    }
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
    io: Mutex<ProcIo>,
}

impl ProcHandle {
    fn new_created(pid: u32, gate_fd: RawFd, io: ProcIo) -> Self {
        Self {
            inner: Mutex::new(ProcSnapshot {
                status: ContainerStatus::Created,
                pid,
                exit_code: None,
                exited_at_unix_nano: None,
                gate_fd: Some(gate_fd),
            }),
            changed: Condvar::new(),
            io: Mutex::new(io),
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

    fn attach_stream(&self, kind: IoStreamKind) -> Result<File> {
        let mut io = self.io.lock().expect("process io poisoned");
        let (source, attached, label) = match &mut *io {
            ProcIo::Legacy => bail!("process uses legacy virtiofs stdio, not VSOCK streaming"),
            ProcIo::Pipes {
                stdin_write,
                stdin_attached,
                stdout_read,
                stdout_attached,
                stderr_read,
                stderr_attached,
            } => match kind {
                IoStreamKind::Stdin => (
                    stdin_write.as_ref().copied().context("stdin stream is absent")?,
                    stdin_attached,
                    "stdin pipe",
                ),
                IoStreamKind::Stdout => (
                    stdout_read.as_ref().copied().context("stdout stream is absent")?,
                    stdout_attached,
                    "stdout pipe",
                ),
                IoStreamKind::Stderr => (
                    stderr_read.as_ref().copied().context("stderr stream is absent")?,
                    stderr_attached,
                    "stderr pipe",
                ),
            },
            ProcIo::Pty { master_fd, stdin_attached, stdout_attached } => match kind {
                IoStreamKind::Stdin => (*master_fd, stdin_attached, "pty stdin"),
                IoStreamKind::Stdout => (*master_fd, stdout_attached, "pty stdout"),
                IoStreamKind::Stderr => bail!("TTY processes have a single PTY output stream"),
            },
        };
        if *attached {
            bail!("{label} is already attached");
        }
        let fd = unsafe { libc::dup(source) };
        if fd < 0 {
            bail!("dup({label}): {}", std::io::Error::last_os_error());
        }
        set_cloexec(fd);
        // Only publish attached state after dup succeeds; otherwise recovery
        // could permanently lose the stream after transient fd exhaustion.
        *attached = true;
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn detach_stream(&self, kind: IoStreamKind) {
        let mut io = self.io.lock().expect("process io poisoned");
        match &mut *io {
            ProcIo::Legacy => {}
            ProcIo::Pipes {
                stdin_attached,
                stdout_attached,
                stderr_attached,
                ..
            } => match kind {
                IoStreamKind::Stdin => *stdin_attached = false,
                IoStreamKind::Stdout => *stdout_attached = false,
                IoStreamKind::Stderr => *stderr_attached = false,
            },
            ProcIo::Pty { stdin_attached, stdout_attached, .. } => match kind {
                IoStreamKind::Stdin => *stdin_attached = false,
                IoStreamKind::Stdout => *stdout_attached = false,
                IoStreamKind::Stderr => {}
            },
        }
    }

    fn resize_pty(&self, width: u32, height: u32) -> Result<()> {
        if width == 0 || height == 0 || width > u16::MAX as u32 || height > u16::MAX as u32 {
            bail!("invalid PTY size {width}x{height}");
        }
        let io = self.io.lock().expect("process io poisoned");
        let ProcIo::Pty { master_fd, .. } = &*io else { bail!("process is not a TTY"); };
        let ws = libc::winsize { ws_row: height as u16, ws_col: width as u16, ws_xpixel: 0, ws_ypixel: 0 };
        if unsafe { libc::ioctl(*master_fd, libc::TIOCSWINSZ as libc::c_ulong, &ws) } != 0 {
            bail!("TIOCSWINSZ: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn close_stdin(&self) -> Result<()> {
        let mut io = self.io.lock().expect("process io poisoned");
        match &mut *io {
            ProcIo::Legacy => Ok(()),
            ProcIo::Pipes { stdin_write, .. } => {
                if let Some(fd) = stdin_write.take() { unsafe { libc::close(fd) }; }
                Ok(())
            }
            ProcIo::Pty { master_fd, .. } => {
                // Canonical terminals interpret ^D as EOF when the input line is empty.
                let eof = [0x04u8; 1];
                let rc = unsafe { libc::write(*master_fd, eof.as_ptr().cast(), 1) };
                if rc < 0 { bail!("writing PTY EOF: {}", std::io::Error::last_os_error()); }
                Ok(())
            }
        }
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
    namespaces: ContainerNamespaces,
    is_sandbox: bool,
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

    let stream_port = DEFAULT_CONTAINER_STREAM_PORT;
    let stream_token = expected_token.clone();
    std::thread::spawn(move || {
        if let Err(e) = run_stream_server(stream_port, stream_token) {
            eprintln!("container stream server failed: {e:#}");
        }
    });

    let listener_fd = create_vsock_listener(port)?;
    eprintln!("fluxvm-container-agent lifecycle listening on vsock port {port}");
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

fn create_vsock_listener(port: u32) -> Result<RawFd> {
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 { bail!("socket(AF_VSOCK): {}", std::io::Error::last_os_error()); }
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        addr.svm_port = port;
        if libc::bind(
            fd,
            (&addr as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        ) != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            bail!("bind(vsock:{port}): {e}");
        }
        if libc::listen(fd, 128) != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            bail!("listen(vsock:{port}): {e}");
        }
        set_cloexec(fd);
        Ok(fd)
    }
}

fn run_stream_server(port: u32, expected_token: Option<String>) -> Result<()> {
    let listener_fd = create_vsock_listener(port)?;
    eprintln!("fluxvm-container-agent stdio listening on vsock port {port}");
    loop {
        let fd = unsafe { libc::accept(listener_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
        if fd < 0 {
            eprintln!("stdio accept failed: {}", std::io::Error::last_os_error());
            continue;
        }
        let token = expected_token.clone();
        std::thread::spawn(move || {
            let file = unsafe { File::from_raw_fd(fd) };
            if let Err(e) = handle_stream_connection(file, token.as_deref()) {
                eprintln!("container stdio stream failed: {e:#}");
            }
        });
    }
}

fn handle_stream_connection(mut socket: File, expected_token: Option<&str>) -> Result<()> {
    let mut line = String::new();
    {
        let mut reader = BufReader::new(socket.try_clone()?);
        let n = reader.read_line(&mut line).context("reading stdio attach request")?;
        if n == 0 { return Ok(()); }
    }
    if line.len() > 64 * 1024 {
        socket.write_all(encode_line(&IoStreamAck { ok: false, message: Some("attach request too large".into()) })?.as_bytes())?;
        socket.flush()?;
        return Ok(());
    }
    let attach: IoStreamAttach = decode_line(&line).context("decoding stdio attach request")?;
    if let Some(expected) = expected_token {
        let ok = attach.token.as_deref().is_some_and(|actual| constant_time_eq(expected, actual));
        if !ok {
            socket.write_all(encode_line(&IoStreamAck { ok: false, message: Some("unauthorized".into()) })?.as_bytes())?;
            socket.flush()?;
            return Ok(());
        }
    }
    let process = match find_process(&attach.id, attach.exec_id.as_deref()) {
        Ok(process) => process,
        Err(e) => {
            socket.write_all(encode_line(&IoStreamAck { ok: false, message: Some(format!("{e:#}")) })?.as_bytes())?;
            socket.flush()?;
            return Ok(());
        }
    };
    let mut endpoint = match process.attach_stream(attach.stream) {
        Ok(endpoint) => endpoint,
        Err(e) => {
            socket.write_all(encode_line(&IoStreamAck { ok: false, message: Some(format!("{e:#}")) })?.as_bytes())?;
            socket.flush()?;
            return Ok(());
        }
    };
    socket.write_all(encode_line(&IoStreamAck { ok: true, message: None })?.as_bytes())?;
    socket.flush()?;
    let stream_kind = attach.stream;
    let result: Result<()> = (|| {
        match stream_kind {
            IoStreamKind::Stdin => {
                // Socket EOF means the transport disappeared, not that
                // containerd issued CloseIO. Keep the guest pipe/PTY alive so
                // a replacement shim can attach again.
                std::io::copy(&mut socket, &mut endpoint)
                    .context("streaming container stdin")?;
                endpoint.flush().ok();
            }
            IoStreamKind::Stdout | IoStreamKind::Stderr => {
                match std::io::copy(&mut endpoint, &mut socket) {
                    Ok(_) => {}
                    Err(e) if e.raw_os_error() == Some(libc::EIO) => {} // PTY slave closed
                    Err(e) => return Err(e).context("streaming guest output"),
                }
                socket.flush()?;
            }
        }
        Ok(())
    })();
    process.detach_stream(stream_kind);
    result
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
        ContainerRequest::Create { id, config_json, io, is_sandbox, share_process_namespace } => {
            create_container(id, &config_json, io, is_sandbox, share_process_namespace)
        }
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
        ContainerRequest::CgroupEvents { id } => Ok(ContainerResponse::CgroupEvents { events: container_cgroup_events(&id)? }),
        ContainerRequest::UpdateResources { id, resources } => {
            update_container_resources(&id, &resources)?;
            Ok(ContainerResponse::ResourcesUpdated)
        }
        ContainerRequest::ResizePty { id, exec_id, width, height } => {
            find_process(&id, exec_id.as_deref())?.resize_pty(width, height)?;
            Ok(ContainerResponse::PtyResized)
        }
        ContainerRequest::CloseIo { id, exec_id } => {
            find_process(&id, exec_id.as_deref())?.close_stdin()?;
            Ok(ContainerResponse::IoClosed)
        }
        ContainerRequest::Delete { id, exec_id, force } => delete_process(&id, exec_id.as_deref(), force),
    }
}

fn create_container(
    id: String,
    config_json: &str,
    io: ContainerIo,
    is_sandbox: bool,
    share_process_namespace: bool,
) -> Result<ContainerResponse> {
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
    let ns_request = NsRequest::Create { is_sandbox, share_process_namespace };
    let (init, namespaces) = match spawn_gated(&id, None, &spec, &io, ns_request) {
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
    if is_sandbox {
        let mut sandbox = sandbox_namespaces().lock().expect("sandbox ns poisoned");
        *sandbox = Some(namespaces);
    }
    reg.insert(
        id,
        ContainerEntry {
            rootfs: spec.rootfs.clone(),
            mounts,
            cgroup_path,
            seccomp: spec.seccomp.clone(),
            namespaces,
            is_sandbox,
            init,
            execs: HashMap::new(),
        },
    );
    Ok(ContainerResponse::Created { pid })
}

fn create_exec(id: &str, exec_id: String, process_json: &str, io: ContainerIo) -> Result<ContainerResponse> {
    let mut reg = registry().lock().expect("registry poisoned");
    let container = reg.get_mut(id).with_context(|| format!("container {id:?} not found"))?;
    if container.execs.contains_key(&exec_id) {
        bail!("exec {exec_id:?} already exists in container {id:?}");
    }
    let mut spec = parse_oci_process(process_json, container.rootfs.clone())?;
    spec.rootfs = container.rootfs.clone();
    spec.seccomp = container.seccomp.clone();
    let ns_request = NsRequest::Exec { target: container.namespaces };
    let (handle, _) = spawn_gated(id, Some(&exec_id), &spec, &io, ns_request)?;
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
        if let Some(mut entry) = reg.remove(id) {
            cleanup_mounts(&entry.mounts);
            cleanup_container_cgroup(&entry.cgroup_path);
            if entry.is_sandbox {
                // Deleting the sandbox invalidates joined-namespace sharing
                // for any container created after it; siblings created
                // earlier already hold their own fds to the same
                // namespaces (namespaces persist as long as any open fd or
                // member process references them), so this only affects
                // containers not yet created.
                *sandbox_namespaces().lock().expect("sandbox ns poisoned") = None;
            }
            entry.namespaces.close();
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
        let major = dev.get("major").and_then(Value::as_i64).unwrap_or(0) as u64;
        let minor = dev.get("minor").and_then(Value::as_i64).unwrap_or(0) as u64;

        // A host block device cannot be made real inside a hardware VM with
        // mknod alone: the guest must have an actual virtio/SCSI/NVMe device
        // attached first. Refuse it instead of accidentally targeting an
        // unrelated guest device with the same major/minor.
        if kind == "b" {
            bail!(
                "OCI block device {path} ({major}:{minor}) is not attached to the FluxVM guest; raw block volumes require VMM device hotplug"
            );
        }

        let mode = match kind {
            "c" | "u" => {
                // Character devices are safe only when the same device already
                // exists in the guest (e.g. /dev/null, /dev/zero, /dev/tty).
                // Device-plugin nodes such as GPUs therefore fail closed until
                // the corresponding hardware is explicitly attached to the VM.
                let source = PathBuf::from(path);
                let meta = std::fs::metadata(&source)
                    .with_context(|| format!("OCI character device {path} is not present in the guest"))?;
                if !meta.file_type().is_char_device() {
                    bail!("OCI character device source {path} is not a guest character device");
                }
                let rdev = meta.rdev();
                let actual_major = libc::major(rdev as libc::dev_t) as u64;
                let actual_minor = libc::minor(rdev as libc::dev_t) as u64;
                if (actual_major, actual_minor) != (major, minor) {
                    bail!(
                        "OCI character device {path} requested {major}:{minor}, guest has {actual_major}:{actual_minor}"
                    );
                }
                libc::S_IFCHR | file_mode
            }
            "p" => libc::S_IFIFO | file_mode,
            other => bail!("unsupported OCI device type {other:?}"),
        };
        let c = CString::new(target.as_os_str().as_bytes())?;
        let _ = std::fs::remove_file(&target);
        let devno = if kind == "p" { 0 } else { libc::makedev(major as _, minor as _) };
        let rc = unsafe { libc::mknod(c.as_ptr(), mode, devno) };
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
    let unified = config
        .pointer("/linux/resources/unified")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
                .collect()
        })
        .unwrap_or_default();
    ResourceLimits {
        cpu_quota: config.pointer("/linux/resources/cpu/quota").and_then(Value::as_i64),
        cpu_period: config.pointer("/linux/resources/cpu/period").and_then(Value::as_u64),
        cpu_shares: config.pointer("/linux/resources/cpu/shares").and_then(Value::as_u64),
        cpuset_cpus: config.pointer("/linux/resources/cpu/cpus").and_then(Value::as_str).map(str::to_string),
        cpuset_mems: config.pointer("/linux/resources/cpu/mems").and_then(Value::as_str).map(str::to_string),
        memory_limit_bytes: config.pointer("/linux/resources/memory/limit").and_then(Value::as_i64),
        memory_reservation_bytes: config.pointer("/linux/resources/memory/reservation").and_then(Value::as_i64),
        memory_swap_bytes: config.pointer("/linux/resources/memory/swap").and_then(Value::as_i64),
        pids_limit: config.pointer("/linux/resources/pids/limit").and_then(Value::as_i64),
        unified,
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

fn read_cgroup_limit(path: &std::path::Path) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let raw = raw.trim();
    if raw == "max" { Some(0) } else { raw.parse::<u64>().ok() }
}

fn current_memory_limit_for_swap(path: &std::path::Path) -> i64 {
    match std::fs::read_to_string(path.join("memory.max")) {
        Ok(raw) if raw.trim() == "max" => -1,
        Ok(raw) => raw.trim().parse::<i64>().unwrap_or(0),
        Err(_) => 0,
    }
}

/// Mirrors opencontainers/cgroups' cgroup-v1-compatible swap conversion:
/// OCI `memory.swap` is memory+swap combined, while cgroup v2's
/// `memory.swap.max` is swap-only.
fn oci_swap_to_cgroup2(memory_swap: i64, memory: i64) -> Result<Option<String>> {
    match (memory, memory_swap) {
        (-1, 0) => return Ok(Some("max".into())),
        (_, -1) => return Ok(Some("max".into())),
        (_, 0) => return Ok(None),
        (-1, swap) if swap > 0 => return Ok(Some(swap.to_string())),
        (0, _) => bail!("unable to set OCI memory.swap without a memory limit"),
        (memory, _) if memory < -1 => bail!("invalid OCI memory.limit value {memory}"),
        (_, swap) if swap < -1 => bail!("invalid OCI memory.swap value {swap}"),
        (memory, swap) if swap < memory => {
            bail!("OCI memory+swap limit ({swap}) must be >= memory limit ({memory})")
        }
        (memory, swap) => Ok(Some((swap - memory).to_string())),
    }
}

fn apply_unified_limits(path: &std::path::Path, unified: &std::collections::BTreeMap<String, String>) -> Result<()> {
    // Deliberately small cgroup-v2 allowlist. Never turn an OCI-provided key
    // directly into a filesystem path.
    const ALLOWED: &[&str] = &[
        "cpu.max.burst", "cpu.uclamp.min", "cpu.uclamp.max",
        "memory.min", "memory.low", "memory.high", "memory.max", "memory.swap.max", "memory.oom.group",
        "pids.max",
    ];
    for (key, value) in unified {
        if !ALLOWED.contains(&key.as_str()) {
            bail!("unsupported OCI LinuxResources.unified key {key:?}");
        }
        let value = value.trim();
        if value.is_empty() || value.contains('\n') || value.contains('\r') {
            bail!("invalid value for OCI unified key {key:?}");
        }
        let target = path.join(key);
        if !target.exists() {
            bail!("OCI unified key {key:?} is unavailable in guest cgroup v2");
        }
        std::fs::write(&target, value)
            .with_context(|| format!("writing OCI unified control {}={value}", target.display()))?;
    }
    Ok(())
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
        let value = match limit {
            0 => None,
            -1 => Some("max".to_string()),
            value if value > 0 => Some(value.to_string()),
            value => bail!("invalid OCI memory.limit value {value}"),
        };
        if let Some(value) = value {
            std::fs::write(path.join("memory.max"), value)?;
        }
    }
    if let Some(reservation) = resources.memory_reservation_bytes {
        let target = path.join("memory.low");
        if !target.exists() { bail!("OCI memory.reservation requested but memory.low is unavailable"); }
        let value = match reservation {
            0 => None,
            -1 => Some("max".to_string()),
            value if value > 0 => Some(value.to_string()),
            value => bail!("invalid OCI memory.reservation value {value}"),
        };
        if let Some(value) = value {
            std::fs::write(target, value)?;
        }
    }
    if let Some(memory_swap) = resources.memory_swap_bytes {
        let target = path.join("memory.swap.max");
        let memory = resources.memory_limit_bytes
            .unwrap_or_else(|| current_memory_limit_for_swap(path));
        if let Some(value) = oci_swap_to_cgroup2(memory_swap, memory)? {
            if !target.exists() {
                // Match runc's practical cgroup-v2 behavior for hosts/guests
                // without swap accounting: unlimited/disabled swap does not
                // need a backing controller file, but a finite request does.
                if value == "max" || value == "0" {
                    // No swap accounting in this guest; unlimited/disabled is
                    // already effectively satisfied, so keep applying the
                    // remaining resource fields below.
                } else {
                    bail!("OCI memory.swap requested but memory.swap.max is unavailable");
                }
            } else {
                std::fs::write(target, value)?;
            }
        }
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
    apply_unified_limits(path, &resources.unified)?;
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

fn read_u64_file(path: &std::path::Path) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

fn container_cgroup_events(id: &str) -> Result<CgroupEvents> {
    let path = container_cgroup(id)?.join("memory.events");
    Ok(CgroupEvents {
        low: parse_u64_field(&path, "low"),
        high: parse_u64_field(&path, "high"),
        max: parse_u64_field(&path, "max"),
        oom: parse_u64_field(&path, "oom"),
        oom_kill: parse_u64_field(&path, "oom_kill"),
        oom_group_kill: parse_u64_field(&path, "oom_group_kill"),
    })
}

fn container_stats(id: &str) -> Result<ContainerStats> {
    let path = container_cgroup(id)?;
    let cpu = path.join("cpu.stat");
    let memory = path.join("memory.stat");
    let events = container_cgroup_events(id)?;
    let pids_max = std::fs::read_to_string(path.join("pids.max")).unwrap_or_default();
    Ok(ContainerStats {
        cpu_usage_usec: parse_u64_field(&cpu, "usage_usec"),
        cpu_user_usec: parse_u64_field(&cpu, "user_usec"),
        cpu_system_usec: parse_u64_field(&cpu, "system_usec"),
        cpu_nr_periods: parse_u64_field(&cpu, "nr_periods"),
        cpu_nr_throttled: parse_u64_field(&cpu, "nr_throttled"),
        cpu_throttled_usec: parse_u64_field(&cpu, "throttled_usec"),
        memory_usage_bytes: read_u64_file(&path.join("memory.current")),
        memory_limit_bytes: read_cgroup_limit(&path.join("memory.max")).unwrap_or(0),
        memory_peak_bytes: read_u64_file(&path.join("memory.peak")),
        memory_swap_usage_bytes: read_u64_file(&path.join("memory.swap.current")),
        memory_swap_limit_bytes: read_cgroup_limit(&path.join("memory.swap.max")).unwrap_or(0),
        memory_anon_bytes: parse_u64_field(&memory, "anon"),
        memory_file_bytes: parse_u64_field(&memory, "file"),
        memory_anon_thp_bytes: parse_u64_field(&memory, "anon_thp"),
        memory_file_mapped_bytes: parse_u64_field(&memory, "file_mapped"),
        memory_dirty_bytes: parse_u64_field(&memory, "file_dirty"),
        memory_writeback_bytes: parse_u64_field(&memory, "file_writeback"),
        memory_pgfault: parse_u64_field(&memory, "pgfault"),
        memory_pgmajfault: parse_u64_field(&memory, "pgmajfault"),
        memory_inactive_anon_bytes: parse_u64_field(&memory, "inactive_anon"),
        memory_active_anon_bytes: parse_u64_field(&memory, "active_anon"),
        memory_total_inactive_file_bytes: parse_u64_field(&memory, "inactive_file"),
        memory_active_file_bytes: parse_u64_field(&memory, "active_file"),
        memory_unevictable_bytes: parse_u64_field(&memory, "unevictable"),
        memory_events_max: events.max,
        memory_events_oom: events.oom,
        memory_events_oom_kill: events.oom_kill,
        pids_current: read_u64_file(&path.join("pids.current")),
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

/// Set 6: opens namespace handles for a just-created container's outer
/// (reaper) process, once it has signaled that its unshare/setns calls are
/// complete. These become the container's durable namespace handles:
/// siblings sharing the sandbox's IPC/UTS/PID join via `setns()` on the
/// recorded fd, and `Exec` joins all of them so exec'd processes share the
/// container's mount/pid/ipc/uts (and user, if enabled) namespaces.
///
/// PID is the one namespace type where `/proc/<outer_pid>/ns/pid` is the
/// WRONG file to read: per pid_namespaces(7), a process that itself called
/// `unshare(CLONE_NEWPID)` (or `setns()` into a PID namespace) is never
/// moved into that namespace itself — only its *future children* are — so
/// `/proc/<outer_pid>/ns/pid` keeps showing the OUTER's own (ambient, e.g.
/// the guest init) namespace forever. The correct handle is the dedicated
/// `pid_for_children` magic symlink (Linux 4.12+), confirmed empirically
/// against this exact fork/unshare/setns sequence: it matches the inner
/// (execve'd) process's actual namespace, while plain `ns/pid` does not.
/// mnt/ipc/uts/user have no such split — unshare/setns move the calling
/// process itself immediately, so their plain `ns/<type>` files are correct.
fn open_container_namespaces(pid: libc::pid_t, include_user: bool) -> ContainerNamespaces {
    let open_ns = |name: &str| -> RawFd {
        match OpenOptions::new().read(true).open(format!("/proc/{pid}/ns/{name}")) {
            Ok(f) => {
                let fd = f.into_raw_fd();
                set_cloexec(fd);
                fd
            }
            Err(_) => -1,
        }
    };
    ContainerNamespaces {
        mnt: open_ns("mnt"),
        pid: open_ns("pid_for_children"),
        ipc: open_ns("ipc"),
        uts: open_ns("uts"),
        user: if include_user { open_ns("user") } else { -1 },
    }
}

/// Set 6: `pivot_root` into `rootfs`, replacing the bare `chroot` used
/// through Set 5. Must run inside a process that has already unshared
/// `CLONE_NEWNS` (a private copy of the mount table) — the bind-mount and
/// pivot below are otherwise visible to every other member of the caller's
/// mount namespace. Async-signal-safe: no allocation, called only from a
/// freshly forked, single-threaded, pre-`execve` child.
unsafe fn pivot_root_into(rootfs: &CString) -> bool {
    unsafe {
        // Detach mount propagation before touching anything, so pivoting
        // never leaks back into whatever peer group "/" belonged to.
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        ) != 0
        {
            return false;
        }
        // pivot_root(2) requires new_root to be a mount point; bind-mounting
        // it onto itself makes an ordinary directory qualify.
        if libc::mount(rootfs.as_ptr(), rootfs.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) != 0 {
            return false;
        }
        if libc::chdir(rootfs.as_ptr()) != 0 {
            return false;
        }
        if libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) != 0 {
            return false;
        }
        // The old root is now mounted at "." (on top of the new root); lazily
        // detach it so it stops being reachable at all, then land at "/".
        if libc::umount2(c".".as_ptr(), libc::MNT_DETACH) != 0 {
            return false;
        }
        if libc::chdir(c"/".as_ptr()) != 0 {
            return false;
        }
        // A private mount namespace inherits whatever /proc was mounted at
        // unshare time, which reflects the wrong PID namespace once this
        // container's init lands in its own (or a joined) PID namespace.
        if libc::mount(c"proc".as_ptr(), c"/proc".as_ptr(), c"proc".as_ptr(), 0, std::ptr::null()) != 0 {
            return false;
        }
        true
    }
}

fn spawn_gated(
    container_id: &str,
    exec_id: Option<&str>,
    spec: &ProcessSpec,
    io: &ContainerIo,
    ns_request: NsRequest,
) -> Result<(Arc<ProcHandle>, ContainerNamespaces)> {
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

    let mut parent_fds = Vec::new();
    let mut pty_slave: Option<File> = None;
    let (stdin, stdout, stderr, process_io) = if io.streaming && io.terminal {
        let (master, slave) = open_pty_pair()?;
        parent_fds.push(master);
        pty_slave = Some(unsafe { File::from_raw_fd(slave) });
        (
            None,
            None,
            None,
            ProcIo::Pty { master_fd: master, stdin_attached: false, stdout_attached: false },
        )
    } else if io.streaming {
        let (stdin_file, stdin_write) = if io.stdin.is_some() {
            let (read_fd, write_fd) = pipe_cloexec()?;
            parent_fds.push(write_fd);
            (Some(unsafe { File::from_raw_fd(read_fd) }), Some(write_fd))
        } else {
            (Some(OpenOptions::new().read(true).open("/dev/null")?), None)
        };
        let (stdout_file, stdout_read) = if io.stdout.is_some() {
            let (read_fd, write_fd) = pipe_cloexec()?;
            parent_fds.push(read_fd);
            (Some(unsafe { File::from_raw_fd(write_fd) }), Some(read_fd))
        } else {
            (Some(OpenOptions::new().write(true).open("/dev/null")?), None)
        };
        let (stderr_file, stderr_read) = if io.stderr.is_some() {
            let (read_fd, write_fd) = pipe_cloexec()?;
            parent_fds.push(read_fd);
            (Some(unsafe { File::from_raw_fd(write_fd) }), Some(read_fd))
        } else {
            (Some(OpenOptions::new().write(true).open("/dev/null")?), None)
        };
        (
            stdin_file,
            stdout_file,
            stderr_file,
            ProcIo::Pipes {
                stdin_write,
                stdin_attached: false,
                stdout_read,
                stdout_attached: false,
                stderr_read,
                stderr_attached: false,
            },
        )
    } else {
        (
            open_input(io.stdin.as_deref())?,
            open_output(io.stdout.as_deref())?,
            open_output(io.stderr.as_deref())?,
            ProcIo::Legacy,
        )
    };

    // Set 6: work out which namespaces this process needs to create fresh
    // vs. join before either fork happens (allocation is unsafe once a
    // multi-threaded process has forked, so this must be fully resolved
    // now — the forked branches below only ever *read* these values).
    let userns = userns_enabled();
    let (create_flags, join_list): (libc::c_int, Vec<(RawFd, libc::c_int)>) = match &ns_request {
        NsRequest::Create { is_sandbox, share_process_namespace } => {
            let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWPID;
            let mut joins = Vec::new();
            if *is_sandbox {
                flags |= libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
            } else {
                let sandbox = sandbox_namespaces().lock().expect("sandbox ns poisoned");
                match sandbox.as_ref() {
                    Some(sb) => {
                        joins.push((sb.ipc, libc::CLONE_NEWIPC));
                        joins.push((sb.uts, libc::CLONE_NEWUTS));
                        if *share_process_namespace && sb.pid >= 0 {
                            joins.push((sb.pid, libc::CLONE_NEWPID));
                            flags &= !libc::CLONE_NEWPID;
                        }
                    }
                    None => {
                        // No sandbox recorded yet (bare `ctr run`, or this
                        // shim's group-derivation saw no CRI sandbox
                        // annotation): fully isolate, matching pre-Set-6
                        // per-container behavior.
                        flags |= libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
                    }
                }
            }
            if userns {
                flags |= libc::CLONE_NEWUSER;
            }
            (flags, joins)
        }
        NsRequest::Exec { target } => {
            let mut joins = Vec::new();
            for (fd, ty) in [
                (target.user, libc::CLONE_NEWUSER),
                (target.mnt, libc::CLONE_NEWNS),
                (target.ipc, libc::CLONE_NEWIPC),
                (target.uts, libc::CLONE_NEWUTS),
                (target.pid, libc::CLONE_NEWPID),
            ] {
                if fd >= 0 { joins.push((fd, ty)); }
            }
            (0, joins)
        }
    };
    let creates_mount_ns = create_flags & libc::CLONE_NEWNS != 0;
    // Exec joining an existing container: `setns(mnt_fd, CLONE_NEWNS)` in the
    // outer process below takes effect immediately (unlike PID) and is
    // inherited by the inner process via the subsequent fork, so "/" is
    // already the container's pivoted rootfs by the time inner code runs —
    // no chroot/pivot_root needed there at all.
    let joined_mount_ns = join_list.iter().any(|(_, ty)| *ty == libc::CLONE_NEWNS);
    let is_create = matches!(ns_request, NsRequest::Create { .. });
    let want_user_ns = create_flags & libc::CLONE_NEWUSER != 0;

    let mut gate = [0; 2];
    if unsafe { libc::pipe2(gate.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe2: {}", std::io::Error::last_os_error());
    }
    // Set 6: signals "the outer (reaper) process has finished unshare/setns
    // and successfully forked the inner (execve'd) process" back to this
    // caller, so it's safe to open /proc/<outer_pid>/ns/* — reading those
    // paths any earlier could observe pre-unshare (i.e. wrong) namespaces.
    let mut ns_ready = [0; 2];
    if unsafe { libc::pipe2(ns_ready.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        unsafe { libc::close(gate[0]); libc::close(gate[1]); }
        bail!("pipe2 (ns_ready): {}", std::io::Error::last_os_error());
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(gate[0]);
            libc::close(gate[1]);
            libc::close(ns_ready[0]);
            libc::close(ns_ready[1]);
        }
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        // === Outer (namespace-establishing reaper) process ===
        unsafe {
            libc::close(gate[1]);
            libc::close(ns_ready[0]);
            for fd in &parent_fds { libc::close(*fd); }

            if create_flags != 0 && libc::unshare(create_flags) != 0 { libc::_exit(126); }
            if want_user_ns {
                // We created this user namespace (via the unshare above), so
                // we automatically hold CAP_SETUID/CAP_SETGID within it and
                // can map ourselves without an external writer. A full
                // identity map buys a distinct capability-scoping namespace
                // without uid-shifting complexity against virtiofs ACLs.
                let _ = std::fs::write("/proc/self/setgroups", "deny");
                if std::fs::write("/proc/self/uid_map", "0 0 4294967295").is_err()
                    || std::fs::write("/proc/self/gid_map", "0 0 4294967295").is_err()
                {
                    libc::_exit(126);
                }
            }
            for (fd, ty) in &join_list {
                if libc::setns(*fd, *ty) != 0 { libc::_exit(126); }
            }

            let inner_pid = libc::fork();
            if inner_pid < 0 { libc::_exit(125); }
            if inner_pid != 0 {
                // Still outer: hand off readiness, drop our own copies of
                // the stdio fds (so EOF on the agent side depends only on
                // the inner process's lifetime, exactly as pre-Set-6), then
                // reap the inner process and exit with its translated code.
                let byte = [1u8; 1];
                let _ = libc::write(ns_ready[1], byte.as_ptr().cast(), 1);
                libc::close(ns_ready[1]);
                libc::close(gate[0]);
                drop(stdin);
                drop(stdout);
                drop(stderr);
                drop(pty_slave);
                let mut status = 0i32;
                let rc = libc::waitpid(inner_pid, &mut status, 0);
                let code = if rc < 0 {
                    255
                } else if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else if libc::WIFSIGNALED(status) {
                    128 + libc::WTERMSIG(status)
                } else {
                    255
                };
                libc::_exit(code);
            }

            // === Inner (execve'd) process: PID 1 of a fresh PID namespace,
            // or a plain member of a joined one, per the setns above ===
            libc::close(ns_ready[1]);

            if let Some(ref slave) = pty_slave {
                if libc::setsid() < 0 { libc::_exit(126); }
                if libc::ioctl(slave.as_raw_fd(), libc::TIOCSCTTY as libc::c_ulong, 0) != 0 { libc::_exit(126); }
                libc::dup2(slave.as_raw_fd(), libc::STDIN_FILENO);
                libc::dup2(slave.as_raw_fd(), libc::STDOUT_FILENO);
                libc::dup2(slave.as_raw_fd(), libc::STDERR_FILENO);
            } else {
                libc::setpgid(0, 0);
                if let Some(ref file) = stdin { libc::dup2(file.as_raw_fd(), libc::STDIN_FILENO); }
                if let Some(ref file) = stdout { libc::dup2(file.as_raw_fd(), libc::STDOUT_FILENO); }
                if let Some(ref file) = stderr { libc::dup2(file.as_raw_fd(), libc::STDERR_FILENO); }
            }

            let mut byte = [0u8; 1];
            if libc::read(gate[0], byte.as_mut_ptr().cast(), 1) != 1 { libc::_exit(126); }
            libc::close(gate[0]);
            if creates_mount_ns {
                if !pivot_root_into(&rootfs) { libc::_exit(126); }
            } else if !joined_mount_ns && libc::chroot(rootfs.as_ptr()) != 0 {
                // Only reachable if a container's own mount-namespace fd
                // could not be recorded at create time (see
                // `open_container_namespaces`) — fall back to a bare chroot
                // rather than running this exec fully unconfined.
                libc::_exit(126);
            }
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

            let groups: Vec<libc::gid_t> = spec.additional_gids.iter().map(|v| *v as libc::gid_t).collect();
            let group_ptr = if groups.is_empty() { std::ptr::null() } else { groups.as_ptr() };
            if libc::setgroups(groups.len(), group_ptr) != 0 { libc::_exit(126); }
            if let Some(caps) = spec.capabilities.as_ref() {
                if drop_bounding_capabilities(caps).is_err() { libc::_exit(126); }
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

    // === Back in the request-handling thread ===
    unsafe { libc::close(ns_ready[1]) };
    let mut ready = [0u8; 1];
    let ready_rc = unsafe { libc::read(ns_ready[0], ready.as_mut_ptr().cast(), 1) };
    unsafe { libc::close(ns_ready[0]) };
    if ready_rc != 1 {
        unsafe { libc::close(gate[0]); libc::close(gate[1]); }
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        bail!("container process failed to establish namespaces (wait status {status})");
    }
    let namespaces = if is_create {
        open_container_namespaces(pid, want_user_ns)
    } else {
        ContainerNamespaces::default()
    };

    unsafe { libc::close(gate[0]) };
    drop(stdin);
    drop(stdout);
    drop(stderr);
    drop(pty_slave);
    let handle = Arc::new(ProcHandle::new_created(pid as u32, gate[1], process_io));
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
    Ok((handle, namespaces))
}

fn pipe_cloexec() -> Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe2: {}", std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

fn open_pty_pair() -> Result<(RawFd, RawFd)> {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if master < 0 { bail!("posix_openpt: {}", std::io::Error::last_os_error()); }
        if libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(master);
            bail!("initializing PTY: {e}");
        }
        let mut name = [0 as libc::c_char; 128];
        if libc::ptsname_r(master, name.as_mut_ptr(), name.len()) != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(master);
            bail!("ptsname_r: {e}");
        }
        let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
        if slave < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(master);
            bail!("opening PTY slave: {e}");
        }
        let ws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
        let _ = libc::ioctl(master, libc::TIOCSWINSZ as libc::c_ulong, &ws);
        Ok((master, slave))
    }
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
    fn rejects_unattached_block_device_nodes() {
        let root = std::env::temp_dir().join(format!("fluxvm-block-device-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let config = serde_json::json!({
            "linux": {"devices": [{
                "path": "/dev/raw-volume", "type": "b", "major": 253, "minor": 17, "fileMode": 384
            }]}
        });
        let error = create_oci_devices(&config, &root).unwrap_err().to_string();
        assert!(error.contains("raw block volumes require VMM device hotplug"));
        let _ = std::fs::remove_dir_all(root);
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

    #[test]
    fn pty_pair_has_default_size_and_can_resize() {
        let (master, slave) = open_pty_pair().unwrap();
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(master, libc::TIOCGWINSZ as libc::c_ulong, &mut ws) };
        assert_eq!(rc, 0);
        assert_eq!((ws.ws_col, ws.ws_row), (80, 24));
        let new_ws = libc::winsize { ws_row: 33, ws_col: 101, ws_xpixel: 0, ws_ypixel: 0 };
        let rc = unsafe { libc::ioctl(master, libc::TIOCSWINSZ as libc::c_ulong, &new_ws) };
        assert_eq!(rc, 0);
        let mut read_back: libc::winsize = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::ioctl(master, libc::TIOCGWINSZ as libc::c_ulong, &mut read_back) };
        assert_eq!(rc, 0);
        assert_eq!((read_back.ws_col, read_back.ws_row), (101, 33));
        unsafe { libc::close(master); libc::close(slave); }
    }

    #[test]
    fn oci_swap_translation_matches_cgroup_v2_semantics() {
        assert_eq!(oci_swap_to_cgroup2(512, 256).unwrap().as_deref(), Some("256"));
        assert_eq!(oci_swap_to_cgroup2(-1, 256).unwrap().as_deref(), Some("max"));
        assert_eq!(oci_swap_to_cgroup2(0, 256).unwrap(), None);
        assert_eq!(oci_swap_to_cgroup2(0, -1).unwrap().as_deref(), Some("max"));
        assert_eq!(oci_swap_to_cgroup2(512, -1).unwrap().as_deref(), Some("512"));
        assert!(oci_swap_to_cgroup2(128, 256).is_err());
        assert!(oci_swap_to_cgroup2(512, 0).is_err());
    }

    #[test]
    fn resource_parser_keeps_reservation_swap_and_unified() {
        let resources = resource_limits_from_oci(&serde_json::json!({
            "linux": {"resources": {
                "memory": {"limit": 256, "reservation": 128, "swap": 512},
                "unified": {"memory.high": "192", "memory.oom.group": "1"}
            }}
        }));
        assert_eq!(resources.memory_limit_bytes, Some(256));
        assert_eq!(resources.memory_reservation_bytes, Some(128));
        assert_eq!(resources.memory_swap_bytes, Some(512));
        assert_eq!(resources.unified.get("memory.high").map(String::as_str), Some("192"));
    }

    #[test]
    fn stream_pipe_is_cloexec() {
        let (read_fd, write_fd) = pipe_cloexec().unwrap();
        let r = unsafe { libc::fcntl(read_fd, libc::F_GETFD) };
        let w = unsafe { libc::fcntl(write_fd, libc::F_GETFD) };
        assert_ne!(r & libc::FD_CLOEXEC, 0);
        assert_ne!(w & libc::FD_CLOEXEC, 0);
        unsafe { libc::close(read_fd); libc::close(write_fd); }
    }
}
