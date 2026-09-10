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
//! Set 8 resolves QMP-hotplugged raw block devices by stable SCSI serial and
//! binds guest-driver-created VFIO character nodes into the container rootfs.
//! Set 9 extends that guest-resolution path to driver companion nodes (for
//! example nvidiactl/UVM and AMD KFD) while keeping host device numbers out.
//! Set 10 adds OCI seccomp argument comparators, AppArmor/SELinux process
//! labels, and per-container cgroup-v2 BPF device access enforcement. Set 11
//! adds a bounded seccomp userspace-notification broker, SELinux mount labels,
//! and monotonic security counters. Newer upstream Secure Containers work also
//! layers per-container namespace isolation.

use anyhow::{Context, Result, bail};
use aya::{
    Btf, Ebpf,
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, Lsm},
};
use clap::Parser;
use fluxvm_container_protocol::{
    CgroupEvents, ContainerEnvelope, ContainerIo, ContainerNetworkPolicy, ContainerRequest,
    ContainerResponse, ContainerStats, ContainerStatus, ResourceLimits, SecurityStats,
    IoStreamAck, IoStreamAttach, IoStreamKind,
    DEFAULT_CONTAINER_AGENT_PORT, DEFAULT_CONTAINER_STREAM_PORT, MAX_MESSAGE_BYTES, decode_line,
    encode_line,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    net::IpAddr,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, OnceLock, atomic::{AtomicU64, Ordering}},
    time::{Duration, SystemTime, UNIX_EPOCH},
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
struct SeccompArg {
    index: u32,
    op: u32,
    value: u64,
    value_two: u64,
}

#[derive(Clone, Debug)]
struct SeccompRule {
    action: u32,
    names: Vec<String>,
    args: Vec<SeccompArg>,
}

#[derive(Clone, Debug)]
struct SeccompProfile {
    default_action: u32,
    rules: Vec<SeccompRule>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SeccompNotifyMode {
    Deny,
    Continue,
}

#[derive(Clone, Copy, Debug)]
struct SeccompNotifyPolicy {
    mode: SeccompNotifyMode,
    errno: i32,
}

impl Default for SeccompNotifyPolicy {
    fn default() -> Self {
        Self { mode: SeccompNotifyMode::Deny, errno: libc::EPERM }
    }
}

#[derive(Default)]
struct SecurityCounters {
    seccomp_notify_received: AtomicU64,
    seccomp_notify_denied: AtomicU64,
    seccomp_notify_continued: AtomicU64,
    seccomp_notify_errors: AtomicU64,
    selinux_mounts_labeled: AtomicU64,
    lsm_apply_failures: AtomicU64,
}

static SECURITY_COUNTERS: OnceLock<SecurityCounters> = OnceLock::new();

fn security_counters() -> &'static SecurityCounters {
    SECURITY_COUNTERS.get_or_init(SecurityCounters::default)
}

fn security_stats_snapshot() -> SecurityStats {
    let c = security_counters();
    SecurityStats {
        seccomp_notify_received: c.seccomp_notify_received.load(Ordering::Relaxed),
        seccomp_notify_denied: c.seccomp_notify_denied.load(Ordering::Relaxed),
        seccomp_notify_continued: c.seccomp_notify_continued.load(Ordering::Relaxed),
        seccomp_notify_errors: c.seccomp_notify_errors.load(Ordering::Relaxed),
        selinux_mounts_labeled: c.selinux_mounts_labeled.load(Ordering::Relaxed),
        lsm_apply_failures: c.lsm_apply_failures.load(Ordering::Relaxed),
    }
}

#[derive(Clone, Debug)]
struct DeviceCgroupRule {
    allow: bool,
    dev_type: Option<u32>,
    major: Option<u32>,
    minor: Option<u32>,
    access: u32,
}

#[derive(Clone, Debug)]
struct DeviceCgroupPolicy {
    default_allow: bool,
    rules: Vec<DeviceCgroupRule>,
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
    seccomp_notify: SeccompNotifyPolicy,
    apparmor_profile: Option<String>,
    selinux_label: Option<String>,
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
    seccomp_notify: SeccompNotifyPolicy,
    apparmor_profile: Option<String>,
    selinux_label: Option<String>,
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
        ContainerRequest::Create { id, config_json, io, is_sandbox, share_process_namespace, network_policy } => {
            create_container(id, &config_json, io, is_sandbox, share_process_namespace, network_policy.as_ref())
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
        ContainerRequest::SecurityStats => Ok(ContainerResponse::SecurityStats { stats: security_stats_snapshot() }),
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
    network_policy: Option<&ContainerNetworkPolicy>,
) -> Result<ContainerResponse> {
    let (spec, mounts, resources, device_policy) = parse_oci_config(config_json)?;
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
    if let Some(policy) = device_policy.as_ref() {
        if let Err(e) = attach_device_cgroup_policy(&cgroup_path, policy) {
            cleanup_mounts(&mounts);
            let _ = std::fs::remove_dir(&cgroup_path);
            return Err(e);
        }
    }
    // Sentinel Set 8S: attach in-guest per-container network policy before
    // spawning the process, so it's enforced from this container's very
    // first packet. Best-effort like the resource-limit cgroup itself above
    // it: a guest kernel missing cgroup_skb/BTF support still runs the
    // container, just without this layer -- see
    // docs/secure-containers-set8s.md for why this differs from the
    // fail-closed-by-default *policy content* design (attach failure is a
    // platform-capability gap, not a missing-policy race).
    match attach_guest_network_policy(&cgroup_path) {
        Ok(()) => {
            if let Err(e) = configure_container_policy(cgroup_id_for(&cgroup_path).unwrap_or(0), network_policy) {
                eprintln!("Set 8S: configuring guest network policy for {id:?} failed: {e:#}");
            }
        }
        Err(e) => eprintln!("Set 8S: attaching guest network policy for {id:?} failed: {e:#}"),
    }
    // Sentinel Set 9S: off by default (FLUXVM_CONTAINER_LSM=1 to enable) --
    // a new guest MAC control that, unlike Set 8S's network policy, can
    // plausibly break a container that legitimately writes outside its
    // declared mounts if misconfigured. Same best-effort posture as Set 8S:
    // a guest kernel missing BPF LSM/BTF still runs the container, just
    // without this layer. See docs/secure-containers-set9s.md.
    let container_identity = if guest_lsm_enabled() {
        let identity = container_identity_for(&id);
        match attach_guest_lsm() {
            Ok(()) => {
                let (root_readonly, write_prefixes) = oci_write_policy(config_json);
                let audit_only = std::env::var("FLUXVM_CONTAINER_LSM_ENFORCE")
                    .map(|v| !matches!(v.as_str(), "1" | "true" | "yes" | "on"))
                    .unwrap_or(true);
                let deny_wx = std::env::var("FLUXVM_CONTAINER_LSM_DENY_WX")
                    .map(|v| !matches!(v.as_str(), "0" | "false" | "no" | "off"))
                    .unwrap_or(true);
                if let Err(e) = configure_container_lsm_policy(
                    cgroup_id_for(&cgroup_path).unwrap_or(0),
                    deny_wx,
                    root_readonly,
                    &write_prefixes,
                    audit_only,
                ) {
                    eprintln!("Set 9S: configuring guest LSM policy for {id:?} failed: {e:#}");
                }
            }
            Err(e) => eprintln!("Set 9S: attaching guest LSM for {id:?} failed: {e:#}"),
        }
        identity
    } else {
        0
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
            seccomp_notify: spec.seccomp_notify,
            apparmor_profile: spec.apparmor_profile.clone(),
            selinux_label: spec.selinux_label.clone(),
            namespaces,
            is_sandbox,
            init,
            execs: HashMap::new(),
        },
    );
    Ok(ContainerResponse::Created { pid, container_identity })
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
    spec.seccomp_notify = container.seccomp_notify;
    if spec.apparmor_profile.is_none() {
        spec.apparmor_profile = container.apparmor_profile.clone();
    }
    if spec.selinux_label.is_none() {
        spec.selinux_label = container.selinux_label.clone();
    }
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
            // Must read the cgroup id before cleanup_container_cgroup
            // removes the directory out from under us.
            if let Ok(cgroup_id) = cgroup_id_for(&entry.cgroup_path) {
                forget_container_policy(cgroup_id);
                forget_container_lsm_policy(cgroup_id);
            }
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

fn parse_oci_config(json: &str) -> Result<(ProcessSpec, Vec<PathBuf>, ResourceLimits, Option<DeviceCgroupPolicy>)> {
    let v: Value = serde_json::from_str(json).context("parsing OCI config.json")?;
    let root = v
        .pointer("/root/path")
        .and_then(Value::as_str)
        .context("OCI root.path is required")?;
    let rootfs = PathBuf::from(root);
    let mount_label = v.pointer("/linux/mountLabel").and_then(Value::as_str).filter(|v| !v.is_empty());
    if let Some(label) = mount_label {
        validate_selinux_mount_label(label)?;
    }
    let mut mounts = apply_oci_mounts(&v, &rootfs, mount_label)?;
    let parsed = (|| -> Result<(ProcessSpec, ResourceLimits, Option<DeviceCgroupPolicy>)> {
        let device_mounts = create_oci_devices(&v, &rootfs)?;
        mounts.extend(device_mounts);
        apply_oci_sysctls(&v)?;
        apply_oci_path_security(&v, &rootfs, &mut mounts)?;
        let process = v.get("process").context("OCI process is required")?;
        let resources = resource_limits_from_oci(&v);
        let device_policy = parse_device_cgroup_policy(&v)?;
        let mut spec = parse_process_value(process, rootfs.clone())?;
        spec.seccomp = parse_seccomp_profile(&v)?;
        spec.seccomp_notify = parse_seccomp_notify_policy(&v)?;
        Ok((spec, resources, device_policy))
    })();
    match parsed {
        Ok((spec, resources, device_policy)) => Ok((spec, mounts, resources, device_policy)),
        Err(e) => {
            cleanup_mounts(&mounts);
            Err(e)
        }
    }
}


fn apply_oci_mounts(config: &Value, rootfs: &PathBuf, mount_label: Option<&str>) -> Result<Vec<PathBuf>> {
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
        let raw_source = item.get("source").and_then(Value::as_str).unwrap_or(fs_type);
        let resolved_source = if let Some(serial) = raw_source.strip_prefix("fluxvm-block://") {
            resolve_hotplug_block(serial, Duration::from_secs(10))?
                .to_string_lossy().into_owned()
        } else {
            raw_source.to_string()
        };
        let source = resolved_source.as_str();
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
        let data = format_selinux_mount_data(data.as_deref(), mount_label)?;
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

        if mount_label.is_some() {
            security_counters().selinux_mounts_labeled.fetch_add(1, Ordering::Relaxed);
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

fn resolve_hotplug_block(serial: &str, timeout: Duration) -> Result<PathBuf> {
    if serial.is_empty() || !serial.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        bail!("unsafe FluxVM block serial {serial:?}");
    }
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(entries) = std::fs::read_dir("/sys/class/block") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let sys = entry.path();
                for serial_path in [sys.join("device/serial"), sys.join("serial")] {
                    let Ok(found) = std::fs::read_to_string(&serial_path) else { continue; };
                    if found.trim() == serial {
                        let dev = PathBuf::from("/dev").join(&name);
                        if std::fs::metadata(&dev).map(|m| m.file_type().is_block_device()).unwrap_or(false) {
                            return Ok(dev);
                        }
                    }
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            bail!("timed out waiting for QMP-hotplugged block device serial {serial}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_guest_char_device(path: &str, timeout: Duration) -> Result<PathBuf> {
    let source = PathBuf::from(path);
    if !source.is_absolute() || !source.starts_with("/dev") || path.contains("..") {
        bail!("unsafe hotplugged guest device path {path:?}");
    }
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if std::fs::metadata(&source).map(|m| m.file_type().is_char_device()).unwrap_or(false) {
            return Ok(source);
        }
        if std::time::Instant::now() >= deadline {
            bail!("timed out waiting for guest driver device {path}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn create_oci_devices(config: &Value, rootfs: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut mounted = Vec::new();
    let Some(devices) = config.pointer("/linux/devices").and_then(Value::as_array) else { return Ok(mounted); };
    for dev in devices {
        let path = dev.get("path").and_then(Value::as_str).context("OCI device.path is required")?;
        let relative = safe_guest_destination(path)?;
        let target = rootfs.join(relative);
        if let Some(parent) = target.parent() { std::fs::create_dir_all(parent)?; }
        let kind = dev.get("type").and_then(Value::as_str).context("OCI device.type is required")?;
        let file_mode = dev.get("fileMode").and_then(Value::as_u64).unwrap_or(0o666) as libc::mode_t;
        let major_raw = dev.get("major").and_then(Value::as_i64).unwrap_or(0);
        let minor_raw = dev.get("minor").and_then(Value::as_i64).unwrap_or(0);

        // Set 8 raw block marker: resolve the QMP SCSI serial in the guest
        // and bind the actual guest block node at the OCI target path.
        if kind == "b" && major_raw == -2 && minor_raw == -2 {
            let serial = dev.get("fluxvmBlockSerial").and_then(Value::as_str)
                .context("FluxVM hotplugged block device is missing fluxvmBlockSerial")?;
            let source = resolve_hotplug_block(serial, Duration::from_secs(10))?;
            if target.exists() { let _ = std::fs::remove_file(&target); }
            File::create(&target)?;
            let source_text = source.to_string_lossy().into_owned();
            mount_one(&source_text, &target, None, libc::MS_BIND, None)
                .with_context(|| format!("binding hotplugged block device {serial} at {path}"))?;
            mounted.push(target);
            continue;
        }

        // Set 8 VFIO marker: the host shim has attached the PCI device to
        // QEMU and rewritten host major/minor to -1. Wait for the guest
        // driver to create the requested node, then bind that *guest* node
        // into the container rootfs. Never recreate a host device number.
        if matches!(kind, "c" | "u") && major_raw < 0 && minor_raw < 0 {
            let source = wait_guest_char_device(path, Duration::from_secs(15))?;
            if target.exists() { let _ = std::fs::remove_file(&target); }
            File::create(&target)?;
            let source_text = source.to_string_lossy().into_owned();
            mount_one(&source_text, &target, None, libc::MS_BIND, None)
                .with_context(|| format!("binding hotplugged guest device {path}"))?;
            mounted.push(target);
            continue;
        }

        let major = major_raw.max(0) as u64;
        let minor = minor_raw.max(0) as u64;

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
    Ok(mounted)
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
const SCMP_ACT_NOTIFY: u32 = 0x7fc0_0000;
const SCMP_ACT_LOG: u32 = 0x7ffc_0000;
const SCMP_ACT_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

const SCMP_CMP_NE: u32 = 1;
const SCMP_CMP_LT: u32 = 2;
const SCMP_CMP_LE: u32 = 3;
const SCMP_CMP_EQ: u32 = 4;
const SCMP_CMP_GE: u32 = 5;
const SCMP_CMP_GT: u32 = 6;
const SCMP_CMP_MASKED_EQ: u32 = 7;

fn seccomp_action(raw: &str, errno_ret: Option<u32>) -> Result<u32> {
    if raw != "SCMP_ACT_ERRNO" && errno_ret.is_some() {
        bail!("OCI seccomp errnoRet is valid only with SCMP_ACT_ERRNO");
    }
    Ok(match raw {
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_THREAD" => SCMP_ACT_KILL_THREAD,
        "SCMP_ACT_KILL_PROCESS" => SCMP_ACT_KILL_PROCESS,
        "SCMP_ACT_TRAP" => SCMP_ACT_TRAP,
        "SCMP_ACT_ERRNO" => {
            let errno = errno_ret.unwrap_or(libc::EPERM as u32);
            if errno > 0xffff { bail!("OCI seccomp errnoRet {errno} exceeds the kernel 16-bit action data field"); }
            SCMP_ACT_ERRNO | errno
        }
        "SCMP_ACT_LOG" => SCMP_ACT_LOG,
        "SCMP_ACT_ALLOW" => SCMP_ACT_ALLOW,
        "SCMP_ACT_NOTIFY" => SCMP_ACT_NOTIFY,
        "SCMP_ACT_TRACE" => bail!("OCI seccomp TRACE is not supported by FluxVM Set 11"),
        other => bail!("unsupported OCI seccomp action {other:?}"),
    })
}

fn parse_seccomp_notify_policy(config: &Value) -> Result<SeccompNotifyPolicy> {
    let annotations = config.get("annotations").and_then(Value::as_object);
    let mode = annotations
        .and_then(|a| a.get("io.zyvor.seccomp.notify.mode"))
        .and_then(Value::as_str)
        .unwrap_or("deny");
    let mode = match mode {
        "deny" => SeccompNotifyMode::Deny,
        "continue" => SeccompNotifyMode::Continue,
        other => bail!("invalid io.zyvor.seccomp.notify.mode {other:?}; expected deny or continue"),
    };
    let errno = annotations
        .and_then(|a| a.get("io.zyvor.seccomp.notify.errno"))
        .and_then(Value::as_str)
        .map(|v| v.parse::<i32>().context("parsing io.zyvor.seccomp.notify.errno"))
        .transpose()?
        .unwrap_or(libc::EPERM);
    if !(1..=4095).contains(&errno) {
        bail!("io.zyvor.seccomp.notify.errno must be in 1..=4095");
    }
    Ok(SeccompNotifyPolicy { mode, errno })
}

fn seccomp_action_base(action: u32) -> u32 {
    action & 0xffff_0000
}

fn seccomp_profile_uses_notify(profile: &SeccompProfile) -> bool {
    seccomp_action_base(profile.default_action) == SCMP_ACT_NOTIFY
        || profile.rules.iter().any(|rule| seccomp_action_base(rule.action) == SCMP_ACT_NOTIFY)
}

fn seccomp_compare(raw: &str) -> Result<u32> {
    Ok(match raw {
        "SCMP_CMP_NE" => SCMP_CMP_NE,
        "SCMP_CMP_LT" => SCMP_CMP_LT,
        "SCMP_CMP_LE" => SCMP_CMP_LE,
        "SCMP_CMP_EQ" => SCMP_CMP_EQ,
        "SCMP_CMP_GE" => SCMP_CMP_GE,
        "SCMP_CMP_GT" => SCMP_CMP_GT,
        "SCMP_CMP_MASKED_EQ" => SCMP_CMP_MASKED_EQ,
        other => bail!("unsupported OCI seccomp comparison operator {other:?}"),
    })
}

fn parse_seccomp_profile(config: &Value) -> Result<Option<SeccompProfile>> {
    let Some(seccomp) = config.pointer("/linux/seccomp") else { return Ok(None); };
    if let Some(arches) = seccomp.get("architectures").and_then(Value::as_array) {
        for arch in arches.iter().filter_map(Value::as_str) {
            if arch != "SCMP_ARCH_X86_64" {
                bail!("unsupported OCI seccomp architecture {arch:?}; FluxVM Set 11 currently enforces native x86_64 only");
            }
        }
    }
    let default_action = seccomp_action(
        seccomp.get("defaultAction").and_then(Value::as_str).context("OCI seccomp.defaultAction is required")?,
        seccomp.get("defaultErrnoRet").and_then(Value::as_u64).map(|v| v as u32),
    )?;
    if seccomp_action_base(default_action) == SCMP_ACT_NOTIFY {
        bail!("SCMP_ACT_NOTIFY is not supported as seccomp.defaultAction because the listener bootstrap syscalls would deadlock; use explicit NOTIFY syscall rules");
    }
    let mut rules = Vec::new();
    if let Some(items) = seccomp.get("syscalls").and_then(Value::as_array) {
        for item in items {
            let action = seccomp_action(
                item.get("action").and_then(Value::as_str).context("OCI seccomp syscall action is required")?,
                item.get("errnoRet").and_then(Value::as_u64).map(|v| v as u32),
            )?;
            let names = item.get("names").and_then(Value::as_array).context("OCI seccomp syscall names are required")?
                .iter().map(|v| v.as_str().map(str::to_string).context("seccomp syscall name must be a string"))
                .collect::<Result<Vec<_>>>()?;
            if names.is_empty() { bail!("OCI seccomp syscall rule must contain at least one name"); }
            if seccomp_action_base(action) == SCMP_ACT_NOTIFY && names.iter().any(|name| name == "sendmsg") {
                bail!("seccomp NOTIFY on sendmsg is unsafe for FluxVM because sendmsg transfers the notification listener to the guest supervisor");
            }
            let mut args = Vec::new();
            if let Some(items) = item.get("args").and_then(Value::as_array) {
                for arg in items {
                    let index = arg.get("index").and_then(Value::as_u64).context("seccomp argument index is required")?;
                    if index > 5 { bail!("seccomp argument index {index} is outside the Linux syscall ABI range 0..=5"); }
                    let op_raw = arg.get("op").and_then(Value::as_str).context("seccomp argument op is required")?;
                    let op = seccomp_compare(op_raw)?;
                    let value = arg.get("value").and_then(Value::as_u64).context("seccomp argument value is required")?;
                    let value_two = arg.get("valueTwo").and_then(Value::as_u64).unwrap_or(0);
                    if op == SCMP_CMP_MASKED_EQ && arg.get("valueTwo").is_none() {
                        bail!("SCMP_CMP_MASKED_EQ requires OCI seccomp argument valueTwo");
                    }
                    if op != SCMP_CMP_MASKED_EQ && arg.get("valueTwo").is_some() {
                        bail!("seccomp argument valueTwo is valid only with SCMP_CMP_MASKED_EQ");
                    }
                    args.push(SeccompArg { index: index as u32, op, value, value_two });
                }
            }
            rules.push(SeccompRule { action, names, args });
        }
    }
    Ok(Some(SeccompProfile { default_action, rules }))
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ScmpArgCmp {
    arg: u32,
    op: u32,
    datum_a: u64,
    datum_b: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ScmpNotifData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ScmpNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: ScmpNotifData,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ScmpNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

fn unix_fd_socketpair() -> Result<[RawFd; 2]> {
    let mut fds = [-1; 2];
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("creating seccomp notification socketpair");
    }
    Ok(fds)
}

fn send_fd(socket: RawFd, fd: RawFd) -> Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let words = space.div_ceil(std::mem::size_of::<usize>());
    let mut control = vec![0usize; words];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space;
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null() { bail!("building SCM_RIGHTS header failed"); }
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
    }
    let rc = unsafe { libc::sendmsg(socket, &msg, libc::MSG_NOSIGNAL) };
    if rc != 1 {
        return Err(std::io::Error::last_os_error()).context("sending seccomp notification fd");
    }
    Ok(())
}

fn recv_fd(socket: RawFd) -> Result<RawFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let words = space.div_ceil(std::mem::size_of::<usize>());
    let mut control = vec![0usize; words];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = space;
    let rc = unsafe { libc::recvmsg(socket, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if rc <= 0 {
        return Err(if rc == 0 {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "seccomp notification socket closed before fd transfer")
        } else {
            std::io::Error::last_os_error()
        }).context("receiving seccomp notification fd");
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        bail!("seccomp notification fd transfer ancillary data was truncated");
    }
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null()
        || unsafe { (*cmsg).cmsg_level } != libc::SOL_SOCKET
        || unsafe { (*cmsg).cmsg_type } != libc::SCM_RIGHTS
        || unsafe { (*cmsg).cmsg_len } < unsafe { libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) } as usize
    {
        bail!("seccomp notification fd transfer did not contain SCM_RIGHTS");
    }
    let fd = unsafe { std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>()) };
    if fd < 0 { bail!("received invalid seccomp notification fd"); }
    Ok(fd)
}

fn process_still_exists(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 { return true; }
    matches!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EPERM))
}

fn wait_for_seccomp_listener(socket: RawFd, target_pid: u32) -> Result<RawFd> {
    loop {
        let mut pfd = libc::pollfd { fd: socket, events: libc::POLLIN, revents: 0 };
        let rc = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if rc < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(std::io::Error::last_os_error()).context("polling seccomp listener bootstrap socket");
        }
        if rc == 0 {
            if !process_still_exists(target_pid) {
                bail!("container process exited before transferring the seccomp notification listener");
            }
            continue;
        }
        if pfd.revents & libc::POLLIN != 0 {
            return recv_fd(socket);
        }
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            bail!("seccomp notification bootstrap socket closed before listener transfer");
        }
    }
}

fn run_seccomp_notify_broker(socket: RawFd, policy: SeccompNotifyPolicy, target_pid: u32, label: String) {
    let received = wait_for_seccomp_listener(socket, target_pid);
    unsafe { libc::close(socket); }
    let notify_fd = match received {
        Ok(fd) => fd,
        Err(e) => {
            security_counters().seccomp_notify_errors.fetch_add(1, Ordering::Relaxed);
            eprintln!("security audit: seccomp-notify broker {label} failed to receive listener: {e:#}");
            return;
        }
    };

    type NotifyAlloc = unsafe extern "C" fn(*mut *mut ScmpNotif, *mut *mut ScmpNotifResp) -> libc::c_int;
    type NotifyFree = unsafe extern "C" fn(*mut ScmpNotif, *mut ScmpNotifResp);
    type NotifyReceive = unsafe extern "C" fn(libc::c_int, *mut ScmpNotif) -> libc::c_int;
    type NotifyRespond = unsafe extern "C" fn(libc::c_int, *mut ScmpNotifResp) -> libc::c_int;
    type NotifyIdValid = unsafe extern "C" fn(libc::c_int, u64) -> libc::c_int;

    let soname = match CString::new("libseccomp.so.2") { Ok(v) => v, Err(_) => return };
    let handle = unsafe { libc::dlopen(soname.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        security_counters().seccomp_notify_errors.fetch_add(1, Ordering::Relaxed);
        eprintln!("security audit: seccomp-notify broker {label} cannot load libseccomp.so.2");
        unsafe { libc::close(notify_fd); }
        return;
    }

    let run = (|| -> Result<()> {
        let alloc: NotifyAlloc = unsafe { dlsym_required(handle, b"seccomp_notify_alloc\0")? };
        let free: NotifyFree = unsafe { dlsym_required(handle, b"seccomp_notify_free\0")? };
        let receive: NotifyReceive = unsafe { dlsym_required(handle, b"seccomp_notify_receive\0")? };
        let respond: NotifyRespond = unsafe { dlsym_required(handle, b"seccomp_notify_respond\0")? };
        let id_valid: NotifyIdValid = unsafe { dlsym_required(handle, b"seccomp_notify_id_valid\0")? };
        let mut req: *mut ScmpNotif = std::ptr::null_mut();
        let mut resp: *mut ScmpNotifResp = std::ptr::null_mut();
        let rc = unsafe { alloc(&mut req, &mut resp) };
        if rc != 0 || req.is_null() || resp.is_null() {
            bail!("seccomp_notify_alloc failed: {rc}");
        }
        struct NotifyBuffers {
            req: *mut ScmpNotif,
            resp: *mut ScmpNotifResp,
            free: NotifyFree,
        }
        impl Drop for NotifyBuffers {
            fn drop(&mut self) { unsafe { (self.free)(self.req, self.resp); } }
        }
        let buffers = NotifyBuffers { req, resp, free };

        loop {
            let mut pfd = libc::pollfd { fd: notify_fd, events: libc::POLLIN, revents: 0 };
            let poll_rc = unsafe { libc::poll(&mut pfd, 1, 1000) };
            if poll_rc < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted { continue; }
                bail!("polling seccomp notification fd: {}", std::io::Error::last_os_error());
            }
            if poll_rc == 0 {
                if !process_still_exists(target_pid) { break; }
                continue;
            }
            if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
                && pfd.revents & libc::POLLIN == 0
            {
                break;
            }
            if pfd.revents & libc::POLLIN == 0 { continue; }

            let rc = unsafe { receive(notify_fd, buffers.req) };
            if rc != 0 {
                if rc == -libc::EINTR || rc == -libc::ENOENT { continue; }
                bail!("seccomp_notify_receive failed: {rc}");
            }
            security_counters().seccomp_notify_received.fetch_add(1, Ordering::Relaxed);
            let request = unsafe { *buffers.req };
            if unsafe { id_valid(notify_fd, request.id) } != 0 { continue; }

            let response = unsafe { &mut *buffers.resp };
            *response = ScmpNotifResp::default();
            response.id = request.id;
            match policy.mode {
                SeccompNotifyMode::Deny => {
                    response.error = -policy.errno;
                    security_counters().seccomp_notify_denied.fetch_add(1, Ordering::Relaxed);
                    eprintln!("security audit: seccomp-notify {label} nr={} pid={} decision=deny errno={}", request.data.nr, request.pid, policy.errno);
                }
                SeccompNotifyMode::Continue => {
                    response.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
                    security_counters().seccomp_notify_continued.fetch_add(1, Ordering::Relaxed);
                    eprintln!("security audit: seccomp-notify {label} nr={} pid={} decision=continue", request.data.nr, request.pid);
                }
            }
            let rc = unsafe { respond(notify_fd, response) };
            if rc != 0 && rc != -libc::ENOENT { bail!("seccomp_notify_respond failed: {rc}"); }
        }
        Ok(())
    })();
    if let Err(e) = run {
        security_counters().seccomp_notify_errors.fetch_add(1, Ordering::Relaxed);
        eprintln!("security audit: seccomp-notify broker {label} stopped with error: {e:#}");
    }
    unsafe {
        libc::dlclose(handle);
        libc::close(notify_fd);
    }
}

unsafe fn dlsym_required<T: Copy>(handle: *mut libc::c_void, name: &[u8]) -> Result<T> {
    let ptr = unsafe { libc::dlsym(handle, name.as_ptr().cast()) };
    if ptr.is_null() { bail!("dynamic security library symbol {} is missing", String::from_utf8_lossy(&name[..name.len()-1])); }
    Ok(unsafe { std::mem::transmute_copy(&ptr) })
}

fn apply_seccomp(profile: &SeccompProfile, notify_socket: Option<RawFd>) -> Result<()> {
    type Init = unsafe extern "C" fn(u32) -> *mut libc::c_void;
    type Release = unsafe extern "C" fn(*mut libc::c_void);
    type Resolve = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;
    type RuleAddArray = unsafe extern "C" fn(*mut libc::c_void, u32, libc::c_int, u32, *const ScmpArgCmp) -> libc::c_int;
    type Load = unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int;
    type NotifyFd = unsafe extern "C" fn(*const libc::c_void) -> libc::c_int;
    let needs_notify = seccomp_profile_uses_notify(profile);
    if needs_notify != notify_socket.is_some() {
        bail!("seccomp notify listener bootstrap state does not match the OCI filter");
    }
    let name = CString::new("libseccomp.so.2")?;
    let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() { bail!("OCI seccomp requested but libseccomp.so.2 is not installed in the guest"); }
    let result = (|| -> Result<()> {
        let init: Init = unsafe { dlsym_required(handle, b"seccomp_init\0")? };
        let release: Release = unsafe { dlsym_required(handle, b"seccomp_release\0")? };
        let resolve: Resolve = unsafe { dlsym_required(handle, b"seccomp_syscall_resolve_name\0")? };
        let rule_add_array: RuleAddArray = unsafe { dlsym_required(handle, b"seccomp_rule_add_array\0")? };
        let load: Load = unsafe { dlsym_required(handle, b"seccomp_load\0")? };
        let notify_fd_fn: Option<NotifyFd> = if needs_notify {
            Some(unsafe { dlsym_required(handle, b"seccomp_notify_fd\0")? })
        } else {
            None
        };
        let ctx = unsafe { init(profile.default_action) };
        if ctx.is_null() { bail!("seccomp_init failed"); }
        let apply = (|| -> Result<()> {
            for rule in &profile.rules {
                let cmps: Vec<ScmpArgCmp> = rule.args.iter().map(|arg| ScmpArgCmp {
                    arg: arg.index,
                    op: arg.op,
                    datum_a: arg.value,
                    datum_b: arg.value_two,
                }).collect();
                for name in &rule.names {
                    let c = CString::new(name.as_bytes())?;
                    let nr = unsafe { resolve(c.as_ptr()) };
                    if nr < 0 { bail!("unknown seccomp syscall {name:?}"); }
                    let ptr = if cmps.is_empty() { std::ptr::null() } else { cmps.as_ptr() };
                    let rc = unsafe { rule_add_array(ctx, rule.action, nr, cmps.len() as u32, ptr) };
                    if rc != 0 { bail!("seccomp_rule_add_array({name}) failed: {rc}"); }
                }
            }
            let rc = unsafe { load(ctx) };
            if rc != 0 { bail!("seccomp_load failed: {rc}"); }
            if let (Some(notify_fd_fn), Some(socket)) = (notify_fd_fn, notify_socket) {
                let fd = unsafe { notify_fd_fn(ctx) };
                if fd < 0 { bail!("seccomp_notify_fd failed after loading notify filter: {fd}"); }
                // Transfer the listener before releasing the filter context or
                // dlclosing libseccomp. This keeps the bootstrap path tiny and
                // ensures any later NOTIFY-triggering cleanup syscall already
                // has a live supervisor on the other end.
                send_fd(socket, fd)?;
            }
            Ok(())
        })();
        unsafe { release(ctx); }
        apply
    })();
    unsafe { libc::dlclose(handle); }
    result
}

fn validate_selinux_mount_label(label: &str) -> Result<()> {
    validate_lsm_string("linux.mountLabel", label)?;
    if label.contains('"') || label.contains('\\') {
        bail!("invalid OCI linux.mountLabel: quote/backslash characters are not supported in mount options");
    }
    type IsEnabled = unsafe extern "C" fn() -> libc::c_int;
    let soname = CString::new("libselinux.so.1")?;
    let handle = unsafe { libc::dlopen(soname.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        security_counters().lsm_apply_failures.fetch_add(1, Ordering::Relaxed);
        bail!("OCI SELinux mount label requested but libselinux.so.1 is not installed in the guest");
    }
    let result = (|| -> Result<()> {
        let is_enabled: IsEnabled = unsafe { dlsym_required(handle, b"is_selinux_enabled\0")? };
        if unsafe { is_enabled() } <= 0 {
            bail!("OCI SELinux mount label {label:?} requested but SELinux is not enabled in the guest");
        }
        Ok(())
    })();
    unsafe { libc::dlclose(handle); }
    if result.is_err() { security_counters().lsm_apply_failures.fetch_add(1, Ordering::Relaxed); }
    result
}

fn format_selinux_mount_data(data: Option<&str>, mount_label: Option<&str>) -> Result<Option<String>> {
    let Some(label) = mount_label else { return Ok(data.map(str::to_string)); };
    if data.is_some_and(|d| d.split(',').any(|part| part.starts_with("context=") || part.starts_with("fscontext=") || part.starts_with("defcontext=") || part.starts_with("rootcontext="))) {
        bail!("OCI mount data already contains an SELinux context option while linux.mountLabel is set");
    }
    let context = format!("context=\"{label}\"");
    let formatted = match data.filter(|d| !d.is_empty()) {
        Some(data) => format!("{data},{context}"),
        None => context,
    };
    Ok(Some(formatted))
}

fn validate_lsm_string(kind: &str, value: &str) -> Result<()> {
    if value.as_bytes().contains(&0) || value.contains('\n') || value.contains('\r') {
        bail!("invalid OCI {kind}: control characters are not allowed");
    }
    if value.len() > 4096 { bail!("invalid OCI {kind}: value is too long"); }
    Ok(())
}

fn apply_apparmor_on_exec(profile: &str) -> Result<()> {
    if profile.is_empty() { return Ok(()); }
    validate_lsm_string("apparmorProfile", profile)?;
    let enabled = std::fs::read_to_string("/sys/module/apparmor/parameters/enabled")
        .map(|v| v.starts_with('Y'))
        .unwrap_or(false);
    if !enabled {
        security_counters().lsm_apply_failures.fetch_add(1, Ordering::Relaxed);
        bail!("OCI AppArmor profile {profile:?} requested but AppArmor is not enabled in the guest");
    }
    let candidates = ["/proc/thread-self/attr/apparmor/exec", "/proc/thread-self/attr/exec", "/proc/self/attr/apparmor/exec", "/proc/self/attr/exec"];
    let payload = format!("exec {profile}");
    let mut last = None;
    for path in candidates {
        match OpenOptions::new().write(true).open(path) {
            Ok(mut f) => {
                let result = f.write_all(payload.as_bytes())
                    .with_context(|| format!("applying OCI AppArmor profile {profile:?}"));
                if result.is_err() { security_counters().lsm_apply_failures.fetch_add(1, Ordering::Relaxed); }
                return result;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => last = Some(e),
            Err(e) => return Err(e).with_context(|| format!("opening AppArmor exec attribute {path}")),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "AppArmor exec attribute missing")))
        .context("AppArmor is enabled but no process exec attribute is available")
}

fn apply_selinux_on_exec(label: &str) -> Result<()> {
    if label.is_empty() { return Ok(()); }
    validate_lsm_string("selinuxLabel", label)?;
    type IsEnabled = unsafe extern "C" fn() -> libc::c_int;
    type SetExecCon = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;
    let soname = CString::new("libselinux.so.1")?;
    let handle = unsafe { libc::dlopen(soname.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() { bail!("OCI SELinux label requested but libselinux.so.1 is not installed in the guest"); }
    let result = (|| -> Result<()> {
        let is_enabled: IsEnabled = unsafe { dlsym_required(handle, b"is_selinux_enabled\0")? };
        let setexeccon: SetExecCon = unsafe { dlsym_required(handle, b"setexeccon\0")? };
        if unsafe { is_enabled() } <= 0 { bail!("OCI SELinux label {label:?} requested but SELinux is not enabled in the guest"); }
        let label = CString::new(label.as_bytes())?;
        if unsafe { setexeccon(label.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("applying OCI SELinux process label");
        }
        Ok(())
    })();
    unsafe { libc::dlclose(handle); }
    result
}

const BPF_DEVCG_ACC_MKNOD: u32 = 1 << 0;
const BPF_DEVCG_ACC_READ: u32 = 1 << 1;
const BPF_DEVCG_ACC_WRITE: u32 = 1 << 2;
const BPF_DEVCG_DEV_BLOCK: u32 = 1 << 0;
const BPF_DEVCG_DEV_CHAR: u32 = 1 << 1;
const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
const BPF_CGROUP_DEVICE: u32 = 6;
const BPF_PROG_LOAD_CMD: libc::c_long = 5;
const BPF_PROG_ATTACH_CMD: libc::c_long = 8;

fn parse_device_access(value: &str) -> Result<u32> {
    let mut mask = 0u32;
    for ch in value.chars() {
        mask |= match ch {
            'r' => BPF_DEVCG_ACC_READ,
            'w' => BPF_DEVCG_ACC_WRITE,
            'm' => BPF_DEVCG_ACC_MKNOD,
            other => bail!("unsupported OCI device access character {other:?}"),
        };
    }
    if mask == 0 { bail!("OCI device cgroup rule access must not be empty"); }
    Ok(mask)
}

fn parse_device_cgroup_policy(config: &Value) -> Result<Option<DeviceCgroupPolicy>> {
    let Some(items) = config.pointer("/linux/resources/devices").and_then(Value::as_array) else { return Ok(None); };
    if items.is_empty() { return Ok(None); }
    if items.len() > 128 { bail!("OCI device cgroup policy has too many rules (max 128)"); }

    // Treat the OCI rules as the desired device-policy state, matching the
    // opencontainers/cgroups emulator: begin in deny-all mode and apply the
    // rule stream into a normalized default + exception set before emitting
    // cgroup-v2 BPF. Deliberately reject wildcard-hole removals that cgroup
    // v1 would silently ignore.
    let mut default_allow = false;
    let mut rules: Vec<DeviceCgroupRule> = Vec::new();
    for item in items {
        let allow = item.get("allow").and_then(Value::as_bool).context("OCI device cgroup rule allow is required")?;
        let raw_type = item.get("type").and_then(Value::as_str).unwrap_or("a");
        let dev_type = match raw_type {
            "a" => None,
            "b" => Some(BPF_DEVCG_DEV_BLOCK),
            "c" => Some(BPF_DEVCG_DEV_CHAR),
            other => bail!("unsupported OCI device cgroup type {other:?}"),
        };
        let parse_num = |name: &str| -> Result<Option<u32>> {
            match item.get(name).and_then(Value::as_i64) {
                None | Some(-1) => Ok(None),
                Some(v) if v >= 0 && v <= u32::MAX as i64 => Ok(Some(v as u32)),
                Some(v) => bail!("invalid OCI device cgroup {name} value {v}"),
            }
        };
        let major = parse_num("major")?;
        let minor = parse_num("minor")?;
        let access = parse_device_access(item.get("access").and_then(Value::as_str).unwrap_or("rwm"))?;

        if dev_type.is_none() {
            if major.is_some() || minor.is_some() || access != 0x7 {
                bail!("OCI wildcard device rule must be type='a', major/minor wildcards, access='rwm'");
            }
            default_allow = allow;
            rules.clear();
            continue;
        }

        let same_meta = |r: &DeviceCgroupRule| r.dev_type == dev_type && r.major == major && r.minor == minor;
        if allow != default_allow {
            if let Some(existing) = rules.iter_mut().find(|r| same_meta(r)) {
                existing.access |= access;
            } else {
                rules.push(DeviceCgroupRule { allow, dev_type, major, minor, access });
            }
            continue;
        }

        // This is an inverse operation: remove permission bits from existing
        // exceptions covered by the selector. A broad inverse (for example
        // c *:* r) can safely remove bits from specific exceptions. A more
        // specific inverse cannot punch a hole through an existing wildcard
        // exception, so reject that shape like opencontainers/cgroups.
        let punches_wildcard = rules.iter().any(|r| {
            r.dev_type == dev_type
                && (r.access & access) != 0
                && (r.major.is_none() && major.is_some() || r.minor.is_none() && minor.is_some())
                && (r.major.is_none() || major.is_none() || r.major == major)
                && (r.minor.is_none() || minor.is_none() || r.minor == minor)
        });
        if punches_wildcard {
            bail!("OCI device cgroup rule would punch a partial hole in an existing wildcard exception");
        }
        for existing in &mut rules {
            if existing.dev_type == dev_type
                && (major.is_none() || existing.major == major)
                && (minor.is_none() || existing.minor == minor)
            {
                existing.access &= !access;
            }
        }
        rules.retain(|r| r.access != 0);
    }
    Ok(Some(DeviceCgroupPolicy { default_allow, rules }))
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct BpfInsn {
    code: u8,
    dst_src: u8,
    off: i16,
    imm: i32,
}

impl BpfInsn {
    fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self { code, dst_src: (src << 4) | (dst & 0x0f), off, imm }
    }
}

fn bpf_mov64_imm(dst: u8, imm: i32) -> BpfInsn { BpfInsn::new(0xb7, dst, 0, 0, imm) }
fn bpf_mov64_reg(dst: u8, src: u8) -> BpfInsn { BpfInsn::new(0xbf, dst, src, 0, 0) }
fn bpf_ldxw(dst: u8, src: u8, off: i16) -> BpfInsn { BpfInsn::new(0x61, dst, src, off, 0) }
fn bpf_and64_imm(dst: u8, imm: i32) -> BpfInsn { BpfInsn::new(0x57, dst, 0, 0, imm) }
fn bpf_rsh64_imm(dst: u8, imm: i32) -> BpfInsn { BpfInsn::new(0x77, dst, 0, 0, imm) }
fn bpf_jne_imm(dst: u8, imm: i32, off: i16) -> BpfInsn { BpfInsn::new(0x55, dst, 0, off, imm) }
fn bpf_exit() -> BpfInsn { BpfInsn::new(0x95, 0, 0, 0, 0) }

fn build_device_bpf(policy: &DeviceCgroupPolicy) -> Result<Vec<BpfInsn>> {
    // Match the opencontainers/cgroups cgroup-device filter shape: cache type,
    // access, major and minor; each normalized exception returns immediately;
    // the final return is the emulated cgroup-v1 default policy.
    let mut out = vec![
        bpf_ldxw(2, 1, 0),
        bpf_and64_imm(2, 0xffff),
        bpf_ldxw(3, 1, 0),
        bpf_rsh64_imm(3, 16),
        bpf_ldxw(4, 1, 4),
        bpf_ldxw(5, 1, 8),
    ];
    for rule in &policy.rules {
        let dev_type = rule.dev_type.context("normalized device BPF rule is missing a type")?;
        let mut jumps = Vec::new();
        jumps.push(out.len());
        out.push(bpf_jne_imm(2, dev_type as i32, 0));

        if rule.access != 0x7 {
            // r1 is safe as a temporary after all ctx fields have been loaded.
            out.push(bpf_mov64_reg(1, 3));
            out.push(bpf_and64_imm(1, rule.access as i32));
            // A rule matches only when every requested access bit is present
            // in its permission set: (request & rule) == request.
            jumps.push(out.len());
            out.push(BpfInsn::new(0x5d, 1, 3, 0, 0)); // JNE X: r1 != r3
        }
        if let Some(major) = rule.major {
            if major > i32::MAX as u32 { bail!("device cgroup major {major} exceeds eBPF immediate range"); }
            jumps.push(out.len());
            out.push(bpf_jne_imm(4, major as i32, 0));
        }
        if let Some(minor) = rule.minor {
            if minor > i32::MAX as u32 { bail!("device cgroup minor {minor} exceeds eBPF immediate range"); }
            jumps.push(out.len());
            out.push(bpf_jne_imm(5, minor as i32, 0));
        }
        out.push(bpf_mov64_imm(0, if rule.allow { 1 } else { 0 }));
        out.push(bpf_exit());
        let end = out.len();
        for index in jumps {
            let skip = end.checked_sub(index + 1).context("device BPF jump underflow")?;
            if skip > i16::MAX as usize { bail!("device cgroup BPF rule is too large"); }
            out[index].off = skip as i16;
        }
    }
    out.push(bpf_mov64_imm(0, if policy.default_allow { 1 } else { 0 }));
    out.push(bpf_exit());
    if out.len() > 4096 { bail!("device cgroup BPF program exceeds the conservative 4096 instruction limit"); }
    Ok(out)
}

#[repr(C)]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
}

#[repr(C)]
struct BpfProgAttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_bpf_fd: u32,
}

fn attach_device_cgroup_policy(path: &std::path::Path, policy: &DeviceCgroupPolicy) -> Result<()> {
    use std::os::fd::IntoRawFd;
    let insns = build_device_bpf(policy)?;
    let license = b"GPL\0";
    let mut log = vec![0u8; 64 * 1024];
    let mut name = [0u8; 16];
    name[..13].copy_from_slice(b"fluxvm-devcg\0");
    let mut load = BpfProgLoadAttr {
        prog_type: BPF_PROG_TYPE_CGROUP_DEVICE,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log.len() as u32,
        log_buf: log.as_mut_ptr() as u64,
        kern_version: 0,
        prog_flags: 0,
        prog_name: name,
        prog_ifindex: 0,
        expected_attach_type: BPF_CGROUP_DEVICE,
    };
    let prog_fd = unsafe {
        libc::syscall(libc::SYS_bpf, BPF_PROG_LOAD_CMD, &mut load, std::mem::size_of::<BpfProgLoadAttr>()) as libc::c_int
    };
    if prog_fd < 0 {
        let verifier = String::from_utf8_lossy(&log).trim_matches(char::from(0)).trim().to_string();
        let err = std::io::Error::last_os_error();
        if verifier.is_empty() { return Err(err).context("loading cgroup-v2 device BPF program"); }
        bail!("loading cgroup-v2 device BPF program: {err}; verifier: {verifier}");
    }
    let cgroup_fd = File::open(path)
        .with_context(|| format!("opening container cgroup {} for device BPF attach", path.display()))?
        .into_raw_fd();
    let mut attach = BpfProgAttachAttr {
        target_fd: cgroup_fd as u32,
        attach_bpf_fd: prog_fd as u32,
        attach_type: BPF_CGROUP_DEVICE,
        attach_flags: 0,
        replace_bpf_fd: 0,
    };
    let rc = unsafe {
        libc::syscall(libc::SYS_bpf, BPF_PROG_ATTACH_CMD, &mut attach, std::mem::size_of::<BpfProgAttachAttr>()) as libc::c_int
    };
    let attach_error = if rc < 0 { Some(std::io::Error::last_os_error()) } else { None };
    unsafe { libc::close(cgroup_fd); libc::close(prog_fd); }
    if let Some(err) = attach_error {
        return Err(err).with_context(|| format!("attaching cgroup-v2 device BPF program to {}", path.display()));
    }
    Ok(())
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

// ---- Sentinel Set 8S: in-guest per-container network policy ----
//
// bpf/fluxvm_guest_cgroup.bpf.c is compiled at `cargo build` time (see
// build.rs) and embedded here so this binary stays a single self-contained
// file to upload over VSOCK. One loaded instance is shared across every
// container in this Pod VM -- see that file's header comment for why that's
// safe (maps are keyed by cgroup id, not by attachment instance).

const FLUXVM_CPOL_ENABLED: u64 = 1 << 0;
const FLUXVM_CPOL_DEFAULT_ALLOW: u64 = 1 << 1;
const FLUXVM_CPOL_AUDIT: u64 = 1 << 2;
const FLUXVM_CPEER_ALLOW: u32 = 1;
const FLUXVM_CPEER_DENY: u32 = 2;

static GUEST_CGROUP_BPF_OBJ: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/fluxvm_guest_cgroup.bpf.o"));

/// Must byte-match `struct fluxvm_cid4_key` in bpf/fluxvm_guest_cgroup.bpf.c.
/// `address` is raw packet-order bytes (`Ipv4Addr::octets()`), never a
/// computed integer -- `bpf_map_lookup_elem` does a byte-for-byte key
/// comparison, so as long as both sides agree on which bytes go where, no
/// endianness conversion is needed or correct to apply.
#[repr(C)]
#[derive(Clone, Copy)]
struct Cid4Key {
    cgroup_id: u64,
    address: [u8; 4],
    reserved: u32,
}
unsafe impl aya::Pod for Cid4Key {}

/// Must byte-match `struct fluxvm_cid6_key`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Cid6Key {
    cgroup_id: u64,
    address: [u8; 16],
}
unsafe impl aya::Pod for Cid6Key {}

struct GuestEbpfState {
    bpf: Ebpf,
    programs_loaded: bool,
}

static GUEST_EBPF: OnceLock<Mutex<Option<GuestEbpfState>>> = OnceLock::new();

fn guest_ebpf_cell() -> &'static Mutex<Option<GuestEbpfState>> {
    GUEST_EBPF.get_or_init(|| Mutex::new(None))
}

/// Attaches both Set 8S programs to `cgroup_path` (already created by
/// `create_container_cgroup`). Lazily loads the shared `Ebpf` object and
/// loads each program into the kernel exactly once, on the first container;
/// every later container only needs a fresh `attach()` call against the
/// already-loaded programs.
fn attach_guest_network_policy(cgroup_path: &Path) -> Result<()> {
    let cgroup_file =
        File::open(cgroup_path).with_context(|| format!("opening cgroup {}", cgroup_path.display()))?;
    let mut guard = guest_ebpf_cell().lock().expect("guest eBPF poisoned");
    if guard.is_none() {
        let bpf = Ebpf::load(GUEST_CGROUP_BPF_OBJ).context("loading fluxvm_guest_cgroup.bpf.o")?;
        *guard = Some(GuestEbpfState { bpf, programs_loaded: false });
    }
    let state = guard.as_mut().expect("just initialized above");

    if !state.programs_loaded {
        let egress: &mut CgroupSkb = state
            .bpf
            .program_mut("fluxvm_guest_egress")
            .context("fluxvm_guest_egress program not found in object")?
            .try_into()?;
        egress.load().context("loading fluxvm_guest_egress into the kernel")?;
        let ingress: &mut CgroupSkb = state
            .bpf
            .program_mut("fluxvm_guest_ingress")
            .context("fluxvm_guest_ingress program not found in object")?
            .try_into()?;
        ingress.load().context("loading fluxvm_guest_ingress into the kernel")?;
        state.programs_loaded = true;
    }

    let egress: &mut CgroupSkb = state.bpf.program_mut("fluxvm_guest_egress").expect("loaded above").try_into()?;
    let egress_cgroup = cgroup_file.try_clone().context("duplicating cgroup fd")?;
    egress
        .attach(egress_cgroup, CgroupSkbAttachType::Egress, CgroupAttachMode::Single)
        .context("attaching fluxvm_guest_egress")?;

    let ingress: &mut CgroupSkb = state.bpf.program_mut("fluxvm_guest_ingress").expect("loaded above").try_into()?;
    ingress
        .attach(cgroup_file, CgroupSkbAttachType::Ingress, CgroupAttachMode::Single)
        .context("attaching fluxvm_guest_ingress")?;

    Ok(())
}

/// Populates (or, with `policy: None`, installs an enabled-but-empty entry
/// for) `cgroup_id`'s policy. Must run after a successful
/// `attach_guest_network_policy` for the same container.
fn configure_container_policy(cgroup_id: u64, policy: Option<&ContainerNetworkPolicy>) -> Result<()> {
    let mut guard = guest_ebpf_cell().lock().expect("guest eBPF poisoned");
    let state = guard.as_mut().context("guest eBPF not attached yet")?;

    let mut flags = FLUXVM_CPOL_ENABLED;
    if let Some(p) = policy {
        if p.default_allow { flags |= FLUXVM_CPOL_DEFAULT_ALLOW; }
        if p.audit_mode { flags |= FLUXVM_CPOL_AUDIT; }
    }

    {
        let cpol_map = state.bpf.map_mut("fluxvm_cpol").context("fluxvm_cpol map not found")?;
        let mut cpol: aya::maps::HashMap<_, u64, u64> = aya::maps::HashMap::try_from(cpol_map)?;
        cpol.insert(cgroup_id, flags, 0).context("writing fluxvm_cpol entry")?;
    }

    let Some(policy) = policy else { return Ok(()) };

    {
        let cid4_map = state.bpf.map_mut("fluxvm_cid4").context("fluxvm_cid4 map not found")?;
        let mut cid4: aya::maps::HashMap<_, Cid4Key, u32> = aya::maps::HashMap::try_from(cid4_map)?;
        for (addrs, verdict) in [(&policy.allow_addresses, FLUXVM_CPEER_ALLOW), (&policy.deny_addresses, FLUXVM_CPEER_DENY)] {
            for addr in addrs {
                if let IpAddr::V4(v4) = addr {
                    let key = Cid4Key { cgroup_id, address: v4.octets(), reserved: 0 };
                    cid4.insert(key, verdict, 0).context("writing fluxvm_cid4 entry")?;
                }
            }
        }
    }
    {
        let cid6_map = state.bpf.map_mut("fluxvm_cid6").context("fluxvm_cid6 map not found")?;
        let mut cid6: aya::maps::HashMap<_, Cid6Key, u32> = aya::maps::HashMap::try_from(cid6_map)?;
        for (addrs, verdict) in [(&policy.allow_addresses, FLUXVM_CPEER_ALLOW), (&policy.deny_addresses, FLUXVM_CPEER_DENY)] {
            for addr in addrs {
                if let IpAddr::V6(v6) = addr {
                    let key = Cid6Key { cgroup_id, address: v6.octets() };
                    cid6.insert(key, verdict, 0).context("writing fluxvm_cid6 entry")?;
                }
            }
        }
    }
    Ok(())
}

/// Best-effort cleanup of a deleted container's map entries. Detaching the
/// programs themselves happens implicitly when the cgroup is removed
/// (`cleanup_container_cgroup`); this only prevents `fluxvm_cpol`/
/// `fluxvm_cid4`/`fluxvm_cid6` from growing unboundedly across a long-lived
/// Pod VM's container churn.
fn forget_container_policy(cgroup_id: u64) {
    let mut guard = guest_ebpf_cell().lock().expect("guest eBPF poisoned");
    let Some(state) = guard.as_mut() else { return };

    if let Some(map) = state.bpf.map_mut("fluxvm_cpol") {
        if let Ok(mut cpol) = aya::maps::HashMap::<_, u64, u64>::try_from(map) {
            let _ = cpol.remove(&cgroup_id);
        }
    }
    if let Some(map) = state.bpf.map_mut("fluxvm_cid4") {
        if let Ok(mut cid4) = aya::maps::HashMap::<_, Cid4Key, u32>::try_from(map) {
            let stale: Vec<Cid4Key> = cid4
                .iter()
                .filter_map(Result::ok)
                .map(|(k, _)| k)
                .filter(|k| k.cgroup_id == cgroup_id)
                .collect();
            for key in stale {
                let _ = cid4.remove(&key);
            }
        }
    }
    if let Some(map) = state.bpf.map_mut("fluxvm_cid6") {
        if let Ok(mut cid6) = aya::maps::HashMap::<_, Cid6Key, u32>::try_from(map) {
            let stale: Vec<Cid6Key> = cid6
                .iter()
                .filter_map(Result::ok)
                .map(|(k, _)| k)
                .filter(|k| k.cgroup_id == cgroup_id)
                .collect();
            for key in stale {
                let _ = cid6.remove(&key);
            }
        }
    }
}

// ---- Sentinel Set 9S: in-guest per-container eBPF LSM MAC ----
//
// Additive to Set 8S's cgroup_skb network policy and to classic seccomp
// (apply_seccomp above): seccomp can only filter by syscall name/argument,
// not by which file is being touched or whether it is one of the
// container's own declared mounts. bpf/fluxvm_guest_lsm.bpf.c's hooks are
// attached once, globally, for the whole agent process lifetime (LSM
// programs cannot be scoped to a cgroup fd the way cgroup_skb can); the
// per-container boundary is enforced entirely by the kernel program's own
// `fluxvm_lsmpol` cgroup-id lookup, so a cgroup with no policy entry is
// always allowed. Off by default -- see docs/secure-containers-set9s.md.

const FLUXVM_LSM_ENABLED: u32 = 1 << 0;
const FLUXVM_LSM_AUDIT: u32 = 1 << 1;
const FLUXVM_LSM_DENY_EXEC: u32 = 1 << 2;
const FLUXVM_LSM_DENY_WX: u32 = 1 << 3;
const FLUXVM_LSM_RESTRICT_DEVICES: u32 = 1 << 4;
const FLUXVM_LSM_RESTRICT_WRITES: u32 = 1 << 5;
const FLUXVM_LSM_MAX_PREFIXES: u32 = 8;
const FLUXVM_LSM_PREFIX_LEN: usize = 64;
/// Top bit reserved so a Set 9S container identity never collides with the
/// host VM-hash space, Service-Fabric's reserved/local identity space, or
/// Set 6S's Pod-id space -- all already-separate identity spaces in this
/// codebase. This VM only ever hosts one Kubernetes Pod's containers, so
/// (unlike Set 6S's Pod identity) no host-assigned Pod component is needed
/// for uniqueness here; the container's own `id` string is already unique
/// within this guest.
const CONTAINER_IDENTITY_TAG_BIT: u32 = 1 << 31;

static GUEST_LSM_BPF_OBJ: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/fluxvm_guest_lsm.bpf.o"));

/// Must byte-match `struct fluxvm_lsm_policy` in bpf/fluxvm_guest_lsm.bpf.c.
#[repr(C)]
#[derive(Clone, Copy)]
struct LsmPolicyValue {
    flags: u32,
    generation: u32,
}
unsafe impl aya::Pod for LsmPolicyValue {}

/// Must byte-match `struct fluxvm_lsm_prefix_key`.
#[repr(C)]
#[derive(Clone, Copy)]
struct LsmPrefixKey {
    cgroup_id: u64,
    slot: u32,
    reserved: u32,
}
unsafe impl aya::Pod for LsmPrefixKey {}

/// Must byte-match `struct fluxvm_lsm_prefix_value`.
#[repr(C)]
#[derive(Clone, Copy)]
struct LsmPrefixValue {
    len: u32,
    bytes: [u8; FLUXVM_LSM_PREFIX_LEN],
}
unsafe impl aya::Pod for LsmPrefixValue {}

struct GuestLsmState {
    bpf: Ebpf,
    attached: bool,
    generation: u32,
}

static GUEST_LSM: OnceLock<Mutex<Option<GuestLsmState>>> = OnceLock::new();

fn guest_lsm_cell() -> &'static Mutex<Option<GuestLsmState>> {
    GUEST_LSM.get_or_init(|| Mutex::new(None))
}

fn guest_lsm_enabled() -> bool {
    std::env::var("FLUXVM_CONTAINER_LSM")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

/// Mints a stable per-container identity so a guest LSM denial event (keyed
/// by cgroup id in the kernel, which is not host-visible or stable across a
/// container recreate) can be correlated back to `(container_id,
/// container_identity)` over the existing lifecycle RPC. FNV-1a like
/// `fluxvm_network::identity`/Set 6S's `pod_identity`, for the same reason:
/// a small, dependency-free, stable hash.
fn container_identity_for(id: &str) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for b in id.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    (h | CONTAINER_IDENTITY_TAG_BIT).max(CONTAINER_IDENTITY_TAG_BIT | 1)
}

/// Lazily loads and attaches (once, globally) the three Set 9S LSM
/// programs. Idempotent: later containers just reuse the already-attached
/// programs. Fails (rather than silently no-op-ing) if `FLUXVM_CONTAINER_LSM`
/// is set but the guest kernel lacks BPF LSM/BTF support, so the caller can
/// log a clear reason instead of a container silently running unconfined.
fn attach_guest_lsm() -> Result<()> {
    let mut guard = guest_lsm_cell().lock().expect("guest LSM poisoned");
    if let Some(state) = guard.as_ref() {
        if state.attached {
            return Ok(());
        }
    }
    if guard.is_none() {
        let bpf = Ebpf::load(GUEST_LSM_BPF_OBJ).context("loading fluxvm_guest_lsm.bpf.o")?;
        *guard = Some(GuestLsmState { bpf, attached: false, generation: 0 });
    }
    let state = guard.as_mut().expect("just initialized above");
    let btf = Btf::from_sys_fs().context("reading kernel BTF (requires CONFIG_DEBUG_INFO_BTF)")?;
    for (prog_name, hook) in [
        ("fluxvm_lsm_exec", "bprm_check_security"),
        ("fluxvm_lsm_mprotect", "file_mprotect"),
        ("fluxvm_lsm_file_open", "file_open"),
    ] {
        let lsm: &mut Lsm = state
            .bpf
            .program_mut(prog_name)
            .with_context(|| format!("{prog_name} program not found in object"))?
            .try_into()?;
        lsm.load(hook, &btf).with_context(|| format!("loading {prog_name} against lsm/{hook}"))?;
        lsm.attach().with_context(|| format!("attaching {prog_name}"))?;
    }
    state.attached = true;
    Ok(())
}

/// Populates `cgroup_id`'s Set 9S policy. `write_prefixes` are guest-visible
/// absolute paths (OCI mount `destination` values, e.g. `/data`) allowed for
/// regular-file writes when `restrict_writes` is set; only the first
/// `FLUXVM_LSM_MAX_PREFIXES` are installed (see bpf/fluxvm_guest_lsm.bpf.c's
/// header comment for why that bound exists).
fn configure_container_lsm_policy(
    cgroup_id: u64,
    deny_wx: bool,
    restrict_writes: bool,
    write_prefixes: &[String],
    audit_only: bool,
) -> Result<()> {
    let mut guard = guest_lsm_cell().lock().expect("guest LSM poisoned");
    let state = guard.as_mut().context("guest LSM not attached yet")?;
    state.generation = state.generation.wrapping_add(1).max(1);

    let mut flags = FLUXVM_LSM_ENABLED;
    if audit_only { flags |= FLUXVM_LSM_AUDIT; }
    if deny_wx { flags |= FLUXVM_LSM_DENY_WX; }
    if restrict_writes && !write_prefixes.is_empty() { flags |= FLUXVM_LSM_RESTRICT_WRITES; }

    let pol_map = state.bpf.map_mut("fluxvm_lsmpol").context("fluxvm_lsmpol map not found")?;
    let mut pol: aya::maps::HashMap<_, u64, LsmPolicyValue> = aya::maps::HashMap::try_from(pol_map)?;
    pol.insert(cgroup_id, LsmPolicyValue { flags, generation: state.generation }, 0)
        .context("writing fluxvm_lsmpol entry")?;

    let write_map = state.bpf.map_mut("fluxvm_lsmwrite").context("fluxvm_lsmwrite map not found")?;
    let mut write: aya::maps::HashMap<_, LsmPrefixKey, LsmPrefixValue> = aya::maps::HashMap::try_from(write_map)?;
    for slot in 0..FLUXVM_LSM_MAX_PREFIXES {
        let key = LsmPrefixKey { cgroup_id, slot, reserved: 0 };
        match write_prefixes.get(slot as usize) {
            Some(prefix) if prefix.len() < FLUXVM_LSM_PREFIX_LEN => {
                let mut bytes = [0u8; FLUXVM_LSM_PREFIX_LEN];
                bytes[..prefix.len()].copy_from_slice(prefix.as_bytes());
                let value = LsmPrefixValue { len: prefix.len() as u32, bytes };
                write.insert(key, value, 0).context("writing fluxvm_lsmwrite entry")?;
            }
            _ => {
                let _ = write.remove(&key);
            }
        }
    }
    Ok(())
}

/// Best-effort cleanup of a deleted container's Set 9S map entries, mirroring
/// `forget_container_policy`.
fn forget_container_lsm_policy(cgroup_id: u64) {
    let mut guard = guest_lsm_cell().lock().expect("guest LSM poisoned");
    let Some(state) = guard.as_mut() else { return };
    if let Some(map) = state.bpf.map_mut("fluxvm_lsmpol") {
        if let Ok(mut pol) = aya::maps::HashMap::<_, u64, LsmPolicyValue>::try_from(map) {
            let _ = pol.remove(&cgroup_id);
        }
    }
    if let Some(map) = state.bpf.map_mut("fluxvm_lsmwrite") {
        if let Ok(mut write) = aya::maps::HashMap::<_, LsmPrefixKey, LsmPrefixValue>::try_from(map) {
            for slot in 0..FLUXVM_LSM_MAX_PREFIXES {
                let _ = write.remove(&LsmPrefixKey { cgroup_id, slot, reserved: 0 });
            }
        }
    }
}

/// Extracts the OCI `root.readonly` flag and declared mount `destination`
/// paths directly from the raw config JSON -- independent of
/// `parse_oci_config`'s host-path-joined `mounts` return, since Set 9S needs
/// the guest-visible destination strings (e.g. `/data`, not
/// `<rootfs>/data`) that a running process actually sees after
/// `pivot_root`. RESTRICT_WRITES is only meaningful (and only ever enabled
/// by `create_container`) when the rootfs itself is OCI-declared read-only;
/// otherwise nearly every ordinary write inside the container's own image
/// layers would be denied.
fn oci_write_policy(config_json: &str) -> (bool, Vec<String>) {
    let Ok(v) = serde_json::from_str::<Value>(config_json) else { return (false, Vec::new()); };
    let root_readonly = v.pointer("/root/readonly").and_then(Value::as_bool).unwrap_or(false);
    let mut prefixes = Vec::new();
    if let Some(items) = v.get("mounts").and_then(Value::as_array) {
        for item in items {
            if let Some(dest) = item.get("destination").and_then(Value::as_str) {
                prefixes.push(dest.to_string());
            }
        }
    }
    (root_readonly, prefixes)
}

fn cgroup_id_for(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path).with_context(|| format!("statting cgroup {}", path.display()))?.ino())
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
        seccomp_notify: SeccompNotifyPolicy::default(),
        apparmor_profile: process.get("apparmorProfile").and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_string),
        selinux_label: process.get("selinuxLabel").and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_string),
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

    let notify_pair = if spec.seccomp.as_ref().is_some_and(seccomp_profile_uses_notify) {
        Some(unix_fd_socketpair()?)
    } else {
        None
    };

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
            if let Some(pair) = notify_pair {
                libc::close(pair[0]);
                libc::close(pair[1]);
            }
        }
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        // === Outer (namespace-establishing reaper) process ===
        unsafe {
            libc::close(gate[1]);
            libc::close(ns_ready[0]);
            // Only the grandparent (request-handling thread, below) reads
            // the notification listener fd; the outer reaper never touches
            // either end of this pair.
            if let Some(pair) = notify_pair { libc::close(pair[0]); }
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
                if let Some(pair) = notify_pair { libc::close(pair[1]); }
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
            if let Some(profile) = spec.apparmor_profile.as_deref() {
                if apply_apparmor_on_exec(profile).is_err() { libc::_exit(126); }
            }
            if let Some(label) = spec.selinux_label.as_deref() {
                if apply_selinux_on_exec(label).is_err() { libc::_exit(126); }
            }
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
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    libc::_exit(126);
                }
                let notify_socket = notify_pair.map(|pair| pair[1]);
                if apply_seccomp(profile, notify_socket).is_err() {
                    if let Some(fd) = notify_socket { libc::close(fd); }
                    libc::_exit(126);
                }
                if let Some(fd) = notify_socket { libc::close(fd); }
            } else if let Some(pair) = notify_pair {
                libc::close(pair[1]);
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
    if let Some(pair) = notify_pair {
        unsafe { libc::close(pair[1]); }
        let policy = spec.seccomp_notify;
        let broker_label = format!("{container_id}/{}", exec_id.unwrap_or("init"));
        // `pid` here is the outer namespace-reaper process (see the
        // double-fork above), not the inner execve'd process directly — but
        // the reaper blocks in waitpid() for the inner process's entire
        // lifetime and exits immediately after it does, so tracking the
        // reaper's liveness is an accurate proxy for "is the notified
        // container process still around" without threading the inner pid
        // back out of the forked child.
        std::thread::spawn(move || run_seccomp_notify_broker(pair[0], policy, pid as u32, broker_label));
    }
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
        let (spec, mounts, resources, device_policy) = parse_oci_config(r#"{
          "root":{"path":"/run/rootfs"},
          "process":{"args":["/bin/echo","hi"],"cwd":"/","env":["A=B"],"user":{"uid":1000,"gid":1001}}
        }"#).unwrap();
        assert!(mounts.is_empty());
        assert_eq!(resources, ResourceLimits::default());
        assert!(device_policy.is_none());
        assert_eq!(spec.rootfs, PathBuf::from("/run/rootfs"));
        assert_eq!(spec.args[0], "/bin/echo");
        assert_eq!(spec.uid, 1000);
        assert_eq!(spec.gid, 1001);
        assert_eq!(spec.env, vec![("A".into(), "B".into())]);
    }

    #[test]
    fn parses_process_security_controls() {
        let (spec, _, _, _) = parse_oci_config(r#"{
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
        let (spec, _, _, _) = parse_oci_config(r#"{
          "root":{"path":"/run/rootfs"},
          "process":{"args":["/bin/true"]},
          "linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["ptrace"],"action":"SCMP_ACT_ERRNO","errnoRet":1}]}}
        }"#).unwrap();
        let seccomp = spec.seccomp.unwrap();
        assert_eq!(seccomp.rules.len(), 1);
        assert_eq!(seccomp.rules[0].names, vec!["ptrace"]);
    }

    #[test]
    fn parses_seccomp_argument_filters() {
        let (spec, _, _, _) = parse_oci_config(r#"{
          "root":{"path":"/run/rootfs"},
          "process":{"args":["/bin/true"]},
          "linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{
            "names":["clone"],"action":"SCMP_ACT_ERRNO","errnoRet":1,
            "args":[
              {"index":0,"value":1,"op":"SCMP_CMP_EQ"},
              {"index":1,"value":255,"valueTwo":7,"op":"SCMP_CMP_MASKED_EQ"}
            ]
          }]}}
        }"#).unwrap();
        let seccomp = spec.seccomp.unwrap();
        assert_eq!(seccomp.rules[0].args.len(), 2);
        assert_eq!(seccomp.rules[0].args[0].op, SCMP_CMP_EQ);
        assert_eq!(seccomp.rules[0].args[1].op, SCMP_CMP_MASKED_EQ);
        assert_eq!(seccomp.rules[0].args[1].value_two, 7);
    }

    #[test]
    fn accepts_all_oci_seccomp_comparison_operators() {
        let cases = [
            ("SCMP_CMP_NE", SCMP_CMP_NE),
            ("SCMP_CMP_LT", SCMP_CMP_LT),
            ("SCMP_CMP_LE", SCMP_CMP_LE),
            ("SCMP_CMP_EQ", SCMP_CMP_EQ),
            ("SCMP_CMP_GE", SCMP_CMP_GE),
            ("SCMP_CMP_GT", SCMP_CMP_GT),
            ("SCMP_CMP_MASKED_EQ", SCMP_CMP_MASKED_EQ),
        ];
        for (raw, expected) in cases {
            assert_eq!(seccomp_compare(raw).unwrap(), expected);
        }
    }

    #[test]
    fn rejects_invalid_seccomp_argument_shapes() {
        assert!(parse_oci_config(r#"{
          "root":{"path":"/run/rootfs"},
          "process":{"args":["/bin/true"]},
          "linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{
            "names":["clone"],"action":"SCMP_ACT_ERRNO",
            "args":[{"index":6,"value":1,"op":"SCMP_CMP_EQ"}]
          }]}}
        }"#).is_err());
        assert!(parse_oci_config(r#"{
          "root":{"path":"/run/rootfs"},
          "process":{"args":["/bin/true"]},
          "linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{
            "names":["clone"],"action":"SCMP_ACT_ERRNO",
            "args":[{"index":0,"value":255,"op":"SCMP_CMP_MASKED_EQ"}]
          }]}}
        }"#).is_err());
    }

    #[test]
    fn parses_lsm_process_labels() {
        let (spec, _, _, _) = parse_oci_config(r#"{
          "root":{"path":"/run/rootfs"},
          "process":{
            "args":["/bin/true"],
            "apparmorProfile":"fluxvm-default",
            "selinuxLabel":"system_u:system_r:container_t:s0:c1,c2"
          }
        }"#).unwrap();
        assert_eq!(spec.apparmor_profile.as_deref(), Some("fluxvm-default"));
        assert_eq!(spec.selinux_label.as_deref(), Some("system_u:system_r:container_t:s0:c1,c2"));
    }

    #[test]
    fn formats_selinux_mount_label_like_oci_runtimes() {
        let label = "system_u:object_r:container_file_t:s0:c1,c2";
        assert_eq!(
            format_selinux_mount_data(Some("mode=755"), Some(label)).unwrap().as_deref(),
            Some("mode=755,context=\"system_u:object_r:container_file_t:s0:c1,c2\"")
        );
        assert!(format_selinux_mount_data(Some("context=\"old\""), Some(label)).is_err());
    }

    #[test]
    fn parses_seccomp_notify_policy_fail_closed() {
        let config = serde_json::json!({
            "annotations": {
                "io.zyvor.seccomp.notify.mode": "continue",
                "io.zyvor.seccomp.notify.errno": "13"
            }
        });
        let policy = parse_seccomp_notify_policy(&config).unwrap();
        assert_eq!(policy.mode, SeccompNotifyMode::Continue);
        assert_eq!(policy.errno, 13);
        let default_policy = parse_seccomp_notify_policy(&serde_json::json!({})).unwrap();
        assert_eq!(default_policy.mode, SeccompNotifyMode::Deny);
        assert_eq!(default_policy.errno, libc::EPERM);
    }

    #[test]
    fn parses_explicit_seccomp_notify_rules() {
        let config = serde_json::json!({
            "linux": {"seccomp": {
                "defaultAction": "SCMP_ACT_ALLOW",
                "syscalls": [{"names": ["mount"], "action": "SCMP_ACT_NOTIFY"}]
            }}
        });
        let profile = parse_seccomp_profile(&config).unwrap().unwrap();
        assert!(seccomp_profile_uses_notify(&profile));
        assert_eq!(profile.rules[0].action, SCMP_ACT_NOTIFY);
    }

    #[test]
    fn rejects_notify_bootstrap_deadlocks() {
        let default_notify = serde_json::json!({
            "linux": {"seccomp": {"defaultAction": "SCMP_ACT_NOTIFY"}}
        });
        assert!(parse_seccomp_profile(&default_notify).is_err());
        let sendmsg_notify = serde_json::json!({
            "linux": {"seccomp": {
                "defaultAction": "SCMP_ACT_ALLOW",
                "syscalls": [{"names": ["sendmsg"], "action": "SCMP_ACT_NOTIFY"}]
            }}
        });
        assert!(parse_seccomp_profile(&sendmsg_notify).is_err());
    }

    /// Real end-to-end validation of the Set 11 seccomp-notify broker: forks
    /// a real child, loads a real NOTIFY filter on the real `getpid` syscall
    /// via `libseccomp.so.2`, transfers the listener fd with real SCM_RIGHTS
    /// over a real socketpair, and runs the real broker loop against it --
    /// not just the OCI-parsing-level unit tests above. Uses
    /// `libc::syscall(SYS_getpid)` (not the glibc `getpid()` wrapper) because
    /// glibc may cache/vDSO-shortcut the wrapper and never issue the actual
    /// syscall the kernel notification path depends on.
    #[test]
    fn seccomp_notify_broker_enforces_deny_and_continue() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: needs root for seccomp NOTIFY");
            return;
        }
        let probe = CString::new("libseccomp.so.2").unwrap();
        let handle = unsafe { libc::dlopen(probe.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            eprintln!("skipping: libseccomp.so.2 not installed");
            return;
        }
        unsafe { libc::dlclose(handle); }

        let deny = run_notify_case(SeccompNotifyPolicy { mode: SeccompNotifyMode::Deny, errno: libc::EACCES });
        assert_eq!(deny, -(libc::EACCES as i64), "denied syscall should observe the configured errno, got {deny}");

        let cont = run_notify_case(SeccompNotifyPolicy { mode: SeccompNotifyMode::Continue, errno: libc::EPERM });
        assert!(cont >= 0, "continued syscall should actually execute and succeed, got {cont}");
    }

    /// Forks a child that installs a NOTIFY filter on `getpid`, calls it, and
    /// reports the raw result (`>=0` success or `-errno`) back over a pipe.
    /// The broker runs synchronously in the parent -- its own poll loop exits
    /// once the child has responded and exited, so this never needs a
    /// separate supervisor thread or an explicit timeout in the test itself.
    fn run_notify_case(policy: SeccompNotifyPolicy) -> i64 {
        let profile = SeccompProfile {
            default_action: SCMP_ACT_ALLOW,
            rules: vec![SeccompRule {
                action: SCMP_ACT_NOTIFY,
                names: vec!["getpid".to_string()],
                args: vec![],
            }],
        };
        let pair = unix_fd_socketpair().expect("notify socketpair");
        let mut result_pipe = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(result_pipe.as_mut_ptr()) }, 0);

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::close(pair[0]);
                libc::close(result_pipe[0]);
                if apply_seccomp(&profile, Some(pair[1])).is_err() {
                    libc::_exit(120);
                }
                libc::close(pair[1]);
                let rc = libc::syscall(libc::SYS_getpid);
                let observed: i64 = if rc < 0 {
                    -(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as i64)
                } else {
                    rc
                };
                let bytes = observed.to_ne_bytes();
                libc::write(result_pipe[1], bytes.as_ptr().cast(), bytes.len());
                libc::close(result_pipe[1]);
                libc::_exit(0);
            }
        }
        unsafe {
            libc::close(pair[1]);
            libc::close(result_pipe[1]);
        }
        run_seccomp_notify_broker(pair[0], policy, pid as u32, "test/notify".to_string());
        let mut buf = [0u8; 8];
        let n = unsafe { libc::read(result_pipe[0], buf.as_mut_ptr().cast(), buf.len()) };
        unsafe { libc::close(result_pipe[0]); }
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &mut status, 0); }
        assert_eq!(n, 8, "child did not report a getpid() result before exiting");
        i64::from_ne_bytes(buf)
    }

    #[test]
    fn device_cgroup_policy_generates_ordered_bpf() {
        let config = serde_json::json!({
            "linux": {"resources": {"devices": [
                {"allow": false, "type": "a", "access": "rwm"},
                {"allow": true, "type": "c", "major": 1, "minor": 3, "access": "rw"}
            ]}}
        });
        let policy = parse_device_cgroup_policy(&config).unwrap().unwrap();
        assert!(!policy.default_allow);
        assert_eq!(policy.rules.len(), 1);
        assert!(policy.rules[0].allow);
        let program = build_device_bpf(&policy).unwrap();
        assert_eq!(program.first().unwrap().code, 0x61);
        assert_eq!(program.last().unwrap().code, 0x95);
        assert!(program.len() > 8);
    }

    #[test]
    fn device_policy_rejects_wildcard_hole_removal() {
        let config = serde_json::json!({
            "linux": {"resources": {"devices": [
                {"allow": false, "type": "a", "access": "rwm"},
                {"allow": true, "type": "c", "major": -1, "minor": -1, "access": "r"},
                {"allow": false, "type": "c", "major": 1, "minor": 3, "access": "r"}
            ]}}
        });
        assert!(parse_device_cgroup_policy(&config).is_err());
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

    /// Set 8S: exercises the real attach/configure/cleanup flow against a
    /// throwaway cgroup v2 subtree -- not a mock. Needs root (cgroup_skb
    /// attach requires CAP_SYS_ADMIN) and a real cgroup2 mount, so it skips
    /// itself rather than failing CI runners that have neither; run with
    /// `sudo cargo test -p fluxvm-container-agent guest_cgroup_policy_attaches_and_enforces -- --nocapture`
    /// on a real Linux host to actually exercise it.
    #[test]
    fn guest_cgroup_policy_attaches_and_enforces() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: needs root for cgroup_skb attach");
            return;
        }
        let cgroup_root = std::path::Path::new("/sys/fs/cgroup");
        if !cgroup_root.join("cgroup.controllers").exists() {
            eprintln!("skipping: no cgroup v2 mount at /sys/fs/cgroup");
            return;
        }
        let test_cgroup = cgroup_root.join("fluxvm-agent-test-8s");
        let _ = std::fs::remove_dir(&test_cgroup);
        std::fs::create_dir_all(&test_cgroup).expect("creating test cgroup");

        let result = (|| -> Result<()> {
            attach_guest_network_policy(&test_cgroup)?;
            let cgroup_id = cgroup_id_for(&test_cgroup)?;
            // default_allow: false, no explicit peers -- everything but
            // loopback should be denied once this is live.
            configure_container_policy(cgroup_id, Some(&ContainerNetworkPolicy::default()))?;

            // Move this test thread's process into the cgroup and prove
            // enforcement with a real socket, not just "attach succeeded".
            std::fs::write(test_cgroup.join("cgroup.procs"), std::process::id().to_string())?;
            let deny = std::net::TcpStream::connect_timeout(
                &"93.184.216.34:80".parse().unwrap(),
                std::time::Duration::from_millis(500),
            );
            assert!(deny.is_err(), "expected non-loopback connect to be blocked by default-deny policy");

            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            let allow = std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().unwrap(),
                std::time::Duration::from_millis(500),
            );
            assert!(allow.is_ok(), "expected loopback connect to remain allowed (both this process's egress and, as the listener, its own ingress are in the same policed cgroup)");

            forget_container_policy(cgroup_id);
            Ok(())
        })();

        // Move this process back to the root cgroup before cleanup can
        // remove the test one (cgroup v2 requires an empty cgroup to rmdir).
        let _ = std::fs::write(cgroup_root.join("cgroup.procs"), std::process::id().to_string());
        let _ = std::fs::remove_dir(&test_cgroup);
        result.expect("guest cgroup policy attach/configure/enforce flow");
    }

    /// Set 9S: exercises the real attach/configure/cleanup flow against a
    /// throwaway cgroup v2 subtree -- not a mock. Needs root and a kernel
    /// with BPF LSM active (`bpf` present in `/sys/kernel/security/lsm`,
    /// which itself requires `CONFIG_BPF_LSM=y` plus the `lsm=...,bpf` boot
    /// parameter), so it skips itself rather than failing hosts/CI runners
    /// without both. Run with `sudo cargo test -p fluxvm-container-agent
    /// guest_lsm_policy_attaches_and_enforces -- --nocapture` on a real
    /// Linux host with BPF LSM enabled to actually exercise it.
    ///
    /// Known environment sensitivity: on at least one validation host this
    /// test intermittently failed at the `Ebpf::load()` step with "error
    /// parsing ELF data" even though the exact embedded object bytes were
    /// independently confirmed byte-correct (verified via a standalone
    /// `aya::Ebpf::load()` reproduction outside this binary, which loaded
    /// the identical file successfully as root) -- the enforcement logic
    /// itself was confirmed correct in the runs where loading succeeded
    /// (both the write-prefix allow/deny and the W+X mprotect denial fired
    /// exactly as expected). The most likely cause traced so far: `aya`
    /// 0.13.1 unconditionally requires the `object` crate's `write` feature
    /// family (`pe`/`coff`/`macho`/`xcoff`) alongside `read_core`, which
    /// this workspace's Cargo.lock pins to `object 0.36.7` -- a version/
    /// feature-unification interaction in that exact pin, not a bug in this
    /// program or in the map-key/path-length fixes already applied here. A
    /// newer `aya`/`aya-obj`/`object` pin is the likely fix; flagged as a
    /// follow-up rather than blocking this Set on a dependency bump.
    #[test]
    fn guest_lsm_policy_attaches_and_enforces() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping: needs root for LSM program load/attach");
            return;
        }
        let cgroup_root = std::path::Path::new("/sys/fs/cgroup");
        if !cgroup_root.join("cgroup.controllers").exists() {
            eprintln!("skipping: no cgroup v2 mount at /sys/fs/cgroup");
            return;
        }
        let active_lsms = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
        if !active_lsms.split(',').any(|v| v == "bpf") {
            eprintln!("skipping: bpf LSM is not active (/sys/kernel/security/lsm={active_lsms:?})");
            return;
        }
        let test_cgroup = cgroup_root.join("fluxvm-agent-test-9s");
        let _ = std::fs::remove_dir(&test_cgroup);
        std::fs::create_dir_all(&test_cgroup).expect("creating test cgroup");
        let allowed_dir = std::env::temp_dir().join(format!("fluxvm-9s-allowed-{}", std::process::id()));
        std::fs::create_dir_all(&allowed_dir).expect("creating allowed write dir");
        let denied_dir = std::env::temp_dir().join(format!("fluxvm-9s-denied-{}", std::process::id()));
        std::fs::create_dir_all(&denied_dir).expect("creating denied write dir");

        let result = (|| -> Result<()> {
            attach_guest_lsm()?;
            let cgroup_id = cgroup_id_for(&test_cgroup)?;
            let allowed_prefix = allowed_dir.to_string_lossy().into_owned();
            configure_container_lsm_policy(
                cgroup_id,
                /* deny_wx */ true,
                /* restrict_writes */ true,
                &[allowed_prefix],
                /* audit_only */ false,
            )?;

            std::fs::write(test_cgroup.join("cgroup.procs"), std::process::id().to_string())?;

            let denied_path = denied_dir.join("blocked.txt");
            let denied = std::fs::OpenOptions::new().create(true).write(true).open(&denied_path);
            assert!(denied.is_err(), "expected write outside the declared mount prefix to be denied");

            let allowed_path = allowed_dir.join("ok.txt");
            let allowed = std::fs::OpenOptions::new().create(true).write(true).open(&allowed_path);
            assert!(allowed.is_ok(), "expected write inside the declared mount prefix to remain allowed");
            drop(allowed);

            let page = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(page, libc::MAP_FAILED, "mmap for W+X test failed");
            let rc = unsafe { libc::mprotect(page, 4096, libc::PROT_WRITE | libc::PROT_EXEC) };
            let wx_errno = if rc != 0 { Some(std::io::Error::last_os_error()) } else { None };
            unsafe { libc::munmap(page, 4096) };
            assert!(rc != 0, "expected W+X mprotect to be denied under FLUXVM_LSM_DENY_WX");
            assert_eq!(
                wx_errno.and_then(|e| e.raw_os_error()),
                Some(libc::EPERM),
                "expected EPERM (LSM denial), not a different mprotect failure"
            );

            forget_container_lsm_policy(cgroup_id);
            Ok(())
        })();

        // Move this process back to the root cgroup before cleanup can
        // remove the test one (cgroup v2 requires an empty cgroup to rmdir).
        let _ = std::fs::write(cgroup_root.join("cgroup.procs"), std::process::id().to_string());
        let _ = std::fs::remove_dir(&test_cgroup);
        let _ = std::fs::remove_dir_all(&allowed_dir);
        let _ = std::fs::remove_dir_all(&denied_dir);
        result.expect("guest LSM attach/configure/enforce flow");
    }

    #[test]
    fn container_identity_is_tagged_and_stable() {
        let a = container_identity_for("container-a");
        let b = container_identity_for("container-b");
        assert_eq!(a, container_identity_for("container-a"));
        assert_ne!(a, b);
        assert_ne!(a & CONTAINER_IDENTITY_TAG_BIT, 0);
        assert_ne!(b & CONTAINER_IDENTITY_TAG_BIT, 0);
    }

    #[test]
    fn oci_write_policy_extracts_readonly_and_mount_destinations() {
        let (readonly, prefixes) = oci_write_policy(
            r#"{"root":{"path":"/r","readonly":true},"mounts":[{"destination":"/data"},{"destination":"/etc/hosts"}]}"#,
        );
        assert!(readonly);
        assert_eq!(prefixes, vec!["/data".to_string(), "/etc/hosts".to_string()]);

        let (readonly, prefixes) = oci_write_policy(r#"{"root":{"path":"/r"}}"#);
        assert!(!readonly);
        assert!(prefixes.is_empty());
    }
}

#[cfg(test)]
mod set8_guest_device_tests {
    use super::*;
    #[test]
    fn rejects_unsafe_block_serials() {
        let err = resolve_hotplug_block("../../evil", Duration::from_millis(0)).unwrap_err();
        assert!(err.to_string().contains("unsafe FluxVM block serial"));
    }
    #[test]
    fn rejects_device_path_escape() {
        let err = wait_guest_char_device("/dev/../etc/passwd", Duration::from_millis(0)).unwrap_err();
        assert!(err.to_string().contains("unsafe hotplugged guest device path"));
    }
}
