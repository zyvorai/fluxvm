// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Rootless `procbox` sandboxes behind `/v1/sandboxes`.
//!
//! A procbox sandbox is a [`VmRecord`] (so tenant scoping, quotas, listing,
//! TTL and delete all work unchanged) with no VMM behind it: a per-sandbox
//! workspace directory, a marker file recording the confinement limits, and
//! commands run through [`fluxvm_procbox`] (Landlock + seccomp). Everything a
//! guest would serve (exec, files, baseline/changes) is answered from the host
//! workspace; guest-only features (snapshot, HTTP proxy, pause, console) are
//! refused with [`ProcboxError::Unsupported`]. See `docs/procbox-backend.md`.

use crate::VmManager;
use crate::changes::{ChangeSet, FingerprintMode, Manifest, diff_manifests, validate_paths};
use anyhow::{Context, Result, bail};
use base64::Engine as _;
use fluxvm_core::config::ProcboxConfig;
use fluxvm_core::model::{BackendKind, CreateVmRequest, NetworkSpec, VmRecord, VmStatus};
use fluxvm_guest_protocol::{AgentResponse, MAX_FILE_TRANSFER_BYTES};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

pub const MARKER_FILE: &str = "procbox.json";
/// Directory (inside the record's workspace) that is the sandbox's only
/// writable place and the root every API path is resolved under.
pub const FILES_DIR: &str = "files";

/// Most files a manifest, size scan or copy will visit, so a workspace full of
/// tiny files cannot pin a worker.
const MAX_WALK_ENTRIES: usize = 500_000;

/// Read-only system locations a command needs to run a shell and common tools.
/// `/etc` is deliberately NOT granted wholesale: it holds host credentials
/// (`shadow`, the daemon's own config with API tokens, SSH keys).
const SYSTEM_READ_DIRS: &[&str] = &[
    "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin",
];
const SYSTEM_READ_ETC: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/alternatives",
    "/etc/localtime",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ssl/certs",
    "/etc/ca-certificates",
    "/etc/mime.types",
    "/dev/urandom",
    "/dev/random",
    "/dev/zero",
];

/// Typed failures the API layer maps to HTTP statuses.
#[derive(Debug)]
pub enum ProcboxError {
    /// Turned off in `[sandbox.procbox]`.
    Disabled,
    /// A feature that needs a guest (snapshot, HTTP proxy, pause, console...).
    Unsupported(String),
    /// A path that is absolute-outside, contains `..`, or crosses a symlink.
    PathEscape(String),
    /// The host cannot enforce the confinement (strict mode fails closed).
    Unavailable(String),
    /// A size or entry cap was exceeded.
    TooLarge(String),
}

impl std::fmt::Display for ProcboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(
                f,
                "procbox sandboxes are disabled on this server; set sandbox.procbox.enabled = true"
            ),
            Self::Unsupported(m) => write!(f, "{m}"),
            Self::PathEscape(m) => write!(f, "path rejected: {m}"),
            Self::Unavailable(m) => write!(f, "confinement unavailable: {m}"),
            Self::TooLarge(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ProcboxError {}

/// Refuse an operation that needs a guest VM when `vm` is a procbox sandbox.
pub fn require_guest(vm: &VmRecord, what: &str) -> Result<()> {
    if is_procbox(vm) {
        return Err(unsupported(what));
    }
    Ok(())
}

fn unsupported(what: &str) -> anyhow::Error {
    ProcboxError::Unsupported(format!(
        "{what} needs a guest VM and is not available for a procbox sandbox"
    ))
    .into()
}

/// What a caller may ask for when creating a procbox sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcboxRequest {
    /// Outbound TCP ports the sandbox may connect to (needs
    /// `sandbox.procbox.allow_net`). Empty = no network.
    pub net_ports: Vec<u16>,
    pub max_memory_mib: Option<u64>,
    pub max_processes: Option<u64>,
    /// Default wall-clock limit per command.
    pub timeout_seconds: Option<u64>,
    pub cpu_seconds: Option<u64>,
}

/// The limits recorded for a sandbox (already checked against the server caps).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcboxSpec {
    pub net_ports: Vec<u16>,
    pub max_memory_mib: u64,
    pub max_processes: u64,
    pub timeout_seconds: u64,
    pub cpu_seconds: Option<u64>,
    /// The uid/gid this sandbox's commands run as (root daemon only), taken
    /// from the server's uid pool when the sandbox is created.
    #[serde(default)]
    pub uid: Option<u32>,
}

/// Check a request against the server caps and fill in defaults. Values over a
/// cap are rejected, not silently lowered, so the caller knows what they got.
pub fn resolve_limits(cfg: &ProcboxConfig, req: &ProcboxRequest) -> Result<ProcboxSpec> {
    let memory = req.max_memory_mib.unwrap_or(cfg.default_memory_mib);
    if !(64..=cfg.max_memory_mib).contains(&memory) {
        bail!(
            "procbox max_memory_mib must be 64..={} (got {memory})",
            cfg.max_memory_mib
        );
    }
    let timeout = req.timeout_seconds.unwrap_or(cfg.default_timeout_secs);
    if timeout == 0 || timeout > cfg.max_timeout_secs {
        bail!(
            "procbox timeout_seconds must be 1..={} (got {timeout})",
            cfg.max_timeout_secs
        );
    }
    let procs = req.max_processes.unwrap_or(cfg.max_processes);
    if procs == 0 || procs > cfg.max_processes {
        bail!(
            "procbox max_processes must be 1..={} (got {procs})",
            cfg.max_processes
        );
    }
    if req.cpu_seconds == Some(0) {
        bail!("procbox cpu_seconds must be at least 1");
    }
    let mut ports = req.net_ports.clone();
    ports.sort_unstable();
    ports.dedup();
    if ports.contains(&0) {
        bail!("procbox net_ports must not contain 0");
    }
    if !ports.is_empty() && !cfg.allow_net {
        bail!("procbox network access is disabled on this server (sandbox.procbox.allow_net)");
    }
    Ok(ProcboxSpec {
        net_ports: ports,
        max_memory_mib: memory,
        max_processes: procs,
        timeout_seconds: timeout,
        cpu_seconds: req.cpu_seconds,
        uid: None,
    })
}

fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// The configured namespace-isolation mode.
pub fn isolation_mode(cfg: &ProcboxConfig) -> Result<fluxvm_procbox::Isolation> {
    cfg.isolation
        .parse()
        .map_err(|e: String| anyhow::anyhow!("sandbox.procbox.isolation: {e}"))
}

/// Serializes uid allocation with the marker write that claims it.
static UID_ALLOC: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Pick the lowest free uid of the pool for a new sandbox (root daemon only).
/// Claimed uids are read from the markers of the existing workspaces, so a
/// deleted sandbox frees its uid with its directory. Call with `UID_ALLOC` held.
fn allocate_uid(cfg: &ProcboxConfig, instances: &Path) -> Result<Option<u32>> {
    if !is_root() {
        return Ok(None);
    }
    if cfg.uid_count == 0 {
        if cfg.allow_root {
            return Ok(None);
        }
        return Err(ProcboxError::Unavailable(
            "the daemon runs as root and sandbox.procbox.uid_count = 0: refusing to run \
             sandbox commands as root (configure a uid pool, or set allow_root = true)"
                .into(),
        )
        .into());
    }
    let mut used = std::collections::HashSet::new();
    if let Ok(rd) = std::fs::read_dir(instances) {
        for ent in rd.flatten() {
            if let Ok(raw) = std::fs::read(ent.path().join(MARKER_FILE)) {
                if let Some(u) = serde_json::from_slice::<ProcboxSpec>(&raw)
                    .ok()
                    .and_then(|s| s.uid)
                {
                    used.insert(u);
                }
            }
        }
    }
    pick_uid(cfg, &used).map(Some)
}

/// The lowest uid of the pool that is not in `used`.
fn pick_uid(cfg: &ProcboxConfig, used: &std::collections::HashSet<u32>) -> Result<u32> {
    let end = cfg
        .uid_base
        .checked_add(cfg.uid_count)
        .filter(|_| cfg.uid_base != 0)
        .ok_or_else(|| {
            anyhow::anyhow!("sandbox.procbox.uid_base/uid_count must be a non-zero range in u32")
        })?;
    (cfg.uid_base..end)
        .find(|u| !used.contains(u))
        .ok_or_else(|| {
            ProcboxError::Unavailable(format!(
                "the procbox uid pool is exhausted ({} sandboxes); delete some or raise \
                 sandbox.procbox.uid_count",
                cfg.uid_count
            ))
            .into()
        })
}

/// The sandbox uid must be able to reach its workspace: every ancestor needs
/// search permission for others. `instances/` and the workspace are opened up
/// here; anything above must already allow it.
#[cfg(unix)]
fn prepare_traversal(workspace: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let instances = workspace.parent().unwrap_or(workspace);
    let mode = std::fs::metadata(instances)?.permissions().mode();
    if mode & 0o001 == 0 {
        std::fs::set_permissions(instances, std::fs::Permissions::from_mode(mode | 0o001))?;
    }
    std::fs::set_permissions(workspace, std::fs::Permissions::from_mode(0o711))?;
    for a in instances.ancestors().skip(1) {
        if a.as_os_str().is_empty() {
            break;
        }
        let m = std::fs::metadata(a)?.permissions().mode();
        if m & 0o001 == 0 {
            return Err(ProcboxError::Unavailable(format!(
                "{} must be searchable by other users (chmod o+x) so sandbox uid {uid} can reach its workspace",
                a.display()
            ))
            .into());
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_traversal(_: &Path, _: u32) -> Result<()> {
    Ok(())
}

/// Whether this host can run a procbox sandbox under the strict default
/// policy (Landlock with TCP rules, i.e. ABI 4+, plus seccomp).
pub fn confinement_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        fluxvm_procbox::probe::probe().default_policy_ok
            && fluxvm_procbox::landlock::kernel_abi() >= 4
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

pub fn is_procbox(vm: &VmRecord) -> bool {
    vm.workspace.join(MARKER_FILE).exists()
}

pub fn files_root(vm: &VmRecord) -> PathBuf {
    vm.workspace.join(FILES_DIR)
}

/// The recorded limits when `vm` is a procbox sandbox, else `None`.
pub fn load_spec(vm: &VmRecord) -> Result<Option<ProcboxSpec>> {
    match std::fs::read(vm.workspace.join(MARKER_FILE)) {
        Ok(raw) => Ok(Some(
            serde_json::from_slice(&raw).context("procbox marker file is corrupt")?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading procbox marker"),
    }
}

/// Turn a caller path into a normalized path relative to the workspace root.
///
/// Relative paths and absolute paths that already lie under `root` are
/// accepted; NUL bytes, `..` components and absolute paths anywhere else are
/// not. This is the cheap first line of defense; the kernel enforces the same
/// boundary again when the file is opened (see [`fsroot`]).
pub fn sanitize_rel(root: &Path, user: &str) -> Result<PathBuf, ProcboxError> {
    if user.is_empty() {
        return Err(ProcboxError::PathEscape("empty path".into()));
    }
    if user.contains('\0') {
        return Err(ProcboxError::PathEscape("path contains a NUL byte".into()));
    }
    let p = Path::new(user);
    let rel: &Path = if p.is_absolute() {
        p.strip_prefix(root).map_err(|_| {
            ProcboxError::PathEscape(format!(
                "absolute path {user:?} is outside the sandbox workspace"
            ))
        })?
    } else {
        p
    };
    let mut out = PathBuf::new();
    for c in rel.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(ProcboxError::PathEscape(format!("{user:?} contains `..`")));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ProcboxError::PathEscape(format!(
                    "{user:?} is not a plain relative path"
                )));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(ProcboxError::PathEscape(format!(
            "{user:?} names the workspace root itself"
        )));
    }
    Ok(out)
}

/// The policy a command runs under. Pure, so the boundary is unit-testable.
pub fn build_policy(
    cfg: &ProcboxConfig,
    spec: &ProcboxSpec,
    workdir: &Path,
    timeout: Option<u64>,
    exists: impl Fn(&Path) -> bool,
) -> fluxvm_procbox::Policy {
    use fluxvm_procbox::{Policy, SeccompMode, TcpRule};
    let read: Vec<PathBuf> = SYSTEM_READ_DIRS
        .iter()
        .chain(SYSTEM_READ_ETC.iter())
        .map(PathBuf::from)
        .filter(|p| exists(p))
        .collect();
    let mut write = vec![workdir.to_path_buf()];
    let null = PathBuf::from("/dev/null");
    if exists(&null) {
        write.push(null);
    }
    let wall = timeout
        .filter(|t| *t > 0)
        .unwrap_or(spec.timeout_seconds)
        .min(cfg.max_timeout_secs);
    Policy {
        read,
        write,
        tcp_connect: if spec.net_ports.is_empty() {
            TcpRule::Deny
        } else {
            TcpRule::Ports(spec.net_ports.clone())
        },
        tcp_bind: TcpRule::Deny,
        scope_ipc: true,
        seccomp: Some(SeccompMode::Errno),
        allow_namespaces: false,
        max_memory: Some(spec.max_memory_mib << 20),
        max_processes: Some(spec.max_processes),
        cpu_seconds: spec.cpu_seconds,
        timeout_secs: Some(wall),
        clean_env: true,
        env: vec![
            ("HOME".into(), workdir.display().to_string()),
            ("WORKSPACE".into(), workdir.display().to_string()),
        ],
        cwd: Some(workdir.to_path_buf()),
        best_effort: cfg.best_effort,
        run_as: spec.uid.map(|uid| fluxvm_procbox::RunAs { uid, gid: uid }),
        isolation: isolation_mode(cfg).unwrap_or(fluxvm_procbox::Isolation::Auto),
        ..Policy::default()
    }
}

struct Confined {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// Run `command` under [`build_policy`] with `workdir` as the only writable
/// directory. Blocking; call from `spawn_blocking`.
fn run_confined(
    cfg: &ProcboxConfig,
    spec: &ProcboxSpec,
    workdir: &Path,
    command: &str,
    timeout: Option<u64>,
) -> Result<Confined> {
    if is_root() && spec.uid.is_none() && !cfg.allow_root {
        return Err(ProcboxError::Unavailable(
            "refusing to run a sandbox command as root: this sandbox has no uid (it predates the \
             uid pool, or the pool is off); recreate it or set sandbox.procbox.allow_root"
                .into(),
        )
        .into());
    }
    isolation_mode(cfg)?;
    let policy = build_policy(cfg, spec, workdir, timeout, |p| p.exists());
    let argv = vec!["/bin/sh".to_string(), "-c".to_string(), command.to_string()];
    let res = fluxvm_procbox::run(
        &policy,
        &argv,
        &fluxvm_procbox::RunOptions { capture: true },
    )
    .map_err(|e| ProcboxError::Unavailable(format!("{e:#}")))?;
    let wall = policy.timeout_secs.unwrap_or(0);
    let exit_code = if res.timed_out {
        124
    } else if let Some(c) = res.exit_code {
        c
    } else if let Some(s) = res.signal {
        128 + s
    } else {
        -1
    };
    let mut stderr = res.stderr;
    if res.timed_out {
        stderr.push_str(&format!("\n[procbox] command timed out after {wall}s\n"));
    }
    if res.output_truncated {
        stderr.push_str("\n[procbox] output truncated\n");
    }
    if !res.enforcement.not_enforced.is_empty() {
        tracing::warn!(
            not_enforced = ?res.enforcement.not_enforced,
            "procbox ran with reduced confinement (best_effort)"
        );
        stderr.push_str(&format!(
            "\n[procbox] not enforced: {}\n",
            res.enforcement.not_enforced.join("; ")
        ));
    }
    Ok(Confined {
        exit_code,
        stdout: res.stdout,
        stderr,
    })
}

#[cfg(target_os = "linux")]
mod fsroot {
    //! A directory fd every access is resolved beneath. `openat2` with
    //! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` makes
    //! the *kernel* refuse `..` escapes and any symlink on the path, at open
    //! time, so a confined process that swaps a directory for a symlink between
    //! our check and our open cannot redirect us.

    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    const SYS_OPENAT2: libc::c_long = 437;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    fn openat2(dir: RawFd, rel: &Path, flags: i32, mode: u32) -> io::Result<OwnedFd> {
        let c = CString::new(rel.as_os_str().as_bytes())
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        let how = OpenHow {
            flags: (flags | libc::O_CLOEXEC) as u64,
            mode: mode as u64,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: valid NUL-terminated path and a correctly sized `open_how`.
        let fd = unsafe {
            libc::syscall(
                SYS_OPENAT2,
                dir,
                c.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: a fresh descriptor we own.
            Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
        }
    }

    fn open_err(e: io::Error, rel: &Path) -> anyhow::Error {
        match e.raw_os_error() {
            Some(libc::ELOOP) | Some(libc::EXDEV) => ProcboxError::PathEscape(format!(
                "{} crosses a symlink or leaves the workspace",
                rel.display()
            ))
            .into(),
            Some(libc::ENOSYS) => ProcboxError::Unavailable(
                "the kernel has no openat2 (Linux 5.6+ required for safe workspace access)".into(),
            )
            .into(),
            _ => anyhow::Error::new(e).context(format!("{}", rel.display())),
        }
    }

    pub struct Root {
        fd: OwnedFd,
        path: PathBuf,
        /// Files and directories created through this root are given to this
        /// (uid, gid), so the sandbox uid can use what the API wrote.
        owner: Option<(u32, u32)>,
    }

    struct Entry {
        rel: String,
        name: PathBuf,
        kind: Kind,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Kind {
        File,
        Dir,
        Symlink,
        Other,
    }

    impl Root {
        pub fn open(path: &Path) -> Result<Root> {
            let c = CString::new(path.as_os_str().as_bytes())?;
            // SAFETY: valid path; the returned fd is owned below.
            let fd = unsafe {
                libc::open(
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("opening workspace {}", path.display()));
            }
            Ok(Root {
                // SAFETY: fresh descriptor.
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
                path: path.to_path_buf(),
                owner: None,
            })
        }

        pub fn with_owner(mut self, owner: Option<(u32, u32)>) -> Root {
            self.owner = owner;
            self
        }

        fn chown_fd(&self, fd: RawFd) -> Result<()> {
            if let Some((uid, gid)) = self.owner {
                // SAFETY: fd is open for the duration of the call.
                if unsafe { libc::fchown(fd, uid, gid) } != 0 {
                    return Err(io::Error::last_os_error()).context("chown to the sandbox uid");
                }
            }
            Ok(())
        }

        pub fn chown_path(&self, p: &Path) -> Result<()> {
            if let Some((uid, gid)) = self.owner {
                let c = CString::new(p.as_os_str().as_bytes())?;
                // SAFETY: valid NUL-terminated path; lchown does not follow symlinks.
                if unsafe { libc::lchown(c.as_ptr(), uid, gid) } != 0 {
                    return Err(io::Error::last_os_error()).context("chown to the sandbox uid");
                }
            }
            Ok(())
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        pub fn read_file(&self, rel: &Path, max: usize) -> Result<(Vec<u8>, u32)> {
            let fd = openat2(
                self.fd.as_raw_fd(),
                rel,
                libc::O_RDONLY | libc::O_NONBLOCK,
                0,
            )
            .map_err(|e| open_err(e, rel))?;
            let file = std::fs::File::from(fd);
            let meta = file.metadata()?;
            if !meta.is_file() {
                bail!("{} is not a regular file", rel.display());
            }
            if meta.len() as usize > max {
                return Err(ProcboxError::TooLarge(format!(
                    "{} is {} bytes; the limit is {max}",
                    rel.display(),
                    meta.len()
                ))
                .into());
            }
            let mut data = Vec::with_capacity(meta.len() as usize);
            file.take(max as u64 + 1).read_to_end(&mut data)?;
            if data.len() > max {
                return Err(ProcboxError::TooLarge(format!(
                    "{} grew past the {max}-byte limit while reading",
                    rel.display()
                ))
                .into());
            }
            Ok((data, meta_mode(&meta)))
        }

        /// Create or replace a regular file, creating parent directories one
        /// component at a time (each step re-resolved beneath the previous fd).
        pub fn write_file(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
            let comps: Vec<&std::ffi::OsStr> = rel
                .components()
                .filter_map(|c| match c {
                    Component::Normal(n) => Some(n),
                    _ => None,
                })
                .collect();
            let Some((last, parents)) = comps.split_last() else {
                bail!("empty path");
            };
            let mut cur: Option<OwnedFd> = None;
            for comp in parents {
                let base = cur
                    .as_ref()
                    .map(|f| f.as_raw_fd())
                    .unwrap_or(self.fd.as_raw_fd());
                let c = CString::new(comp.as_bytes())?;
                // SAFETY: valid dirfd and NUL-terminated single component.
                let rc = unsafe { libc::mkdirat(base, c.as_ptr(), 0o755) };
                let created = rc == 0;
                if rc != 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() != Some(libc::EEXIST) {
                        return Err(open_err(e, rel));
                    }
                }
                let next = openat2(base, Path::new(comp), libc::O_RDONLY | libc::O_DIRECTORY, 0)
                    .map_err(|e| open_err(e, rel))?;
                if created {
                    self.chown_fd(next.as_raw_fd())?;
                }
                cur = Some(next);
            }
            let base = cur
                .as_ref()
                .map(|f| f.as_raw_fd())
                .unwrap_or(self.fd.as_raw_fd());
            let fd = openat2(
                base,
                Path::new(last),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW,
                mode & 0o777,
            )
            .map_err(|e| open_err(e, rel))?;
            let mut file = std::fs::File::from(fd);
            if !file.metadata()?.is_file() {
                bail!("{} is not a regular file", rel.display());
            }
            self.chown_fd(file.as_raw_fd())?;
            file.write_all(data)?;
            Ok(())
        }

        fn walk(
            &self,
            dir: RawFd,
            prefix: &str,
            count: &mut usize,
            visit: &mut dyn FnMut(RawFd, &Entry) -> Result<()>,
        ) -> Result<()> {
            // `/proc/self/fd/N` names the already-open directory itself, so the
            // listing cannot be redirected by swapping a path underneath us.
            let listing = std::fs::read_dir(format!("/proc/self/fd/{dir}"))
                .context("listing workspace directory")?;
            for ent in listing {
                let ent = ent?;
                *count += 1;
                if *count > MAX_WALK_ENTRIES {
                    return Err(ProcboxError::TooLarge(format!(
                        "workspace has more than {MAX_WALK_ENTRIES} entries"
                    ))
                    .into());
                }
                let name = PathBuf::from(ent.file_name());
                let ft = ent.file_type()?;
                let kind = if ft.is_dir() {
                    Kind::Dir
                } else if ft.is_symlink() {
                    Kind::Symlink
                } else if ft.is_file() {
                    Kind::File
                } else {
                    Kind::Other
                };
                let rel = format!("{prefix}/{}", name.to_string_lossy());
                let entry = Entry { rel, name, kind };
                visit(dir, &entry)?;
                if kind == Kind::Dir {
                    let sub = openat2(dir, &entry.name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
                        .map_err(|e| open_err(e, &entry.name))?;
                    self.walk(sub.as_raw_fd(), &entry.rel, count, visit)?;
                }
            }
            Ok(())
        }

        /// SHA-256 manifest of every regular file, keyed `/relative/path`.
        pub fn manifest(&self) -> Result<Manifest> {
            let mut files = BTreeMap::new();
            let mut count = 0usize;
            self.walk(self.fd.as_raw_fd(), "", &mut count, &mut |dir, e| {
                if e.kind != Kind::File {
                    return Ok(());
                }
                let fd = match openat2(dir, &e.name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
                    Ok(fd) => fd,
                    // Vanished or swapped for a symlink since the listing: skip.
                    Err(_) => return Ok(()),
                };
                let mut file = std::fs::File::from(fd);
                if !file.metadata().map(|m| m.is_file()).unwrap_or(false) {
                    return Ok(());
                }
                let mut hasher = Sha256::new();
                let mut buf = [0u8; 64 * 1024];
                loop {
                    let n = file.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                }
                files.insert(e.rel.clone(), format!("{:x}", hasher.finalize()));
                Ok(())
            })?;
            Ok(Manifest {
                mode: FingerprintMode::Sha256,
                files,
            })
        }

        /// Total bytes in regular files.
        pub fn total_size(&self) -> Result<u64> {
            let mut total = 0u64;
            let mut count = 0usize;
            self.walk(self.fd.as_raw_fd(), "", &mut count, &mut |dir, e| {
                if e.kind == Kind::File {
                    if let Ok(fd) = openat2(dir, &e.name, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
                        if let Ok(m) = std::fs::File::from(fd).metadata() {
                            total += m.len();
                        }
                    }
                }
                Ok(())
            })?;
            Ok(total)
        }

        /// Copy the tree into the existing empty directory `dest`. Symlinks are
        /// recreated as symlinks and never followed; special files are skipped.
        pub fn copy_to(&self, dest: &Path) -> Result<()> {
            let mut count = 0usize;
            self.walk(self.fd.as_raw_fd(), "", &mut count, &mut |dir, e| {
                let target = dest.join(e.rel.trim_start_matches('/'));
                match e.kind {
                    Kind::Dir => {
                        std::fs::create_dir(&target)?;
                        self.chown_path(&target)?;
                    }
                    Kind::File => {
                        let fd = openat2(dir, &e.name, libc::O_RDONLY | libc::O_NONBLOCK, 0)
                            .map_err(|er| open_err(er, &e.name))?;
                        let mut src = std::fs::File::from(fd);
                        let meta = src.metadata()?;
                        if !meta.is_file() {
                            return Ok(());
                        }
                        let mut out = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(meta_mode(&meta))
                            .open(&target)?;
                        io::copy(&mut src, &mut out)?;
                        drop(out);
                        std::fs::set_permissions(
                            &target,
                            std::os::unix::fs::PermissionsExt::from_mode(meta_mode(&meta)),
                        )?;
                        self.chown_path(&target)?;
                    }
                    Kind::Symlink => {
                        let link = std::fs::read_link(format!(
                            "/proc/self/fd/{dir}/{}",
                            e.name.to_string_lossy()
                        ))?;
                        std::os::unix::fs::symlink(link, &target)?;
                        self.chown_path(&target)?;
                    }
                    Kind::Other => {}
                }
                Ok(())
            })
        }
    }

    fn meta_mode(m: &std::fs::Metadata) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o777
    }
}

#[cfg(not(target_os = "linux"))]
mod fsroot {
    use super::*;

    pub struct Root;

    impl Root {
        pub fn open(_: &Path) -> Result<Root> {
            Err(unsupported("procbox workspaces (Linux only)"))
        }
        pub fn path(&self) -> &Path {
            Path::new("")
        }
        pub fn with_owner(self, _: Option<(u32, u32)>) -> Root {
            self
        }
        pub fn chown_path(&self, _: &Path) -> Result<()> {
            Ok(())
        }
        pub fn read_file(&self, _: &Path, _: usize) -> Result<(Vec<u8>, u32)> {
            Err(unsupported("procbox workspaces (Linux only)"))
        }
        pub fn write_file(&self, _: &Path, _: &[u8], _: u32) -> Result<()> {
            Err(unsupported("procbox workspaces (Linux only)"))
        }
        pub fn manifest(&self) -> Result<Manifest> {
            Err(unsupported("procbox workspaces (Linux only)"))
        }
        pub fn total_size(&self) -> Result<u64> {
            Err(unsupported("procbox workspaces (Linux only)"))
        }
        pub fn copy_to(&self, _: &Path) -> Result<()> {
            Err(unsupported("procbox workspaces (Linux only)"))
        }
    }
}

pub use fsroot::Root;

/// Remove a tree even if a confined command left directories unreadable.
fn force_remove(path: &Path) {
    if std::fs::remove_dir_all(path).is_ok() {
        return;
    }
    fn open_up(p: &Path) {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::symlink_metadata(p) {
            if meta.is_dir() {
                let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
                if let Ok(rd) = std::fs::read_dir(p) {
                    for e in rd.flatten() {
                        open_up(&e.path());
                    }
                }
            }
        }
    }
    open_up(path);
    let _ = std::fs::remove_dir_all(path);
}

/// Deletes the directory on drop, so a dry-run copy never outlives its request.
struct TempTree(PathBuf);

impl Drop for TempTree {
    fn drop(&mut self) {
        force_remove(&self.0);
    }
}

/// Result of a dry-run: what the command changed, then everything discarded.
#[derive(Debug, Serialize)]
pub struct DryRunReport {
    pub changes: ChangeSet,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub discarded: bool,
    /// How the discard was done: `workspace-copy` (procbox ran on a throwaway
    /// copy) or `snapshot` (VM restored from a snapshot).
    pub reverted_via: &'static str,
    pub paths: Vec<String>,
}

/// Snapshot manifest of `root`, for baseline/changes on a procbox sandbox.
pub fn take_manifest(vm: &VmRecord, paths: &[String]) -> Result<Manifest> {
    let root = Root::open(&files_root(vm))?;
    Ok(root.manifest()?.restrict_to(paths))
}

impl VmManager {
    /// Create a procbox sandbox: workspace + marker + record, no VMM.
    pub(crate) async fn create_procbox_sandbox(
        self: &std::sync::Arc<Self>,
        req: crate::SandboxCreateRequest,
        pb: ProcboxRequest,
        token_tenant: Option<&str>,
        created_by_token: Option<&str>,
    ) -> Result<VmRecord> {
        let cfg = &self.cfg.sandbox.procbox;
        if !cfg.enabled {
            return Err(ProcboxError::Disabled.into());
        }
        if req.template.is_some()
            || req.spec.is_some()
            || !req.volumes.is_empty()
            || req.http_proxy_port.is_some()
            || !req.http_proxy_ports.is_empty()
            || req.vcpus.is_some()
            || req.confidential.is_some()
        {
            bail!(
                "a procbox sandbox takes no template, spec, volumes, HTTP proxy ports, vcpus or confidential setting"
            );
        }
        let mut pb = pb;
        if pb.max_memory_mib.is_none() {
            pb.max_memory_mib = req.memory_mib;
        }
        let mut spec = resolve_limits(cfg, &pb)?;
        let isolation = isolation_mode(cfg)?;

        // Fail closed at create time if the host cannot enforce this policy.
        let probe_policy = build_policy(cfg, &spec, Path::new("/"), None, |p: &Path| p.exists());
        #[cfg(target_os = "linux")]
        {
            let abi = fluxvm_procbox::landlock::kernel_abi();
            match fluxvm_procbox::landlock::plan(&probe_policy, abi) {
                Ok(plan) => {
                    if !cfg.best_effort && !plan.enforcement.not_enforced.is_empty() {
                        return Err(ProcboxError::Unavailable(
                            plan.enforcement.not_enforced.join("; "),
                        )
                        .into());
                    }
                }
                Err(e) if !cfg.best_effort => {
                    return Err(ProcboxError::Unavailable(format!("{e:#}")).into());
                }
                Err(_) => {}
            }
            if !cfg.best_effort && !fluxvm_procbox::seccomp::available() {
                return Err(ProcboxError::Unavailable("seccomp is not available".into()).into());
            }
            if isolation == fluxvm_procbox::Isolation::Strict {
                let ids = is_root().then_some((cfg.uid_base.max(1), cfg.uid_base.max(1)));
                if let Err(why) = fluxvm_procbox::isolate::userns_status(ids) {
                    return Err(ProcboxError::Unavailable(format!(
                        "isolation = strict but namespaces are unavailable: {why}"
                    ))
                    .into());
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = probe_policy;
            return Err(unsupported("procbox sandboxes (Linux only)"));
        }

        let mut create = minimal_request(req.name.clone(), &spec);
        if let Some(t) = token_tenant {
            create.tenant = Some(t.to_string());
        }
        create.created_by_token = created_by_token.map(String::from);
        create.ttl_seconds = req.ttl_seconds;
        if create.name.is_empty() {
            create.name = format!("sandbox-{}", Uuid::new_v4());
        }
        self.enforce_token_quotas(created_by_token, &create).await?;

        let id = Uuid::new_v4();
        let workspace = self.cfg.state_dir.join("instances").join(id.to_string());
        let files = workspace.join(FILES_DIR);
        let staged = (|| -> Result<()> {
            use std::os::unix::fs::PermissionsExt;
            let _claim = UID_ALLOC.lock().unwrap_or_else(|e| e.into_inner());
            spec.uid = allocate_uid(
                cfg,
                &workspace
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_default(),
            )?;
            std::fs::create_dir_all(&files)?;
            std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700))?;
            std::fs::set_permissions(&files, std::fs::Permissions::from_mode(0o700))?;
            if let Some(uid) = spec.uid {
                prepare_traversal(&workspace, uid)?;
                let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(
                    files.as_os_str(),
                ))?;
                // SAFETY: valid NUL-terminated path.
                if unsafe { libc::chown(c.as_ptr(), uid, uid) } != 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("giving the sandbox uid its workspace");
                }
            }
            std::fs::write(
                workspace.join(MARKER_FILE),
                serde_json::to_vec_pretty(&spec)?,
            )?;
            Ok(())
        })();
        if let Err(e) = staged {
            let _ = std::fs::remove_dir_all(&workspace);
            return Err(e.context("creating procbox workspace"));
        }

        let expires_at = create
            .ttl_seconds
            .map(|s| chrono::Utc::now() + chrono::Duration::seconds(s as i64));
        let record = make_record(id, &workspace, create, expires_at);
        if let Err(e) = self.store.insert(record.clone()).await {
            let _ = std::fs::remove_dir_all(&workspace);
            return Err(e);
        }
        let vm_id = id.to_string();
        let tenant = record.request.tenant.clone().unwrap_or_default();
        crate::audit_event(
            "vm.create",
            &[
                ("vm_id", &vm_id),
                ("tenant", &tenant),
                ("backend", "procbox"),
            ],
        );
        Ok(record)
    }

    /// Run `command` confined to the sandbox workspace.
    pub(crate) async fn procbox_exec(
        &self,
        vm: &VmRecord,
        spec: ProcboxSpec,
        command: String,
        timeout: Option<u64>,
    ) -> Result<AgentResponse> {
        let cfg = self.cfg.sandbox.procbox.clone();
        if !cfg.enabled {
            return Err(ProcboxError::Disabled.into());
        }
        let root = files_root(vm);
        let out = tokio::task::spawn_blocking(move || {
            run_confined(&cfg, &spec, &root, &command, timeout)
        })
        .await
        .context("procbox worker panicked")??;
        Ok(AgentResponse::Exec {
            exit_code: out.exit_code,
            stdout: out.stdout,
            stderr: out.stderr,
            enforcement: None,
        })
    }

    pub(crate) async fn procbox_get_file(
        &self,
        vm: &VmRecord,
        path: String,
    ) -> Result<AgentResponse> {
        let root_path = files_root(vm);
        tokio::task::spawn_blocking(move || -> Result<AgentResponse> {
            let rel = sanitize_rel(&root_path, &path)?;
            let root = Root::open(&root_path)?;
            let (data, mode) = root.read_file(&rel, MAX_FILE_TRANSFER_BYTES)?;
            Ok(AgentResponse::FileContent {
                content_base64: base64::engine::general_purpose::STANDARD.encode(data),
                mode,
            })
        })
        .await
        .context("procbox worker panicked")?
    }

    pub(crate) async fn procbox_put_file(
        &self,
        vm: &VmRecord,
        path: String,
        content_base64: String,
        mode: Option<u32>,
    ) -> Result<AgentResponse> {
        let root_path = files_root(vm);
        let cap_bytes = self.cfg.sandbox.procbox.max_workspace_mib << 20;
        let owner = load_spec(vm)?.and_then(|s| s.uid).map(|u| (u, u));
        tokio::task::spawn_blocking(move || -> Result<AgentResponse> {
            let rel = sanitize_rel(&root_path, &path)?;
            let data = base64::engine::general_purpose::STANDARD
                .decode(content_base64.as_bytes())
                .context("content_base64 is not valid base64")?;
            if data.len() > MAX_FILE_TRANSFER_BYTES {
                return Err(ProcboxError::TooLarge(format!(
                    "file is {} bytes; the limit is {MAX_FILE_TRANSFER_BYTES}",
                    data.len()
                ))
                .into());
            }
            let root = Root::open(&root_path)?.with_owner(owner);
            if root.total_size()? + data.len() as u64 > cap_bytes {
                return Err(ProcboxError::TooLarge(format!(
                    "writing this file would exceed the {} MiB workspace cap",
                    cap_bytes >> 20
                ))
                .into());
            }
            root.write_file(&rel, &data, mode.unwrap_or(0o644))?;
            Ok(AgentResponse::FileWritten)
        })
        .await
        .context("procbox worker panicked")?
    }

    /// Run `command` against a throwaway copy of the workspace and report what
    /// it changed. The real workspace is only ever read.
    pub async fn sandbox_dry_run(
        self: &std::sync::Arc<Self>,
        id: Uuid,
        command: String,
        timeout: Option<u64>,
        paths: Option<Vec<String>>,
    ) -> Result<DryRunReport> {
        let vm = self.get(id).await?;
        let Some(spec) = load_spec(&vm)? else {
            // Not a procbox sandbox: a VM sandbox reverts through a snapshot.
            return self.vm_sandbox_dry_run(id, command, timeout, paths).await;
        };
        let cfg = self.cfg.sandbox.procbox.clone();
        if !cfg.enabled {
            return Err(ProcboxError::Disabled.into());
        }
        let paths = match paths {
            Some(p) => validate_paths(&p)?,
            None => vec!["/".to_string()],
        };
        let workspace = vm.workspace.clone();
        let root_path = files_root(&vm);
        self.touch_activity(id).await;
        tokio::task::spawn_blocking(move || -> Result<DryRunReport> {
            let root = Root::open(&root_path)?;
            let cap = cfg.max_workspace_mib << 20;
            let size = root.total_size()?;
            if size > cap {
                return Err(ProcboxError::TooLarge(format!(
                    "workspace is {} MiB; a dry-run copies it and the cap is {} MiB",
                    size >> 20,
                    cfg.max_workspace_mib
                ))
                .into());
            }
            let copy = workspace.join(format!("dryrun-{}", Uuid::new_v4()));
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new().mode(0o700).create(&copy)?;
            }
            let guard = TempTree(copy.clone());
            let root = root.with_owner(spec.uid.map(|u| (u, u)));
            root.chown_path(&copy)?;
            root.copy_to(&copy)?;
            let copy_root = Root::open(&copy)?;
            let before = copy_root.manifest()?.restrict_to(&paths);
            let out = run_confined(&cfg, &spec, &copy, &command, timeout)?;
            let after = Root::open(&copy)?.manifest()?.restrict_to(&paths);
            let changes = diff_manifests(&before, &after)?;
            drop(guard);
            Ok(DryRunReport {
                changes,
                exit_code: out.exit_code,
                stdout: out.stdout,
                stderr: out.stderr,
                discarded: true,
                reverted_via: "workspace-copy",
                paths,
            })
        })
        .await
        .context("procbox worker panicked")?
    }
}

fn make_record(
    id: Uuid,
    workspace: &Path,
    create: CreateVmRequest,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> VmRecord {
    VmRecord {
        id,
        name: create.name.clone(),
        // Nominal: nothing launches a VMM for it, and every backend
        // entry point checks `is_procbox` first.
        backend: BackendKind::FluxVm,
        status: VmStatus::Running,
        pid: None,
        created_at: chrono::Utc::now(),
        expires_at,
        workspace: workspace.to_path_buf(),
        disk: workspace.join("none"),
        seed_disk: None,
        tap_name: None,
        control_socket: None,
        log_path: workspace.join("console.log"),
        error: None,
        request: create,
        guest_cid: None,
        jail_path: None,
        vsock_socket: None,
        qga_socket: None,
        cgroup_path: None,
        netns: None,
        lvm_lv: None,
        nbd_pid: None,
        virtiofsd_pids: Vec::new(),
        swtpm_pid: None,
        dhcp_leasefile: None,
        guest_ip: None,
        requested_security_profile: Default::default(),
        achieved_security_profile: Default::default(),
        security_evidence: None,
        labels: Default::default(),
    }
}

/// A `CreateVmRequest` for the record: accounting fields only, since no VM is
/// ever launched from it.
fn minimal_request(name: Option<String>, spec: &ProcboxSpec) -> CreateVmRequest {
    CreateVmRequest {
        name: name.unwrap_or_default(),
        tenant: None,
        created_by_token: None,
        backend: BackendKind::FluxVm,
        image: PathBuf::from("procbox"),
        vcpus: 1,
        // Counted against `max_memory_mib_per_token` like a VM of that size.
        memory_mib: spec.max_memory_mib,
        max_vcpus: None,
        max_memory_mib: None,
        loadvm_tag: None,
        disk_size_gib: None,
        kernel: None,
        initrd: None,
        firmware: None,
        kernel_args: None,
        network: NetworkSpec::None,
        cloud_init: None,
        ttl_seconds: None,
        extra_args: Vec::new(),
        shared_memory: false,
        agent: None,
        qga: None,
        hyperv: false,
        storage: Default::default(),
        shared_folders: Vec::new(),
        data_disks: vec![],
        cdroms: vec![],
        numa_node: None,
        cpuset: None,
        hugepages: None,
        vfio_devices: Vec::new(),
        pod_uid: None,
        secure_boot: None,
        tpm: None,
        security_profile: Default::default(),
        measurement_policy: None,
        net_mbit_limit: None,
        net_pps_limit: None,
        blk_mbit_limit: None,
        blk_ops_limit: None,
        cpu_template: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ProcboxConfig {
        ProcboxConfig {
            enabled: true,
            allow_root: true,
            isolation: "off".to_string(),
            ..ProcboxConfig::default()
        }
    }

    #[test]
    fn limits_default_and_reject_over_cap() {
        let s = resolve_limits(&cfg(), &ProcboxRequest::default()).unwrap();
        assert_eq!(s.max_memory_mib, 512);
        assert_eq!(s.timeout_seconds, 30);
        assert!(s.net_ports.is_empty());
        let over = ProcboxRequest {
            max_memory_mib: Some(1 << 20),
            ..Default::default()
        };
        assert!(resolve_limits(&cfg(), &over).is_err());
        let slow = ProcboxRequest {
            timeout_seconds: Some(10_000),
            ..Default::default()
        };
        assert!(resolve_limits(&cfg(), &slow).is_err());
        let zero = ProcboxRequest {
            timeout_seconds: Some(0),
            ..Default::default()
        };
        assert!(resolve_limits(&cfg(), &zero).is_err());
    }

    #[test]
    fn network_is_off_unless_the_server_allows_it() {
        let req = ProcboxRequest {
            net_ports: vec![443, 443, 80],
            ..Default::default()
        };
        assert!(resolve_limits(&cfg(), &req).is_err());
        let mut c = cfg();
        c.allow_net = true;
        let s = resolve_limits(&c, &req).unwrap();
        assert_eq!(s.net_ports, vec![80, 443]);
        let zero = ProcboxRequest {
            net_ports: vec![0],
            ..Default::default()
        };
        assert!(resolve_limits(&c, &zero).is_err());
    }

    #[test]
    fn sanitize_accepts_relative_and_in_root_absolute_paths() {
        let root = Path::new("/var/lib/fluxvm/instances/x/files");
        assert_eq!(
            sanitize_rel(root, "a/b.txt").unwrap(),
            PathBuf::from("a/b.txt")
        );
        assert_eq!(sanitize_rel(root, "./a//b").unwrap(), PathBuf::from("a/b"));
        assert_eq!(
            sanitize_rel(root, "/var/lib/fluxvm/instances/x/files/a").unwrap(),
            PathBuf::from("a")
        );
    }

    #[test]
    fn sanitize_rejects_escapes() {
        let root = Path::new("/var/lib/fluxvm/instances/x/files");
        for bad in [
            "",
            "..",
            "../x",
            "a/../../x",
            "a/..",
            "/etc/passwd",
            "/var/lib/fluxvm/instances/x/files/../../y/files/a",
            "/var/lib/fluxvm/instances/x/filesX/a",
            "/",
            "a\0b",
            ".",
            "./",
        ] {
            assert!(sanitize_rel(root, bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn policy_grants_only_the_workdir_for_writing_and_no_wholesale_etc() {
        let spec = resolve_limits(&cfg(), &ProcboxRequest::default()).unwrap();
        let work = Path::new("/w/files");
        let p = build_policy(&cfg(), &spec, work, None, |_| true);
        assert_eq!(
            p.write,
            vec![PathBuf::from("/w/files"), PathBuf::from("/dev/null")]
        );
        assert!(!p.read.contains(&PathBuf::from("/etc")));
        assert!(!p.read.iter().any(|r| r.starts_with("/etc/shadow")));
        assert!(p.read.contains(&PathBuf::from("/usr")));
        assert_eq!(p.tcp_connect, fluxvm_procbox::TcpRule::Deny);
        assert_eq!(p.tcp_bind, fluxvm_procbox::TcpRule::Deny);
        assert!(p.clean_env && !p.best_effort);
        assert_eq!(p.cwd.as_deref(), Some(work));
        assert_eq!(p.max_memory, Some(512 << 20));
    }

    #[test]
    fn uid_pool_hands_out_the_lowest_free_uid_and_reports_exhaustion() {
        let mut c = cfg();
        c.uid_base = 5000;
        c.uid_count = 3;
        let mut used = std::collections::HashSet::new();
        assert_eq!(pick_uid(&c, &used).unwrap(), 5000);
        used.insert(5000);
        used.insert(5002);
        assert_eq!(pick_uid(&c, &used).unwrap(), 5001);
        used.insert(5001);
        let e = pick_uid(&c, &used).unwrap_err();
        assert!(matches!(
            e.downcast_ref::<ProcboxError>(),
            Some(ProcboxError::Unavailable(_))
        ));
        c.uid_base = 0;
        assert!(pick_uid(&c, &Default::default()).is_err());
        c.uid_base = u32::MAX - 1;
        c.uid_count = 10;
        assert!(pick_uid(&c, &Default::default()).is_err());
    }

    #[test]
    fn markers_written_before_the_uid_pool_still_parse() {
        let old = r#"{"net_ports":[],"max_memory_mib":512,"max_processes":4096,"timeout_seconds":30,"cpu_seconds":null}"#;
        let s: ProcboxSpec = serde_json::from_str(old).unwrap();
        assert_eq!(s.uid, None);
        let with = serde_json::to_string(&ProcboxSpec {
            uid: Some(200_001),
            ..s
        })
        .unwrap();
        assert_eq!(
            serde_json::from_str::<ProcboxSpec>(&with).unwrap().uid,
            Some(200_001)
        );
    }

    #[test]
    fn policy_carries_the_sandbox_uid_and_the_isolation_mode() {
        let mut spec = resolve_limits(&cfg(), &ProcboxRequest::default()).unwrap();
        spec.uid = Some(200_007);
        let mut c = cfg();
        c.isolation = "strict".to_string();
        let p = build_policy(&c, &spec, Path::new("/w"), None, |_| true);
        assert_eq!(
            p.run_as,
            Some(fluxvm_procbox::RunAs {
                uid: 200_007,
                gid: 200_007
            })
        );
        assert_eq!(p.isolation, fluxvm_procbox::Isolation::Strict);
        assert!(!p.allow_unix && !p.allow_udp);
        c.isolation = "bogus".to_string();
        assert!(isolation_mode(&c).is_err());
        let none = build_policy(
            &cfg(),
            &resolve_limits(&cfg(), &Default::default()).unwrap(),
            Path::new("/w"),
            None,
            |_| true,
        );
        assert!(none.run_as.is_none());
    }

    #[test]
    fn a_root_daemon_refuses_a_sandbox_without_a_uid_unless_allowed() {
        if !is_root() {
            eprintln!("skip: needs a root caller");
            return;
        }
        let mut c = cfg();
        c.allow_root = false;
        let spec = resolve_limits(&c, &ProcboxRequest::default()).unwrap();
        let e = run_confined(&c, &spec, Path::new("/tmp"), "true", Some(5))
            .err()
            .expect("must refuse");
        assert!(matches!(
            e.downcast_ref::<ProcboxError>(),
            Some(ProcboxError::Unavailable(_))
        ));
        let mut none = c.clone();
        none.uid_count = 0;
        let e = allocate_uid(&none, Path::new("/nonexistent")).unwrap_err();
        assert!(matches!(
            e.downcast_ref::<ProcboxError>(),
            Some(ProcboxError::Unavailable(_))
        ));
        none.allow_root = true;
        assert_eq!(
            allocate_uid(&none, Path::new("/nonexistent")).unwrap(),
            None
        );
    }

    #[test]
    fn policy_timeout_is_capped_by_the_server() {
        let spec = resolve_limits(&cfg(), &ProcboxRequest::default()).unwrap();
        let p = build_policy(&cfg(), &spec, Path::new("/w"), Some(99_999), |_| true);
        assert_eq!(p.timeout_secs, Some(300));
        let d = build_policy(&cfg(), &spec, Path::new("/w"), None, |_| true);
        assert_eq!(d.timeout_secs, Some(30));
        let z = build_policy(&cfg(), &spec, Path::new("/w"), Some(0), |_| true);
        assert_eq!(z.timeout_secs, Some(30));
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::os::unix::fs::symlink;

        fn root_dir() -> (tempfile::TempDir, Root) {
            let d = tempfile::tempdir().unwrap();
            let files = d.path().join("files");
            std::fs::create_dir(&files).unwrap();
            let r = Root::open(&files).unwrap();
            (d, r)
        }

        #[test]
        fn write_then_read_round_trips_and_creates_parents() {
            let (_d, r) = root_dir();
            r.write_file(Path::new("a/b/c.txt"), b"hello", 0o640)
                .unwrap();
            let (data, mode) = r.read_file(Path::new("a/b/c.txt"), 1024).unwrap();
            assert_eq!(data, b"hello");
            assert_eq!(mode, 0o640);
            // Overwrite truncates.
            r.write_file(Path::new("a/b/c.txt"), b"x", 0o644).unwrap();
            assert_eq!(r.read_file(Path::new("a/b/c.txt"), 1024).unwrap().0, b"x");
        }

        #[test]
        fn read_refuses_files_over_the_limit() {
            let (_d, r) = root_dir();
            r.write_file(Path::new("big"), &[7u8; 100], 0o644).unwrap();
            let err = r.read_file(Path::new("big"), 10).unwrap_err();
            assert!(matches!(
                err.downcast_ref::<ProcboxError>(),
                Some(ProcboxError::TooLarge(_))
            ));
        }

        #[test]
        fn a_symlink_to_outside_is_refused_for_read_and_write() {
            let (d, r) = root_dir();
            let outside = d.path().join("secret");
            std::fs::write(&outside, b"top secret").unwrap();
            symlink(&outside, r.path().join("leak")).unwrap();
            let err = r.read_file(Path::new("leak"), 1024).unwrap_err();
            assert!(
                matches!(
                    err.downcast_ref::<ProcboxError>(),
                    Some(ProcboxError::PathEscape(_))
                ),
                "{err:#}"
            );
            let err = r
                .write_file(Path::new("leak"), b"clobber", 0o644)
                .unwrap_err();
            assert!(matches!(
                err.downcast_ref::<ProcboxError>(),
                Some(ProcboxError::PathEscape(_))
            ));
            assert_eq!(std::fs::read(&outside).unwrap(), b"top secret");
        }

        #[test]
        fn a_directory_symlink_to_outside_is_not_traversed() {
            let (d, r) = root_dir();
            let outside = d.path().join("outdir");
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("f"), b"outside").unwrap();
            symlink(&outside, r.path().join("dirlink")).unwrap();
            assert!(r.read_file(Path::new("dirlink/f"), 1024).is_err());
            assert!(r.write_file(Path::new("dirlink/new"), b"x", 0o644).is_err());
            assert!(!outside.join("new").exists());
        }

        #[test]
        fn an_in_root_symlink_is_refused_too() {
            let (_d, r) = root_dir();
            r.write_file(Path::new("real"), b"1", 0o644).unwrap();
            symlink("real", r.path().join("alias")).unwrap();
            assert!(r.read_file(Path::new("alias"), 1024).is_err());
        }

        #[test]
        fn symlink_swapped_in_after_the_check_is_still_blocked() {
            // The lexical check passes, then a parent directory is replaced by
            // a symlink before the open: openat2 must still refuse.
            let (d, r) = root_dir();
            r.write_file(Path::new("sub/f"), b"inside", 0o644).unwrap();
            let rel = sanitize_rel(r.path(), "sub/f").unwrap();
            let outside = d.path().join("outdir");
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("f"), b"outside").unwrap();
            std::fs::remove_dir_all(r.path().join("sub")).unwrap();
            symlink(&outside, r.path().join("sub")).unwrap();
            assert!(r.read_file(&rel, 1024).is_err());
        }

        #[test]
        fn manifest_lists_regular_files_and_ignores_symlinks() {
            let (d, r) = root_dir();
            r.write_file(Path::new("a"), b"1", 0o644).unwrap();
            r.write_file(Path::new("d/b"), b"2", 0o644).unwrap();
            symlink(d.path(), r.path().join("evil")).unwrap();
            let m = r.manifest().unwrap();
            let keys: Vec<_> = m.files.keys().cloned().collect();
            assert_eq!(keys, vec!["/a", "/d/b"]);
        }

        #[test]
        fn copy_preserves_content_modes_and_symlinks_without_following() {
            let (d, r) = root_dir();
            r.write_file(Path::new("x/y"), b"data", 0o600).unwrap();
            symlink("/etc/passwd", r.path().join("link")).unwrap();
            let dest = d.path().join("copy");
            std::fs::create_dir(&dest).unwrap();
            r.copy_to(&dest).unwrap();
            assert_eq!(std::fs::read(dest.join("x/y")).unwrap(), b"data");
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dest.join("x/y"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::read_link(dest.join("link")).unwrap(),
                PathBuf::from("/etc/passwd")
            );
        }

        #[test]
        fn a_confined_command_writes_inside_but_not_outside_the_workspace() {
            if !super::super::confinement_available() {
                eprintln!("skip: Landlock/seccomp not fully available on this host");
                return;
            }
            let (d, r) = root_dir();
            let outside = d.path().join("outside.txt");
            let spec = resolve_limits(&cfg(), &ProcboxRequest::default()).unwrap();
            let cmd = format!(
                "echo ok > inside.txt; (echo bad > {} ) 2>/dev/null && echo ESCAPED || echo BLOCKED",
                outside.display()
            );
            let out = run_confined(&cfg(), &spec, r.path(), &cmd, Some(20)).unwrap();
            assert!(out.stdout.contains("BLOCKED"), "stdout: {}", out.stdout);
            assert!(!outside.exists());
            assert_eq!(
                std::fs::read_to_string(r.path().join("inside.txt")).unwrap(),
                "ok\n"
            );
        }

        #[test]
        fn dry_run_semantics_leave_the_original_byte_identical() {
            if !super::super::confinement_available() {
                eprintln!("skip: Landlock/seccomp not fully available on this host");
                return;
            }
            let (d, r) = root_dir();
            r.write_file(Path::new("keep.txt"), b"keep", 0o644).unwrap();
            r.write_file(Path::new("edit.txt"), b"v1", 0o644).unwrap();
            r.write_file(Path::new("gone.txt"), b"bye", 0o644).unwrap();
            let before = r.manifest().unwrap();

            let copy = d.path().join("copy");
            std::fs::create_dir(&copy).unwrap();
            r.copy_to(&copy).unwrap();
            let copy_root = Root::open(&copy).unwrap();
            let base = copy_root.manifest().unwrap();
            let spec = resolve_limits(&cfg(), &ProcboxRequest::default()).unwrap();
            let out = run_confined(
                &cfg(),
                &spec,
                &copy,
                "echo v2 > edit.txt; rm gone.txt; echo new > new.txt",
                Some(20),
            )
            .unwrap();
            assert_eq!(out.exit_code, 0, "{}", out.stderr);
            let after = Root::open(&copy).unwrap().manifest().unwrap();
            let cs = diff_manifests(&base, &after).unwrap();
            assert_eq!(cs.added, vec!["/new.txt"]);
            assert_eq!(cs.modified, vec!["/edit.txt"]);
            assert_eq!(cs.deleted, vec!["/gone.txt"]);
            assert_eq!(r.manifest().unwrap(), before, "original must be untouched");
        }

        fn manager(enabled: bool) -> (tempfile::TempDir, std::sync::Arc<crate::VmManager>) {
            let d = tempfile::tempdir().unwrap();
            let mut c = fluxvm_core::config::Config::default();
            c.state_dir = d.path().join("state");
            c.run_dir = d.path().join("run");
            c.sandbox.procbox.enabled = enabled;
            (d, crate::VmManager::new(c).unwrap())
        }

        fn create_req() -> crate::SandboxCreateRequest {
            serde_json::from_value(serde_json::json!({"procbox": {}, "name": "pb"})).unwrap()
        }

        fn code<T>(r: Result<T>) -> String {
            match r {
                Ok(_) => panic!("expected an error"),
                Err(e) => format!("{e:#}"),
            }
        }

        #[tokio::test]
        async fn disabled_by_default_and_fails_closed() {
            let (_d, m) = manager(false);
            let err = m
                .create_sandbox(create_req(), None, None)
                .await
                .unwrap_err();
            assert!(matches!(
                err.downcast_ref::<ProcboxError>(),
                Some(ProcboxError::Disabled)
            ));
        }

        #[tokio::test]
        async fn full_lifecycle_confinement_changes_dry_run_and_cleanup() {
            if !super::super::confinement_available() {
                eprintln!("skip: Landlock/seccomp not fully available on this host");
                return;
            }
            let (d, m) = manager(true);
            {
                // A root daemon drops commands to a sandbox uid, which must
                // be able to search down to the workspace.
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let rec = m
                .create_sandbox(create_req(), Some("acme"), Some("tok"))
                .await
                .unwrap();
            assert_eq!(rec.request.tenant.as_deref(), Some("acme"));
            assert_eq!(rec.status, VmStatus::Running);
            assert!(is_procbox(&rec));
            let id = rec.id;
            let ws = rec.workspace.clone();
            {
                use std::os::unix::fs::PermissionsExt;
                let expect = if is_root() { 0o711 } else { 0o700 };
                assert_eq!(
                    std::fs::metadata(&ws).unwrap().permissions().mode() & 0o777,
                    expect
                );
            }

            // Files: write, read back, refuse escapes.
            let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
            m.put_file(id, "src/hello.txt".into(), b64(b"hello"), None)
                .await
                .unwrap();
            match m.get_file(id, "src/hello.txt".into()).await.unwrap() {
                AgentResponse::FileContent { content_base64, .. } => {
                    assert_eq!(content_base64, b64(b"hello"))
                }
                other => panic!("unexpected {other:?}"),
            }
            for bad in ["../evil", "/etc/passwd", "src/../../evil"] {
                let e = m
                    .put_file(id, bad.into(), b64(b"x"), None)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(
                        e.downcast_ref::<ProcboxError>(),
                        Some(ProcboxError::PathEscape(_))
                    ),
                    "{bad}: {e:#}"
                );
                assert!(m.get_file(id, bad.into()).await.is_err());
            }

            // Exec: sees the workspace as cwd, cannot write elsewhere.
            let out = m
                .exec(id, "cat src/hello.txt; pwd".into(), Some(20))
                .await
                .unwrap();
            match out {
                AgentResponse::Exec {
                    exit_code, stdout, ..
                } => {
                    assert_eq!(exit_code, 0);
                    assert!(stdout.starts_with("hello"), "{stdout}");
                    assert!(stdout.trim_end().ends_with("/files"), "{stdout}");
                }
                other => panic!("unexpected {other:?}"),
            }
            let escape = format!(
                "echo bad > {}/escaped 2>/dev/null && echo ESCAPED || echo BLOCKED",
                ws.display()
            );
            match m.exec(id, escape, Some(20)).await.unwrap() {
                AgentResponse::Exec { stdout, .. } => {
                    assert!(stdout.contains("BLOCKED"), "{stdout}")
                }
                other => panic!("unexpected {other:?}"),
            }
            assert!(!ws.join("escaped").exists());
            // The marker is outside the writable root, so a command cannot tamper with it.
            match m
                .exec(
                    id,
                    format!(
                        "echo {{}} > {}/procbox.json 2>/dev/null && echo TAMPERED || echo SAFE",
                        ws.display()
                    ),
                    Some(20),
                )
                .await
                .unwrap()
            {
                AgentResponse::Exec { stdout, .. } => assert!(stdout.contains("SAFE"), "{stdout}"),
                other => panic!("unexpected {other:?}"),
            }
            // A timeout is reported as 124 like a VM sandbox.
            match m.exec(id, "sleep 30".into(), Some(1)).await.unwrap() {
                AgentResponse::Exec { exit_code, .. } => assert_eq!(exit_code, 124),
                other => panic!("unexpected {other:?}"),
            }

            // Baseline / changes against the host workspace.
            let bl = m.sandbox_baseline(id, vec!["/".into()]).await.unwrap();
            assert_eq!(bl.files, 1);
            m.exec(
                id,
                "echo new > added.txt; echo hello2 > src/hello.txt".into(),
                Some(20),
            )
            .await
            .unwrap();
            let ch = m.sandbox_changes(id, None).await.unwrap();
            assert_eq!(ch.changes.added, vec!["/added.txt"]);
            assert_eq!(ch.changes.modified, vec!["/src/hello.txt"]);
            assert!(ch.changes.deleted.is_empty());

            // Dry-run: reports changes, leaves the workspace untouched.
            let before = Root::open(&files_root(&rec)).unwrap().manifest().unwrap();
            let dr = m
                .sandbox_dry_run(
                    id,
                    "rm added.txt; echo z > zz.txt; echo mod > src/hello.txt".into(),
                    Some(20),
                    None,
                )
                .await
                .unwrap();
            assert!(dr.discarded);
            assert_eq!(dr.exit_code, 0, "{}", dr.stderr);
            assert_eq!(dr.changes.added, vec!["/zz.txt"]);
            assert_eq!(dr.changes.deleted, vec!["/added.txt"]);
            assert_eq!(dr.changes.modified, vec!["/src/hello.txt"]);
            let after = Root::open(&files_root(&rec)).unwrap().manifest().unwrap();
            assert_eq!(before, after, "dry-run must not touch the real workspace");
            let leftovers: Vec<_> = std::fs::read_dir(&ws)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("dryrun-"))
                .collect();
            assert!(leftovers.is_empty(), "dry-run copy must be removed");

            // Guest-only features are refused clearly.
            for e in [
                m.snapshot_sandbox(id, Path::new("/tmp/snap"))
                    .await
                    .unwrap_err(),
                m.pause(id).await.unwrap_err(),
                m.resume(id).await.unwrap_err(),
            ] {
                assert!(
                    matches!(
                        e.downcast_ref::<ProcboxError>(),
                        Some(ProcboxError::Unsupported(_))
                    ),
                    "{e:#}"
                );
            }
            assert!(code(m.open_console(id, 80, 24).await).contains("needs a guest"));

            // Delete removes the workspace and the record.
            m.delete(id).await.unwrap();
            assert!(!ws.exists());
            assert!(m.get(id).await.is_err());
        }

        #[tokio::test]
        async fn dry_run_on_a_vm_sandbox_is_not_implemented() {
            let (_d, m) = manager(true);
            let id = Uuid::new_v4();
            let ws = m.cfg.state_dir.join("instances").join(id.to_string());
            std::fs::create_dir_all(&ws).unwrap();
            let spec = resolve_limits(&cfg(), &ProcboxRequest::default()).unwrap();
            // No marker file: this record stands in for an ordinary VM sandbox.
            let vm = make_record(id, &ws, minimal_request(Some("vm".into()), &spec), None);
            m.store.insert(vm).await.unwrap();
            // A VM sandbox no longer answers 501 outright: it needs `paths` (the
            // guest root is too big to scan) and a reachable guest agent.
            let e = m
                .sandbox_dry_run(id, "true".into(), None, None)
                .await
                .unwrap_err();
            assert!(format!("{e:#}").contains("paths is required"), "{e:#}");
            let e = m
                .sandbox_dry_run(id, "true".into(), None, Some(vec!["/work".into()]))
                .await
                .unwrap_err();
            assert!(
                matches!(
                    e.downcast_ref::<crate::vm_restore::RestoreError>(),
                    Some(crate::vm_restore::RestoreError::Conflict(_))
                ),
                "{e:#}"
            );
            assert!(format!("{e:#}").contains("agent"), "{e:#}");
        }

        #[test]
        fn force_remove_clears_unreadable_directories() {
            use std::os::unix::fs::PermissionsExt;
            let d = tempfile::tempdir().unwrap();
            let t = d.path().join("t");
            std::fs::create_dir_all(t.join("locked")).unwrap();
            std::fs::write(t.join("locked/f"), b"x").unwrap();
            std::fs::set_permissions(t.join("locked"), std::fs::Permissions::from_mode(0o000))
                .unwrap();
            force_remove(&t);
            assert!(!t.exists());
        }
    }
}
