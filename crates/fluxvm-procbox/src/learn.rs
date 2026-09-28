// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `learn`: run a program for real, observe what it touches, and emit the
//! smallest sensible [`Profile`] that would allow exactly that.
//!
//! Observation is a ptrace syscall trace (see `docs/procbox.md` for why
//! ptrace and not seccomp user-notification). The pure half of this module,
//! [`generalize`] and [`render_toml`], has no OS dependencies and is unit
//! tested on its own.

use crate::policy::TcpRule;
use crate::profile::{NetRule, Profile};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// Everything the traced program did that a profile could care about. Paths
/// are canonical (symlinks resolved) where the path existed.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Observed {
    /// Regular files opened read-only.
    pub read_files: BTreeSet<PathBuf>,
    /// Directories opened for listing.
    pub read_dirs: BTreeSet<PathBuf>,
    /// Files executed (plus the interpreter and mapped libraries).
    pub exec: BTreeSet<PathBuf>,
    /// Existing files opened for writing or truncated.
    pub write_files: BTreeSet<PathBuf>,
    /// Files that did not exist and were created.
    pub create_files: BTreeSet<PathBuf>,
    /// Directories in which entries were created, removed or renamed.
    pub mutated_dirs: BTreeSet<PathBuf>,
    pub tcp_connect: BTreeSet<u16>,
    pub tcp_bind: BTreeSet<u16>,
    /// `ip:port` of every TCP connect (Landlock restricts ports, not hosts).
    pub tcp_endpoints: BTreeSet<String>,
    pub unix_sockets: BTreeSet<PathBuf>,
    /// UDP and other non-TCP endpoints (not restricted by Landlock).
    pub other_endpoints: BTreeSet<String>,
    pub notes: BTreeSet<String>,
    pub processes: usize,
    pub syscalls: u64,
}

/// A generated profile plus the reasoning behind it.
#[derive(Debug, Clone, Serialize)]
pub struct Generalized {
    pub profile: Profile,
    /// What was widened (many paths collapsed into one) and why.
    pub generalized: Vec<String>,
    /// What a human should look at before trusting the profile.
    pub review: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LearnOptions {
    pub cwd: Option<PathBuf>,
    pub env: Vec<(String, String)>,
    /// Kill the traced program after this many seconds.
    pub timeout_secs: Option<u64>,
    /// Send the program's stdout to our stderr so stdout stays clean for the
    /// generated profile.
    pub stdout_to_stderr: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LearnResult {
    pub observed: Observed,
    pub generalized: Generalized,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub wall_ms: u64,
}

impl LearnResult {
    /// The traced program exited 0 within the time limit.
    pub fn program_succeeded(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }
}

// ---------------------------------------------------------------- generalize

/// Directories that are collapsed into wholesale (libraries and binaries).
const SYSTEM_ROOTS: [&str; 7] = [
    "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin",
];

/// Directories never granted wholesale by collapsing siblings.
const NEVER_WHOLESALE: [&str; 20] = [
    "/", "/home", "/root", "/etc", "/var", "/tmp", "/proc", "/sys", "/dev", "/run", "/boot",
    "/opt", "/mnt", "/media", "/srv", "/usr", "/lib", "/lib64", "/bin", "/sbin",
];

/// Shared scratch directories: a write grant is allowed but flagged.
const SCRATCH_DIRS: [&str; 3] = ["/tmp", "/var/tmp", "/dev/shm"];

fn depth(p: &Path) -> usize {
    p.components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count()
}

/// A directory too broad to grant just because a program touched files in it.
fn too_broad(p: &Path) -> bool {
    if NEVER_WHOLESALE.iter().any(|d| p == Path::new(d)) {
        return true;
    }
    // A whole home directory (/home/<user>) is as broad as /home.
    p.starts_with("/home") && depth(p) <= 2
}

fn system_root_of(p: &Path) -> Option<&'static str> {
    SYSTEM_ROOTS.iter().copied().find(|r| p.starts_with(r))
}

/// `/proc/<pid>/...`, `/proc/self/...`: not expressible in a profile, because
/// Landlock rules are attached to inodes in the launcher, not the child.
fn is_proc_pid_path(p: &Path) -> bool {
    let mut it = p.components();
    if !matches!(it.next(), Some(Component::RootDir)) {
        return false;
    }
    if it.next().map(|c| c.as_os_str()) != Some(OsStr::new("proc")) {
        return false;
    }
    match it.next() {
        Some(Component::Normal(n)) => {
            let s = n.to_string_lossy();
            s == "self"
                || s == "thread-self"
                || (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        }
        _ => false,
    }
}

fn minimal(set: BTreeSet<PathBuf>) -> BTreeSet<PathBuf> {
    set.iter()
        .filter(|p| !set.iter().any(|a| a != *p && p.starts_with(a)))
        .cloned()
        .collect()
}

/// Turn observations into a minimal profile. Pure: does no filesystem access.
pub fn generalize(obs: &Observed) -> Generalized {
    let mut generalized = Vec::new();
    let mut review = Vec::new();
    let mut read: BTreeSet<PathBuf> = BTreeSet::new();
    let mut write: BTreeSet<PathBuf> = BTreeSet::new();

    // ---- reads and executables
    let mut collapsed: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut loose_files: BTreeSet<PathBuf> = BTreeSet::new();
    let mut proc_skipped: BTreeSet<PathBuf> = BTreeSet::new();
    for p in obs
        .read_files
        .iter()
        .chain(obs.read_dirs.iter())
        .chain(obs.exec.iter())
    {
        if is_proc_pid_path(p) {
            proc_skipped.insert(p.clone());
        } else if let Some(root) = system_root_of(p) {
            *collapsed.entry(root).or_default() += 1;
            read.insert(PathBuf::from(root));
        } else if obs.read_dirs.contains(p) {
            read.insert(p.clone());
        } else {
            loose_files.insert(p.clone());
        }
    }
    for (root, n) in &collapsed {
        generalized.push(format!(
            "{n} path(s) under {root} -> {root} (read-only, executable)"
        ));
    }
    let mut by_parent: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    for f in loose_files {
        let parent = f
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        by_parent.entry(parent).or_default().push(f);
    }
    for (parent, files) in by_parent {
        if files.len() >= 3 && !too_broad(&parent) {
            generalized.push(format!(
                "{} files in {} -> {} (read-only)",
                files.len(),
                parent.display(),
                parent.display()
            ));
            read.insert(parent);
        } else {
            read.extend(files);
        }
    }
    if !proc_skipped.is_empty() {
        review.push(format!(
            "{} per-process /proc path(s) (e.g. {}) are not granted: Landlock rules bind to \
             inodes when procbox applies them, so /proc/self would name procbox, not the \
             sandboxed child. Most programs tolerate this; check if yours does",
            proc_skipped.len(),
            proc_skipped.iter().next().unwrap().display()
        ));
    }

    // ---- writes
    for f in &obs.write_files {
        if is_proc_pid_path(f) {
            review.push(format!(
                "write to {} not granted (per-process /proc path)",
                f.display()
            ));
        } else {
            write.insert(f.clone());
        }
    }
    let grant_dir = |dir: &Path,
                     why: &str,
                     write: &mut BTreeSet<PathBuf>,
                     review: &mut Vec<String>| {
        let refused = too_broad(dir) && !SCRATCH_DIRS.iter().any(|d| dir == Path::new(d));
        if refused {
            review.push(format!(
                "NOT granted: the program {why} in {}, which is too broad to grant wholesale. \
                 Point it at a private directory (for example via TMPDIR or a --cwd) and learn again",
                dir.display()
            ));
        } else {
            if SCRATCH_DIRS.iter().any(|d| dir == Path::new(d)) {
                review.push(format!(
                    "write access to shared scratch directory {} is granted: any other process \
                     can see and race those files. Prefer a private directory",
                    dir.display()
                ));
            }
            write.insert(dir.to_path_buf());
        }
    };
    for f in &obs.create_files {
        // Landlock rules need an existing path, so a file that will not exist
        // yet is covered by write access to its directory.
        if let Some(dir) = f.parent() {
            grant_dir(
                dir,
                &format!("created {}", f.display()),
                &mut write,
                &mut review,
            );
        }
    }
    for d in &obs.mutated_dirs {
        grant_dir(
            d,
            "created, removed or renamed entries",
            &mut write,
            &mut review,
        );
    }
    if !obs.create_files.is_empty() || !obs.mutated_dirs.is_empty() {
        generalized.push(
            "files created or removed -> write access to their directory (a rule cannot name \
             a file that does not exist yet)"
                .into(),
        );
    }

    // ---- dedup: descendants of a grant add nothing
    let write = minimal(write);
    let read: BTreeSet<PathBuf> = minimal(read)
        .into_iter()
        .filter(|p| !write.iter().any(|w| p.starts_with(w)))
        .collect();

    // ---- network
    let net = |ports: &BTreeSet<u16>| {
        if ports.is_empty() {
            NetRule::Keyword("deny".into())
        } else {
            NetRule::Ports(ports.iter().copied().collect())
        }
    };
    if obs.tcp_connect.is_empty() {
        generalized.push("no TCP connect observed -> net_connect = \"deny\"".into());
    } else {
        review.push(
            "Landlock restricts TCP ports, not addresses: allowing these ports allows every host \
             on them. Observed: "
                .to_string()
                + &obs
                    .tcp_endpoints
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
        );
    }
    if obs.tcp_bind.is_empty() {
        generalized.push("no TCP bind observed -> net_bind = \"deny\"".into());
    }
    for s in &obs.unix_sockets {
        review.push(format!(
            "connected to unix socket {}: Landlock filesystem rules do not restrict AF_UNIX \
             connect before ABI 9, so this is neither granted nor blocked",
            s.display()
        ));
    }
    for e in &obs.other_endpoints {
        review.push(format!(
            "non-TCP endpoint {e}: Landlock network rules cover TCP only, so this stays unrestricted"
        ));
    }
    for n in &obs.notes {
        review.push(n.clone());
    }
    review.push(
        "environment variables, stdin and inherited file descriptors are not captured".into(),
    );
    review.push(
        "one run cannot prove completeness: code paths that did not execute are not in this profile"
            .into(),
    );

    let profile = Profile {
        fs_read: read.into_iter().collect(),
        fs_write: write.into_iter().collect(),
        net_connect: Some(net(&obs.tcp_connect)),
        net_bind: Some(net(&obs.tcp_bind)),
        ..Profile::default()
    };
    Generalized {
        profile,
        generalized,
        review,
    }
}

/// The generated profile as commented TOML, ready to save and review.
pub fn render_toml(res: &LearnResult) -> Result<String> {
    let mut out = String::new();
    out.push_str("# Generated by `fluxvm-procbox learn`. REVIEW BEFORE USE.\n");
    out.push_str(&format!(
        "# Observed {} process(es), {} decoded syscall(s) in {} ms.\n",
        res.observed.processes, res.observed.syscalls, res.wall_ms
    ));
    let how = if res.timed_out {
        "was killed by the time limit".to_string()
    } else if let Some(c) = res.exit_code {
        format!("exited with status {c}")
    } else if let Some(s) = res.signal {
        format!("was killed by signal {s}")
    } else {
        "ended".to_string()
    };
    out.push_str(&format!("# The traced program {how}.\n"));
    if !res.program_succeeded() {
        out.push_str(
            "# WARNING: it did not exit 0, so this profile may be missing accesses it would\n\
             # have made on a successful run.\n",
        );
    }
    if !res.generalized.generalized.is_empty() {
        out.push_str("#\n# Generalized:\n");
        for g in &res.generalized.generalized {
            out.push_str(&format!("#   - {g}\n"));
        }
    }
    if !res.generalized.review.is_empty() {
        out.push_str("#\n# Needs human review:\n");
        for r in &res.generalized.review {
            out.push_str(&format!("#   - {r}\n"));
        }
    }
    out.push('\n');
    out.push_str(&res.generalized.profile.to_toml_string()?);
    Ok(out)
}

// ------------------------------------------------------------ pure decoding

/// What an `open`-family call did, from its flags and whether the path
/// already existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenKind {
    /// `O_PATH`: no data access.
    Ignore,
    /// `O_TMPFILE`: an anonymous file created in the directory.
    TmpFile,
    Create,
    Write,
    Read,
}

const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const O_TRUNC: u64 = 0o1000;
const O_PATH: u64 = 0o10000000;
const O_TMPFILE: u64 = 0o20200000;

pub fn classify_open(flags: u64, existed: bool) -> OpenKind {
    if flags & O_PATH != 0 {
        return OpenKind::Ignore;
    }
    if flags & O_TMPFILE == O_TMPFILE {
        return OpenKind::TmpFile;
    }
    if flags & O_CREAT != 0 && !existed {
        return OpenKind::Create;
    }
    if flags & O_ACCMODE != 0 || flags & O_TRUNC != 0 {
        return OpenKind::Write;
    }
    OpenKind::Read
}

/// Decoded `struct sockaddr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SockAddr {
    V4(Ipv4Addr, u16),
    V6(Ipv6Addr, u16),
    Unix(PathBuf),
    UnixAbstract(String),
    Other(u16),
}

pub fn parse_sockaddr(b: &[u8]) -> Option<SockAddr> {
    if b.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([b[0], b[1]]);
    match family {
        1 => {
            let rest = &b[2..];
            if rest.first() == Some(&0) {
                let name: Vec<u8> = rest[1..].iter().copied().take_while(|c| *c != 0).collect();
                return Some(SockAddr::UnixAbstract(
                    String::from_utf8_lossy(&name).into_owned(),
                ));
            }
            let end = rest.iter().position(|c| *c == 0).unwrap_or(rest.len());
            if end == 0 {
                return None;
            }
            Some(SockAddr::Unix(PathBuf::from(OsStr::from_bytes(
                &rest[..end],
            ))))
        }
        2 if b.len() >= 8 => Some(SockAddr::V4(
            Ipv4Addr::new(b[4], b[5], b[6], b[7]),
            u16::from_be_bytes([b[2], b[3]]),
        )),
        10 if b.len() >= 24 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[8..24]);
            Some(SockAddr::V6(
                Ipv6Addr::from(a),
                u16::from_be_bytes([b[2], b[3]]),
            ))
        }
        0 => None,
        f => Some(SockAddr::Other(f)),
    }
}

/// Collapse `.`, `..` and repeated slashes without touching the filesystem.
pub fn normalize_lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::RootDir => out.push("/"),
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(n) => out.push(n),
        }
    }
    if out.as_os_str().is_empty() {
        out.push("/");
    }
    out
}

// -------------------------------------------------------------------- learn

/// Run `argv` under observation and return what it did plus a profile.
///
/// The program runs UNCONFINED with its real side effects: use a disposable
/// environment. Needs Linux >= 5.3 (`PTRACE_GET_SYSCALL_INFO`) and permission
/// to ptrace your own children (not blocked by seccomp or `ptrace_scope=3`).
#[cfg(target_os = "linux")]
pub fn learn(argv: &[String], opts: &LearnOptions) -> Result<LearnResult> {
    let start = std::time::Instant::now();
    let (observed, exit) = tracer::observe(argv, opts)?;
    let generalized = generalize(&observed);
    Ok(LearnResult {
        observed,
        generalized,
        exit_code: exit.exit_code,
        signal: exit.signal,
        timed_out: exit.timed_out,
        wall_ms: start.elapsed().as_millis() as u64,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn learn(_argv: &[String], _opts: &LearnOptions) -> Result<LearnResult> {
    anyhow::bail!("fluxvm-procbox learn only runs on Linux (ptrace)")
}

/// Render a [`TcpRule`] the way a profile spells it (used in summaries).
pub fn describe_rule(r: &TcpRule) -> String {
    match r {
        TcpRule::Any => "any".into(),
        TcpRule::Deny => "deny".into(),
        TcpRule::Ports(p) => format!("{p:?}"),
    }
}

#[cfg(target_os = "linux")]
struct Exit {
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
}

#[cfg(target_os = "linux")]
mod tracer {
    use super::*;
    use std::collections::HashMap;
    use std::io;
    use std::os::fd::AsFd;
    use std::os::raw::c_void;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    const AT_FDCWD: i64 = -100;
    const SOCK_STREAM: i32 = 1;
    const PTRACE_GET_SYSCALL_INFO: u32 = 0x420e;
    // pidfd_open / pidfd_getfd have the same numbers on x86_64 and aarch64.
    const SYS_PIDFD_OPEN: libc::c_long = 434;
    const SYS_PIDFD_GETFD: libc::c_long = 438;

    macro_rules! ptrace {
        ($req:expr, $pid:expr, $addr:expr, $data:expr) => {
            unsafe {
                libc::ptrace(
                    $req as _,
                    $pid as libc::pid_t,
                    $addr as usize as *mut c_void,
                    $data as usize as *mut c_void,
                )
            }
        };
    }

    enum Pending {
        Open {
            path: PathBuf,
            flags: u64,
            existed: bool,
        },
        Exec(PathBuf),
        Dirs(Vec<PathBuf>),
        Truncate(PathBuf),
    }

    struct Tracee {
        pending: Option<Pending>,
        /// Newly auto-attached children announce themselves with a SIGSTOP
        /// that must not be delivered.
        fresh: bool,
    }

    // ---- reading the tracee

    fn read_mem(pid: i32, addr: u64, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut c_void,
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: addr as usize as *mut c_void,
            iov_len: len,
        };
        let n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(buf)
    }

    fn read_cstr(pid: i32, addr: u64) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut a = addr;
        while out.len() < 4096 {
            let to_page = 4096 - (a % 4096) as usize;
            let chunk = read_mem(pid, a, to_page)?;
            if let Some(i) = chunk.iter().position(|b| *b == 0) {
                out.extend_from_slice(&chunk[..i]);
                return Some(out);
            }
            a += chunk.len() as u64;
            out.extend_from_slice(&chunk);
        }
        None
    }

    // ---- path handling

    fn fix_proc(pid: i32, p: PathBuf) -> PathBuf {
        let mut it = p.components();
        if let (Some(Component::RootDir), Some(Component::Normal(a)), Some(Component::Normal(b))) =
            (it.next(), it.next(), it.next())
        {
            if a == "proc" && (b == "self" || b == "thread-self") {
                let mut np = PathBuf::from(format!("/proc/{pid}"));
                np.extend(it);
                return np;
            }
        }
        p
    }

    fn resolve(pid: i32, dirfd: i64, raw: &[u8]) -> Option<PathBuf> {
        let base_of = |dirfd: i64| -> Option<PathBuf> {
            let link = if dirfd == AT_FDCWD {
                format!("/proc/{pid}/cwd")
            } else {
                format!("/proc/{pid}/fd/{dirfd}")
            };
            std::fs::read_link(link).ok()
        };
        if raw.is_empty() {
            // AT_EMPTY_PATH: the descriptor itself.
            return if dirfd == AT_FDCWD {
                None
            } else {
                base_of(dirfd)
            };
        }
        let p = Path::new(OsStr::from_bytes(raw));
        let abs = if p.is_absolute() {
            p.to_path_buf()
        } else {
            base_of(dirfd)?.join(p)
        };
        Some(fix_proc(pid, normalize_lexical(&abs)))
    }

    /// Resolve symlinks; a path that does not exist yet keeps its final
    /// component and canonicalizes the directory.
    fn canon(p: &Path) -> PathBuf {
        if p.starts_with("/proc") {
            return p.to_path_buf();
        }
        if let Ok(c) = std::fs::canonicalize(p) {
            return c;
        }
        if let (Some(parent), Some(name)) = (p.parent(), p.file_name()) {
            if let Ok(c) = std::fs::canonicalize(parent) {
                return c.join(name);
            }
        }
        p.to_path_buf()
    }

    fn canon_parent(p: &Path) -> PathBuf {
        canon(p.parent().unwrap_or(Path::new("/")))
    }

    fn path_arg(pid: i32, dirfd: i64, ptr: u64) -> Option<PathBuf> {
        let raw = read_cstr(pid, ptr)?;
        resolve(pid, dirfd, &raw)
    }

    fn maps_paths(pid: i32) -> Vec<PathBuf> {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
            return Vec::new();
        };
        let mut out = BTreeSet::new();
        for line in text.lines() {
            if let Some(idx) = line.find('/') {
                let path = &line[idx..];
                if !path.ends_with(" (deleted)") {
                    out.insert(PathBuf::from(path));
                }
            }
        }
        out.into_iter().collect()
    }

    // ---- sockets

    fn socket_type(pid: i32, fd: i32) -> Option<i32> {
        let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0) };
        if pidfd < 0 {
            return None;
        }
        let dup = unsafe { libc::syscall(SYS_PIDFD_GETFD, pidfd as i32, fd, 0) };
        unsafe { libc::close(pidfd as i32) };
        if dup < 0 {
            return None;
        }
        let mut ty: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                dup as i32,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                &mut ty as *mut _ as *mut c_void,
                &mut len,
            )
        };
        unsafe { libc::close(dup as i32) };
        (rc == 0).then_some(ty)
    }

    fn on_socket_call(pid: i32, args: &[u64; 6], connect: bool, obs: &mut Observed) {
        let len = (args[2] as usize).clamp(2, 128);
        let Some(bytes) = read_mem(pid, args[1], len) else {
            return;
        };
        let Some(addr) = parse_sockaddr(&bytes) else {
            return;
        };
        match addr {
            SockAddr::V4(..) | SockAddr::V6(..) => {
                let (ip, port) = match &addr {
                    SockAddr::V4(a, p) => (a.to_string(), *p),
                    SockAddr::V6(a, p) => (format!("[{a}]"), *p),
                    _ => unreachable!(),
                };
                let ty = socket_type(pid, args[0] as i32);
                if ty.is_none() {
                    obs.notes.insert(format!(
                        "could not determine the socket type for {ip}:{port}; assumed TCP"
                    ));
                }
                if ty.map_or(true, |t| t == SOCK_STREAM) {
                    if connect {
                        obs.tcp_connect.insert(port);
                        obs.tcp_endpoints.insert(format!("{ip}:{port}"));
                    } else {
                        obs.tcp_bind.insert(port);
                    }
                } else {
                    obs.other_endpoints.insert(format!(
                        "{} {ip}:{port}",
                        if connect { "connect" } else { "bind" }
                    ));
                }
            }
            SockAddr::Unix(p) => {
                let abs = if p.is_absolute() {
                    normalize_lexical(&p)
                } else {
                    match std::fs::read_link(format!("/proc/{pid}/cwd")) {
                        Ok(c) => normalize_lexical(&c.join(&p)),
                        Err(_) => return,
                    }
                };
                if connect {
                    obs.unix_sockets.insert(canon(&abs));
                } else {
                    obs.mutated_dirs.insert(canon_parent(&abs));
                }
            }
            SockAddr::UnixAbstract(n) => {
                obs.other_endpoints
                    .insert(format!("abstract unix socket @{n}"));
            }
            SockAddr::Other(_) => {}
        }
    }

    // ---- syscall decoding

    fn on_entry(pid: i32, nr: i64, a: &[u64; 6], obs: &mut Observed) -> Option<Pending> {
        let fd = |v: u64| v as i32 as i64;
        let open = |dirfd: i64, ptr: u64, flags: u64| -> Option<Pending> {
            let path = path_arg(pid, dirfd, ptr)?;
            let path = canon(&path);
            let existed = path.symlink_metadata().is_ok();
            Some(Pending::Open {
                path,
                flags,
                existed,
            })
        };
        let parent_of = |dirfd: i64, ptr: u64| -> Option<PathBuf> {
            let path = path_arg(pid, dirfd, ptr)?;
            Some(canon_parent(&path))
        };
        match nr {
            #[cfg(target_arch = "x86_64")]
            libc::SYS_open => open(AT_FDCWD, a[0], a[1]),
            #[cfg(target_arch = "x86_64")]
            libc::SYS_creat => open(AT_FDCWD, a[0], O_CREAT | O_TRUNC | 1),
            libc::SYS_openat => open(fd(a[0]), a[1], a[2]),
            libc::SYS_openat2 => {
                let how = read_mem(pid, a[2], 8)?;
                let flags = u64::from_ne_bytes(how[..8].try_into().ok()?);
                open(fd(a[0]), a[1], flags)
            }
            libc::SYS_execve => path_arg(pid, AT_FDCWD, a[0]).map(|p| Pending::Exec(canon(&p))),
            libc::SYS_execveat => path_arg(pid, fd(a[0]), a[1]).map(|p| Pending::Exec(canon(&p))),
            libc::SYS_truncate => {
                path_arg(pid, AT_FDCWD, a[0]).map(|p| Pending::Truncate(canon(&p)))
            }
            #[cfg(target_arch = "x86_64")]
            libc::SYS_mkdir | libc::SYS_rmdir | libc::SYS_unlink | libc::SYS_mknod => {
                parent_of(AT_FDCWD, a[0]).map(|d| Pending::Dirs(vec![d]))
            }
            libc::SYS_mkdirat | libc::SYS_unlinkat | libc::SYS_mknodat => {
                parent_of(fd(a[0]), a[1]).map(|d| Pending::Dirs(vec![d]))
            }
            #[cfg(target_arch = "x86_64")]
            libc::SYS_symlink => parent_of(AT_FDCWD, a[1]).map(|d| Pending::Dirs(vec![d])),
            libc::SYS_symlinkat => parent_of(fd(a[1]), a[2]).map(|d| Pending::Dirs(vec![d])),
            #[cfg(target_arch = "x86_64")]
            libc::SYS_link => parent_of(AT_FDCWD, a[1]).map(|d| Pending::Dirs(vec![d])),
            libc::SYS_linkat => parent_of(fd(a[2]), a[3]).map(|d| Pending::Dirs(vec![d])),
            #[cfg(target_arch = "x86_64")]
            libc::SYS_rename => {
                let mut v = Vec::new();
                v.extend(parent_of(AT_FDCWD, a[0]));
                v.extend(parent_of(AT_FDCWD, a[1]));
                Some(Pending::Dirs(v))
            }
            libc::SYS_renameat | libc::SYS_renameat2 => {
                let mut v = Vec::new();
                v.extend(parent_of(fd(a[0]), a[1]));
                v.extend(parent_of(fd(a[2]), a[3]));
                Some(Pending::Dirs(v))
            }
            libc::SYS_connect => {
                on_socket_call(pid, a, true, obs);
                None
            }
            libc::SYS_bind => {
                on_socket_call(pid, a, false, obs);
                None
            }
            _ => None,
        }
    }

    fn on_exit(pid: i32, pending: Pending, obs: &mut Observed) {
        match pending {
            Pending::Open {
                path,
                flags,
                existed,
            } => match classify_open(flags, existed) {
                OpenKind::Ignore => {}
                OpenKind::TmpFile => {
                    obs.mutated_dirs.insert(path);
                }
                OpenKind::Create => {
                    obs.create_files.insert(path);
                }
                OpenKind::Write => {
                    obs.write_files.insert(path);
                }
                OpenKind::Read => {
                    if path.is_dir() {
                        obs.read_dirs.insert(path);
                    } else {
                        obs.read_files.insert(path);
                    }
                }
            },
            Pending::Exec(path) => {
                obs.exec.insert(path);
                // The kernel opens the interpreter and the dynamic loader
                // itself, with no open syscall to observe: take them from the
                // new image's mappings.
                if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
                    obs.exec.insert(exe);
                }
                for m in maps_paths(pid) {
                    obs.exec.insert(canon(&m));
                }
            }
            Pending::Dirs(dirs) => obs.mutated_dirs.extend(dirs),
            Pending::Truncate(p) => {
                obs.write_files.insert(p);
            }
        }
    }

    /// `(nr, args)` for an entry stop, `(rval, is_error)` for an exit stop.
    enum SysInfo {
        Entry(i64, [u64; 6]),
        Exit(bool),
    }

    fn syscall_info(pid: i32) -> Option<SysInfo> {
        let mut buf = [0u8; 88];
        let n = ptrace!(PTRACE_GET_SYSCALL_INFO, pid, buf.len(), buf.as_mut_ptr());
        if n < 0 {
            return None;
        }
        let u64_at = |o: usize| u64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
        match buf[0] {
            1 => {
                let mut args = [0u64; 6];
                for (i, a) in args.iter_mut().enumerate() {
                    *a = u64_at(32 + i * 8);
                }
                Some(SysInfo::Entry(u64_at(24) as i64, args))
            }
            2 => Some(SysInfo::Exit(buf[32] != 0)),
            _ => None,
        }
    }

    // ---- the trace loop

    fn wait_all(status: &mut i32) -> i32 {
        loop {
            let pid = unsafe { libc::waitpid(-1, status, libc::__WALL) };
            if pid < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return pid;
        }
    }

    pub(super) fn observe(argv: &[String], o: &LearnOptions) -> Result<(Observed, Exit)> {
        anyhow::ensure!(!argv.is_empty(), "no command given");
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        if let Some(cwd) = &o.cwd {
            cmd.current_dir(cwd);
        }
        for (k, v) in &o.env {
            cmd.env(k, v);
        }
        if o.stdout_to_stderr {
            let dup = std::io::stderr()
                .as_fd()
                .try_clone_to_owned()
                .context("duplicating stderr")?;
            cmd.stdout(Stdio::from(dup));
        }
        cmd.process_group(0);
        let hook = || {
            if ptrace!(libc::PTRACE_TRACEME, 0, 0usize, 0usize) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        };
        // SAFETY: the hook only makes the ptrace syscall between fork and exec.
        unsafe {
            cmd.pre_exec(hook);
        }
        let child = cmd.spawn().with_context(|| {
            format!(
                "cannot start {:?} under ptrace (is ptrace blocked here, e.g. by a container \
                 seccomp profile or kernel.yama.ptrace_scope=3?)",
                argv[0]
            )
        })?;
        let root = child.id() as i32;
        drop(child);

        let mut status = 0;
        let r = unsafe { libc::waitpid(root, &mut status, libc::__WALL) };
        anyhow::ensure!(
            r == root && libc::WIFSTOPPED(status),
            "traced program did not stop at exec (status {status:#x})"
        );
        let opts = libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEEXEC
            | libc::PTRACE_O_EXITKILL;
        if ptrace!(libc::PTRACE_SETOPTIONS, root, 0usize, opts as usize) != 0 {
            anyhow::bail!("PTRACE_SETOPTIONS failed: {}", io::Error::last_os_error());
        }
        // Fail early, and clearly, on kernels without PTRACE_GET_SYSCALL_INFO.
        let mut probe = [0u8; 88];
        let n = ptrace!(
            PTRACE_GET_SYSCALL_INFO,
            root,
            probe.len(),
            probe.as_mut_ptr()
        );
        if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EIO) {
            unsafe { libc::kill(-root, libc::SIGKILL) };
            anyhow::bail!("learn needs Linux >= 5.3 (PTRACE_GET_SYSCALL_INFO)");
        }

        let done = Arc::new(AtomicBool::new(false));
        let timed_out = Arc::new(AtomicBool::new(false));
        if let Some(secs) = o.timeout_secs {
            let (done, timed_out) = (done.clone(), timed_out.clone());
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + Duration::from_secs(secs);
                while !done.load(Ordering::Relaxed) {
                    if std::time::Instant::now() >= deadline {
                        timed_out.store(true, Ordering::Relaxed);
                        unsafe { libc::kill(-root, libc::SIGKILL) };
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            });
        }

        let mut obs = Observed {
            processes: 1,
            ..Observed::default()
        };
        let mut tracees: HashMap<i32, Tracee> = HashMap::new();
        tracees.insert(
            root,
            Tracee {
                pending: None,
                fresh: false,
            },
        );
        let mut exit = Exit {
            exit_code: None,
            signal: None,
            timed_out: false,
        };
        ptrace!(libc::PTRACE_SYSCALL, root, 0usize, 0usize);

        loop {
            let mut st = 0;
            let pid = wait_all(&mut st);
            if pid < 0 {
                break; // ECHILD: nothing left to wait for
            }
            if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) {
                tracees.remove(&pid);
                if pid == root {
                    if libc::WIFEXITED(st) {
                        exit.exit_code = Some(libc::WEXITSTATUS(st));
                    } else {
                        exit.signal = Some(libc::WTERMSIG(st));
                    }
                }
                if tracees.is_empty() {
                    break;
                }
                continue;
            }
            if !libc::WIFSTOPPED(st) {
                continue;
            }
            let sig = libc::WSTOPSIG(st);
            let event = (st >> 16) & 0xff;
            let t = tracees.entry(pid).or_insert_with(|| {
                obs.processes += 1;
                Tracee {
                    pending: None,
                    fresh: true,
                }
            });
            let mut inject = 0usize;
            if sig == (libc::SIGTRAP | 0x80) {
                match syscall_info(pid) {
                    Some(SysInfo::Entry(nr, args)) => {
                        obs.syscalls += 1;
                        t.pending = on_entry(pid, nr, &args, &mut obs);
                    }
                    Some(SysInfo::Exit(is_error)) => {
                        if let Some(p) = t.pending.take() {
                            if !is_error {
                                on_exit(pid, p, &mut obs);
                            }
                        }
                    }
                    None => {}
                }
            } else if event != 0 || sig == libc::SIGTRAP {
                // fork/vfork/clone/exec events: children are auto-attached
                // and announce themselves through waitpid.
            } else if sig == libc::SIGSTOP && t.fresh {
                t.fresh = false;
            } else {
                inject = sig as usize;
            }
            if ptrace!(libc::PTRACE_SYSCALL, pid, 0usize, inject) != 0 {
                // ESRCH: the tracee vanished between wait and resume.
                tracees.remove(&pid);
                if tracees.is_empty() {
                    break;
                }
            }
        }
        done.store(true, Ordering::Relaxed);
        exit.timed_out = timed_out.load(Ordering::Relaxed);
        // Nothing the program left running should outlive the trace.
        unsafe { libc::kill(-root, libc::SIGKILL) };
        Ok((obs, exit))
    }
}

// ------------------------------------------------------------------ merging

/// Version of the `<profile>.observed.json` sidecar this build reads and writes.
pub const SIDECAR_VERSION: u32 = 1;
const MAX_SIDECAR_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RUNS: usize = 256;
const MAX_ENTRIES: usize = 200_000;
const MAX_TEXT: usize = 4096;
/// Label of the synthetic run that carries a hand-written prior profile.
pub const PRIOR_LABEL: &str = "prior";
/// Label of the synthetic run that carries hand edits found in a prior profile.
pub const PRIOR_EDITED_LABEL: &str = "prior-edited";

impl Observed {
    /// Union `other` into `self`: sets are unioned, counters add.
    pub fn merge(&mut self, other: &Observed) {
        self.read_files.extend(other.read_files.iter().cloned());
        self.read_dirs.extend(other.read_dirs.iter().cloned());
        self.exec.extend(other.exec.iter().cloned());
        self.write_files.extend(other.write_files.iter().cloned());
        self.create_files.extend(other.create_files.iter().cloned());
        self.mutated_dirs.extend(other.mutated_dirs.iter().cloned());
        self.tcp_connect.extend(other.tcp_connect.iter().copied());
        self.tcp_bind.extend(other.tcp_bind.iter().copied());
        self.tcp_endpoints
            .extend(other.tcp_endpoints.iter().cloned());
        self.unix_sockets.extend(other.unix_sockets.iter().cloned());
        self.other_endpoints
            .extend(other.other_endpoints.iter().cloned());
        self.notes.extend(other.notes.iter().cloned());
        self.processes = self.processes.saturating_add(other.processes);
        self.syscalls = self.syscalls.saturating_add(other.syscalls);
    }

    fn entry_count(&self) -> usize {
        self.read_files.len()
            + self.read_dirs.len()
            + self.exec.len()
            + self.write_files.len()
            + self.create_files.len()
            + self.mutated_dirs.len()
            + self.tcp_connect.len()
            + self.tcp_bind.len()
            + self.tcp_endpoints.len()
            + self.unix_sockets.len()
            + self.other_endpoints.len()
            + self.notes.len()
    }

    fn validate(&self, what: &str) -> Result<()> {
        anyhow::ensure!(
            self.entry_count() <= MAX_ENTRIES,
            "{what}: more than {MAX_ENTRIES} observations"
        );
        let paths = self
            .read_files
            .iter()
            .chain(&self.read_dirs)
            .chain(&self.exec)
            .chain(&self.write_files)
            .chain(&self.create_files)
            .chain(&self.mutated_dirs)
            .chain(&self.unix_sockets);
        for p in paths {
            let s = p.as_os_str().as_bytes();
            anyhow::ensure!(
                p.is_absolute() && s.len() <= MAX_TEXT && !s.contains(&0),
                "{what}: bad path {p:?} (must be absolute, under {MAX_TEXT} bytes, no NUL)"
            );
        }
        for t in self
            .tcp_endpoints
            .iter()
            .chain(&self.other_endpoints)
            .chain(&self.notes)
        {
            anyhow::ensure!(
                t.len() <= MAX_TEXT,
                "{what}: text entry over {MAX_TEXT} bytes"
            );
        }
        Ok(())
    }
}

/// One observed run: what a command touched, plus how it ended. The wall
/// time is deliberately not stored so re-learning the same run is a no-op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRecord {
    pub label: String,
    pub observed: Observed,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub signal: Option<i32>,
    #[serde(default)]
    pub timed_out: bool,
}

impl RunRecord {
    pub fn from_result(label: impl Into<String>, r: &LearnResult) -> RunRecord {
        RunRecord {
            label: label.into(),
            observed: r.observed.clone(),
            exit_code: r.exit_code,
            signal: r.signal,
            timed_out: r.timed_out,
        }
    }

    /// The command exited 0 within the time limit. Synthetic runs (`prior`,
    /// `prior-edited`) count as fine.
    pub fn succeeded(&self) -> bool {
        (self.exit_code == Some(0) && !self.timed_out)
            || (self.exit_code.is_none() && self.signal.is_none() && !self.timed_out)
    }

    fn how(&self) -> String {
        if self.timed_out {
            "killed by the time limit".into()
        } else if let Some(c) = self.exit_code {
            format!("exited with status {c}")
        } else if let Some(s) = self.signal {
            format!("killed by signal {s}")
        } else {
            "carried over from the prior profile".into()
        }
    }
}

/// What [`Sidecar::add_run`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunChange {
    Added,
    Replaced,
    Unchanged,
}

/// The raw observations behind a learned profile, saved next to it as
/// `<profile>.observed.json` so later runs can be merged losslessly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sidecar {
    pub version: u32,
    pub runs: Vec<RunRecord>,
}

impl Default for Sidecar {
    fn default() -> Self {
        Sidecar {
            version: SIDECAR_VERSION,
            runs: Vec::new(),
        }
    }
}

impl Sidecar {
    /// `<profile>.observed.json`: the profile's full file name plus the suffix.
    pub fn path_for(profile: &Path) -> PathBuf {
        let mut s = profile.as_os_str().to_owned();
        s.push(".observed.json");
        PathBuf::from(s)
    }

    /// Reject anything a well-formed file from this tool could not contain.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.version == SIDECAR_VERSION,
            "unsupported observation file version {} (this build reads version {SIDECAR_VERSION})",
            self.version
        );
        anyhow::ensure!(self.runs.len() <= MAX_RUNS, "more than {MAX_RUNS} runs");
        let mut seen = BTreeSet::new();
        let mut total = 0usize;
        for r in &self.runs {
            anyhow::ensure!(
                !r.label.is_empty() && r.label.len() <= MAX_TEXT,
                "a run label is empty or over {MAX_TEXT} bytes"
            );
            anyhow::ensure!(seen.insert(&r.label), "duplicate run label {:?}", r.label);
            r.observed.validate(&format!("run {:?}", r.label))?;
            total = total.saturating_add(r.observed.entry_count());
        }
        anyhow::ensure!(total <= MAX_ENTRIES * 4, "observation file is too large");
        Ok(())
    }

    pub fn from_json_str(s: &str) -> Result<Sidecar> {
        anyhow::ensure!(
            s.len() as u64 <= MAX_SIDECAR_BYTES,
            "observation file over {MAX_SIDECAR_BYTES} bytes"
        );
        let sc: Sidecar = serde_json::from_str(s)
            .map_err(|e| anyhow::anyhow!("invalid observation file: {e}"))?;
        sc.validate()?;
        Ok(sc)
    }

    pub fn load(path: &Path) -> Result<Sidecar> {
        let len = std::fs::metadata(path)
            .with_context(|| format!("reading {}", path.display()))?
            .len();
        anyhow::ensure!(
            len <= MAX_SIDECAR_BYTES,
            "{} is over {MAX_SIDECAR_BYTES} bytes",
            path.display()
        );
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Sidecar::from_json_str(&text).with_context(|| path.display().to_string())
    }

    /// Stable JSON: runs sorted by label, sets already sorted.
    pub fn to_json_string(&self) -> Result<String> {
        let mut sorted = self.clone();
        sorted.runs.sort_by(|a, b| a.label.cmp(&b.label));
        let mut text = serde_json::to_string_pretty(&sorted)?;
        text.push('\n');
        Ok(text)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        write_atomic(path, &self.to_json_string()?)
    }

    /// Add a run, replacing any earlier run with the same label. Re-adding an
    /// identical run changes nothing.
    pub fn add_run(&mut self, run: RunRecord) -> RunChange {
        let change = match self.runs.iter_mut().find(|r| r.label == run.label) {
            Some(existing) if *existing == run => RunChange::Unchanged,
            Some(existing) => {
                *existing = run;
                RunChange::Replaced
            }
            None => {
                self.runs.push(run);
                RunChange::Added
            }
        };
        self.runs.sort_by(|a, b| a.label.cmp(&b.label));
        change
    }

    /// Drop a run by label; false if there was none.
    pub fn forget(&mut self, label: &str) -> bool {
        let before = self.runs.len();
        self.runs.retain(|r| r.label != label);
        self.runs.len() != before
    }

    /// Everything every run observed, unioned.
    pub fn union(&self) -> Observed {
        let mut all = Observed::default();
        for r in &self.runs {
            all.merge(&r.observed);
        }
        all
    }
}

/// Write `text` to `path` through a temporary file in the same directory.
fn write_atomic(path: &Path, text: &str) -> Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", path.display()))?
        .to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.tmp{}", std::process::id()));
    std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("replacing {}: {e}", path.display())
    })
}

/// Write the profile text and its sidecar; the sidecar lands first so a
/// failure between the two never leaves a profile without its observations.
pub fn write_profile_and_sidecar(
    profile_path: &Path,
    profile_text: &str,
    sidecar: &Sidecar,
) -> Result<()> {
    sidecar.save(&Sidecar::path_for(profile_path))?;
    write_atomic(profile_path, profile_text)
}

/// The prior state a merge starts from.
pub enum Prior {
    /// A fresh learn: nothing to merge with.
    None,
    /// A learned profile with its sidecar.
    Full { profile: Profile, sidecar: Sidecar },
    /// A hand-written or sidecar-less profile: its grants become observations
    /// labelled `prior`.
    ProfileOnly { profile: Profile },
}

/// The outcome of [`plan_merge`].
#[derive(Debug, Clone)]
pub struct Merged {
    pub sidecar: Sidecar,
    /// The union of every run's observations.
    pub observed: Observed,
    /// The merged profile (learned keys regenerated, other keys kept from
    /// the prior profile) and the reasoning behind it.
    pub generalized: Generalized,
    /// What the merge itself did: runs added/replaced, keys kept, hand edits.
    pub notes: Vec<String>,
}

impl Merged {
    pub fn runs_succeeded(&self) -> bool {
        self.sidecar.runs.iter().all(RunRecord::succeeded)
    }
}

fn is_learned_broad(p: &Path) -> bool {
    too_broad(p) && !SCRATCH_DIRS.iter().any(|d| p == Path::new(d))
}

/// Observations equivalent to a profile's grants (`is_file` says whether a
/// path is an existing regular file; anything else becomes a directory rule).
/// Grants too broad for `learn` to ever produce (`/`, `/home`, `/etc`, ...)
/// are not carried over.
pub fn observed_from_profile(
    profile: &Profile,
    is_file: &dyn Fn(&Path) -> bool,
) -> (Observed, Vec<String>) {
    let mut o = Observed::default();
    let mut notes = Vec::new();
    for p in &profile.fs_read {
        if is_learned_broad(p) {
            notes.push(format!(
                "prior read grant {} is too broad for a learned profile and was not carried over",
                p.display()
            ));
        } else if is_file(p) {
            o.read_files.insert(p.clone());
        } else {
            o.read_dirs.insert(p.clone());
        }
    }
    for p in &profile.fs_write {
        if is_learned_broad(p) {
            notes.push(format!(
                "prior write grant {} is too broad for a learned profile and was not carried over",
                p.display()
            ));
        } else if is_file(p) {
            o.write_files.insert(p.clone());
        } else {
            o.mutated_dirs.insert(p.clone());
        }
    }
    if let Some(NetRule::Ports(ports)) = &profile.net_connect {
        o.tcp_connect.extend(ports.iter().copied());
    }
    if let Some(NetRule::Ports(ports)) = &profile.net_bind {
        o.tcp_bind.extend(ports.iter().copied());
    }
    (o, notes)
}

/// Merge new runs (and an optional prior profile) into one profile.
///
/// Pure apart from the `is_file` probe used to read a hand-written prior. The
/// merged profile always comes out of [`generalize`] over the union of all
/// observations, so merging can never grant more than generalizing those
/// same observations would.
pub fn plan_merge(
    prior: Prior,
    forget: &[String],
    new_runs: Vec<RunRecord>,
    is_file: &dyn Fn(&Path) -> bool,
) -> Result<Merged> {
    let mut notes = Vec::new();
    let (prior_profile, mut sidecar) = match prior {
        Prior::None => (None, Sidecar::default()),
        Prior::Full { profile, sidecar } => {
            sidecar.validate()?;
            let mut sidecar = sidecar;
            // Hand edits: grants in the prior profile that the tool's own
            // output for the recorded runs would not contain.
            let regen = generalize(&sidecar.union()).profile;
            let mut extra = Profile {
                fs_read: profile
                    .fs_read
                    .iter()
                    .filter(|p| !regen.fs_read.contains(p))
                    .cloned()
                    .collect(),
                fs_write: profile
                    .fs_write
                    .iter()
                    .filter(|p| !regen.fs_write.contains(p))
                    .cloned()
                    .collect(),
                ..Profile::default()
            };
            extra.net_connect = ports_not_in(&profile.net_connect, &regen.net_connect);
            extra.net_bind = ports_not_in(&profile.net_bind, &regen.net_bind);
            let (edited, skipped) = observed_from_profile(&extra, is_file);
            notes.extend(skipped);
            if edited.entry_count() > 0 {
                let mut combined = sidecar
                    .runs
                    .iter()
                    .find(|r| r.label == PRIOR_EDITED_LABEL)
                    .map(|r| r.observed.clone())
                    .unwrap_or_default();
                combined.merge(&edited);
                notes.push(format!(
                    "the prior profile was edited by hand: {} extra grant(s) are kept as run \
                     \"{PRIOR_EDITED_LABEL}\"; hand removals of learned grants are not \
                     preserved (drop a run with --forget instead)",
                    edited.entry_count()
                ));
                sidecar.add_run(RunRecord {
                    label: PRIOR_EDITED_LABEL.into(),
                    observed: combined,
                    exit_code: None,
                    signal: None,
                    timed_out: false,
                });
            }
            (Some(profile), sidecar)
        }
        Prior::ProfileOnly { profile } => {
            let (o, skipped) = observed_from_profile(&profile, is_file);
            notes.extend(skipped);
            notes.push(format!(
                "no observation file for the prior profile: its grants are treated as observations \
                 labelled \"{PRIOR_LABEL}\""
            ));
            let mut sc = Sidecar::default();
            sc.add_run(RunRecord {
                label: PRIOR_LABEL.into(),
                observed: o,
                exit_code: None,
                signal: None,
                timed_out: false,
            });
            (Some(profile), sc)
        }
    };
    for label in forget {
        anyhow::ensure!(
            sidecar.forget(label),
            "--forget {label:?}: no such run (have: {})",
            sidecar
                .runs
                .iter()
                .map(|r| r.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        notes.push(format!("forgot run \"{label}\""));
    }
    for run in new_runs {
        let label = run.label.clone();
        match sidecar.add_run(run) {
            RunChange::Added => notes.push(format!("added run \"{label}\"")),
            RunChange::Replaced => notes.push(format!("replaced run \"{label}\" with the new one")),
            RunChange::Unchanged => notes.push(format!("run \"{label}\" was already recorded")),
        }
    }
    sidecar.validate()?;

    let observed = sidecar.union();
    let mut g = generalize(&observed);
    let nruns = sidecar.runs.len();
    for r in g.review.iter_mut() {
        if r.starts_with("one run cannot prove completeness") {
            *r = format!(
                "{nruns} run(s) cannot prove completeness: code paths that none of them executed \
                 are not in this profile"
            );
        }
    }

    // Learned keys come from the union; everything else is the prior's.
    let learned = g.profile.clone();
    let mut profile = prior_profile.clone().unwrap_or_default();
    profile.fs_read = learned.fs_read;
    profile.fs_write = learned.fs_write;
    for (slot, fresh, name) in [
        (&mut profile.net_connect, learned.net_connect, "net_connect"),
        (&mut profile.net_bind, learned.net_bind, "net_bind"),
    ] {
        if matches!(slot, Some(NetRule::Keyword(k)) if k == "any") {
            g.review.push(format!(
                "{name} = \"any\" was set by hand in the prior profile and is kept as is"
            ));
        } else {
            *slot = fresh;
        }
    }
    if prior_profile.is_some() {
        notes.push(
            "learned keys (fs_read, fs_write, net_*) were regenerated from all runs; other keys \
             (limits, syscall overrides, env, ...) are kept from the prior profile; comments in \
             the prior file are not preserved"
                .into(),
        );
    }
    profile
        .validate()
        .context("the merged profile failed validation")?;
    g.profile = profile;
    Ok(Merged {
        sidecar,
        observed,
        generalized: g,
        notes,
    })
}

fn ports_not_in(prior: &Option<NetRule>, regen: &Option<NetRule>) -> Option<NetRule> {
    let Some(NetRule::Ports(p)) = prior else {
        return None;
    };
    let have: BTreeSet<u16> = match regen {
        Some(NetRule::Ports(r)) => r.iter().copied().collect(),
        _ => BTreeSet::new(),
    };
    let extra: Vec<u16> = p.iter().copied().filter(|x| !have.contains(x)).collect();
    if extra.is_empty() {
        None
    } else {
        Some(NetRule::Ports(extra))
    }
}

/// The merged profile as commented TOML: the same header and review blocks as
/// [`render_toml`], plus the list of runs.
pub fn render_merged_toml(m: &Merged) -> Result<String> {
    let mut out = String::new();
    out.push_str("# Generated by `fluxvm-procbox learn`. REVIEW BEFORE USE.\n");
    out.push_str(&format!(
        "# Merged {} run(s); observed {} process(es), {} decoded syscall(s) in total:\n",
        m.sidecar.runs.len(),
        m.observed.processes,
        m.observed.syscalls
    ));
    for r in &m.sidecar.runs {
        out.push_str(&format!("#   - {}: {}\n", one_line(&r.label), r.how()));
    }
    let failed = m.sidecar.runs.iter().filter(|r| !r.succeeded()).count();
    if failed > 0 {
        out.push_str(&format!(
            "# WARNING: {failed} run(s) did not exit 0, so this profile may be missing accesses \
             they would\n# have made on a successful run.\n"
        ));
    }
    if !m.notes.is_empty() {
        out.push_str("#\n# This merge:\n");
        for n in &m.notes {
            out.push_str(&format!("#   - {}\n", one_line(n)));
        }
    }
    if !m.generalized.generalized.is_empty() {
        out.push_str("#\n# Generalized:\n");
        for g in &m.generalized.generalized {
            out.push_str(&format!("#   - {}\n", one_line(g)));
        }
    }
    if !m.generalized.review.is_empty() {
        out.push_str("#\n# Needs human review:\n");
        for r in &m.generalized.review {
            out.push_str(&format!("#   - {}\n", one_line(r)));
        }
    }
    out.push('\n');
    out.push_str(&m.generalized.profile.to_toml_string()?);
    Ok(out)
}

/// Keep a value on one comment line (labels are command lines).
fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

/// Learn several commands in sequence, one [`RunRecord`] each.
pub fn learn_all(runs: &[(String, Vec<String>)], opts: &LearnOptions) -> Result<Vec<RunRecord>> {
    let mut out = Vec::new();
    for (label, argv) in runs {
        let res = learn(argv, opts).with_context(|| format!("learning {label:?}"))?;
        out.push(RunRecord::from_result(label.clone(), &res));
    }
    Ok(out)
}

/// Split a command line into arguments the way a POSIX shell would for the
/// simple cases (whitespace, single and double quotes, backslash escapes).
/// No expansion of any kind happens.
pub fn split_command(s: &str) -> Result<Vec<String>> {
    let mut args: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if in_word {
                    args.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => anyhow::bail!("unterminated single quote in {s:?}"),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(n @ ('"' | '\\' | '$' | '`')) => cur.push(n),
                            Some('\n') => {}
                            Some(n) => {
                                cur.push('\\');
                                cur.push(n);
                            }
                            None => anyhow::bail!("unterminated double quote in {s:?}"),
                        },
                        Some(ch) => cur.push(ch),
                        None => anyhow::bail!("unterminated double quote in {s:?}"),
                    }
                }
            }
            '\\' => {
                in_word = true;
                match chars.next() {
                    Some('\n') => {}
                    Some(n) => cur.push(n),
                    None => anyhow::bail!("trailing backslash in {s:?}"),
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        args.push(cur);
    }
    anyhow::ensure!(!args.is_empty(), "empty command");
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    fn obs_with(f: impl FnOnce(&mut Observed)) -> Generalized {
        let mut o = Observed::default();
        f(&mut o);
        generalize(&o)
    }

    #[test]
    fn system_paths_collapse_to_their_root() {
        let g = obs_with(|o| {
            o.read_files
                .insert(p("/usr/lib/x86_64-linux-gnu/libc.so.6"));
            o.read_files.insert(p("/usr/share/zoneinfo/UTC"));
            o.exec.insert(p("/usr/bin/dash"));
            o.read_files.insert(p("/lib/x86_64-linux-gnu/libm.so.6"));
        });
        assert_eq!(g.profile.fs_read, vec![p("/lib"), p("/usr")]);
        assert!(g.generalized.iter().any(|m| m.contains("under /usr")));
    }

    #[test]
    fn broad_directories_are_never_granted_by_collapsing() {
        let g = obs_with(|o| {
            for f in [
                "hostname",
                "passwd",
                "nsswitch.conf",
                "hosts",
                "resolv.conf",
            ] {
                o.read_files.insert(p(&format!("/etc/{f}")));
            }
            for f in ["a", "b", "c"] {
                o.read_files.insert(p(&format!("/home/alice/{f}")));
            }
        });
        assert!(!g.profile.fs_read.contains(&p("/etc")));
        assert!(!g.profile.fs_read.contains(&p("/home/alice")));
        assert!(g.profile.fs_read.contains(&p("/etc/hostname")));
        assert_eq!(g.profile.fs_read.len(), 8);
    }

    #[test]
    fn many_siblings_in_a_specific_directory_collapse_to_it() {
        let g = obs_with(|o| {
            for f in ["a.pem", "b.pem", "c.pem"] {
                o.read_files.insert(p(&format!("/etc/ssl/certs/{f}")));
            }
            o.read_files.insert(p("/opt/app/one"));
            o.read_files.insert(p("/opt/app/two"));
        });
        assert!(g.profile.fs_read.contains(&p("/etc/ssl/certs")));
        // Two siblings are not enough to widen.
        assert!(g.profile.fs_read.contains(&p("/opt/app/one")));
        assert!(g.profile.fs_read.contains(&p("/opt/app/two")));
    }

    #[test]
    fn created_files_grant_their_directory_narrowly() {
        let g = obs_with(|o| {
            o.create_files.insert(p("/home/alice/work/out/result.txt"));
            o.write_files.insert(p("/home/alice/work/out/existing.log"));
            o.write_files.insert(p("/home/alice/work/state.db"));
        });
        assert_eq!(
            g.profile.fs_write,
            vec![p("/home/alice/work/out"), p("/home/alice/work/state.db")]
        );
    }

    #[test]
    fn writes_in_broad_directories_are_refused_and_reported() {
        let g = obs_with(|o| {
            o.create_files.insert(p("/etc/newconf"));
            o.create_files.insert(p("/home/alice/newfile"));
            o.mutated_dirs.insert(p("/"));
        });
        assert!(g.profile.fs_write.is_empty(), "{:?}", g.profile.fs_write);
        assert!(
            g.review
                .iter()
                .filter(|r| r.starts_with("NOT granted"))
                .count()
                >= 3
        );
    }

    #[test]
    fn scratch_directories_are_granted_but_flagged() {
        let g = obs_with(|o| {
            o.create_files.insert(p("/tmp/learn-out"));
        });
        assert_eq!(g.profile.fs_write, vec![p("/tmp")]);
        assert!(g
            .review
            .iter()
            .any(|r| r.contains("shared scratch directory /tmp")));
    }

    #[test]
    fn covered_paths_are_dropped() {
        let g = obs_with(|o| {
            o.create_files.insert(p("/srv/data/new"));
            o.write_files.insert(p("/srv/data/old"));
            o.read_files.insert(p("/srv/data/cfg"));
        });
        // `/srv` is not broad-refused for writes below it, and the file grants
        // are absorbed by the directory grant.
        assert_eq!(g.profile.fs_write, vec![p("/srv/data")]);
        assert!(g.profile.fs_read.is_empty());
    }

    #[test]
    fn per_process_proc_paths_are_flagged_not_granted() {
        let g = obs_with(|o| {
            o.read_files.insert(p("/proc/self/maps"));
            o.read_files.insert(p("/proc/12345/status"));
            o.read_files.insert(p("/proc/meminfo"));
        });
        assert_eq!(g.profile.fs_read, vec![p("/proc/meminfo")]);
        assert!(g.review.iter().any(|r| r.contains("per-process /proc")));
    }

    #[test]
    fn network_rules_follow_observations() {
        let none = obs_with(|_| {});
        assert_eq!(
            none.profile.net_connect,
            Some(NetRule::Keyword("deny".into()))
        );
        assert_eq!(none.profile.net_bind, Some(NetRule::Keyword("deny".into())));
        let some = obs_with(|o| {
            o.tcp_connect.insert(443);
            o.tcp_connect.insert(80);
            o.tcp_endpoints.insert("1.2.3.4:443".into());
            o.tcp_bind.insert(8080);
            o.unix_sockets.insert(p("/run/x.sock"));
            o.other_endpoints.insert("connect 8.8.8.8:53".into());
        });
        assert_eq!(
            some.profile.net_connect,
            Some(NetRule::Ports(vec![80, 443]))
        );
        assert_eq!(some.profile.net_bind, Some(NetRule::Ports(vec![8080])));
        assert!(some.review.iter().any(|r| r.contains("not addresses")));
        assert!(some.review.iter().any(|r| r.contains("unix socket")));
        assert!(some.review.iter().any(|r| r.contains("non-TCP")));
    }

    #[test]
    fn generated_toml_parses_back_to_the_same_profile() {
        let g = obs_with(|o| {
            o.read_files.insert(p("/usr/lib/libc.so.6"));
            o.read_files.insert(p("/etc/hostname"));
            o.create_files.insert(p("/srv/out/x"));
            o.tcp_connect.insert(443);
        });
        let res = LearnResult {
            observed: Observed::default(),
            generalized: g.clone(),
            exit_code: Some(0),
            signal: None,
            timed_out: false,
            wall_ms: 5,
        };
        let text = render_toml(&res).unwrap();
        assert!(text.starts_with("# Generated by"));
        assert!(text.contains("Needs human review"));
        let back = Profile::from_toml_str(&text).unwrap();
        assert_eq!(back, g.profile);
    }

    #[test]
    fn a_failed_program_is_called_out_in_the_header() {
        let res = LearnResult {
            observed: Observed::default(),
            generalized: generalize(&Observed::default()),
            exit_code: Some(3),
            signal: None,
            timed_out: false,
            wall_ms: 1,
        };
        assert!(render_toml(&res).unwrap().contains("WARNING"));
    }

    #[test]
    fn open_flags_classify() {
        let (rd, wr, rw) = (0, 1, 2);
        assert_eq!(classify_open(rd, true), OpenKind::Read);
        assert_eq!(classify_open(wr, true), OpenKind::Write);
        assert_eq!(classify_open(rw, true), OpenKind::Write);
        assert_eq!(classify_open(rd | O_TRUNC, true), OpenKind::Write);
        assert_eq!(classify_open(wr | O_CREAT, false), OpenKind::Create);
        assert_eq!(classify_open(wr | O_CREAT, true), OpenKind::Write);
        assert_eq!(classify_open(rd | O_CREAT, true), OpenKind::Read);
        assert_eq!(classify_open(O_PATH, true), OpenKind::Ignore);
        assert_eq!(classify_open(O_TMPFILE | 2, true), OpenKind::TmpFile);
    }

    #[test]
    fn sockaddrs_decode() {
        let mut v4 = vec![2, 0, 0x01, 0xbb, 10, 0, 0, 7];
        v4.extend([0u8; 8]);
        assert_eq!(
            parse_sockaddr(&v4),
            Some(SockAddr::V4(Ipv4Addr::new(10, 0, 0, 7), 443))
        );
        let mut v6 = vec![10, 0, 0x1f, 0x90, 0, 0, 0, 0];
        let mut lo = [0u8; 16];
        lo[15] = 1;
        v6.extend(lo);
        assert_eq!(
            parse_sockaddr(&v6),
            Some(SockAddr::V6(Ipv6Addr::LOCALHOST, 8080))
        );
        let mut un = vec![1, 0];
        un.extend(b"/run/x.sock\0");
        assert_eq!(parse_sockaddr(&un), Some(SockAddr::Unix(p("/run/x.sock"))));
        let mut ab = vec![1, 0, 0];
        ab.extend(b"name\0");
        assert_eq!(
            parse_sockaddr(&ab),
            Some(SockAddr::UnixAbstract("name".into()))
        );
        assert_eq!(parse_sockaddr(&[0, 0, 1, 2]), None);
        assert_eq!(parse_sockaddr(&[2]), None);
    }

    #[test]
    fn lexical_normalization() {
        assert_eq!(normalize_lexical(Path::new("/a/./b//c/../d")), p("/a/b/d"));
        assert_eq!(normalize_lexical(Path::new("/../..")), p("/"));
        assert_eq!(normalize_lexical(Path::new("/")), p("/"));
    }

    // ---------------------------------------------------------------- merging

    fn rec(label: &str, f: impl FnOnce(&mut Observed)) -> RunRecord {
        let mut o = Observed::default();
        f(&mut o);
        RunRecord {
            label: label.into(),
            observed: o,
            exit_code: Some(0),
            signal: None,
            timed_out: false,
        }
    }

    fn nofile(_: &Path) -> bool {
        false
    }

    fn fresh(runs: Vec<RunRecord>) -> Merged {
        plan_merge(Prior::None, &[], runs, &nofile).unwrap()
    }

    fn again(prev: &Merged, forget: &[String], runs: Vec<RunRecord>) -> Merged {
        plan_merge(
            Prior::Full {
                profile: prev.generalized.profile.clone(),
                sidecar: prev.sidecar.clone(),
            },
            forget,
            runs,
            &nofile,
        )
        .unwrap()
    }

    fn a_run() -> RunRecord {
        rec("a", |o| {
            o.read_files.insert(p("/opt/app/data/a"));
            o.read_files.insert(p("/opt/app/data/b"));
            o.write_files.insert(p("/srv/out/a.txt"));
            o.tcp_connect.insert(8080);
        })
    }

    fn b_run() -> RunRecord {
        rec("b", |o| {
            o.read_files.insert(p("/opt/app/data/c"));
            o.create_files.insert(p("/srv/other/b.txt"));
            o.tcp_connect.insert(9090);
        })
    }

    fn toml_of(m: &Merged) -> String {
        m.generalized.profile.to_toml_string().unwrap()
    }

    #[test]
    fn sidecar_add_run_reports_what_it_did() {
        let mut sc = Sidecar::default();
        assert_eq!(sc.add_run(a_run()), RunChange::Added);
        assert_eq!(sc.add_run(a_run()), RunChange::Unchanged);
        let mut changed = a_run();
        changed.observed.tcp_connect.insert(1);
        assert_eq!(sc.add_run(changed), RunChange::Replaced);
        assert_eq!(sc.runs.len(), 1);
        assert!(sc.forget("a"));
        assert!(!sc.forget("a"));
    }

    #[test]
    fn merging_the_same_run_twice_changes_nothing() {
        let first = fresh(vec![a_run(), b_run()]);
        let second = again(&first, &[], vec![a_run(), b_run()]);
        assert_eq!(toml_of(&first), toml_of(&second));
        assert_eq!(first.sidecar, second.sidecar);
        assert!(second.notes.iter().any(|n| n.contains("already recorded")));
    }

    #[test]
    fn merge_does_not_depend_on_the_order_of_runs() {
        let ab = fresh(vec![a_run(), b_run()]);
        let ba = fresh(vec![b_run(), a_run()]);
        assert_eq!(toml_of(&ab), toml_of(&ba));
        assert_eq!(
            ab.sidecar.to_json_string().unwrap(),
            ba.sidecar.to_json_string().unwrap()
        );
        // Learning them one after the other gives the same profile too.
        let seq = again(&fresh(vec![a_run()]), &[], vec![b_run()]);
        assert_eq!(toml_of(&ab), toml_of(&seq));
    }

    #[test]
    fn generalizing_the_union_collapses_siblings_from_different_runs() {
        let a_only = fresh(vec![a_run()]);
        assert_eq!(
            a_only.generalized.profile.fs_read,
            vec![p("/opt/app/data/a"), p("/opt/app/data/b")],
            "two files alone stay listed"
        );
        let both = fresh(vec![a_run(), b_run()]);
        assert_eq!(both.generalized.profile.fs_read, vec![p("/opt/app/data")]);
        // Ports from both runs, created files -> their directories.
        assert_eq!(
            both.generalized.profile.net_connect,
            Some(NetRule::Ports(vec![8080, 9090]))
        );
        assert!(both.generalized.profile.fs_write.contains(&p("/srv/other")));
        assert!(both
            .generalized
            .profile
            .fs_write
            .contains(&p("/srv/out/a.txt")));
    }

    #[test]
    fn completeness_note_counts_the_runs() {
        let m = fresh(vec![a_run(), b_run()]);
        assert!(
            m.generalized
                .review
                .iter()
                .any(|r| r.starts_with("2 run(s) cannot prove completeness")),
            "{:?}",
            m.generalized.review
        );
    }

    #[test]
    fn merging_never_grants_more_than_generalizing_would() {
        // A hand-written prior with broad grants: none of them may survive.
        let prior = Profile {
            fs_read: vec![p("/"), p("/home"), p("/etc"), p("/opt/app")],
            fs_write: vec![p("/"), p("/home/alice"), p("/var")],
            ..Profile::default()
        };
        let m = plan_merge(
            Prior::ProfileOnly { profile: prior },
            &[],
            vec![b_run()],
            &nofile,
        )
        .unwrap();
        let g = &m.generalized.profile;
        for bad in ["/", "/home", "/etc", "/home/alice", "/var"] {
            assert!(!g.fs_read.contains(&p(bad)), "read {bad}: {g:?}");
            assert!(!g.fs_write.contains(&p(bad)), "write {bad}: {g:?}");
        }
        assert!(g.fs_read.contains(&p("/opt/app")), "{g:?}");
        assert!(m
            .notes
            .iter()
            .any(|n| n.contains("too broad for a learned profile")));
        // The result is exactly what generalizing the union yields.
        let again_from_union = generalize(&m.observed).profile;
        assert_eq!(g.fs_read, again_from_union.fs_read);
        assert_eq!(g.fs_write, again_from_union.fs_write);
    }

    #[test]
    fn profile_only_prior_becomes_a_labelled_run() {
        let prior = Profile {
            fs_read: vec![p("/usr")],
            net_connect: Some(NetRule::Ports(vec![443])),
            max_memory: Some(crate::profile::SizeValue::Text("256M".into())),
            ..Profile::default()
        };
        let m = plan_merge(
            Prior::ProfileOnly { profile: prior },
            &[],
            vec![a_run()],
            &nofile,
        )
        .unwrap();
        assert!(m.sidecar.runs.iter().any(|r| r.label == PRIOR_LABEL));
        assert_eq!(
            m.generalized.profile.net_connect,
            Some(NetRule::Ports(vec![443, 8080]))
        );
        // Non-learned keys come from the prior profile.
        assert_eq!(
            m.generalized.profile.max_memory,
            Some(crate::profile::SizeValue::Text("256M".into()))
        );
    }

    #[test]
    fn hand_edits_and_other_keys_survive_a_merge() {
        let first = fresh(vec![a_run()]);
        let mut edited = first.generalized.profile.clone();
        edited.fs_read.push(p("/opt/extra"));
        edited.max_processes = Some(64);
        edited.syscall_deny = vec!["chmod".into()];
        let prev = Merged {
            generalized: Generalized {
                profile: edited,
                ..first.generalized.clone()
            },
            ..first
        };
        let merged = again(&prev, &[], vec![b_run()]);
        let g = &merged.generalized.profile;
        assert!(g.fs_read.contains(&p("/opt/extra")), "{g:?}");
        assert_eq!(g.max_processes, Some(64));
        assert_eq!(g.syscall_deny, vec!["chmod".to_string()]);
        assert!(merged
            .sidecar
            .runs
            .iter()
            .any(|r| r.label == PRIOR_EDITED_LABEL));
        assert!(merged.notes.iter().any(|n| n.contains("edited by hand")));
        // The hand edit is now recorded, so merging again is a no-op.
        let third = again(&merged, &[], vec![b_run()]);
        assert_eq!(merged.sidecar, third.sidecar);
        assert_eq!(toml_of(&merged), toml_of(&third));
    }

    #[test]
    fn a_hand_set_any_rule_is_kept_and_flagged() {
        let first = fresh(vec![a_run()]);
        let mut prof = first.generalized.profile.clone();
        prof.net_connect = Some(NetRule::Keyword("any".into()));
        let m = plan_merge(
            Prior::Full {
                profile: prof,
                sidecar: first.sidecar.clone(),
            },
            &[],
            vec![b_run()],
            &nofile,
        )
        .unwrap();
        assert_eq!(
            m.generalized.profile.net_connect,
            Some(NetRule::Keyword("any".into()))
        );
        assert!(m
            .generalized
            .review
            .iter()
            .any(|r| r.contains("net_connect = \"any\" was set by hand")));
    }

    #[test]
    fn forgetting_a_run_shrinks_the_profile_and_unknown_labels_fail() {
        let both = fresh(vec![a_run(), b_run()]);
        let only_a = again(&both, &["b".to_string()], vec![]);
        assert_eq!(only_a.sidecar.runs.len(), 1);
        assert_eq!(
            only_a.generalized.profile.net_connect,
            Some(NetRule::Ports(vec![8080]))
        );
        let err = plan_merge(
            Prior::Full {
                profile: both.generalized.profile.clone(),
                sidecar: both.sidecar.clone(),
            },
            &["nope".to_string()],
            vec![],
            &nofile,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("no such run"), "{err:#}");
    }

    #[test]
    fn sidecar_json_round_trips_and_rejects_bad_files() {
        let m = fresh(vec![b_run(), a_run()]);
        let text = m.sidecar.to_json_string().unwrap();
        let back = Sidecar::from_json_str(&text).unwrap();
        assert_eq!(back.to_json_string().unwrap(), text);
        // Runs come out sorted by label whatever the insertion order.
        assert!(text.find("\"a\"").unwrap() < text.find("\"b\"").unwrap());

        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let mut with_extra = v.clone();
        with_extra["surprise"] = 1.into();
        assert!(Sidecar::from_json_str(&with_extra.to_string()).is_err());
        v["version"] = 2.into();
        let err = Sidecar::from_json_str(&v.to_string()).unwrap_err();
        assert!(format!("{err:#}").contains("unsupported observation file version"));

        let mut dup = m.sidecar.clone();
        dup.runs.push(dup.runs[0].clone());
        assert!(dup.validate().is_err(), "duplicate labels");
        let mut rel = m.sidecar.clone();
        rel.runs[0].observed.read_files.insert(p("relative/path"));
        assert!(rel.validate().is_err(), "relative path");
        let mut many = Sidecar::default();
        for i in 0..=MAX_RUNS {
            many.runs.push(rec(&format!("r{i}"), |_| {}));
        }
        assert!(many.validate().is_err(), "too many runs");
        assert!(Sidecar::from_json_str("{not json").is_err());
        assert!(Sidecar::from_json_str("").is_err());
    }

    #[test]
    fn sidecar_path_appends_to_the_profile_file_name() {
        assert_eq!(
            Sidecar::path_for(Path::new("/x/p.toml")),
            p("/x/p.toml.observed.json")
        );
    }

    #[test]
    fn rendered_merge_lists_runs_notes_and_review_and_reparses() {
        let mut failed = b_run();
        failed.exit_code = Some(3);
        let m = fresh(vec![a_run(), failed]);
        let text = render_merged_toml(&m).unwrap();
        assert!(text.contains("Merged 2 run(s)"), "{text}");
        assert!(text.contains("#   - a: exited with status 0"), "{text}");
        assert!(text.contains("#   - b: exited with status 3"), "{text}");
        assert!(text.contains("WARNING: 1 run(s) did not exit 0"), "{text}");
        assert!(text.contains("# This merge:"), "{text}");
        assert!(text.contains("# Needs human review:"), "{text}");
        let reparsed = Profile::from_toml_str(&text).unwrap();
        assert_eq!(reparsed, m.generalized.profile);
        assert!(!m.runs_succeeded());
    }

    #[test]
    fn split_command_follows_shell_quoting() {
        let v = |s: &str| split_command(s).unwrap();
        assert_eq!(v("ls -l  /tmp"), ["ls", "-l", "/tmp"]);
        assert_eq!(v("sh -c 'echo a b'"), ["sh", "-c", "echo a b"]);
        assert_eq!(
            v(r#"sh -c "echo \"hi\" > /tmp/x""#),
            ["sh", "-c", r#"echo "hi" > /tmp/x"#]
        );
        assert_eq!(v(r"a\ b c"), ["a b", "c"]);
        assert_eq!(v("x '' y"), ["x", "", "y"]);
        assert_eq!(v(r#"p 'it'"'"'s'"#), ["p", "it's"]);
        assert!(split_command("").is_err());
        assert!(split_command("   ").is_err());
        assert!(split_command("echo 'open").is_err());
        assert!(split_command("echo \"open").is_err());
        assert!(split_command("echo trailing\\").is_err());
    }
}
