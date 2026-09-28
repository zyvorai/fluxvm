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
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// Everything the traced program did that a profile could care about. Paths
/// are canonical (symlinks resolved) where the path existed.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
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
}
