// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Namespace isolation: unprivileged user, mount, pid, ipc and uts namespaces
//! (plus a network namespace when the policy grants no network) and a private
//! root that contains only the paths the policy grants.
//!
//! Everything fallible or allocating happens in the parent ([`prepare`]); the
//! child ([`enter`]) only makes raw syscalls on data prepared there, because
//! it runs between `fork` and `exec` in a possibly multi-threaded process.
//!
//! Layout inside the child, in order: `unshare`, uid/gid maps (identity, so
//! file ownership and `id` do not change), a `fork` so the command is inside
//! the new pid namespace (the intermediate process only forwards the exit
//! status), a tmpfs root with read-only bind mounts of the granted read paths
//! and read-write binds of the granted write paths, `pivot_root`, and finally
//! every capability is dropped. Landlock and seccomp are applied afterwards by
//! the caller, exactly as without isolation.

use crate::policy::{Policy, TcpRule};
use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

const NS_FLAGS: libc::c_int = libc::CLONE_NEWUSER
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUTS;

/// Mount flags that a bind mount must keep from its source when it is
/// remounted inside a user namespace (the kernel refuses to clear them).
const LOCKED_MASK: libc::c_ulong = libc::MS_NOSUID
    | libc::MS_NODEV
    | libc::MS_NOEXEC
    | libc::MS_NOATIME
    | libc::MS_NODIRATIME
    | libc::MS_RELATIME
    | libc::MS_RDONLY;

/// Whether the policy grants no network at all (then the child also gets an
/// empty network namespace, which closes UDP and every host socket).
pub fn wants_net_isolation(policy: &Policy) -> bool {
    policy.tcp_connect == TcpRule::Deny && policy.tcp_bind == TcpRule::Deny
}

// ---------------------------------------------------------------------------
// Availability probe
// ---------------------------------------------------------------------------

/// Can the host create the namespaces isolation needs, as the caller (or as
/// `ids` after a uid switch)? `Err` carries the reason, including the sysctl
/// that usually explains it.
pub fn userns_status(ids: Option<(u32, u32)>) -> std::result::Result<(), String> {
    static CACHE: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    match ids {
        None => CACHE.get_or_init(|| check(None)).clone(),
        Some(_) => check(ids),
    }
}

/// A root caller builds the namespaces with its real privileges and needs no
/// user namespace. `FLUXVM_PROCBOX_FORCE_USERNS` (a testing knob; `run_as` is
/// ignored then) makes even a root caller take the unprivileged-user path, so
/// that path can be exercised on hosts that restrict unprivileged userns.
fn use_userns() -> bool {
    unsafe { libc::geteuid() != 0 || std::env::var_os("FLUXVM_PROCBOX_FORCE_USERNS").is_some() }
}

fn sysctl(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn hints() -> String {
    let mut h = Vec::new();
    if sysctl("/proc/sys/user/max_user_namespaces").as_deref() == Some("0") {
        h.push("user.max_user_namespaces=0");
    }
    if sysctl("/proc/sys/kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        h.push("kernel.unprivileged_userns_clone=0");
    }
    if sysctl("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() == Some("1") {
        h.push("AppArmor restricts unprivileged user namespaces: kernel.apparmor_restrict_unprivileged_userns=1");
    }
    h.join("; ")
}

fn check(ids: Option<(u32, u32)>) -> std::result::Result<(), String> {
    let userns = use_userns();
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!("pipe: {}", io::Error::last_os_error()));
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let e = io::Error::last_os_error();
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return Err(format!("fork: {e}"));
    }
    if pid == 0 {
        // SAFETY: raw syscalls only, then _exit.
        unsafe {
            let (step, errno) = probe_child(ids, userns);
            let buf = [step, errno];
            libc::write(fds[1], buf.as_ptr() as *const libc::c_void, 2);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(fds[1]) };
    let mut buf = [0u8; 2];
    let n = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, 2) };
    unsafe {
        libc::close(fds[0]);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }
    if n != 2 {
        return Err("the namespace probe process died".into());
    }
    let (step, errno) = (buf[0], buf[1]);
    if step == 0 {
        return Ok(());
    }
    let what = match step {
        1 => "cannot switch to the sandbox uid",
        2 => "unshare(CLONE_NEWUSER|CLONE_NEWNS) failed",
        3 => "writing the uid/gid map failed",
        4 => "making the mount tree private failed",
        _ => "mounting a tmpfs in the new namespace failed",
    };
    let mut msg = format!("{what}: {}", io::Error::from_raw_os_error(errno as i32));
    let h = hints();
    if !h.is_empty() {
        msg.push_str(&format!(" ({h})"));
    }
    Err(msg)
}

fn errno() -> u8 {
    (unsafe { *libc::__errno_location() }) as u8
}

/// Format `"{id} {id} 1\n"` without allocating; returns the length.
fn fmt_map(id: u32, buf: &mut [u8; 48]) -> usize {
    let mut digits = [0u8; 10];
    let mut n = id;
    let mut len = 0;
    loop {
        digits[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let mut out = 0;
    for _ in 0..2 {
        for i in (0..len).rev() {
            buf[out] = digits[i];
            out += 1;
        }
        buf[out] = b' ';
        out += 1;
    }
    buf[out] = b'1';
    buf[out + 1] = b'\n';
    out + 2
}

unsafe fn write_file(path: &[u8], data: &[u8]) -> io::Result<()> {
    let fd = libc::open(path.as_ptr() as *const libc::c_char, libc::O_WRONLY);
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = libc::write(fd, data.as_ptr() as *const libc::c_void, data.len());
    let err = io::Error::last_os_error();
    libc::close(fd);
    if rc != data.len() as isize {
        return Err(err);
    }
    Ok(())
}

unsafe fn probe_child(ids: Option<(u32, u32)>, userns: bool) -> (u8, u8) {
    if !userns {
        // A root caller needs no user namespace (and is not subject to the
        // unprivileged-userns restrictions): only a mount namespace.
        if libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWPID) != 0 {
            return (2, errno());
        }
        return probe_mounts();
    }
    if let Some((uid, gid)) = ids {
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setgid(gid) != 0
            || libc::setuid(uid) != 0
        {
            return (1, errno());
        }
    }
    let uid = libc::geteuid();
    let gid = libc::getegid();
    // A uid switch clears the dumpable flag, which would make /proc/self/*
    // (and so the id maps) root-owned.
    libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
    if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) != 0 {
        return (2, errno());
    }
    let mut buf = [0u8; 48];
    if write_file(b"/proc/self/setgroups\0", b"deny").is_err() {
        return (3, errno());
    }
    let n = fmt_map(uid, &mut buf);
    if write_file(b"/proc/self/uid_map\0", &buf[..n]).is_err() {
        return (3, errno());
    }
    let n = fmt_map(gid, &mut buf);
    if write_file(b"/proc/self/gid_map\0", &buf[..n]).is_err() {
        return (3, errno());
    }
    probe_mounts()
}

unsafe fn probe_mounts() -> (u8, u8) {
    if libc::mount(
        std::ptr::null(),
        c"/".as_ptr(),
        std::ptr::null(),
        libc::MS_REC | libc::MS_PRIVATE,
        std::ptr::null(),
    ) != 0
    {
        return (4, errno());
    }
    if libc::mount(
        c"tmpfs".as_ptr(),
        c"/tmp".as_ptr(),
        c"tmpfs".as_ptr(),
        0,
        std::ptr::null(),
    ) != 0
        && errno() != libc::ENOENT as u8
    {
        return (5, errno());
    }
    (0, 0)
}

// ---------------------------------------------------------------------------
// Preparation (parent)
// ---------------------------------------------------------------------------

struct Bind {
    src: CString,
    dst: CString,
    /// `Some(flags)`: remount read-only with these flags (source flags kept).
    remount: Option<libc::c_ulong>,
}

/// Everything the child needs, built in the parent.
pub struct Prepared {
    flags: libc::c_int,
    stage: CString,
    stage_path: PathBuf,
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    dirs: Vec<CString>,
    files: Vec<CString>,
    binds: Vec<Bind>,
    proc_dst: Option<CString>,
    cwd: CString,
    lo_up: bool,
    proc_rule: Option<(CString, u64)>,
    newnet: bool,
    /// A user namespace is used (non-root caller). A root caller keeps its
    /// real privileges to build the namespaces and root, then drops them.
    userns: bool,
    /// Root caller only: uid/gid to switch to once the root is built.
    switch: Option<(u32, u32)>,
}

impl Prepared {
    /// The child also gets an empty network namespace.
    pub fn newnet(&self) -> bool {
        self.newnet
    }

    /// The directory the private root is assembled under (host side).
    pub fn stage_path(&self) -> &Path {
        &self.stage_path
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        // The tmpfs lives only in the child's mount namespace, so on the host
        // this is an empty directory.
        let _ = std::fs::remove_dir(&self.stage_path);
    }
}

fn source_info(path: &Path) -> Option<(bool, libc::c_ulong)> {
    let c = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    let flags = if unsafe { libc::statvfs(c.as_ptr(), &mut vfs) } == 0 {
        (vfs.f_flag as libc::c_ulong) & LOCKED_MASK
    } else {
        0
    };
    Some((is_dir, flags))
}

fn under(stage: &Path, p: &Path) -> PathBuf {
    let rel = p.strip_prefix("/").unwrap_or(p);
    stage.join(rel)
}

/// Build the private-root plan for `policy`, running as `ids` (uid, gid).
/// `handled_fs` is the Landlock filesystem rights in effect (for `/proc`).
/// Paths that do not exist are skipped and noted.
pub fn prepare(policy: &Policy, handled_fs: u64, notes: &mut Vec<String>) -> Result<Prepared> {
    let userns = use_userns();
    let ids = unsafe { (libc::geteuid(), libc::getegid()) };
    let switch = if userns {
        None
    } else {
        policy.run_as.map(|r| (r.uid, r.gid))
    };
    let base = std::env::temp_dir();
    let mut template = base.join(".fvpb-XXXXXX").as_os_str().as_bytes().to_vec();
    template.push(0);
    if unsafe { libc::mkdtemp(template.as_mut_ptr() as *mut libc::c_char) }.is_null() {
        return Err(io::Error::last_os_error()).context("creating the private-root staging dir");
    }
    template.pop();
    let stage_path = PathBuf::from(std::ffi::OsStr::from_bytes(&template));
    // Other uids must be able to traverse it to mount over it.
    let _ = std::fs::set_permissions(
        &stage_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    );
    let stage = CString::new(stage_path.as_os_str().as_bytes())?;

    let mut dirs: BTreeSet<PathBuf> = BTreeSet::new();
    let mut files: Vec<PathBuf> = Vec::new();
    let mut binds: Vec<(PathBuf, PathBuf, bool, libc::c_ulong, bool)> = Vec::new();
    let mut proc_rw: Option<bool> = None;

    let mut add = |path: &Path, writable: bool, notes: &mut Vec<String>| -> Result<()> {
        if !path.is_absolute() {
            bail!(
                "isolation needs absolute policy paths, got {}",
                path.display()
            );
        }
        if path == Path::new("/proc") {
            proc_rw = Some(proc_rw.unwrap_or(false) | writable);
            return Ok(());
        }
        let Some((is_dir, src_flags)) = source_info(path) else {
            notes.push(format!(
                "path {} does not exist and is absent from the private root",
                path.display()
            ));
            return Ok(());
        };
        let dst = under(&stage_path, path);
        if is_dir {
            dirs.insert(dst.clone());
        } else if let Some(parent) = dst.parent() {
            dirs.insert(parent.to_path_buf());
            files.push(dst.clone());
        }
        // Parents of every target, up to the stage.
        let mut cur = dst.parent();
        while let Some(p) = cur {
            if p == stage_path || !p.starts_with(&stage_path) {
                break;
            }
            dirs.insert(p.to_path_buf());
            cur = p.parent();
        }
        binds.push((path.to_path_buf(), dst, writable, src_flags, is_dir));
        Ok(())
    };
    for p in &policy.read {
        add(p, false, notes)?;
    }
    for p in &policy.write {
        add(p, true, notes)?;
    }
    if proc_rw.is_some() {
        dirs.insert(stage_path.join("proc"));
    }

    // Shallow paths first so a child mountpoint is never hidden by its parent.
    let mut dirs: Vec<PathBuf> = dirs.into_iter().collect();
    dirs.sort_by_key(|p| p.components().count());
    binds.sort_by_key(|(_, dst, ..)| dst.components().count());

    let to_c = |p: &Path| CString::new(p.as_os_str().as_bytes());
    let mut c_binds = Vec::new();
    for (src, dst, writable, src_flags, _is_dir) in binds {
        let dev = dst.starts_with(stage_path.join("dev"));
        let extra = if dev {
            0
        } else {
            libc::MS_NOSUID | libc::MS_NODEV
        };
        // Read-only and read-write binds are both remounted so nosuid/nodev
        // (and, for reads, read-only) hold inside the namespace.
        let remount = if writable {
            if dev {
                None
            } else {
                Some(src_flags | extra)
            }
        } else {
            Some(src_flags | extra | libc::MS_RDONLY)
        };
        c_binds.push(Bind {
            src: to_c(&src)?,
            dst: to_c(&dst)?,
            remount,
        });
    }

    let cwd = policy
        .cwd
        .as_deref()
        .filter(|c| c.is_absolute())
        .unwrap_or(Path::new("/"));
    let proc_rule = match proc_rw {
        Some(rw) if handled_fs != 0 => {
            let rights = if rw {
                crate::landlock::write_rights(handled_fs)
            } else {
                crate::landlock::read_rights(handled_fs)
            };
            Some((CString::new("/proc")?, rights))
        }
        _ => None,
    };
    let newnet = wants_net_isolation(policy);
    Ok(Prepared {
        flags: (if userns {
            NS_FLAGS
        } else {
            NS_FLAGS & !libc::CLONE_NEWUSER
        }) | if newnet { libc::CLONE_NEWNET } else { 0 },
        stage,
        stage_path: stage_path.clone(),
        uid_map: format!("{} {} 1\n", ids.0, ids.0).into_bytes(),
        gid_map: format!("{} {} 1\n", ids.1, ids.1).into_bytes(),
        dirs: dirs.iter().map(|p| to_c(p)).collect::<Result<_, _>>()?,
        files: files.iter().map(|p| to_c(p)).collect::<Result<_, _>>()?,
        binds: c_binds,
        proc_dst: if proc_rw.is_some() {
            Some(to_c(&stage_path.join("proc"))?)
        } else {
            None
        },
        cwd: CString::new(cwd.as_os_str().as_bytes())?,
        lo_up: newnet,
        proc_rule,
        newnet,
        userns,
        switch,
    })
}

// ---------------------------------------------------------------------------
// Child side (async-signal-safe: raw syscalls on prepared data only)
// ---------------------------------------------------------------------------

unsafe fn last() -> io::Error {
    io::Error::last_os_error()
}

unsafe fn mnt(
    src: *const libc::c_char,
    dst: *const libc::c_char,
    fstype: *const libc::c_char,
    flags: libc::c_ulong,
    data: *const libc::c_void,
) -> io::Result<()> {
    if libc::mount(src, dst, fstype, flags, data) != 0 {
        return Err(last());
    }
    Ok(())
}

/// Close every fd above stderr (so the intermediate process does not keep
/// the exec-status pipe open and block `spawn`).
unsafe fn close_from_3() {
    if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) != 0 {
        for fd in 3..1024 {
            libc::close(fd);
        }
    }
}

/// The intermediate process: wait for the pid-namespace init and mirror how
/// it ended, so the caller sees the command's own exit code or signal.
unsafe fn forward(child: libc::pid_t) -> ! {
    close_from_3();
    let mut st: libc::c_int = 0;
    loop {
        let r = libc::waitpid(child, &mut st, 0);
        if r == child {
            break;
        }
        if r < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        libc::_exit(127);
    }
    if libc::WIFEXITED(st) {
        libc::_exit(libc::WEXITSTATUS(st));
    }
    if libc::WIFSIGNALED(st) {
        let sig = libc::WTERMSIG(st);
        libc::signal(sig, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, sig);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::kill(libc::getpid(), sig);
        libc::_exit(128 + sig);
    }
    libc::_exit(1)
}

unsafe fn bring_up_lo() {
    #[repr(C)]
    struct Ifreq {
        name: [u8; 16],
        flags: i16,
        pad: [u8; 22],
    }
    let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
    if fd < 0 {
        return;
    }
    let mut req = Ifreq {
        name: [0; 16],
        flags: 0,
        pad: [0; 22],
    };
    req.name[..2].copy_from_slice(b"lo");
    if libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut req as *mut Ifreq) == 0 {
        req.flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &mut req as *mut Ifreq);
    }
    libc::close(fd);
}

/// Drop every capability: ambient and bounding sets first (they need
/// CAP_SETPCAP), then the optional uid/gid switch (which needs CAP_SETUID and
/// CAP_SETGID), then the permitted/effective/inheritable sets.
unsafe fn drop_capabilities(switch: Option<(u32, u32)>) -> io::Result<()> {
    // PR_CAP_AMBIENT = 47, PR_CAP_AMBIENT_CLEAR_ALL = 4
    libc::prctl(47, 4, 0, 0, 0);
    for cap in 0..64 {
        libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
    }
    if let Some((uid, gid)) = switch {
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setgid(gid) != 0
            || libc::setuid(uid) != 0
        {
            return Err(last());
        }
    }
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let hdr = Header {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if libc::syscall(libc::SYS_capset, &hdr as *const Header, data.as_ptr()) != 0 {
        return Err(last());
    }
    Ok(())
}

unsafe fn build_root(p: &Prepared, ruleset_fd: Option<i32>) -> io::Result<()> {
    mnt(
        std::ptr::null(),
        c"/".as_ptr(),
        std::ptr::null(),
        libc::MS_REC | libc::MS_PRIVATE,
        std::ptr::null(),
    )?;
    mnt(
        c"tmpfs".as_ptr(),
        p.stage.as_ptr(),
        c"tmpfs".as_ptr(),
        libc::MS_NOSUID | libc::MS_NODEV,
        c"mode=0755,size=4m".as_ptr() as *const libc::c_void,
    )?;
    for d in &p.dirs {
        if libc::mkdir(d.as_ptr(), 0o755) != 0 && *libc::__errno_location() != libc::EEXIST {
            return Err(last());
        }
    }
    for f in &p.files {
        let fd = libc::open(
            f.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
            0o644,
        );
        if fd < 0 {
            return Err(last());
        }
        libc::close(fd);
    }
    for b in &p.binds {
        mnt(
            b.src.as_ptr(),
            b.dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )?;
        if let Some(flags) = b.remount {
            mnt(
                std::ptr::null(),
                b.dst.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | flags,
                std::ptr::null(),
            )?;
        }
    }
    if let Some(proc_dst) = &p.proc_dst {
        mnt(
            c"proc".as_ptr(),
            proc_dst.as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )?;
    }
    // pivot_root(".", ".") then detach the old root.
    if libc::chdir(p.stage.as_ptr()) != 0 {
        return Err(last());
    }
    let dot = c".".as_ptr();
    if libc::syscall(libc::SYS_pivot_root, dot, dot) != 0 {
        return Err(last());
    }
    if libc::umount2(dot, libc::MNT_DETACH) != 0 {
        return Err(last());
    }
    if libc::chdir(c"/".as_ptr()) != 0 {
        return Err(last());
    }
    // The command's working directory, if the policy granted it.
    let _ = libc::chdir(p.cwd.as_ptr());
    // The fresh /proc is a new mount, so its Landlock rule can only be added
    // now that it exists.
    if let (Some((path, rights)), Some(fd)) = (&p.proc_rule, ruleset_fd) {
        crate::landlock::add_path_raw(fd, path, *rights)?;
    }
    Ok(())
}

/// Enter the namespaces and build the private root. Returns `Ok` only in the
/// process that will `exec` the command (pid 1 of the new pid namespace); the
/// intermediate process never returns.
///
/// # Safety
/// Must be called between `fork` and `exec` (e.g. from `pre_exec`); performs
/// only async-signal-safe operations on data owned by `p`.
pub unsafe fn enter(p: &Prepared, ruleset_fd: Option<i32>) -> io::Result<()> {
    libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
    if libc::unshare(p.flags) != 0 {
        return Err(last());
    }
    if p.userns {
        write_file(b"/proc/self/setgroups\0", b"deny")?;
        let mut buf = [0u8; 48];
        let n = p.uid_map.len().min(buf.len());
        buf[..n].copy_from_slice(&p.uid_map[..n]);
        write_file(b"/proc/self/uid_map\0", &buf[..n])?;
        let n = p.gid_map.len().min(buf.len());
        buf[..n].copy_from_slice(&p.gid_map[..n]);
        write_file(b"/proc/self/gid_map\0", &buf[..n])?;
    }

    let pid = libc::fork();
    if pid < 0 {
        return Err(last());
    }
    if pid > 0 {
        forward(pid);
    }
    build_root(p, ruleset_fd)?;
    if p.lo_up {
        bring_up_lo();
    }
    drop_capabilities(p.switch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_lines_are_formatted_without_allocation() {
        let mut b = [0u8; 48];
        let n = fmt_map(1000, &mut b);
        assert_eq!(&b[..n], b"1000 1000 1\n");
        let n = fmt_map(0, &mut b);
        assert_eq!(&b[..n], b"0 0 1\n");
        let n = fmt_map(4_294_967_294, &mut b);
        assert_eq!(&b[..n], b"4294967294 4294967294 1\n");
    }

    #[test]
    fn net_isolation_only_when_no_tcp_is_granted() {
        let mut p = Policy::default();
        // Deny-by-default: a bare policy denies both connect and bind, so it
        // gets its own empty network namespace under isolation too.
        assert!(wants_net_isolation(&p));
        p.tcp_connect = TcpRule::Ports(vec![443]);
        assert!(!wants_net_isolation(&p));
        p.tcp_connect = TcpRule::Deny;
        assert!(wants_net_isolation(&p));
        p.tcp_bind = TcpRule::Ports(vec![8080]);
        assert!(!wants_net_isolation(&p));
    }

    #[test]
    fn probe_gives_a_verdict_or_a_reason() {
        match userns_status(None) {
            Ok(()) => {}
            Err(why) => assert!(!why.is_empty()),
        }
    }

    #[test]
    fn prepare_plans_binds_and_removes_its_staging_dir_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        let rw = dir.path().join("rw");
        std::fs::create_dir(&ro).unwrap();
        std::fs::create_dir(&rw).unwrap();
        let file = ro.join("f.txt");
        std::fs::write(&file, "x").unwrap();

        let p = Policy {
            read: vec![ro.clone(), file.clone(), dir.path().join("missing")],
            write: vec![rw.clone()],
            tcp_connect: TcpRule::Deny,
            tcp_bind: TcpRule::Deny,
            ..Default::default()
        };
        let mut notes = Vec::new();
        let prepared = prepare(&p, 0, &mut notes).unwrap();
        let stage = prepared.stage_path().to_path_buf();
        assert!(stage.is_dir());
        assert!(prepared.newnet());
        assert_eq!(prepared.binds.len(), 3, "ro dir + ro file + rw dir");
        assert_eq!(prepared.files.len(), 1);
        assert!(notes.iter().any(|n| n.contains("missing")));
        // Shallow targets are created first.
        let depth: Vec<usize> = prepared
            .dirs
            .iter()
            .map(|d| Path::new(d.to_str().unwrap()).components().count())
            .collect();
        assert!(depth.windows(2).all(|w| w[0] <= w[1]));
        // Read-only binds remount read-only; the writable bind does not.
        let ro_flag = |b: &Bind| b.remount.is_some_and(|f| f & libc::MS_RDONLY != 0);
        assert!(prepared.binds.iter().filter(|b| ro_flag(b)).count() == 2);
        drop(prepared);
        assert!(!stage.exists(), "staging dir must be removed on drop");
    }

    #[test]
    fn relative_policy_paths_are_rejected() {
        let p = Policy {
            read: vec!["relative/path".into()],
            ..Default::default()
        };
        let mut notes = Vec::new();
        assert!(prepare(&p, 0, &mut notes).is_err());
    }
}
