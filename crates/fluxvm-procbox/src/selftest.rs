// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Hidden helper operations: `fluxvm-procbox selftest <op> [arg]`.
//!
//! Each op performs one syscall-level action and prints `ok` or
//! `errno=<n>`. The integration tests run these inside the sandbox to observe
//! what the kernel really allows, instead of trusting a shell or a libc wrapper.

/// Run one op; returns the line to print and whether it succeeded.
#[cfg(target_os = "linux")]
pub fn run_op(op: &str, arg: Option<&str>) -> (String, bool) {
    use std::io::{Read, Write};

    fn err(e: std::io::Error) -> (String, bool) {
        (format!("errno={}", e.raw_os_error().unwrap_or(-1)), false)
    }
    fn last() -> (String, bool) {
        err(std::io::Error::last_os_error())
    }
    let ok = || ("ok".to_string(), true);
    let need = |name: &str| arg.ok_or_else(|| format!("op {name} needs an argument"));

    match op {
        "write" => match need(op) {
            Ok(p) => match std::fs::File::create(p).and_then(|mut f| f.write_all(b"x")) {
                Ok(()) => ok(),
                Err(e) => err(e),
            },
            Err(m) => (m, false),
        },
        "read" => match need(op) {
            Ok(p) => {
                let path = std::path::Path::new(p);
                let r = if path.is_dir() {
                    std::fs::read_dir(path).map(|_| ())
                } else {
                    std::fs::File::open(path).and_then(|mut f| f.read(&mut [0u8; 1]).map(|_| ()))
                };
                match r {
                    Ok(()) => ok(),
                    Err(e) => err(e),
                }
            }
            Err(m) => (m, false),
        },
        "connect" => match need(op).and_then(|a| a.parse::<u16>().map_err(|e| e.to_string())) {
            Ok(port) => match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(_) => ok(),
                Err(e) => err(e),
            },
            Err(m) => (m, false),
        },
        "bind" => match need(op).and_then(|a| a.parse::<u16>().map_err(|e| e.to_string())) {
            Ok(port) => match std::net::TcpListener::bind(("127.0.0.1", port)) {
                Ok(_) => ok(),
                Err(e) => err(e),
            },
            Err(m) => (m, false),
        },
        "alloc" => match need(op).and_then(|a| a.parse::<usize>().map_err(|e| e.to_string())) {
            Ok(mib) => unsafe {
                let len = mib << 20;
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if p == libc::MAP_FAILED {
                    return last();
                }
                std::ptr::write_bytes(p as *mut u8, 1, len);
                ok()
            },
            Err(m) => (m, false),
        },
        "ptrace" => {
            let rc = unsafe {
                libc::syscall(libc::SYS_ptrace, 0 /* PTRACE_TRACEME */, 0, 0, 0)
            };
            if rc == 0 {
                ok()
            } else {
                last()
            }
        }
        "keyctl" => {
            // KEYCTL_GET_KEYRING_ID(KEY_SPEC_SESSION_KEYRING, create=0)
            let rc = unsafe { libc::syscall(libc::SYS_keyctl, 0, -3i64, 0) };
            if rc >= 0 {
                ok()
            } else {
                last()
            }
        }
        "pvm" => {
            let mut buf = [0u8; 8];
            let iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_process_vm_readv,
                    libc::getpid(),
                    &iov as *const libc::iovec,
                    1usize,
                    &iov as *const libc::iovec,
                    1usize,
                    0usize,
                )
            };
            if rc >= 0 {
                ok()
            } else {
                last()
            }
        }
        "unshare-user" => {
            let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            if rc == 0 {
                ok()
            } else {
                last()
            }
        }
        "signal-parent" => {
            // SIGURG is ignored by default, so an unconfined delivery is harmless.
            let rc = unsafe { libc::kill(libc::getppid(), libc::SIGURG) };
            if rc == 0 {
                ok()
            } else {
                last()
            }
        }
        "unix-abstract" => match need(op) {
            Ok(name) => unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if fd < 0 {
                    return last();
                }
                let mut addr: libc::sockaddr_un = std::mem::zeroed();
                addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
                let bytes = name.as_bytes();
                for (i, b) in bytes.iter().enumerate() {
                    addr.sun_path[i + 1] = *b as libc::c_char;
                }
                let len =
                    (std::mem::size_of::<libc::sa_family_t>() + 1 + bytes.len()) as libc::socklen_t;
                let rc = libc::connect(fd, &addr as *const _ as *const libc::sockaddr, len);
                let out = if rc == 0 { ok() } else { last() };
                libc::close(fd);
                out
            },
            Err(m) => (m, false),
        },
        "env" => match need(op) {
            Ok(name) => match std::env::var(name) {
                Ok(v) => (format!("value={v}"), true),
                Err(_) => ("unset".to_string(), true),
            },
            Err(m) => (m, false),
        },
        "sleep" => match need(op).and_then(|a| a.parse::<u64>().map_err(|e| e.to_string())) {
            Ok(s) => {
                std::thread::sleep(std::time::Duration::from_secs(s));
                ok()
            }
            Err(m) => (m, false),
        },
        other => (format!("unknown selftest op {other:?}"), false),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn run_op(_op: &str, _arg: Option<&str>) -> (String, bool) {
    ("selftest is Linux-only".to_string(), false)
}
