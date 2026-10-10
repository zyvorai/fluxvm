// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! A userspace Ethernet switch for one private network of `vz` guests.
//!
//! Virtualization.framework's NAT keeps guests from reaching each other. A guest that joins a private network gets a
//! second network card backed by `VZFileHandleNetworkDeviceAttachment`: one end of a `SOCK_DGRAM` socket pair carries
//! its Ethernet frames, one frame per datagram. The runner connects to this switch's Unix stream socket, sends a
//! [`Hello`] line and passes the other end of the pair with `SCM_RIGHTS`; the switch then reads and writes the guest's
//! frames directly. The stream stays open for as long as the port exists.
//!
//! Every port has exactly one MAC address, assigned by the daemon. Frames from any other source address are dropped
//! (no spoofing), unicast goes only to the port owning the destination, unknown unicast is dropped, and broadcast and
//! multicast go to every other port. One process serves one network, so networks cannot see each other.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Largest frame accepted: a 1500-byte MTU frame plus headroom for VLAN tags. Bigger datagrams are dropped.
pub const MAX_FRAME: usize = 1600;
const ETH_HEADER: usize = 14;

/// The first line a runner sends on the stream, together with the frame socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub vm: String,
    pub mac: String,
}

pub type Mac = [u8; 6];

pub fn parse_mac(s: &str) -> Option<Mac> {
    let parts: Vec<u8> = s
        .split(':')
        .map(|h| {
            (h.len() == 2)
                .then(|| u8::from_str_radix(h, 16).ok())
                .flatten()
        })
        .collect::<Option<_>>()?;
    let mac: Mac = parts.try_into().ok()?;
    // A port's own address must be unicast.
    (mac[0] & 1 == 0 && mac != [0; 6]).then_some(mac)
}

/// Where a frame from `from` goes. `Err` names why it is dropped.
pub fn targets(ports: &[(u64, Mac)], from: u64, frame: &[u8]) -> Result<Vec<u64>, &'static str> {
    if frame.len() < ETH_HEADER {
        return Err("runt frame");
    }
    if frame.len() > MAX_FRAME {
        return Err("oversized frame");
    }
    let own = ports
        .iter()
        .find(|(id, _)| *id == from)
        .map(|(_, m)| *m)
        .ok_or("unknown port")?;
    if frame[6..12] != own {
        return Err("spoofed source address");
    }
    let dst = &frame[0..6];
    if dst[0] & 1 == 1 {
        return Ok(ports
            .iter()
            .filter(|(id, _)| *id != from)
            .map(|(id, _)| *id)
            .collect());
    }
    match ports.iter().find(|(id, m)| *id != from && m == dst) {
        Some((id, _)) => Ok(vec![*id]),
        None => Err("unknown destination"),
    }
}

struct Port {
    id: u64,
    vm: String,
    mac: Mac,
    frames: OwnedFd,
    closed: AtomicBool,
}

#[derive(Default)]
struct Table {
    ports: RwLock<Vec<Arc<Port>>>,
    next: AtomicU64,
}

impl Table {
    fn snapshot(&self) -> Vec<Arc<Port>> {
        self.ports.read().unwrap().clone()
    }

    /// Adds a port, replacing an older one with the same MAC (a runner that reconnected).
    fn add(&self, vm: String, mac: Mac, frames: OwnedFd) -> Arc<Port> {
        let port = Arc::new(Port {
            id: self.next.fetch_add(1, Ordering::Relaxed),
            vm,
            mac,
            frames,
            closed: AtomicBool::new(false),
        });
        let mut ports = self.ports.write().unwrap();
        for old in ports.iter().filter(|p| p.mac == mac) {
            old.closed.store(true, Ordering::Relaxed);
        }
        ports.retain(|p| p.mac != mac);
        ports.push(port.clone());
        port
    }

    fn remove(&self, id: u64) {
        let mut ports = self.ports.write().unwrap();
        for p in ports.iter().filter(|p| p.id == id) {
            p.closed.store(true, Ordering::Relaxed);
        }
        ports.retain(|p| p.id != id);
    }

    fn is_empty(&self) -> bool {
        self.ports.read().unwrap().is_empty()
    }
}

/// Reads one line and the descriptor passed with it.
pub fn recv_hello(stream: &UnixStream) -> Result<(Hello, OwnedFd)> {
    let mut buf = [0u8; 1024];
    let mut cmsg = [0u8; 64];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = cmsg.len() as _;
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error()).context("recvmsg");
    }
    let mut fd: Option<OwnedFd> = None;
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c) as *const RawFd;
                let count =
                    ((*c).cmsg_len as usize - (data as usize - c as usize)) / size_of::<RawFd>();
                for i in 0..count {
                    let raw = std::ptr::read_unaligned(data.add(i));
                    let owned = OwnedFd::from_raw_fd(raw);
                    // Keep the first; any extra descriptors are closed when dropped.
                    if fd.is_none() {
                        fd = Some(owned);
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    let fd = fd.context("no frame socket was passed")?;
    let line = &buf[..n as usize];
    let line = line.split(|b| *b == b'\n').next().unwrap_or_default();
    let hello: Hello = serde_json::from_slice(line).context("parsing the hello line")?;
    Ok((hello, fd))
}

/// The switch's reply once a port is registered. The sender must keep its copy of the frame socket open until then:
/// macOS may garbage-collect a socket that is closed while it is still in flight.
pub const ACK: &[u8] = b"ok\n";

/// Waits for [`ACK`].
pub fn wait_ack(stream: &UnixStream) -> Result<()> {
    let mut b = [0u8; 3];
    (&*stream)
        .read_exact(&mut b)
        .context("waiting for the switch")?;
    if b != *ACK {
        bail!("unexpected reply from the switch");
    }
    Ok(())
}

/// Sends `hello` and `fd` the way the runner does (used by tests and tools).
pub fn send_hello(stream: &UnixStream, hello: &Hello, fd: RawFd) -> Result<()> {
    let mut line = serde_json::to_vec(hello)?;
    line.push(b'\n');
    let mut iov = libc::iovec {
        iov_base: line.as_mut_ptr().cast(),
        iov_len: line.len(),
    };
    let space = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut cmsg = vec![0u8; space];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut RawFd, fd);
    }
    if unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, 0) } < 0 {
        return Err(std::io::Error::last_os_error()).context("sendmsg");
    }
    Ok(())
}

fn pump(table: Arc<Table>, port: Arc<Port>) {
    let mut buf = vec![0u8; 65536];
    let fd = port.frames.as_raw_fd();
    while !port.closed.load(Ordering::Relaxed) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut pfd, 1, 500) };
        if r <= 0 {
            continue;
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
            && pfd.revents & libc::POLLIN == 0
        {
            break;
        }
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n == 0 {
            break;
        }
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
                continue;
            }
            break;
        }
        let frame = &buf[..n as usize];
        let ports = table.snapshot();
        let ids: Vec<(u64, Mac)> = ports.iter().map(|p| (p.id, p.mac)).collect();
        match targets(&ids, port.id, frame) {
            Ok(to) => {
                for p in ports.iter().filter(|p| to.contains(&p.id)) {
                    // A full receiver drops the frame, as a real switch would; TCP retransmits.
                    unsafe {
                        libc::send(
                            p.frames.as_raw_fd(),
                            frame.as_ptr().cast(),
                            frame.len(),
                            libc::MSG_DONTWAIT,
                        )
                    };
                }
            }
            Err(why) if why == "spoofed source address" => {
                eprintln!("fluxvm-vz-switch: dropped a frame from {} ({why})", port.vm);
            }
            Err(_) => {}
        }
    }
    table.remove(port.id);
}

fn serve_port(table: Arc<Table>, stream: UnixStream) -> Result<()> {
    let (hello, fd) = recv_hello(&stream)?;
    let mac = parse_mac(&hello.mac).with_context(|| format!("bad MAC {:?}", hello.mac))?;
    let mut ty: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut ty as *mut libc::c_int).cast(),
            &mut len,
        )
    } != 0
        || ty != libc::SOCK_DGRAM
    {
        bail!(
            "the frame socket from {} is not a datagram socket",
            hello.vm
        );
    }
    let port = table.add(hello.vm.clone(), mac, fd);
    (&stream).write_all(ACK).context("acknowledging the join")?;
    eprintln!("fluxvm-vz-switch: {} joined as {}", hello.vm, hello.mac);
    let pumping = {
        let (table, port) = (table.clone(), port.clone());
        std::thread::spawn(move || pump(table, port))
    };
    // The port lives as long as the runner keeps the stream open.
    let mut sink = [0u8; 64];
    let mut reader = BufReader::new(&stream);
    loop {
        match reader.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if port.closed.load(Ordering::Relaxed) {
            break;
        }
    }
    let _ = reader.fill_buf();
    table.remove(port.id);
    let _ = pumping.join();
    eprintln!("fluxvm-vz-switch: {} left", hello.vm);
    Ok(())
}

/// Serves the network on `socket` until no guest has been connected for `idle`.
pub fn serve(socket: &Path, idle: Duration) -> Result<()> {
    if socket.exists() {
        if UnixStream::connect(socket).is_ok() {
            eprintln!("fluxvm-vz-switch: {} is already served", socket.display());
            return Ok(());
        }
        std::fs::remove_file(socket)
            .with_context(|| format!("removing stale {}", socket.display()))?;
    }
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let listener = match UnixListener::bind(socket) {
        Ok(l) => l,
        // Another switch for this network won the race.
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("binding {}", socket.display())),
    };
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    }
    listener.set_nonblocking(true)?;
    let table = Arc::new(Table::default());
    let mut last_busy = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                let table = table.clone();
                std::thread::spawn(move || {
                    if let Err(e) = serve_port(table, stream) {
                        eprintln!("fluxvm-vz-switch: {e:#}");
                    }
                });
                last_busy = Instant::now();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e).context("accepting"),
        }
        if !table.is_empty() {
            last_busy = Instant::now();
        } else if last_busy.elapsed() >= idle {
            let _ = std::fs::remove_file(socket);
            return Ok(());
        }
    }
}

/// `vm id -> mac` of the ports currently connected (for tests and diagnostics).
pub fn describe(ports: &[(String, Mac)]) -> HashMap<String, String> {
    ports
        .iter()
        .map(|(vm, m)| {
            (
                vm.clone(),
                m.iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Mac = [2, 0, 0, 0, 0, 0xa];
    const B: Mac = [2, 0, 0, 0, 0, 0xb];
    const C: Mac = [2, 0, 0, 0, 0, 0xc];

    fn frame(dst: Mac, src: Mac) -> Vec<u8> {
        let mut f = dst.to_vec();
        f.extend(src);
        f.extend([0x08, 0x00]);
        f.extend([0u8; 46]);
        f
    }

    #[test]
    fn unicast_goes_to_its_owner_broadcast_to_everyone_else() {
        let ports = [(1, A), (2, B), (3, C)];
        assert_eq!(targets(&ports, 1, &frame(B, A)), Ok(vec![2]));
        assert_eq!(targets(&ports, 1, &frame([0xff; 6], A)), Ok(vec![2, 3]));
        let multicast = [0x01, 0x00, 0x5e, 0, 0, 1];
        assert_eq!(targets(&ports, 3, &frame(multicast, C)), Ok(vec![1, 2]));
        assert_eq!(
            targets(&ports, 1, &frame([2, 9, 9, 9, 9, 9], A)),
            Err("unknown destination")
        );
        assert_eq!(targets(&ports, 1, &frame(A, A)), Err("unknown destination"));
    }

    #[test]
    fn spoofed_runt_and_oversized_frames_are_dropped() {
        let ports = [(1, A), (2, B)];
        assert_eq!(
            targets(&ports, 1, &frame(B, C)),
            Err("spoofed source address")
        );
        assert_eq!(
            targets(&ports, 1, &frame(B, B)),
            Err("spoofed source address")
        );
        assert_eq!(targets(&ports, 1, &[0u8; 10]), Err("runt frame"));
        assert_eq!(
            targets(&ports, 1, &vec![0u8; MAX_FRAME + 1]),
            Err("oversized frame")
        );
    }

    #[test]
    fn macs_must_be_unicast_and_well_formed() {
        assert_eq!(parse_mac("02:00:00:00:00:0a"), Some(A));
        assert_eq!(parse_mac("03:00:00:00:00:0a"), None);
        assert_eq!(parse_mac("00:00:00:00:00:00"), None);
        assert_eq!(parse_mac("02:00:00:00:00"), None);
        assert_eq!(parse_mac("02:00:00:00:00:0g"), None);
        assert_eq!(parse_mac("2:00:00:00:00:0a"), None);
    }

    fn dgram_pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) },
            0
        );
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn recv_timeout(fd: &OwnedFd, ms: i32) -> Option<Vec<u8>> {
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, ms) } <= 0 {
            return None;
        }
        let mut b = vec![0u8; 2048];
        let n = unsafe { libc::recv(fd.as_raw_fd(), b.as_mut_ptr().cast(), b.len(), 0) };
        (n > 0).then(|| b[..n as usize].to_vec())
    }

    #[track_caller]
    fn send(fd: &OwnedFd, f: &[u8]) {
        let n = unsafe { libc::send(fd.as_raw_fd(), f.as_ptr().cast(), f.len(), 0) };
        assert!(n > 0, "send: {}", std::io::Error::last_os_error());
    }

    /// Joins `mac` to the switch at `sock`; returns the guest's end of the frame socket and the control stream.
    fn join(sock: &Path, vm: &str, mac: Mac) -> (OwnedFd, UnixStream) {
        let (guest, switch_end) = dgram_pair();
        let stream = UnixStream::connect(sock).unwrap();
        let hello = Hello {
            vm: vm.into(),
            mac: describe(&[(vm.into(), mac)])[vm].clone(),
        };
        send_hello(&stream, &hello, switch_end.as_raw_fd()).unwrap();
        wait_ack(&stream).unwrap();
        (guest, stream)
    }

    #[test]
    fn guests_exchange_frames_through_a_running_switch_and_leave_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("net.sock");
        let s = sock.clone();
        let server = std::thread::spawn(move || serve(&s, Duration::from_millis(1500)).unwrap());
        for _ in 0..50 {
            if UnixStream::connect(&sock).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let (a, a_ctl) = join(&sock, "a", A);
        let (b, _b_ctl) = join(&sock, "b", B);
        let (c, _c_ctl) = join(&sock, "c", C);
        std::thread::sleep(Duration::from_millis(200));

        send(&a, &frame(B, A));
        assert_eq!(recv_timeout(&b, 1000), Some(frame(B, A)));
        assert_eq!(recv_timeout(&c, 200), None, "unicast reached a third guest");

        send(&c, &frame([0xff; 6], C));
        assert_eq!(recv_timeout(&a, 1000), Some(frame([0xff; 6], C)));
        assert_eq!(recv_timeout(&b, 1000), Some(frame([0xff; 6], C)));

        send(&a, &frame(B, C));
        assert_eq!(recv_timeout(&b, 300), None, "a spoofed frame was delivered");

        drop(a_ctl);
        std::thread::sleep(Duration::from_millis(700));
        send(&b, &frame(A, B));
        assert_eq!(
            recv_timeout(&a, 300),
            None,
            "a guest that left still got frames"
        );

        // A second switch on the same socket defers to the running one.
        serve(&sock, Duration::from_millis(10)).unwrap();
        drop((_b_ctl, _c_ctl));
        server.join().unwrap();
        assert!(!sock.exists(), "an idle switch removes its socket");
    }
}
