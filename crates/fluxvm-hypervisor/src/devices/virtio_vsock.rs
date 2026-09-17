// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Firecracker-style virtio-vsock over MMIO (unix host backend).
//!
//! Host apps connect to `uds_path` and send `CONNECT <guest_port>\n`; the
//! device replies `OK <host_port>\n` once the guest accepts, then bridges a
//! raw byte stream. Guest sees AF_VSOCK with `guest_cid`.
//!
//! MVP: host-initiated connections only (guest-agent ping/exec). Guest→host
//! `uds_path_<port>` muxer is deferred.

use crate::devices::virtio_mmio::VirtioState;
use crate::error::Result;
use crate::memory::GuestMemory;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

/// Host CID in virtio-vsock (Linux UAPI).
pub const VSOCK_HOST_CID: u32 = 2;

pub const VSOCK_TYPE_STREAM: u16 = 1;

pub const VSOCK_OP_INVALID: u16 = 0;
pub const VSOCK_OP_REQUEST: u16 = 1;
pub const VSOCK_OP_RESPONSE: u16 = 2;
pub const VSOCK_OP_RST: u16 = 3;
pub const VSOCK_OP_SHUTDOWN: u16 = 4;
pub const VSOCK_OP_RW: u16 = 5;
pub const VSOCK_OP_CREDIT_UPDATE: u16 = 6;
pub const VSOCK_OP_CREDIT_REQUEST: u16 = 7;

/// Default host receive buffer advertised to the guest (Firecracker-scale).
pub const DEFAULT_BUF_ALLOC: u32 = 128 * 1024;

const HDR_LEN: usize = 44;
const MAX_RW_CHUNK: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VsockHeader {
    pub src_cid: u64,
    pub dst_cid: u64,
    pub src_port: u32,
    pub dst_port: u32,
    pub len: u32,
    pub type_: u16,
    pub op: u16,
    pub flags: u32,
    pub buf_alloc: u32,
    pub fwd_cnt: u32,
}

impl VsockHeader {
    pub fn encode(self) -> [u8; HDR_LEN] {
        let mut b = [0u8; HDR_LEN];
        b[0..8].copy_from_slice(&self.src_cid.to_le_bytes());
        b[8..16].copy_from_slice(&self.dst_cid.to_le_bytes());
        b[16..20].copy_from_slice(&self.src_port.to_le_bytes());
        b[20..24].copy_from_slice(&self.dst_port.to_le_bytes());
        b[24..28].copy_from_slice(&self.len.to_le_bytes());
        b[28..30].copy_from_slice(&self.type_.to_le_bytes());
        b[30..32].copy_from_slice(&self.op.to_le_bytes());
        b[32..36].copy_from_slice(&self.flags.to_le_bytes());
        b[36..40].copy_from_slice(&self.buf_alloc.to_le_bytes());
        b[40..44].copy_from_slice(&self.fwd_cnt.to_le_bytes());
        b
    }

    pub fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < HDR_LEN {
            return None;
        }
        Some(Self {
            src_cid: u64::from_le_bytes(raw[0..8].try_into().ok()?),
            dst_cid: u64::from_le_bytes(raw[8..16].try_into().ok()?),
            src_port: u32::from_le_bytes(raw[16..20].try_into().ok()?),
            dst_port: u32::from_le_bytes(raw[20..24].try_into().ok()?),
            len: u32::from_le_bytes(raw[24..28].try_into().ok()?),
            type_: u16::from_le_bytes(raw[28..30].try_into().ok()?),
            op: u16::from_le_bytes(raw[30..32].try_into().ok()?),
            flags: u32::from_le_bytes(raw[32..36].try_into().ok()?),
            buf_alloc: u32::from_le_bytes(raw[36..40].try_into().ok()?),
            fwd_cnt: u32::from_le_bytes(raw[40..44].try_into().ok()?),
        })
    }

    fn ctrl(
        src_cid: u64,
        dst_cid: u64,
        src_port: u32,
        dst_port: u32,
        op: u16,
        buf_alloc: u32,
        fwd_cnt: u32,
    ) -> Self {
        Self {
            src_cid,
            dst_cid,
            src_port,
            dst_port,
            len: 0,
            type_: VSOCK_TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc,
            fwd_cnt,
        }
    }
}

#[derive(Debug)]
struct PendingHost {
    stream: UnixStream,
    buf: Vec<u8>,
}

#[derive(Debug)]
struct Established {
    stream: UnixStream,
    guest_port: u32,
    host_port: u32,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    /// Bytes we have sent to the guest (for credit accounting).
    tx_cnt: u32,
    /// Bytes we have consumed from the guest (fwd_cnt we advertise).
    rx_cnt: u32,
}

#[derive(Debug)]
enum ConnState {
    /// Sent REQUEST to guest; waiting for RESPONSE before OK to host.
    WaitResponse {
        stream: UnixStream,
        guest_port: u32,
        host_port: u32,
    },
    Established(Established),
}

pub struct VsockBackend {
    pub uds_path: PathBuf,
    pub guest_cid: u32,
    inner: Mutex<VsockInner>,
}

struct VsockInner {
    listener: Option<UnixListener>,
    pending_hosts: Vec<PendingHost>,
    conns: HashMap<u32, ConnState>,
    /// Packets waiting to be placed on the guest RX queue.
    rx_q: VecDeque<Vec<u8>>,
    next_host_port: u32,
    host_buf_alloc: u32,
}

fn push_pkt(rx_q: &mut VecDeque<Vec<u8>>, hdr: VsockHeader, payload: &[u8]) {
    let mut pkt = hdr.encode().to_vec();
    pkt.extend_from_slice(payload);
    rx_q.push_back(pkt);
}

impl VsockBackend {
    pub fn new(uds_path: &Path, guest_cid: u32) -> Result<Self> {
        let _ = std::fs::remove_file(uds_path);
        if let Some(parent) = uds_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let listener = {
            let l = UnixListener::bind(uds_path).map_err(|e| {
                crate::error::FluxError::Hypervisor(format!(
                    "vsock uds bind {}: {e}",
                    uds_path.display()
                ))
            })?;
            l.set_nonblocking(true).ok();
            Some(l)
        };
        Ok(Self {
            uds_path: uds_path.to_path_buf(),
            guest_cid: guest_cid.max(3),
            inner: Mutex::new(VsockInner {
                listener,
                pending_hosts: Vec::new(),
                conns: HashMap::new(),
                rx_q: VecDeque::new(),
                next_host_port: 50000,
                host_buf_alloc: DEFAULT_BUF_ALLOC,
            }),
        })
    }

    /// Accept UDS clients, parse CONNECT, enqueue virtio REQUEST packets, and
    /// shuttle host→guest RW for established connections.
    pub fn poll_host(&self) -> u32 {
        let mut inner = self.inner.lock().unwrap();
        let mut work = 0u32;
        work += inner.accept_pending();
        work += inner.drain_connect_lines(self.guest_cid);
        work += inner.poll_established_host_reads(self.guest_cid);
        work
    }
}

impl VsockInner {
    fn accept_pending(&mut self) -> u32 {
        let Some(listener) = self.listener.as_ref() else {
            return 0;
        };
        let mut n = 0u32;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(true);
                    self.pending_hosts.push(PendingHost {
                        stream,
                        buf: Vec::new(),
                    });
                    n += 1;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        n
    }

    fn drain_connect_lines(&mut self, guest_cid: u32) -> u32 {
        let mut n = 0u32;
        let mut i = 0;
        while i < self.pending_hosts.len() {
            let pending = &mut self.pending_hosts[i];
            let mut tmp = [0u8; 256];
            match pending.stream.read(&mut tmp) {
                Ok(0) => {
                    self.pending_hosts.remove(i);
                    continue;
                }
                Ok(k) => pending.buf.extend_from_slice(&tmp[..k]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    i += 1;
                    continue;
                }
                Err(_) => {
                    self.pending_hosts.remove(i);
                    continue;
                }
            }
            if let Some(nl) = self.pending_hosts[i].buf.iter().position(|&b| b == b'\n') {
                let line = String::from_utf8_lossy(&self.pending_hosts[i].buf[..=nl]).to_string();
                let PendingHost { stream, .. } = self.pending_hosts.remove(i);
                if let Some(port) = parse_connect(&line) {
                    let host_port = self.alloc_host_port();
                    let hdr = VsockHeader::ctrl(
                        VSOCK_HOST_CID as u64,
                        guest_cid as u64,
                        host_port,
                        port,
                        VSOCK_OP_REQUEST,
                        self.host_buf_alloc,
                        0,
                    );
                    push_pkt(&mut self.rx_q, hdr, &[]);
                    self.conns.insert(
                        host_port,
                        ConnState::WaitResponse {
                            stream,
                            guest_port: port,
                            host_port,
                        },
                    );
                    n += 1;
                }
                continue;
            }
            if self.pending_hosts[i].buf.len() > 128 {
                self.pending_hosts.remove(i);
                continue;
            }
            i += 1;
        }
        n
    }

    fn alloc_host_port(&mut self) -> u32 {
        for _ in 0..10_000 {
            let p = self.next_host_port;
            self.next_host_port = self.next_host_port.wrapping_add(1).max(1024);
            if !self.conns.contains_key(&p) {
                return p;
            }
        }
        self.next_host_port
    }

    fn poll_established_host_reads(&mut self, guest_cid: u32) -> u32 {
        let mut n = 0u32;
        let keys: Vec<u32> = self.conns.keys().copied().collect();
        let host_buf_alloc = self.host_buf_alloc;

        for host_port in keys {
            enum Action {
                CreditRequest { hp: u32, gp: u32, rx: u32 },
                Shutdown { hp: u32, gp: u32, rx: u32 },
                Rst { hp: u32, gp: u32, rx: u32 },
                Rw {
                    hp: u32,
                    gp: u32,
                    rx: u32,
                    data: Vec<u8>,
                },
                None,
            }

            let action = {
                let Some(ConnState::Established(est)) = self.conns.get_mut(&host_port) else {
                    continue;
                };
                let credit = est
                    .peer_buf_alloc
                    .saturating_sub(est.tx_cnt.wrapping_sub(est.peer_fwd_cnt));
                if credit == 0 {
                    Action::CreditRequest {
                        hp: est.host_port,
                        gp: est.guest_port,
                        rx: est.rx_cnt,
                    }
                } else {
                    let mut buf = vec![0u8; MAX_RW_CHUNK.min(credit as usize).max(1)];
                    match est.stream.read(&mut buf) {
                        Ok(0) => Action::Shutdown {
                            hp: est.host_port,
                            gp: est.guest_port,
                            rx: est.rx_cnt,
                        },
                        Ok(k) => {
                            buf.truncate(k);
                            Action::Rw {
                                hp: est.host_port,
                                gp: est.guest_port,
                                rx: est.rx_cnt,
                                data: buf,
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Action::None,
                        Err(_) => Action::Rst {
                            hp: est.host_port,
                            gp: est.guest_port,
                            rx: est.rx_cnt,
                        },
                    }
                }
            };

            match action {
                Action::None => {}
                Action::CreditRequest { hp, gp, rx } => {
                    let hdr = VsockHeader::ctrl(
                        VSOCK_HOST_CID as u64,
                        guest_cid as u64,
                        hp,
                        gp,
                        VSOCK_OP_CREDIT_REQUEST,
                        host_buf_alloc,
                        rx,
                    );
                    push_pkt(&mut self.rx_q, hdr, &[]);
                    n += 1;
                }
                Action::Shutdown { hp, gp, rx } => {
                    let mut hdr = VsockHeader::ctrl(
                        VSOCK_HOST_CID as u64,
                        guest_cid as u64,
                        hp,
                        gp,
                        VSOCK_OP_SHUTDOWN,
                        host_buf_alloc,
                        rx,
                    );
                    hdr.flags = 3;
                    push_pkt(&mut self.rx_q, hdr, &[]);
                    self.conns.remove(&host_port);
                    n += 1;
                }
                Action::Rst { hp, gp, rx } => {
                    let hdr = VsockHeader::ctrl(
                        VSOCK_HOST_CID as u64,
                        guest_cid as u64,
                        hp,
                        gp,
                        VSOCK_OP_RST,
                        host_buf_alloc,
                        rx,
                    );
                    push_pkt(&mut self.rx_q, hdr, &[]);
                    self.conns.remove(&host_port);
                    n += 1;
                }
                Action::Rw { hp, gp, rx, data } => {
                    let k = data.len() as u32;
                    let hdr = VsockHeader {
                        src_cid: VSOCK_HOST_CID as u64,
                        dst_cid: guest_cid as u64,
                        src_port: hp,
                        dst_port: gp,
                        len: k,
                        type_: VSOCK_TYPE_STREAM,
                        op: VSOCK_OP_RW,
                        flags: 0,
                        buf_alloc: host_buf_alloc,
                        fwd_cnt: rx,
                    };
                    push_pkt(&mut self.rx_q, hdr, &data);
                    if let Some(ConnState::Established(est)) = self.conns.get_mut(&host_port) {
                        est.tx_cnt = est.tx_cnt.wrapping_add(k);
                    }
                    n += 1;
                }
            }
        }
        n
    }

    fn handle_guest_packet(&mut self, guest_cid: u32, hdr: VsockHeader, payload: &[u8]) -> u32 {
        let mut n = 0u32;
        let host_buf_alloc = self.host_buf_alloc;

        match hdr.op {
            VSOCK_OP_RESPONSE => {
                if let Some(ConnState::WaitResponse {
                    stream,
                    guest_port,
                    host_port,
                }) = self.conns.remove(&hdr.dst_port)
                {
                    let gport = if hdr.src_port != 0 {
                        hdr.src_port
                    } else {
                        guest_port
                    };
                    let ack = format!("OK {host_port}\n");
                    let _ = (&stream).write_all(ack.as_bytes());
                    self.conns.insert(
                        host_port,
                        ConnState::Established(Established {
                            stream,
                            guest_port: gport,
                            host_port,
                            peer_buf_alloc: hdr.buf_alloc.max(1),
                            peer_fwd_cnt: hdr.fwd_cnt,
                            tx_cnt: 0,
                            rx_cnt: 0,
                        }),
                    );
                    n += 1;
                }
            }
            VSOCK_OP_RW => {
                let mut follow_up: Option<(u32, u32, u32)> = None; // hp, gp, rx
                let mut kill: Option<(u32, u32)> = None;
                if let Some(ConnState::Established(est)) = self.conns.get_mut(&hdr.dst_port) {
                    if hdr.buf_alloc > 0 {
                        est.peer_buf_alloc = hdr.buf_alloc;
                    }
                    est.peer_fwd_cnt = hdr.fwd_cnt;
                    if !payload.is_empty() {
                        match est.stream.write_all(payload) {
                            Ok(()) => {
                                est.rx_cnt = est.rx_cnt.wrapping_add(payload.len() as u32);
                                follow_up = Some((est.host_port, est.guest_port, est.rx_cnt));
                            }
                            Err(_) => {
                                kill = Some((est.host_port, est.guest_port));
                            }
                        }
                    }
                }
                if let Some((hp, gp)) = kill {
                    self.conns.remove(&hp);
                    let rst = VsockHeader::ctrl(
                        VSOCK_HOST_CID as u64,
                        guest_cid as u64,
                        hp,
                        gp,
                        VSOCK_OP_RST,
                        host_buf_alloc,
                        0,
                    );
                    push_pkt(&mut self.rx_q, rst, &[]);
                    n += 1;
                } else if let Some((hp, gp, rx)) = follow_up {
                    let credit_hdr = VsockHeader::ctrl(
                        VSOCK_HOST_CID as u64,
                        guest_cid as u64,
                        hp,
                        gp,
                        VSOCK_OP_CREDIT_UPDATE,
                        host_buf_alloc,
                        rx,
                    );
                    push_pkt(&mut self.rx_q, credit_hdr, &[]);
                    n += 1;
                }
            }
            VSOCK_OP_CREDIT_UPDATE | VSOCK_OP_CREDIT_REQUEST => {
                let mut reply: Option<(u32, u32, u32)> = None;
                if let Some(ConnState::Established(est)) = self.conns.get_mut(&hdr.dst_port) {
                    if hdr.buf_alloc > 0 {
                        est.peer_buf_alloc = hdr.buf_alloc;
                    }
                    est.peer_fwd_cnt = hdr.fwd_cnt;
                    if hdr.op == VSOCK_OP_CREDIT_REQUEST {
                        reply = Some((est.host_port, est.guest_port, est.rx_cnt));
                    }
                }
                if let Some((hp, gp, rx)) = reply {
                    let upd = VsockHeader::ctrl(
                        VSOCK_HOST_CID as u64,
                        guest_cid as u64,
                        hp,
                        gp,
                        VSOCK_OP_CREDIT_UPDATE,
                        host_buf_alloc,
                        rx,
                    );
                    push_pkt(&mut self.rx_q, upd, &[]);
                    n += 1;
                }
            }
            VSOCK_OP_SHUTDOWN | VSOCK_OP_RST => {
                self.conns.remove(&hdr.dst_port);
                if hdr.op == VSOCK_OP_SHUTDOWN {
                    let rst = VsockHeader::ctrl(
                        VSOCK_HOST_CID as u64,
                        guest_cid as u64,
                        hdr.dst_port,
                        hdr.src_port,
                        VSOCK_OP_RST,
                        host_buf_alloc,
                        0,
                    );
                    push_pkt(&mut self.rx_q, rst, &[]);
                    n += 1;
                }
            }
            VSOCK_OP_REQUEST => {
                let rst = VsockHeader::ctrl(
                    VSOCK_HOST_CID as u64,
                    guest_cid as u64,
                    hdr.dst_port,
                    hdr.src_port,
                    VSOCK_OP_RST,
                    host_buf_alloc,
                    0,
                );
                push_pkt(&mut self.rx_q, rst, &[]);
                n += 1;
            }
            _ => {
                let _ = VSOCK_OP_INVALID;
            }
        }
        n
    }
}

fn parse_connect(line: &str) -> Option<u32> {
    let line = line.trim();
    let rest = line
        .strip_prefix("CONNECT ")
        .or_else(|| line.strip_prefix("connect "))?;
    rest.trim().parse().ok()
}

fn used_push(
    mem: &mut GuestMemory,
    used_gpa: u64,
    qnum: u32,
    desc_id: u16,
    written: u32,
) -> Result<()> {
    let idx = mem.read_u16(used_gpa + 2)?;
    let slot = (idx as u32) % qnum;
    let elem = used_gpa + 4 + slot as u64 * 8;
    mem.write_at(elem, &(desc_id as u32).to_le_bytes())?;
    mem.write_at(elem + 4, &written.to_le_bytes())?;
    mem.write_u16(used_gpa + 2, idx.wrapping_add(1))?;
    Ok(())
}

fn gather_tx(mem: &GuestMemory, desc_base: u64, head: u16) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut idx = head;
    for _ in 0..32 {
        let mut raw = [0u8; 16];
        mem.read_at(desc_base + idx as u64 * 16, &mut raw)?;
        let addr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let flags = u16::from_le_bytes(raw[12..14].try_into().unwrap());
        let next = u16::from_le_bytes(raw[14..16].try_into().unwrap());
        if flags & VRING_DESC_F_WRITE == 0 {
            let mut buf = vec![0u8; len as usize];
            mem.read_at(addr, &mut buf)?;
            out.extend_from_slice(&buf);
        }
        if flags & VRING_DESC_F_NEXT == 0 {
            break;
        }
        idx = next;
    }
    Ok(out)
}

fn inject_rx_packet(mem: &mut GuestMemory, st: &mut VirtioState, pkt: &[u8]) -> Result<bool> {
    let q = &mut st.queues[0];
    if q.ready == 0 || q.num == 0 {
        return Ok(false);
    }
    let avail_idx = mem.read_u16(q.avail + 2)?;
    if q.last_avail == avail_idx {
        return Ok(false);
    }
    let slot = (q.last_avail as u32) % q.num;
    let head = mem.read_u16(q.avail + 4 + slot as u64 * 2)?;

    let mut remaining = pkt;
    let mut idx = head;
    let mut written = 0u32;
    for _ in 0..32 {
        let mut raw = [0u8; 16];
        mem.read_at(q.desc + idx as u64 * 16, &mut raw)?;
        let addr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        let len = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
        let flags = u16::from_le_bytes(raw[12..14].try_into().unwrap());
        let next = u16::from_le_bytes(raw[14..16].try_into().unwrap());
        if flags & VRING_DESC_F_WRITE != 0 && len > 0 && !remaining.is_empty() {
            let n = remaining.len().min(len);
            mem.write_at(addr, &remaining[..n])?;
            remaining = &remaining[n..];
            written += n as u32;
        }
        if flags & VRING_DESC_F_NEXT == 0 {
            break;
        }
        idx = next;
    }
    used_push(mem, q.used, q.num, head, written)?;
    q.last_avail = q.last_avail.wrapping_add(1);
    Ok(remaining.is_empty())
}

fn flush_rx(backend: &VsockBackend, mem: &mut GuestMemory, st: &mut VirtioState) -> Result<u32> {
    let mut n = 0u32;
    loop {
        let pkt = {
            let mut inner = backend.inner.lock().unwrap();
            inner.rx_q.pop_front()
        };
        let Some(pkt) = pkt else {
            break;
        };
        match inject_rx_packet(mem, st, &pkt)? {
            true => n += 1,
            false => {
                backend.inner.lock().unwrap().rx_q.push_front(pkt);
                break;
            }
        }
    }
    Ok(n)
}

/// Process TX queue (guest→host) and flush pending RX; call after virtio notify
/// or from the VM poll loop.
pub fn handle_notify(
    mem: &mut GuestMemory,
    st: &mut VirtioState,
    qsel: u32,
    backend: Option<&VsockBackend>,
) -> Result<u32> {
    let mut n = 0u32;
    if let Some(be) = backend {
        n += flush_rx(be, mem, st)?;
    }

    if qsel == 1 {
        let q = &st.queues[1];
        if q.ready != 0 && q.num != 0 {
            loop {
                let q = &st.queues[1];
                let avail_idx = mem.read_u16(q.avail + 2)?;
                if q.last_avail == avail_idx {
                    break;
                }
                let slot = (q.last_avail as u32) % q.num;
                let head = mem.read_u16(q.avail + 4 + slot as u64 * 2)?;
                let desc = q.desc;
                let used = q.used;
                let qnum = q.num;
                let pkt = gather_tx(mem, desc, head)?;
                used_push(mem, used, qnum, head, 0)?;
                st.queues[1].last_avail = st.queues[1].last_avail.wrapping_add(1);
                n += 1;
                if let Some(be) = backend {
                    if let Some(hdr) = VsockHeader::decode(&pkt) {
                        let plen = hdr.len.min(pkt.len().saturating_sub(HDR_LEN) as u32) as usize;
                        let payload = if pkt.len() > HDR_LEN {
                            &pkt[HDR_LEN..HDR_LEN + plen]
                        } else {
                            &[]
                        };
                        be.inner
                            .lock()
                            .unwrap()
                            .handle_guest_packet(be.guest_cid, hdr, payload);
                    }
                }
                if n > 64 {
                    break;
                }
            }
        }
    }

    if let Some(be) = backend {
        n += flush_rx(be, mem, st)?;
    }
    Ok(n)
}

/// Host-side poll: accept CONNECT, enqueue REQUEST/RW, flush into guest RX.
pub fn poll(mem: &mut GuestMemory, st: &mut VirtioState, backend: &VsockBackend) -> Result<u32> {
    let mut n = backend.poll_host();
    n += flush_rx(backend, mem, st)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn header_round_trip() {
        let h = VsockHeader {
            src_cid: 2,
            dst_cid: 5,
            src_port: 50001,
            dst_port: 17777,
            len: 3,
            type_: VSOCK_TYPE_STREAM,
            op: VSOCK_OP_RW,
            flags: 0,
            buf_alloc: DEFAULT_BUF_ALLOC,
            fwd_cnt: 9,
        };
        let enc = h.encode();
        assert_eq!(enc.len(), 44);
        let d = VsockHeader::decode(&enc).unwrap();
        assert_eq!(d, h);
    }

    #[test]
    fn parse_connect_line() {
        assert_eq!(parse_connect("CONNECT 17777\n"), Some(17777));
        assert_eq!(parse_connect("connect 9"), Some(9));
        assert!(parse_connect("HELLO 1\n").is_none());
    }

    #[test]
    fn connect_enqueues_request_and_ok_on_response() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("vsock.sock");
        let be = VsockBackend::new(&uds, 5).unwrap();

        let mut client = UnixStream::connect(&uds).unwrap();
        client.set_nonblocking(false).ok();
        client.write_all(b"CONNECT 17777\n").unwrap();

        for _ in 0..50 {
            if be.poll_host() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        let pkt = {
            let mut inner = be.inner.lock().unwrap();
            inner.rx_q.pop_front().expect("REQUEST enqueued")
        };
        let hdr = VsockHeader::decode(&pkt).unwrap();
        assert_eq!(hdr.op, VSOCK_OP_REQUEST);
        assert_eq!(hdr.dst_port, 17777);
        assert_eq!(hdr.src_cid, VSOCK_HOST_CID as u64);
        assert_eq!(hdr.dst_cid, 5);
        let host_port = hdr.src_port;

        let resp = VsockHeader::ctrl(
            5,
            VSOCK_HOST_CID as u64,
            17777,
            host_port,
            VSOCK_OP_RESPONSE,
            DEFAULT_BUF_ALLOC,
            0,
        );
        be.inner.lock().unwrap().handle_guest_packet(5, resp, &[]);

        client.set_read_timeout(Some(Duration::from_secs(1))).ok();
        let mut buf = [0u8; 64];
        let k = client.read(&mut buf).unwrap();
        let ack = std::str::from_utf8(&buf[..k]).unwrap();
        assert!(
            ack.starts_with(&format!("OK {host_port}")),
            "ack={ack:?}"
        );

        client.write_all(b"hi").unwrap();
        for _ in 0..50 {
            if be.poll_host() > 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let rw = be.inner.lock().unwrap().rx_q.pop_front().expect("RW pkt");
        let rh = VsockHeader::decode(&rw).unwrap();
        assert_eq!(rh.op, VSOCK_OP_RW);
        assert_eq!(&rw[44..], b"hi");
    }
}
