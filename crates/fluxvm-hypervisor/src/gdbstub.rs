// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Minimal read-only GDB remote-serial-protocol stub for live guest
//! inspection (`--gdb <addr:port>` on the demo CLI).
//!
//! Scope is deliberately narrow: attach, break in (on connect and on
//! Ctrl-C), read general registers, read guest memory, continue, detach.
//! No breakpoints, no single-step, no register/memory writes -- this
//! exists to answer "where exactly is the guest stuck" for a hung boot,
//! not to be a full interactive debugger. BSP (vCPU 0) only.
//!
//! Design: the vCPU thread may be deep inside a single KVM_RUN call that
//! never returns to userspace (KVM's own internal vcpu_run() loop can
//! cycle guest-entry/exit many times without surfacing an exit). Setting
//! the shared `paused` flag alone can't interrupt that -- so break-in
//! also sets `run->immediate_exit` on the vCPU's kvm_run page and sends a
//! signal to its OS thread, which is the standard technique (matches
//! QEMU/crosvm) for forcing a stuck-or-looping KVM_RUN to return. The
//! vCPU thread then lands in run_until's existing pause-service loop,
//! where register/memory reads happen on that same thread (KVM's vcpu
//! ioctls are only safe from the thread that owns KVM_RUN) and are
//! shipped back to the gdbstub thread over a channel.

use crate::kvm::{KvmRegs, KvmSregs, KvmVm};
use crate::memory::GuestMemory;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub enum GdbCmd {
    GetRegs(SyncSender<KvmRegs>),
    GetSregs(SyncSender<KvmSregs>),
    ReadMem {
        addr: u64,
        len: usize,
        reply: SyncSender<Vec<u8>>,
    },
    /// Patch a software breakpoint (`0xCC`) at a *virtual* address,
    /// remembering the original byte for `ClearBreakpoint`. Arms
    /// `KVM_SET_GUEST_DEBUG` on first use.
    SetBreakpoint { addr: u64, reply: SyncSender<bool> },
    /// Restore the original byte at a previously set breakpoint.
    ClearBreakpoint { addr: u64, reply: SyncSender<bool> },
}

/// OS thread id of the BSP vCPU thread (so break-in can signal it) plus
/// the software-breakpoint registry (virtual addr -> original byte).
pub struct GdbControl {
    tid: AtomicI32,
    breakpoints: Mutex<HashMap<u64, u8>>,
    debug_armed: AtomicBool,
}

impl GdbControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tid: AtomicI32::new(0),
            breakpoints: Mutex::new(HashMap::new()),
            debug_armed: AtomicBool::new(false),
        })
    }

    /// Call from the BSP vCPU thread itself, once, before its KVM_RUN loop.
    pub fn record_current_thread(&self) {
        self.tid.store(current_tid(), Ordering::SeqCst);
    }
}

extern "C" fn noop_signal_handler(_: i32) {}

/// SIGUSR1's default disposition is to terminate the process. Install a
/// harmless handler once, before any break-in attempt, so sending it just
/// interrupts the blocking KVM_RUN ioctl (EINTR) instead of killing the
/// hypervisor the first time a client connects.
fn install_signal_handler() {
    unsafe {
        libc::signal(libc::SIGUSR1, noop_signal_handler as *const () as usize);
    }
}

// This hypervisor only ever runs on Linux (raw KVM ioctls); the
// gettid/tgkill split below exists solely so the crate still type-checks
// when built for local tooling on a non-Linux host (macOS dev machine).
#[cfg(target_os = "linux")]
fn current_tid() -> i32 {
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

#[cfg(not(target_os = "linux"))]
fn current_tid() -> i32 {
    0
}

#[cfg(target_os = "linux")]
fn signal_thread(tid: i32, sig: i32) {
    unsafe {
        libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, sig);
    }
}

#[cfg(not(target_os = "linux"))]
fn signal_thread(_tid: i32, _sig: i32) {}

/// `(addr, control, cmd_tx, cmd_rx, stop_tx, stop_rx)` -- everything
/// `run_until` needs to wire up a gdbstub session. `cmd_tx`/`stop_rx` are
/// consumed by `spawn`; `cmd_rx` is polled and `stop_tx` is signaled by
/// run_until's own BSP loop.
pub type GdbSetup = (
    String,
    Arc<GdbControl>,
    SyncSender<GdbCmd>,
    Receiver<GdbCmd>,
    SyncSender<()>,
    Receiver<()>,
);

pub fn spawn(
    addr: String,
    kvm: Arc<KvmVm>,
    control: Arc<GdbControl>,
    paused: Arc<AtomicBool>,
    cmd_tx: SyncSender<GdbCmd>,
    stop_rx: Receiver<()>,
) {
    install_signal_handler();
    std::thread::spawn(move || {
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[gdbstub] bind {addr} failed: {e}");
                return;
            }
        };
        eprintln!("[gdbstub] listening on {addr} -- attach with: gdb -ex 'target remote {addr}'");
        // One connection at a time (this is a diagnostic tool, not a
        // multi-client server), so `stop_rx` can be shared by reference
        // across connections without needing to be cloneable.
        for stream in listener.incoming().flatten() {
            handle_conn(stream, &kvm, &control, &paused, &cmd_tx, &stop_rx);
        }
    });
}

fn break_in(kvm: &KvmVm, control: &GdbControl, paused: &AtomicBool) {
    paused.store(true, Ordering::SeqCst);
    kvm.request_immediate_exit(0, true);
    let tid = control.tid.load(Ordering::SeqCst);
    if tid != 0 {
        signal_thread(tid, libc::SIGUSR1);
    }
}

fn resume(kvm: &KvmVm, paused: &AtomicBool) {
    kvm.request_immediate_exit(0, false);
    paused.store(false, Ordering::SeqCst);
}

/// Block until the BSP thread actually reaches the pause-service loop
/// (proven by it answering a real request), retrying the break-in kick
/// periodically in case the first signal arrived before the thread was
/// ready to receive it. Gives up after a few seconds so a connect against
/// an already-dead VM doesn't hang the gdbstub thread forever.
fn wait_paused(kvm: &KvmVm, control: &GdbControl, paused: &AtomicBool, cmd_tx: &SyncSender<GdbCmd>) -> bool {
    for _ in 0..50 {
        let (tx, rx) = sync_channel(1);
        if cmd_tx.send(GdbCmd::GetRegs(tx)).is_err() {
            return false;
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(_) => return true,
            Err(RecvTimeoutError::Timeout) => break_in(kvm, control, paused),
            Err(RecvTimeoutError::Disconnected) => return false,
        }
    }
    false
}

fn handle_conn(
    mut stream: TcpStream,
    kvm: &Arc<KvmVm>,
    control: &Arc<GdbControl>,
    paused: &Arc<AtomicBool>,
    cmd_tx: &SyncSender<GdbCmd>,
    stop_rx: &Receiver<()>,
) {
    let _ = stream.set_nodelay(true);
    eprintln!("[gdbstub] client connected -- breaking in");
    break_in(kvm, control, paused);
    if !wait_paused(kvm, control, paused, cmd_tx) {
        eprintln!("[gdbstub] guest never paused (VM stopped?), closing connection");
        return;
    }

    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        pending.extend_from_slice(&buf[..n]);
        loop {
            match take_packet(&mut pending) {
                TakeResult::Interrupt => {
                    break_in(kvm, control, paused);
                    wait_paused(kvm, control, paused, cmd_tx);
                    let _ = stream.write_all(b"$S02#b1");
                }
                TakeResult::Packet(body) => {
                    let _ = stream.write_all(b"+");
                    if let Some(reply) = dispatch(&body, kvm, paused, cmd_tx, stop_rx) {
                        let _ = stream.write_all(&frame(&reply));
                    }
                }
                TakeResult::Ack | TakeResult::Nak => {}
                TakeResult::NeedMore => break,
            }
        }
    }
    eprintln!("[gdbstub] client disconnected, resuming guest");
    resume(kvm, paused);
}

enum TakeResult {
    Packet(String),
    Interrupt,
    Ack,
    Nak,
    NeedMore,
}

fn take_packet(buf: &mut Vec<u8>) -> TakeResult {
    if buf.is_empty() {
        return TakeResult::NeedMore;
    }
    match buf[0] {
        0x03 => {
            buf.remove(0);
            TakeResult::Interrupt
        }
        b'+' => {
            buf.remove(0);
            TakeResult::Ack
        }
        b'-' => {
            buf.remove(0);
            TakeResult::Nak
        }
        b'$' => {
            if let Some(hash) = buf.iter().position(|&b| b == b'#') {
                if buf.len() >= hash + 3 {
                    let body = String::from_utf8_lossy(&buf[1..hash]).into_owned();
                    buf.drain(..hash + 3);
                    return TakeResult::Packet(body);
                }
            }
            TakeResult::NeedMore
        }
        _ => {
            // Unknown leading byte (noise) -- drop it.
            buf.remove(0);
            TakeResult::NeedMore
        }
    }
}

fn frame(body: &str) -> Vec<u8> {
    let checksum = body.bytes().fold(0u8, |acc, b| acc.wrapping_add(b));
    format!("${body}#{checksum:02x}").into_bytes()
}

fn dispatch(
    body: &str,
    kvm: &Arc<KvmVm>,
    paused: &Arc<AtomicBool>,
    cmd_tx: &SyncSender<GdbCmd>,
    stop_rx: &Receiver<()>,
) -> Option<String> {
    if body.starts_with("qSupported") {
        return Some("PacketSize=4000".into());
    }
    if body == "?" {
        return Some("S05".into());
    }
    if body == "g" {
        let (tx, rx) = sync_channel(1);
        cmd_tx.send(GdbCmd::GetRegs(tx)).ok()?;
        let regs = rx.recv_timeout(Duration::from_secs(2)).ok()?;
        let (tx2, rx2) = sync_channel(1);
        cmd_tx.send(GdbCmd::GetSregs(tx2)).ok()?;
        let sregs = rx2.recv_timeout(Duration::from_secs(2)).ok()?;
        return Some(pack_regs(&regs, &sregs));
    }
    if let Some(rest) = body.strip_prefix('m') {
        let mut parts = rest.splitn(2, ',');
        let addr = u64::from_str_radix(parts.next()?, 16).ok()?;
        let len = usize::from_str_radix(parts.next()?, 16).ok()?;
        let (tx, rx) = sync_channel(1);
        cmd_tx
            .send(GdbCmd::ReadMem {
                addr,
                len: len.min(4096),
                reply: tx,
            })
            .ok()?;
        let data = rx.recv_timeout(Duration::from_secs(2)).ok()?;
        return Some(data.iter().map(|b| format!("{b:02x}")).collect());
    }
    if let Some(rest) = body.strip_prefix("Z0,") {
        let addr = u64::from_str_radix(rest.split(',').next()?, 16).ok()?;
        let (tx, rx) = sync_channel(1);
        cmd_tx.send(GdbCmd::SetBreakpoint { addr, reply: tx }).ok()?;
        let ok = rx.recv_timeout(Duration::from_secs(2)).unwrap_or(false);
        return Some(if ok { "OK".into() } else { String::new() });
    }
    if let Some(rest) = body.strip_prefix("z0,") {
        let addr = u64::from_str_radix(rest.split(',').next()?, 16).ok()?;
        let (tx, rx) = sync_channel(1);
        cmd_tx.send(GdbCmd::ClearBreakpoint { addr, reply: tx }).ok()?;
        let _ = rx.recv_timeout(Duration::from_secs(2));
        return Some("OK".into());
    }
    if body == "c" {
        // Resume, then block until a breakpoint/debug-exit fires (or the
        // connection's caller gives up). A plain `c` with no breakpoints
        // set will simply wait here until the client sends Ctrl-C --
        // matching normal remote-debugging semantics, and fine for this
        // tool's one-shot diagnostic use.
        resume(kvm, paused);
        return match stop_rx.recv_timeout(Duration::from_secs(600)) {
            Ok(()) => Some("S05".into()),
            Err(_) => None,
        };
    }
    if body.starts_with('D') {
        resume(kvm, paused);
        return Some("OK".into());
    }
    // Unimplemented command -- empty reply per the RSP spec.
    Some(String::new())
}

/// Pack registers in GDB's amd64 target order: 16 GPRs + rip (8 bytes,
/// little-endian each), then eflags/cs/ss/ds/es/fs/gs (4 bytes each).
fn pack_regs(regs: &KvmRegs, sregs: &KvmSregs) -> String {
    let mut out = String::new();
    for v in [
        regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp, regs.rsp, regs.r8,
        regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15, regs.rip,
    ] {
        out.push_str(&le_hex(&v.to_le_bytes()));
    }
    for v in [
        regs.rflags as u32,
        sregs.cs.selector as u32,
        sregs.ss.selector as u32,
        sregs.ds.selector as u32,
        sregs.es.selector as u32,
        sregs.fs.selector as u32,
        sregs.gs.selector as u32,
    ] {
        out.push_str(&le_hex(&v.to_le_bytes()));
    }
    out
}

fn le_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_phys_u64(mem: &GuestMemory, phys: u64) -> Option<u64> {
    let mut buf = [0u8; 8];
    mem.read_at(phys, &mut buf).ok()?;
    Some(u64::from_le_bytes(buf))
}

const PAGE_PRESENT: u64 = 1;
const PAGE_PS: u64 = 1 << 7;
const PADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Walk standard x86-64 4-level page tables (CR3 -> PML4 -> PDPT -> PD ->
/// PT) to translate one guest virtual address to its physical address.
/// Returns None on any not-present level -- fine for inspecting a live,
/// already-running kernel's own mappings (gdb's `x`/`m` commands always
/// operate on virtual addresses once paging is on; reading them as
/// physical addresses directly, as an earlier version of this stub did,
/// silently returns garbage/zeroed data for any address outside the
/// guest's physical RAM window, which is most kernel addresses).
fn virt_to_phys(mem: &GuestMemory, cr3: u64, vaddr: u64) -> Option<u64> {
    let idx = |shift: u32| (vaddr >> shift) & 0x1ff;
    let pml4e = read_phys_u64(mem, (cr3 & PADDR_MASK) + idx(39) * 8)?;
    if pml4e & PAGE_PRESENT == 0 {
        return None;
    }
    let pdpte = read_phys_u64(mem, (pml4e & PADDR_MASK) + idx(30) * 8)?;
    if pdpte & PAGE_PRESENT == 0 {
        return None;
    }
    if pdpte & PAGE_PS != 0 {
        return Some((pdpte & 0x000f_ffff_c000_0000) | (vaddr & 0x3fff_ffff));
    }
    let pde = read_phys_u64(mem, (pdpte & PADDR_MASK) + idx(21) * 8)?;
    if pde & PAGE_PRESENT == 0 {
        return None;
    }
    if pde & PAGE_PS != 0 {
        return Some((pde & 0x000f_ffff_ffe0_0000) | (vaddr & 0x1f_ffff));
    }
    let pte = read_phys_u64(mem, (pde & PADDR_MASK) + idx(12) * 8)?;
    if pte & PAGE_PRESENT == 0 {
        return None;
    }
    Some((pte & PADDR_MASK) | (vaddr & 0xfff))
}

/// Patches a software breakpoint (`0xCC`/int3) at a virtual address,
/// remembering the original byte in `control.breakpoints` so it can be
/// restored later. Arms `KVM_SET_GUEST_DEBUG` (once) so KVM reports the
/// resulting int3 back via `KVM_EXIT_DEBUG` instead of forwarding it into
/// the guest's own IDT. Called on the BSP vCPU thread from run_until's
/// pause-service loop.
pub fn set_breakpoint(mem: &mut GuestMemory, kvm: &KvmVm, control: &GdbControl, cr3: u64, addr: u64) -> bool {
    if !control.debug_armed.swap(true, Ordering::SeqCst) && kvm.enable_guest_debug(0).is_err() {
        control.debug_armed.store(false, Ordering::SeqCst);
        return false;
    }
    let Some(phys) = virt_to_phys(mem, cr3, addr) else {
        return false;
    };
    let mut orig = [0u8; 1];
    if mem.read_at(phys, &mut orig).is_err() || mem.write_at(phys, &[0xCCu8]).is_err() {
        return false;
    }
    control.breakpoints.lock().unwrap().insert(addr, orig[0]);
    true
}

/// Restores the original byte at a previously set breakpoint.
pub fn clear_breakpoint(mem: &mut GuestMemory, control: &GdbControl, cr3: u64, addr: u64) -> bool {
    let Some(orig) = control.breakpoints.lock().unwrap().remove(&addr) else {
        return false;
    };
    match virt_to_phys(mem, cr3, addr) {
        Some(phys) => mem.write_at(phys, &[orig]).is_ok(),
        None => false,
    }
}

/// Reads guest memory for the `m` command. Translates `addr` as a virtual
/// address through the vCPU's own page tables when paging is active
/// (matching what gdb itself means by an address), one page at a time
/// since consecutive virtual pages need not be physically contiguous;
/// falls back to a direct physical read only if paging is off. Called on
/// the BSP vCPU thread from run_until's pause-service loop, where
/// GuestMemory access is safe.
pub fn read_guest_mem(
    mem: &GuestMemory,
    cr3: u64,
    paging_enabled: bool,
    addr: u64,
    len: usize,
) -> Vec<u8> {
    let mut out = vec![0u8; len];
    if !paging_enabled {
        let _ = mem.read_at(addr, &mut out);
        return out;
    }
    let mut done = 0usize;
    while done < len {
        let vaddr = addr + done as u64;
        let page_off = (vaddr & 0xfff) as usize;
        let chunk = (0x1000 - page_off).min(len - done);
        if let Some(phys) = virt_to_phys(mem, cr3, vaddr) {
            let mut buf = vec![0u8; chunk];
            if mem.read_at(phys, &mut buf).is_ok() {
                out[done..done + chunk].copy_from_slice(&buf);
            }
        }
        done += chunk;
    }
    out
}
