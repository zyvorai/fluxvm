// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::boot;
use crate::bus::Bus;
use crate::config::VmConfig;
use crate::devices::cmos::CmosRtc;
use crate::devices::serial::Serial16550;
use crate::devices::virtio_blk::{self, BlockBackend};
use crate::devices::virtio_mmio::{self, VirtioMmio};
use crate::devices::virtio_net::{self, VirtioNetConfig};
use crate::error::{FluxError, Result};
use crate::ffi;
use crate::gdbstub::{self, GdbCmd, GdbControl, GdbSetup};
use crate::kvm::KvmVm;
use crate::kvm_snap::{self, CpuSnapshot, SnapCmd};
use crate::memory::{self, GuestMemory, GUEST_STACK, KERNEL_LOAD_ADDR, MMIO_WINDOW};
use crate::tap::Tap;
use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::Receiver,
    Arc,
};
use std::time::{Duration, Instant};

/// Second virtio-mmio slot (blk) after net at MMIO_WINDOW.
pub const MMIO_BLK_WINDOW: u64 = MMIO_WINDOW + 0x200;

pub struct VirtualMachine {
    pub cfg: VmConfig,
    pub mem: GuestMemory,
    pub bus: Arc<Bus>,
    pub serial: Arc<Serial16550>,
    pub net: Option<Arc<VirtioMmio>>,
    pub blk: Option<Arc<VirtioMmio>>,
    pub blk_backend: Option<Arc<BlockBackend>>,
    pub tap: Option<Tap>,
    pub boot_rip: u64,
    /// Linux zero-page GPA for RSI (64-bit boot protocol). None for Windows / netboot.
    pub boot_params_gpa: Option<u64>,
    pub notes: Vec<String>,
}

impl VirtualMachine {
    pub fn instantiate(cfg: VmConfig) -> Result<Self> {
        cfg.validate()?;
        let mut mem = GuestMemory::allocate(cfg.memory_bytes())?;
        let _cr3 = boot::build_identity_page_tables(&mut mem)?;

        let guest = include_bytes!(concat!(env!("OUT_DIR"), "/netboot.bin"));
        mem.write_at(KERNEL_LOAD_ADDR, guest)?;

        let mut notes = vec![
            format!(
                "embedded netboot guest {} bytes at {:#x}",
                guest.len(),
                KERNEL_LOAD_ADDR
            ),
            "gateway 192.168.100.1  guest 192.168.100.2".into(),
        ];

        let mut bus = Bus::new();
        let serial = Arc::new(Serial16550::com1());
        bus.add_pio(serial.clone());
        bus.add_pio(Arc::new(CmosRtc::new()));

        let mac = VirtioNetConfig::parse_mac(&cfg.mac).unwrap_or([0x02, 0, 0, 0, 0, 2]);
        let net = Arc::new(VirtioMmio::net(MMIO_WINDOW, mac));
        bus.add_mmio(net.clone());

        let tap_name = cfg.tap.clone().unwrap_or_else(|| "flux0".into());
        let tap = match Tap::open(&tap_name, [192, 168, 100, 1]) {
            Ok(t) => {
                notes.push(format!("TAP {} is UP with 192.168.100.1/24", t.name));
                Some(t)
            }
            Err(e) => {
                notes.push(format!(
                    "TAP optional: {e} (gateway still answers ARP/ICMP)"
                ));
                None
            }
        };

        Ok(Self {
            cfg,
            mem,
            bus: Arc::new(bus),
            serial,
            net: Some(net),
            blk: None,
            blk_backend: None,
            tap,
            boot_rip: KERNEL_LOAD_ADDR,
            boot_params_gpa: None,
            notes,
        })
    }

    /// Boot from an external kernel/initrd (FluxVM `engine=kvm` path).
    pub fn from_boot_config(cfg: VmConfig) -> Result<Self> {
        cfg.validate()?;
        let mut mem = GuestMemory::allocate(cfg.memory_bytes())?;
        let _cr3 = boot::build_identity_page_tables(&mut mem)?;
        let boot_info = boot::prepare(&mut mem, &cfg)?;
        let mut notes = boot_info.notes;
        if let Err(e) = crate::mptable::write_mptable(&mut mem, cfg.cpus) {
            notes.push(format!("mptable write failed: {e}"));
        } else {
            notes.push(format!(
                "MP table at GPA {:#x} (cpus={})",
                crate::mptable::MPFLOAT_GPA,
                cfg.cpus
            ));
        }

        let mut bus = Bus::new();
        let serial = Arc::new(Serial16550::com1());
        bus.add_pio(serial.clone());
        bus.add_pio(Arc::new(CmosRtc::new()));

        let mac = VirtioNetConfig::parse_mac(&cfg.mac).unwrap_or([0x02, 0, 0, 0, 0, 2]);
        let net = Arc::new(VirtioMmio::net(MMIO_WINDOW, mac));
        bus.add_mmio(net.clone());

        let (blk, blk_backend) = if let Some(disk) = &cfg.disk {
            match BlockBackend::open(disk, false) {
                Ok(backend) => {
                    notes.push(format!(
                        "virtio-blk {} sectors={} ({})",
                        disk.display(),
                        backend.capacity_sectors,
                        backend.path.display()
                    ));
                    let mmio = Arc::new(VirtioMmio::block(
                        MMIO_BLK_WINDOW,
                        backend.capacity_sectors,
                        backend.read_only,
                    ));
                    bus.add_mmio(mmio.clone());
                    (Some(mmio), Some(backend))
                }
                Err(e) => {
                    notes.push(format!("virtio-blk open failed: {e}"));
                    (None, None)
                }
            }
        } else {
            notes.push("no disk — virtio-blk not attached".into());
            (None, None)
        };

        let tap = if let Some(tap_name) = &cfg.tap {
            match Tap::open(tap_name, [192, 168, 100, 1]) {
                Ok(t) => {
                    notes.push(format!("TAP {} attached", t.name));
                    Some(t)
                }
                Err(e) => {
                    notes.push(format!("TAP optional: {e}"));
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            cfg,
            mem,
            bus: Arc::new(bus),
            serial,
            net: Some(net),
            blk,
            blk_backend,
            tap,
            boot_rip: boot_info.entry_rip,
            boot_params_gpa: boot_info.boot_params_gpa,
            notes,
        })
    }

    pub fn dump(&self) -> String {
        let mut s = format!(
            "FluxVM  cpus={}  ram={} MiB  rip={:#x}\n",
            self.cfg.cpus, self.cfg.memory_mib, self.boot_rip
        );
        for n in &self.notes {
            s.push_str(&format!("  - {n}\n"));
        }
        s.push_str("devices:\n");
        for line in self.bus.inventory() {
            s.push_str(&format!("  {line}\n"));
        }
        s
    }

    pub fn run(self) -> Result<String> {
        self.run_with_gdb(None)
    }

    /// Like `run`, but if `gdb_addr` is set, spawns a minimal read-only
    /// gdbstub (see `gdbstub.rs`) listening there for live inspection of
    /// a hung/misbehaving guest.
    pub fn run_with_gdb(self, gdb_addr: Option<String>) -> Result<String> {
        let gdb: Option<GdbSetup> = gdb_addr.map(|addr| {
            let control = GdbControl::new();
            let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel(0);
            let (stop_tx, stop_rx) = std::sync::mpsc::sync_channel(0);
            (addr, control, cmd_tx, cmd_rx, stop_tx, stop_rx)
        });
        // The gdbstub thread needs Arc<KvmVm>/paused before run_until
        // creates them, so spawn it from inside run_until once those
        // exist instead of here.
        self.run_until(
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            None,
            None,
            gdb,
        )
    }

    pub fn run_until(
        mut self,
        stop: Arc<AtomicBool>,
        paused: Arc<AtomicBool>,
        snap_rx: Option<Receiver<SnapCmd>>,
        restore: Option<CpuSnapshot>,
        gdb: Option<GdbSetup>,
    ) -> Result<String> {
        let cr3 = 0x8000u64;
        let num_cpus = self.cfg.cpus.max(1);
        let kvm = Arc::new(KvmVm::create(&self.mem, num_cpus)?);
        if let Some(cpu) = restore {
            // Snapshot/restore is BSP-only; extending it to N vCPUs is
            // separate, out-of-scope follow-up work. Under SMP the APs
            // still come up fresh via a real SIPI, same as a normal boot.
            kvm.set_sregs(0, cpu.sregs)?;
            kvm.set_regs(0, cpu.regs)?;
            eprintln!(
                "[kvm] restored FLUXKVM1 snapshot rip={:#x} cr3={:#x}",
                cpu.regs.rip, cpu.sregs.cr3
            );
        } else {
            let rsi = self.boot_params_gpa.unwrap_or(0);
            kvm.setup_long_mode(&mut self.mem, self.boot_rip, GUEST_STACK, cr3, rsi)?;
            eprintln!(
                "[kvm] long mode rip={:#x} cr3={cr3:#x} rsi={rsi:#x}",
                self.boot_rip
            );
        }

        // Secondary vCPUs (APs). With the in-kernel irqchip already active
        // (KVM_CREATE_IRQCHIP), a freshly created non-BSP vCPU starts
        // KVM_MP_STATE_UNINITIALIZED and just blocks inside KVM_RUN until
        // the guest's own real INIT-SIPI-SIPI sequence arrives -- handled
        // entirely by KVM's in-kernel LAPIC, no userspace SIPI emulation
        // needed here. AP threads service register-level PIO/MMIO traps
        // (bus/serial are already thread-safe for concurrent access) but
        // deliberately do not run the virtio queue-notify -> guest-RAM
        // path -- that stays BSP-only, the same scope boundary many
        // minimal VMMs use by pinning device-queue processing to one
        // vCPU. Threads are intentionally not joined: an idle AP parked
        // in KVM_RUN on HLT only wakes on its own next interrupt, so
        // joining here could block VM teardown indefinitely; each AP
        // notices `stop` on its next wake (or the thread just outlives
        // the VM harmlessly, kept alive by its own Arc<KvmVm> clone).
        for idx in 1..num_cpus as usize {
            let kvm = kvm.clone();
            let bus = self.bus.clone();
            let serial = self.serial.clone();
            let stop = stop.clone();
            std::thread::spawn(move || run_ap(idx, &kvm, &bus, &serial, &stop));
        }

        let mut gdb_cmd_rx: Option<Receiver<GdbCmd>> = None;
        let mut gdb_stop_tx: Option<std::sync::mpsc::SyncSender<()>> = None;
        let mut gdb_control: Option<Arc<GdbControl>> = None;
        if let Some((addr, control, cmd_tx, cmd_rx, stop_tx, stop_rx)) = gdb {
            gdbstub::spawn(
                addr,
                kvm.clone(),
                control.clone(),
                paused.clone(),
                cmd_tx,
                stop_rx,
            );
            control.record_current_thread();
            gdb_cmd_rx = Some(cmd_rx);
            gdb_stop_tx = Some(stop_tx);
            gdb_control = Some(control);
        }

        let mut serial_log = String::new();
        let run_secs: u64 = std::env::var("FLUXVM_KVM_RUN_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600);
        let deadline = Instant::now() + Duration::from_secs(run_secs);
        let mut exits = 0u64;
        // TEMP diagnostic (Bug 2 investigation, remove before merge).
        let mut diag_ports: std::collections::HashMap<u16, u64> = std::collections::HashMap::new();
        let mut this = self;
        let mut serial_injected = false;
        let inject = std::env::var("FLUXVM_SERIAL_INJECT").ok();
        make_stdin_nonblocking();

        while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
            while paused.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed) {
                if let Some(rx) = snap_rx.as_ref() {
                    while let Ok(cmd) = rx.try_recv() {
                        let r = kvm_snap::dump(&kvm, &this.mem, &cmd.vmstate, &cmd.mem)
                            .map_err(|e| e.to_string());
                        let _ = cmd.reply.send(r);
                    }
                }
                if let Some(rx) = gdb_cmd_rx.as_ref() {
                    while let Ok(cmd) = rx.try_recv() {
                        match cmd {
                            GdbCmd::GetRegs(reply) => {
                                let r = kvm.get_regs(0).unwrap_or(unsafe { std::mem::zeroed() });
                                let _ = reply.send(r);
                            }
                            GdbCmd::GetSregs(reply) => {
                                let r = kvm.get_sregs(0).unwrap_or(unsafe { std::mem::zeroed() });
                                eprintln!(
                                    "[gdbstub] cr0={:#x} cr2={:#x} cr3={:#x} cr4={:#x}",
                                    r.cr0, r.cr2, r.cr3, r.cr4
                                );
                                // TEMP: dump the actual e820 table as the
                                // guest kernel parsed it from the zero
                                // page, to check for a discrepancy against
                                // what fill_e820 intended to write.
                                let mut nent = [0u8; 1];
                                let _ = this
                                    .mem
                                    .read_at(memory::BOOT_PARAMS_ADDR + 0x1e8, &mut nent);
                                eprintln!("[diag] e820_entries={}", nent[0]);
                                for i in 0..(nent[0] as u64).min(8) {
                                    let mut ent = [0u8; 20];
                                    let _ = this.mem.read_at(
                                        memory::BOOT_PARAMS_ADDR + 0x2d0 + i * 20,
                                        &mut ent,
                                    );
                                    let addr = u64::from_le_bytes(ent[0..8].try_into().unwrap());
                                    let size = u64::from_le_bytes(ent[8..16].try_into().unwrap());
                                    let typ = u32::from_le_bytes(ent[16..20].try_into().unwrap());
                                    eprintln!(
                                        "[diag] e820[{i}] addr={addr:#x} size={size:#x} end={:#x} type={typ}",
                                        addr + size
                                    );
                                }
                                let _ = reply.send(r);
                            }
                            GdbCmd::ReadMem { addr, len, reply } => {
                                let sregs =
                                    kvm.get_sregs(0).unwrap_or(unsafe { std::mem::zeroed() });
                                let paging_enabled = sregs.cr0 & (1 << 31) != 0;
                                let data = gdbstub::read_guest_mem(
                                    &this.mem,
                                    sregs.cr3,
                                    paging_enabled,
                                    addr,
                                    len,
                                );
                                let _ = reply.send(data);
                            }
                            GdbCmd::SetBreakpoint { addr, reply } => {
                                let cr3 = kvm.get_sregs(0).map(|s| s.cr3).unwrap_or(0);
                                let ok = gdbstub::set_breakpoint(
                                    &mut this.mem,
                                    &kvm,
                                    gdb_control.as_ref().unwrap(),
                                    cr3,
                                    addr,
                                );
                                let _ = reply.send(ok);
                            }
                            GdbCmd::ClearBreakpoint { addr, reply } => {
                                let cr3 = kvm.get_sregs(0).map(|s| s.cr3).unwrap_or(0);
                                let ok = gdbstub::clear_breakpoint(
                                    &mut this.mem,
                                    gdb_control.as_ref().unwrap(),
                                    cr3,
                                    addr,
                                );
                                let _ = reply.send(ok);
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(2));
                if Instant::now() >= deadline {
                    break;
                }
            }
            if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
                break;
            }
            // Host → guest console: stdin bytes and optional one-shot inject.
            let mut fed = drain_stdin_to_serial(&this.serial);
            if !serial_injected {
                if let Some(payload) = inject.as_ref() {
                    if serial_log.contains("FLUXVM_USERSPACE_OK")
                        || serial_log.contains("FLUXVM_PROMPT_READY")
                    {
                        this.serial.push_rx(payload.as_bytes());
                        if !payload.ends_with('\n') {
                            this.serial.push_rx(b"\n");
                        }
                        serial_injected = true;
                        fed = true;
                        eprintln!("[kvm] serial inject {} bytes after userspace", payload.len());
                    }
                }
            }
            if fed && this.serial.irq_pending() {
                let _ = kvm.pulse_irq(this.serial.irq);
            }

            let reason = kvm.run_once(0)?;
            exits += 1;
            if exits <= 20 {
                eprintln!("[kvm] exit#{exits} reason={reason}");
            }
            if exits % 5000 == 0 {
                let mut v: Vec<_> = diag_ports.iter().collect();
                v.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
                eprintln!("[diag] exits={exits} top ports={:?}", &v[..v.len().min(10)]);
            }
            match reason {
                ffi::KVM_EXIT_IO => {
                    let (dir, size, port, count, off) = kvm.io_info(0);
                    *diag_ports.entry(port).or_insert(0) += 1;
                    let n = (size as u32 * count) as usize;
                    if dir == ffi::KVM_EXIT_IO_OUT {
                        let data = kvm.io_data(0, off, n).to_vec();
                        this.bus.pio_write(port, &data)?;
                        for b in data {
                            if b.is_ascii() && (b >= 32 || b == b'\n' || b == b'\r') {
                                serial_log.push(b as char);
                            }
                        }
                    } else {
                        let mut buf = vec![0u8; n];
                        this.bus.pio_read(port, &mut buf)?;
                        kvm.set_io_data(0, off, &buf);
                    }
                    if this.serial.irq_pending() {
                        let _ = kvm.pulse_irq(this.serial.irq);
                    }
                }
                ffi::KVM_EXIT_MMIO => {
                    let (addr, data, _len, is_write) = kvm.mmio_info(0);
                    if is_write {
                        let _ = this.bus.mmio_write(addr, &data);
                    } else {
                        let mut buf = data;
                        let _ = this.bus.mmio_read(addr, &mut buf);
                        kvm.mmio_set_data(0, &buf);
                    }
                    if let Some(net) = &this.net {
                        if let Some(q) = virtio_mmio::take_notify(&net.state) {
                            let mut st = net.state.lock().unwrap();
                            match virtio_net::handle_notify(
                                &mut this.mem,
                                &mut st,
                                this.tap.as_ref(),
                                q,
                            ) {
                                Ok(n) => {
                                    eprintln!("[net] processed q={q} frames={n}");
                                    drop(st);
                                    net.raise_vring_interrupt();
                                    let _ = kvm.pulse_irq(net.irq());
                                }
                                Err(e) => eprintln!("[net] notify err {e}"),
                            }
                        }
                    }
                    if let (Some(blk), Some(backend)) = (&this.blk, &this.blk_backend) {
                        if let Some(q) = virtio_mmio::take_notify(&blk.state) {
                            let mut st = blk.state.lock().unwrap();
                            match virtio_blk::handle_notify(
                                &mut this.mem,
                                &mut st,
                                backend.as_ref(),
                                q,
                            ) {
                                Ok(n) => {
                                    eprintln!("[blk] processed q={q} reqs={n}");
                                    drop(st);
                                    blk.raise_vring_interrupt();
                                    let _ = kvm.pulse_irq(blk.irq());
                                }
                                Err(e) => eprintln!("[blk] notify err {e}"),
                            }
                        }
                    }
                }
                ffi::KVM_EXIT_HLT => {
                    // BSP HLT ends the VM (as before). An idle AP HLTing
                    // while waiting for its next IPI/timer is normal and
                    // handled separately in run_ap -- it must not reach
                    // this arm since this loop only ever drives vCPU 0.
                    eprintln!("[kvm] HLT after {exits} exits");
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
                ffi::KVM_EXIT_DEBUG => {
                    // A gdbstub software breakpoint (int3) fired. RIP has
                    // already advanced past the 0xCC byte -- rewind it so
                    // register reads and any later continue see/redo the
                    // real instruction, then park in the pause-service
                    // loop and let the gdbstub thread know we've stopped.
                    if let Ok(mut regs) = kvm.get_regs(0) {
                        regs.rip = regs.rip.saturating_sub(1);
                        let _ = kvm.set_regs(0, regs);
                    }
                    paused.store(true, Ordering::Relaxed);
                    if let Some(tx) = gdb_stop_tx.as_ref() {
                        let _ = tx.send(());
                    }
                    continue;
                }
                ffi::KVM_EXIT_SHUTDOWN => {
                    eprintln!("[kvm] shutdown");
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
                ffi::KVM_EXIT_FAIL_ENTRY => {
                    let reason = unsafe {
                        std::ptr::read_unaligned(kvm.vcpus[0].run.add(32) as *const u64)
                    };
                    stop.store(true, Ordering::Relaxed);
                    return Err(FluxError::Hypervisor(format!(
                        "KVM_EXIT_FAIL_ENTRY reason={reason:#x}"
                    )));
                }
                ffi::KVM_EXIT_INTERNAL_ERROR => {
                    stop.store(true, Ordering::Relaxed);
                    return Err(FluxError::Hypervisor("KVM_EXIT_INTERNAL_ERROR".into()));
                }
                ffi::KVM_EXIT_INTR => continue,
                other => {
                    eprintln!("[kvm] exit {other}");
                    if exits > 50_000 {
                        break;
                    }
                }
            }
            if serial_log.contains("NETWORK IS UP")
                || serial_log.contains("NET TIMEOUT")
                || serial_log.contains("FLUXVM_STDIN_OK")
                || serial_log.contains("login:")
                || serial_log.contains("Run /sbin/init")
                || serial_log.contains("Kernel panic")
                // Fallbacks when no stdin inject is configured.
                || (inject.is_none()
                    && (serial_log.contains("FLUXVM_USERSPACE_OK")
                        || serial_log.contains("FLUXVM_PROMPT_READY")
                        || serial_log.contains("can't access tty")))
            {
                break;
            }
        }

        // Make sure any AP threads parked in KVM_RUN notice on their next
        // wake, whichever path above (deadline/serial-match/HLT/shutdown)
        // ended the loop.
        stop.store(true, Ordering::Relaxed);

        eprintln!("[kvm] serial log:\n{serial_log}");
        Ok(serial_log)
    }
}

/// Secondary-vCPU (AP) run loop. See the comment in `run_until` for the
/// scope boundary: register-level PIO/MMIO only, no virtio queue-notify
/// processing (that stays BSP-only).
fn run_ap(idx: usize, kvm: &KvmVm, bus: &Bus, serial: &Serial16550, stop: &AtomicBool) {
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let reason = match kvm.run_once(idx) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[kvm] vcpu{idx} run error: {e}");
                return;
            }
        };
        match reason {
            ffi::KVM_EXIT_HLT | ffi::KVM_EXIT_INTR => continue,
            ffi::KVM_EXIT_IO => {
                let (dir, size, port, count, off) = kvm.io_info(idx);
                let n = (size as u32 * count) as usize;
                if dir == ffi::KVM_EXIT_IO_OUT {
                    let data = kvm.io_data(idx, off, n).to_vec();
                    let _ = bus.pio_write(port, &data);
                } else {
                    let mut buf = vec![0u8; n];
                    let _ = bus.pio_read(port, &mut buf);
                    kvm.set_io_data(idx, off, &buf);
                }
                if serial.irq_pending() {
                    let _ = kvm.pulse_irq(serial.irq);
                }
            }
            ffi::KVM_EXIT_MMIO => {
                let (addr, data, _len, is_write) = kvm.mmio_info(idx);
                if is_write {
                    let _ = bus.mmio_write(addr, &data);
                } else {
                    let mut buf = data;
                    let _ = bus.mmio_read(addr, &mut buf);
                    kvm.mmio_set_data(idx, &buf);
                }
            }
            ffi::KVM_EXIT_SHUTDOWN => {
                eprintln!("[kvm] vcpu{idx} shutdown");
                stop.store(true, Ordering::Relaxed);
                return;
            }
            ffi::KVM_EXIT_FAIL_ENTRY | ffi::KVM_EXIT_INTERNAL_ERROR => {
                eprintln!("[kvm] vcpu{idx} fatal exit reason={reason}");
                stop.store(true, Ordering::Relaxed);
                return;
            }
            _ => {}
        }
    }
}

fn make_stdin_nonblocking() {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = io::stdin().as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags >= 0 {
            let _ = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        }
    }
}

fn drain_stdin_to_serial(serial: &Serial16550) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 256];
    match io::stdin().lock().read(&mut buf) {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            serial.push_rx(&buf[..n]);
            true
        }
    }
}
