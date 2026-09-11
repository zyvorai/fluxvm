// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::boot;
use crate::bus::Bus;
use crate::config::VmConfig;
use crate::devices::cmos::CmosRtc;
use crate::devices::rate_limiter::RateLimiter;
use crate::devices::serial::Serial16550;
use crate::devices::virtio_blk::{self, BlockBackend};
use crate::devices::virtio_mmio::{self, VirtioMmio, MMIO_LEN};
use crate::devices::virtio_net::{self, VirtioNetConfig};
use crate::devices::virtio_vsock::VsockBackend;
use crate::devices::{virtio_balloon, virtio_rng, virtio_vsock};
use crate::error::{FluxError, Result};
use crate::ffi;
use crate::gdbstub::{self, GdbCmd, GdbControl, GdbSetup};
use crate::jailer::{self, JailerConfig};
use crate::kvm::KvmVm;
use crate::kvm_snap::{self, CpuSnapshot, SnapCmd};
use crate::memory::{self, GuestMemory, GUEST_STACK, KERNEL_LOAD_ADDR, MMIO_WINDOW};
use crate::pci::PciEcam;
use crate::tap::Tap;
use crate::vhost::VhostNet;
use std::io;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::Receiver,
    Arc,
};
use std::time::{Duration, Instant};

/// Virtio-mmio slots (Firecracker-style sequential windows).
pub const MMIO_BLK_WINDOW: u64 = MMIO_WINDOW + MMIO_LEN;
pub const MMIO_VSOCK_WINDOW: u64 = MMIO_WINDOW + MMIO_LEN * 2;
pub const MMIO_BALLOON_WINDOW: u64 = MMIO_WINDOW + MMIO_LEN * 3;
pub const MMIO_RNG_WINDOW: u64 = MMIO_WINDOW + MMIO_LEN * 4;

pub struct VirtualMachine {
    pub cfg: VmConfig,
    pub mem: GuestMemory,
    pub bus: Arc<Bus>,
    pub serial: Arc<Serial16550>,
    pub net: Option<Arc<VirtioMmio>>,
    pub blk: Option<Arc<VirtioMmio>>,
    pub blk_backend: Option<Arc<BlockBackend>>,
    pub vsock: Option<Arc<VirtioMmio>>,
    pub vsock_backend: Option<Arc<VsockBackend>>,
    pub balloon: Option<Arc<VirtioMmio>>,
    pub rng: Option<Arc<VirtioMmio>>,
    pub net_limiter: Arc<RateLimiter>,
    pub blk_limiter: Arc<RateLimiter>,
    pub tap: Option<Tap>,
    pub vhost: Option<VhostNet>,
    pub boot_rip: u64,
    pub boot_params_gpa: Option<u64>,
    pub pvh_start_info_gpa: Option<u64>,
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
            vsock: None,
            vsock_backend: None,
            balloon: None,
            rng: None,
            net_limiter: Arc::new(RateLimiter::unlimited()),
            blk_limiter: Arc::new(RateLimiter::unlimited()),
            tap,
            vhost: None,
            boot_rip: KERNEL_LOAD_ADDR,
            boot_params_gpa: None,
            pvh_start_info_gpa: None,
            notes,
        })
    }

    /// Boot from an external kernel/initrd (FluxVM `engine=kvm` path).
    pub fn from_boot_config(cfg: VmConfig) -> Result<Self> {
        cfg.validate()?;
        let mut cfg = cfg;
        // Firecracker: advertise every virtio-mmio device on the cmdline.
        let mut mmio_devs = vec![(MMIO_WINDOW, MMIO_LEN, 5u32)];
        if cfg.disk.is_some() {
            mmio_devs.push((MMIO_BLK_WINDOW, MMIO_LEN, 6));
        }
        let mut next_irq = 7u32;
        let mut next_base = MMIO_VSOCK_WINDOW;
        if cfg.vsock_cid.is_some() && cfg.vsock_uds.is_some() {
            mmio_devs.push((next_base, MMIO_LEN, next_irq));
            next_base += MMIO_LEN;
            next_irq += 1;
        }
        if cfg.balloon {
            mmio_devs.push((MMIO_BALLOON_WINDOW, MMIO_LEN, 8));
        }
        if cfg.rng {
            mmio_devs.push((MMIO_RNG_WINDOW, MMIO_LEN, 9));
        }
        let _ = (next_base, next_irq);
        cfg.cmdline = boot::append_virtio_mmio_cmdline(&cfg.cmdline, &mmio_devs);

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
        if cfg.pci {
            bus.add_mmio(Arc::new(PciEcam::new()));
            notes.push(format!(
                "PCI ECAM at {:#x} (cloud-hypervisor / FC --enable-pci layout)",
                memory::PCI_MMCONFIG_START
            ));
        }

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

        let (vsock, vsock_backend) = match (&cfg.vsock_cid, &cfg.vsock_uds) {
            (Some(cid), Some(uds)) => match VsockBackend::new(uds, *cid) {
                Ok(be) => {
                    notes.push(format!("virtio-vsock cid={cid} uds={}", uds.display()));
                    let mmio = Arc::new(VirtioMmio::vsock(MMIO_VSOCK_WINDOW, *cid, 7));
                    bus.add_mmio(mmio.clone());
                    (Some(mmio), Some(Arc::new(be)))
                }
                Err(e) => {
                    notes.push(format!("virtio-vsock failed: {e}"));
                    (None, None)
                }
            },
            _ => (None, None),
        };

        let balloon = if cfg.balloon {
            let mmio = Arc::new(VirtioMmio::balloon(MMIO_BALLOON_WINDOW, 8));
            bus.add_mmio(mmio.clone());
            notes.push("virtio-balloon attached".into());
            Some(mmio)
        } else {
            None
        };

        let rng_dev = if cfg.rng {
            let mmio = Arc::new(VirtioMmio::rng(MMIO_RNG_WINDOW, 9));
            bus.add_mmio(mmio.clone());
            notes.push("virtio-rng attached".into());
            Some(mmio)
        } else {
            None
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

        let vhost = if cfg.vhost_net {
            match VhostNet::open() {
                Ok(v) => {
                    notes.push(
                        "vhost-net opened (/dev/vhost-net); queues still userspace until full bind"
                            .into(),
                    );
                    Some(v)
                }
                Err(e) => {
                    notes.push(format!("vhost-net fallback to userspace TAP: {e}"));
                    None
                }
            }
        } else {
            None
        };

        let net_limiter = Arc::new(RateLimiter::from_mbit(cfg.net_mbit_limit));
        let blk_limiter = Arc::new(RateLimiter::from_mbit(cfg.blk_mbit_limit));

        Ok(Self {
            cfg,
            mem,
            bus: Arc::new(bus),
            serial,
            net: Some(net),
            blk,
            blk_backend,
            vsock,
            vsock_backend,
            balloon,
            rng: rng_dev,
            net_limiter,
            blk_limiter,
            tap,
            vhost,
            boot_rip: boot_info.entry_rip,
            boot_params_gpa: boot_info.boot_params_gpa,
            pvh_start_info_gpa: boot_info.pvh_start_info_gpa,
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
            true,
        )
    }

    pub fn run_until(
        mut self,
        stop: Arc<AtomicBool>,
        paused: Arc<AtomicBool>,
        snap_rx: Option<Receiver<SnapCmd>>,
        restore: Option<CpuSnapshot>,
        gdb: Option<GdbSetup>,
        exit_on_boot_marker: bool,
    ) -> Result<String> {
        let cr3 = 0x8000u64;
        let num_cpus = self.cfg.cpus.max(1);
        let kvm = Arc::new(KvmVm::create(&self.mem, num_cpus)?);
        // Firecracker: register_irq(serial.interrupt_evt(), COM1_GSI=4).
        if let Some(fd) = self.serial.interrupt_evt() {
            kvm.register_irqfd(fd, self.serial.irq)?;
        }
        for dev in [&self.net, &self.blk, &self.vsock, &self.balloon, &self.rng]
            .into_iter()
            .flatten()
        {
            if let Some(fd) = dev.interrupt_evt() {
                kvm.register_irqfd(fd, dev.irq())?;
            }
        }
        // Jailer after kvm/device fds are open (FC order: open resources, then drop privs).
        let mut jail = JailerConfig::from_env();
        if self.cfg.jailer {
            jail.enabled = true;
        }
        jailer::apply(&jail)?;
        if let Some(cpu) = restore {
            kvm_snap::restore_vcpus(&kvm, &cpu)?;
            eprintln!(
                "[kvm] restored FLUXKVM1 snapshot vcpus={} rip={:#x} cr3={:#x}",
                cpu.all_vcpus.len(),
                cpu.regs.rip,
                cpu.sregs.cr3
            );
        } else if let Some(start_info_gpa) = self.pvh_start_info_gpa {
            // PVH: hand the kernel a bare 32-bit entry point and let its
            // own startup_32/startup_64 code build page tables and make
            // the long-mode transition itself (see kvm.rs::setup_pvh_entry
            // for why this sidesteps a whole class of bug our own
            // hand-built identity map + direct long-mode jump can have).
            kvm.setup_pvh_entry(&mut self.mem, self.boot_rip, start_info_gpa)?;
            eprintln!(
                "[kvm] PVH entry rip={:#x} start_info={start_info_gpa:#x}",
                self.boot_rip
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
            let stop = stop.clone();
            std::thread::spawn(move || run_ap(idx, &kvm, &bus, &stop));
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
                        eprintln!(
                            "[kvm] serial inject {} bytes after userspace",
                            payload.len()
                        );
                    }
                }
            }
            let _ = fed;

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
                    // Serial IRQ is edge-triggered via KVM_IRQFD (FC/CH), not
                    // re-pulsed on every PIO while still pending.
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
                                Some(this.net_limiter.as_ref()),
                            ) {
                                Ok(n) => {
                                    eprintln!("[net] processed q={q} frames={n}");
                                    drop(st);
                                    net.raise_vring_interrupt();
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
                                Some(this.blk_limiter.as_ref()),
                            ) {
                                Ok(n) => {
                                    eprintln!("[blk] processed q={q} reqs={n}");
                                    drop(st);
                                    blk.raise_vring_interrupt();
                                }
                                Err(e) => eprintln!("[blk] notify err {e}"),
                            }
                        }
                    }
                    if let Some(vsock) = &this.vsock {
                        if let Some(q) = virtio_mmio::take_notify(&vsock.state) {
                            let mut st = vsock.state.lock().unwrap();
                            match virtio_vsock::handle_notify(&mut this.mem, &mut st, q) {
                                Ok(n) => {
                                    if n > 0 {
                                        eprintln!("[vsock] processed q={q} pkts={n}");
                                    }
                                    drop(st);
                                    vsock.raise_vring_interrupt();
                                }
                                Err(e) => eprintln!("[vsock] notify err {e}"),
                            }
                        }
                    }
                    if let Some(balloon) = &this.balloon {
                        if let Some(q) = virtio_mmio::take_notify(&balloon.state) {
                            let mut st = balloon.state.lock().unwrap();
                            match virtio_balloon::handle_notify(&mut this.mem, &mut st, q) {
                                Ok(n) => {
                                    if n > 0 {
                                        eprintln!("[balloon] q={q} bufs={n}");
                                    }
                                    drop(st);
                                    balloon.raise_vring_interrupt();
                                }
                                Err(e) => eprintln!("[balloon] notify err {e}"),
                            }
                        }
                    }
                    if let Some(rng) = &this.rng {
                        if let Some(q) = virtio_mmio::take_notify(&rng.state) {
                            let mut st = rng.state.lock().unwrap();
                            match virtio_rng::handle_notify(&mut this.mem, &mut st, q) {
                                Ok(n) => {
                                    if n > 0 {
                                        eprintln!("[rng] q={q} bufs={n}");
                                    }
                                    drop(st);
                                    rng.raise_vring_interrupt();
                                }
                                Err(e) => eprintln!("[rng] notify err {e}"),
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
                    // A gdbstub software breakpoint (int3) fired. Live-
                    // tested: KVM already reports RIP sitting exactly at
                    // the breakpoint address for a KVM_GUESTDBG_USE_SW_BP
                    // exit (unlike raw hardware int3 semantics, where RIP
                    // would land one byte past it) -- no rewind needed;
                    // an earlier version that subtracted 1 here landed
                    // one byte *before* the intended address instead.
                    //
                    // TEMP: breakpoint is set at exc_page_fault(struct
                    // pt_regs *regs, unsigned long error_code) -- regs is
                    // in rdi, error_code in rsi (System V AMD64 ABI).
                    // pt_regs->ip (the actual faulting instruction, not
                    // exc_page_fault's own entry) is at offset 0x80.
                    // Dumped here directly (bypassing the gdbstub client)
                    // since scripting many rapid `continue`s over the RSP
                    // wire hit a client-side race.
                    if let Ok(regs) = kvm.get_regs(0) {
                        let cr3 = kvm.get_sregs(0).map(|s| s.cr3).unwrap_or(0);
                        let fault_ip = gdbstub::virt_to_phys(&this.mem, cr3, regs.rdi + 0x80)
                            .and_then(|phys| {
                                let mut buf = [0u8; 8];
                                this.mem.read_at(phys, &mut buf).ok()?;
                                Some(u64::from_le_bytes(buf))
                            });
                        eprintln!(
                            "[diag] exc_page_fault regs={:#x} error_code={:#x} fault_ip={:x?}",
                            regs.rdi, regs.rsi, fault_ip
                        );
                    }
                    paused.store(true, Ordering::Relaxed);
                    if let Some(tx) = gdb_stop_tx.as_ref() {
                        // try_send, not send: this is a rendezvous
                        // (capacity-0) channel, and if no gdb client is
                        // currently blocked in a `c` waiting to receive,
                        // a blocking send here would hang this vCPU
                        // thread forever (e.g. the breakpoint re-fires
                        // after a client detaches without clearing it).
                        let _ = tx.try_send(());
                    }
                    continue;
                }
                ffi::KVM_EXIT_SHUTDOWN => {
                    eprintln!("[kvm] shutdown");
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
                ffi::KVM_EXIT_FAIL_ENTRY => {
                    let reason =
                        unsafe { std::ptr::read_unaligned(kvm.vcpus[0].run.add(32) as *const u64) };
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
            // Demo/smoke-test convenience only (CLI `--guest` path via
            // run()/run_with_gdb()): stop as soon as boot visibly reaches
            // one of these milestones, so a quick manual test doesn't have
            // to wait for the full deadline. A real VM launched through the
            // control-plane API (guest.rs) must NOT stop here -- reaching
            // "Run /sbin/init" is the *start* of a long-lived sandbox's
            // life, not a reason to freeze its vCPU forever. Confirmed live:
            // before this guard existed, every control-plane-launched VM's
            // execution silently and permanently halted the instant the
            // guest kernel logged "Run /sbin/init", indistinguishable from
            // a genuine hang from the caller's perspective.
            if exit_on_boot_marker
                && (serial_log.contains("NETWORK IS UP")
                    || serial_log.contains("NET TIMEOUT")
                    || serial_log.contains("FLUXVM_STDIN_OK")
                    || serial_log.contains("login:")
                    || serial_log.contains("Run /sbin/init")
                    || serial_log.contains("Kernel panic")
                    // Fallbacks when no stdin inject is configured.
                    || (inject.is_none()
                        && (serial_log.contains("FLUXVM_USERSPACE_OK")
                            || serial_log.contains("FLUXVM_PROMPT_READY")
                            || serial_log.contains("can't access tty"))))
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
fn run_ap(idx: usize, kvm: &KvmVm, bus: &Bus, stop: &AtomicBool) {
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
