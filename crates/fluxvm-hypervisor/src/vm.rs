// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::boot;
use crate::bus::Bus;
use crate::config::VmConfig;
use crate::devices::serial::Serial16550;
use crate::devices::virtio_mmio::{self, VirtioMmio};
use crate::devices::virtio_net::{self, VirtioNetConfig};
use crate::error::{FluxError, Result};
use crate::ffi;
use crate::kvm::KvmVm;
use crate::memory::{GuestMemory, GUEST_STACK, KERNEL_LOAD_ADDR, MMIO_WINDOW};
use crate::tap::Tap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

pub struct VirtualMachine {
    pub cfg: VmConfig,
    pub mem: GuestMemory,
    pub bus: Arc<Bus>,
    pub net: Option<Arc<VirtioMmio>>,
    pub tap: Option<Tap>,
    pub boot_rip: u64,
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
        bus.add_pio(Arc::new(Serial16550::com1()));

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
            net: Some(net),
            tap,
            boot_rip: KERNEL_LOAD_ADDR,
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

        let mut bus = Bus::new();
        bus.add_pio(Arc::new(Serial16550::com1()));

        let mac = VirtioNetConfig::parse_mac(&cfg.mac).unwrap_or([0x02, 0, 0, 0, 0, 2]);
        let net = Arc::new(VirtioMmio::net(MMIO_WINDOW, mac));
        bus.add_mmio(net.clone());

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
            net: Some(net),
            tap,
            boot_rip: boot_info.entry_rip,
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
        self.run_until(Arc::new(AtomicBool::new(false)))
    }

    pub fn run_until(mut self, stop: Arc<AtomicBool>) -> Result<String> {
        let cr3 = 0x8000u64;
        let mut kvm = KvmVm::create(&self.mem)?;
        kvm.setup_long_mode(&mut self.mem, self.boot_rip, GUEST_STACK, cr3)?;
        eprintln!("[kvm] long mode rip={:#x} cr3={cr3:#x}", self.boot_rip);

        let mut serial_log = String::new();
        let deadline = Instant::now() + Duration::from_secs(3600);
        let mut exits = 0u64;
        let mut this = self;

        while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
            let reason = kvm.run_once()?;
            exits += 1;
            if exits <= 20 {
                eprintln!("[kvm] exit#{exits} reason={reason}");
            }
            match reason {
                ffi::KVM_EXIT_IO => {
                    let (dir, size, port, count, off) = kvm.io_info();
                    let n = (size as u32 * count) as usize;
                    if dir == ffi::KVM_EXIT_IO_OUT {
                        let data = kvm.io_data(off, n).to_vec();
                        this.bus.pio_write(port, &data)?;
                        for b in data {
                            if b.is_ascii() && (b >= 32 || b == b'\n' || b == b'\r') {
                                serial_log.push(b as char);
                            }
                        }
                    } else {
                        let mut buf = vec![0u8; n];
                        this.bus.pio_read(port, &mut buf)?;
                        kvm.io_data_mut(off, n).copy_from_slice(&buf);
                    }
                }
                ffi::KVM_EXIT_MMIO => {
                    let (addr, data, _len, is_write) = kvm.mmio_info();
                    if is_write {
                        let _ = this.bus.mmio_write(addr, &data);
                    } else {
                        let mut buf = data;
                        let _ = this.bus.mmio_read(addr, &mut buf);
                        kvm.mmio_set_data(&buf);
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
                                Ok(n) => eprintln!("[net] processed q={q} frames={n}"),
                                Err(e) => eprintln!("[net] notify err {e}"),
                            }
                        }
                    }
                }
                ffi::KVM_EXIT_HLT => {
                    eprintln!("[kvm] HLT after {exits} exits");
                    break;
                }
                ffi::KVM_EXIT_SHUTDOWN => {
                    eprintln!("[kvm] shutdown");
                    break;
                }
                ffi::KVM_EXIT_FAIL_ENTRY => {
                    let reason = unsafe { std::ptr::read_unaligned(kvm.run.add(32) as *const u64) };
                    return Err(FluxError::Hypervisor(format!(
                        "KVM_EXIT_FAIL_ENTRY reason={reason:#x}"
                    )));
                }
                ffi::KVM_EXIT_INTERNAL_ERROR => {
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
            if serial_log.contains("NETWORK IS UP") || serial_log.contains("NET TIMEOUT") {
                break;
            }
        }

        eprintln!("[kvm] serial log:\n{serial_log}");
        Ok(serial_log)
    }
}
