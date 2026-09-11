// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::bus::MmioDevice;
use crate::devices::eventfd::{close_eventfd, create_eventfd, trigger_eventfd};
use crate::error::Result;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

pub const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
pub const VIRTIO_MMIO_VERSION: u32 = 2;
pub const VIRTIO_ID_NET: u32 = 1;
pub const VIRTIO_ID_BLOCK: u32 = 2;
pub const VIRTIO_ID_RNG: u32 = 4;
pub const VIRTIO_ID_BALLOON: u32 = 5;
pub const VIRTIO_ID_VSOCK: u32 = 19;
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;

pub const VIRTIO_MMIO_INT_VRING: u32 = 1 << 0;
pub const VIRTIO_MMIO_INT_CONFIG: u32 = 1 << 1;

pub const MMIO_LEN: u64 = 0x200;

#[derive(Clone, Debug, Default)]
pub struct QueueState {
    pub num: u32,
    pub ready: u32,
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
    pub last_avail: u16,
}

#[derive(Clone)]
pub struct VirtioState {
    pub device_id: u32,
    pub features: u64,
    pub driver_features: u64,
    pub status: u32,
    pub mac: [u8; 6],
    pub capacity_sectors: u64,
    /// virtio-vsock guest CID (Firecracker `guest_cid`).
    pub guest_cid: u32,
    /// virtio-balloon target pages (4 KiB).
    pub balloon_num_pages: u32,
    pub balloon_actual: u32,
    pub queues: [QueueState; 4],
    pub num_queues: u32,
    pub sel: u32,
    pub notify: Option<u32>,
    pub interrupt_status: u32,
    pub irq: u32,
}

impl Default for VirtioState {
    fn default() -> Self {
        Self {
            device_id: VIRTIO_ID_NET,
            features: VIRTIO_F_VERSION_1 | (1 << 5) | (1 << 16),
            driver_features: 0,
            status: 0,
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            capacity_sectors: 0,
            guest_cid: 3,
            balloon_num_pages: 0,
            balloon_actual: 0,
            queues: Default::default(),
            num_queues: 2,
            sel: 0,
            notify: None,
            interrupt_status: 0,
            irq: 5,
        }
    }
}

pub struct VirtioMmio {
    base: u64,
    size: u64,
    pub state: Arc<Mutex<VirtioState>>,
    dev_feat_sel: AtomicU32,
    drv_feat_sel: AtomicU32,
    /// Firecracker-style interrupt eventfd → `KVM_IRQFD`.
    interrupt_evt: i32,
}

impl VirtioMmio {
    fn new(base: u64, st: VirtioState) -> Self {
        Self {
            base,
            size: MMIO_LEN,
            state: Arc::new(Mutex::new(st)),
            dev_feat_sel: AtomicU32::new(0),
            drv_feat_sel: AtomicU32::new(0),
            interrupt_evt: create_eventfd(),
        }
    }

    pub fn net(base: u64, mac: [u8; 6]) -> Self {
        let mut st = VirtioState::default();
        st.mac = mac;
        st.irq = 5;
        st.num_queues = 2;
        Self::new(base, st)
    }

    pub fn block(base: u64, capacity_sectors: u64, read_only: bool) -> Self {
        let mut st = VirtioState::default();
        st.device_id = VIRTIO_ID_BLOCK;
        st.features = VIRTIO_F_VERSION_1;
        if read_only {
            st.features |= VIRTIO_BLK_F_RO;
        }
        st.capacity_sectors = capacity_sectors;
        st.mac = [0; 6];
        st.irq = 6;
        st.num_queues = 1;
        Self::new(base, st)
    }

    /// Firecracker virtio-vsock (3 queues: RX/TX/EVENT).
    pub fn vsock(base: u64, guest_cid: u32, irq: u32) -> Self {
        let mut st = VirtioState::default();
        st.device_id = VIRTIO_ID_VSOCK;
        st.features = VIRTIO_F_VERSION_1;
        st.guest_cid = guest_cid.max(3);
        st.mac = [0; 6];
        st.irq = irq;
        st.num_queues = 3;
        Self::new(base, st)
    }

    /// Firecracker virtio-balloon (inflate + deflate queues).
    pub fn balloon(base: u64, irq: u32) -> Self {
        let mut st = VirtioState::default();
        st.device_id = VIRTIO_ID_BALLOON;
        st.features = VIRTIO_F_VERSION_1;
        st.mac = [0; 6];
        st.irq = irq;
        st.num_queues = 2;
        Self::new(base, st)
    }

    /// Firecracker virtio-rng / entropy (1 queue).
    pub fn rng(base: u64, irq: u32) -> Self {
        let mut st = VirtioState::default();
        st.device_id = VIRTIO_ID_RNG;
        st.features = VIRTIO_F_VERSION_1;
        st.mac = [0; 6];
        st.irq = irq;
        st.num_queues = 1;
        Self::new(base, st)
    }

    pub fn irq(&self) -> u32 {
        self.state.lock().unwrap().irq
    }

    pub fn interrupt_evt(&self) -> Option<i32> {
        if self.interrupt_evt >= 0 {
            Some(self.interrupt_evt)
        } else {
            None
        }
    }

    pub fn raise_vring_interrupt(&self) {
        let mut st = self.state.lock().unwrap();
        st.interrupt_status |= VIRTIO_MMIO_INT_VRING;
        drop(st);
        trigger_eventfd(self.interrupt_evt);
    }

    pub fn raise_config_interrupt(&self) {
        let mut st = self.state.lock().unwrap();
        st.interrupt_status |= VIRTIO_MMIO_INT_CONFIG;
        drop(st);
        trigger_eventfd(self.interrupt_evt);
    }

    fn rel(&self, addr: u64) -> u64 {
        addr.saturating_sub(self.base)
    }

    fn q(st: &mut VirtioState) -> &mut QueueState {
        let max = st.num_queues.saturating_sub(1).min(3);
        let i = st.sel.min(max) as usize;
        &mut st.queues[i]
    }
}

impl Drop for VirtioMmio {
    fn drop(&mut self) {
        close_eventfd(self.interrupt_evt);
        self.interrupt_evt = -1;
    }
}

impl MmioDevice for VirtioMmio {
    fn name(&self) -> &'static str {
        match self.state.lock().unwrap().device_id {
            VIRTIO_ID_BLOCK => "virtio-mmio-blk",
            VIRTIO_ID_VSOCK => "virtio-mmio-vsock",
            VIRTIO_ID_BALLOON => "virtio-mmio-balloon",
            VIRTIO_ID_RNG => "virtio-mmio-rng",
            _ => "virtio-mmio-net",
        }
    }

    fn mmio_range(&self) -> std::ops::RangeInclusive<u64> {
        self.base..=self.base + self.size - 1
    }

    fn mmio_write(&self, addr: u64, data: &[u8]) -> Result<()> {
        let val = match data.len() {
            1 => data[0] as u32,
            2 => u16::from_le_bytes([data[0], data.get(1).copied().unwrap_or(0)]) as u32,
            _ => {
                let mut tmp = [0u8; 4];
                tmp[..data.len().min(4)].copy_from_slice(&data[..data.len().min(4)]);
                u32::from_le_bytes(tmp)
            }
        };
        let off = self.rel(addr);
        let mut st = self.state.lock().unwrap();
        match off {
            0x014 => self.dev_feat_sel.store(val, Ordering::SeqCst),
            0x024 => self.drv_feat_sel.store(val, Ordering::SeqCst),
            0x020 => {
                let sel = self.drv_feat_sel.load(Ordering::SeqCst);
                if sel == 0 {
                    st.driver_features = (st.driver_features & !0xffff_ffff) | val as u64;
                } else {
                    st.driver_features = (st.driver_features & 0xffff_ffff) | ((val as u64) << 32);
                }
            }
            0x030 => st.sel = val,
            0x038 => Self::q(&mut st).num = val,
            0x044 => Self::q(&mut st).ready = val,
            0x050 => st.notify = Some(val),
            0x064 => {
                st.interrupt_status &= !val;
            }
            0x070 => st.status = val,
            0x080 => {
                let q = Self::q(&mut st);
                q.desc = (q.desc & !0xffff_ffff) | val as u64;
            }
            0x084 => {
                let q = Self::q(&mut st);
                q.desc = (q.desc & 0xffff_ffff) | ((val as u64) << 32);
            }
            0x090 => {
                let q = Self::q(&mut st);
                q.avail = (q.avail & !0xffff_ffff) | val as u64;
            }
            0x094 => {
                let q = Self::q(&mut st);
                q.avail = (q.avail & 0xffff_ffff) | ((val as u64) << 32);
            }
            0x0a0 => {
                let q = Self::q(&mut st);
                q.used = (q.used & !0xffff_ffff) | val as u64;
            }
            0x0a4 => {
                let q = Self::q(&mut st);
                q.used = (q.used & 0xffff_ffff) | ((val as u64) << 32);
            }
            // Balloon config: num_pages at 0x100.
            0x100 if st.device_id == VIRTIO_ID_BALLOON => {
                st.balloon_num_pages = val;
            }
            _ => {}
        }
        Ok(())
    }

    fn mmio_read(&self, addr: u64, data: &mut [u8]) -> Result<()> {
        let off = self.rel(addr);
        let st = self.state.lock().unwrap();
        match st.device_id {
            VIRTIO_ID_BLOCK => {
                if (0x100..0x108).contains(&off) && !data.is_empty() {
                    let bytes = st.capacity_sectors.to_le_bytes();
                    let i = (off - 0x100) as usize;
                    let n = data.len().min(8 - i);
                    data[..n].copy_from_slice(&bytes[i..i + n]);
                    return Ok(());
                }
            }
            VIRTIO_ID_VSOCK => {
                // virtio_vsock_config.guest_cid (le64) at 0x100.
                if (0x100..0x108).contains(&off) && !data.is_empty() {
                    let bytes = (st.guest_cid as u64).to_le_bytes();
                    let i = (off - 0x100) as usize;
                    let n = data.len().min(8 - i);
                    data[..n].copy_from_slice(&bytes[i..i + n]);
                    return Ok(());
                }
            }
            VIRTIO_ID_BALLOON => {
                if (0x100..0x104).contains(&off) && !data.is_empty() {
                    let bytes = st.balloon_num_pages.to_le_bytes();
                    let i = (off - 0x100) as usize;
                    let n = data.len().min(4 - i);
                    data[..n].copy_from_slice(&bytes[i..i + n]);
                    return Ok(());
                }
                if (0x104..0x108).contains(&off) && !data.is_empty() {
                    let bytes = st.balloon_actual.to_le_bytes();
                    let i = (off - 0x104) as usize;
                    let n = data.len().min(4 - i);
                    data[..n].copy_from_slice(&bytes[i..i + n]);
                    return Ok(());
                }
            }
            VIRTIO_ID_RNG => {}
            _ => {
                if (0x100..0x106).contains(&off) {
                    let i = (off - 0x100) as usize;
                    if !data.is_empty() {
                        data[0] = st.mac[i];
                    }
                    return Ok(());
                } else if off == 0x106 && data.len() >= 2 {
                    data[0] = 1;
                    data[1] = 0;
                    return Ok(());
                }
            }
        }
        let max_q = st.num_queues.saturating_sub(1).min(3);
        let val = match off {
            0x000 => VIRTIO_MMIO_MAGIC,
            0x004 => VIRTIO_MMIO_VERSION,
            0x008 => st.device_id,
            0x00c => 0x554d_5846,
            0x010 => {
                if self.dev_feat_sel.load(Ordering::SeqCst) == 0 {
                    st.features as u32
                } else {
                    (st.features >> 32) as u32
                }
            }
            0x034 => 256,
            0x044 => st.queues[st.sel.min(max_q) as usize].ready,
            0x060 => st.interrupt_status,
            0x070 => st.status,
            _ => 0,
        };
        let bytes = val.to_le_bytes();
        let n = data.len().min(4);
        data[..n].copy_from_slice(&bytes[..n]);
        Ok(())
    }
}

pub fn take_notify(state: &Arc<Mutex<VirtioState>>) -> Option<u32> {
    state.lock().unwrap().notify.take()
}
