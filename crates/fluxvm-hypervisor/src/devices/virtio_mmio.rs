// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::bus::MmioDevice;
use crate::error::Result;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

pub const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
pub const VIRTIO_MMIO_VERSION: u32 = 2;
pub const VIRTIO_ID_NET: u32 = 1;
pub const VIRTIO_ID_BLOCK: u32 = 2;
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

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
    pub queues: [QueueState; 2],
    pub sel: u32,
    pub notify: Option<u32>,
}

impl Default for VirtioState {
    fn default() -> Self {
        Self {
            device_id: VIRTIO_ID_NET,
            features: VIRTIO_F_VERSION_1 | (1 << 5) | (1 << 16),
            driver_features: 0,
            status: 0,
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            queues: [QueueState::default(), QueueState::default()],
            sel: 0,
            notify: None,
        }
    }
}

pub struct VirtioMmio {
    base: u64,
    size: u64,
    pub state: Arc<Mutex<VirtioState>>,
    dev_feat_sel: AtomicU32,
    drv_feat_sel: AtomicU32,
}

impl VirtioMmio {
    pub fn net(base: u64, mac: [u8; 6]) -> Self {
        let mut st = VirtioState::default();
        st.mac = mac;
        Self {
            base,
            size: 0x200,
            state: Arc::new(Mutex::new(st)),
            dev_feat_sel: AtomicU32::new(0),
            drv_feat_sel: AtomicU32::new(0),
        }
    }

    fn rel(&self, addr: u64) -> u64 {
        addr.saturating_sub(self.base)
    }

    fn q(st: &mut VirtioState) -> &mut QueueState {
        let i = st.sel.min(1) as usize;
        &mut st.queues[i]
    }
}

impl MmioDevice for VirtioMmio {
    fn name(&self) -> &'static str {
        "virtio-mmio-net"
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
            _ => {}
        }
        Ok(())
    }

    fn mmio_read(&self, addr: u64, data: &mut [u8]) -> Result<()> {
        let off = self.rel(addr);
        let st = self.state.lock().unwrap();
        if (0x100..0x106).contains(&off) {
            let i = (off - 0x100) as usize;
            if !data.is_empty() {
                data[0] = st.mac[i];
            }
            return Ok(());
        }
        if off == 0x106 && data.len() >= 2 {
            data[0] = 1;
            data[1] = 0;
            return Ok(());
        }
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
            0x044 => st.queues[st.sel.min(1) as usize].ready,
            0x060 => 0,
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
