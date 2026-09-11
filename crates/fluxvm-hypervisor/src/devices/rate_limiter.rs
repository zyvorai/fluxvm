// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Firecracker-style token-bucket rate limiter for virtio blk/net.

use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiter {
    inner: Mutex<Inner>,
}

struct Inner {
    capacity: u64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl RateLimiter {
    /// `mbit_limit == 0` means unlimited.
    pub fn from_mbit(mbit_limit: u32) -> Self {
        if mbit_limit == 0 {
            return Self::unlimited();
        }
        let bytes_per_sec = (mbit_limit as u64) * 1_000_000 / 8;
        Self {
            inner: Mutex::new(Inner {
                capacity: bytes_per_sec,
                tokens: bytes_per_sec as f64,
                refill_per_sec: bytes_per_sec as f64,
                last: Instant::now(),
            }),
        }
    }

    pub fn unlimited() -> Self {
        Self {
            inner: Mutex::new(Inner {
                capacity: u64::MAX,
                tokens: f64::MAX,
                refill_per_sec: 0.0,
                last: Instant::now(),
            }),
        }
    }

    pub fn consume(&self, bytes: u64) -> bool {
        let mut g = self.inner.lock().unwrap();
        if g.capacity == u64::MAX {
            return true;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(g.last).as_secs_f64();
        g.last = now;
        g.tokens = (g.tokens + elapsed * g.refill_per_sec).min(g.capacity as f64);
        if g.tokens >= bytes as f64 {
            g.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}
