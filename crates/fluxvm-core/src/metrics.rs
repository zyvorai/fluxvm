// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Process-wide counters for Prometheus `/metrics` (atomics, no locks).

use std::sync::atomic::{AtomicU64, Ordering};

static AUTH_DENY_TOTAL: AtomicU64 = AtomicU64::new(0);
static EGRESS_DENY_TOTAL: AtomicU64 = AtomicU64::new(0);
static VM_CREATE_TOTAL: AtomicU64 = AtomicU64::new(0);
static VM_CREATE_DURATION_MS_TOTAL: AtomicU64 = AtomicU64::new(0);
static VM_START_TOTAL: AtomicU64 = AtomicU64::new(0);
static VM_START_DURATION_MS_TOTAL: AtomicU64 = AtomicU64::new(0);

pub fn inc_auth_deny() {
    AUTH_DENY_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn inc_egress_deny() {
    EGRESS_DENY_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub fn record_vm_create(duration_ms: u64) {
    VM_CREATE_TOTAL.fetch_add(1, Ordering::Relaxed);
    VM_CREATE_DURATION_MS_TOTAL.fetch_add(duration_ms, Ordering::Relaxed);
}

pub fn record_vm_start(duration_ms: u64) {
    VM_START_TOTAL.fetch_add(1, Ordering::Relaxed);
    VM_START_DURATION_MS_TOTAL.fetch_add(duration_ms, Ordering::Relaxed);
}

pub fn auth_deny_total() -> u64 {
    AUTH_DENY_TOTAL.load(Ordering::Relaxed)
}

pub fn egress_deny_total() -> u64 {
    EGRESS_DENY_TOTAL.load(Ordering::Relaxed)
}

pub fn vm_create_total() -> u64 {
    VM_CREATE_TOTAL.load(Ordering::Relaxed)
}

pub fn vm_create_duration_ms_total() -> u64 {
    VM_CREATE_DURATION_MS_TOTAL.load(Ordering::Relaxed)
}

pub fn vm_start_total() -> u64 {
    VM_START_TOTAL.load(Ordering::Relaxed)
}

pub fn vm_start_duration_ms_total() -> u64 {
    VM_START_DURATION_MS_TOTAL.load(Ordering::Relaxed)
}
