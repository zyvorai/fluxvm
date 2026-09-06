// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! FluxVM hypervisor — lightweight KVM microVMM (one VM per process).
//!
//! Long-lived mode: JSON-over-UDS control API (`--api-sock`).
//! Demo mode: freestanding netboot guest (legacy CLI flags).

pub mod api;
pub mod backend;
pub mod boot;
pub mod bus;
pub mod config;
pub mod control;
pub mod devices;
pub mod error;
pub mod ffi;
pub mod guest;
pub mod hypervisor;
pub mod kvm;
pub mod memory;
pub mod net;
pub mod seccomp;
pub mod snapshot;
pub mod state;
pub mod tap;
pub mod vcpu;
pub mod vm;

pub use api::{ApiRequest, ApiResponse, BootConfig, SnapshotSpec};
pub use backend::FluxVmBackend;
pub use config::VmConfig;
pub use error::FluxError;
pub use state::{VmLifecycle, VmState};
pub use vm::VirtualMachine;
