// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `fluxvm-procbox`: a rootless process sandbox built on Landlock and
//! seccomp-bpf. It is the lightweight tier below FluxVM's microVMs: no root,
//! no KVM, no image, but it shares the host kernel (see `docs/procbox.md`).

pub mod landlock;
pub mod learn;
pub mod policy;
pub mod probe;
pub mod profile;
mod run;
#[cfg(target_os = "linux")]
pub mod seccomp;
pub mod selftest;

pub use policy::{parse_size, Enforcement, Policy, SeccompMode, TcpRule};
pub use profile::Profile;
pub use run::{build_env, run, run_with, RunOptions, RunResult, SyscallOverrides};
