// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Guest side of FluxVM OCI sandboxes on `vz`.
//!
//! The host boots one lightweight VM per container: an uncompressed arm64 kernel plus an initramfs holding
//! `fluxvm-oci-init` (this crate's binary, PID 1), `fluxvm-guest-agent` and `mke2fs`. A read-only virtiofs
//! share tagged [`config::META_TAG`] carries [`config::InitConfig`] and the agent token.
//!
//! * `boot`: mount the image rootfs (`/dev/vda`, read-only through an overlay unless writable), configure the
//!   network, switch root, start the agent, run the image's process with its user, environment and directory.
//! * `unpack`: in a short-lived builder VM, `mke2fs` the blank `/dev/vda` and apply the image's layers from a
//!   read-only blob share, honouring OCI whiteouts and verifying each layer's diff_id.
//!
//! Everything here except `main.rs` is portable and unit-tested on any host.

pub mod config;
pub mod dhcp;
pub mod supervise;
pub mod unpack;
pub mod user;
