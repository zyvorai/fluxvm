// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! FluxVM MicroVM: Kubernetes-native MicroVM compute (not KubeVirt).
//! Supports short-lived / disposable jobs via TTL when configured.
//! QEMU does not live in a Pod. kube-scheduler places a capacity ticket;
//! the node agent drives local `fluxctl serve`.

pub mod capacity;
pub mod controller;
pub mod convert;
pub mod crd;
pub mod fluxvm_client;
pub mod guest_images;
pub mod images;
pub mod jobs;
pub mod metrics;
pub mod node_agent;
pub mod policy;
pub mod pools;
pub mod shadow;
