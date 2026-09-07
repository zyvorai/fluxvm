// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! FluxVM MicroVM: Kubernetes-native disposable compute.
//! QEMU does not live in a Pod. kube-scheduler places a capacity ticket;
//! the node agent drives local `fluxvm serve`.

pub mod capacity;
pub mod controller;
pub mod convert;
pub mod crd;
pub mod fluxvm_client;
pub mod jobs;
pub mod node_agent;
pub mod policy;
pub mod pools;
pub mod shadow;
