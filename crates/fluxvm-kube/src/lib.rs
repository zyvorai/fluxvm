// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `DisposableVm` CRD + a node-local operator that reconciles them against a
//! *local* `fluxvm serve` instance's REST API. See `crd::DisposableVmSpec`
//! for the per-node targeting model and `controller` for the reconcile loop.

pub mod controller;
pub mod crd;
pub mod fluxvm_client;
pub mod placement;
