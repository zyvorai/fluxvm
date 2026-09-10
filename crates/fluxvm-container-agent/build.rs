// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// Sentinel Set 8S: compiles bpf/fluxvm_guest_cgroup.bpf.c at `cargo build`
// time so main.rs can embed the resulting object via `include_bytes!` --
// this binary stays a single self-contained file the shim uploads into the
// guest over VSOCK (docs/secure-containers.md), with no separate .o to
// transfer alongside it. Requires `clang` on whatever machine builds this
// crate (already a project-wide requirement for bpf/, now also needed here
// specifically -- see .github/workflows/secure-containers.yml).

use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/fluxvm-container-agent is two levels below the workspace root")
        .to_path_buf();
    let script = workspace_root.join("scripts/build-ebpf-guest.sh");
    let source = workspace_root.join("bpf/fluxvm_guest_cgroup.bpf.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed={}", script.display());

    let status = Command::new("bash")
        .arg(&script)
        .arg(&out_dir)
        .status()
        .unwrap_or_else(|e| panic!("running {}: {e}", script.display()));
    if !status.success() {
        panic!("{} exited with {status}", script.display());
    }
}
