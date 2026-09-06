// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Safe Cilium coexistence boundary.
//!
//! FluxVM never writes Cilium's private BPF maps. Cilium owns Kubernetes
//! node/CNI networking; FluxVM owns only the VM-edge TAP/veth program and
//! pins its maps below `/sys/fs/bpf/fluxvm`.

use anyhow::{Context, Result, bail};
use std::path::Path;

pub fn validate_host() -> Result<()> {
    let socket = Path::new("/var/run/cilium/cilium.sock");
    if !socket.exists() {
        bail!(
            "Cilium coexistence requested but {} is not visible; install Cilium or mount /var/run/cilium into FluxVM",
            socket.display()
        );
    }
    let bpffs = Path::new("/sys/fs/bpf");
    if !bpffs.exists() {
        bail!("Cilium coexistence requires bpffs at /sys/fs/bpf");
    }
    std::fs::metadata(bpffs).with_context(|| format!("reading {} metadata", bpffs.display()))?;
    Ok(())
}
