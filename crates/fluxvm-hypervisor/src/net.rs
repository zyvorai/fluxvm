// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Host network bring-up helpers (documentation + command generation).
//! FluxVM does not create TAP devices itself when running jailed.

use crate::config::VmConfig;

pub fn host_setup_script(cfg: &VmConfig) -> String {
    let tap = cfg.tap.as_deref().unwrap_or("tap0");
    format!(
        r#"#!/bin/bash
# Run once as root on the host. Then start fluxvm as an unprivileged user
# that owns the TAP.
set -euo pipefail
TAP={tap}
USER=${{SUDO_USER:-$USER}}

# multi_queue if the guest has more than one virtio-net queue
ip tuntap add dev "$TAP" mode tap user "$USER" multi_queue || true
ip link set "$TAP" up

# Option A — NAT via libvirt default bridge
# ip link set "$TAP" master virbr0

# Option B — dedicated bridge onto a physical NIC
# ip link add name br0 type bridge
# ip link set dev eth0 master br0
# ip link set "$TAP" master br0
# ip link set br0 up

# Option C — macvtap (high throughput, no guest↔host L2)
# ip link add link eth0 name macvtap0 type macvtap mode bridge

echo "TAP $TAP ready. Start:"
echo "  fluxvm --tap $TAP --mac {} --vhost-net --cpus {} --memory-mib {} --kernel /path/vmlinux"
"#,
        cfg.mac, cfg.cpus, cfg.memory_mib
    )
}

pub fn nftables_nat_example(tap: &str) -> String {
    format!(
        r#"# Egress NAT + basic filter. Always filter at the host; the VMM does not.
nft add table inet fluxvm
nft add chain inet fluxvm nat '{{ type nat hook postrouting priority srcnat; }}'
nft add rule  inet fluxvm nat oifname "eth0" ip saddr 10.0.0.0/24 masquerade
nft add chain inet fluxvm filter '{{ type filter hook forward priority filter; }}'
nft add rule  inet fluxvm filter iifname "{tap}" oifname "eth0" accept
nft add rule  inet fluxvm filter iifname "eth0" oifname "{tap}" ct state established,related accept
"#
    )
}
