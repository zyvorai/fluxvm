# Security groups (Cilium-style identities)

FluxVM Network Fabric v3 keeps per-VM TC pins. Security groups add the
control-plane piece Cilium uses at scale: **label → numeric identity →
shared L3/L4 policy**, plus deny CIDRs, ICMP passthrough, and an
established-flow table.

Cilium private maps are still never written. Groups live under
`$state_dir/network-groups/groups.json` and are folded into FluxVM-owned
maps (`fluxvm_v4` / `fluxvm_v6` / `fluxvm_l4` / `fluxvm_deny4` /
`fluxvm_deny6`) plus `fluxvm_gid` and `fluxvm_ct`.

## Model

| Object | Role |
|--------|------|
| Label | `key=value`. Example: `app=web`, `env=prod`. |
| Group | Named policy + labels + priority. Identity is a stable FNV of sorted labels in the `0x10000+` range. |
| VM policy | May list `groups`, `labels`, `deny_cidrs`, `allow_icmp`. |
| Membership | Named group **or** every group label present on the VM. Cap: 8 groups / VM. |
| Effective policy | Union of allow/deny CIDRs and ports. Tightest Mbps/PPS wins. Any fail-closed member forces `default_allow=false`. |

Per-VM identities stay in `1..=0xffff` (`ebpf::identity_for`).

## BPF maps added

| Map | Role |
|-----|------|
| `fluxvm_gid` | ifindex → up to eight group identities |
| `fluxvm_ct` | LRU established 5-tuple table |
| `fluxvm_deny4` / `fluxvm_deny6` | LPM deny lists (evaluated before allow) |

`iface_config.allow_icmp` uses the former pad word so ICMP/ICMPv6 can bypass L4 allowlists when set.

L4 rules accept `tcp/PORT`, `udp/PORT`, `icmp/0`, `icmp6/0`. Port `0` on ICMP means any type.

## REST

```http
GET    /v1/network/groups
POST   /v1/network/groups
GET    /v1/network/groups/{name}
DELETE /v1/network/groups/{name}
GET    /v1/vms/{id}/network/effective
POST   /v1/vms/{id}/network/policy
```

`POST /v1/network/groups`:

```json
{
  "name": "web",
  "labels": ["app=web", "env=prod"],
  "priority": 10,
  "description": "HTTPS egress",
  "policy": {
    "default_allow": false,
    "allow_cidrs": ["10.0.0.0/8", "2001:db8::/32"],
    "deny_cidrs": ["10.66.0.0/16"],
    "allow_ports": ["tcp/443", "udp/53", "icmp/0"],
    "allow_icmp": true,
    "max_egress_mbps": 250
  }
}
```

Admin role required for writes when auth is enabled.

## CLI

```bash
fluxvm group set web \
  --label app=web --label env=prod \
  --allow-cidr 10.0.0.0/8 \
  --deny-cidr 10.66.0.0/16 \
  --allow-port tcp/443 \
  --allow-icmp \
  --priority 10 \
  --default-allow false

fluxvm group list
fluxvm group get web
fluxvm group delete web
```

## Why this is not writing Cilium maps

Cilium identities are cluster-scoped and encoded in release-specific private
maps. FluxVM VMs are not Cilium endpoints today. Shared **semantics** stay
on `/sys/fs/bpf/fluxvm`.

## Validation

Control-plane unit checks (no root / no Rust toolchain required for the
Python suite):

```bash
python3 scripts/test-security-groups.py
cargo test -p fluxvm-network --lib
```

Full privileged e2e on Linux/KVM (builds BPF, enables `mode=ebpf`, creates a
FluxVm TAP+netns sandbox, exercises group CRUD, label/named membership,
`/v1/vms/{id}/network/effective` merge rules, deny/L4 maps, `allow_icmp`,
CLI delete → membership refresh, and teardown):

```bash
sudo -E ./scripts/test-security-groups-e2e.sh
# optional: --kernel PATH --rootfs PATH --skip-download --skip-unit
```

Also covered by the broader Network Fabric suite:

```bash
sudo -E ./scripts/test-network-fabric.sh
```

Example group: [examples/security-group-web.json](../examples/security-group-web.json).
