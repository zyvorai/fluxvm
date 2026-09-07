# Cilium-style tutorials for FluxVM Network Fabric

These tutorials mirror the hands-on style of [Cilium’s getting-started
guides](https://docs.cilium.io/en/stable/gettingstarted/) — short goals,
copy-paste commands, and a clear “what you should see” check — but they
target **FluxVM’s VM-edge dataplane**, not a Kubernetes CNI.

FluxVM does **not** write Cilium-private maps. Policies compile onto
Network Fabric pins under `/sys/fs/bpf/fluxvm` (schema **v4** when Cilium
parity is enabled).

| Tutorial | Cilium analogue | Time |
|----------|-----------------|------|
| [01 — Getting started](01-getting-started.md) | Install / first Hubble glance | ~10 min |
| [02 — Identities](02-identities.md) | Identity concept | ~10 min |
| [03 — Security groups](03-security-groups.md) | Label-based policy | ~15 min |
| [04 — Network policy (CNP)](04-network-policy.md) | CiliumNetworkPolicy | ~20 min |
| [05 — Default deny + deny CIDRs](05-default-deny.md) | `enableDefaultDeny` / `egressDeny` | ~15 min |
| [06 — Named ports](06-named-ports.md) | Named port in `toPorts` | ~10 min |
| [07 — Entities and FQDNs](07-entities-and-fqdns.md) | `toEntities` / `toFQDNs` | ~15 min |
| [08 — Audit mode](08-audit-mode.md) | `auditMode` | ~10 min |
| [09 — Observe (Hubble-lite)](09-observe.md) | `hubble observe` / identity list | ~10 min |
| [10 — Multi-group merge](10-multi-group-merge.md) | Multiple selectors | ~15 min |

Reference docs: [cilium-parity.md](../cilium-parity.md) ·
[network-groups.md](../network-groups.md) ·
[network-fabric.md](../network-fabric.md) ·
[ebpf-cilium.md](../ebpf-cilium.md).

## Shared prerequisites

1. Linux host with KVM, `fluxvm` installed, and Network Fabric eBPF enabled:

```toml
# /etc/fluxvm.toml (excerpt)
[sandbox.dataplane]
mode = "ebpf"
bpf_object = "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
pin_root = "/sys/fs/bpf/fluxvm"
required = true
```

Or: `sudo ./scripts/enable-network-fabric-ga.sh --restart` then bump to the
parity BPF object after `./scripts/build-ebpf.sh`.

2. Admin CLI access to the API (default `127.0.0.1:7788`):

```bash
export FLUXVM_CONFIG=/etc/fluxvm.toml
# Prefer sudo when state_dir is /var/lib/fluxvm (root-owned).
alias fx='sudo fluxvm --config /etc/fluxvm.toml'
```

3. Optional: a running FluxVm sandbox with TAP + netns (tutorials that need a
   live VM say so). Create one with your usual image/kernel, for example:

```bash
fx create --spec examples/fluxvm.json   # adjust image/kernel paths
fx list
```

## Quick map: Cilium CLI → FluxVM CLI

| Cilium / Hubble | FluxVM |
|-----------------|--------|
| `cilium status` | `curl -s localhost:7788/v1/vms` + `…/network/status` |
| `cilium identity list` | `fluxvm identity list` |
| `cilium policy get` / apply CNP | `fluxvm cnp apply\|list\|get\|delete` |
| Label selectors on endpoints | VM policy `labels` / `groups` |
| `hubble observe` | `fluxvm observe` + `…/network/flows` |
| Security / identity groups | `fluxvm group …` |

## Automated checks

```bash
python3 scripts/test-security-groups.py
python3 scripts/test-cilium-parity.py
cargo test -p fluxvm-network --lib
sudo -E ./scripts/test-security-groups-e2e.sh
# when present:
sudo -E ./scripts/test-cilium-parity-e2e.sh
```
