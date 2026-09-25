# Network policy tutorials

**One identity. One policy. At the VM edge.**

Label identities, CNP documents, deny lists, audit, and observe — copy-paste labs for operators of the FluxVM Network Fabric.

FluxVM pins programs under `/sys/fs/bpf/fluxvm` (schema **v4**). It does not write foreign CNI private maps. Node CNI coexistence (`mode=cilium`): [ebpf-cilium.md](../ebpf-cilium.md).

| Tutorial | Focus | Time |
|----------|-------|------|
| [01 — Getting started](01-getting-started.md) | Enable Fabric, identities, observe | ~10 min |
| [02 — Identities](02-identities.md) | Reserved + group identity numbers | ~10 min |
| [03 — Security groups](03-security-groups.md) | Label-based policy | ~15 min |
| [04 — Network policy (CNP)](04-network-policy.md) | Apply a CNP JSON | ~20 min |
| [05 — Default deny + deny CIDRs](05-default-deny.md) | Fail-closed egress | ~15 min |
| [06 — Named ports](06-named-ports.md) | `https` / `dns` in `toPorts` | ~10 min |
| [07 — Entities and FQDNs](07-entities-and-fqdns.md) | `toEntities` / `toFQDNs` | ~15 min |
| [08 — Audit mode](08-audit-mode.md) | Log-and-forward | ~10 min |
| [09 — Observe](09-observe.md) | Snapshot identities/groups/CNPs/VMs | ~10 min |
| [10 — Multi-group merge](10-multi-group-merge.md) | Union / min-rate semantics | ~15 min |

Reference: [network-policy.md](../network-policy.md) ·
[network-groups.md](../network-groups.md) ·
[network-fabric.md](../network-fabric.md) ·
[production-dataplane.md](../production-dataplane.md) ·
[PRODUCTION.md](../PRODUCTION.md) ·
[production readiness tutorials](../production/README.md) ·
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

Or: `sudo ./scripts/enable-network-fabric-ga.sh --restart` then install a
fresh BPF object from `./scripts/build-ebpf.sh`.

2. Admin CLI access (default API `127.0.0.1:7788`):

```bash
export FLUXVM_CONFIG=/etc/fluxvm.toml
# Prefer sudo when state_dir is /var/lib/fluxvm (root-owned).
alias fx='sudo fluxctl --config /etc/fluxvm.toml'
```

3. Optional: a running FluxVm sandbox with TAP + netns when a live VM is
   required:

```bash
fx create --spec examples/fluxvm.json   # adjust image/kernel paths
fx list
```

## CLI cheat sheet

| Task | Command |
|------|---------|
| Liveness | `curl -sf localhost:7788/healthz` |
| Readiness | `curl -sf localhost:7788/readyz` |
| API / VM list | `curl -s localhost:7788/v1/vms` |
| Per-VM dataplane status | `GET …/v1/vms/{id}/network/status` |
| List identities | `fluxctl identity list` |
| Apply / list CNP | `fluxvm cnp apply\|list\|get\|delete` |
| Security groups | `fluxvm group …` |
| Observe snapshot | `fluxctl observe` |
| Dataplane health | `fluxvm dataplane health` |
| Guest IP → identity | `fluxvm dataplane ipcache` |
| Refresh FQDN allowlist | `fluxvm dataplane refresh-dns` |
| Per-VM flows | `GET …/network/flows` |

## Automated checks

```bash
python3 scripts/test-security-groups.py
python3 scripts/test-network-policy.py
python3 scripts/test-production-dataplane.py
cargo test -p fluxvm-network --lib
sudo -E ./scripts/test-security-groups-e2e.sh
sudo -E ./scripts/test-production-dataplane-e2e.sh
```
