# Native eBPF as the primary dataplane

The VM-edge Network Fabric was already documented as GA. Its optional behavior
came from compatibility defaults (`legacy`, `required = false`), rather than an
experimental Rust feature gate. Native eBPF now becomes the code default.

## Default behavior

```toml
[sandbox.dataplane]
mode = "ebpf"
required = true
default_allow = true
```

These values apply when the table or individual fields are omitted, including
`Config::default()` and `DataplaneMode::default()`. A native attachment failure
on a host-visible VM edge propagates to create/start. It cannot silently take
the nftables fallback branch. Networking with no host-visible edge (`none`,
user-mode NAT) still skips attachment. Cilium coexistence remains explicitly
selected with `mode = "cilium"`; FluxVM never modifies Cilium private maps.

`required` governs attachment reliability, not packet allow/deny policy.
The default allow-all policy is preserved. For an explicit deny-by-default
allowlist, use `configs/network-fabric-ga.toml` or the production profile.

## Upgrade existing hosts

This is a behavior change for configs omitting the dataplane mode. Perform
readiness checks before restarting an upgraded daemon:

```sh
./scripts/network-fabric-preflight.sh --require-bpf
# Builds and installs the BPF objects, merges the GA policy profile:
sudo ./scripts/enable-network-fabric-ga.sh --dry-run
sudo ./scripts/enable-network-fabric-ga.sh --restart
```

Review that script's proposed policy first: the GA profile changes
`default_allow` to false and supplies an allowlist. It is not required just to
select the new defaults. Alternatively build/install the BPF objects and
retain your existing explicit policy. Host kernel support, bpffs, loader tools,
BPF permissions and service MEMLOCK/path access are still required; see
[network-fabric.md](network-fabric.md) and
[production-dataplane.md](production-dataplane.md).

For compatibility on a host that cannot attach native BPF:

```toml
[sandbox.dataplane]
mode = "legacy"
```

For an intentional lab fallback, set `mode = "ebpf"`, `required = false`.
Native-only policies still reject downgrade when their semantics cannot be
preserved. Explicit existing mode/required settings remain honored.

## Scope and verification

This promotes the existing VM-edge policy path. It does not replace host routing,
namespace setup, every NAT rule, the VM virtio transport, or Cilium's node CNI.
It adds no new BPF program or map ABI and makes no throughput claim.

Tests cover omitted tables/fields, enum defaults, explicit legacy/Cilium/lab
settings, missing-object failure without fallback, and skipping networks without
an edge. Run `cargo test -p fluxvm-core -p fluxvm-network --locked` in a complete
workspace. Live attachment, VM traffic, restart/reconcile and migration tests
must also run on a suitable privileged Linux host before production rollout.
The existing `sudo -E ./scripts/test-network-fabric.sh` exercises TC/XDP and
VM/API traffic; it temporarily changes service configuration and restarts the
service, so use a dedicated validation host. Run migration and restart recovery
checks there as well.
