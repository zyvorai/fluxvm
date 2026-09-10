# FluxVM Secure Containers — Set 6

Set 6 focuses on restart safety and CNI dual-stack while preserving the Set 5
VSOCK/PTY data path.

## Recovery journal

Each runtime group stores a versioned journal at:

```text
$FLUXVM_CONTAINERD_STATE_DIR/<namespace>/<group>/runtime-state.json
```

The journal records the FluxVM VM identity, CNI bridge/netns metadata, Pod
share paths, init task metadata and exec metadata. Writes are atomic
(temp-file + rename).

As soon as FluxVM returns a new VM ID, the shim writes `ready=false` ownership
before waiting for guest boot. Once guest networking, virtiofs mounts and the
container agent are ready, the journal becomes `ready=true`.

A replacement shim can recover only when it can prove that:

- the recorded VM still exists and its name matches;
- the recorded CNI host bridge/veth and netns bridge/veth still exist;
- the FluxVM guest agent responds;
- required virtiofs shares are mounted; and
- the secure-container agent is available for any recorded live process.

If live task metadata exists and those checks fail, the shim fails closed.
It will not cold-create a second VM for the same Pod.

A corrupt or unsupported journal also fails closed. Operators can disable
journal recovery with `FLUXVM_CONTAINER_RECOVER=0`, but should only do so after
they have independently established that no journal-owned VM is still alive.

> containerd supervision is separate from runtime state recovery. Set 6 makes a
> replacement shim safe to attach; it does not claim that every stock
> containerd configuration automatically respawns an abruptly killed shim.

## Re-attachable VSOCK streams

Set 5 introduced streaming stdio on VSOCK port 17779. Set 6 keeps the guest
pipe/PTY endpoints owned by `fluxvm-container-agent` and duplicates file
descriptors for each successful attachment. When a transport disconnects its
attachment flag is released so a replacement shim can attach again.

For stdin, transport EOF does **not** close the OCI process input. Only
containerd `CloseIO` performs the explicit EOF operation. This prevents a
temporary shim/socket loss from permanently closing interactive input.

## Dual-stack CNI

Set 6 captures every routable IPv4 and IPv6 address on the configured primary
CNI interface plus family-specific routes. The guest receives the same
addresses and routes, and teardown restores both families into the Pod netns.

IPv6 address replay uses `nodad` because the CNI plugin already owned and
validated the address before FluxVM moved the L2 endpoint into the guest.

### Multi-interface / Multus guard

A single FluxVM guest NIC currently represents the primary CNI endpoint. If the
Pod netns already contains another interface with a routable IPv4/IPv6 address,
Set 6 rejects the sandbox by default rather than silently dropping the
secondary network.

For controlled labs only:

```bash
export FLUXVM_CONTAINER_CNI_STRICT_MULTI_INTERFACE=0
```

Real Multus support should add explicit secondary NIC hotplug/rebind instead of
using that escape hatch in production.

## Warm-pool decision

FluxVM has paused VM pools, but current pool claims override only name and TTL.
Secure Containers needs Pod-specific CNI topology and Pod-specific virtiofs
shares, which are fixed at VM creation today. Reusing such a pool member across
Pods would break isolation.

Set 6 therefore instruments cold-start and recovered-sandbox latency but does
not use the existing VM pool API. A later performance set should first add
safe NIC/share rebinding or hotplug.

## Suggested node tests

```bash
sudo ./scripts/e2e-secure-containers-dualstack.sh
./scripts/inspect-secure-container-recovery.sh
```

Run the existing Set 5 TTY and volume tests as regressions as well.
