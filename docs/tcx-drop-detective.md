# FluxVM TCX + Drop Detective

This set adds two node-local FluxVM capabilities and deliberately leaves distributed routing, BGP, multi-site topology and remote identity ownership to Zyvor Fabric.

## 1. TCX / BPF-link VM edge

`FLUXVM_TCX` controls the attachment preference:

- `auto` (default): try TCX first; if the kernel/helper rejects it, fall back to the existing clsact/`tc` attachment.
- `off`: preserve the current clsact/`tc` path.
- `required`: TCX is a hard requirement; VM-edge dataplane attachment fails closed when TCX is unavailable.

The helper is `/usr/libexec/fluxvm/fluxvm-tcx` when installed. `FLUXVM_TCX_HELPER` can override it.

TCX is used only on FluxVM-owned VM TAP/veth/macvtap edges. FluxVM never writes Cilium private maps. The pinned link lives beside the VM's existing BPF program/maps under:

```
/sys/fs/bpf/fluxvm/vms/<uuid>/links/tcx_ingress
```

The helper supports `probe`, `attach`, `status`, `update` and `detach`. `update` uses `BPF_LINK_UPDATE`, so a preloaded compatible program generation can replace the program behind the pinned link atomically without an unattached policy window.

## 2. VM Drop Detective

Runtime Intelligence gains:

```
GET /v1/intelligence/vms/<uuid>/diagnose
fluxvm diagnose <uuid>
fluxvm-intelligence diagnose <uuid>
```

`fluxvm diagnose` is a direct one-shot path: it reads the VM record through the local manager, samples Runtime Intelligence, and correlates policy/flow state without requiring the companion intelligence HTTP daemon. The HTTP endpoint and `fluxvm-intelligence diagnose` remain useful for long-running observability integrations.

It correlates the VM's stable identity/runtime snapshot with:

- `/v1/vms/<uuid>/network/effective` (merged VM + group/CNP policy)
- `/v1/vms/<uuid>/network/pod-policy`
- `/v1/vms/<uuid>/network/flows?limit=256`
- the eBPF VM-edge allow/drop counters already included in Runtime Intelligence v1

Deterministic visible-policy causes are marked `exact`: explicit CIDR deny, CIDR allowlist miss, L4 allowlist miss, Pod peer deny/default-deny, and VM default-deny. Stateful/rate/group/FQDN cases are marked `probable` instead of claiming kernel certainty that the current flow-map ABI does not carry.

Example output fragment:

```json
{
  "severity": "warning",
  "summary": "1 VM-edge drop finding(s); top cause l4-not-allowed at vm-policy/l4-allowlist (17 packet(s)).",
  "drop_findings": [{
    "stage": "vm-policy/l4-allowlist",
    "code": "l4-not-allowed",
    "confidence": "exact",
    "explanation": "protocol tcp destination port 80 is outside the VM L4 allowlist.",
    "suggestion": "Permit only the required protocol/port pair in allow_ports."
  }]
}
```

## Validation

Run the portable gates:

```
./scripts/test-tcx-drop-detective-static.sh
```

On a Linux 6.6+ root-capable host with KVM/eBPF dependencies installed, also run:

```
sudo ./scripts/test-tcx-host.sh
```

The GitHub workflow in this set builds the Rust crates, compiles both libbpf helpers, builds all eBPF objects, and runs the portable tests. The privileged TCX smoke script is intentionally separate because standard GitHub-hosted runners do not provide the host privileges needed to prove real TCX attachment safely.

## Compatibility and PR dependency

This is PR/set 2 and depends on **Runtime Intelligence v1**. It intentionally keeps the existing VM-edge BPF map/flow schema unchanged, so already pinned Network Fabric v5 maps do not need an ABI migration. Drop causes that can be proven from the current policy + flow tuple are labelled `exact`; rate/compiled-policy cases are labelled `probable`. A kernel-carried branch/reason code is deliberately reserved for the next ABI-changing set.
