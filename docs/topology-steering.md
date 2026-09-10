# FluxVM Set 8 — vCPU/NUMA/RPS steering and IRQ intelligence

Set 8 turns scheduler and interrupt behavior into VM-scoped topology evidence, then produces an explicit, reversible steering plan. It is intentionally split into an observation plane (eBPF) and a mutation plane (userspace). Nothing changes CPU affinity, IRQ routing, RPS/XPS, RSS, Cilium, or Zyvor Fabric policy merely because telemetry crosses a threshold.

## Signals

`fluxvm_topology.bpf.c` records vCPU runtime by `(vm, vcpu, host cpu)`, scheduler migrations, maximum observed run slice, hardirq/softirq duration per CPU, and NET_RX/NET_TX softirq time. Long IRQ/softirq/vCPU slices and vCPU migrations are sent to a bounded ring buffer. VM identity comes only from vCPU TIDs explicitly registered by userspace; arbitrary VMM helper threads are never pinned as vCPUs.

Userspace augments the BPF data with host CPU package/core/NUMA topology, `/proc/<pid>/numa_maps`, per-queue RPS/XPS masks, and interface-matching `/proc/interrupts` entries.

## Planning rules

The planner prefers the NUMA node that already backs most of the VMM's resident pages. If that is unavailable it uses observed vCPU runtime locality. CPUs on that node are ordered by observed hardirq + softirq time so noisy CPUs are selected last. Every recognized vCPU receives a proposed single-CPU affinity. If a dedicated VM interface is supplied, its RPS/XPS queues and directly matching IRQ affinities are included.

Hardware RSS indirection is advisory only. FluxVM will not run `ethtool -X` automatically because the physical NIC may be shared with Cilium, Fabric, host traffic, SR-IOV peers, or other VMs. A dedicated PF/VF can be tuned separately after ownership is verified.

## Transaction and rollback safety

Before applying a plan, Set 8 re-reads every task affinity, queue mask, and IRQ affinity and refuses the transaction if any value differs from the plan preimage. If a later action fails, earlier actions are rolled back best-effort. A receipt under `/var/lib/fluxvm/topology/<uuid>.receipt.json` stores the exact old/new values. Rollback itself is drift-guarded: if another operator or daemon changed a setting after FluxVM applied it, FluxVM refuses to overwrite that newer state.

## Commands

```text
fluxvm-topology load
fluxvm-topology register <uuid> <vmm-pid>
fluxvm-topology snapshot <uuid> <vmm-pid> [interface]
fluxvm-topology plan <uuid> <vmm-pid> [interface] [plan.json]
fluxvm-topology apply plan.json
fluxvm-topology rollback <uuid>
fluxvm-topology events <uuid> 5 128
fluxvm-topology serve 127.0.0.1:7794
```

The service exposes `/healthz`, `/v1/topology/status`, `/v1/topology/vms`, `/v1/topology/vms/{id}`, and `/metrics`. The daemon only snapshots telemetry; plan application stays a local administrative action.

## Coexistence boundary

Set 8 never writes Cilium maps, Zyvor Fabric maps, Kubernetes policy, TC/XDP attachment state, or hardware RSS by itself. It only writes scheduler affinity and queue/IRQ sysfs/procfs controls explicitly present in an approved plan. For shared physical NICs, prefer leaving hardware queue ownership to the existing network stack and use Set 8 as diagnostics.
