# CPU / memory oversubscription

Firecracker’s design leaves oversubscription to the operator. FluxVM does the
same via **cgroup v2** on every backend (QEMU, Cloud Hypervisor, Firecracker,
FluxVm hypervisor).

## Runtime controls

`PATCH /v1/vms/{id}/resources` (or CLI equivalent) applies:

| Field | Effect |
|---|---|
| `cpu_quota_percent` | `cpu.max` via `CpuMax::from_percent` |
| `memory_max_bytes` | `memory.max` |
| `cpuset_cpus` | `cpuset.cpus` |
| `pids_max` / `io_weight` | pids / io controllers |

## Policy defaults (FC1)

In `[policy]` (all backends at cgroup attach):

```toml
[policy]
# Cap each VM to 50% of one host CPU at launch
default_cpu_quota_percent = 50
# Pin memory.max to the guest's memory_mib (no silent host overcommit)
memory_max_equals_guest = true
```

With `memory_max_equals_guest = false` (default), `memory.max` stays unlimited
and the host may overcommit guest RAM — same as Firecracker’s default demand
paging story. Set it true when you want hard per-VM memory caps.

Warm pools and dense microVM packing still use Firecracker Track B benches
([capability-figures.md](capability-figures.md)); oversub knobs do not change
product identity.

## Recipes

| Goal | Knobs |
|---|---|
| Soft oversub (dense packing) | Leave `memory_max_equals_guest` false; optional low `default_cpu_quota_percent` |
| Hard isolation | `memory_max_equals_guest = true` + per-tenant `max_memory_mib_total` |
| Pin to cores | `cpuset` on create (QEMU) or PATCH `cpuset_cpus` after start |
| Per-VM live change | `set_resources` / PATCH resources |

See also [PRODUCTION.md](PRODUCTION.md) and [operations.md](operations.md).
