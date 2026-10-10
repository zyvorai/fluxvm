# Scheduling small agent VMs across Mac minis and Mac Studios

Several Macs, each running `fluxctl serve` on the `vz` backend, can share bursts of small agent sandboxes. Kairon (or any fleet
scheduler) decides which Mac gets each VM; this page lists what FluxVM gives it to decide with.

```
 Mac Studio                Mac Studio                Mac mini
 fluxctl serve (vz)        fluxctl serve (vz)        fluxctl serve (vz)
 fluxvm-agent node ──┐     fluxvm-agent node ──┐     fluxvm-agent node ──┐
                     └──────────────┬──────────┴─────────────────────────┘
                          fluxvm-agent central  (or Kairon)
```

## What each Mac reports

`fluxvm-agent node` heartbeats to the central registry every 10 s (see [deploy/kairon-node-mac.md](../deploy/kairon-node-mac.md)):

| Field                     | Source                                 | Use                                    |
|---------------------------|----------------------------------------|----------------------------------------|
| `vcpus_total`, `memory_mib_total`, `vm_count` | the host and `GET /v1/vms` | residual-capacity placement    |
| `labels`                  | `--label key=value`, set by the operator | `nodeSelector`                        |
| `density.host_pressure_level` | `kern.memorystatus_vm_pressure_level` | avoid Macs under memory pressure    |
| `density.host_mem_available_mib` | `vm_stat`                       | room for one more VM                   |
| `density.warm_slots_ready` | the warm pool                         | prefer Macs that start a sandbox in 2 s |
| `density.active_sandboxes`, `paused_sandboxes`, `hibernated_sandboxes` | sandbox labels | load               |

`density` is the node's [`GET /v1/sandboxes/density`](agent-density.md). `GET /fleet/nodes` returns all of it.

Suggested static labels:

| Label                              | Example   |
|------------------------------------|-----------|
| `kairon.zyvor.dev/backend.vz`      | `true`    |
| `kairon.zyvor.dev/chip`            | `m4-max`  |
| `kairon.zyvor.dev/memory-gib`      | `64`      |

Labels are fixed at agent start; anything that changes (pressure, warm slots) is in `density`, not in labels, because a
`nodeSelector` matches exactly.

## How the built-in central placement uses it

`POST /fleet/vms` without a `node` places automatically:

1. Healthy, uncordoned nodes whose labels match the `nodeSelector`.
2. A node reporting **critical** memory pressure is skipped.
3. A node at **normal** pressure (or reporting none, as Linux hosts do) is preferred over one at **warn**.
4. Among those, the most residual capacity wins, then fewer VMs.

If every candidate is critical, placement fails with "no healthy, uncordoned nodes"; the caller retries or queues. On each Mac, the
daemon's own admission (`policy.deny_host_pressure_level`, `min_host_mem_available_mib`) is the last check and refuses a create the
fleet view raced past.

## macOS guests

macOS guests are limited to two per Mac by Apple. `fluxvm_scheduler::apple_placement::pick` takes each host's macOS guest count and
memory and picks the tightest fit, so small hosts fill first and large ones stay free for large VMs. See
[macos-cluster.md](macos-cluster.md).

## What Kairon sends

A Kairon `Machine` ends up as a FluxVM create request. For a tiny agent sandbox that is
[examples/sandbox-agent-micro.json](../examples/sandbox-agent-micro.json) (`POST /v1/sandboxes`) or, for a plain VM, a create request
with `"backend": "vz"`, `"vcpus": 1`, `"memory_mib": 512`. [examples/machine-tiny-agent.yaml](../examples/machine-tiny-agent.yaml)
shows the Kairon side; its field names belong to Kairon and are not validated here.

## One Mac

With one node, placement always picks it, and behaviour is the same as plain FluxVM.
