# Memory ballooning for sandboxes

A VM's balloon lets the host take memory back from an idle guest without stopping it. FluxVM has one for the KVM engine (`flux-vm`)
and for `vz`, where the runner sets the target of Virtualization.framework's traditional memory balloon device.

## By hand

```bash
curl -s localhost:7788/v1/vms/$ID/balloon                                  # {"memory_mib": 2048, "target_mib": 0, "actual_mib": 0}
curl -s -X POST localhost:7788/v1/vms/$ID/balloon -d '{"balloon_mib": 1024}' -H 'Content-Type: application/json'
```

`balloon_mib` is how much to take back; `0` gives it all back. `GET /v1/vms/{id}/memory` reports the balloon together with the VM's
configured memory.

## Idle reclaim

With `sandbox.idle_balloon_secs` set, the AutoPause scan inflates the balloon of a sandbox idle that long, taking
`sandbox.idle_balloon_percent` of its memory (at most 90 %, and never leaving it below 64 MiB), and deflates it on the next request. It touches
sandboxes only: KVM-engine VMs and `vz` VMs labelled `fluxvm.sandbox`.

While the host reports memory pressure (macOS level **warn** or **critical**), an idle sandbox is ballooned after 60 s instead, if
`idle_balloon_secs` is longer. Pressure never turns reclaim on by itself; `idle_balloon_secs = 0` keeps it off.

```toml
[sandbox]
idle_balloon_secs = 300
idle_balloon_percent = 50
```

## Metrics

| Metric                                | Meaning                                                     |
|---------------------------------------|-------------------------------------------------------------|
| `fluxvm_sandbox_balloons_inflated`    | sandboxes whose balloon idle reclaim currently holds inflated |
| `fluxvm_host_memory_pressure_level`   | 0 normal, 1 warn, 2 critical (macOS)                        |
| `fluxvm_host_mem_available_mib`       | memory the host can hand out without swapping               |

## Limits

- The guest must load `virtio_balloon` (stock Debian and Ubuntu cloud kernels do).
- A guest under its own memory pressure may not give memory back quickly; `actual_mib` shows what it really returned.
- Ballooning lowers what a running VM holds; it does not free a paused VM's memory. Hibernate (`sandbox.hibernate_idle_secs`, see
  [agent-density.md](agent-density.md)) does.
