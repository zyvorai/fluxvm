# Many small agent VMs on Macs: how the pieces fit

| Piece                      | What it does                                                        | Doc                                         |
|----------------------------|---------------------------------------------------------------------|---------------------------------------------|
| Mac Studio options         | displays, clipboard, bridged and vmnet networking, custom virtio     | [macos.md](macos.md)                        |
| macOS guests               | install from an IPSW through the API, first-boot SSH keys           | [macos.md](macos.md)                        |
| Agent density              | profiles, pressure admission, idle pause, hibernate, warm pool      | [agent-density.md](agent-density.md)        |
| Guest agent over vsock     | exec and files without SSH; token by cloud-init                     | [vsock-agent.md](vsock-agent.md)            |
| vsock path for sandboxes   | agent first, SSH fallback; runner relay                             | [vsock-proxy.md](vsock-proxy.md)            |
| agent-micro image          | Debian 13 arm64 with the agent                                      | [agent-micro.md](agent-micro.md)            |
| Ballooning                 | idle reclaim, sooner under pressure                                 | [ballooning.md](ballooning.md)              |
| Fleet placement            | nodes report pressure and warm slots; placement avoids hot Macs     | [kairon-mac-scheduling.md](kairon-mac-scheduling.md) |
| Topology labels            | `nodeSelector` on fabric, rack, chip                                | [topology.md](topology.md)                  |

## A request, end to end

```
agent / MCP client
   │  POST /fleet/vms or Kairon Machine
   ▼
fleet registry ── skips Macs at critical pressure, prefers normal, then most room
   │
   ▼
fluxctl serve on the chosen Mac (vz)
   ├─ admission: policy.deny_host_pressure_level, min_host_mem_available_mib (vm_stat + kernel level)
   ├─ default shape: restore a warm slot (about 2 s); other shapes and images: cold boot
   ├─ /process, /fs/*: guest agent over vsock (agent-micro), else SSH
   └─ AutoPause scan: balloon (sooner under pressure) → pause → hibernate; the next request undoes it
```

## What to watch

`GET /v1/sandboxes/density` per Mac, and in `/metrics`: `fluxvm_host_memory_pressure_level`, `fluxvm_host_mem_available_mib`,
`fluxvm_sandbox_warm_hits_total` / `_misses_total`, `fluxvm_sandbox_balloons_inflated`, `fluxvm_vz_agent_calls_total` /
`fluxvm_vz_agent_ssh_fallbacks_total`.

## Testing on a Mac

```bash
fluxctl serve &
scripts/e2e-smoke.sh                       # health, warm and profiled sandboxes, exec and files, density, metrics
AGENT_MICRO=1 scripts/e2e-smoke.sh         # also requires the guest agent to answer (agent-micro in the catalog)
scripts/density-smoke.sh 8 tiny            # how many tiny sandboxes this Mac carries
cargo test -p fluxvm-core -p fluxvm-scheduler -p fluxvm-apple -p fluxvm-api -p fluxvm-agent
```

Unattended Macs: [deploy/launchd-notes.md](../deploy/launchd-notes.md).
