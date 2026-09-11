# Sentinel Set 15E — Fleet Rollout + Canary Controller

Set 15E turns the node-local Set 14E upgrade transaction into an auditable fleet rollout. It does **not** bypass Set 14E: every node still performs its own state-ABI checks, map snapshot/restore, health verification, and rollback.

Safety properties:
- SSH host keys are strict by default; insecure checking is an explicit plan opt-in.
- Rollout plans are SHA-256 pinned after the journal is created.
- Node inventory is captured before changes and nodes are grouped by architecture/kernel-minor/sched_ext cohort.
- First wave is a canary; it can require an explicit `approve` before later waves. Subsequent waves are bounded by `wave_size` and `max_parallel`.
- A wave exceeding `max_failures` pauses the rollout and can roll back that wave in reverse node order.
- Each node delegates to `fluxvm-upgrade` (Set 14E); Set 15E does not directly rewrite bpffs state.
- Evidence contains the final journal, normalized plan and SHA-256 manifest.
- The privileged host gate is inventory-only unless an operator explicitly runs `fluxvm-fleet run`.

## Commands
```bash
fluxvm-fleet validate fleet.json
fluxvm-fleet probe fleet.json
fluxvm-fleet plan fleet.json
sudo fluxvm-fleet run fleet.json
fluxvm-fleet approve fleet.json   # when manual canary approval is enabled
sudo fluxvm-fleet resume fleet.json
fluxvm-fleet status fleet.json
fluxvm-fleet evidence fleet.json
```

## Production rollout pattern
Use one node as canary, dwell long enough to observe production SLOs, then proceed in small waves. Set `max_failures=0` for control-plane/kernel changes. Keep at least one healthy node per failure domain outside the active wave. Do not place SSH private keys or tokens in the rollout JSON; reference protected files from the node entries instead.

## Boundary
This is a host-fleet rollout controller, not a cluster scheduler and not a replacement for Zyvor Fabric. It does not perform BGP/ECMP decisions, VM placement, service discovery, or Kubernetes workload rollout.
