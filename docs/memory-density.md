# Memory density

Tools for packing more sandboxes on a host: a balloon you can drive per VM, create admission that looks
at real host memory pressure, automatic reclaim from idle sandboxes, and per-VM memory accounting that
counts shared pages fairly. For the fork and restore side of density see
[ROADMAP-DENSITY.md](ROADMAP-DENSITY.md) and [kvm-density.md](kvm-density.md).

## Roadmap and status

| Item | Implemented and type-checked | Verified on hardware |
|---|---|---|
| Balloon control (`GET/POST /v1/vms/{id}/balloon`, `fluxctl balloon`) | yes (unit tests pass) | not yet |
| Pressure-aware create admission | yes (pure decision function unit tested) | not yet |
| Idle balloon reclaim | yes (policy functions unit tested) | not yet |
| `GET /v1/vms/{id}/memory` (PSS, private, shared) | yes (parser unit tested) | not yet |
| `scripts/bench-density-count.sh` | yes (shell, not run) | not yet |
| Guest balloon driver reaching `actual_mib` | n/a | not yet |

Nothing in this batch has been run end-to-end on real VMs. No density numbers are claimed here; run the
benchmark below to get them for your host.

## Balloon control

The in-tree KVM engine (`backend = "flux-vm"`) exposes a virtio-balloon. The balloon takes memory
away from the guest so the host can reuse it.

```bash
fluxctl balloon $VM                    # read
fluxctl balloon $VM --set-mib 256      # ask the guest to give back 256 MiB
fluxctl balloon $VM --set-mib 0        # deflate fully
```

```bash
curl -sS http://127.0.0.1:7788/v1/vms/$VM/balloon
curl -sS http://127.0.0.1:7788/v1/vms/$VM/balloon -H 'content-type: application/json' -d '{"balloon_mib":256}'
```

```json
{"memory_mib": 1024, "target_mib": 256, "actual_mib": 192}
```

- `target_mib` is the size requested; the daemon writes it into the device config and raises a
  config-change interrupt.
- `actual_mib` is the size the guest driver has reached so far. It lags the target and can stop short.
- A balloon that would leave the guest under 64 MiB is rejected.
- Only a **running** VM on the flux-vm KVM engine has a balloon. Other backends and stopped VMs return
  400. `POST` is admin-only; `GET` is allowed for read-only tokens.
- Setting the balloon is audited as `vm.balloon` (`vm_id`, `target_mib`).

**Guest balloon driver caveat.** The host side only moves the target. The guest kernel must include and
load the `virtio_balloon` driver for `actual_mib` to follow. Without it the target changes and
`actual_mib` stays where it was, and no memory is returned. Check `actual_mib` after setting a target
and do not assume reclaim happened. Reclaimed memory also only helps the host if the pages were
actually backed by host memory; a guest that never touched them has nothing to give back.

## Pressure-aware admission

`policy.enforce_host_totals` compares requested sizes with declared quotas. The new gate looks at what
the host is doing instead. It runs on the create path (`POST /v1/vms` and sandbox create) after the
quota check. It is **off by default**: every threshold is unset.

```toml
[policy]
min_host_mem_available_mib   = 4096   # leave at least this much MemAvailable after the new VM lands
max_host_mem_psi_some_avg10  = 20.0   # refuse while memory PSI "some avg10" (percent) is above this
max_host_mem_psi_full_avg10  = 5.0    # refuse while memory PSI "full avg10" (percent) is above this
pressure_defer_secs          = 30     # wait up to this long for pressure to clear (0 = refuse now)
```

| Field | Check |
|---|---|
| `min_host_mem_available_mib` | `MemAvailable - requested memory_mib` must stay at or above this value |
| `max_host_mem_psi_some_avg10` | `/proc/pressure/memory` `some avg10` must not exceed it |
| `max_host_mem_psi_full_avg10` | `/proc/pressure/memory` `full avg10` must not exceed it |
| `pressure_defer_secs` | How long the create waits (re-sampling every second) before it is refused |

Behavior:

- A threshold whose input is unavailable (no PSI in the kernel, non-Linux host, unreadable file) is
  skipped, not treated as a failure.
- With `pressure_defer_secs > 0` the create request stays open and retries until the host recovers or
  the deadline passes. Size your client timeout above it.
- A refusal returns 400 with a message such as
  `host under memory pressure: 3100 MiB available, 2048 MiB requested, policy.min_host_mem_available_mib reserve is 4096 MiB`,
  and records a `quota.deny` audit event with `scope=pressure`.
- Only create is gated. Fork, pool claim and restore do not pass through this check.

## Idle reclaim

When a sandbox has been idle for a while, the daemon can inflate its balloon to hand memory back, and
deflate it again when the sandbox is active.

```toml
[sandbox]
idle_balloon_secs    = 60    # 0 (default) disables idle reclaim
idle_balloon_percent = 50    # share of guest memory to reclaim, 1-90 (default 50)
autopause_scan_secs  = 10    # how often the idle scanner runs (default 10)
```

- It runs on the same scanner as AutoPause (`autopause_scan_secs`). The scanner starts when either
  `autopause_idle_secs` or `idle_balloon_secs` is non-zero. Set `idle_balloon_secs` lower than
  `autopause_idle_secs`, otherwise the sandbox is paused before it is ballooned.
- Target size is `idle_balloon_percent` of the VM's `memory_mib`, never leaving the guest under 64 MiB.
- Only running flux-vm KVM-engine sandboxes are touched; procbox sandboxes and other backends are
  skipped. The scanner deflates only balloons it inflated itself, so a balloon you set by hand is
  left alone.
- It uses the same control path as `POST /v1/vms/{id}/balloon`, so it is subject to the guest driver
  caveat above, and it emits `vm.balloon` audit events.

## Per-VM memory report

```bash
fluxctl memory $VM
curl -sS http://127.0.0.1:7788/v1/vms/$VM/memory
```

```json
{
  "vm_id": "0c1d2e3f-0000-4000-8000-000000000001",
  "configured_mib": 1024,
  "usage": {"rss_kib": 310000, "pss_kib": 180000, "private_kib": 120000, "shared_kib": 190000, "swap_kib": 0},
  "balloon": {"memory_mib": 1024, "target_mib": 0, "actual_mib": 0}
}
```

Numbers come from `/proc/<pid>/smaps_rollup` of the VMM process:

- `pss_kib`: proportional set size. Private pages plus this process's share of shared pages. This is
  the number to add up across VMs, because forked children share their snapshot's clean pages and RSS
  counts those once per child.
- `private_kib`: private clean plus dirty. What this VM alone holds.
- `shared_kib`: shared clean plus dirty.
- `rss_kib`, `swap_kib`: as reported by the kernel.

`usage` is `null` when the VM has no VMM process or the file is unreadable; `balloon` is `null` when the
VM has no balloon device. It is read-only and available to read-only tokens.

## Measuring density: `scripts/bench-density-count.sh`

Boots flux-vm VMs of a fixed size one at a time until create is refused, host `MemAvailable` falls
below a floor, or `MAX` is reached. It records the count, the host `MemAvailable` change and each VM's
PSS (from `GET /v1/vms/{id}/memory`), and prints a JSON summary.

**It consumes host memory**, so it refuses to run unless `FLUXVM_BENCH_CONFIRM=1`. Safety rules, all
in the script:

- Linux with `/dev/kvm` only; otherwise it skips.
- A mandatory floor, `MIN_AVAIL_MIB` (default 2048). Values below 512 are refused. It does not start if
  `MemAvailable` is already below the floor, and before each create it stops if
  `MemAvailable - MEM_MIB` would fall below it (`stop_reason: "below_floor"`).
- It tracks the ids of the VMs it created and deletes only those, on exit. It never deletes by name
  pattern and never touches other VMs.

```bash
FLUXVM_BENCH_CONFIRM=1 MODE=BASELINE MEM_MIB=256 MAX=20 ./scripts/bench-density-count.sh
FLUXVM_BENCH_CONFIRM=1 MODE=TUNED    MEM_MIB=256 MAX=20 ./scripts/bench-density-count.sh
```

Environment: `MEM_MIB` (256), `MAX` (20), `MIN_AVAIL_MIB` (2048), `SETTLE_SECS` (5), `IMAGE`, `KERNEL`,
`FLUXVM_API`, `FLUXVM_TOKEN`, `FLUXVM_CONFIG`.

`MODE` is a **label** for a server configuration the script cannot change. Start the daemon to match:

| Mode | Server configuration |
|---|---|
| `BASELINE` | No idle balloon (`[sandbox] idle_balloon_secs = 0`) and eager restore (`FLUXVM_KVM_EAGER_RESTORE=1` in the daemon's environment) |
| `TUNED` | Idle balloon on (`idle_balloon_secs > 0`) and the default lazy, copy-on-write restore |

With `FLUXVM_CONFIG` pointing at the daemon's config file, the script checks `idle_balloon_secs`
against `MODE` and exits 2 on a contradiction. The eager-restore variable cannot be checked from the
script, so confirm it yourself. The summary's `mode_config_check` says whether the config check ran.

Output fields: `mode`, `mem_mib`, `count`, `stop_reason` (`max_reached`, `below_floor` or
`create_refused`), `host_mem_available_start_mib`, `..._end_mib`, `..._delta_mib`,
`host_delta_per_vm_mib`, `pss_avg_kib`, `pss_total_kib` and `per_vm[]`. Compare the two modes on the
same host, image and `MEM_MIB`. The script does not turn on pressure admission; set the `[policy]`
thresholds separately if you want create to be refused before the floor.
