# Agent density on a Mac mini or Mac Studio

How to run many small Linux agent sandboxes on one Apple Silicon Mac with the `vz` backend. The sandbox API itself is described in
[macos-sandboxes.md](macos-sandboxes.md); this page covers sizing, admission, idle reclaim and the warm pool.

## Profiles

`POST /v1/sandboxes` takes a `profile`:

| Profile    | vCPUs | Memory   | Use                                  |
|------------|-------|----------|--------------------------------------|
| `tiny`     | 1     | 512 MiB  | shell-and-files agents; the densest  |
| `small`    | 1     | 1 GiB    | light coding agents                  |
| `standard` | 2     | 2 GiB    | the default sandbox shape            |

```json
{"name": "agent-1", "profile": "tiny", "ttl_seconds": 600}
```

An explicit `vcpus` or `memory_mib` wins over the profile. Warm slots are standard-sized, so `tiny` and `small` sandboxes cold-boot
(about 8 s with `debian-13`); `"image": "agent-micro"` gives them the [vsock guest agent](agent-micro.md) instead of SSH. A `standard` profile is the same as
no profile and can claim a warm slot. See [examples/sandbox-tiny.json](../examples/sandbox-tiny.json).

Container sandboxes ([oci-sandboxes.md](oci-sandboxes.md)) are the lightest shape: a container image booted straight into its
entrypoint with no systemd, cloud-init or sshd, 1 vCPU and 512 MiB unless a profile or size says otherwise. Profiles, admission,
quotas and TTLs apply to them as to any sandbox; they do not use the warm pool yet.

## Admission on real memory pressure

The pressure gate in `policy` (all off by default) now works on macOS too. On a Mac the daemon samples available memory from
`vm_stat` (free + inactive + speculative + purgeable pages) and the kernel's own verdict, `kern.memorystatus_vm_pressure_level`
(normal, warn, critical):

```toml
[policy]
deny_host_pressure_level = "warn"     # refuse creates while macOS reports warn or critical
min_host_mem_available_mib = 4096     # keep 4 GiB free after the new VM's memory is counted
pressure_defer_secs = 30              # wait up to 30 s for pressure to clear before refusing
```

A refused create is reported with the reason (for example `host under memory pressure: level warn reaches
policy.deny_host_pressure_level (warn)`) and audited as `quota.deny`. The PSI thresholds (`max_host_mem_psi_*`) are Linux-only and
are skipped on a Mac.

## Idle sandboxes

Three idle stages, all off by default and all driven by the same scan (`sandbox.autopause_scan_secs`). Each `vz` sandbox is labelled
`fluxvm.sandbox`, so only sandboxes are touched, never an ordinary `vz` VM.

| Setting                         | After this long idle                  | What it frees                        | Comes back on the next request |
|---------------------------------|---------------------------------------|--------------------------------------|--------------------------------|
| `sandbox.idle_balloon_secs`     | inflate the balloon                   | `idle_balloon_percent` of its memory | deflated, instantly            |
| `sandbox.autopause_idle_secs`   | pause the VM                          | CPU only (memory stays resident)     | resumed, instantly             |
| `sandbox.hibernate_idle_secs`   | save memory to disk and stop the VM   | all of its memory                    | restored, about 2 s            |

"Request" means any sandbox API call: `/process`, `/fs/read`, `/fs/write` and the MCP tools. A hibernated sandbox shows as `stopped`
with the label `fluxvm.hibernated`. Hibernate uses snapshot restore, so it needs an unlocked login session; when the restore fails
(locked screen, macOS updated in between) the sandbox cold-boots instead, losing what was in memory but keeping its disk.
Set the stages in increasing order:

```toml
[sandbox]
idle_balloon_secs = 60
autopause_idle_secs = 180
hibernate_idle_secs = 900
```

## Warm pool

`sandbox.warm_slots` (default 2 on a Mac) keeps that many stopped, snapshotted VMs ready. Before a burst of creates, fill it further:

```bash
fluxctl --server http://127.0.0.1:7788 sandbox warm --count 8
curl -s -X POST localhost:7788/v1/sandboxes/warm -H 'Content-Type: application/json' -d '{"count": 8}'
# -> {"target": 8}   (202; slots are built one at a time in the background, about 8 s each)
```

`count` is 1-64 and never below `warm_slots`. After the burst, the pool refills to `warm_slots` only; surplus slots stay until claimed
or deleted. Each slot costs disk (an APFS clone plus its saved memory), not RAM. Warm requests and the density report are host-wide,
so a tenant-scoped token is refused.

## Density report and metrics

```bash
fluxctl sandbox density            # or: curl -s localhost:7788/v1/sandboxes/density
```

```json
{
  "warm_slots_configured": 2, "warm_slots_ready": 2, "warm_hits": 14, "warm_misses": 3,
  "active_sandboxes": 9, "paused_sandboxes": 4, "hibernated_sandboxes": 11,
  "resident_estimate_mib": 6656,
  "host_mem_available_mib": 9120, "host_mem_total_mib": 36864, "host_pressure_level": "normal",
  "oci_warm_slots_configured": 2, "oci_warm_slots_ready": 2, "oci_warm_slots_booting": 0,
  "oci_warm_resident_mib": 1024, "oci_warm_hits": 31, "oci_warm_misses": 2, "oci_warm_last_claim_ms": 410
}
```

The `oci_warm_*` fields describe the container sandbox warm pool ([oci-sandboxes.md](oci-sandboxes.md#warm-pool)): waiting slots
hold their memory, so `oci_warm_resident_mib` is not part of `resident_estimate_mib`.

`resident_estimate_mib` is the configured memory of running and paused sandboxes (a balloon gives some of it back). `/metrics` adds
`fluxvm_sandbox_warm_hits_total` and `fluxvm_sandbox_warm_misses_total`.

## Rough capacity

Active `tiny` sandboxes, leaving room for macOS:

| Mac                  | Active tiny sandboxes |
|----------------------|-----------------------|
| Mac mini, 16 GB      | 4-8                   |
| Mac Studio, 36 GB    | 12-20                 |
| Mac Studio, 64 GB+   | 25-40                 |

Hibernated sandboxes hold no memory, so many more can exist; they are limited by disk. These are estimates, not measurements; host
load, the guest image and what the agents run change them. `scripts/density-smoke.sh` creates a batch and prints the report, which
is the quickest way to find the real number for a host.

## Unattended hosts

Snapshot restore (warm slots, hibernate) needs an unlocked login session. On a headless Mac: a dedicated user with automatic login,
the daemon started by launchd in that user's session, and the screen lock off. See [deploy/launchd-notes.md](../deploy/launchd-notes.md).
