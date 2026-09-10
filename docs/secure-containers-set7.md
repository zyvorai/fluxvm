# FluxVM Secure Containers — Set 7

Set 7 closes operational gaps that become visible once the Set 5 streaming and
Set 6 recovery paths are in place: container OOM events, richer cgroup-v2
metrics/resource updates, fail-closed device handling, and retry-safe sandbox
teardown.

## OOM events

`fluxvm-container-agent` exposes monotonic counters from each container
cgroup's `memory.events` file. The shim polls those counters over the existing
authenticated lifecycle VSOCK channel and publishes containerd `TaskOOM`
(`/tasks/oom`) when `oom_kill` increases.

The last published `oom_kill` value is stored in the Set 6 runtime journal.
That matters during replacement-shim recovery: an OOM kill that happens while
the previous shim is unavailable is not silently forgotten when the new shim
re-attaches.

The monitor is container-level, not exec-level, matching cgroup-v2 accounting:
init and exec processes share the container cgroup.

## Richer cgroup-v2 metrics

`StatsTask` now carries:

- CPU usage/user/system time;
- CPU periods, throttled periods, and throttled time;
- memory current/peak/limit;
- swap current/limit;
- anon, file, THP, mapped-file, dirty/writeback accounting;
- page faults and major page faults;
- active/inactive anon/file and unevictable memory;
- memory `max`, `oom`, and `oom_kill` event counters; and
- pids current/limit.

The shim maps these into containerd's cgroup metrics protobuf, including CPU
`Throttle` and `MemoryOomControl`.

## Resource updates

Set 7 extends the portable guest resource contract with:

- OCI `memory.reservation` -> cgroup-v2 `memory.low`;
- OCI `memory.swap` -> cgroup-v2 `memory.swap.max`; and
- a strict allowlist for OCI `LinuxResources.unified`.

OCI `memory.swap` is **memory + swap total**, while cgroup-v2
`memory.swap.max` is **swap only**. Set 7 subtracts the effective finite memory
limit before writing the cgroup-v2 value and rejects impossible combinations.
It does not copy the OCI number directly. `0` remains "unset" and `-1`
remains unlimited, matching the opencontainers cgroup-v2 conversion model.

Allowed `unified` keys are intentionally narrow:

```text
cpu.max.burst
cpu.uclamp.min
cpu.uclamp.max
memory.min
memory.low
memory.high
memory.max
memory.swap.max
memory.oom.group
pids.max
```

Unknown keys and unavailable controller files fail closed.

## Device safety

A device node inside a hardware VM is not host-device passthrough. Creating a
block node with the host's major/minor can target the wrong guest device.
Therefore Set 7:

- rejects raw block-device bind sources in the host shim;
- rejects host character/FIFO/socket bind sources instead of trying to copy
  them into the Pod share;
- rejects OCI block devices in the guest until a VMM device has actually been
  attached; and
- permits OCI character-device nodes only when the same major/minor already
  exists in the guest (normal `/dev/null`, `/dev/zero`, `/dev/tty`, etc.).

Kubernetes raw block volumes and device-plugin passthrough need explicit QEMU
hotplug/VFIO plumbing. That is intentionally deferred to Set 8 rather than
faked with virtiofs or `mknod`.

## Retry-safe sandbox teardown

Set 6 made VM ownership durable. Set 7 applies the same rule to teardown: the
shim does not erase the runtime journal until FluxVM confirms the owned VM was
deleted (HTTP success or already-gone/404).

If the FluxVM API is temporarily unavailable, shim cleanup returns an error and
keeps the journal/CNI ownership metadata for a later retry instead of making a
still-running VM invisible to the runtime.

## Suggested node tests

Run all earlier regressions, then:

```bash
sudo ./scripts/e2e-secure-containers-oom.sh
```

Also inspect metrics for a running task:

```bash
ctr -n k8s.io tasks metrics <container-id>
```

Expected Set 7 signals include CPU throttling fields and memory OOM accounting.

### OOM polling interval

The shim defaults to a 1000 ms OOM counter poll. For controlled environments it can be tuned with `FLUXVM_CONTAINER_OOM_POLL_MS` (clamped to 100–60000 ms).
