# FluxVM Set 5 — VMM Guard + Adaptive QoS

Set 5 adds host-side VM isolation and a conservative QoS controller on top of
Runtime Intelligence / Flight Recorder. It stays node-local. Zyvor Fabric
continues to own distributed routing, service discovery, BGP/ECMP and remote
migration orchestration.

## VMM Guard

`fluxvm_guard.bpf.o` is a BPF-LSM object with three hooks:

- `bprm_check_security`: optionally blocks `execve()` from a guarded VM cgroup.
- `file_mprotect`: optionally blocks W+X mappings.
- `file_open`: optionally restricts character/block devices and writable
  regular files to exact allow-list identities.

The program is attached globally, but policy lookup starts with
`bpf_get_current_cgroup_id()`. Tasks outside cgroups in `guard_policies` are
untouched.

The file/device allow-list deliberately uses kernel object identity rather than
path strings:

- devices: VM key + policy generation + kernel `rdev` + char/block kind;
- writable regular files: VM key + generation + filesystem device + inode.

Every policy update gets a new generation. The new generation is populated
first and published with one cgroup-map update. Old keys therefore cannot
silently broaden a later policy even if cleanup is interrupted.

### Modes

`audit` records a would-deny event and allows the operation. `enforce` returns
`-EPERM`. Start with audit on existing workloads.

Defaults for `fluxvm-guard apply` are deliberately useful but conservative:

- deny exec: on;
- deny W+X: on;
- device allow-list: on;
- writable regular-file allow-list: off;
- mode: audit.

When device restriction is enabled, existing host VMM devices that exist on
the node are automatically allowed: `/dev/kvm`, `/dev/net/tun`,
`/dev/vhost-net`, `/dev/vhost-vsock`, and `/dev/vhost-vdpa`. Extra devices can
be added explicitly. Writable-file restriction is opt-in because a VMM may
need log, state, firmware/NVRAM or migration files in addition to the VM disk.

Examples:

```bash
sudo fluxvm-guard apply <vm-uuid> <vmm-pid> --mode audit
sudo fluxvm-guard events <vm-uuid> 10 200
sudo fluxvm-guard apply <vm-uuid> <vmm-pid> --mode enforce \
  --restrict-writes --allow-file /var/lib/fluxvm/vms/<vm>/disk.qcow2 \
  --allow-file /var/lib/fluxvm/vms/<vm>/nvram.fd
sudo fluxvm-guard status <vm-uuid>
sudo fluxvm-guard remove <vm-uuid>
```

For complete device/file-open protection, apply the policy before the VMM
opens those resources. Applying it to an already-running VM still protects
future opens, exec and W+X transitions, but it cannot retroactively revoke an
already-open file descriptor.

### Kernel requirements

The kernel needs `CONFIG_BPF_LSM=y`, BTF/CO-RE support, and `bpf` in the active
LSM list (`/sys/kernel/security/lsm`). The loader fails explicitly when the BPF
LSM is not enabled instead of pretending enforcement is active.

## Adaptive QoS

`fluxvm-qos` consumes the Set-4 Flight Recorder snapshot plus cgroup-v2 PSI.
It is intentionally explicit-apply:

```bash
fluxvm-qos evaluate <vm-uuid> <vmm-pid>
sudo fluxvm-qos apply <vm-uuid> <vmm-pid>
```

Signals:

- p95 vCPU runnable latency;
- p95 VM-attributed block I/O latency;
- cgroup `cpu.pressure` (`some avg10`);
- cgroup `io.pressure` (`full avg10`);
- VM-edge packet drop ratio when network stats are present.

The actuator only changes `cpu.weight` and `io.weight`. It never rewrites a
Cilium policy, FluxVM VM-edge allow-list or Zyvor Fabric route. Each adjustment
is bounded to a 25% step and capped at weight 1000, preventing one noisy VM
from rapidly monopolizing a node. Network drops are reported as a signal for
policy/rate-limit review rather than automatically increasing bandwidth.

## Security notes

- Guard map state is pinned under `/sys/fs/bpf/fluxvm/guard` by default.
- Human-readable active policy state is under `/run/fluxvm/guard`.
- Map keys use stable FluxVM VM keys and policy generations.
- No guest memory, Cilium-private map, or Fabric-private state is inspected.
- Guard audit events are a bounded ring buffer; policy enforcement never waits
  for userspace event consumption.
