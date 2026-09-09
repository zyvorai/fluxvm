# FluxVM Secure Containers — Set 3

Base reviewed: `zyvorai/fluxvm` main at `d77c1afb9364b02e897079b7325470e9a2bf361e`.

Set 3 builds on the merged Set 2 runtime and the follow-up fixes already on main
(virtiofs-safe regular-file stdio, explicit fs0 Pod-share mount, and i64 exit
timestamps).

## Set 3 additions

- containerd runtime-v2 task events: create, start, exec-added, exec-started,
  paused, resumed, exit, and delete
- asynchronous exit watchers backed by the guest `Wait` operation
- de-duplicated exit publication so Wait and force-delete do not emit duplicate
  `/tasks/exit` events
- definitive delete response from the guest: pid, exit status, exit timestamp
- separate init/exec metadata so `State` reports the correct process stdio/pid
- per-process regular-file stdio staging, retaining the current virtiofs-safe
  relay while preventing concurrent exec sessions from colliding
- retry-safe rootfs/mount staging cleanup
- OCI process hardening inside the guest:
  - supplementary GIDs
  - umask
  - rlimits
  - `noNewPrivileges`
  - bounding/effective/inheritable/permitted/ambient Linux capabilities
- capability validation and explicit rejection of unsupported capability/rlimit
  names

## Still explicit follow-ups

This remains a developer-preview runtime until the real-node conformance gate
is complete. The following are not claimed as finished by Set 3 alone:

1. TTY/PTY and resize semantics.
2. CSI/PVC write-through and dynamic volume hotplug — **partially addressed in
   [Set 4](secure-containers-set4.md)** (Pod-UID kubelet volumes/subpaths);
   hostPath allowlist and late CSI hotplug remain open.
3. Full OCI namespace, seccomp, masked/readonly-path and device parity —
   **partially addressed in Set 4** (RO rootfs, masked/RO paths, devices,
   sysctls, name-based libseccomp); namespace parity and seccomp arg
   comparators remain open.
4. IPv6/multi-interface CNI conformance and high-churn teardown validation.
5. Cloud Hypervisor/Firecracker secure-container backends.
6. Broader Kubernetes conformance beyond lab `ctr` / RuntimeClass smoke.

## Required node test

Run on a Linux host with `/dev/kvm`, QEMU, containerd and a bootable secure
container guest image:

```bash
./scripts/test-secure-containers.sh
FLUXVM_SECURE_CONTAINERS_E2E=1 ./scripts/test-secure-containers.sh
```

Then validate a Kubernetes Pod using `runtimeClassName: fluxvm`, including Pod
IP/Service connectivity, exec, kill, resource update, stats, delete and VM/CNI
teardown.
