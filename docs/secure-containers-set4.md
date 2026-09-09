# FluxVM Secure Containers — Set 4

Base reviewed for this handoff: `d77c1afb9364b02e897079b7325470e9a2bf361e`.
Set 4 layers on top of the Set 3 lifecycle/event/OCI work.

## 1. Kubernetes write-through volumes

The shim reads `io.kubernetes.cri.sandbox-uid` from the OCI annotations.  When
present, the QEMU sandbox receives additional virtiofs exports for only this
Pod's kubelet volume roots:

- `/var/lib/kubelet/pods/<uid>/volumes` -> `/run/fluxvm/kubelet/volumes`
- `/var/lib/kubelet/pods/<uid>/volume-subpaths` -> `/run/fluxvm/kubelet/volume-subpaths`

Bind sources below those roots are rewritten to the corresponding guest path
instead of copied. Reads and writes therefore hit the kubelet-mounted PVC,
CSI, emptyDir, projected, Secret or ConfigMap volume directly.

Other bind mounts remain snapshot-based. Set 4 intentionally does not expose
arbitrary hostPath mounts. A future hotplug/broker path can add explicitly
allowlisted hostPath exports without broadening the default trust boundary.

## 2. Guest OCI hardening

The guest container agent adds:

- `root.readonly`
- `linux.maskedPaths`
- `linux.readonlyPaths`
- OCI Linux device nodes
- Pod-VM-scoped `linux.sysctl`
- seccomp via guest `libseccomp.so.2`

Seccomp rules are resolved by syscall name and loaded immediately before
`execve`. Set 4 supports name/action rules without argument comparators.
Profiles using argument filters fail closed with a clear error rather than
silently losing enforcement. Unsupported architectures/actions also fail.

Set 3 controls remain enforced: UID/GID, supplementary groups, umask, rlimits,
noNewPrivileges and Linux capability sets.

## Remaining gates

- VSOCK-native stdio + TTY/PTY/resize — delivered in
  [Set 5](secure-containers-set5.md)
- seccomp argument comparators / notify
- Linux namespace creation parity and device-cgroup rules
- explicitly allowlisted hostPath hotplug/broker
- Cloud Hypervisor / Firecracker shared-rootfs parity
- real Kubernetes/KVM conformance and churn tests

## Required guest packages

A guest using OCI seccomp profiles must provide `libseccomp.so.2`. If a profile
is requested and libseccomp is absent, the container fails closed.

## Test gates

Host-independent source checks:

```bash
./scripts/test-secure-containers.sh
```

On a real Kubernetes + KVM node, additionally run:

```bash
sudo ./scripts/e2e-secure-containers-volume.sh <namespace> <runtime-class>
```

The volume test creates a PVC-backed Pod, writes from the FluxVM-isolated
container, and verifies persistence after the Pod is recreated.
