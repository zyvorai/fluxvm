## Secure Containers Set 4 — write-through Pod volumes + OCI security

### Summary

Move FluxVM Secure Containers closer to production Kubernetes semantics by
passing the current Pod's kubelet volume roots into the QEMU sandbox via
virtiofs, while strengthening the in-guest OCI boundary.

### Volumes

- derive Pod UID from `io.kubernetes.cri.sandbox-uid`
- export only that Pod's `volumes/` and `volume-subpaths/`
- translate matching OCI bind sources to guest virtiofs paths
- preserve read/write behavior for PVC/CSI/emptyDir/projected volumes
- keep arbitrary/non-Pod bind sources snapshot-based

### OCI hardening

- read-only rootfs
- masked + read-only paths
- OCI device-node creation
- Pod-VM sysctls
- guest libseccomp syscall-name filters
- fail closed on unsupported seccomp argument filters/actions/architectures
- rollback partial mount state on create failures

### Deliberately deferred

TTY/PTY/VSOCK streaming, seccomp argument comparators/notify, namespace parity,
device cgroup policy, hostPath hotplug, and non-QEMU shared-rootfs backends.

### Required real-node gate

Run repository CI plus KVM/containerd/Kubernetes tests covering PVC write/read
across Pod recreation, emptyDir, projected volumes, read-only mounts, seccomp
deny behavior, masked paths, teardown, and repeated Pod churn.
