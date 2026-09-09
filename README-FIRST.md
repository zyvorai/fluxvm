# FluxVM Secure Containers — Set 4 handoff

## Base

Reviewed against `zyvorai/fluxvm` commit:

`d77c1afb9364b02e897079b7325470e9a2bf361e`

Set 4 assumes Set 3 behavior is already present: task events, async exit
monitoring, definitive delete metadata, regular-file virtiofs stdio with drain,
OCI capabilities/rlimits/noNewPrivileges, CNI L2, and guest cgroup v2.

## Set 4 adds

1. Pod-UID-scoped write-through kubelet `volumes` / `volume-subpaths` exports.
2. Bind-source rewriting so PVC/CSI/emptyDir volume writes reach the host mount.
3. Read-only rootfs, masked/read-only paths, OCI device nodes and sysctls.
4. Guest libseccomp enforcement for syscall-name rules; unsupported comparator
   profiles fail closed.
5. Rollback of partial mounts when OCI/security setup fails.

## Apply

Prefer the patch:

```bash
git checkout <branch-based-on-d77c1afb>
git apply --check patches/0004-secure-containers-volumes-security.patch
git apply patches/0004-secure-containers-volumes-security.patch
```

The ZIP also carries the replacement files for manual review.

## Validation status

Static/source checks and patch apply-check are included in `TEST_REPORT.md`.
This artifact environment does not have a Rust toolchain, `/dev/kvm`, QEMU or
containerd, so it does not claim cargo/KVM E2E execution.
