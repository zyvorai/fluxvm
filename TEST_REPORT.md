# Test report — FluxVM Secure Containers Set 4

## Reviewed base

`zyvorai/fluxvm` main was checked before this set and the reviewed base is:

`d77c1afb9364b02e897079b7325470e9a2bf361e`

That base includes the Set 2 merge plus the virtiofs stdio/share/timestamp/drain
runtime fixes. Set 4 is intended to layer on top of the Set 3 handoff.

## Checks executed in this artifact environment

PASS:

- `bash -n` for every shell script in the bundle
- TOML parse for every `Cargo.toml`
- YAML parse for deployment manifests
- Rust lexical delimiter balance for all Rust sources
- `git diff --check` for the Set 4 delta
- `git apply --check` for `patches/0004-secure-containers-volumes-security.patch`
- source review of Pod-UID volume boundary and guest path translation
- source review of mount rollback and fail-closed seccomp handling
- ZIP integrity test and SHA-256 manifest generation

## Important execution limitation

This artifact environment does **not** provide `cargo`/`rustc`, `/dev/kvm`,
QEMU, a running containerd, kubelet, CSI driver, or a secure-container guest
image. Therefore this report does not claim:

- Rust compilation or clippy success
- libseccomp ABI execution inside the guest
- VM boot / virtiofs mount success
- `ctr` execution
- Kubernetes PVC/CSI write-through E2E
- seccomp enforcement E2E

## Required merge gate

Run repository CI, then on a Linux KVM Kubernetes node verify at least:

1. create/start/wait/delete + TaskExit lifecycle
2. PVC write, Pod deletion/recreation, persisted read
3. emptyDir and projected ConfigMap/Secret mounts
4. `subPath` volume mounts
5. read-only volumeMount behavior
6. masked/read-only paths and read-only rootfs
7. seccomp syscall denial and missing-libseccomp fail closed
8. OCI device-node creation in the guest
9. CNI connectivity + volume use together
10. repeated Pod churn and teardown with no leaked virtiofsd/QEMU/mounts

The included `scripts/e2e-secure-containers-volume.sh` provides the PVC
write/recreate/read smoke once a suitable StorageClass is available.
