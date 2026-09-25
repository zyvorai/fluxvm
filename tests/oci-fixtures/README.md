# OCI conformance fixtures (S9 / P0)

Checked-in configs for Secure Containers Kata-equivalence gates. Each JSON
is a minimal `config.json` fragment exercised by
`scripts/evidence-kata-p0p1-matrix.sh` and the live e2e scripts.

| Fixture | Covers |
|---|---|
| `ns-pid-mount-ipc-uts.json` | Set 6 namespace isolation matrix |
| `device-cgroup.json` | Set 10 device-cgroup deny/allow |
| `seccomp-notify.json` | Set 11 SCMP_ACT_NOTIFY broker |
| `hostpath-allowlisted.json` | P0 hostPath broker allowlist |
| `tty-churn.json` | P1 repeated resize / stdin-close |
| `firecracker-shares.json` | Firecracker ext4 block-staging shares (no virtio-fs) |

Live execution still requires `FLUXVM_SECURE_CONTAINERS_E2E=1` on a KVM host.
Firecracker legs also need `FLUXVM_CONTAINER_KERNEL` (or daemon `firecracker_kernel`).
