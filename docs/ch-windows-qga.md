# Cloud Hypervisor Windows + QGA

**Status:** not GA. Windows guest customization and live QGA
(`fluxvm qga …`, virtio-serial) are implemented for the **QEMU** backend
only. See `examples/windows-qga.json`.

Cloud Hypervisor (`backend: cloud-hypervisor`) rejects `qga.enabled` at
admission. CH Windows + a guest-control channel (virtio-serial/QGA or an
equivalent agent) remains a follow-up; use QEMU for Windows day-2 today.

## In-tree KVM engine

`fluxvm_engine = "kvm"` is an opt-in lab path for `BackendKind::FluxVm`.
It is **not** a production density story — Firecracker remains the default
sandbox engine. Snapshots require `fluxvm_engine=firecracker`. Publish
real numbers via `scripts/bench-sandbox.sh` before claiming density.
