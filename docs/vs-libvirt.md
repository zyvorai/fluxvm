# FluxVM vs. libvirt/virsh, and the backends

The virsh-to-fluxctl command mapping, and which backend to choose for what.

[Back to README](../README.md)

<a id="vs-libvirtvirsh"></a>

## vs. libvirt/virsh

FluxVM is the Zyvor **host-local** replacement for libvirt/virsh VM lifecycle and networking. It is **not** a
drop-in for KubeVirt/OpenShift.

| libvirt/virsh | FluxVM | Same job? |
|---|---|---|
| `virsh define` + `virsh start` | `fluxctl create` | Yes |
| `virsh list` / `virsh dominfo` | `fluxctl list` / `fluxctl get` | Yes |
| `virsh suspend` / `virsh resume` | `fluxctl pause` / `fluxctl resume` | Yes |
| `virsh destroy` | `fluxctl delete` | Yes |
| `virsh reboot` | `fluxctl restart` | Yes |
| `virsh domrename` / metadata | `fluxctl rename-vm` / `fluxctl label` | Yes (labels drive `-l` selectors) |
| `virsh console` | `fluxctl serial` (websocket over REST too) | Yes |
| `virsh attach-disk` / `blockresize` / `detach-disk` | `fluxctl disk attach\|resize\|detach` | Yes (QEMU) |
| `virsh snapshot-create` / `-list` / `-delete` | `fluxctl snapshot` / `snapshot-list` / `snapshot-delete` | Yes (QEMU internal snapshots) |
| `virsh backup-begin` | `fluxctl backup [--all-disks]` | Yes (standalone qcow2) |
| `virt-clone` | `fluxctl clone-vm` | Yes |
| `virsh event` | `fluxctl events -f` (SSE: `/v1/events/stream`) | Yes |
| `virsh -c qemu+ssh://host` | `fluxctl --server` / `fluxctl context` | Yes (REST, bearer token) |
| XML domain definitions | JSON VM spec (`fluxctl create --spec vm.json`) | Different format, same purpose |
| No REST API | Full REST API (`fluxctl serve`) | FluxVM adds this |

No libvirtd and no XML: FluxVM speaks its own REST API and manages TAP/bridge/netns networking directly via netlink.

---

## Backends

| Backend | Best for |
|---|---|
| **QEMU/KVM** | Broad guest/device compatibility, qcow2 CoW overlays, QMP socket |
| **Cloud Hypervisor** | Modern cloud workloads on a Rust VMM; direct-kernel or firmware boot |
| **Firecracker** | MicroVMs from a Linux kernel + raw root filesystem, with the jailer |
| **FluxVM hypervisor** (`"backend":"flux-vm"`) | Agent sandboxes: memory snapshots, `/v1/sandboxes`, guest HTTP proxy + AutoResume, L7 egress, AutoPause, `/console`. With `fluxvm_engine = "kvm"` it is a **pure in-tree KVM VMM with no QEMU or Firecracker process**: multi-vCPU (verified at 2/4/8), pause/snapshot across all vCPUs, virtio queues on ioeventfd, direct-kernel boot from a raw ext4 — [docs/native-kvm-no-qemu.md](native-kvm-no-qemu.md) · [docs/agent-sandbox-gaps.md](agent-sandbox-gaps.md) |
| **procbox** (`"procbox": {}` on `/v1/sandboxes`) | The lightest tier: a rootless **Landlock + seccomp process sandbox** on the host kernel (no VM, no root; a weaker boundary than a microVM, off by default) — [docs/procbox.md](procbox.md) · [docs/procbox-backend.md](procbox-backend.md) |
