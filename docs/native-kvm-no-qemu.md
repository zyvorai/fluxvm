# Linux VM with the in-tree KVM engine and no QEMU binaries

This profile boots a Linux guest with a direct kernel and a **raw** root disk.
It does not invoke `qemu-system-x86_64`, `qemu-img`, or `qemu-nbd` at create
time. The source image must already be raw and named `.raw` (or `.ext4`).
Use a kernel with the virtio-mmio and virtio-blk drivers and a root filesystem
matching the kernel command line (`root=/dev/vda` by default).

1. Install the built `fluxctl` and `fluxvm-hypervisor` binaries and provide
   `/dev/kvm`. Set `fluxvm_engine = "kvm"` and `fluxvm_kernel =
   "/var/lib/fluxvm/kernels/vmlinux"` in `/etc/fluxvm.toml`.
2. Place a bootable raw image at
   `/var/lib/fluxvm/images/linux-rootfs.raw` and the matching kernel at the
   path above. Keep the base image offline while cloning it.
3. Run `./scripts/preflight.sh --native-kvm` and then
   `sudo fluxctl --config /etc/fluxvm.toml create --spec examples/fluxvm-native-kvm.json`.
   Check `fluxctl list` and the VM's console log.

Create waits for the in-tree VMM to reach its running state and reports
initialization failures. This readiness check does not wait for the guest OS
to finish booting; inspect the console or guest agent for that.
On a Linux host with `/dev/kvm`, run the acceptance gate with
`sudo KERNEL=/path/to/vmlinux ROOTFS=/path/to/root.raw ./scripts/test-native-kvm-no-qemu.sh`.
Set `FLUXVM_AGENT=1` when the image includes the enabled guest agent and
Cloud-init to check the vsock path and offline NoCloud injection too.

`backend: "auto"` selects the in-tree VMM only when `fluxvm_engine = "kvm"`,
a direct kernel is available, and the image is named `.raw` or `.ext4`.
Use `flux-vm` explicitly for a predictable deployment.
The default `fluxvm_engine` is Firecracker, so set it to `kvm` explicitly.
The example disables the guest agent for a first boot. For agent control,
install and enable `fluxvm-guest-agent` in the guest image and set
`"agent": {"enabled": true}`. On a flat ext4 root disk, FluxVM injects its
per-VM token with `debugfs` instead of GuestKit's `qemu-nbd`. Cloud-init
requests are embedded as NoCloud files in the cloned root disk, without
`cloud-localds`; the guest must have Cloud-init installed. Install
`e2fsprogs` (`debugfs`) on the host for either feature. Injection supports
flat ext4 rootfs images only and fails for GPT-partitioned images. SELinux
enforcing guests need the token file labeled appropriately in the image.
qcow2 inputs require `qemu-img` conversion before launch.
Pause and memory snapshots work with any vCPU count: every vCPU (BSP and APs) parks before a pause is reported complete, and the snapshot records each vCPU's registers and MP state. Restore reloads registers only (no LAPIC/MSR/FPU state), so treat a restored guest as best-effort rather than bit-exact.

This is a Linux direct-kernel profile. Windows/UEFI, QEMU device parity,
multi-vCPU snapshots, broad storage backends, and a QEMU-free image
build pipeline are separate work.

**Verified (2026-09-28) via a real `fluxctl create`, not just unit tests:**
the auto-generated per-VM token showed up correctly at
`/etc/fluxvm-guest-agent.token` on the actual cloned instance disk
(`debugfs -R 'cat ...' <instance>/root.raw`), matching the token in the
`create` response — the offline `debugfs` injection path works end to end
through the real control plane.

**Guest-agent binary compatibility gotcha, found the same way:** build
`fluxvm-guest-agent` for a glibc no newer than the guest's. A binary built
on a modern host (e.g. glibc 2.39) dropped into an older guest image
(e.g. Ubuntu 18.04 "bionic", glibc 2.27) fails to exec at all —
`version 'GLIBC_2.28' not found` and further, repeated for each missing
symbol version, visible on the guest's own console. This isn't specific to
the native KVM profile, but it's easy to hit here because the natural test
images (Firecracker's public quickstart rootfs) are old. Either build the
agent in an environment matching the guest, or link it statically
(e.g. against musl) for portability across guest glibc versions. The same
quickstart image also has no Cloud-init installed at all, so the NoCloud
seed-consumption half of this profile (as opposed to seed-*writing*, which
is what the token-injection test above already proves) still needs a
properly equipped guest image to verify end to end.
