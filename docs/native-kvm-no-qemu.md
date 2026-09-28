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

`backend: "auto"` can select QEMU; always request `flux-vm` explicitly.
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
Snapshots and pause in the native engine currently require one vCPU.

This is a Linux direct-kernel profile. Windows/UEFI, QEMU device parity,
multi-vCPU snapshots, broad storage backends, and a QEMU-free image
build pipeline are separate work.
