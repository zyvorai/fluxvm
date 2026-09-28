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

`backend: "auto"` can select QEMU; always request `flux-vm` explicitly.
The default `fluxvm_engine` is Firecracker, so set it to `kvm` explicitly.
This profile disables the guest agent: its per-VM token injection currently
uses GuestKit's `qemu-nbd` path. Do not request cloud-init, since seed creation
uses `cloud-localds` and the native KVM boot config does not currently attach
the seed disk. qcow2 inputs require `qemu-img` conversion before launch.
Snapshots and pause in the native engine currently require one vCPU.

This is a Linux direct-kernel profile. Windows/UEFI, QEMU device parity,
multi-vCPU snapshots, broad storage backends, and a QEMU-free image
customization pipeline are separate work.
