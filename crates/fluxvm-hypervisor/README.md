# FluxVM Hypervisor

A **lightweight KVM Virtual Machine Monitor** in Rust (Firecracker / cloud-hypervisor class for Linux microVMs).

## Honest performance claim

| Layer | Who is faster than QEMU? |
|---|---|
| Guest CPU after boot | Neither. Both use KVM VT-x / AMD-V. Same silicon. |
| Cold boot + memory overhead | Yes, if you skip BIOS/UEFI, PCI, VGA, USB, floppy, ACPI bloat. |
| Device I/O | Yes, with virtio + optional vhost-net, not emulated e1000/IDE. |
| Pure software CPU emulation | **No.** Do not write a CPU emulator. |

## What works (in-tree KVM)

- **Boot:** PVH (preferred) + ELF/bzImage fallback; Firecracker-style e820/memmap; cmdline auto-appends `virtio_mmio.device=`
- **CPU:** SMP, CPUID, boot MSRs, FPU, LAPIC lint, TSC-deadline, `KVM_SET_TSS_ADDR`
- **Devices (virtio-mmio):** net, blk, vsock, balloon, rng + 16550 serial (all on `KVM_IRQFD`)
- **Host I/O:** TAP userspace net; optional `/dev/vhost-net` open; token-bucket `--net-mbit-limit` / `--blk-mbit-limit`
- **Firmware extras:** minimal ACPI (RSDP/XSDT/FADT/MADT) + PVH `rsdp_paddr`; optional `--pci` ECAM; `--jailer` / `FLUXVM_JAILER`
- **Control:** UDS JSON API, pause/resume, seccomp, gdbstub, `FLUXKVM1` v2 snapshots (all vCPUs)

Verified: Linux 5.10 guests reach `zbud: loaded`, mount `root=/dev/vda`, and `Run /sbin/init`.

## Host requirements

- Linux x86_64, `/dev/kvm`, Intel VT-x or AMD-V
- For Windows guests: use Cloud Hypervisor–style ACPI + virtio-pci (`--guest windows --firmware … --pci`); full virtio-pci BARs remain follow-up

## Build / run

```bash
cargo build -p fluxvm-hypervisor --release
sudo target/release/fluxvm-hypervisor \
  --memory-mib 512 --cpus 1 \
  --kernel /path/to/vmlinux \
  --disk /path/to/rootfs.ext4 \
  --cmdline "console=ttyS0 root=/dev/vda rw"
# virtio_mmio.device=… entries are appended automatically
```

Useful flags: `--vsock-cid` / `--vsock-uds`, `--no-balloon`, `--no-rng`, `--no-acpi`, `--pci`, `--jailer`, `--gdb ADDR:PORT`.

## Boot protocols

- **PVH** (preferred): 32-bit protected mode entry; kernel builds its own page tables.
- **Direct 64-bit** (fallback): identity map + long mode when no PVH note.

## SMP

One KVM vCPU per `--cpus`. APs start `KVM_MP_STATE_UNINITIALIZED` and wait for guest INIT-SIPI via in-kernel LAPIC. Virtio queue-notify stays BSP-only.

## Debugging: gdbstub

`--gdb 127.0.0.1:1234` — register/memory reads, SW breakpoints, break-in. No reg/mem write or single-step.

## Known limitations

- Virtio **device live-state** in snapshots is a watermark only; backends re-attach from boot config (Firecracker remains production snap format).
- Full virtio-pci BAR wiring / Windows production path → cloud-hypervisor SoT (P2 follow-up).
- virtio-fs, live migration, CPU/device hotplug → demand-driven P3 stubs (`Unsupported` until product needs them).

Lab density / packing: [docs/kvm-density.md](../../docs/kvm-density.md). Gaps: [docs/agent-sandbox-gaps.md](../../docs/agent-sandbox-gaps.md). Ranked next work: [docs/NEXT-FEATURES.md](../../docs/NEXT-FEATURES.md). Design notes: [DESIGN.md](DESIGN.md).

## Study (do not reinvent)

- [Firecracker](https://github.com/firecracker-microvm/firecracker) — Linux microVM SoT
- [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) — Windows / PCI / migrate SoT
- [rust-vmm](https://github.com/rust-vmm)
