# FluxVM

A **lightweight KVM Virtual Machine Monitor** in Rust.

This is a *design + starter implementation*, not a drop-in replacement for QEMU.
A production VMM (Firecracker / Cloud Hypervisor class) is 50k–100k+ lines.
FluxVM shows the architecture you should actually build if the goal is
**faster boot, smaller attack surface, and near-native runtime vs QEMU**.

## Honest performance claim

| Layer | Who is faster than QEMU? |
|---|---|
| Guest CPU after boot | Neither. Both use KVM VT-x / AMD-V. Same silicon. |
| Cold boot + memory overhead | Yes, if you skip BIOS/UEFI, PCI, VGA, USB, floppy, ACPI bloat. |
| Device I/O | Yes, with virtio + vhost-net / io_uring, not emulated e1000/IDE. |
| Pure software CPU emulation | **No.** QEMU TCG will beat a homemade emulator. Do not go there. |

**Do not write a CPU emulator.** Drive KVM. Emulate only virtio + a tiny
machine model.

## What this repo contains

- Architecture and machine model (`DESIGN.md`)
- Working KVM bootstrap: open `/dev/kvm`, create VM, map guest RAM, create vCPU
- Exit-handling skeleton (`KVM_RUN` loop)
- Linux bzImage / ELF load path (interface)
- Windows / UEFI boot path (interface + requirements)
- virtio-net TAP + vhost-net design
- virtio-blk, serial console, vsock, balloon interfaces
- Rate limiting, seccomp, jailer notes

## Host requirements

- Linux x86_64 (primary). aarch64 is the same design with different boot.
- `/dev/kvm` accessible (`kvm` group or root)
- Intel VT-x or AMD-V
- For Windows guests: Cloud Hypervisor–style ACPI + virtio-win drivers

```bash
# check KVM
ls -l /dev/kvm
egrep -c '(vmx|svm)' /proc/cpuinfo
```

## Build

```bash
cd fluxvm
cargo build --release
# needs a host with KVM to actually run a guest
```

## Boot protocols

Two boot paths for Linux guests, chosen automatically per kernel:

- **PVH** (preferred): if the kernel ELF carries a PVH entry-point note
  (most modern x86_64 `vmlinux` builds do), the vCPU is entered in 32-bit
  protected mode with paging off, and the kernel's own `startup_32`/
  `startup_64` code builds its own page tables and makes the 32-to-64-bit
  transition itself — the same as a real PVH-aware hypervisor (Xen) or
  cloud-hypervisor. This sidesteps an entire class of bug that hand-rolled
  guest page-table/GDT construction is prone to.
- **Direct 64-bit boot** (fallback): for kernels without a PVH note, we
  build an identity-mapped page table and GDT ourselves and jump straight
  into the kernel's 64-bit entry point.

## SMP

Real multi-vCPU support: one KVM vCPU per `--cpus`, each on its own OS
thread. APs are explicitly parked in `KVM_MP_STATE_UNINITIALIZED` right
after creation and block inside `KVM_RUN` until the guest's own real
INIT-SIPI-SIPI sequence arrives, handled entirely by KVM's in-kernel
LAPIC — no userspace SIPI emulation needed. AP threads service
register-level PIO/MMIO traps; virtio queue-notify processing (touches
guest RAM) stays pinned to the BSP, the same scope boundary many minimal
VMMs use.

## Debugging: gdbstub

`--gdb <addr:port>` starts a minimal GDB remote-serial-protocol stub for
live guest inspection — useful for diagnosing a hung or misbehaving boot:

```bash
fluxvm-hypervisor --guest linux --kernel vmlinux --disk rootfs.img --gdb 127.0.0.1:1234
# in another shell:
gdb -ex 'target remote 127.0.0.1:1234'
```

Supports register reads (`info registers`), memory reads (`x`/`m`,
translated through the guest's own page tables when paging is active),
break-in on connect or Ctrl-C, and software breakpoints (`break *addr`)
via `KVM_SET_GUEST_DEBUG`. Deliberately narrow scope — no register/memory
writes, no single-step — this is a tool for answering "where exactly is
the guest stuck", not a full interactive debugger.

## Known limitations

- **Boot hang on some guests**: a Linux 5.10 guest deterministically
  hangs late in boot (around the `workingset_init`/`init_zbud` initcalls)
  in what traces to a page-fault-related loop. Confirmed *not* caused by
  boot-time CPU/paging setup — the hang is identical under both the PVH
  and direct-64-bit boot paths, which rules out hand-rolled page tables/
  GDT/long-mode setup as the cause. Most likely in device emulation
  (virtio/PIT/timer) or memory declaration; not yet root-caused. Use
  `--gdb` (see above) to continue the investigation.
- Snapshot/restore (`kvm_snap.rs`) is single-vCPU only; extending it to
  capture all vCPUs under SMP is unimplemented follow-up work.

## Next real projects to study (do not reinvent)

- [rust-vmm](https://github.com/rust-vmm)
- [Firecracker](https://github.com/firecracker-microvm/firecracker) — microVMs, Linux only
- [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) — Linux + Windows
- [libkrun](https://github.com/containers/libkrun) — embeddable VMM
