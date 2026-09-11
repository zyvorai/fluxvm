# FluxVM Design

## 1. Goal

Build a Type-2 VMM on Linux KVM that:

- Boots Linux in ~100–300 ms (direct kernel + virtio, no firmware).
- Can boot Windows via OVMF/UEFI + ACPI + virtio-win (slower boot, still
  faster device path than default QEMU).
- Speaks virtio for net, block, vsock, balloon, rng, console.
- Uses TAP + optional `vhost-net` so packet processing stays in kernel.
- Has a tiny device surface compared to QEMU (~2M LOC C vs tens of kLOC Rust).

## 2. Why QEMU is “slow” (and what is not slow)

QEMU is two products in one:

1. **TCG emulator** — software CPU. Slow. We will never beat this by writing
   another emulator in Rust.
2. **KVM accelerator + giant device model** — hardware virtualization plus
   every legacy device ever needed (i440fx, Q35, IDE, e1000, VGA BIOS, USB,
   ACPI AML, SMBIOS, floppy, parallel port…).

Firecracker / Cloud Hypervisor beat *default QEMU* because they:

- Skip SeaBIOS / OVMF for Linux (direct 64-bit kernel entry or PVH).
- Expose ~5–16 devices instead of 40+.
- Keep the VMM out of the packet path (`vhost-net`, `vhost-user`, io_uring).
- Are memory-safe and small enough to jail (seccomp, namespaces).

Runtime CPU of a warmed Linux guest on QEMU+KVM vs Firecracker is essentially
identical. Optimize boot, footprint, and I/O path — not “the CPU”.

## 3. Process and thread model

```
fluxvm process
├── control thread     HTTP/UDS API, config, snapshot
├── vmm / device thread  virtio kick handling, TAP read/write if no vhost
├── vCPU-0 thread      KVM_RUN
├── vCPU-1 thread      KVM_RUN
└── …                  one OS thread per vCPU
```

Rules:

- One VM per process (Firecracker model). Isolation is free.
- vCPU threads only handle MMIO/PIO exits that must be synchronous.
- Network RX from TAP is either:
  - **vhost-net**: kernel writes into guest virtqueues. Fast path.
  - **userspace virtio-net**: device thread copies frames. Simpler, slower.

## 4. Address space (x86_64 Linux microVM)

```
GPA
0x0000_0000  real-mode / identity (tiny, often unused if 64-bit boot)
0x000A_0000  VGA hole (leave unmapped — do not emulate VGA)
0x000F_0000  reserved
0x0010_0000  low RAM start for kernel if needed
0x0000_7000  zero page / boot params (Linux)
0x0020_0000  kernel load (typical)
…            guest RAM
0xFEB0_0000  MMIO window (virtio-mmio, ACPI if Windows)
0xFEE0_0000  local APIC (KVM in-kernel)
0xFEC0_0000  IOAPIC (KVM in-kernel)
```

KVM in-kernel PIC / IOAPIC / PIT / LAPIC stay in the kernel. Userspace does
**not** emulate them.

## 5. Device model

### Always (Linux microVM) — implemented in-tree

| Device         | Backend                         | Notes                                      |
|----------------|---------------------------------|--------------------------------------------|
| virtio-net     | TAP + optional `/dev/vhost-net` | `KVM_IRQFD`; rate limit via `--net-mbit-limit` |
| virtio-blk     | raw file                        | `KVM_IRQFD`; `--blk-mbit-limit`            |
| serial 16550   | stdio                           | COM1 GSI 4 irqfd (vm-superio / CH semantics) |
| virtio-rng     | `getrandom`                     | on by default (`--no-rng` to disable)      |
| virtio-balloon | `madvise(DONTNEED)` / touch      | on by default (`--no-balloon`)             |
| virtio-vsock   | host UDS (`--vsock-uds`)        | Firecracker unix model; CID via `--vsock-cid` |

Cmdline discovery: VMM appends `virtio_mmio.device=<size>@<base>:<irq>` like Firecracker.

### Extra for Windows (cloud-hypervisor SoT)

| Device        | Status                                                |
|---------------|-------------------------------------------------------|
| UEFI firmware | `--firmware` / `--guest windows` loads image          |
| ACPI tables   | RSDP/XSDT/FADT/MADT written; full DSDT/AML follow-up  |
| PCI ECAM      | `--pci` reserves MMCONFIG; virtio-pci BARs follow-up  |

### Demand-driven (P3 stubs)

virtio-fs, live migration, CPU/device hotplug — modules return `Unsupported`
until product requires them (SoT = cloud-hypervisor).


## 6. Networking

```
guest TCP/IP
    → virtio-net driver
    → virtqueue (guest RAM)
    → vhost-net (kernel)  OR  fluxvm device thread
    → TAP  (e.g. tap0)
    → Linux bridge / macvtap / nftables NAT
    → physical NIC
```

Host setup:

```bash
sudo ip tuntap add dev tap0 mode tap user $USER multi_queue
sudo ip link set tap0 master br0
sudo ip link set tap0 up
```

Performance knobs that actually matter:

1. `vhost=on` — kernel consumes virtqueues.
2. Multi-queue virtio-net (`MQ`) — one queue per vCPU.
3. Guest offloads: TSO/GSO/csum. Windows virtio-win historically has LSO bugs;
   test and disable LSO on Windows if TX is ~Mbps.
4. `busy_poll` / `SO_BUSY_POLL` on TAP for latency.
5. Rate limiter (token bucket) in VMM to stop noisy neighbors.

User-mode net (slirp / passt / gvproxy) is for unprivileged hosts. It will
never beat TAP+vhost.

## 7. Boot paths

### Linux fast path (target: <200 ms to userspace with tiny kernel)

1. Map RAM.
2. Load `vmlinux` ELF or `bzImage` with `linux-loader`.
3. Write `boot_params` zero page (x86).
4. Init ramdisk at chosen GPA.
5. Set RIP = kernel entry, RSI = boot_params, long mode already on
   (or use PVH).
6. `KVM_RUN`.

No BIOS. No option ROMs. Kernel must be built with virtio-mmio or virtio-pci
and a small config (`vmlinux` + virtio + ext4 + net).

### Windows path

1. Load OVMF.fd into flash GPA.
2. Expose ACPI + PCI config space + virtio-pci.
3. Attach virtio-blk with NTFS image or installer ISO.
4. Guest needs virtio-win drivers (inbox on newer Server, or inject).
5. Expect seconds of boot, not 125 ms. Still far less device work than QEMU
   Q35+everything.

## 8. Exit handling

```
loop {
    match vcpu.run() {
        IoOut { port, data } => pio_bus.write(port, data),
        IoIn  { port }       => pio_bus.read(port),
        MmioWrite { addr }   => mmio_bus.write(addr),
        MmioRead  { addr }   => mmio_bus.read(addr),
        Shutdown | Hlt       => break,
        Intr                 => continue,  // interrupt window
        InternalError        => abort,
    }
}
```

Hot path: **zero exits** for ordinary guest userspace. Exits happen on
virtio notify (doorbell MMIO/PIO) and legacy serial.

Batch notifications. Do not handle one packet per exit if vhost is available.

## 9. Security

- One VM / process.
- Drop privileges after opening `/dev/kvm` and TAP.
- seccomp-bpf allowlist (`ioctl`, `KVM_*`, `read`/`write` on known fds,
  `io_uring`, `timerfd`, `epoll`).
- Landlock or chroot + mount namespace (jailer).
- No file-backed executable mappings of guest memory as host code.
- Rate-limit net and block.

## 10. Snapshot / restore (optional, high leverage)

For “faster than QEMU” in practice, **restore a snapshot** of a booted guest.
Firecracker restore is tens of milliseconds. Cold boot is the wrong metric
for agent sandboxes and functions.

## 11. Implementation phases

| Phase | Deliverable | Status |
|---|---|---|
| 0 | KVM VM + memory + vCPU + PIO/MMIO buses | **Done** |
| 1 | Serial + tiny 16-bit/64-bit test payload | **Done** |
| 2 | linux-loader + boot_params / PVH; serial console | **Done** |
| 3 | virtio-blk + virtio-net TAP | **Done** |
| 4 | vhost-net open + rate limits (`--net/blk-mbit-limit`); multi-queue bind still follow-up | **Partial** |
| 5 | balloon, vsock, rng, irqfd, seccomp jailer | **Done** |
| 6 | Minimal ACPI + PCI ECAM + Windows/UEFI path | **Partial** (ACPI/ECAM yes; full virtio-pci BAR / Windows → CH SoT) |

Boot hang past `init_zbud` is **resolved** (Firecracker-matched TSS/MSRs/FPU/LAPIC/serial). Lab snapshots: `FLUXKVM1` v2. See [README.md](README.md), [docs/kvm-density.md](../../docs/kvm-density.md), [docs/NEXT-FEATURES.md](../../docs/NEXT-FEATURES.md).

Do not expand Windows/PCI until Linux boot + net benches stay green.

## 12. What we will not implement

- TCG / software MMU / binary translation
- VGA / GPU emulation (use VFIO passthrough later if needed)
- USB, sound, floppy, PS/2 beyond reset
- Live nested QEMU device compatibility
- A new guest Windows kernel
