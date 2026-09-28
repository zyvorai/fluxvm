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
- **CPU:** CPUID, boot MSRs, FPU, LAPIC lint, TSC-deadline, `KVM_SET_TSS_ADDR`. SMP is implemented but **confirmed non-functional on real hardware** (AP wake-up fails — see SMP section below); single-vCPU boots are solid.
- **Devices (virtio-mmio):** net, blk, vsock, balloon, rng + 16550 serial (all on `KVM_IRQFD`)
- **Host I/O:** TAP userspace net; optional `/dev/vhost-net` open; token-bucket `--net-mbit-limit` / `--blk-mbit-limit`
- **Firmware extras:** minimal ACPI (RSDP/XSDT/FADT/MADT) + PVH `rsdp_paddr`; optional `--pci` ECAM; `--jailer` / `FLUXVM_JAILER`
- **Control:** UDS JSON API, pause/resume, seccomp, gdbstub, `FLUXKVM1` v2 snapshots (all vCPUs)

Verified end-to-end through the real control-plane boot path (not just
the CLI demo): a Linux 5.10 + systemd guest reaches `zbud: loaded`,
mounts `root=/dev/vda`, runs `/sbin/init`, and **the in-guest
`fluxvm-guest-agent` (vsock ping/exec/shutdown) actually starts** —
`[ OK ] Started Zyvor FluxVM in-guest agent`.

Also verified (2026-09-28) through `fluxctl create` itself, not just the
raw `fluxvm-hypervisor` binary: `backend: "flux-vm"` +
`fluxvm_engine = "kvm"` end to end via `scripts/test-native-kvm-no-qemu.sh`
against a real Firecracker-quickstart kernel/rootfs — `create` correctly
blocks until the guest reaches `running` (see
[docs/native-kvm-no-qemu.md](../../docs/native-kvm-no-qemu.md)). This run
is what found and fixed the seccomp/jailer syscall gap below.

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

CPUID topology is patched per vCPU (leaf-1 APIC ID + logical processor
count; host `0xB`/`0x1F` topology leaves cleared; x2APIC cleared until
MADT type-9 exists) so Linux AP bring-up matches MADT. Re-run the smoke:

```bash
sudo ./scripts/test-kvm-smp-boot.sh   # --cpus 2, asserts userspace + no do_boot_cpu failed
```

If that script soft-skips (no KERNEL/KVM), treat multi-vCPU as
**experimental** until it has been green on a lab host.

**Confirmed broken on real KVM hardware (2026-09-28):** `test-kvm-smp-boot.sh`
against a real kernel/rootfs on `/dev/kvm` fails AP bring-up —
`smpboot: do_boot_cpu failed(-1) to wakeup CPU#1`, falling back to 1 active
processor. The BSP boots and reaches userspace correctly; only the
secondary vCPU's INIT-SIPI-SIPI delivery is affected. Until this is fixed,
treat `--cpus > 1` as **non-functional**, not just unverified — this is why
pause/snapshot (see Known limitations) are deliberately restricted to one
vCPU rather than attempting to support a multi-vCPU barrier on top of AP
bring-up that doesn't work yet.

## Debugging: gdbstub

`--gdb 127.0.0.1:1234` — register/memory reads, SW breakpoints, break-in. No reg/mem write or single-step.

## Known limitations

  * The in-tree virtio-blk backend expects a nonempty, 512-byte-aligned raw disk. It rejects qcow2 and VMDK/VHDX headers; convert a stopped image to raw before selecting `fluxvm_engine = "kvm"`. Requested disk, TAP and vsock devices must initialize successfully or VM creation fails.
  * In-tree KVM pause and memory snapshots currently require one vCPU. The BSP now acknowledges a pause after leaving `KVM_RUN`; AP threads do not yet participate in that barrier, so multi-vCPU pause/snapshot requests fail instead of producing an inconsistent image. This is a deliberate restriction, not just an unimplemented feature — see the SMP section: AP bring-up itself is confirmed broken on real hardware, so there's no working multi-vCPU state to snapshot yet anyway.
  * The in-tree block device uses split virtqueues with direct raw-sector I/O. It rejects indirect descriptors and malformed or cyclic chains. Guest FLUSH requests call `sync_data` on the backing file.
  * `jailer::apply()` (`--jailer` / `FLUXVM_JAILER`, and implicitly whenever `seccomp` is requested — `guest.rs` pairs them 1:1) calls `unshare()`/`chroot()`/`setuid()`/`setgid()`. These must stay in `seccomp.rs`'s allowlist: they were missing until 2026-09-28, which meant a seccomp-enabled KVM boot through the real control plane was an instant `SIGSYS` the moment the jailer ran, found via `strace` against a real `fluxctl create`. If you extend the jailer with a new syscall, add it to the allowlist in the same change — the two are never exercised together except through the full control-plane path, so `cargo test` alone won't catch a gap here.

- Virtio **device live-state** in snapshots is a watermark only; backends re-attach from boot config (Firecracker remains production snap format).
- Full virtio-pci BAR wiring / Windows production path → cloud-hypervisor SoT (P2 follow-up).
- virtio-fs / live migration / CPU+disk hotplug → **H4 Done** (see DESIGN.md); CH remains preferred for production shared-FS depth.
- Guest kernels need `CONFIG_EFI_PARTITION` to boot from a GPT-partitioned
  image (standard cloud images). Without it, the guest falls back to
  legacy protective-MBR parsing and can't find the real root partition —
  a guest-kernel config requirement, not a virtio-blk bug (verified: the
  same image/hypervisor boots cleanly to `/sbin/init` on a plain,
  non-GPT ext4 disk). Check with `nm vmlinux | grep efi_partition`.
- Multi-vCPU: see SMP section. Lab gate is `scripts/test-kvm-smp-boot.sh`.
- Virtio-mmio devices reset cleanly on status=0 (required by Ubuntu probe).
  MicroVM cmdline defaults to `pci=off` when `--pci` is not set.

**Resolved:** every control-plane-launched VM (`guest.rs`, the real path
`fluxvm.service` uses for `fluxvm_engine = "kvm"`) used to have its vCPU
execution silently and permanently freeze the instant the guest kernel
logged `Run /sbin/init` — indistinguishable from a hang, and the guest's
real agent never got to run. Root cause: `run_until()`'s serial-log
string-match break (a CLI `--guest` demo/smoke-test convenience) was
unconditionally shared by the production boot path too. Fixed by gating
it behind an explicit `exit_on_boot_marker` flag, true only for the CLI
demo entry point. This was never caught before because the (also now
fixed) `init_zbud` kernel hang meant no VM ever reached that point.

Lab density / packing: [docs/kvm-density.md](../../docs/kvm-density.md). Gaps: [docs/agent-sandbox-gaps.md](../../docs/agent-sandbox-gaps.md). Ranked next work: [docs/NEXT-FEATURES.md](../../docs/NEXT-FEATURES.md). Design notes: [DESIGN.md](DESIGN.md).

## Study (do not reinvent)

- [Firecracker](https://github.com/firecracker-microvm/firecracker) — Linux microVM SoT
- [Cloud Hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor) — Windows / PCI / migrate SoT
- [rust-vmm](https://github.com/rust-vmm)
