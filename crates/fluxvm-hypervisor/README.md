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
- **CPU:** CPUID, boot MSRs, FPU, LAPIC lint, TSC-deadline, `KVM_SET_TSS_ADDR`. SMP boots a 2-vCPU Linux guest on real hardware (see SMP section); pause/snapshot cover every vCPU.
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

One KVM vCPU per `--cpus`. APs start `KVM_MP_STATE_UNINITIALIZED` and wait for the guest's INIT-SIPI-SIPI, handled by the in-kernel LAPIC. Each AP runs on its own thread (`run_ap`) and services only PIO/MMIO. Virtio queues are not handled by any vCPU: see "Virtio queue servicing" below.

**Verified on real KVM hardware (2026-09-28):** `scripts/test-kvm-smp-boot.sh` boots a 2-vCPU Linux guest to userspace (`smp: Brought up 1 node, 2 CPUs`). Pause and snapshot cover all vCPUs (see "Pause barrier" below).

Root causes found while getting there, kept so they are not re-derived:

1. **Guest CPUID topology (the real AP crash).** With >1 vCPU the AP panicked in `start_secondary` (`Package 1 of CPU 1 exceeds BIOS package data 1`, `kernel BUG at arch/x86/kernel/cpu/common.c:1276`) and the `reboot=k` path turned that into a silent triple fault. Linux derives the package/thread topology from CPUID leaf 1 (HTT bit, logical processor count in EBX[23:16]) and leaf 4 (EAX[31:26], cores per package). `setup_cpuid` now sets HTT and the leaf-4 core count for more than one vCPU, matching Firecracker's `cpuid.normalize()`. The panic text was recovered by decoding the AP's own 0x3f8 writes; nothing reaches the console because BSP and AP serial output interleave.
2. **`KVM_SET_IDENTITY_MAP_ADDR` was never called.** Intel VMX hosts with an in-kernel irqchip need it alongside `KVM_SET_TSS_ADDR` so an AP can run in real mode after SIPI (Firecracker/crosvm/cloud-hypervisor all call both).
3. **`KVM_RUN` returning `EAGAIN` is not an error.** For a not-yet-runnable vCPU (freshly SIPI'd AP) the kernel blocks and then returns `-EAGAIN` by design; retrying is correct. `run_once` treats it like `EINTR`.
4. **AP virtio notifies were dropped.** Only the BSP drained the per-device pending-notify flag, so once the guest issued a block request from CPU 1 the boot stalled after the first request. Fixed properly by the ioeventfd design below (an intermediate AP-to-BSP signal hack was replaced by it).

Ruled out: host oversubscription, nested virtualization, vCPU register state, and retry timing alone.


### Pause barrier

Same shape as Firecracker (`Pause` event + signal kick + `Paused` reply from every vCPU thread), Cloud Hypervisor (per-vCPU paused flag) and QEMU (`pause_all_vcpus`), implemented in `pause.rs`:

1. The controller sets `paused`, bumps the pause epoch, and kicks every vCPU: `immediate_exit = 1` on its `kvm_run` page plus a `SIGUSR1` (no-op handler) to its thread, so even a vCPU sleeping in an in-kernel HLT (or an AP still waiting for SIPI) leaves `KVM_RUN`. It re-kicks until the barrier completes.
2. Each vCPU loop clears `immediate_exit` and *then* re-checks `paused`, so a pause that races the check still forces the next `KVM_RUN` to return instead of sleeping in the guest.
3. Each AP parks in userspace and acknowledges the current epoch; the BSP publishes the quiesced epoch only once every AP has acknowledged, so a snapshot never sees a vCPU still running. Pausing times out with an error if any vCPU fails to park.

Snapshot format is `FLUXKVM1` v4: v3 plus one `KVM_MP_STATE` per vCPU so restored APs come back runnable. v1-v3 files still load. The pause and snapshot smokes take `VCPUS=N` and verify each AP parked once per pause (`[kvm] vcpuN paused`), 12 back-to-back cycles at 4 vCPUs, and that a restored 2/4-vCPU guest does not crash after resume.

### Virtio queue servicing

Every virtio-mmio `QueueNotify` register (offset `0x50`) is bound with `KVM_IOEVENTFD` to one eventfd per device queue, matched on the queue index -- the same approach as Firecracker and Cloud Hypervisor. A guest notify from *any* vCPU completes in the kernel and wakes a dedicated worker thread (`queue_service.rs`); no vCPU exits to userspace for it, so it does not matter which CPU the guest happens to notify from, and simultaneous notifies for different queues can no longer coalesce into one pending slot. Completions go back through the existing `KVM_IRQFD` interrupts.

The worker and everything it touches (guest RAM alias, backends, rate limiters, TAP/vhost) live in one `QueueService` behind a mutex. Snapshot dumps take that lock so device state and RAM are consistent while paused, and the BSP's host-initiated vsock poll uses `try_lock` so a vCPU never stalls behind disk I/O. A failed `KVM_IOEVENTFD` registration fails VM creation rather than silently dropping notifies. The worker is spawned after the jailer/seccomp setup and uses only `poll`/`read`/`futex` beyond what the vCPU threads already need (checked with `strace -f` against the allowlist).

`scripts/test-kvm-smp-boot.sh` covers it: it boots N vCPUs (`CPUS=2|4|8`), and its probe runs one `dd` reader per CPU so notifies arrive from every vCPU at once. Verified on real hardware at 2, 4 and 8 vCPUs.

## Debugging: gdbstub

`--gdb 127.0.0.1:1234` — register/memory reads, SW breakpoints, break-in. No reg/mem write or single-step.

## Known limitations

  * The in-tree virtio-blk backend expects a nonempty, 512-byte-aligned raw disk. It rejects qcow2 and VMDK/VHDX headers; convert a stopped image to raw before selecting `fluxvm_engine = "kvm"`. Requested disk, TAP and vsock devices must initialize successfully or VM creation fails.
  * In-tree KVM snapshots save and restore registers, special registers and `KVM_MP_STATE` per vCPU plus RAM and virtio queue state. LAPIC, MSR, FPU and TSC state are not captured, so a restored guest is best-effort, not bit-exact; Firecracker remains the production snapshot format.
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
