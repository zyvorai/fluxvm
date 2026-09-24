# UEFI Secure Boot and vTPM

`CreateVmRequest.secure_boot` and `.tpm` add real UEFI Secure Boot
enforcement and an emulated TPM 2.0 device to a VM. The two fields have
**different real scope across backends**, deliberately not treated the
same — see "Backend support" below before assuming both work everywhere.

## `firmware`, fixed (QEMU backend)

`CreateVmRequest.firmware` (OVMF path) existed before this, but the QEMU
backend never actually read it — a QEMU-backend request setting `firmware`
silently got no `-bios`/pflash args and fell back to QEMU's default BIOS.
This is now wired up as split code/vars pflash (see below), which is also
the prerequisite Secure Boot needs. Cloud Hypervisor already wired
`firmware` correctly before this change.

## Backend support

| | QEMU | Cloud Hypervisor | Firecracker |
|---|---|---|---|
| `firmware` (plain UEFI boot) | Yes (this change) | Yes (already worked) | No firmware concept at all — always direct kernel boot |
| `secure_boot` | Yes | **No — rejected at `create()`** | **No — rejected at `create()`** |
| `tpm` | Yes | **Yes** | **No — rejected at `create()`** |

**Why `secure_boot` is QEMU-only, not "not implemented yet" on Cloud
Hypervisor:** QEMU's OVMF integration uses a split code/vars pflash pair —
a read-only firmware code image plus a separate, per-VM writable
`OVMF_VARS.fd`-shaped file that holds the enrolled Secure Boot keys
(PK/KEK/db/dbx) and persists across boots. Cloud Hypervisor's own
`--firmware` is a single opaque file
([confirmed against Cloud Hypervisor's own `docs/uefi.md`](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/uefi.md):
"Pass the firmware file to `--firmware`", one file, `CLOUDHV.fd`) — there
is no documented separate variable store to enroll keys into, and no
documented Secure Boot enable/enforce mechanism in Cloud Hypervisor's own
UEFI or Windows-guest docs. Claiming `secure_boot` support there would be
dishonest, not just unimplemented — it's rejected outright rather than
silently doing nothing or (worse) appearing to work without actually
enforcing anything.

**Why `tpm` *is* real on Cloud Hypervisor:** unlike Secure Boot, TPM
passthrough is a documented, first-class Cloud Hypervisor feature —
confirmed directly against a real `cloud-hypervisor --help` (v53.0):
`--tpm <tpm>` — `"(UNIX Domain Socket from swtpm) socket=</path/to/a/socket>"`.
This dials the exact same `swtpm`-backed Unix socket QEMU's own
`-tpmdev emulator` does, so both backends share one spawn function
(`fluxvm_core::process::spawn_swtpm`).

## Config

```toml
# QEMU only. Host-wide default for requests that omit firmware. Per-request
# `firmware` always wins when set.
qemu_ovmf_code = "/usr/share/OVMF/OVMF_CODE_4M.ms.fd"
# QEMU only. Required whenever a VM's effective firmware resolves to Some.
# A *template* — read-only, never written to directly. Copied once per VM
# into <workspace>/ovmf_vars.fd on first launch; that per-VM copy persists
# across stop/start so enrolled keys and boot order survive, and is
# deleted only on VM delete (same lifetime as the disk file).
qemu_ovmf_vars_template = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
# Consulted by both the QEMU and Cloud Hypervisor backends when tpm: true.
swtpm_binary = "swtpm"
```

Typical OVMF paths vary by distro:

- **Debian/Ubuntu** ship a "Microsoft keys pre-enrolled" pair —
  `OVMF_CODE_4M.ms.fd` / `OVMF_VARS_4M.ms.fd` — secure-boot-ready out of
  the box, no manual enrollment needed inside the guest.
- **Fedora/RHEL** ship `OVMF_CODE.fd` plus a separate
  `OVMF_CODE.secboot.fd`, with keys enrolled at first boot via the
  firmware's own setup menu instead of a pre-enrolled vars file.

This project doesn't synthesize or bundle either — same "admin manages the
file path, no packaging convention" posture `cloud_hypervisor_firmware`
already has. Not configuring `qemu_ovmf_vars_template` when `firmware` is
set is a hard error at launch (not a silent fallback to a guessed/blank
vars file — a wrong-size zero-filled file risks a pflash size mismatch or
a vars store OVMF can't actually use).

## Request

QEMU, Secure Boot + TPM:

```json
{
  "name": "secure-vm",
  "backend": "qemu",
  "image": "/var/lib/fluxvm/images/base.qcow2",
  "vcpus": 2,
  "memory_mib": 4096,
  "firmware": "/usr/share/OVMF/OVMF_CODE_4M.ms.fd",
  "secure_boot": true,
  "tpm": true
}
```

Cloud Hypervisor, TPM only (`secure_boot` would be rejected here):

```json
{
  "name": "ch-tpm-vm",
  "backend": "cloud-hypervisor",
  "image": "/var/lib/fluxvm/images/base.raw",
  "vcpus": 2,
  "memory_mib": 4096,
  "firmware": "/usr/share/cloud-hypervisor/CLOUDHV.fd",
  "tpm": true
}
```

`firmware` here overrides `qemu_ovmf_code`/`cloud_hypervisor_firmware`
when both are set — same per-request-wins convention every backend/config
pair already has.

## What actually happens

**QEMU:**

- **`firmware` set** (from the request or `qemu_ovmf_code`): split
  code/vars pflash —
  `-drive if=pflash,format=raw,unit=0,readonly=on,file=<code>` (the
  admin-provided, read-only OVMF code) +
  `-drive if=pflash,format=raw,unit=1,file=<workspace>/ovmf_vars.fd` (this
  VM's own writable copy of the vars template) — plus
  `-global driver=cfi.pflash01,property=secure,value=on` and `smm=on` on
  `-machine`. These three are set for *any* OVMF boot, not gated
  separately on `secure_boot` — the standard modern QEMU+OVMF+q35
  invocation (the same shape libvirt itself generates) regardless of
  whether Secure Boot enforcement is actually on. Secure Boot enforcement
  itself is controlled entirely by the vars store's own enrolled-key
  content, not by these flags.
- **`secure_boot: true`**: in addition to the above, requires
  `firmware` (request or config default) to resolve to `Some` and
  `qemu_ovmf_vars_template` to be configured — both fail closed with a
  clear error rather than booting without real Secure Boot enforcement
  and pretending otherwise.
- **`tpm: true`**: spawns the shared `swtpm` sidecar (see "Both backends"
  below), then QEMU gets `-chardev socket,id=chrtpm,path=<sock>`,
  `-tpmdev emulator,id=tpm0,chardev=chrtpm`,
  `-device tpm-crb,tpmdev=tpm0`.

**Cloud Hypervisor:**

- **`tpm: true`**: spawns the shared `swtpm` sidecar, then Cloud
  Hypervisor gets one flag: `--tpm socket=<workspace>/swtpm.sock` — no
  separate chardev/tpmdev/device triad, Cloud Hypervisor abstracts that
  away itself.
- **`secure_boot: true`**: rejected at `create()` time — see "Backend
  support" above for why.

**Both backends** — `tpm: true` spawns `fluxvm_core::process::spawn_swtpm`
before the VMM itself: `swtpm socket --tpmstate dir=<workspace>/tpm --ctrl
type=unixio,path=<workspace>/swtpm.sock --tpm2`, the same
respawn-every-`launch()` lifecycle the existing `virtiofsd` sidecars have
(fresh process on every `launch()` call — both initial create and a later
`start` — not kept alive across `stop`). Independent of `secure_boot`/
`firmware` — a TPM is useful under legacy BIOS/direct-kernel boot too
(measured boot, disk encryption unseal). TPM **state** (NVRAM/keys, under
`<workspace>/tpm/`) persists for the VM's whole lifetime, same as the disk
file — deleted only on VM delete. The `swtpm` *process* itself is
ephemeral per launch; its socket is torn down and respawned fresh on every
`stop`/`start` cycle, but the state directory backing it is untouched.

## Real limits

- **`secure_boot` is QEMU-only, permanently, not "not implemented yet" on
  Cloud Hypervisor** — see "Backend support" above. Firecracker rejects
  both fields; it has no firmware concept at all.
- **The QEMU vars template must be admin-provided, never synthesized.**
  This project makes no attempt to generate a valid OVMF vars file from
  scratch or guess its size — get the real one shipped by your distro's
  OVMF package.
- **`build_args`'s pure argument construction has real unit test coverage
  on both backends** (the QEMU pflash drives/`smm=on`/`secure=on` flags
  and TPM chardev/tpmdev/device triad; Cloud Hypervisor's `--tpm
  socket=...` flag) — the process-spawning/file-copy glue around it
  (`spawn_swtpm`, the OVMF vars copy) has no dedicated *unit* test of its
  own, the same gap `spawn_virtiofsd_instances` itself already had before
  this change (no existing test spawns real `virtiofsd` either).
- **The exact argument shapes `build_args` constructs were manually
  smoke-tested against real binaries on a real KVM host** (not through
  `fluxvm`'s own compiled code paths — a hand-invoked `qemu-system-x86_64`/
  `cloud-hypervisor` with the identical flags, to validate the argument
  *syntax* is accepted at all): real `swtpm socket --tpmstate ... --ctrl
  type=unixio,... --tpm2` starts and creates its control socket; real
  `qemu-system-x86_64 -machine q35,accel=kvm,smm=on ... -global
  driver=cfi.pflash01,property=secure,value=on -drive
  if=pflash,...,unit=0,readonly=on,file=<OVMF_CODE_4M.ms.fd> -drive
  if=pflash,...,unit=1,file=<OVMF_VARS_4M.ms.fd copy> -chardev
  socket,id=chrtpm,... -tpmdev emulator,... -device tpm-crb,...` boots
  real EDK2 UEFI firmware through to its own boot manager (`BdsDxe: No
  bootable option or device was found` — the correct, expected message
  for an intentionally blank test disk, confirming the firmware itself
  loaded and ran); real `cloud-hypervisor --firmware CLOUDHV.fd --tpm
  socket=...` does the same.
- **A real `fluxctl create` call with `secure_boot`/`tpm` was also driven
  through the actual compiled binary and REST API** (not just the
  argument-syntax smoke test above) on a real Ubuntu host, and surfaced a
  genuine, environment-specific obstacle worth naming plainly:
  **AppArmor.** Debian/Ubuntu's `swtpm` package ships a confining profile
  (`/etc/apparmor.d/usr.bin.swtpm`, enforcing by default) scoped to
  libvirt's own conventional paths — it has no entry for FluxVM's own
  `<state_dir>/instances/<id>/` workspace, so `spawn_swtpm` fails outright
  with `Could not open UnixIO socket: Permission denied` on any host where
  that profile is enforced (which is the common case on stock
  Ubuntu/Debian with the `swtpm` package installed — confirmed via
  `aa-status`). `packaging/apparmor/usr.bin.swtpm.fluxvm` is a ready-to-use
  local-include snippet (Debian/Ubuntu's own supported mechanism for
  extending a packaged profile — the packaged profile already carries the
  `#include <local/usr.bin.swtpm>` hook for exactly this) granting the
  one path FluxVM actually needs; see the file's own header for the
  two-command install. **This snippet was derived from a real diagnosed
  failure and the AppArmor profile's own confirmed local-include
  mechanism, but the fix itself was not live-verified end-to-end in this
  session** — installing it means editing a host's live security policy,
  a deliberately different, more sensitive class of change than editing
  FluxVM's own config file, and wasn't done here without separately
  checking first. Confirm it resolves the failure on your own host before
  relying on it in production. A host without AppArmor enforcing (or a
  distro that doesn't ship a `swtpm` confinement profile at all) is
  unaffected by any of this.
- **No attestation/measurement consumption story.** A `tpm: true` VM gets
  a real TPM 2.0 device the guest OS can use (measured boot, BitLocker,
  `tpm2-tools`, etc.) — nothing in FluxVM itself reads PCR values or does
  remote attestation on the host side.

For Phase 6 **security profiles** (`measured`, `confidential-snp`,
`confidential-tdx`), software-test evidence collection, fleet placement,
and secret release on policy match, see
[security-profiles.md](security-profiles.md).
