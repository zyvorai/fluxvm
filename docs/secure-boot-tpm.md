# UEFI Secure Boot and vTPM (QEMU backend only)

`CreateVmRequest.secure_boot` and `.tpm` add real UEFI Secure Boot
enforcement and an emulated TPM 2.0 device to a VM. **QEMU backend only** —
Cloud Hypervisor has no vTPM/Secure-Boot wiring today, and Firecracker has
no firmware concept at all (always direct kernel boot); both are rejected
outright at `create()` time with a clear error rather than silently
ignoring the fields.

## `firmware`, fixed

`CreateVmRequest.firmware` (OVMF path) existed before this, but the QEMU
backend never actually read it — a QEMU-backend request setting `firmware`
silently got no `-bios`/pflash args and fell back to QEMU's default BIOS.
This is now wired up as split code/vars pflash (see below), which is also
the prerequisite Secure Boot needs.

## Config

```toml
# Host-wide default for requests that omit firmware. Per-request
# `firmware` always wins when set.
qemu_ovmf_code = "/usr/share/OVMF/OVMF_CODE_4M.ms.fd"
# Required whenever a VM's effective firmware resolves to Some. A
# *template* — read-only, never written to directly. Copied once per VM
# into <workspace>/ovmf_vars.fd on first launch; that per-VM copy persists
# across stop/start so enrolled keys and boot order survive, and is
# deleted only on VM delete (same lifetime as the disk file).
qemu_ovmf_vars_template = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
swtpm_binary = "swtpm"
```

Typical paths vary by distro:

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

`firmware` here overrides `qemu_ovmf_code` when both are set — same
per-request-wins convention every other backend/config pair already has.

## What actually happens (QEMU backend)

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
- **`tpm: true`**: the QEMU backend spawns a
  `swtpm socket --tpmstate dir=<workspace>/tpm --ctrl
  type=unixio,path=<workspace>/swtpm.sock --tpm2` sidecar before QEMU
  starts (same respawn-every-launch lifecycle as the existing `virtiofsd`
  sidecars — fresh process on every `launch()` call, not kept alive across
  `stop`), then QEMU gets `-chardev socket,id=chrtpm,path=<sock>`,
  `-tpmdev emulator,id=tpm0,chardev=chrtpm`, `-device
  tpm-crb,tpmdev=tpm0`. Independent of `secure_boot`/`firmware` — a TPM is
  useful under legacy BIOS too (measured boot, disk encryption unseal).
- TPM **state** (NVRAM/keys, under `<workspace>/tpm/`) persists for the
  VM's whole lifetime, same as the disk file — deleted only on VM delete.
  The `swtpm` *process* is ephemeral per launch; its socket is torn down
  and respawned fresh on every `stop`/`start` cycle, but the state
  directory backing it is untouched.

## Real limits

- **QEMU backend only.** `secure_boot`/`tpm` on Cloud Hypervisor or
  Firecracker are rejected at `create()` time with a clear error, not
  silently ignored — unlike `vfio_devices`/`numa_node`/`hugepages`, which
  other backends do silently ignore, a caller believing they got Secure
  Boot/measured boot when they silently didn't is a real,
  security-relevant footgun, not a cosmetic no-op.
- **The vars template must be admin-provided, never synthesized.** This
  project makes no attempt to generate a valid OVMF vars file from
  scratch or guess its size — get the real one shipped by your
  distro's OVMF package.
- **Not validated against real `swtpm`/`qemu-system-x86_64` binaries in
  this project's own dev/CI environment for this change** — neither
  binary is installed in the environment this was developed in.
  `build_args`'s pure QEMU-argument construction (the pflash drives, the
  `smm=on`/`secure=on` flags, the TPM chardev/tpmdev/device triad) has
  real unit test coverage; the process-spawning/file-copy glue around it
  (`spawn_swtpm`, the OVMF vars copy) does not — the same gap
  `spawn_virtiofsd_instances` itself already had before this change (no
  existing unit test spawns real `virtiofsd` either, it's only ever
  exercised manually/in a real deployment). Treat this as unvalidated
  until exercised against real binaries on a real KVM host.
- **No attestation/measurement consumption story.** A `tpm: true` VM gets
  a real TPM 2.0 device the guest OS can use (measured boot, BitLocker,
  `tpm2-tools`, etc.) — nothing in FluxVM itself reads PCR values or does
  remote attestation on the host side.
