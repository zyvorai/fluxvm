# Cloud Hypervisor Windows + QGA

## Phase status

| Capability | Status |
|------------|--------|
| CH Windows **boot** (UEFI + `hyperv: true`) | **Done** (Phase-1) |
| Live QGA (`fluxvm qga …`) on CH | **Host path shipped** — `--serial socket=qga.sock`; guest must speak QGA |
| Named virtio-serial `org.qemu.guest_agent.0` | **QEMU-only** |
| In-tree Hubble-lite / CEP-*shaped* views | **Done** — see [hubble-lite.md](hubble-lite.md); real Cilium-agent CEP still Not started |

## Boot Windows on Cloud Hypervisor

1. Install / customize the guest as a **raw** disk (CH does not use qcow2 for this path). QEMU + GuestKit `windows{}` offline customize still applies.
2. Place UEFI firmware (typically `CLOUDHV.fd`) where FluxVM can read it.
3. Create with `backend: cloud-hypervisor`, `hyperv: true`, and `firmware` (or `cloud_hypervisor_firmware` in config):

```bash
fluxvm create --spec examples/windows-ch.json
```

`hyperv: true` passes `kvm_hyperv=on` on CH `--cpus` (required for most Windows guests).

Networking must be `tap` or `macvtap` (no user-mode NAT on CH).

Console: CH Windows uses serial (SAC); `console` is off. Use RDP once the guest has network.

## QGA

`qga.enabled` on Cloud Hypervisor now opens `--serial socket=<workspace>/qga.sock`
and keeps boot logs on `--console file=…`. `fluxvm qga ping|exec|powershell`
uses the same `fluxvm_image::qga` client as QEMU.

The guest must speak the QEMU guest-agent JSON protocol on that serial
(Windows: install qemu-ga and bind it to the CH serial port, or use a
serial-attached agent). Named virtio-serial `org.qemu.guest_agent.0` remains
QEMU-only.

Example: [`examples/windows-ch-qga.json`](../examples/windows-ch-qga.json).

Auth / mTLS notes: [auth-oidc-mtls.md](auth-oidc-mtls.md). Density roadmap:
[ROADMAP-DENSITY.md](ROADMAP-DENSITY.md).

## In-tree KVM density

Unrelated to CH: `fluxvm_engine = "kvm"` is a lab prototype. Production density
for the FluxVm sandbox track remains Firecracker. See [benchmarks](benchmarks/README.md),
[kvm-density.md](kvm-density.md), and [ROADMAP-DENSITY.md](ROADMAP-DENSITY.md).
