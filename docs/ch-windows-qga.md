# Cloud Hypervisor Windows + QGA

## Phase status

| Capability | Status |
|------------|--------|
| CH Windows **boot** (UEFI + `hyperv: true`) | **Done** (Phase-1) |
| Live QGA (`fluxvm qga …`) on CH | **Blocked** — QEMU only until CH day-2 channel |
| In-tree Hubble / Cilium-native CEP | **Not started** — see [ROADMAP-DENSITY.md](ROADMAP-DENSITY.md) |

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

`qga.enabled` remains **QEMU-only**. Cloud Hypervisor has no named virtio-serial
port (`org.qemu.guest_agent.0`) in FluxVM today. For PowerShell / firewall /
`guest-ping`, use [`examples/windows-qga.json`](../examples/windows-qga.json).

Phase-2 (months): CH virtio-serial (or a GuestKit Windows agent on another
channel) before claiming `fluxvm qga` parity.

## In-tree KVM density

Unrelated to CH: `fluxvm_engine = "kvm"` is a lab prototype. Production density
for the FluxVm sandbox track remains Firecracker. See [benchmarks](benchmarks/README.md)
and [ROADMAP-DENSITY.md](ROADMAP-DENSITY.md).
