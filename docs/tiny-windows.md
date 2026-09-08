# Tiny Windows on FluxVM

Lightweight Windows guests (Tiny11, Tiny11 Core, Tiny10) run on the **QEMU**
backend only. Use OVMF for UEFI disks. Do not combine Linux `cloud_init`
fields with a `windows{}` block.

**Preferred golden path:** build via sibling
[Kryton](https://github.com/zyvorai/kryton) (`VERSION=tiny11`), then customize
here — see [windows-golden.md](windows-golden.md). Bring-your-own VHDX still
works for quick labs.

## Host

```bash
sudo ./scripts/bootstrap-host.sh
```

Typical firmware path on RHEL-family hosts: `/usr/share/OVMF/OVMF_CODE.fd`.

Need: QEMU/KVM, OVMF, `qemu-img`, `virtio-win` drivers, `hivex`/`libhivex`,
and GuestKit built with `registry-write` + `agent`.

## Disk (Kryton golden — recommended)

```bash
# Clone kryton next to fluxvm, then (~45–90m first time):
./scripts/prepare-windows-golden.sh --build --version tiny11 --image-id windows-tiny11

# Installs: /var/lib/fluxvm/images/windows-tiny11-golden.qcow2
```

Point `examples/build-image-tiny11.json` `source` at that path (or symlink
`tiny11-base.qcow2` → the golden).

## Disk (BYO VHDX)

```bash
qemu-img convert -O qcow2 tiny11.vhdx /var/lib/fluxvm/images/tiny11-base.qcow2
guestkit doctor /var/lib/fluxvm/images/tiny11-base.qcow2 --target kvm --explain
guestkit plan apply virtio.yaml --vm /var/lib/fluxvm/images/tiny11-base.qcow2 --yes
```

## Customize then boot

```bash
sudo fluxvm --config /etc/fluxvm.toml build-image --spec examples/build-image-tiny11.json
sudo fluxvm --config /etc/fluxvm.toml create --spec examples/tiny11-qga.json
fluxvm list
fluxvm get <id>
```

RDP to host port 3389 (user-mode forward). For a known guest IP use
`examples/tiny11-tap.json` after `vmbr0` exists.

## Live QGA

```bash
fluxvm qga ping <id>
fluxvm qga powershell <id> -- 'hostname; Get-Content C:\fluxvm-ready.txt'
```

## Smoke

```bash
WINDOWS_IMAGE=/var/lib/fluxvm/images/windows-tiny11-golden.qcow2 \
  sudo -E ./scripts/test-tiny11-windows.sh
```

## Limits

| Backend | Windows |
|---|---|
| QEMU + OVMF + QGA | Supported |
| Cloud Hypervisor | Not supported for this Tiny path (see [ch-windows-qga.md](ch-windows-qga.md)) |
| Firecracker / `flux-vm` sandbox | Linux kernel + raw rootfs only |

## Fabric

[zyvorai/fabric](https://github.com/zyvorai/fabric) orchestrates FluxVM over
REST. It does not implement the VMM. Tiny Windows must work in FluxVM first.
A later Fabric PR should pass `qga.enabled` + OVMF and skip Linux cloud-init
when the guest is Windows.

Tiny11 is unofficial. This tree does not ship ISOs or product keys — Kryton
and dockur handle media when you build goldens yourself.
