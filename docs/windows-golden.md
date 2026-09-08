# Windows golden images (Kryton → FluxVM)

FluxVM does **not** download Windows media. Sysprepped golden qcow2 disks are
built by **[Kryton](https://github.com/zyvorai/kryton)** (dockur install →
Sysprep → capture), then customized and booted here with GuestKit + QEMU.

```text
  Kryton                              FluxVM
  build-golden-image.sh  →  *.qcow2  →  build-image windows{}  →  create + QGA
```

Tiny11 / Tiny10 labs can use the same pipeline (`VERSION=tiny11`) or a
converted VHDX — see [tiny-windows.md](tiny-windows.md). For production-like
Windows 11 / Server goldens, prefer Kryton.

## Sibling layout

Clone Kryton next to FluxVM (same parent as GuestKit):

```text
tt/
  fluxvm/
  guestkit/
  kryton/          # https://github.com/zyvorai/kryton
```

## Build or reuse a golden

```bash
# One-shot (45–90+ min first time; needs docker/podman + KVM):
./scripts/prepare-windows-golden.sh --build --version 11e

# Tiny11 catalog (lighter lab disk):
./scripts/prepare-windows-golden.sh --build --version tiny11 --image-id windows-tiny11

# Already have Kryton output:
KRYTON_WINDOWS_IMAGE=../kryton/out/windows-11e-golden.qcow2 \
  ./scripts/prepare-windows-golden.sh
```

Default install path: `/var/lib/fluxvm/images/windows-<version>-golden.qcow2`.

Kryton details: [GOLDEN-IMAGES.md](https://github.com/zyvorai/kryton/blob/main/docs/GOLDEN-IMAGES.md).

## Customize + boot on FluxVM

```bash
# Edit agent paths, then:
sudo fluxvm --config /etc/fluxvm.toml \
  build-image --spec examples/build-image-kryton-golden.json

sudo fluxvm --config /etc/fluxvm.toml \
  create --spec examples/windows-qga.json
```

Offline smoke (no boot):

```bash
WINDOWS_IMAGE=/var/lib/fluxvm/images/windows-11e-golden.qcow2 \
  sudo -E ./scripts/test-windows-customize.sh
```

Boot + QGA smoke (Tiny11 or any golden qcow2):

```bash
WINDOWS_IMAGE=/var/lib/fluxvm/images/windows-tiny11-golden.qcow2 \
  sudo -E ./scripts/test-tiny11-windows.sh
```

`KRYTON_WINDOWS_IMAGE` is accepted as an alias for `WINDOWS_IMAGE` in both
gated scripts.

## Ownership

| Step | Owner |
|------|--------|
| ISO download, unattended install, Sysprep | Kryton (`scripts/build-golden-image.sh`) |
| GuestKit gate / passport on capture | Kryton (optional `guestkit` on PATH) |
| Offline RDP/WinRM/scripts/agent inject | FluxVM `build-image` `windows{}` |
| Live day-2 PowerShell / firewall | FluxVM QEMU + QGA |
| KubeVirt CDI DataSource | Kryton (not FluxVM) |

## Limits

- Windows guests on FluxVM remain **QEMU + OVMF** (see [ch-windows-qga.md](ch-windows-qga.md) for CH status).
- Kryton KubeVirt provider is out of scope for this tree — only the golden qcow2 artifact is shared.
