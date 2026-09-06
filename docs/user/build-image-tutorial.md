# Building custom OS images

`fluxvm build-image` takes a base disk image and applies customizations —
hostname, package installs, arbitrary commands, SSH-key injection, file
copy-in, and systemd service enablement — to produce a new, ready-to-boot
image. It does this through [GuestKit](/guestkit) (`qemu-nbd` + `chroot`).
Use **GuestKit only** — never libguestfs, `virt-customize`, or `guestfish`.
There is **no VM boot**, so `build-image` doesn't need `/dev/kvm` — only root
and the `nbd` kernel module. Windows disks use a `windows{}` block (offline
RDP/WinRM/firewall/scripts and Zyvor GuestKit agent inject) instead of the
Linux chroot path — see [Windows images](#windows-images) below.

This page walks through the three package-manager families `build-image`
supports: Debian/Ubuntu (`apt`), RHEL-family (`dnf`/`tdnf`/`yum`), and Arch
Linux (`pacman`). Every example here is real-hardware-verified and covered
by an automated CI job that runs the same checks against fresh Ubuntu,
Rocky Linux, and Arch cloud images on every commit — see
[`scripts/test-image-customize.sh`](https://github.com/zyvorai/fluxvm/blob/main/scripts/test-image-customize.sh)
in the repo.

## How it works, briefly

| Field | What it does | Needs network? |
|---|---|---|
| `hostname` | Writes `/etc/hostname` | No |
| `packages` | Detects the guest's package manager, installs via it | **Yes** |
| `commands` | Runs each string via `sh -c` inside the chroot | Depends on the command |
| `ssh_key` | Appends to `/root/.ssh/authorized_keys`, `0600` perms | No |
| `copy_in` | Copies a host file into the image at the given path | No |
| `enable_services` | Runs `systemctl enable <name>` for each unit | No |

`packages` is the one field that needs real outbound networking — the
guest's package manager has to actually reach its repositories.
`build-image` handles this for you: it stages a working `/etc/resolv.conf`
into the guest for the duration of the install (a stock cloud image's own
`resolv.conf` is usually a dangling symlink that only resolves under a
running systemd instance) and removes it again afterward.

Package-manager detection execs `command -v <tool>` inside the chroot and
checks what's actually there, in this order: `apt-get → tdnf → dnf → yum →
pacman`. If none are found, `packages` fails with a clear error telling you
to use an equivalent `commands` entry instead.

## Prerequisites

```bash
sudo modprobe nbd max_part=16
```

`scripts/bootstrap-host.sh` does this for you as part of general host setup.
You need root (for the `qemu-nbd` mount) and enough free disk for a copy of
the base image plus the output image — no VMM, no `/dev/kvm`. For Windows
offline customize, also install `libhivex-dev` (Debian/Ubuntu) or
`hivex-devel` (RHEL-family); bootstrap and remote deploy install it.

## Debian / Ubuntu

```json
{
  "source": "/var/lib/fluxvm/images/ubuntu-noble.qcow2",
  "output": "/var/lib/fluxvm/images/ubuntu-dev.qcow2",
  "format": "qcow2",
  "hostname": "ubuntu-dev",
  "packages": ["tree", "jq", "qemu-guest-agent"],
  "commands": ["touch /etc/provisioned-by-fluxvm"],
  "ssh_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... you@example.com",
  "enable_services": ["qemu-guest-agent", "cron"]
}
```

```bash
sudo fluxvm build-image --spec ubuntu-dev.json
```

Ubuntu's stock cloud image enables the `universe` component by default, so
most common CLI tools install with no extra repo configuration. The system
cron daemon's unit is `cron.service` — not `crond` (that's the RHEL-family
name).

## Rocky Linux, AlmaLinux, Fedora (`dnf`)

```json
{
  "source": "/var/lib/fluxvm/images/rocky9.qcow2",
  "output": "/var/lib/fluxvm/images/rocky9-dev.qcow2",
  "format": "qcow2",
  "hostname": "rocky-dev",
  "packages": ["tree", "jq"],
  "commands": ["touch /etc/provisioned-by-fluxvm"],
  "enable_services": ["crond"]
}
```

```bash
sudo fluxvm build-image --spec rocky-dev.json
```

Rocky's `GenericCloud` image ships `cronie` (providing `crond.service`)
pre-installed — `enable_services: ["crond"]` works without needing
`packages` to install it first. Photon OS (`tdnf`) and older RHEL/CentOS 7
(`yum`) images go through the exact same code path.

## Arch Linux (`pacman`)

```json
{
  "source": "/var/lib/fluxvm/images/arch.qcow2",
  "output": "/var/lib/fluxvm/images/arch-dev.qcow2",
  "format": "qcow2",
  "hostname": "arch-dev",
  "packages": ["tree", "jq"],
  "commands": ["touch /etc/provisioned-by-fluxvm"],
  "enable_services": ["sshd"]
}
```

```bash
sudo fluxvm build-image --spec arch-dev.json
```

Arch needs two things every other distro here doesn't — both handled for
you automatically:

1. **Empty keyring.** A fresh Arch image ships with no trusted pacman
   keyring, so `build-image` runs `pacman-key --init` and `pacman-key
   --populate archlinux` before the actual install. This takes a few extra
   seconds the first time.
2. **No `/etc/mtab`.** `pacman` refuses to run without a readable
   `/etc/mtab` — on a real system that's a symlink to `/proc/self/mounts`,
   which doesn't exist in this bare chroot. `build-image` stages a minimal
   synthetic one for the duration of the install.

Arch's official cloud image doesn't ship cron by default, so this example
enables `sshd` (which *is* preinstalled) instead — add `"cronie"` to
`packages` and use `enable_services: ["cronie"]` if you want cron.

## Windows images

Use a `windows{}` block instead of Linux fields. Do **not** mix
`windows{}` with `packages`, `commands`, `enable_services`, `ssh_key`,
`copy_in`, or top-level `hostname`.

```json
{
  "source": "/var/lib/fluxvm/images/windows-base.qcow2",
  "output": "/var/lib/fluxvm/images/windows-custom.qcow2",
  "format": "qcow2",
  "windows": {
    "hostname": "win-lab",
    "enable_rdp": true,
    "enable_winrm": false,
    "firewall_open": [
      { "name": "ZyvorApp", "port": 8080, "protocol": "tcp" }
    ],
    "scripts": [
      {
        "name": "hello",
        "powershell": true,
        "content": "Set-Content -Path C:\\fluxvm-ready.txt -Value ok\r\n"
      }
    ],
    "agent": {
      "binary": "/path/to/guestkitd.exe",
      "virtio_serial_driver": "/usr/share/virtio-win/vioserial/w10/amd64"
    }
  }
}
```

```bash
sudo fluxvm build-image --spec examples/build-image-windows.json
```

| Field | What it does |
|---|---|
| `hostname` | Offline Windows hostname plan (GuestKit) |
| `enable_rdp` / `enable_winrm` | Stock RDP (:3389) / WinRM (:5985) + firewall rules |
| `firewall_open` / `firewall_close` | Custom inbound FirewallRules blobs |
| `scripts` / `run_once` | Write files + stage RunOnce for first boot |
| `user` / `password` | Stage RunOnce `net user` |
| `agent` | Offline Zyvor/GuestKit `guestkitd.exe` inject (+ optional virtio-serial driver) |

### Boot and live control (QGA)

Create with QEMU and `"qga": {"enabled": true}` so FluxVM adds a
virtio-serial `org.qemu.guest_agent.0` channel (see
`examples/windows-qga.json`). After the GuestKit Windows agent is up:

```bash
fluxvm qga ping <id>
fluxvm qga powershell <id> -- 'Get-NetFirewallRule | Select-Object -First 5'
fluxvm qga firewall-open <id> --name ZyvorApp --port 8080 --protocol tcp
fluxvm qga firewall-close <id> --name ZyvorApp
```

REST: `POST /v1/vms/{id}/qga/ping`, `/qga/exec`, `/qga/firewall/open`,
`/qga/firewall/close`. Linux vsock `fluxvm exec` is unchanged and separate.

Gated smoke (skips without a fixture):  
`WINDOWS_IMAGE=… sudo -E ./scripts/test-windows-customize.sh`.

## Verifying an image without booting it

Since `build-image` never boots a VM, you can sanity-check the output by
mounting it directly, the same way it was built:

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd -c /dev/nbd0 /var/lib/fluxvm/images/ubuntu-dev.qcow2
sudo partprobe /dev/nbd0 && sudo udevadm settle
sudo mount /dev/nbd0p1 /mnt   # partition number varies by image layout
cat /mnt/etc/hostname
sudo umount /mnt
sudo qemu-nbd -d /dev/nbd0
```

## Troubleshooting

- **"cannot install packages: no supported package manager found"** — the
  image's package manager isn't apt/dnf/tdnf/yum/pacman (e.g. Alpine's
  `apk`). Use `commands` to install packages manually.
- **A package install fails with a DNS/network-looking error** — check the
  *host's* own network/DNS first; `packages` needs the host to have real
  outbound connectivity.
- **`enable_services` fails with "unit does not exist"** — the service name
  is distro-specific (`cron` vs `crond`, `ssh` vs `sshd`), or the package
  providing it isn't installed yet.
- **`windows{}` combined with Linux fields** — FluxVM rejects the request;
  put hostname under `windows.hostname` and drop `packages` / `commands` /
  `enable_services` / `ssh_key` / `copy_in`.
- **Windows agent inject fails** — needs `libhivex` on the host and a
  Windows `guestkitd.exe` path in `windows.agent.binary`; virtio-serial
  driver dir is recommended for QGA after first boot.

## Next steps

- [Common workflows](workflows.md)
- [Use cases](use-cases.md)
- [Technical docs](/docs/fluxvm)

## Operate from the console (UX)

1. Open this route from the nav or command palette and wait for live API data.
2. Use filters/search when present; drill into a row for detail.
3. For mutating actions: confirm role gates and impact before applying.
4. **Empty / fail:** Check service health, auth, and that required CRDs/backends for this domain are installed.
5. **Success:** Live data loads; created/updated objects appear without error toasts.

