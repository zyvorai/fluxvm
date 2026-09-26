# AppArmor / SELinux

FluxVM ships an AppArmor profile at `deploy/apparmor/fluxvm`, installed by
`scripts/bootstrap-host.sh` when AppArmor is present. The profile is loaded in
**enforce** mode and covers both VM lifecycle and `fluxctl build-image`
(guestkit: qemu-nbd, mount/chroot, package managers).

## What the profile allows (build-image)

- Exec of host helpers: `kmod`/`modprobe`, `sync`, `mount`/`umount`, `chroot`,
  `blkid`, `losetup`, `parted`, `qemu-img`, `qemu-nbd`, shells; `lsof`/`fuser`
  run unconfined (`Ux`) for cleanup probes
- Mount/umount/remount anywhere guestkit needs (`/run/guestkit-*`, `/tmp/...`)
- Devices: `/dev/kvm`, `/dev/nbd*`, `/dev/loop*`, `/dev/mapper/**`
- Workdirs: `/var/lib/fluxvm/**`, `/run/fluxvm/**`, `/run/guestkit*/**`,
  `/run/blkid/**`, `/tmp/**`
- User-owned specs / `copy_in` sources / outputs anywhere (`owner /** rw`)
- `/proc/*/cgroup`, `/sys/devices/system/node/**` (qemu-img)
- Capabilities for guestkit + chrooted package managers: `ipc_lock`,
  `dac_read_search`, `chown`, `fowner`, `sys_resource`, …

Smoke under enforce (root, Linux + AppArmor):

```bash
sudo ./scripts/test-apparmor-build-image.sh --image /path/to/base.qcow2
```

## SELinux

On SELinux hosts, load the permissive reference module in
[`deploy/selinux`](../selinux/README.md) (`fluxvm_t`). It stays permissive
until the `permissive` line is removed and the module is rebuilt. Pair the
AppArmor profile with `packaging/systemd/fluxvm.service` (`AppArmorProfile=fluxvm`)
or the drop-in in `packaging/systemd/fluxvm.service.d/apparmor.conf`.
