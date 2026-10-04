# Importing VMware VMs

FluxVM imports an exported VMware VM (OVA, or OVF plus VMDKs) into raw disks
and fixes the guest offline so it boots on virtio. No libguestfs or virt-v2v
is involved; the repair goes through guestkit.

```bash
fluxctl import-image /srv/exports/web01.ova --name web01
# or over the API
curl -X POST "$API/v1/images/import" -H "Authorization: Bearer $TOKEN" \
  -d '{"source": "/srv/exports/web01.ova", "name": "web01"}'
```

The source path is on the FluxVM host. When `policy.allowed_image_dirs` is set
the source must be under one of those directories. The route is admin-only.

## What it does

1. Extracts the OVA (plain files with bare names only; anything with a path
   is rejected) and parses the OVF: vCPUs, memory, NIC count, firmware
   (`efi`/`bios`), guest OS type and the disks in controller order.
2. Converts every disk to raw under
   `<state_dir>/images/imported/<name>/disk<N>.raw`. Sparse and
   stream-optimized VMDKs are read natively; other formats go through
   `qemu-img`. `disk0.raw` is the boot disk.
3. With `repair` (default on), mounts the boot disk and:
   - disables `vmtoolsd`, `open-vm-tools`, `vmware-tools`, `vgauth` and
     related units. `remove_vmware_tools: true` also purges the packages
     with `dpkg`/`rpm` (no network needed);
   - adds `virtio_blk`, `virtio_scsi`, `virtio_net`, `virtio_pci` and
     `virtio_console` to the dracut or initramfs-tools config and rebuilds
     the initramfs for every installed kernel;
   - rewrites `/dev/sdX` and `/dev/hdX` to `/dev/vdX` in `/etc/fstab`,
     `/etc/default/grub` and `grub.cfg` (`UUID=` and `LABEL=` entries are
     left alone);
   - removes `70-persistent-net.rules` and adds a DHCP fallback for any
     `en*` interface (netplan, or a NetworkManager keyfile on RHEL-family
     guests).
4. Returns the disk paths, the OVF summary, a repair report and a
   suggested `POST /v1/vms` body.

```json
{
  "image": "/var/lib/fluxvm/images/imported/web01/disk0.raw",
  "extra_disks": ["/var/lib/fluxvm/images/imported/web01/disk1.raw"],
  "ovf": {"name": "web01", "vcpus": 4, "memory_mib": 8192, "firmware": "efi", "os": "ubuntu64Guest", "nics": 1, "disks": [...]},
  "repair": {
    "os_type": "linux", "distro": "ubuntu",
    "actions": ["disabled open-vm-tools.service", "/etc/fstab: 2 /dev/sdX reference(s) moved to /dev/vdX", "rebuilt initramfs (update-initramfs -u -k all)"],
    "warnings": []
  },
  "suggested": {"name": "web01", "image": ".../disk0.raw", "backend": "qemu", "vcpus": 4, "memory_mib": 8192,
                "firmware": "/usr/share/OVMF/OVMF_CODE.fd",
                "notes": ["attach .../disk1.raw after create with POST /v1/vms/{id}/disks"]}
}
```

Drop `notes` from `suggested` and send it to `POST /v1/vms`. For a UEFI
source, `firmware` is filled from `qemu_ovmf_code` when it is configured;
otherwise a note asks for it.

## Read the warnings

- **Static IPs:** a config file naming a VMware NIC (`ens192`, `ens160`, ...)
  is reported. The virtio NIC gets a different name, so edit it or rely on
  the DHCP fallback.
- **Initramfs rebuild failed:** the virtio config is still written. Boot
  with a rescue kernel or run the printed command on first boot.
- **Windows:** no offline driver injection. Install the virtio-win drivers
  (viostor, vioscsi, netkvm) in the VM before exporting it.

## MCP

`fluxctl mcp serve --allow-write` exposes `image_import` with the same
arguments. See [mcp.md](mcp.md).
