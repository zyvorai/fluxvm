# virtio-flux Linux guest driver

The macOS 27 VZ runner exposes custom Virtio device ID `0x3f` (PCI 1af4:107f; an ID above 0x3f makes the PCI device ID leave the range Linux virtio-pci binds, so no guest driver can attach) with queue 0 (control) and queue 1 (bulk DRAM operations). Build this module against the guest kernel, load `virtio_flux.ko`, and use `/dev/fluxvm` and `/dev/fluxvm-bulk`.

```bash
make
sudo insmod virtio_flux.ko
cc -O2 -Wall -Wextra fluxvm_virtioctl.c -o fluxvm-virtioctl
sudo ./fluxvm-virtioctl ping
sudo ./fluxvm-virtioctl capabilities
sudo ./fluxvm-virtioctl bulk-test 65536 90
```

Built and tested on Debian 13 (kernel 6.12.111): `ping`, `echo`, `stats` and `capabilities` work. The driver needs the 6.12 API (`struct virtqueue_info` for `virtio_find_vqs`, no `no_llseek`, no `virtio_set_drvdata`).

`bulk-test` allocates guest memory in the kernel, passes its guest physical address to the host through queue 1, asks the VZ host backend to fill it through `VZGuestMemoryMapping`, verifies every byte in the guest and reports CRC32.

**Known issue:** on the one hardware run so far, `bulk-test 65536 90` (queue 1) never completes. The guest blocks in `wait_for_completion`, and afterwards even control requests hang. The root cause is not found, so treat the bulk path as unverified.
