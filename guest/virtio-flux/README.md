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

**Verified on hardware:** on a Debian 13 guest (kernel 6.12.111, Apple M4, macOS 27.2), `bulk-test` with 1 B, 4 KiB, 64 KiB and 1 MiB passes and the CRC32 matches an independent computation. Only the `bulk-fill` operation is exercised; zero, copy and crc32 are not. Earlier it hung because the request was built in a kernel-stack buffer, which is not valid virtqueue memory (virtqueue buffers must be linearly mapped).
