# virtio-flux Linux guest driver

The macOS 27 VZ runner exposes custom Virtio device ID `0xff00` with queue 0 (control) and queue 1 (bulk DRAM operations). Build this module against the guest kernel, load `virtio_flux.ko`, and use `/dev/fluxvm` and `/dev/fluxvm-bulk`.

```bash
make
sudo insmod virtio_flux.ko
cc -O2 -Wall -Wextra fluxvm_virtioctl.c -o fluxvm-virtioctl
sudo ./fluxvm-virtioctl ping
sudo ./fluxvm-virtioctl capabilities
sudo ./fluxvm-virtioctl bulk-test 65536 90
```

`bulk-test` allocates guest memory in the kernel, passes its guest physical address to the host through queue 1, asks the VZ host backend to fill it through `VZGuestMemoryMapping`, verifies every byte in the guest and reports CRC32.
