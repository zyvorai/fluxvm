# GPUs for sandboxes

A sandbox can ask for GPUs with `gpus` on `POST /v1/sandboxes`. FluxVM picks free ones itself and passes them through
to the guest with VFIO. The caller never names a device, so two callers cannot be given the same GPU.

```json
{ "template": "gpu-qemu", "gpus": 2, "ttl_seconds": 3600 }
```

The chosen addresses come back in the record as `request.vfio_devices`. Check that they are there: an older FluxVM
ignores a field it does not know and would give you a CPU-only VM.

## What counts as a free GPU

A GPU is free when its whole IOMMU group is bound to `vfio-pci` **and** nothing holds the group: no VM that has not
failed lists it in `vfio_devices`, and no process has `/dev/vfio/<group>` open. Bind a GPU first with
`POST /v1/host/gpus/bind` (`GET /v1/host/gpus` shows each one's `group_bound_to_vfio` and `group_held`). FluxVM never
rebinds a device as a side effect of creating a sandbox.

## How they are picked

- Deterministic: the same inventory gives the same answer.
- A request that fits on one NUMA node gets it, on the node with the **fewest** free GPUs that still fits, so a big
  request is not starved by small ones scattered across nodes. Otherwise GPUs are taken in NUMA-node then address order.
- Selection and the VM create happen under one lock (`sandbox_gpu_lock`), held until the VM record exists, so the next
  sandbox sees the GPUs as taken. A failed VM does not keep its GPUs.
- Devices the template already lists in `vfio_devices` are never picked again.

## Refusals

| Situation | Answer |
|---|---|
| Fewer free GPUs than asked | **503**, `N GPU(s) requested but only M free (…)` |
| Template is not QEMU-backed | 400. Every other backend ignores `vfio_devices`, so a GPU request there is an error, not a no-op |
| `confidential` is also set | 400. A passed-through device is outside the encrypted guest |
| `procbox` is also set | 400. A process sandbox has no device passthrough |
| More than 8 | 400 |

`gpus: 0` is the same as leaving it out. There is no waiting queue: a shortage is an immediate 503 the caller can retry.

## Limits

- QEMU only, so no Firecracker or in-tree FluxVM GPU cells. QEMU generally cannot save a VM's memory state while a VFIO
  device is attached, so do not expect pause-and-snapshot or restore to work on a GPU sandbox. This change does not
  test that.
- Only the GPU function is passed, not the other members of its IOMMU group. They stay bound to `vfio-pci`, which QEMU
  accepts. If you need the group's audio function in the guest, list it in the template's `vfio_devices`.
- Tested: the picking logic (unit and randomized tests), request validation, and the SDK calls. **Not tested on real
  GPUs or with a real VFIO bind**: the sysfs inventory, the QEMU device arguments and guest driver setup are the
  existing passthrough code, not exercised by this change.

SDKs: `create_sandbox(gpus=2)` (Python), `CreateSandbox(ctx, CreateSandboxRequest{GPUs: 2})` (Go),
`createSandbox({ gpus: 2 })` (TypeScript). See also [agent-sandbox-gaps.md](agent-sandbox-gaps.md) and, in Fabric,
`docs/gpu-passthrough.md` for the host setup.
