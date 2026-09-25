# Use cases

What FluxVM is for — outcomes that map to shipping features. Not aspirational.

Detail and specs live in the linked tutorials and examples.

---

## CI/CD runners

**Outcome:** A real VM per job. Exec over vsock. Cleanup even if the job dies.

Firecracker jailer · `network.mode: none` · `ttl_seconds` · [README](../README.md#use-cases)

---

## Golden images

**Outcome:** Build once. Clone forever. Optional signed catalog.

`fluxctl build-image` · CoW overlays · [build-image tutorial](user/build-image-tutorial.md)

---

## Kubernetes without KubeVirt

**Outcome:** Declarative VMs on the host VMM — DisposableVm or scheduled MicroVM.

[microvm.md](microvm.md) · [tutorials/microvm](tutorials/microvm/README.md)

---

## Secure Containers *(preview)*

**Outcome:** Pods with their own guest kernel via containerd.

[secure-containers.md](secure-containers.md)

---

## Multi-host fleet

**Outcome:** Placement across hosts without standing up Kubernetes.

`fluxvm-agent` · [operations.md](operations.md#distributed-node-agent)

---

## Network policy at the VM edge

**Outcome:** Allowlists, deny lists, rate limits — Network Fabric GA.

[network-fabric.md](network-fabric.md) · [tutorials/network-policy](tutorials/network-policy/README.md)

---

## Agent sandboxes

**Outcome:** Pause, resume, HTTP proxy, AutoPause on the FluxVM hypervisor track.

[agent-sandbox-gaps.md](agent-sandbox-gaps.md)

---

## Longer-lived guests

**Outcome:** Same API without TTL — QEMU/CH guests that stay up.

Leave `ttl_seconds` unset. Use pause/resume and warm pools as needed.

---

## Production host bar

**Outcome:** Auth, `/readyz`, tenant IDs before you expose the API.

[PRODUCTION.md](PRODUCTION.md) · [tutorials/production](tutorials/production/README.md)
