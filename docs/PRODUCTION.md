# FluxVM production checklist (whole project)

This is the host-local production bar — VMM, storage, auth, network, k8s,
images — not only the dataplane.

## 1. Control plane

- [ ] `listen` is loopback **or** `auth.require = true` with real tokens
- [ ] Per-token `max_vms_per_token` / `max_memory_mib_per_token`
- [ ] Tokens carry optional `tenant`; VM specs set `tenant`
- [ ] Token tenant is inherited on create when the body omits `tenant`
- [ ] `GET /readyz` returns `"ok": true` (state dir + dataplane if required)
- [ ] `GET /healthz` for liveness; `/readyz` for readiness probes
- [ ] JSON audit target `fluxvm_audit` shipped to your collector
- [ ] Tutorials: [production/01-readyz-tenant-auth.md](tutorials/production/01-readyz-tenant-auth.md)

## 2. Compute

- [ ] `/dev/kvm` present; cgroup v2 delegated
- [ ] Firecracker jailer on for untrusted guests
- [ ] `allowed_backends` pinned
- [ ] Warm pools only on dedicated hosts
- [ ] Snapshots tested for the backends you run (QEMU `savevm`, CH `ch-remote`)

## 3. Images & storage

- [ ] Catalog names instead of raw paths where possible
- [ ] Ed25519 and/or `cosign verify-blob` on catalog entries
- [ ] `allowed_image_dirs` set
- [ ] Storage backend chosen (local qcow2, LVM-thin, NBD, Ceph RBD) and backed up

## 4. Network

- [ ] Merge `configs/network-fabric-prod.toml` when VMs have a host edge
- [ ] `fluxvm dataplane health` ok
- [ ] CNP/groups for tenant labels; `fluxvm observe`
- [ ] Cilium nodes: `mode = "cilium"`, no FluxVM XDP
- [ ] See [production-dataplane.md](production-dataplane.md)

## 5. Kubernetes

- [ ] Privileged DaemonSet + hostNetwork as in `deploy/k8s/`
- [ ] Host `nbd` module loaded if GuestKit customize runs on-node
- [ ] Operator talks to an already-healthy fabricd/FluxVM API

## 6. Fleet (non-k8s)

- [ ] `fluxvm-agent` TLS + token
- [ ] Persisted `fleet-nodes.json`
- [ ] Placement uses residual CPU/memory

## Do not ship yet as “done”

OIDC/mTLS exchange, Cilium-native VM endpoints, Hubble UI, CH Windows+QGA,
in-tree KVM without Firecracker for production density.
