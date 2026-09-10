# FluxVM production checklist (whole project)

This is the host-local production bar — VMM, storage, auth, network, k8s,
images — not only the dataplane.

## 1. Control plane

- [ ] `listen` is loopback **or** `auth.require = true` with real tokens and/or OIDC
- [ ] Per-token `max_vms_per_token` / `max_memory_mib_per_token`
- [ ] Tokens carry optional `tenant`; VM specs set `tenant`
- [ ] Token/OIDC tenant is authoritative on create (inherited when omitted; mismatch → 403)
- [ ] Token tenant auto-scopes list / get / mutate (other tenants → 404)
- [ ] `GET /readyz` returns HTTP 503 when `"ok": false`
- [ ] `GET /v1/vms?tenant=<id>` filters the fleet
- [ ] `GET /readyz` returns `"ok": true` (state dir + dataplane if required)
- [ ] `GET /healthz` for liveness; `/readyz` for readiness probes
- [ ] `auth.oidc_issuer` + `auth.oidc_audience` set together when using OIDC JWTs (or left unset)
- [ ] Optional `[tls]` / `tls.client_ca` when terminating TLS on FluxVM itself
- [ ] JSON audit target `fluxvm_audit` shipped to your collector
- [ ] Tutorials: [production/01-readyz-tenant-auth.md](tutorials/production/01-readyz-tenant-auth.md)
- [ ] Example: [examples/create-vm-prod.json](../examples/create-vm-prod.json)
- [ ] DevOps gates: [DEVOPS.md](DEVOPS.md) + `scripts/devops-gate.sh` / `scripts/upgrade-snapshot.sh`
- [ ] **Ship stack:** `./scripts/ship USER@HOST` (or from Fabric repo) then confirm done card
- [ ] **Production readiness script:** `FABRIC_URL=… FLUXVM_URL=… ./scripts/test-production-readiness.sh`
  (control + Network Fabric health + Service Fabric schema/pins; optional `VIP=` SLO)

## 2. Compute

- [ ] `/dev/kvm` present; cgroup v2 delegated
- [ ] Firecracker jailer on for untrusted guests
- [ ] `allowed_backends` pinned
- [ ] Warm pools only on dedicated hosts
- [ ] Snapshots tested for the backends you run (QEMU `savevm`, CH `ch-remote`)
- [ ] Windows + QGA only on QEMU ([ch-windows-qga.md](ch-windows-qga.md)); `fluxvm_engine=kvm` lab-only

## 3. Images & storage

- [ ] Catalog names instead of raw paths where possible
- [ ] Ed25519 and/or `cosign verify-blob` on catalog entries
- [ ] `allowed_image_dirs` set
- [ ] Storage backend chosen (local qcow2, LVM-thin, NBD, Ceph RBD) and backed up

## 4. Network

- [ ] Merge `configs/network-fabric-prod.toml` when VMs have a host edge
- [ ] `fluxvm dataplane health` ok
- [ ] CNP/groups for tenant labels; `fluxvm observe`
- [ ] Packet flow: `fluxvm hubble observe --output color` and `--output plain`; UI `/v1/network/hubble/ui` ([packet-flow.md](packet-flow.md))
- [ ] Cilium coexistence (`mode=cilium`) only if sock/bpffs present — not Cilium-native endpoints
- [ ] Cilium nodes: no FluxVM XDP on the shared datapath
- [ ] See [production-dataplane.md](production-dataplane.md)

## 5. Kubernetes

- [ ] DaemonSet readiness → `/readyz`; liveness → `/healthz`
- [ ] Privileged DaemonSet + hostNetwork as in `deploy/k8s/`
- [ ] Host `nbd` module loaded if GuestKit customize runs on-node
- [ ] Operator talks to an already-healthy fabricd/FluxVM API
- [ ] Optional MicroVM stack after DaemonSet: `deploy/k8s/microvm/`
      (GuestImage Ready on host files; `--convert` opt-in only)
      (`fluxvm-microvm` controller + node-agent; API
      `microvm.fluxvm.zyvor.io`) — [microvm.md](microvm.md),
      [tutorials/microvm/](tutorials/microvm/README.md)
- [ ] Secure Containers RuntimeClass on lab nodes after guest-image + CNI L2
      + Set 3–5 lifecycle/OCI/volume/stdio-TTY smoke —
      [secure-containers.md](secure-containers.md),
      [secure-containers-set3.md](secure-containers-set3.md),
      [secure-containers-set4.md](secure-containers-set4.md),
      [secure-containers-set5.md](secure-containers-set5.md),
      `deploy/containerd/` (`FLUXVM_CONTAINER_CNI=0` for user-mode only)

## 6. Fleet (non-k8s)

- [ ] `fluxvm-agent` TLS + token
- [ ] Persisted `fleet-nodes.json`
- [ ] Placement uses residual CPU/memory

## Do not ship yet as “done”

Cilium-native VM endpoints / in-tree Hubble UI, CH Windows+QGA,
in-tree KVM without Firecracker for production density.
Secure Containers RuntimeClass as full Kata-equivalent (hostPath hotplug,
broad CNI conformance, device-cgroup enforcement, opt-in `CLONE_NEWUSER`
unvalidated under load beyond Set 6) — [secure-containers.md](secure-containers.md).
Sentinel Pod-scoped network policy (Set 6) as automatically enforcing
Kubernetes `NetworkPolicy` objects — the eBPF mechanism and API exist, but
nothing yet watches/resolves live `NetworkPolicy` objects into it.
