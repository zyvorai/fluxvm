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
      + Set 3–5 lifecycle/OCI/volume/stdio-TTY smoke, Set 6/6R recovery +
      namespace isolation, Set 7–9 OOM/metrics + device lifecycle, and
      Set 10/11 guest AppArmor/SELinux/seccomp-argument/seccomp-notify
      enforcement —
      [secure-containers.md](secure-containers.md) (rollup + per-Set links),
      `deploy/containerd/` (`FLUXVM_CONTAINER_CNI=0` for user-mode only)

## 6. Fleet (non-k8s)

- [ ] `fluxvm-agent` TLS + token
- [ ] Persisted `fleet-nodes.json`
- [ ] Placement uses residual CPU/memory

## 7. Sentinel operations tooling

Not the same "fleet" as section 6 above — `fluxvm-fleet` here is a
multi-node *rollout orchestrator* for Sentinel's own eBPF/controller
components, unrelated to `fluxvm-agent`'s VM-placement fleet.

- [ ] `fluxvm-sentinel-certify` (Set 12E): GA hardening & performance
      certification — capability profiles (`baseline`/`performance`/`strict`),
      versioned budgets, evidence bundling, ownership-conservative stale-bpffs
      reconcile, and double-gated failure injection. Static + host recovery
      gates are proven; a full release certification (real verifier matrix,
      privileged lab lane, archived evidence + commit SHA) is still a
      release-engineering step, not an automatic claim
      ([sentinel-ga-certification.md](sentinel-ga-certification.md),
      [sentinel-ga-release-checklist.md](sentinel-ga-release-checklist.md))
- [ ] `fluxvm-migrate` (Set 13E): crash-resumable per-VM migration
      transactions wrapping the real `fluxvm dataplane migration-*` CLI —
      real CLI integration and real failure/rollback proven; not yet run
      against a VM with a live dataplane actually attached
      ([sentinel-migration-orchestrator.md](sentinel-migration-orchestrator.md))
- [ ] `fluxvm-upgrade` (Set 14E): crash-resumable per-node component
      upgrades with eBPF map snapshot/restore across a reload — a real
      transaction against a real pinned BPF map proven end to end on the
      lab host, including three bugs (`bpftool` JSON field-name/encoding
      mismatches, an unhandled `PermissionError` in `probe`) found and
      fixed during that validation, not just claimed
      ([sentinel-stateful-upgrades.md](sentinel-stateful-upgrades.md))
- [ ] `fluxvm-fleet` (Set 15E): canary-first multi-node rollout wrapping
      `fluxvm-upgrade` per node — real SSH-shaped single-node and 2-node
      canary-approval runs proven via a local `ssh` shim on the lab host,
      including two real bugs found and fixed (a canary-approval-gate
      bypass on resume, and a `remote()` stdin bug that always wrote an
      empty file to the target node); a genuinely multi-host run with real
      SSH trust between separate machines has not been done
      ([sentinel-fleet-rollout.md](sentinel-fleet-rollout.md))
- [ ] `fluxvm-fleet-guard` (Set 16E): continuous observe-only fleet drift /
      SLO verification with policy-gated remediation, evidence journals, and
      systemd timer wiring after Set 15E rollout — static/unit gates proven;
      disposable multi-host smoke remains opt-in behind
      `FLUXVM_FLEET_GUARD_HOST_TEST`
      ([sentinel-fleet-drift-slo-guard.md](sentinel-fleet-drift-slo-guard.md))
- [ ] `fluxvm-admit` (Set 17E): non-mutating pre-rollout release admission —
      artifact/evidence integrity, strict-SSH capability probes, state-ABI
      compatibility, cohort coverage, and short-lived tamper-evident admission
      records — static/unit gates proven; never deploys or remediates
      ([sentinel-release-admission.md](sentinel-release-admission.md))

## Do not ship yet as “done”

Cilium-native VM endpoints / in-tree Hubble UI, CH Windows+QGA,
in-tree KVM without Firecracker for production density.
Secure Containers RuntimeClass as full Kata-equivalent (hostPath hotplug,
broad CNI/OCI conformance fixtures, `CLONE_NEWUSER` unvalidated under load,
seccomp `SECCOMP_IOCTL_NOTIF_ADDFD`/remote policy RPC) —
[secure-containers.md](secure-containers.md). Device-cgroup enforcement
(`BPF_PROG_TYPE_CGROUP_DEVICE`, Set 10) and the seccomp user-notification
broker (Set 11) are both implemented; live-node validation of the seccomp
notify path against a real containerd/Kubernetes Pod and a real
enforcing-SELinux mount label are still open.
Sentinel Pod-scoped network policy (Set 6S) automatically enforcing
Kubernetes `NetworkPolicy` objects — a standalone `fluxvm-networkpolicy-
controller` DaemonSet compiles both egress and ingress `NetworkPolicy`
objects into a versioned directional CIDR+L4 tuple Pod policy schema
(Set 14, superseding Set 13's exact-peer/exact-port design), including exact
numeric and named TCP/UDP/SCTP ports, `endPort` ranges, real recursive CIDR
subtraction for `ipBlock.except` (no approximation fallback), and a separate
Pod-ingress eBPF program that shares the main program's conntrack table for
a stateful return-traffic fast path (dataplane schema v9 — Set 16 changed
the shared conntrack table's value from a one-byte, never-expiring presence
marker to a timestamped entry with a per-protocol idle timeout, and made a
VM/Pod policy update clear it synchronously so a tightened policy can never
be bypassed by a stale established-flow entry; TCP SYN/SCTP INIT packets
always re-evaluate current policy rather than taking the established-flow
shortcut, closing a same-5-tuple replay gap). Build/test/
verifier validation for Set 14 is real (workspace `cargo build`/`test`, both
BPF objects load through the real kernel verifier with confirmed shared map
IDs, full Go build/vet/test/race/gofmt/cross-build gate), and so is live
validation: the rewritten `scripts/test-ebpf-smoke.sh` exercises the unified
`fluxvm_prules` rich CIDR+L4 tuple rules (including SCTP) and the separate
shared-map `fluxvm_pod_ingress.bpf.o` object in real network namespaces
against the real kernel verifier, and the rewritten
`scripts/test-networkpolicy-live.sh` proves the new schema-v2 wire shape
against a real single-node k3s cluster — see
[secure-containers-set14.md](secure-containers-set14.md) for specifics,
including the four eBPF verifier bugs found and fixed in the process. Set 15
adds directional `fluxvm_pod_ingress` attachment health and the read-only
Sentinel Policy Observer (`tools/fluxvm-policy-observer`) —
[secure-containers-set15.md](secure-containers-set15.md). Set 16's schema-v9
conntrack revocation-safety was verifier-loaded and its `ct_state` write
confirmed for real (a real ping's learned entry decodes as a plausible
`last_seen_ns` timestamp via bpftool's BTF-aware dump), and VM-level
`allow_ports` now also accepts `sctp/PORT` — see
[secure-containers-set16.md](secure-containers-set16.md). Set 17 adds optional
`fluxvm_prhit` rule-attributed directional telemetry (no schema-v8 ABI bump;
Policy Observer prefers it when present and keeps Set 15's shared-counter
fallback otherwise) —
[secure-containers-set17.md](secure-containers-set17.md). Set 18 tightens
opt-in Service ClusterIP inclusion with EndpointSlice routing proof
([secure-containers-set18.md](secure-containers-set18.md)). Set 19 is the
code-side GA completion candidate (schema-v10, `fluxvm_pridx`, IPv6 extension
walk, guest policy mirror, Observer sizing) —
[secure-containers-set19.md](secure-containers-set19.md). Still open: the live
stateful-conntrack-bypass path between the egress and Pod-ingress programs,
and Set 16's own timeout expiry/anti-replay behavior, are implemented but not
yet proven with a live TCP handshake or wall-clock timing test; the per-VM
rule cap is 64 (kernel verifier limit); multi-node Pod-to-Pod dataplane
conformance is still missing; Set 17/19 production Prometheus scrape evidence
and Kata/fleet/migration lab gates remain open — see
[NEXT-FEATURES.md](NEXT-FEATURES.md),
[secure-containers-set14.md](secure-containers-set14.md),
[secure-containers-set16.md](secure-containers-set16.md),
[secure-containers-set17.md](secure-containers-set17.md),
[secure-containers-set18.md](secure-containers-set18.md), and
[secure-containers-set19.md](secure-containers-set19.md). Sentinel
in-guest per-container network policy (Set 8S) as inheriting a Pod's Set 6S
policy automatically — every container is enforced fail-closed by default,
but the shim does not yet forward Pod policy content per container. Sentinel
in-guest eBPF LSM MAC (Set 9S) is off by default
(`FLUXVM_CONTAINER_LSM=1`) and audit-only unless
`FLUXVM_CONTAINER_LSM_ENFORCE=1` is also set; the guest-embedded `aya`
loader has a known intermittent "error parsing ELF data" load failure on at
least one validation host (see [secure-containers-set9s.md](secure-containers-set9s.md)),
not yet root-caused to a fix.
