# FluxVM Secure Containers — Set 6 (Sentinel): Pod-scoped eBPF network policy

Set 6 (Sentinel track) is the first piece of **FluxVM Sentinel**: the
eBPF-based policy substrate spanning the host VMM edge and (in later Sets)
the guest kernel, sharing one schema and identity model — the differentiator
from Kata's namespace+seccomp+static-policy-file security story. This Set
wires Secure Containers Pod VMs into a Kubernetes-NetworkPolicy-*shaped*,
identity-based ACL, extending the existing per-VM `fluxvm_tc.bpf.c` dataplane
that Secure Containers already attaches to (via
`fluxvm_network::dataplane::apply_sandbox_policy`) but that, through Set 5,
carried no Pod-aware policy concept at all — only flat CIDR/L4 rules keyed by
a VM-UUID hash.

## What changed

- **New, independent map set** (`bpf/fluxvm_pod_policy.bpf.h`): `fluxvm_pspol`
  (per-Pod policy flags: `ENABLED`/`DEFAULT_DENY`/`AUDIT`), `fluxvm_pid4`/
  `fluxvm_pid6` (individual peer-address allow/deny, mirroring Service
  Fabric's `fluxvm_sid4`/`fluxvm_sid6` VIP-identity-ACL schema), `fluxvm_ppstat`
  (per-Pod allow/deny/audit counters). Deliberately a *separate* map set from
  Service Fabric's VIP policy — independent lifecycle, sizing, and ownership —
  even though the verdict logic is intentionally similar.
- **`struct iface_config` gains a `pod_id` field** (`bpf/fluxvm_tc.bpf.c`,
  `DATAPLANE_SCHEMA_VERSION` 4→5). `handle_ipv4`/`handle_ipv6` AND the
  existing CIDR/L4/rate verdict with a pod-policy lookup whenever
  `pod_id != 0` — additive only: pod policy can narrow an allow into a deny,
  never widen a deny into an allow. `pod_id == 0` (every non-Secure-Containers
  sandbox) skips the check entirely — zero behavior change for existing
  dataplane users.
- **Pod identity** (`fluxvm-network::pod_identity`): mints a stable `u32`
  `pod_id` from a Kubernetes Pod UID, persisted under
  `state_dir/network-groups/pod-ids.json` with deterministic collision
  resolution (a pure 32-bit hash of a UID has a non-negligible birthday-bound
  collision chance at real cluster scale; a collision here would silently
  merge two Pods' policy).
- **End-to-end wiring**: the shim already resolves `hints.pod_uid` from the
  CRI `io.kubernetes.cri.sandbox-uid` annotation (used since Set 4 for
  kubelet volume exports) and now also sends it as `pod_uid` on
  `POST /v1/vms`. `CreateVmRequest::pod_uid` flows through
  `VmManager::create()`/`apply_sandbox_policy()`, which mints the Pod
  identity and threads it into `ebpf::apply()`.
- **Independent policy-content API**: `dataplane::set_pod_network_policy`
  (HTTP: `GET`/`POST`/`DELETE /v1/vms/{id}/network/pod-policy`, admin-only for
  writes) sets or clears a Pod's peer allow/deny list without requiring a
  full VM re-attach, persisted under `state_dir/network-pod-policy/` so a
  restart/repair re-applies it instead of silently resetting to unconfigured.

## Deliberately out of scope for this Set

**Populating peer addresses from a live Kubernetes `NetworkPolicy` object is
not implemented.** `PodNetworkPolicy` (`allow_addresses`/`deny_addresses`) is
the mechanism's *input* — resolving a `NetworkPolicy`'s pod-selector-based
`ingress`/`egress` rules into concrete peer IPs requires a Kubernetes watcher
(watching `NetworkPolicy` and `Pod` objects, resolving selectors) that does
not exist anywhere in this codebase yet, for any policy type. Building that
watcher is a separate, sizable piece of work; this Set delivers the data-plane
mechanism it would call (`set_pod_network_policy`), safely inert until
something calls it. Until then, an attached Secure Containers Pod VM has a
`pod_id` association (visible via `GET .../network/pod-policy` returning
`null`) but no Pod-scoped policy content — behavior is unchanged from Set 5.

## Why a separate map set instead of reusing `fluxvm_spol`/`fluxvm_sid4/6`

Service Fabric's identity ACL is keyed by VIP `service_id` and only reachable
from the Service-Fabric TC/XDP/connect4 programs Secure Containers VMs never
attach. Even setting that aside, Pod policy and VIP policy have different
owners, different lifecycles (a Pod's policy dies with its one VM; a VIP's
serves many backends across many VMs), and different sizing needs
(`FLUXVM_MAX_POD`/`FLUXVM_MAX_POD_PEER` vs `FLUXVM_MAX_SVC`/`FLUXVM_MAX_SID`).
Reusing the VIP maps would couple two independent concerns for no benefit —
this is intentional duplication, not an oversight.

Since `bpf/fluxvm_tc.bpf.c` is loaded per-VM (`bpftool prog load ... pinmaps
<vm-private-dir>` creates a fresh map instance set for every VM), these new
maps are automatically private per VM too — the same collision-free property
`fluxvm_v4`/`fluxvm_v6` already have, confirmed by inspecting the pin
directory of a real loaded program.

## Validation performed

- **Kernel verifier**: `scripts/build-ebpf.sh` compiles cleanly; a real
  `bpftool prog load` of the modified `fluxvm_tc.bpf.o` on a Linux 6.8 host
  is accepted by the verifier (not just clang — the two are different
  checks). BTF confirms `struct iface_config` is exactly 48 bytes with
  `pod_id` at byte offset 40, matching the Rust encoder exactly.
- **Kernel runtime behavior** (`scripts/test-ebpf-smoke.sh`, extended):
  real veth-pair packet tests confirm (a) a Pod with no `fluxvm_pspol` entry
  behaves identically to before this Set (allowed); (b) `ENABLED|DEFAULT_DENY`
  with no explicit peer entry blocks traffic that would otherwise be allowed
  by the VM-level policy; (c) an explicit `fluxvm_pid4` allow entry restores
  it. This is real enforcement, not just "loads without crashing."
- **Rust**: `cargo build`/`cargo test` for `fluxvm-network`, `fluxvm-core`,
  `fluxvm-scheduler`, `fluxvm-storage`, `fluxvm-api`, `fluxvm-qemu`, and
  `fluxvm-containerd-shim` on the same host — all existing tests plus four new
  `pod_identity` tests (including a forced-collision case) pass.
- **Not yet run**: a live end-to-end pass (install the rebuilt shim/daemon
  binaries, restart the `fluxvm`/`containerd` services, launch a real Secure
  Containers Pod, confirm `fluxvm_id`'s `pod_id` field and `fluxvm_pspol`
  entries land correctly) — deliberately not performed against the
  already-running FluxVM host used for the validation above, since that would
  mean restarting a live daemon; do this on request.

## Remaining gates

- A Kubernetes `NetworkPolicy` watcher/controller to populate
  `PodNetworkPolicy` automatically (see "Deliberately out of scope" above).
- Live end-to-end validation on a real KVM/containerd/Kubernetes node (see
  "Not yet run" above).
- A `guest_security`-style production-readiness gate section asserting
  `pod_id` association and policy enforcement for a live Pod (planned for a
  later Sentinel Set once the in-guest pieces exist too).
