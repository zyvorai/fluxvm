# Secure Containers Set 13 — Kubernetes NetworkPolicy control plane

Set 13 closes the control-plane gap left intentionally open by Sentinel Set 6S. The VM-edge dataplane already accepts a Pod-scoped policy containing `default_deny`, `audit_mode`, exact IPv4/IPv6 allow addresses and exact deny addresses. Set 13 adds the Kubernetes controller that continuously derives that state from `networking.k8s.io/v1 NetworkPolicy`.

## Why this is a separate controller

The containerd shim is latency-sensitive and owns one Pod VM's lifecycle. Kubernetes policy reconciliation is cluster control-plane work: it needs cross-namespace Pods, Namespace labels and policy objects, and it changes independently of container start/stop. Keeping this in a node-local controller means policy updates do not require a shim restart and Kubernetes API credentials never enter the guest VM.

Each DaemonSet instance:

1. lists Pods, Namespaces, Services and NetworkPolicies from the Kubernetes API;
2. lists VMs from its node-local FluxVM API;
3. matches local Pods to VMs through `metadata.uid == VM.request.pod_uid`;
4. unions every egress NetworkPolicy that selects the Pod;
5. resolves Pod/Namespace selectors to current Pod IPs;
6. compares the desired policy with the current FluxVM policy and writes only when it changed.

Multiple VMs carrying the same Pod UID are all updated to the same policy instead of choosing one silently.

## Translation rules

Set 13 intentionally compiles only policy that the current Set 6S wire/API shape can express without widening access.

| Kubernetes rule | Set 13 result |
|---|---|
| no egress- or ingress-isolating policy selects Pod at all | clear generated FluxVM Pod policy (unmanaged) |
| an ingress-isolating policy selects Pod, but no egress-isolating one does | egress compiles to an explicit `default_deny=false` with an empty allow set (`PodNetworkPolicy` is the top-level, non-optional struct, so *some* value is always written) -- behaviorally identical to "no policy" |
| an egress-isolating policy selects Pod, but no ingress-isolating one does | `ingress` is left `null` on the wire (it's an optional sub-field, unlike the top-level struct) -- the same "unconfigured means allow" semantics as a Pod with no policy at all, just without an explicit empty struct. Note Kubernetes defaults `policyTypes` to *include* Ingress even for an egress-only policy, unlike Egress's own opt-in default, so this case is rarer than it sounds |
| explicit `policyTypes: [Egress]` with no egress rules (or, for ingress, no `ingress` rules present at all) | `default_deny=true`, empty allow set for that direction |
| Pod selector | exact current Pod IPv4/IPv6 addresses |
| Namespace selector | current Pod addresses from matching Namespaces |
| Namespace + Pod selector | intersection, as Kubernetes requires |
| multiple selecting policies | union of allows, per direction |
| empty `to`/`from` and no ports | `default_deny=false` for that direction (allow all destinations/sources) |
| `/32` or `/128` `ipBlock` | exact address |
| broader `ipBlock`, no `except` | a real dataplane schema v8 CIDR entry (`fluxvm_pid4_cidr`/`fluxvm_pid6_cidr`), not an approximation |
| broader `ipBlock` with `except`, or any `ipBlock` inside a `ports`-restricted rule | only currently-known cluster addresses in the prefix, respecting `except`; external unknown addresses remain denied -- Kubernetes `except` subtracts from a CIDR, which an LPM-trie entry cannot represent, and the port-scoped maps have no CIDR dimension at all |
| egress rule with `ports` naming exact numeric TCP/UDP ports | schema v7 protocol+port allow for each resolved peer, not widened to every port |
| egress rule with `ports` naming a *named* port | resolved independently per selected peer Pod's own container spec (Kubernetes semantics: the name is per-destination-container); a peer that doesn't declare that name is denied for that peer only, not the whole rule |
| ingress rule with `ports` naming a named port | resolved once against the policy's own protected Pod's container spec (Kubernetes semantics: an ingress rule's `ports` restricts *this* Pod's own ports, not the peer's) |
| rule with `ports` containing an `endPort` range | schema v8 protocol+range allow (`fluxvm_pid4_port_range`/`fluxvm_pid6_port_range`) for each resolved peer, capped at 8 ranges per peer+protocol (`FLUXVM_MAX_PORT_RANGES`); the excess beyond 8 is denied and reported unsupported, not silently dropped |
| rule with `ports` and no `to`/`from` | contributes no allow and is reported unsupported (there is no all-address port-scoped allow to compile to) |

The remaining approximation (`except`-bearing or port-restricted-context broad `ipBlock`) and the 8-range-per-peer cap are deliberately **stricter than Kubernetes**, not more permissive: they can break a workload until a future extension removes them, but never silently turn a restriction into a broader allow. When a peer is reachable both through an unrestricted rule and a port-restricted rule (from any selected policy, same direction), the unrestricted rule wins for that peer -- matching Kubernetes' own union-of-rules semantics -- and the now-redundant port-scoped entry is dropped before compiling.

## Service VIP compatibility

The VM-edge hook may see a ClusterIP before the host Kubernetes dataplane translates it. `--include-service-clusterips` is therefore available but disabled by default. When enabled, Set 13 adds a selector-based Service ClusterIP only when every currently active Pod selected by that Service is already in the policy's allowed peer set. A Service with manual endpoints cannot be proven equivalent from its Service selector and is not made safe by this option.

## Eventual consistency

Set 13 uses deterministic paginated list/reconcile cycles rather than a watch cache. This keeps the first release dependency-free and restart-safe, but updates are eventually consistent at the configured interval (5 seconds by default), not atomically synchronized across Kubernetes resource kinds. Policy writes themselves are idempotent and old policy is retained when a VM's Pod UID disappears from a snapshot, avoiding a teardown race that would widen a still-running stale VM.

## Security controls

- generated enforcement is default-deny once a Pod is egress-isolated;
- compiler/address-limit errors return a deny-all fallback and the controller attempts to apply it;
- the controller never runs privileged and needs no host filesystem mounts;
- Kubernetes RBAC is read-only for Pods, Namespaces, Services and NetworkPolicies;
- FluxVM writes use its normal authenticated `/v1/vms/{id}/network/pod-policy` API;
- ServiceAccount and FluxVM token files are reread for requests, supporting projected/rotated tokens;
- TLS verification is on by default for HTTPS; insecure skip is explicit only;
- there are no workload-controlled Pod annotations that disable or downgrade policy; audit mode is an operator-level controller setting only.

## Observability

The controller exposes `/healthz`, `/readyz` and Prometheus `/metrics`. Counters/gauges cover reconciliation failures, API errors, policy changes, clears, unsupported rules, managed local Pods, matched VMs and last successful reconcile time. Structured JSON logs include Pod UID, VM ID, selected policy names and compiled allow-address count.

## Validation in the Set 13 build environment

The controller has no third-party Go dependencies. The release build ran:

```text
go test ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath ...
```

All passed on Go 1.22.2 locally and Go 1.27.1 (the toolchain available in this session; the remote validation host's installed Go 1.22.2 could not build against this repo's `go 1.23` `go.mod` requirement and had no network access to download the pinned toolchain -- a pre-existing environment gap, not something this change introduced). HTTP integration tests exercise Kubernetes token + pagination behavior and the exact FluxVM `{"items": [...]}` VM-list / `null` Pod-policy response shapes. Reconcile tests exercise apply, clear, duplicate-VM handling and deny-all fallback after an address-limit compile error. Compiler tests now additionally cover: ingress compilation (Pod/Namespace-selector `from`, named ports resolved against the *target*'s own container spec), egress named ports resolved independently per selected peer Pod, `endPort` ranges (including the 8-range-per-peer overflow case), and CIDR compilation for `ipBlock` with and without `except`.

The eBPF side (dataplane schema v8 -- CIDR and port-range fallback maps, the new `fluxvm_pod_ingress` tc-egress-hook program) was additionally proven against a real kernel: `scripts/test-ebpf-smoke.sh` loads the actual compiled `fluxvm_tc.bpf.o` into real network namespaces and asserts CIDR-fallback allow/deny, port-range-fallback allow/deny, and independent ingress-hook allow/deny via a real second `tc filter add ... egress ...` attachment -- not just unit-tested Go compilation logic.

A real multi-node Kubernetes + FluxVM dataplane reconciliation test (creating live Pods, applying a real `NetworkPolicy`, and asserting actual connectivity allow/deny) is still required before claiming full Kubernetes NetworkPolicy conformance -- see "Next protocol step" below for what specifically remains.

## Numeric port/protocol rules and schema v8 extensions

Dataplane schema v7 added `fluxvm_pid4_port`/`fluxvm_pid6_port`: a peer with no address-wide `fluxvm_pid4`/`fluxvm_pid6` entry falls through to an exact `(pod_id, address, protocol, port)` lookup before the pod-level `default_deny` fallback. Schema v8 (see [drop-reason-migration-state.md](drop-reason-migration-state.md#dataplane-schema-v8)) extends this fallback chain with a CIDR tier (`fluxvm_pid4_cidr`/`fluxvm_pid6_cidr`, LPM-trie) and a bounded port-range tier (`fluxvm_pid4_port_range`/`fluxvm_pid6_port_range`, up to 8 ranges per peer+protocol), and adds a fully parallel `_in`-suffixed map set plus a new `fluxvm_pod_ingress` program for the Pod-**ingress** direction (who may reach the Pod), attached at the tc *egress* hook alongside the pre-existing, unchanged `fluxvm_egress` program at the tc *ingress* hook.

## Next protocol step

What remains, in priority order:

1. **Live multi-node reconciliation/conformance test.** Everything above is validated at the unit and single-host-kernel level; a real cluster test (live Pods, a real `NetworkPolicy` object, asserted actual connectivity) has not yet run.
2. **CIDR + `except`.** An LPM-trie entry cannot represent Kubernetes' `except` subtraction; a CIDR peer with `except` still falls back to exact-address approximation.
3. **CIDR combined with a port restriction.** The port-scoped maps have no CIDR dimension; a `ports`-restricted rule with an `ipBlock` peer still falls back to exact-address approximation, never a real CIDR entry.
4. **More than 8 port ranges per peer+protocol.** `FLUXVM_MAX_PORT_RANGES` is a fixed kernel array; the excess is denied and reported unsupported rather than silently dropped, but is not yet representable at all.
