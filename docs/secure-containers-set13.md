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
| no egress-isolating policy selects Pod | clear generated FluxVM Pod policy |
| explicit `policyTypes: [Egress]` with no egress rules | `default_deny=true`, empty allow set |
| Pod selector | exact current Pod IPv4/IPv6 addresses |
| Namespace selector | current Pod addresses from matching Namespaces |
| Namespace + Pod selector | intersection, as Kubernetes requires |
| multiple selecting policies | union of egress allows |
| empty `to` and no ports | `default_deny=false` (allow all destinations) |
| `/32` or `/128` `ipBlock` | exact address |
| broader `ipBlock` | only currently-known cluster addresses in the prefix, respecting `except`; external unknown addresses remain denied |
| any rule containing `ports` / named ports / `endPort` | rule is not widened to all ports; it contributes no allow addresses and is reported unsupported |
| ingress policy | not compiled in this Set |

The broad-`ipBlock` and port cases are deliberately **stricter than Kubernetes**, not more permissive. This can break a workload until the next protocol extension adds CIDR and L4 tuples, but it does not silently turn a port/CIDR restriction into a broader allow.

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

All passed on Go 1.23.2. HTTP integration tests exercise Kubernetes token + pagination behavior and the exact FluxVM `{"items": [...]}` VM-list / `null` Pod-policy response shapes. Reconcile tests exercise apply, clear, duplicate-VM handling and deny-all fallback after an address-limit compile error.

A real multi-node Kubernetes + FluxVM dataplane test is still required before claiming Kubernetes NetworkPolicy conformance. Set 13 explicitly does not make that claim because the current Pod policy API lacks ingress, CIDR and L4 dimensions.

## Next protocol step

Extend `PodNetworkPolicy` with direction, CIDR and L4 tuples (including named-port resolution at controller level). Once that exists, this controller can compile full egress semantics without stricter approximations and can add ingress translation as a separate hook direction.
