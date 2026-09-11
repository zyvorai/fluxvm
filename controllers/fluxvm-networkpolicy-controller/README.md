# FluxVM Kubernetes NetworkPolicy Controller — Secure Containers Set 14

Set 14 upgrades Sentinel from Set 13's mostly address-oriented egress bridge to
a **directional CIDR + L4 Kubernetes NetworkPolicy compiler** for FluxVM Secure
Containers.

The node-local controller still maps Kubernetes Pod UIDs to
`VmRecord.request.pod_uid`, but it now emits Pod policy schema v2:

```json
{
  "schema_version": 2,
  "default_deny": true,
  "audit_mode": false,
  "egress_isolated": true,
  "ingress_isolated": true,
  "rules": [
    {"direction":"egress","cidr":"10.42.2.19/32","protocol":"TCP","port_start":443,"port_end":443},
    {"direction":"ingress","cidr":"10.42.3.0/24","protocol":"TCP","port_start":8080,"port_end":8090}
  ]
}
```

Rules are ORed. Peer CIDR, protocol and port interval inside one rule are ANDed.
An empty protocol with `0..0` ports means all protocols and ports. A protocol
with `0..0` ports means all ports of that protocol.

## What Set 14 adds

- independent Kubernetes **Ingress** and **Egress** isolation;
- selector resolution across Pods and Namespaces for both directions;
- native IPv4/IPv6 CIDRs rather than expanding broad `ipBlock` ranges to known
  addresses;
- exact `ipBlock.except` subtraction into disjoint allowed prefixes;
- TCP, UDP and SCTP;
- numeric ports and inclusive `endPort` ranges;
- named ingress ports resolved against the target Pod;
- named egress ports resolved per selected destination Pod, keeping each
  destination address bound to its own named-port number;
- additive union across every NetworkPolicy selecting a Pod;
- bounded `--max-rules` fail-closed compilation;
- the optional conservative Service ClusterIP rule from Set 13;
- rollout-safe legacy fields so an older Set 6S/13 node over-denies instead of
  silently bypassing a directional Set 14 policy.

## Dataplane model

Set 14 preserves Set 6S exact-address maps and the already-merged Set 13 exact
peer+TCP/UDP-port maps. Pod policy schema v2 adds a bounded `fluxvm_prules` map.
The existing VM-edge program enforces egress. A second `fluxvm_pod_ingress`
classifier is attached to TC egress on the host-visible VM edge, which is
host-to-guest traffic in the FluxVM topology.

The ingress program reuses the existing `fluxvm_ct` map. This keeps policy
stateful in both directions: replies to an allowed guest-initiated flow pass a
restrictive ingress policy, and replies to an allowed ingress-initiated flow
pass a restrictive egress policy.

FluxVM-owned maps remain private to the VM and do not mutate Cilium-private
maps. The extra TC egress filter uses preference `49153`, handle `2`; the
existing VM-edge filter keeps its previous ownership slot.

## Security behavior

The compiler never widens an unsupported rule. Important fail-closed cases:

- an unresolvable named port contributes no allow tuple;
- named egress ports require selector-resolved destination Pods; an unrestricted
  or `ipBlock` peer cannot safely supply a destination Pod's named port;
- malformed CIDRs, invalid `except`, invalid port ranges and rule-limit overflow
  cause a safe deny result;
- a disappeared Kubernetes Pod UID does not trigger a teardown-time widening;
- an isolated Pod that becomes unmanaged has generated policy cleared only when
  the Pod is still present and is no longer selected by isolation policy.

ARP, DHCPv4/DHCPv6 and IPv6 NDP are bootstrap-exempt at the VM edge. Direct
IPv6 extension-header L4 walking is not added in this set; the final live
conformance gate must include those corner cases.

## Build and test

The controller has no third-party Go module dependencies.

```bash
cd controllers/fluxvm-networkpolicy-controller
gofmt -w cmd internal
go test ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/fluxvm-networkpolicy-controller
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./cmd/fluxvm-networkpolicy-controller
```

The Set 14 release kit also supplies Rust/eBPF CI gates for the changed FluxVM
network crate and both VM-edge BPF objects.

## Deploy

Build/push the image and then:

```bash
kubectl apply -k controllers/fluxvm-networkpolicy-controller/deploy
```

The DaemonSet is non-privileged and uses `hostNetwork` only so the controller
can reach the node-local FluxVM API at `127.0.0.1`. It needs read-only access to
Pods, Namespaces, Services and NetworkPolicies. Kernel eBPF attachment remains
the FluxVM daemon's responsibility, not the controller Pod's.

## Configuration

| Flag | Environment | Default |
|---|---|---|
| `--node-name` | `NODE_NAME` | required |
| `--interval` | `RECONCILE_INTERVAL` | `5s` |
| `--fluxvm-url` | `FLUXVM_URL` | `http://127.0.0.1:7788` |
| `--fluxvm-token-file` | `FLUXVM_TOKEN_FILE` | empty |
| `--max-rules` | `MAX_RULES` | `64` (kernel verifier cap for Set 14 `fluxvm_prules`) |
| `--max-addresses` | `MAX_ADDRESSES` | `12000` (legacy compatibility) |
| `--include-service-clusterips` | `INCLUDE_SERVICE_CLUSTERIPS` | `false` |
| `--audit` | `POLICY_AUDIT` | `false` |
| `--metrics-listen` | `METRICS_LISTEN` | `:9090` |

Kubernetes API URL/token/CA default to the standard in-cluster ServiceAccount
values. Kubernetes and FluxVM HTTPS verify certificates by default; insecure
skip is explicit opt-in only.

## Production gate

Set 14 closes NetworkPolicy representation gaps from Set 13; Set 15 adds
directional attachment health and the read-only Policy Observer. This source
handoff does **not** claim live multi-node Kubernetes NetworkPolicy
conformance. Before production enablement, run the live gates on a Linux KVM
node with the real FluxVM TC objects, CNI, dual-stack traffic and policy
transitions. See `docs/secure-containers-set14.md`,
`docs/secure-containers-set15.md`, and `docs/NEXT-FEATURES.md`.
