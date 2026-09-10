# FluxVM Kubernetes NetworkPolicy Controller — Secure Containers Set 13

A small, node-local control-plane bridge that turns Kubernetes **egress** `NetworkPolicy` selection into FluxVM Set 6S `PodNetworkPolicy` state.

Set 6S already provides the VM-edge eBPF mechanism and the API:

```text
POST /v1/vms/{id}/network/pod-policy
{
  "default_deny": true,
  "audit_mode": false,
  "allow_addresses": ["10.42.1.20", "fd00::20"],
  "deny_addresses": []
}
```

What was missing was the controller that continuously resolves Kubernetes selectors into the exact peer addresses that mechanism expects. Set 13 supplies that piece without modifying the containerd shim or the hot VM runtime path.

## Architecture

```text
Kubernetes API
   │
   ├── Pods / Pod IPs / labels / nodeName
   ├── Namespaces / labels
   ├── Services / ClusterIPs (optional conservative mode)
   └── networking.k8s.io/v1 NetworkPolicy
            │
            ▼
fluxvm-networkpolicy-controller (one per node)
   │  maps Pod UID to local FluxVM VM.request.pod_uid
   │  compiles union of selected egress allow rules
   │
   └── FluxVM node API
       GET    /v1/vms
       GET    /v1/vms/{id}/network/pod-policy
       POST   /v1/vms/{id}/network/pod-policy
       DELETE /v1/vms/{id}/network/pod-policy
                    │
                    ▼
             Set 6S VM-edge eBPF maps
```

The controller runs as a `hostNetwork` DaemonSet so `127.0.0.1` is the node's FluxVM API, filters target Pods by its own `spec.nodeName`, and still reads peer Pods cluster-wide so namespace/pod selectors resolve correctly.

## Security semantics

The compiler intentionally never turns a Kubernetes restriction into a broader FluxVM allow. The current Set 6S `PodNetworkPolicy` schema is address-only, so exact Kubernetes semantics are possible for selector-based destination peers and `/32` or `/128` `ipBlock` peers. Unsupported dimensions are handled as a stricter subset:

- any egress rule with `ports` is **not** converted into an all-port allow; the rule contributes no addresses and is reported as unsupported;
- broad `ipBlock` CIDRs are approximated only to currently known Pod/Service addresses inside the CIDR (respecting `except`); unknown external addresses remain denied;
- ingress policy is not compiled in Set 13 because the current Pod policy contract does not encode direction;
- if an isolated Pod's compiled address set exceeds `--max-addresses`, the controller applies deny-all and reports an error;
- if compilation fails after the Pod is known to be egress-isolated, the returned safe policy is deny-all rather than a stale/wider allow;
- if a Pod is no longer selected by any egress-isolating policy, an old FluxVM Pod policy is cleared;
- if a VM's Pod UID disappears from the Kubernetes snapshot entirely, Set 13 leaves its existing policy in place rather than widening a potentially still-running stale VM during teardown.

Kubernetes `NetworkPolicy` allow rules are additive, so multiple policies selecting the same Pod are unioned. An egress rule with no `to` and no `ports` allows all destinations and therefore produces `default_deny=false`.

`--audit` is available as an operator-level controller flag, but audit mode is intentionally not the default because it is log-and-allow rather than enforcement. Set 13 deliberately does not provide Pod annotations that disable or downgrade policy: workload authors must not be able to bypass enforcement by editing their own Pod metadata.

## Service ClusterIPs

`--include-service-clusterips` is off by default. When enabled, a Service ClusterIP is added only if the Service has a selector, it resolves to at least one currently active Pod, and **every** currently active Pod selected by that Service is already an allowed peer. This avoids widening a narrow Pod selector through a broader Service selector. Services with manual EndpointSlices cannot be proven safe from Service selectors alone and are therefore not included by this mechanism.

## Build and test

The controller has **zero non-standard-library Go dependencies**.

```bash
cd controllers/fluxvm-networkpolicy-controller
go test ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build ./cmd/fluxvm-networkpolicy-controller
```

Or:

```bash
make test vet race build
```

## Deploy

Build/push the image, update the image reference in `deploy/daemonset.yaml`, then:

```bash
kubectl apply -k controllers/fluxvm-networkpolicy-controller/deploy
```

If FluxVM requires bearer authentication, create a Secret from a token, mount it into the DaemonSet, and pass `--fluxvm-token-file`. The example Secret contains a placeholder only; never commit a real token.

Health and observability are exposed on port 9090:

- `/healthz` — process liveness;
- `/readyz` — at least one recent successful reconcile;
- `/metrics` — Prometheus text metrics for reconciles, API errors, managed Pods, applied/cleared policies and unsupported rule counts.

## Configuration

Key flags/environment variables:

| Flag | Environment | Default |
|---|---|---|
| `--node-name` | `NODE_NAME` | required |
| `--interval` | `RECONCILE_INTERVAL` | `5s` |
| `--fluxvm-url` | `FLUXVM_URL` | `http://127.0.0.1:7788` |
| `--fluxvm-token-file` | `FLUXVM_TOKEN_FILE` | empty |
| `--max-addresses` | `MAX_ADDRESSES` | `12000` |
| `--include-service-clusterips` | `INCLUDE_SERVICE_CLUSTERIPS` | `false` |
| `--audit` | `POLICY_AUDIT` | `false` |
| `--metrics-listen` | `METRICS_LISTEN` | `:9090` |

Kubernetes API URL/token/CA default to the standard in-cluster ServiceAccount environment and projected token paths. Both Kubernetes and FluxVM HTTPS clients verify TLS by default; insecure-skip flags are explicit opt-ins only.

## Deliberate Set 13 boundaries

This is not presented as full Kubernetes `NetworkPolicy` conformance. Address-only Set 6S policy cannot exactly encode L4 ports, named ports, ingress direction, arbitrary external CIDRs, `endPort`, SCTP-specific behavior, or policy semantics requiring EndpointSlice state. Set 13 reports these limitations and fails stricter where enforcement cannot be represented without widening access.

The natural next protocol step is to extend FluxVM `PodNetworkPolicy` to direction + CIDR + L4 tuples and then have this controller compile the full Kubernetes model without those approximations.
