# Secure Containers Set 18 — EndpointSlice-aware Service VIP policy

Set 18 closes Sentinel backlog S4 without changing the eBPF/dataplane ABI.
It strengthens the existing opt-in `--include-service-clusterips` compiler
mode by using `discovery.k8s.io/v1 EndpointSlice` as the Service-routing
source of truth instead of inferring backend safety from the Service selector
alone.

A ClusterIP is emitted only for egress destination peers and only when, for that IP family, at least one endpoint
may receive Service traffic and every such endpoint can be proven to be a
non-terminal Pod already selected by the NetworkPolicy peer. The endpoint's
address must be one of that Pod's current addresses and the Pod must still
match the Service selector. Unknown/external targets, stale addresses,
selector drift, or an unselected routable backend fail closed for that
Service address family. Dual-stack Services are evaluated independently for
IPv4 and IPv6.

Endpoint condition handling follows discovery/v1 semantics: nil `ready` and
`serving` are true; nil `terminating` is false. Normal ready endpoints are
considered routable, and `serving && terminating` endpoints are also treated
as potentially routable because Service proxies can use them during draining
fallback. A merely NotReady/non-serving backend does not block a VIP.

The controller adds a standard-library EndpointSlice client method and
requires `get,list` RBAC on `discovery.k8s.io/endpointslices`. To preserve
existing controller test fakes and deployments that leave Service VIP mode
off, the base Kubernetes interface is not widened; the controller requests
EndpointSlices through a small capability interface only when
`IncludeServiceClusterIPs` is enabled.

## Validation

Portable/unit gates cover: safe ready backend, unsafe selected-set drift,
NotReady exclusion, serving+terminating drain fallback, ready=nil semantics,
dual-stack per-family behavior, and discovery/v1 client decoding. The live
script creates a real Service and real EndpointSlices in Kubernetes, proves a
NotReady unselected backend does not block the VIP, then recreates that backend
as Ready and proves the VIP is removed.

No dataplane schema bump is required; this is controller-only policy
compilation hardening and is independent of Set 17's proposed telemetry ABI.
