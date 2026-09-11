# Secure Containers / Sentinel use-case matrix

Source of truth for portable CI coverage. Every **portable** row must have an
existing test target that `scripts/check-use-case-matrix.sh` can resolve.
**Live** rows require lab infrastructure and are not required for PR green.

CI job names refer to [`.github/workflows/secure-containers-coverage.yml`](../.github/workflows/secure-containers-coverage.yml)
unless noted. Live rows use `secure-containers-live.yml` (opt-in via
`FLUXVM_SECURE_CONTAINERS_LIVE_CI=1`).

| ID | Use case | Set | Test target | CI job | Live? |
|---|---|---|---|---|---|
| UC-NP-01 | No matching policy → unmanaged | 14 | `controllers/fluxvm-networkpolicy-controller/internal/policy/compiler_test.go` | go-controller | no |
| UC-NP-02 | Explicit egress deny-all | 14 | `controllers/fluxvm-networkpolicy-controller/internal/policy/compiler_test.go` | go-controller | no |
| UC-NP-03 | Selector union across policies | 14 | `controllers/fluxvm-networkpolicy-controller/internal/policy/compiler_test.go` | go-controller | no |
| UC-NP-04 | Exact TCP port + endPort range | 14 | `controllers/fluxvm-networkpolicy-controller/internal/policy/compiler_test.go` | go-controller | no |
| UC-NP-05 | SCTP supported | 14 | `controllers/fluxvm-networkpolicy-controller/internal/policy/compiler_test.go` | go-controller | no |
| UC-NP-06 | ipBlock except decomposition | 14 | `controllers/fluxvm-networkpolicy-controller/internal/policy/compiler_test.go` | go-controller | no |
| UC-NP-07 | IPv6 host block | 14 | `controllers/fluxvm-networkpolicy-controller/internal/policy/compiler_test.go` | go-controller | no |
| UC-NP-08 | Named port resolve + fail-closed | 14 | `controllers/fluxvm-networkpolicy-controller/internal/policy/compiler_test.go` | go-controller | no |
| UC-NP-09 | Rule-cap / malformed → safe deny | 14 | `controllers/fluxvm-networkpolicy-controller/internal/policy/compiler_test.go` | go-controller | no |
| UC-NP-10 | Reconcile apply / clear / deny-on-compile-error | 14 | `controllers/fluxvm-networkpolicy-controller/internal/controller/controller_test.go` | go-controller | no |
| UC-NP-11 | K8s list failure stops before FluxVM writes | 14 | `controllers/fluxvm-networkpolicy-controller/internal/controller/controller_test.go` | go-controller | no |
| UC-18-01 | EndpointSlice VIP when only selected Ready | 18 | `controllers/fluxvm-networkpolicy-controller/internal/policy/endpointslice_set18_test.go` | go-controller | no |
| UC-18-02 | Reject VIP when routable backend outside peer | 18 | `controllers/fluxvm-networkpolicy-controller/internal/policy/endpointslice_set18_test.go` | go-controller | no |
| UC-18-03 | Unselected serving+terminating blocks VIP | 18 | `controllers/fluxvm-networkpolicy-controller/internal/policy/endpointslice_set18_test.go` | go-controller | no |
| UC-18-04 | Ready=nil treated as routable | 18 | `controllers/fluxvm-networkpolicy-controller/internal/policy/endpointslice_set18_test.go` | go-controller | no |
| UC-18-05 | Dual-stack safety per family | 18 | `controllers/fluxvm-networkpolicy-controller/internal/policy/endpointslice_set18_test.go` | go-controller | no |
| UC-18-06 | VIP never ingress source identity | 18 | `controllers/fluxvm-networkpolicy-controller/internal/policy/endpointslice_set18_test.go` | go-controller | no |
| UC-18-07 | Stale endpoint address blocks VIP | 18 | `controllers/fluxvm-networkpolicy-controller/internal/policy/endpointslice_set18_test.go` | go-controller | no |
| UC-18-08 | VIP mode requires EndpointSlice capability | 18 | `controllers/fluxvm-networkpolicy-controller/internal/controller/endpointslice_set18_test.go` | go-controller | no |
| UC-18-09 | VIP mode off / empty slice / selectorless Service | 18 | `controllers/fluxvm-networkpolicy-controller/internal/policy/endpointslice_coverage_test.go` | go-controller | no |
| UC-18-10 | Selected serving+terminating alone admits VIP | 18 | `controllers/fluxvm-networkpolicy-controller/internal/policy/endpointslice_coverage_test.go` | go-controller | no |
| UC-18-11 | Dual-stack partial fail (IPv4 ok, IPv6 blocked) | 18 | `controllers/fluxvm-networkpolicy-controller/internal/policy/endpointslice_coverage_test.go` | go-controller | no |
| UC-18-12 | EndpointSlice list error fail-closed before writes | 18 | `controllers/fluxvm-networkpolicy-controller/internal/controller/endpointslice_coverage_test.go` | go-controller | no |
| UC-18-13 | Live EndpointSlice NotReady→Ready withdraws VIP | 18 | `scripts/test-networkpolicy-endpointslice-set18.sh` | live-endpointslice | yes |
| UC-17-01 | Rule telemetry aggregates direction + identity | 17 | `tools/fluxvm-policy-observer/internal/observer/rule_telemetry_set17_test.go` | go-observer | no |
| UC-17-02 | Rule telemetry ignores other Pod | 17 | `tools/fluxvm-policy-observer/internal/observer/rule_telemetry_set17_test.go` | go-observer | no |
| UC-17-03 | Prefer prhit; fall back to shared counters | 17 | `tools/fluxvm-policy-observer/internal/observer/schema_coverage_test.go` | go-observer | no |
| UC-17-04 | Schema-v10 / v9 recognition | 19 | `tools/fluxvm-policy-observer/internal/observer/schema_coverage_test.go` | go-observer | no |
| UC-17-05 | Observer sizing model JSON | 19 | `scripts/benchmark-policy-observer-set19.py` | observer-sizing | no |
| UC-17-06 | Stateful CT TCP live proof (S1 starter) | 17 | `scripts/test-networkpolicy-stateful-set17.sh` | live-stateful | yes |
| UC-19-01 | pridx key encoding + wildcard protocol OR | 19 | `crates/fluxvm-network/src/ebpf.rs` | rust-crates | no |
| UC-19-02 | IPv6 extension-header walk table | 19 | `crates/fluxvm-network/src/ipv6_ext_walk.rs` | rust-crates | no |
| UC-19-03 | UpdateNetworkPolicy serde round-trip | 19 | `crates/fluxvm-container-protocol/src/lib.rs` | rust-crates | no |
| UC-19-04 | Guest mirror empty / dedupe / schema_version | 19 | `crates/fluxvm-container-protocol/src/lib.rs` | rust-crates | no |
| UC-19-05 | Host eBPF objects build (schema-v10) | 19 | `scripts/build-ebpf.sh` | ebpf-objects | no |
| UC-19-06 | Guest eBPF objects build | 19 | `scripts/build-ebpf-guest.sh` | ebpf-objects | no |
| UC-S12E-01 | Sentinel GA static + unit | 12E | `scripts/test-sentinel-ga-static.sh` | sentinel-python | no |
| UC-S16E-01 | Fleet drift/SLO guard static | 16E | `scripts/test-sentinel-fleet-guard-static.sh` | sentinel-python | no |
| UC-S17E-01 | Release admission static | 17E | `scripts/test-sentinel-release-admission-static.sh` | sentinel-python | no |
| UC-SHELL-01 | NetworkPolicy live scripts syntax | * | `scripts/test-networkpolicy-live.sh` | shell-contracts | no |
| UC-SHELL-02 | Set17/18/19 + GA gate scripts syntax | * | `scripts/secure-containers-ga-gate-set19.sh` | shell-contracts | no |
| UC-SHELL-03 | NP controller RBAC lists EndpointSlices | 18 | `controllers/fluxvm-networkpolicy-controller/deploy/rbac.yaml` | shell-contracts | no |
| UC-MATRIX | Matrix targets resolve on disk | * | `scripts/check-use-case-matrix.sh` | matrix-lint | no |
| UC-S1 | Live CT-bypass + revocation TCP (S1) | 14/16 | `scripts/test-networkpolicy-stateful-set17.sh` | live-stateful | yes |
| UC-S2 | Multi-node + second CNI (S2) | 14 | `scripts/secure-containers-ga-gate-set19.sh` | live-ga | yes |
| UC-S9 | Kata P0/P1 fixtures (S9) | * | `scripts/secure-containers-ga-gate-set19.sh` | live-ga | yes |
| UC-S10 | Real multi-host fleet (S10) | 15E | `scripts/secure-containers-ga-gate-set19.sh` | live-ga | yes |
| UC-S11 | Attached-VM migration (S11) | 13E | `scripts/secure-containers-ga-gate-set19.sh` | live-ga | yes |

See also [NEXT-FEATURES.md](NEXT-FEATURES.md) and [secure-containers-set19.md](secure-containers-set19.md).
