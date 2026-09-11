# Secure Containers Set 17 — rule-attributed policy telemetry

<!-- FLUXVM_SECURE_CONTAINERS_SET17 -->

Set 17 closes the highest-value observability gap left after Set 15 without
changing the schema-v8 NetworkPolicy wire ABI.

## What changes

`bpf/fluxvm_pod_policy.bpf.h` gains an optional per-CPU hash map named
`fluxvm_prhit`. Each key records the Pod id, rich-rule slot, direction, and
verdict. A rule slot `0xffffffff` is the explicit no-rule/default-deny or
no-rule/audit sentinel. Values are packet counters.

The existing `fluxvm_ppstat` map remains unchanged for compatibility. On a
new object, Policy Observer prefers `fluxvm_prhit` and therefore exports true
per-direction allow/drop/audit counters. On an older schema-v8 object where
that map is absent, it continues to expose Set 15's shared-counter fallback.

Policy updates clear `fluxvm_prhit` before publishing a new rule set. That is
important because `fluxvm_prules` slots are positional: a new rule may reuse
slot 3, and it must never inherit slot 3's historical hit count from the
previous policy generation.

## New metrics

- `fluxvm_sentinel_policy_directional_counters` — 1 when the VM has Set 17's
  exact directional map, 0 when the observer is using the older shared
  fallback.
- `fluxvm_sentinel_policy_rule_packets_total` — packets by VM, Pod, direction,
  rule index (or `miss`) and verdict.
- `fluxvm_sentinel_policy_rule_info` — current identity of each hit rule:
  family, protocol, CIDR and inclusive port range.

The existing `fluxvm_sentinel_policy_packets_total` metric is preserved. Its
per-direction values become exact when `fluxvm_prhit` is available.

## Stateful proof / multi-node starter

`scripts/test-networkpolicy-stateful-set17.sh` uses real RuntimeClass `fluxvm`
Pods. It first proves both HTTP listeners work, then installs:

- client ingress deny-all;
- client egress allow only server TCP/8080;
- server ingress allow only client TCP/8080;
- server egress deny-all.

A client HTTP request must still receive `set17-ok`. The response can only
succeed if the guest-initiated flow's return traffic bypasses client ingress
isolation and the ingress-accepted request's response bypasses server egress
isolation through the shared FluxVM conntrack state. A new server->client
connection is then required to fail as a control.

When at least two Ready schedulable nodes exist, the script pins the client
and server to different nodes automatically. `REQUIRE_MULTI_NODE=1` converts
that behavior into a mandatory cross-node conformance gate.

## Compatibility

This Set is additive to dataplane schema v8. It intentionally does **not**
bump `DATAPLANE_SCHEMA_VERSION`, change `fluxvm_pspol`, `fluxvm_prules`, or
`PodNetworkPolicy`, or alter controller wire JSON. Main and ingress objects
must simply be rebuilt together so the separate ingress object can reuse the
new pinned `fluxvm_prhit` map.

## Production gates

The portable release verifies the patch contracts, ABI layout, telemetry
parser model, Go formatting, shell syntax and workflow YAML. The merge host
must still run the real Rust workspace, eBPF build/verifier, Policy Observer
Go tests/race/vet, and the live RuntimeClass test above. A two-node run is the
preferred production evidence.
