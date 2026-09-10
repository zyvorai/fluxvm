# FluxVM eBPF Set 3 — kernel drop reasons and migration state continuity

Set 3 moves Drop Detective from policy inference to a kernel-owned reason ABI and adds the node-local state contract required for VM migration without immediately breaking established connections.

## Ownership boundary

FluxVM owns VM-local eBPF mechanics: the VM edge, stable VM identity, conntrack, policy branch reasons, quiesce/restore gates, and state import/export. Zyvor Fabric remains the distributed control plane for node selection, leases, routing/BGP, multi-site coordination, and orchestration.

## Dataplane schema v6

Schema v6 adds two maps to each VM's private pin set:

* `fluxvm_drop_reasons` — LRU branch-accounting map keyed by the existing 44-byte flow tuple plus a stable `reason` and `action` field.
* `fluxvm_migration` — per-VM state (`running`, `quiescing`, `restoring`) plus a monotonic local generation.

The original `fluxvm_flows`, policy maps and conntrack key/value ABI stay intact. Existing schema-v5 pins are intentionally considered incompatible and are repaired by the existing attach/reconcile path. Schema v6 also closes an older conntrack fast-path gap: established flows continue to hit the configured Mbps/PPS limiter instead of bypassing QoS after the first accepted packet.

### Stable reason codes

| Code | Name | Meaning |
|---:|---|---|
| 1 | `malformed-l4` | transport header could not be safely parsed |
| 2 | `fragmented-l4` | fragmented IPv4 packet while L4 enforcement is active |
| 3 | `explicit-cidr-deny` | destination matched VM/group deny CIDR |
| 4 | `cidr-miss` | destination missed the effective CIDR allowlist |
| 5 | `l4-miss` | protocol/port missed the effective L4 allowlist |
| 6 | `pod-policy-deny` | Pod-identity policy rejected the peer |
| 7 | `rate-limit` | packet or bandwidth ceiling rejected the packet |
| 8 | `default-deny` | no allow dimension and default action is deny |
| 9 | `migration-quiesce` | source rejects a new flow during quiesce |
| 10 | `migration-restoring` | destination rejects a new flow during restore |
| 11 | `unsupported-ethertype` | non-ARP/non-IP frame rejected by default policy |

`action=drop` means the packet was rejected. `action=audit` means the same branch would have rejected it, but audit mode allowed it. Schema v6 also preserves Pod-policy audit verdicts with a richer internal verdict API while keeping the existing boolean Pod-policy helpers as compatibility wrappers. This fixes the previous ambiguity around rate-limit and audit-only observations.

## Migration contract

The migration sequence is deliberately explicit and fail-closed:

```text
source                              destination
------                              -----------
running
   |
   +-- quiesce
       existing CT: allow
       new flows:   deny (reason 9)
   |
   +-- export CT + optional flow/reason history ---> attach same VM UUID/policy
                                                     mark restoring
                                                     new flows: deny (reason 10)
                                                     import CT/history
                 VMM memory/device cutover -------->
                                                     resume
                                                     new flows: allow by policy
```

Bootstrap traffic remains available: ARP, DHCP, IPv6 NDP and DHCPv6 are not blocked by the migration gate.

The snapshot carries the stable VM UUID-derived FluxVM identity, dataplane schema, and the committed effective-policy fingerprint. Export refuses an uncommitted policy generation, and restore requires the destination fingerprint to exactly match the source before conntrack is imported. This prevents stale established-flow state from bypassing a changed destination policy. Restore also rejects a mismatched VM UUID, identity or schema rather than importing state into the wrong VM.

## REST API

```text
GET  /v1/vms/{id}/network/drop-reasons?limit=256
GET  /v1/vms/{id}/network/migration/state
POST /v1/vms/{id}/network/migration/quiesce
GET  /v1/vms/{id}/network/migration/export
POST /v1/vms/{id}/network/migration/restore
POST /v1/vms/{id}/network/migration/resume
```

All mutation/export operations use the existing admin-role enforcement. Drop reasons and state inspection remain read-only authenticated endpoints.

## CLI

```bash
fluxvm diagnose <uuid>
fluxvm dataplane migration-state <uuid>
fluxvm dataplane migration-quiesce <uuid>
fluxvm dataplane migration-export <uuid> --output /tmp/vm-net.json
fluxvm dataplane migration-restore <uuid> --input /tmp/vm-net.json
fluxvm dataplane migration-resume <uuid>
```

`fluxvm diagnose` automatically prefers schema-v6 kernel reasons and falls back to Set-2 policy inference when running against an older node.

## What is intentionally not transferred

The rate map contains a `bpf_spin_lock` and is not raw-imported. Rate windows restart on the destination. Per-CPU stats are also not imported. Those are local telemetry/rate-window details, not connection correctness. Policy is reconciled from the existing FluxVM control-plane state before restore; the migration snapshot moves connection and diagnostic state, not policy ownership.

## Testing

`test-drop-reason-migration-static.sh` validates source contracts and runs the affected Rust tests/build when Cargo is available. `test-drop-reason-migration-host.sh` is a privileged Linux smoke test that loads the production TC object on a veth, proves an established flow survives quiesce, then proves new flows receive quiesce/restoring kernel reason codes.
