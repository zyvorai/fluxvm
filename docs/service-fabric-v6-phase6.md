# Service Fabric Phase 6 — implemented

This merge kit implements the next additive control/state-plane tranche on top of merged v5:

1. Identity-aware service policy compiled from FluxVM's existing ipcache.
2. Default allow/deny, explicit allow/deny identities and audit-only mode.
3. Envoy HTTP/gRPC transparent redirect contract with TC as the redirect owner.
4. XDP handoff (`XDP_PASS`) for L7-enforced services.
5. Bypass-mark consumption in TC to prevent redirect loops.
6. Distributed Fabric policy fanout with previous-state snapshot and rollback.
7. BPF queue assisted HA mutation events for forward conntrack/NAT creates.
8. Direct userspace `bpf(BPF_MAP_LOOKUP_AND_DELETE_ELEM)` queue drain with cross-service dispatch into the owning journal.
9. Existing v5 snapshot-diff journal retained as the correctness backstop.
10. Separate program generation 6 while preserving BPF service schema 4, with fail-closed policy restore during reload.

Ownership remains unchanged: FluxVM owns node-local packet/runtime mechanics; Fabric owns distributed service/policy/HA/routing intent; Envoy owns application parsing.
