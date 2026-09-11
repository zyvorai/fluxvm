# Secure Containers Set 19 — GA completion candidate

Set 19 folds Set 18 into current main and closes the remaining **code-side** high-priority Secure Containers gaps S4–S8. It does **not** turn missing lab evidence into a release claim.

- **S4 — EndpointSlice Service VIP:** already merged upstream as Set 18 / PR #51; ClusterIP permission follows actual EndpointSlice backends, readiness/drain state, Pod identity and address family. The vendored Set 18 handoff remains only for reproducibility.
- **S5 — Rich-rule index:** a direction/family/protocol bitmap narrows the existing 64-slot `fluxvm_prules` scan. The existing rule map remains the source of truth and Set 17 rule-index attribution is preserved.
- **S6 — IPv6 extension headers:** a verifier-bounded six-header walk handles Hop-by-Hop, Routing, Destination Options, Fragment and AH; ESP/No-Next stop without unsafe L4 parsing. Final protocol is used for policy/conntrack/telemetry, SCTP works behind supported extension headers, and fragments are not learned into conntrack.
- **S7 — Guest mirror:** Set 14 Pod policy is fetched at container create and refreshed every two seconds. The in-guest cgroup policy mirrors **direction + CIDR**. Host TC remains authoritative for protocol/port, so the guest is defense in depth rather than a replacement for the richer host rule. Clearing a Pod policy becomes an explicit unisolated guest policy; fetch failures remain fail-closed at create.
- **S8 — Observer operations:** observer schema recognition moves with dataplane v10, Prometheus Operator `ServiceMonitor` example is supplied, and a deterministic sizing model is included. Real RSS/scrape latency still belongs in the target-host evidence bundle.

## What still blocks the words “production GA”

The final runner deliberately fails unless real-environment evidence is supplied for S1/S2/S9/S10/S11: stateful TCP/revocation, multi-node plus a second CNI, Kata-equivalence fixtures, a real multi-host fleet rollout/rollback, and migration against a live attached VM. It also reuses the repository's existing Sentinel Set 12E certification gates rather than defining a competing certification process.

Portable use-case → test → CI mapping:
[secure-containers-use-case-matrix.md](secure-containers-use-case-matrix.md).
Live gates are opt-in (`FLUXVM_SECURE_CONTAINERS_LIVE_CI=1`).
