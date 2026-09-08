# Service Fabric phase 2 — archive (shipped)

This page is historical. Dual-stack DSR/SNAT/north-south XDP and the items below
shipped in Service Fabric **v2**, then were carried into **v3**.

**Current docs:** [service-fabric.md](service-fabric.md) · [phase 4](service-fabric-phase4.md)

## Originally planned (now done)

1. **North-south XDP service ingress** — node/physical NIC VIP lookup with the
   same Maglev contract; XDP/TC ownership rules preserved.
2. **DSR** — routed DSR with source-IP preservation (`mode: dsr`).
3. **SNAT** — collision-safe SNAT for non-routable VM sources; symmetric reverse NAT.
4. **IPv6 services** — dual-stack VIPs and backends.
5. **Active health** — landed in **v3** as node-local TCP probes (Fabric still owns durable intent).
6. **Identity-aware service policy** — still open (see phase 4 / Fabric identity work).
7. **EDT bandwidth manager** — still open (phase 4).
8. **Hubble-grade service events** — still open (phase 4).
9. **Local redirect** — still open.
10. **L7 redirect contract** — still open (phase 4).

Items 5–10 that remain open are tracked under [service-fabric-phase4.md](service-fabric-phase4.md)
and Fabric's phase-4 note; do not treat this file as an active backlog.
