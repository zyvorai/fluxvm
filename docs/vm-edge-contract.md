# Kairon VM-edge contract

Kairon (`kairon-node`) posts a per-VM edge document to FluxVM when a
Machine sets `dataplaneMode: ebpf`, `antiSpoof`, `learnIP`, or `qos`.
These routes are the userspace side of that contract. The BPF programs
(`fluxvm_tc.bpf.o`, `fluxvm_direct.bpf.o`) are unchanged.

The Kairon side is documented in
[kairon docs/ebpf-edge.md](https://github.com/zyvorai/kairon/blob/main/docs/ebpf-edge.md).

## Routes

| Route | Body / response |
| --- | --- |
| `POST /v1/vms/{id}/network/edge` | `EdgeSpec`; echoes the stored spec |
| `GET /v1/vms/{id}/network/conntrack` | `ConntrackSnapshot`; 400 when none is stored |
| `POST /v1/vms/{id}/network/conntrack` | `ConntrackSnapshot`; 400 on identity mismatch |
| `GET /v1/vms/{id}/network/learned-ip` | `{"ip": "...", "source": "..."}`; empty when nothing is known |
| `GET /v1/vms/{id}/network/drops?limit=N` | `{"items": [DropEvent]}` |
| `POST /v1/vms/{id}/network/capture` | `CaptureSession`; `seconds` must be 1-30 |

`edge`, `conntrack` and `capture` require the admin role. All routes
return 400 `VM not found` for an unknown VM.

## Field names

FluxVM uses Kairon's JSON names exactly, including the upper-case
acronyms: `learnIP`, `assignedMAC`, `assignedIP`, `allowSNI`,
`allowDNS`, `srcIP`, `dstIP`. Other fields are camelCase (`antiSpoof`,
`policyName`, `allowCidrs`, `allowIcmp`, `exportedAt`). serde matches
names case-sensitively, so a misspelled field is silently defaulted.

## Fail-closed rules

- Conntrack restore requires a non-zero `identity` and an `exportedAt`.
  If an edge spec is applied, its identity must match the snapshot.
- Capture rejects `seconds` outside 1-30 and an empty `token`.

## Current limits

- State is in memory. A FluxVM restart drops every edge spec, conntrack
  snapshot, learned IP and capture session; Kairon re-posts the edge on
  its next tick, but a stored conntrack snapshot is lost.
- The edge spec is stored, not yet loaded into the BPF maps, so
  anti-spoof, SNI/DNS allow lists and QoS are not enforced.
- `drops` is derived from the stored spec (`spoof_mac` when anti-spoof
  is on, `sni_deny` when an SNI list is set), not read from the
  datapath. Treat it as a placeholder.
- `learned-ip` only echoes `assignedIP` (source `agent`) when the edge
  spec sets `learnIP`. Nothing observes ARP, DHCP or ND on the tap yet.
- `conntrack` export returns 400 for a VM that has not received a
  restore. Kairon logs a warning and migrates without it.
