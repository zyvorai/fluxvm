# Kairon VM-edge contract

Kairon (`kairon-node`) posts a per-VM edge document to FluxVM when a
Machine sets `dataplaneMode: ebpf`, `antiSpoof`, `learnIP`, or `qos`.
FluxVM loads it into the VM's TC/TCX program (`fluxvm_tc.bpf.o`) and
the host interface's qdiscs. It requires the eBPF dataplane
(`network.dataplane.mode: ebpf` or `cilium`); in `legacy` mode a spec
that enforces anything is rejected.

The Kairon side is documented in
[kairon docs/ebpf-edge.md](https://github.com/zyvorai/kairon/blob/main/docs/ebpf-edge.md).

## Routes

| Route | Body / response |
| --- | --- |
| `POST /v1/vms/{id}/network/edge` | `EdgeSpec`; echoes the stored spec |
| `GET /v1/vms/{id}/network/conntrack` | `ConntrackSnapshot` from the live `fluxvm_ct` map; empty `entries` when the VM is not attached |
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

## Enforcement

The spec is written to the per-VM pinned maps under
`/sys/fs/bpf/fluxvm/vms/<uuid>/maps` (dataplane schema 12):

| Spec field | Datapath |
| --- | --- |
| `antiSpoof` + `assignedMAC` / `assignedIP` | `fluxvm_edge`: guest frames with another source MAC, ARP sender or IPv4/IPv6 source drop as `spoof_mac` / `spoof_ip` |
| `learnIP` | `fluxvm_learn`: guest ARP and IPv6 neighbor advertisements record the address; with anti-spoof and no `assignedIP`, the first learned address is pinned |
| `allowDNS` | `fluxvm_names`: DNS queries (UDP and TCP port 53) for other names drop as `dns_deny` |
| `allowSNI` | `fluxvm_names`: TLS ClientHello on TCP 443 with another SNI drops as `sni_deny` |
| `qos.egressMbps` / `egressPps` | token bucket in `fluxvm_edge`; excess guest packets drop as `rate_limit` |
| `qos.ingressMbps` / `ingressPps` | `tbf` root qdisc and a `matchall` police on the host interface |

Names match exactly, or by suffix when written `*.example.com`
(which matches subdomains, not `example.com` itself). Names are
lower-cased and the trailing dot is stripped. A posted spec takes effect
immediately when the VM is attached, and is reapplied on every attach.

### Routed (netns) VMs

A VM on a per-VM network namespace is hooked on the host veth
(`vh<8hex>`), behind the namespace's router. FluxVM sets the routed flag
on that hook: MAC and ARP checks are skipped (every frame carries the
router's MAC) and the router's address is accepted as a source (it
forwards the guest's DNS). IP anti-spoof, DNS/SNI allow lists and QoS
still apply. MAC anti-spoof and ARP learning only work on a bridged tap.

## Drops

`drops` reads the per-VM `fluxvm_drop_reasons` counters and returns the
most recent event per reason, with the packet count, 5-tuple and
direction. Ingress QoS drops come from the qdisc statistics. Reasons map
to Kairon's names: `spoof_mac`, `spoof_ip`, `dns_deny`, `sni_deny`,
`rate_limit`, `policy_deny`, `default_deny`, `malformed`, `migration`.

## Conntrack

Export dumps `fluxvm_ct` with the identity from the spec (or the VM's
policy identity). Restore rewrites each entry to the destination
identity and refreshes `last_seen`. A restore that arrives before the
VM attaches is kept and applied on attach.

## Persistence

The spec, a pending conntrack restore and capture sessions are stored
in `<state_dir>/network-edge/<uuid>.json` and survive a FluxVM restart.
Deleting the VM removes the file.

## Fail-closed rules

- Conntrack restore requires a non-zero `identity` and an `exportedAt`.
  If an edge spec is applied, its identity must match the snapshot.
- An invalid `assignedMAC` / `assignedIP` or a name over 128 bytes is
  rejected.
- Capture rejects `seconds` outside 1-30 and an empty `token`.

## Host requirements

FluxVM shells out to `bpftool`, `tc` and `fluxvm-tcx`. Under AppArmor
the `fluxvm` profile in `deploy/apparmor/fluxvm` must allow them; an
older profile denies `bpftool` and no VM can attach.

## Current limits

- On a netns VM the namespace bridges the tap and the guest uses the
  same MAC, so the guest may report IPv6 duplicate-address detection
  failures. IPv4 is unaffected.
- `learned-ip` falls back to the DHCP lease (`dhcp`) or the configured
  guest address (`fluxvm`) when nothing was learned; on a routed hook
  that is the usual source.
- Ingress `ingressPps` is enforced by a police action on the host
  interface's egress; a Pod-policy TCX program that returns pass skips
  it.
