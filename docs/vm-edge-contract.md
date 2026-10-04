# Kairon VM-edge contract

Kairon (`kairon-node`) posts a per-VM edge document to FluxVM when a
Machine sets `dataplaneMode: ebpf`, `antiSpoof`, `learnIP`, or `qos`.
FluxVM loads the document into the VM's TC/TCX program
(`fluxvm_tc.bpf.o`) and into qdiscs on the VM's host-side interface.

This page is FluxVM's side of the contract: the routes, the wire format,
what the datapath enforces, how state is kept, and how to inspect and
troubleshoot it. The Kairon side (CRD fields, status, CLI) is in
[kairon docs/ebpf-edge.md](https://github.com/zyvorai/kairon/blob/main/docs/ebpf-edge.md).

## Requirements

| Requirement | Why |
| --- | --- |
| `sandbox.dataplane.mode = "ebpf"` or `"cilium"` | The edge lives in the eBPF VM-edge program. In `legacy` (nftables) mode a spec that enforces anything is rejected with 400. |
| Dataplane schema 12 BPF objects in `/usr/lib/fluxvm/bpf/` | Schema 12 adds the edge maps. An older `fluxvm_tc.bpf.o` has no `fluxvm_edge` map and the apply fails with `schema 12 is required`. |
| `network.mode = "tap"` (bridged or netns) | The program hooks the VM's tap or, for a netns VM, the host end of its veth. `user` networking has no hook. |
| `bpftool`, `tc` and `ip` on the host | FluxVM writes the maps with `bpftool` and installs ingress QoS with `tc`. |
| The current AppArmor profile, where AppArmor is enforcing | See [Host requirements](#host-requirements). |

## Lifecycle

1. Kairon posts the spec on every node-agent tick.
2. FluxVM validates it. If the VM is attached, it writes the BPF maps
   and the qdiscs immediately. Then it persists the spec.
3. On every later attach (VM start, restart, FluxVM restart, a dataplane
   repair, a network-policy update), the persisted spec is written into
   the fresh maps, ingress QoS is reinstalled, and a pending conntrack
   restore is applied.
4. Deleting the VM deletes the persisted state.

A spec posted before the VM attaches is not lost: it is stored and
applied on attach.

## Routes

| Route | Role | Body | Response |
| --- | --- | --- | --- |
| `POST /v1/vms/{id}/network/edge` | admin | `EdgeSpec` | the stored spec |
| `GET /v1/vms/{id}/network/conntrack` | admin | — | `ConntrackSnapshot` from the live table |
| `POST /v1/vms/{id}/network/conntrack` | admin | `ConntrackSnapshot` | the accepted snapshot |
| `GET /v1/vms/{id}/network/learned-ip` | read | — | `{"ip": "...", "source": "..."}` |
| `GET /v1/vms/{id}/network/drops?limit=N` | read | — | `{"items": [DropEvent]}` |
| `POST /v1/vms/{id}/network/capture` | admin | `CaptureSession` | the session, `state: running` |
| `GET /v1/vms/{id}/network/capture` | admin | — | `{"items": [CaptureSession]}` |
| `GET /v1/vms/{id}/network/capture/{token}` | admin | — | the pcap file |

Every route returns 400 `VM not found` for an unknown VM, and 400 with
the reason for a spec or snapshot that fails validation.

### Field names

FluxVM uses Kairon's JSON names exactly, including the upper-case
acronyms: `learnIP`, `assignedMAC`, `assignedIP`, `allowSNI`,
`allowDNS`, `srcIP`, `dstIP`. Other fields are camelCase (`antiSpoof`,
`policyName`, `allowCidrs`, `allowIcmp`, `exportedAt`). serde matches
names case-sensitively, so a misspelled field is silently defaulted.

### `POST /network/edge`

```json
{
  "namespace": "default",
  "machine": "web",
  "identity": 1606429,
  "antiSpoof": true,
  "learnIP": true,
  "assignedMAC": "52:54:00:ed:9e:01",
  "assignedIP": "169.254.0.19",
  "policyName": "web-egress",
  "defaultAllow": true,
  "allowSNI": ["*.example.com"],
  "allowDNS": ["*.example.com", "allowed.test"],
  "qos": {"ingressMbps": 100, "egressMbps": 50, "ingressPps": 20000, "egressPps": 2000}
}
```

| Field | Required | Effect in FluxVM |
| --- | --- | --- |
| `namespace`, `machine` | yes | Labels on drop events. |
| `identity` | yes, non-zero | Kairon's stable Machine identity. Checked against conntrack restores and returned by export. |
| `antiSpoof` | no | Drops guest frames with a foreign source MAC, ARP sender or IP. |
| `learnIP` | no | Records the guest address from ARP and IPv6 neighbor advertisements. |
| `assignedMAC` | no | The MAC anti-spoof expects. `aa:bb:cc:dd:ee:ff` or `aa-bb-…`. |
| `assignedIP` | no | The IPv4 or IPv6 address anti-spoof expects. Empty means "use the learned address". |
| `allowSNI` | no | TLS SNI allow list. Empty means no SNI check. |
| `allowDNS` | no | DNS query-name allow list. Empty means no DNS check. |
| `qos` | no | Rate limits. Zero or absent means no limit in that direction. |
| `policyName` | no | Copied onto drop events. |
| `defaultAllow`, `allowCidrs`, `denyCidrs`, `allowPorts`, `allowIcmp` | no | Stored only. CIDR and port policy is enforced by the VM network policy (`POST /network/policy`), which Kairon posts separately. |

A spec with none of `antiSpoof`, `learnIP`, `allowSNI`, `allowDNS` or
`qos` removes the edge from the datapath; the VM keeps its network
policy.

Validation rejects: an empty `namespace` or `machine`, a zero
`identity`, a malformed `assignedMAC` or `assignedIP`, an allow-list
name that is empty, longer than 128 bytes, or not a DNS name or
`*.suffix`, and an `egressMbps` too large to express in bytes per
second.

### `GET` / `POST /network/conntrack`

```json
{
  "identity": 1606429,
  "generation": 1791102712345678901,
  "exportedAt": "2026-10-04T00:58:32Z",
  "entries": [
    {"proto": "tcp", "srcIP": "169.254.0.19", "dstIP": "93.184.215.14",
     "srcPort": 41234, "dstPort": 443, "state": "established"}
  ]
}
```

Export dumps the VM's live `fluxvm_ct` table. `identity` is the edge
spec's identity, or FluxVM's own VM identity when no spec was posted.
`generation` is the export time in nanoseconds; `exportedAt` is RFC 3339
UTC, which Kairon decodes as `time.Time`. A VM that is not attached
exports an empty `entries` list instead of failing, so a live migration
proceeds without conntrack rather than aborting.

Restore requires a non-zero `identity` and a non-empty `exportedAt`. If
the VM has an edge spec, the snapshot identity must equal the spec's
identity; otherwise the restore fails with `conntrack identity X does
not match machine identity Y`. Each entry is rewritten to this VM's
datapath identity and stamped with this host's monotonic clock, so a
restored flow gets a full idle timeout on the destination. If the VM is
not attached yet, the snapshot is persisted as pending and written into
the table on attach.

`seq` and `ack` are accepted but not used: the datapath tracks flows,
not TCP sequence state.

### `GET /network/learned-ip`

```json
{"ip": "192.168.122.212", "source": "arp"}
```

| `source` | Meaning |
| --- | --- |
| `arp` | Learned from a guest ARP packet on the tap. |
| `nd` | Learned from a guest IPv6 neighbor advertisement. |
| `dhcp` | Nothing learned; this is the address in FluxVM's DHCP lease. |
| `fluxvm` | Nothing learned; this is the VM's configured address. |
| empty | Nothing is known. |

### `GET /network/drops`

```json
{"items": [
  {"namespace": "default", "machine": "web", "reason": "dns_deny",
   "policyName": "web-egress", "srcIP": "169.254.0.19", "dstIP": "169.254.0.18",
   "proto": "udp", "dstPort": 53, "direction": "egress", "action": "drop",
   "packets": 4},
  {"namespace": "default", "machine": "web", "reason": "rate_limit",
   "policyName": "web-egress", "srcIP": "", "dstIP": "",
   "direction": "ingress", "action": "drop", "packets": 112}
]}
```

There is one event per distinct reason and flow, carrying the packet
count and the addresses of that flow. Events are sorted by packet count
and capped at `limit` (default 100, maximum 4096). Ingress rate-limit
drops come from qdisc statistics, so they have no addresses. A VM that
is not attached returns an empty list.

Kernel reason codes map to Kairon's names:

| Code | Kernel label | Kairon `reason` |
| ---: | --- | --- |
| 3, 4, 5, 6, 12 | `explicit-cidr-deny`, `cidr-miss`, `l4-miss`, `pod-policy-deny`, `udp-deny` | `policy_deny` |
| 7 | `rate-limit` | `rate_limit` |
| 8 | `default-deny` | `default_deny` |
| 13 | `spoof-mac` | `spoof_mac` |
| 14 | `spoof-ip` | `spoof_ip` |
| 15 | `dns-deny` | `dns_deny` |
| 16 | `sni-deny` | `sni_deny` |
| 1, 2, 11 | `malformed-l4`, `fragmented-l4`, `unsupported-ethertype` | `malformed` |
| 9, 10 | `migration-quiesce`, `migration-restoring` | `migration` |

`action` is `drop`, or `audit` when the VM policy is in audit mode and
the packet was let through.

### `POST /network/capture`

```json
{"token": "c0ffee…", "namespace": "default", "machine": "web",
 "seconds": 15, "filter": "tcp port 443", "expiresAt": "2026-10-04T01:00:00Z"}
```

FluxVM runs `tcpdump` on the VM's recorded dataplane interface (the
`vh<8hex>` veth for a netns VM, the tap otherwise), inside the VM's
network namespace, and writes a pcap under
`<state_dir>/network-edge/captures/<uuid>/<token>.pcap`. The capture
stops after `seconds` (SIGINT, then a kill after 5 s), or at 20,000
packets. Frames are cut at 1,600 bytes.

| Rule | Value |
| --- | --- |
| `seconds` | 1-30 |
| `token` | 1-128 characters from `[A-Za-z0-9_-]` (it names the file) |
| `filter` | a tcpdump expression, at most 512 bytes, no control characters; passed as one argument after `--` |
| Concurrency | one running capture per VM; a second request returns 400 |
| VM state | must be attached to the eBPF dataplane |
| Kept | the newest 16 sessions per VM; older pcaps are deleted |

A bad filter, or a host without `tcpdump`, fails the `POST` with 400 and
tcpdump's message, because FluxVM checks that tcpdump is still running
300 ms after it starts.

Each session carries `state`, `startedUnix`, `packets` and `error`:

| `state` | Meaning |
| --- | --- |
| `running` | tcpdump is running. |
| `done` | Finished; `packets` is tcpdump's count. |
| `failed` | tcpdump exited with an error; see `error`. |
| `interrupted` | Still marked running 30 s after it should have ended, usually because FluxVM restarted mid-capture. |

`GET /network/capture/{token}` returns the file as
`application/vnd.tcpdump.pcap` with a `Content-Disposition` filename,
409 `capture is still running` while tcpdump runs, and 404 for an
unknown token or a capture that wrote no file.

```bash
curl -s -X POST localhost:7788/v1/vms/$ID/network/capture \
  -H 'content-type: application/json' \
  -d '{"token":"dns1","namespace":"default","machine":"web","seconds":10,"filter":"udp port 53","expiresAt":"2026-10-04T01:00:00Z"}'
sleep 11
curl -s localhost:7788/v1/vms/$ID/network/capture | jq '.items[] | {token,state,packets}'
curl -s -o dns.pcap localhost:7788/v1/vms/$ID/network/capture/dns1
tcpdump -nr dns.pcap
```

## Enforcement

All guest-side checks run in the VM's TC/TCX program on frames leaving
the guest. Anti-spoof, learning and the egress token bucket run first,
before the VM network policy, and always drop. The DNS and SNI checks
run inside the policy pass, after the CIDR and port checks; when the VM
policy is in audit mode they record an `audit` event and let the packet
through. The maps are pinned per VM under
`/sys/fs/bpf/fluxvm/vms/<uuid-without-dashes>/maps`.

| Spec field | Datapath | Drop reason |
| --- | --- | --- |
| `antiSpoof` + `assignedMAC` | Source MAC and ARP sender MAC must equal `assignedMAC`. | `spoof_mac` |
| `antiSpoof` + `assignedIP` | IPv4 source, ARP sender IP, or IPv6 source must equal `assignedIP`. | `spoof_ip` |
| `learnIP` | `fluxvm_learn` records the guest address. | — |
| `allowDNS` | Queries to port 53 (UDP and TCP) must ask for an allowed name. | `dns_deny` |
| `allowSNI` | TLS ClientHello to TCP 443 must carry an allowed SNI. | `sni_deny` |
| `qos.egressMbps`, `qos.egressPps` | Token bucket per VM, one second of burst. | `rate_limit` |
| `qos.ingressMbps` | `tbf` root qdisc on the host interface. | `rate_limit` (ingress) |
| `qos.ingressPps` | `matchall` police on the host interface's egress hook. | `rate_limit` (ingress) |

### Anti-spoof and learn-IP

- With `assignedIP` set, only that address is accepted as a source.
  IPv6 link-local sources (`fe80::/10`) and the unspecified address used
  by duplicate-address detection are always accepted.
- With `assignedIP` empty and `learnIP` on, the first address the guest
  announces is learned and pinned: later packets from another address
  drop as `spoof_ip`. The learned entry is cleared when `learnIP` is
  turned off.
- With neither, only the MAC is checked.
- A DHCP request (UDP from `0.0.0.0` port 68 to port 67) is always let
  through, so a guest can obtain its lease before it has an address.

Kairon fills `assignedIP` from the Machine's guest IP. If the guest
moves to a new address (a DHCP re-lease on another subnet, a manually
configured address), its traffic drops as `spoof_ip` until Kairon posts
the new address on its next tick.

### DNS and SNI allow lists

| Entry | Matches |
| --- | --- |
| `example.com` | exactly `example.com` |
| `*.example.com` | `a.example.com`, `a.b.example.com`; not `example.com` |

Names are compared case-insensitively, the trailing dot is ignored, and
names up to 128 bytes are supported. List both `example.com` and
`*.example.com` to allow the apex and its subdomains.

- DNS: the first question of each query (QR=0) is checked, over UDP and
  over TCP. Responses, and queries to resolvers on other ports, are not
  inspected.
- SNI: the ClientHello must fit in one TCP segment. A ClientHello with
  no `server_name`, or one split across segments, is denied while an SNI
  list is set. Non-TLS traffic to port 443 is let through.
- Not covered: DNS over HTTPS or TLS, QUIC (UDP 443), TLS on ports other
  than 443, and Encrypted Client Hello. Pair the allow lists with a VM
  network policy that restricts ports and resolvers if those paths must
  be closed.

### QoS

- Egress (guest to host) is a token bucket in the TC program with one
  second of burst, for bytes and packets independently.
- Ingress bandwidth replaces the root qdisc of the VM's host-side
  interface with `tbf rate <N>mbit burst max(rate/50, 64KiB) latency
  50ms`. Any other root qdisc on that interface is replaced.
- Ingress packet rate is a `matchall` filter at pref 49150, handle
  0x10, on the clsact egress hook, with `police pkts_rate N pkts_burst N
  conform-exceed drop/pipe`.
- Removing a limit from the spec removes the matching qdisc or filter.

### Routed (netns) VMs

A VM on a per-VM network namespace (`network.netns = true`) is hooked
on the host veth `vh<first 8 hex of the UUID>`, behind the namespace's
router:

- every frame on the hook carries the namespace router's MAC, not the
  guest's;
- the namespace answers ARP itself;
- dnsmasq in the namespace forwards the guest's DNS from the router's
  own address (the host veth address plus one).

FluxVM detects this hook and sets the routed flag. On a routed hook:

| Check | Applies |
| --- | --- |
| MAC anti-spoof, ARP checks, ARP learning | no |
| IP anti-spoof | yes; the router address is also accepted as a source |
| DNS and SNI allow lists | yes; DNS forwarded by dnsmasq is checked |
| Egress and ingress QoS | yes |
| IPv6 learning from neighbor advertisements | yes |

Use a bridged tap (`network.netns = false`, `network.bridge = …`) when
MAC anti-spoof or ARP learning is required.

## BPF ABI (dataplane schema 12)

| Map | Key | Value |
| --- | --- | --- |
| `fluxvm_edge` | ifindex (`u32`) | `struct edge_config`, 56 bytes |
| `fluxvm_edge_rate` | ifindex | token-bucket state |
| `fluxvm_learn` | ifindex | `struct edge_learned`, 40 bytes |
| `fluxvm_names` | `{identity u32, kind u32, hash u64}` | `u32` flags: 1 exact, 2 suffix |

`struct edge_config`:

| Offset | Field | Notes |
| ---: | --- | --- |
| 0 | `flags` (`u32`) | 1 anti-spoof, 2 learn-IP, 4 SNI, 8 DNS, 16 routed |
| 4 | `ip4` | assigned IPv4, network order; 0 if none |
| 8 | `mac[6]` + 2 pad | assigned MAC; zero if none |
| 16 | `ip6[16]` | assigned IPv6; zero if none |
| 32 | `egress_bytes_per_sec` (`u64`) | 0 = no byte limit |
| 40 | `egress_packets_per_sec` (`u64`) | 0 = no packet limit |
| 48 | `router_ip4` + 4 pad | routed hooks only |

Name `kind` is 1 for SNI and 2 for DNS. `hash` is 64-bit FNV-1a over the
lower-cased name read right to left, which lets the program test a
suffix entry at every `.` while it walks the name once.

## Persistence

`<state_dir>/network-edge/<uuid>.json` (default
`/var/lib/fluxvm/network-edge/`) holds:

```json
{
  "edge": { "...": "the last accepted EdgeSpec" },
  "pendingConntrack": null,
  "captures": []
}
```

The file is written atomically (temporary file and rename) under a
process-wide lock. It is read on every attach and deleted with the VM,
together with the `captures/<uuid>/` pcap directory.
The live datapath is the source of truth for learned addresses, drop
counters and conntrack; those are not copied into the file.

## Host requirements

FluxVM shells out to `bpftool`, `tc`, `ip`, `nsenter`, `tcpdump` (capture only) and
`/usr/libexec/fluxvm/fluxvm-tcx`.
Under AppArmor, the `fluxvm` and `fluxctl` profiles in
`deploy/apparmor/fluxvm` must allow them, along with `/sys/fs/bpf`,
`/usr/lib/fluxvm/bpf` and the `bpf`, `perfmon`, `net_admin`, `net_raw`
and `sys_module` capabilities, and `network packet raw` for tcpdump. An older profile denies `bpftool`, and then no
VM attaches to the eBPF dataplane at all (`network/status` shows
`attached: false`). Reload after upgrading:

```bash
sudo install -m 0644 deploy/apparmor/fluxvm /etc/apparmor.d/fluxvm
sudo apparmor_parser -r /etc/apparmor.d/fluxvm
sudo systemctl restart fluxvm
```

## Inspecting a VM

```bash
ID=e94c7e6f-7ab2-492b-9316-293fcd5b8c94
MAPS=/sys/fs/bpf/fluxvm/vms/$(echo $ID | tr -d -)/maps

# Is the VM attached, on which interface, which schema?
curl -s localhost:7788/v1/vms/$ID/network/status

# The loaded edge config, allow-list entries and learned address
sudo bpftool map dump pinned $MAPS/fluxvm_edge
sudo bpftool map dump pinned $MAPS/fluxvm_names
sudo bpftool map dump pinned $MAPS/fluxvm_learn

# Ingress QoS on the host interface (vh<8hex> for netns VMs, the tap otherwise)
sudo tc -s qdisc show dev vhe94c7e6f
sudo tc -s filter show dev vhe94c7e6f egress

# What was persisted
sudo cat /var/lib/fluxvm/network-edge/$ID.json
```

A netns VM's namespace lives in FluxVM's private mount namespace, so
`ip netns exec` does not find it. Enter it through the QEMU process
instead: `sudo nsenter --net=/proc/<qemu pid>/ns/net ip addr`.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `POST /network/edge` returns `requires sandbox.dataplane.mode=ebpf or cilium` | FluxVM is in `legacy` mode. | Set `[sandbox.dataplane] mode = "ebpf"` and restart. |
| `schema 12 is required` | Old BPF objects. | Rebuild with `scripts/build-ebpf.sh` and install to `/usr/lib/fluxvm/bpf/`. |
| `network/status` shows `attached: false` for every VM | AppArmor denies `bpftool`; check `journalctl -k \| grep apparmor`. | Install and reload the current profile. |
| Guest traffic drops as `spoof_ip` after an address change | `assignedIP` is stale. | Wait for Kairon's next tick, or post the new address. |
| `spoof_mac` drops on a netns VM | Not possible: MAC checks are off on routed hooks. Check that the hook is `vh…`. | — |
| Allowed name still denied | Apex not listed, or ClientHello split across segments. | Add the exact name; check the client's TLS record size. |
| Capture `POST` returns 400 `spawn tcpdump` or exits at once | tcpdump missing, or AppArmor denies it (`operation="bind" family="packet"`). | Install tcpdump; reload the current profile. |
| Capture `POST` returns 400 `a capture is already running` | One capture per VM. | Wait for it to finish. |
| Drops list is empty | VM not attached, or nothing dropped yet. | Check `network/status`. |
| Conntrack restore rejected with an identity mismatch | The snapshot came from another Machine. | Expected: restores fail closed. |

## Testing

| Test | What it covers |
| --- | --- |
| `cargo test -p fluxvm-network --lib` | Spec validation, map encoding, name hashing, conntrack round trip, learned-address parsing, QoS statistics, persistence, capture validation, tcpdump arguments and capture states. |
| `scripts/test-vm-edge-verdict.py` | Loads the real `fluxvm_tc.bpf.o` with `BPF_PROG_TEST_RUN` and checks every verdict: MAC and IP spoofing, ARP, learning, DNS and SNI allow and deny, the token bucket, and the routed flag. Needs root and `FLUXVM_BPF_DIR`. Runs in the `network-fabric` workflow. |
| `scripts/test-drop-reason-migration-static.sh` | Checks the schema number and drop-reason contract. |

## Current limits

- On a netns VM, the namespace bridges the tap and the guest uses the
  same MAC, so the guest may report IPv6 duplicate-address detection
  failures. IPv4 is unaffected.
- On a routed hook, learned-IP usually falls back to the DHCP lease,
  because ARP learning is off.
- The ingress packet-rate police runs on the TC filter chain. A TCX
  Pod-ingress program on the same hook that returns pass skips it;
  ingress bandwidth (`tbf`) is unaffected.
- CIDR and port fields in the edge spec are not enforced from the spec;
  they are enforced through the VM network policy.
