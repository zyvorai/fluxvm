# Secure Containers Set 14 — NetworkPolicy v2

## Purpose

Set 13 supplied the Sentinel node-local Kubernetes NetworkPolicy controller.
A subsequent exact-peer+TCP/UDP-port extension, and later a first pass at
Pod-ingress/CIDR/`endPort`/named-port support, both landed directly on
`main`. This Set replaces that ingress/CIDR/range/named-port design with an
independently-developed, more complete one: a single versioned directional
tuple rule model, real `ipBlock.except` CIDR subtraction, SCTP support, and a
separate Pod-ingress program that shares the main program's conntrack table
for a stateful return-traffic fast path. The two designs solved the same gap
in incompatible ways; this document describes the one that shipped.

## Pod policy schema v2

```json
{
  "schema_version": 2,
  "default_deny": true,
  "audit_mode": false,
  "egress_isolated": true,
  "ingress_isolated": true,
  "rules": [
    {
      "direction": "egress",
      "cidr": "203.0.113.0/24",
      "protocol": "TCP",
      "port_start": 443,
      "port_end": 443
    }
  ]
}
```

`rules` are a union. Within one rule, direction + peer CIDR + protocol + port
interval are intersected. `protocol=""` and ports `0..0` mean all L4 traffic.
A protocol with ports `0..0` means every port for that protocol.

Legacy fields (`allow_addresses`, `deny_addresses`, `allow_port_rules`,
`default_deny`) remain readable in FluxVM. A schema-v2 controller sets the
legacy `default_deny` bit when either direction is isolated, so a downgrade to
an older dataplane fails strict rather than silently bypassing an ingress-only
policy.

## Kubernetes lowering

### Policy selection

Every `networking.k8s.io/v1` NetworkPolicy in the target Pod namespace whose
`podSelector` matches the target contributes to the union. `policyTypes`
defaulting follows Kubernetes semantics: when omitted, Ingress is implied and
Egress is also implied if an egress rule exists.

### Peers

- `podSelector`: current non-terminal Pod IPs in the policy namespace.
- `namespaceSelector`: current non-terminal Pod IPs in matching namespaces.
- combined namespace + Pod selector: intersection.
- empty peer `{}`: `0.0.0.0/0` and `::/0`.
- `ipBlock`: kept as a native CIDR.
- `ipBlock.except`: recursively subtracted into exact disjoint CIDRs.

The optional Service ClusterIP mode remains conservative: a selector-backed
Service VIP is included only when all currently selected active backends are
already in the allowed Pod peer set.

### Ports

- TCP, UDP and SCTP are accepted.
- a numeric port is represented exactly.
- `endPort` is an inclusive range and requires a numeric start port.
- omitted `port` with a protocol means all ports of that protocol.
- named ingress ports resolve against the selected target Pod's declared
  container ports.
- named egress ports resolve independently for every selected destination Pod;
  the numeric port discovered on one Pod is never applied to another Pod's IP.

A named egress port with unrestricted or `ipBlock` destinations has no finite
Pod set from which the name can be resolved and therefore contributes no allow
rule. This is intentionally stricter than widening the rule.

## eBPF ABI

Set 14 reuses the 16-byte `fluxvm_pod_policy` value and consumes previously
reserved fields:

- `reserved0`: rich-rule count;
- `reserved1`: Pod-policy wire schema version.

New flags indicate rich-rule mode plus independent egress/ingress isolation.
A new per-VM `fluxvm_prules` hash stores at most `FLUXVM_MAX_POD_RULE`
(**64**, not the 512 originally proposed — see "Rule cap" below)
`fluxvm_pod_rule` values. Each value is 28 bytes and carries Pod identity,
direction, address family, protocol, prefix length, port interval and
address bytes.

The prior Set 6S exact-address maps and Set 13 exact peer+port maps remain in
the object and are used for legacy policy records.

### Rule cap: 64, not 512

`fluxvm_pod_policy_rich_verdict` scans up to `FLUXVM_MAX_POD_RULE` rules with
a non-unrolled bounded loop (`bpf_map_lookup_elem` plus branching per
iteration), verified once for the IPv4 path and once for the IPv6 path in the
same program. At 512 this combination hits the kernel verifier's
`BPF_COMPLEXITY_LIMIT_JMP_SEQ` (8192 jumps) hard resource cap — confirmed
empirically ("The sequence of 8193 jumps is too complex") on real hardware,
not a theoretical concern. Lowering the bound to 64 was the empirical fix.
`internal/policy/compiler.go`'s `defaultMaxRules`, `cmd/.../main.go`'s
`--max-rules` default, and the Rust `MAX_POD_RULES` constant in `ebpf.rs` are
all kept at 64 in lockstep with this kernel-side bound; `validate_pod_policy`
rejects any policy that would exceed it before it reaches the kernel.

## Directional enforcement

The existing FluxVM TC/TCX program remains the guest-to-host (Pod egress)
policy point and invokes the rich tuple evaluator with `EGRESS`.

Set 14 adds `fluxvm_pod_ingress.bpf.o`, a separate compiled object (loaded
lazily via `bpftool prog load ... map name X pinned Y`, only for a Pod whose
policy actually isolates ingress). FluxVM attaches this classifier to TC
egress of the host-visible VM edge, which is host-to-guest traffic. It reuses
the existing VM's pinned policy maps instead of introducing a second policy
owner.

### Stateful return traffic

The ingress classifier also reuses the main `fluxvm_ct` LRU map. For an ingress
packet it constructs the reverse guest-to-remote tuple:

```
ingress remote:src -> guest:dst
             becomes
guest:dst -> remote:src
```

If that tuple is already in `fluxvm_ct`, the packet is a return path for a
previously allowed guest-initiated flow and bypasses ingress isolation. When a
new ingress packet is allowed, the same reverse tuple is learned so the main
egress program permits the reply even when egress is isolated.

This is deliberately consistent with FluxVM's existing VM-edge conntrack
shortcut. It is not presented as a replacement for Kubernetes/CNI conntrack.

## Bootstrap traffic

The ingress hook permits ARP, DHCPv4, DHCPv6 and IPv6 NDP before rich policy.
The existing egress program already contains equivalent bootstrap behavior.

## Fail-closed behavior

The controller emits at most `--max-rules` tuples (default 64). Overflow,
malformed `ipBlock`, invalid `except`, invalid numeric ports and invalid ranges
produce a schema-v2 safe-deny policy rather than a partial wider policy.
Unsupported named-port cases are omitted from the allow union and surfaced via
controller metrics/logging.

During map replacement, FluxVM publishes a restrictive Pod policy before
clearing/rebuilding allow state. Rich policy publication occurs only after rule
map population completes.

## Coexistence

- FluxVM modifies only its own per-VM bpffs pins.
- No Cilium private map is read or written.
- Existing TCX/TC guest-to-host attachment ownership remains unchanged.
- The new host-to-guest filter uses TC preference `49153`, handle `2` and is
  removed only when the pinned FluxVM program ID matches that slot.

## What was actually validated

Unlike the packaging environment this design originated in, adopting it into
this tree included real validation, not just static checks:

- `cargo build --workspace` / `cargo test --workspace` on the real target
  (Linux); `fluxvm-network`'s 68 unit tests pass.
- Both `fluxvm_tc.bpf.o` (back to exactly one `SEC("tc")` program) and the new
  `fluxvm_pod_ingress.bpf.o` compile and load through the real kernel BPF
  verifier; confirmed map-id sharing between the two loaded programs.
- Four real verifier bugs in the adopted eBPF header were found and fixed in
  the process (loop-unroll-with-`break`, variable-indexed raw packet pointer,
  the `BPF_COMPLEXITY_LIMIT_JMP_SEQ` rule-cap issue above, and a
  compiler-eliminated bounds check papered over with a bitmask) — see the
  merge commit message for specifics.
- Go: `go build/vet/test/test -race/gofmt` and `CGO_ENABLED=0` cross builds
  for linux/amd64 and linux/arm64, all real, all green.
- Two default-port bugs (`http://127.0.0.1:8080` in both `client.go` and
  `main.go`, when the real FluxVM control-plane port is `7788`) were found
  and fixed before this shipped, not after.

Both live tests were rewritten for this design and actually run, not just
updated on paper:

- `scripts/test-ebpf-smoke.sh`, in real Linux network namespaces against the
  real kernel verifier, proves a `fluxvm_prules` CIDR-only rule, then the
  same rule slot narrowed to TCP/18080 (denying tcp/18081 and ICMP at the
  same time), a real SCTP packet matched by protocol number, and the
  separate `fluxvm_pod_ingress.bpf.o` object loaded with shared pinned maps
  (map-id subset checked programmatically, not just visually) enforcing an
  ingress-direction rule against the same VM edge.
- `scripts/test-networkpolicy-live.sh` proves the new schema-v2 wire shape
  (`schema_version`, `egress_isolated`/`ingress_isolated`, `rules: [...]`)
  against a real single-node k3s cluster with real Pods and a real
  `NetworkPolicy` object, including named-port resolution against another
  Pod's real container spec.

The one live capability still unproven end-to-end is the stateful
conntrack-bypass path itself (a guest-initiated flow's reply skipping
ingress isolation) — the smoke test proves the CIDR/L4/SCTP rule matching
and the shared-map object loading, but not yet that specific bypass under a
live TCP handshake; tracked as a follow-up.

## Remaining follow-ups after Set 14

1. replace bounded rich-rule linear scanning with indexed LPM/L4 structures if
   p99 packet cost becomes material, and/or if the 64-rule cap proves too low
   in practice (would require a verifier-budget rework, not just a constant
   bump);
2. add IPv6 extension-header walking within the chosen minimum-kernel verifier
   budget;
3. add EndpointSlice-aware Service semantics if Kubernetes Service-IP policy
   parity is required;
4. run a focused upstream-style NetworkPolicy conformance matrix across Cilium
   and at least one non-Cilium CNI, ideally as a genuine multi-node
   conformance suite rather than single-node reconciliation checks;
5. expose per-direction Pod-policy verdict counters and rule-hit identity.
