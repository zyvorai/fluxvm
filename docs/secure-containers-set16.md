# Secure Containers Set 16 — Conntrack Revocation Safety & VM-level SCTP

## Why this Set exists

Secure Containers Set 14 already made Pod ingress and egress policy
bidirectionally stateful: the separate `fluxvm_pod_ingress.bpf.o` object
shares the main program's `fluxvm_ct` conntrack table, so a reply to a
guest-initiated flow crosses a restrictive ingress policy and vice versa.
What Set 14 did **not** address, and what this Set actually closes, is two
narrower correctness gaps in that same shared table:

1. **No expiry.** `fluxvm_ct`'s value was a bare one-byte "have I ever seen
   this tuple" marker, learned once and never touched again. A flow allowed
   under an old policy stayed authorized in the LRU table indefinitely —
   bounded only by eviction pressure, which under light load could be a very
   long time — even after the Pod's policy was tightened to newly deny it.
2. **No anti-replay check.** Nothing stopped a *brand-new* connection that
   happened to reuse an old 5-tuple (e.g. after a prior connection closed)
   from riding a stale conntrack hit instead of being evaluated against
   current policy.

This kit originally targeted a pre-Set-14 upstream snapshot and proposed a
substantially different, overlapping design (its own embedded Pod-ingress
program, its own bidirectional-conntrack introduction, its own SCTP
plumbing) — all superseded by what Set 14 already shipped. Only the two
gaps above were genuinely new; everything else here reflects what was
actually reconciled into the current, already-merged Set 14 architecture,
not the kit's original design.

## Dataplane schema v9

`fluxvm_ct` changes value ABI:

- v8 value: one byte (`__u8`), presence only, no expiry;
- v9 value: `struct ct_state { __u64 last_seen_ns; }`.

Both `fluxvm_tc.bpf.o` (the main egress program) and the separate
`fluxvm_pod_ingress.bpf.o` object declare their own copy of the `fluxvm_ct`
map definition and must agree on this layout, since Set 14 already binds
them to the same pinned map instance. Existing VMs attached with schema v8
must reattach the new object; `configure_pod_policy()` now refuses to
silently program a live pre-v9 VM's Pod policy rather than risk a stale
established-flow bypass under a scheme it doesn't understand.

### Idle expiry

State is refreshed on every hit and expires at:

- TCP: 2 hours;
- SCTP: 2 hours;
- UDP: 120 seconds;
- other IP protocols: 30 seconds.

This is a lightweight policy-continuity table, not a complete TCP or SCTP
state machine.

### New-flow protection

A stale established tuple must not authorize a brand-new connection that
reuses the same 5-tuple. TCP initial `SYN && !ACK` and SCTP packets with
verification tag zero (the INIT path) always go through current policy
rather than taking the conntrack shortcut — on both the main egress program
and the separate Pod-ingress object's reverse-tuple check.

## Immediate policy revocation

`reconfigure()` (VM-level policy) and `configure_pod_policy()` (Pod-level
policy) both clear the VM-private `fluxvm_ct` map **before** changing any
allow map. A policy update can therefore never leave a window where a tuple
admitted by the old policy survives past a newly tightened one. If conntrack
invalidation fails, the policy update fails before publish — the existing
fail-closed-first map update ordering is unchanged.

## SCTP

Set 14 already carries `IPPROTO_SCTP` end to end for the Kubernetes-facing
Pod policy path (the unified `fluxvm_prules` rich rules, the Go controller's
compiler, and both TC programs' packet parsers). The one place Set 14 never
touched is the older, non-Kubernetes **VM-level** `allow_ports` mechanism
(`fluxvm_l4`), which only accepted `tcp/PORT`, `udp/PORT`, `icmp` and
`icmp6`. This Set adds `sctp/PORT` there too, so an operator can express a
VM-level SCTP allow rule directly through the FluxVM API/CLI, independent of
Kubernetes NetworkPolicy.

## Compatibility with Set 15

Independent. Set 15's `attachment_status()`/`fluxvm-policy-observer` changes
and this Set's `fluxvm_ct` ABI change touch disjoint parts of the dataplane;
Set 15's observer does not read `fluxvm_ct` at all.

## What was actually validated

- `cargo build --workspace` clean; `fluxvm-network`'s unit tests pass,
  including a new VM-level `sctp/443` parse test.
- Both `fluxvm_tc.bpf.o` and `fluxvm_pod_ingress.bpf.o` load through the
  real kernel BPF verifier with the new `struct ct_state` map value ABI.
- `scripts/e2e-networkpolicy-set16.sh` (kept from the original kit largely
  unchanged, since it tests observable behavior rather than
  implementation) run for real against a live single-node k3s cluster:
  ingress-authorized replies crossing an egress deny-all, egress-authorized
  replies crossing an ingress deny-all, and a tightened policy revoking an
  established connection's ability to open a *new* flow.

Not covered here: SCTP-specific live traffic (needs an SCTP-capable kernel
module and client tooling on the test cluster) and IPv6 SCTP behind
extension headers, same boundary Set 14 already documented.
