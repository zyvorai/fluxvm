# FluxVM Sentinel stateful upgrades — Set 14E

Set 14E adds a transaction manager for upgrading FluxVM Sentinel components without treating pinned BPF state as disposable. It is deliberately separate from the packet datapath and hypervisor runtime: the manager coordinates operator-supplied component hooks and preserves only state that the plan explicitly declares.

## Safety model

An upgrade is identified by a stable `transaction_id`. The canonical JSON plan is SHA-256 hashed when the transaction begins; `resume` or `rollback` refuses a modified plan. A non-blocking `flock` prevents two processes from operating the same transaction simultaneously. Journal and snapshot files use write+fsync+rename and the containing directory is fsync'd after replacement.

Commands are JSON argv arrays and run directly with `subprocess.run`; there is no shell expansion. Set 14E does not discover arbitrary BPF objects and does not recursively copy bpffs. Only map pins listed in the plan and resolved beneath `bpffs_root` may be snapshotted.

## State ABI contract

A component may declare a logical state ABI:

```json
"state_abi": {
  "current": 2,
  "target": 3,
  "target_compatible_from": [2, 3]
}
```

When `current != target`, Set 14E refuses the upgrade unless the current logical ABI is explicitly listed as compatible with the target. This catches semantic schema changes that physical map sizes alone cannot detect. Incompatible logical migrations must be performed by a component-specific migration step before running the Set 14E transaction; the generic manager does not guess how to transform security or connection-state semantics.

Each declared map can additionally specify its physical type/key/value ABI and one of three state policies:

- `metadata-only`: validate ABI and record metadata, but do not copy entries;
- `merge`: replay snapshot entries into the replacement map without deleting new entries;
- `replace`: delete current keys from a deletable hash-family map, then replay the snapshot.

The manager refuses restore if map type, key size or value size changed. It also refuses a snapshot that cannot fit into the replacement map's `max_entries`. Generic restoration is intentionally limited to byte-array values. Nested/per-CPU bpftool encodings are recorded but not blindly reconstructed because their representation varies across kernel/bpftool versions; use component-specific migration hooks for those maps.

This is a compatibility gate, not a promise that every logical schema change with identical byte sizes is safe. When semantics change while the physical ABI stays equal, increment the component's own schema and make its preflight/upgrade hook perform the semantic migration.

## Transaction sequence

For each component in order, Set 14E runs:

```text
preflight
   ↓
snapshot declared files + maps
   ↓
apply
   ↓
restore compatible declared map state
   ↓
health
   ↓
next component
```

On the success path, declared `merge`/`replace` map state is replayed after the component apply hook recreates its target maps and before the health hook runs. File snapshots are rollback-only so a successful upgrade does not overwrite newly installed configuration.

If a step fails, already-applied components are rolled back in reverse order. The rollback hook runs before file/map restoration so it can recreate the old programs and pins first. Optional `rollback_health` then verifies the recovered component. If rollback or state restoration fails, the transaction becomes `manual-intervention` rather than claiming success.

A stale `running` journal can be handled by `fluxvm-upgrade reconcile`; the bundled systemd timer checks every five minutes and rolls back transactions that have made no journal progress for 15 minutes.

## Evidence and signing

Every terminal transaction writes `journal.final.json` and `EVIDENCE.sha256`, covering the plan, journal and snapshots. If the plan contains:

```json
"signing": {
  "ssh_private_key": "/etc/fluxvm/upgrade-signing-key",
  "namespace": "fluxvm-upgrade"
}
```

Set 14E invokes OpenSSH `ssh-keygen -Y sign`. Verification supports an OpenSSH `allowed_signers` file and identity using `fluxvm-upgrade verify-evidence`.

The private key is referenced by path only and is never copied into the transaction directory.

## Commands

```bash
fluxvm-upgrade validate plan.json
fluxvm-upgrade probe plan.json
fluxvm-upgrade plan plan.json
sudo fluxvm-upgrade run plan.json
sudo fluxvm-upgrade resume plan.json
sudo fluxvm-upgrade rollback plan.json
fluxvm-upgrade status plan.json
sudo fluxvm-upgrade reconcile --stale-minutes 15
fluxvm-upgrade verify-evidence /var/lib/fluxvm/sentinel-upgrades/<transaction>
```

For signed evidence:

```bash
fluxvm-upgrade verify-evidence \
  /var/lib/fluxvm/sentinel-upgrades/<transaction> \
  --allowed-signers /etc/fluxvm/allowed_signers \
  --identity release@zyvor.dev \
  --namespace fluxvm-upgrade
```

## Recommended FluxVM component policy

Observability counters and caches whose loss is harmless should usually be `metadata-only`. Connection state that materially affects workload continuity should use `merge` only if its logical schema is stable. Security/policy maps should normally be rebuilt from durable source-of-truth policy rather than blindly restored. A component preflight should reject upgrades when its durable policy/config cannot reproduce the intended enforcement state.

## Destructive test gate

The default test suite uses a fake command/bpftool runner. The real bpffs round-trip test requires both:

```text
FLUXVM_UPGRADE_DESTRUCTIVE_E2E=1
/etc/fluxvm/ALLOW_DESTRUCTIVE_E2E
```

and must run only on a throwaway/self-hosted eBPF lab node. It creates one explicitly named test map under `/sys/fs/bpf/fluxvm` and removes it on exit.

## Boundaries

Set 14E does not hot-replace arbitrary BPF links, infer hidden map semantics, or mutate Cilium-owned bpffs objects. Program/link replacement remains the responsibility of each component's apply/rollback hook. The manager supplies ordering, state preservation, compatibility checks, crash recovery and evidence around those component-native operations.
