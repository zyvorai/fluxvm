# Sentinel Set 13E — End-to-End Migration Orchestrator

Set 13E turns the independent node-local migration mechanisms into one crash-resumable transaction. It does **not** replace the VMM migration engine or Zyvor Fabric's distributed placement/intent.

## Transaction
1. preflight + exclusive journal lock;
2. quiesce new VM flows;
3. export conntrack/flow/drop state and optional QUIC CID affinity;
4. stop AF_XDP and rollback temporary topology/sched_ext steering on source;
5. execute the configured VMM migration argv;
6. restore network/QUIC state on destination;
7. apply destination topology/sched_ext plans and AF_XDP;
8. explicitly resume destination network state;
9. seal `EVIDENCE.sha256` and mark complete.

Each step is fsync'd to `journal.json` before the next begins. Re-running `run` or `resume` skips completed steps. Changing the plan after a transaction starts is rejected by its plan SHA-256.

## Failure semantics
Before the VMM move completes, rollback rebuilds source auxiliaries before reopening source flows. After the VMM move completes, rollback requires explicit `vmm.rollback_argv`; without it the state becomes `manual-intervention` rather than guessing where the VM runs.

## Security
No plan command uses `shell=True`; argv is an array; SSH is BatchMode with strict host-key checking by default; transfer paths are generated below `/tmp/fluxvm-migrate-*`; journals are 0700/0600; known secret flag values are redacted; observer HTTP binds loopback by default.

## CLI
```bash
fluxvm-migrate validate plan.json
sudo fluxvm-migrate run plan.json
sudo fluxvm-migrate resume plan.json
sudo fluxvm-migrate rollback plan.json
fluxvm-migrate status <migration-id>
fluxvm-migrate reconcile --stale-minutes 15
fluxvm-migrate serve --listen 127.0.0.1:7797
```

Set 13E intentionally leaves leader election, placement, BGP/ECMP, storage replication and application consistency to their owning layers.
