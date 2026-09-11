# Sentinel Set 16E — Continuous Fleet Drift & SLO Guard

Set 16E closes the loop after Set 15E rollout. It does not add another packet-processing feature; it continuously proves that the fleet remains on the release that was approved.

## What it checks

* release ID and artifact SHA from `/var/lib/fluxvm/sentinel-release.json`;
* declared state-ABI fingerprints;
* optional critical file SHA-256 values;
* explicit health commands;
* numeric SLO commands (`lt`, `le`, `gt`, `ge`, `eq`);
* SSH reachability/inventory integrity.

## Safety model

`observe` is the default. Mutating modes require both `policy.mode != observe` and `policy.allow_actions=true`. Set 16E never synthesizes a quarantine/remediation command: the exact argv must be present in the immutable plan. Actions require N consecutive critical observations, are capped per run and per compatibility cohort, and are disabled when either the fleet or a cohort is already beyond its unhealthy-node budget. Failed actions become `manual-intervention`.

All remote commands are argv arrays transported through JSON to a fixed Python subprocess wrapper. Strict SSH host-key verification is on by default. A changed plan is rejected for an existing `guard_id`; use a new ID for a new desired release.

## Release marker

Each node should expose a root-owned JSON marker such as:

```json
{"release_id":"r2026.09.11-1","artifact_sha256":"...","state_abis":{"network":"schema-v8"}}
```

This marker should be written by the release/upgrade workflow only after health has succeeded.

## Commands

```bash
fluxvm-fleet-guard validate guard.json
fluxvm-fleet-guard check guard.json
fluxvm-fleet-guard status guard.json
fluxvm-fleet-guard verify-evidence /var/lib/fluxvm/sentinel-fleet-guard/<id>/evidence/run-000001
```

The systemd timer runs one check every five minutes. Evidence is a per-run directory with the immutable plan, observations/actions, journal, and SHA-256 manifest. Optional OpenSSH signing is supported with `evidence_signing_key`.
