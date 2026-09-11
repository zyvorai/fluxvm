# Sentinel Set 17E — Release Admission & Preflight Controller

Set 17E adds a **pre-rollout release gate** for FluxVM Sentinel. It is intentionally non-mutating: it does not install, upgrade, quarantine, or roll back nodes. Its only job is to decide whether a candidate release is admissible for a declared fleet and to produce tamper-evident evidence for that decision.

## Why this exists

Sets 14E–16E make upgrade, fleet rollout, and post-rollout drift handling safer. Set 17E closes the remaining gap: a bad or incompatible release should be rejected **before** canary rollout begins.

The admission decision combines:

- exact candidate artifact SHA-256 and optional build-manifest integrity;
- GA/certification evidence with JSON-pointer assertions and numeric budgets;
- strict-SSH fleet capability probes;
- architecture/kernel requirements;
- BTF, bpftool, bpffs, cgroup-v2, KVM, sched_ext and BPF-LSM capability facts;
- current release state-ABI inventory;
- explicit current→candidate ABI compatibility lists;
- fleet reachability/compatibility percentages and cohort coverage;
- a short-lived admission record with a deterministic fleet/evidence fingerprint.

## Safety model

1. **Local proof first.** Candidate and evidence are verified before node probes. If local proof fails, network probing is skipped.
2. **No deployment side effects.** All remote operations are read-only probes.
3. **Strict SSH by default.** Host-key checking is enabled unless the plan explicitly opts out.
4. **No ABI guesswork.** A changed state ABI is accepted only when the old fingerprint is explicitly listed as compatible.
5. **Fail closed.** Missing current ABI state is incompatible by default.
6. **Short-lived admission.** Admission records expire and are hash-manifested. Optional OpenSSH signing is supported.
7. **Cohort awareness.** An overall percentage cannot hide a hardware/kernel cohort with zero compatible nodes.

## Commands

```bash
fluxvm-admit validate admission.json
fluxvm-admit probe admission.json
fluxvm-admit evaluate admission.json
sudo fluxvm-admit admit admission.json
fluxvm-admit verify-admission \
  /var/lib/fluxvm/sentinel-admission/<admission-id> \
  --require-admitted

# If evidence_signing_key was configured, strict verification also requires:
fluxvm-admit verify-admission /var/lib/fluxvm/sentinel-admission/<admission-id> \
  --require-admitted --allowed-signers /etc/fluxvm/admission_allowed_signers
```

`evaluate` writes an evidence bundle but does not mark the release admitted. `admit` writes `admitted=true` only when every configured gate passes.

## Evidence assertions

Evidence can be a single JSON document or a Set-12E-style evidence directory whose `manifest.json` cryptographically covers the assertion document.

Example:

```json
{
  "name": "strict-ga",
  "kind": "evidence-dir",
  "path": "/srv/releases/evidence/strict",
  "document": "run.json",
  "assertions": [
    {"pointer": "/status", "op": "eq", "value": "pass"},
    {"pointer": "/metrics/network_p99_us", "op": "le", "value": 250}
  ]
}
```

Supported assertion operators are `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `contains`, and full-regex `matches`.

## State ABI compatibility

A node currently reporting `network=service-schema-v7` can move to a candidate declaring `network=service-schema-v8` only when `service-schema-v7` appears under:

```json
"compatibility": {
  "allowed_from_state_abis": {
    "network": ["service-schema-v7"]
  }
}
```

Matching current/candidate fingerprints are always compatible. This gate is deliberately independent of semantic version strings.

## Integration with Set 15E / Set 16E

Set 17E does not modify those controllers. The intended operator flow is:

```text
Set 12E certification
        ↓
Set 17E admission
        ↓
Set 15E canary/fleet rollout
        ↓
Set 16E continuous drift + SLO guard
```

The admitted record contains the candidate artifact hash, plan hash, fleet fingerprint, evidence fingerprint, and expiration time. A rollout pipeline can require `verify-admission --require-admitted` before invoking `fluxvm-fleet run`.

## Deliberate boundaries

Set 17E does not claim software supply-chain signature verification for arbitrary package formats, vulnerability-scanner integration, TPM attestation, or cluster scheduling. Those can be layered in as evidence assertions without making this controller a package manager or an orchestrator.
