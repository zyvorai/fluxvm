# How to test security profiles (Phase 6)

Hardware-free guide. You do **not** need SEV-SNP or TDX silicon to run these
tests or to exercise the measured control plane.

## What this covers

| Profile | What CI / local tests prove | What they do **not** prove |
|---|---|---|
| `standard` | Default create path unchanged | — |
| `measured` | Admission, SB+TPM force, signed catalog, software-test evidence, secret-release fail-closed | Host cannot inspect guest |
| `confidential-snp` / `confidential-tdx` | Arg generation, malformed evidence rejection, `extra_args` rejection, fleet placement gates | Real launch or host-memory encryption |

Full semantics: [security-profiles.md](../security-profiles.md). Secure Boot / vTPM plumbing: [secure-boot-tpm.md](../secure-boot-tpm.md).

## Run the same suite as GitHub Actions

```bash
git clone https://github.com/zyvorai/fluxvm.git && cd fluxvm
# guestkit must sit as a sibling (same as CI)
git clone https://github.com/zyvorai/guestkit.git ../guestkit

./scripts/test-security-profiles.sh
```

Workflow: [`.github/workflows/security-profiles.yml`](../../.github/workflows/security-profiles.yml).

Individual packages:

```bash
cargo test -p fluxvm-core security
cargo test -p fluxvm-qemu confidential
cargo test -p fluxvm-agent explicit_node_targeting_still_rejects_ineligible_confidential_profile
cargo test -p fluxvm-agent automatic_placement_skips_nodes_that_cannot_satisfy_snp
```

## Manual API smoke (QEMU host with OVMF + swtpm + signed catalog)

1. Configure `qemu_ovmf_code`, `qemu_ovmf_vars_template`, `swtpm_binary`, and a
   catalog with `trusted_signers` in your FluxVM config.
2. Create from the example:

```bash
curl -sS -X POST http://127.0.0.1:7788/v1/vms \
  -H 'Content-Type: application/json' \
  --data @examples/qemu-measured.json
```

3. Inspect evidence and try secret release:

```bash
ID=<vm-uuid>
curl -sS "http://127.0.0.1:7788/v1/vms/$ID/attest" | jq .
curl -sS -X POST "http://127.0.0.1:7788/v1/vms/$ID/secrets/release" | jq .
curl -sS http://127.0.0.1:7788/v1/security/capabilities | jq .
```

Expect `evidence.class = "software-test"` and `hardware_attestation = false`.

## Fleet placement check

An explicit `"node"` on `POST /fleet/vms` still bypasses cordon/`nodeSelector`,
but **must not** bypass the security-profile capability check. The agent tests
above cover that; on a live fleet, heartbeats report
`security.{measured,snp,tdx,*_launch_verified}`.

## Confidential claim (Keep / FluxVM 0.2)

Do not flip `security.snp_launch_verified` / `tdx_launch_verified` until a real
hardware integration run. Until then `achieved_security_profile` stays
`measured` (or `standard`) even if the request asked for confidential-*.
