# Security profiles (Phase 6)

`CreateVmRequest.security_profile` selects the launch and evidence path.
The VM record stores **requested** and **achieved** profiles separately so
a control-plane accept cannot be read as a hardware attestation claim.

**How to test (same as CI):** [`./scripts/test-security-profiles.sh`](../scripts/test-security-profiles.sh) ·
[guide](guides/security-profiles-howto.md) ·
[GitHub Actions](../.github/workflows/security-profiles.yml).
Example create body: [`examples/qemu-measured.json`](../examples/qemu-measured.json).

| Profile | What it requires | Evidence class | Hardware attestation? |
|---|---|---|---|
| `standard` (default) | Nothing new | none | no |
| `measured` | QEMU + Secure Boot + swtpm + approved signed catalog image | `software-test` | **never** |
| `confidential-snp` | QEMU + SEV-SNP CPU/firmware on the node | `sev-snp` only after a verified hardware run | gated |
| `confidential-tdx` | QEMU + TDX CPU/firmware on the node | `tdx` only after a verified hardware run | gated |

## Why measured is not hardware attestation

FluxVM already attaches a real UEFI Secure Boot chain and an `swtpm`-backed
vTPM (see [secure-boot-tpm.md](./secure-boot-tpm.md)). That document is explicit: FluxVM does not consume PCR
quotes or perform remote attestation, and an `swtpm` process is controlled
by the host. A host-controlled TPM **cannot** prove that the host cannot
inspect the guest.

`measured` therefore:

1. Forces `secure_boot` + `tpm` on the QEMU backend.
2. Requires the image to be a catalog alias whose Ed25519 signature
   verifies against `catalog.trusted_signers`.
3. Collects a software measurement transcript (image / firmware / kernel
   SHA-256 plus synthetic PCR0/PCR4/PCR7).
4. Evaluates `measurement_policy` and will release `measurement_policy.test_secret`
   only on a full match (`POST /v1/vms/{id}/secrets/release`).
5. Labels every bundle `evidence.class = "software-test"` and
   `hardware_attestation = false`.

This is the hardware-free development mode. It is real control-plane
coverage for the measurement and secret-release flow. It is not SNP/TDX.

## Confidential control plane vs. the security claim

SNP and TDX launch argument generation and evidence verification live
behind separate QEMU provider traits (`SnpLaunchProvider`,
`TdxLaunchProvider` in `fluxvm-qemu`). Unit tests cover:

- argument generation (machine + `-object`)
- malformed evidence (`SNP\x01` / `TDX\x01` headers)
- policy denial
- fail-closed behavior when `hardware_attestation` is false
- rejection of `extra_args` as “proof” of a confidential launch

Real launch and host-memory protection stay **unverified** until an
operator flips, after a hardware integration run:

```toml
[security]
snp_launch_verified = false
tdx_launch_verified = false
# Exercise arg generation / admission only. Does not assert memory protection.
allow_unverified_confidential = false
```

Until those verified flags are true:

- `requested_security_profile` may be `confidential-snp` / `confidential-tdx`
- `achieved_security_profile` stays `measured` (software-test) or `standard`
- the record notes that the hardware claim is unverified

## Operations a confidential profile must not inherit

The ordinary QEMU backend supports memory hotplug, CPU hotplug, NIC/share
hotplug, snapshots, `loadvm`, hugepages, shared memory, and `extra_args`.
A confidential profile **does not inherit them**. Each operation has an
explicit compatibility check and fails closed.

`extra_args` containing `-object sev-snp-guest...` is not evidence that a
confidential launch succeeded.

## Host capability discovery and fleet placement

`GET /v1/security/capabilities` reports what *this node* can do.
`fluxvm-agent node` heartbeats that report to the fleet registry.

Automatic placement only lands a `measured` / `confidential-*` request on
a capable node.

An explicit `"node"` on `POST /fleet/vms` still bypasses cordon and
`nodeSelector` — that is existing FluxVM fleet behavior — but it **does
not** bypass the security-profile check. A confidential request is
rejected on an ineligible node even when the caller named that node.

The node's own `POST /v1/vms` repeats the same admission check, so a
direct create (no fleet) cannot skip it either.

## API

```http
GET  /v1/security/capabilities
GET  /v1/vms/{id}/attest
POST /v1/vms/{id}/secrets/release
```

Create body:

```json
{
  "name": "measured-dev",
  "backend": "qemu",
  "image": "ubuntu-24.04",
  "security_profile": "measured",
  "measurement_policy": {
    "test_secret": "dev-only-not-a-production-secret"
  }
}
```
