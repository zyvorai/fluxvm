# Security policy

## Supported versions

The `main` branch of [zyvorai/fluxvm](https://github.com/zyvorai/fluxvm) is
the supported line. Report issues against current main.

## What this project is

FluxVM is a **host-local disposable VM control plane**. It is not a finished
multi-tenant public cloud. Before exposing it off-loopback:

1. Set `auth.require = true` and populate `[[auth.tokens]]` and/or
   `auth.oidc_issuer` + `auth.oidc_audience` (JWKS JWT validation).
   Optional per-token / OIDC `tenant` is authoritative on create (inherited when
   omitted; mismatch → 403) and scopes list/get/mutate. Optional `[tls]` enables
   HTTPS; `tls.client_ca` enables mTLS. Probes `GET /healthz` and `GET /readyz`
   stay auth-exempt (liveness vs readiness; `/readyz` → 503 when not ready).
2. Bind loopback or put TLS in front (nginx/Caddy/Fabric) — or use FluxVM `[tls]`.
3. Keep `allow_extra_args = false`.
4. Restrict `allowed_network_modes`, `allowed_image_dirs`, `allowed_backends`.
5. Enable Network Fabric production profile (`configs/network-fabric-prod.toml`)
   when VMs have a host-visible edge.
6. Use Firecracker jailer + cgroup v2 limits for untrusted guests.
7. Sign catalog images (Ed25519 / optional cosign).
8. Walk [docs/PRODUCTION.md](docs/PRODUCTION.md) and run
   `./scripts/release-checklist.sh` before calling a host production-ready.

## Report a vulnerability

Email the maintainers listed in [NOTICE](NOTICE) or open a private advisory
on GitHub. Do not file a public issue for exploitable auth/isolation bugs.

## Explicitly out of scope today

- Cilium-native VM endpoints / in-tree Hubble (use coexistence + optional
  Fabric `network.hubble_ui_url` link)
- Cloud Hypervisor Windows + QGA (QEMU path is GA; see [docs/ch-windows-qga.md](docs/ch-windows-qga.md))
- In-tree KVM as a production density engine (`fluxvm_engine=kvm` is lab-only)
