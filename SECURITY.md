# Security policy

## Supported versions

The `main` branch of [zyvorai/fluxvm](https://github.com/zyvorai/fluxvm) is
the supported line. Report issues against current main.

## What this project is

FluxVM is a **host-local disposable VM control plane**. It is not a finished
multi-tenant public cloud. Before exposing it off-loopback:

1. Set `auth.require = true` and populate `[[auth.tokens]]`.
2. Bind loopback or put TLS in front (nginx/Caddy/Fabric).
3. Keep `allow_extra_args = false`.
4. Restrict `allowed_network_modes`, `allowed_image_dirs`, `allowed_backends`.
5. Enable Network Fabric production profile (`configs/network-fabric-prod.toml`)
   when VMs have a host-visible edge.
6. Use Firecracker jailer + cgroup v2 limits for untrusted guests.
7. Sign catalog images (Ed25519 / optional cosign).

## Report a vulnerability

Email the maintainers listed in [NOTICE](NOTICE) or open a private advisory
on GitHub. Do not file a public issue for exploitable auth/isolation bugs.

## Explicitly out of scope today

- OIDC/mTLS token exchange (config keys reserved; bearer tokens are the GA path)
- Cilium-private map integration
- Treating `extra_args` as a tenant API
