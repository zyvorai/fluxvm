# Contributing to FluxVM

## Build

```bash
make build          # cargo build --workspace
make test           # rust unit tests (needs workspace toolchain)
make test-policy    # python control-plane tests (no rustc required)
make check          # test-policy + preflight
make bpf            # scripts/build-ebpf.sh
make preflight
./scripts/release-checklist.sh   # docs + production python suites
```

## PR bar

- Apache-2.0 headers on new files
- Changelog entry under `## 0.4.0 (unreleased)`
- Docs next to the feature (`docs/` + README TOC if it is operator-facing)
- Operator-facing production/auth/tenant/probe changes also update
  [docs/PRODUCTION.md](docs/PRODUCTION.md),
  [docs/tutorials/production/](docs/tutorials/production/), and
  `examples/create-vm-prod.json` when the create shape changes
- Tests: Rust `#[cfg(test)]` and/or `scripts/test-*.py`
- Do not write Cilium-private BPF maps
- Do not expand `extra_args` as a tenant feature

## Layout

See README “Project layout”. Network Fabric lives in `crates/fluxvm-network`
+ `bpf/`. Kubernetes packaging is `deploy/k8s/` + `crates/fluxvm-kube`.
Secure Containers (containerd runtime-v2) lives in `crates/fluxvm-container-*` /
`crates/fluxvm-containerd-shim` + `deploy/containerd/` — see
`docs/secure-containers.md`.
