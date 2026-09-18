# Production dataplane runbook

Use this after **Network Fabric (GA; dataplane schema v4)** + network policy
(groups/CNP) are in place. See also [network-policy.md](network-policy.md).

For the **whole-project** bar (auth, `/readyz`, tenant, storage, k8s — not only
the dataplane), start with [PRODUCTION.md](PRODUCTION.md) and
`./scripts/release-checklist.sh`.

## Host checklist

Prefer the one-command enable (builds/installs BPF objects, merges the GA
profile, optional restart). Dataplane knobs match
[`configs/network-fabric-ga.toml`](../configs/network-fabric-ga.toml) /
[`configs/network-fabric-prod.toml`](../configs/network-fabric-prod.toml);
"prod" here means the operator loop below, not a different `mode`.

1. `./scripts/network-fabric-preflight.sh` (bpffs, `bpftool`/`tc`, optional BPF object).
2. `sudo ./scripts/enable-network-fabric-ga.sh --restart`
   (or `--cilium --restart` on CNI nodes; lab: `--lab --restart`).
3. Manual alternative: `./scripts/build-ebpf.sh`, install `.o` under
   `/usr/lib/fluxvm/bpf/`, ensure `LimitMEMLOCK=infinity` + `ReadWritePaths`
   for `/sys/fs/bpf` and `/run/fluxvm`, merge `network-fabric-prod.toml`.
4. Nodes with an existing CNI agent: `mode = "cilium"`, mount `/var/run/cilium` read-only, do not enable FluxVM XDP.
5. `curl -sf http://127.0.0.1:7788/readyz` and `fluxvm dataplane health` must report `"ok": true` before creating tenant VMs.
6. Prefer `tenant` on create (or token `tenant`) so `GET /v1/vms?tenant=` works for fleet filters.

## Operator loop

```bash
fluxvm dataplane health
fluxvm cnp apply --spec examples/cnp-web.json
fluxctl identity list
fluxctl observe
fluxvm dataplane ipcache
fluxvm dataplane refresh-dns   # after FQDN allowlist / DNS TTL change
```

REST: `GET /v1/network/health`, `/ipcache`, `/observe`; `POST /v1/network/refresh-dns`.

`POST /v1/network/refresh-dns` is **best-effort** across the fleet: VMs without a
host-visible dataplane interface (or a failed reconfigure) are skipped with a warn;
the response returns the count refreshed and does not fail the whole host.

## What production now does

- Resolves CNP `toFQDNs` to IPv4 /32 and IPv6 /128 at apply/reconfigure
- Skips wildcard `*` patterns (still need an explicit name or CIDR)
- Writes guest IP → identity into a FluxVM ipcache (not foreign CNI maps)
- Reconciles running members when a group or CNP changes
- Health probe fails closed on missing BPF object / bpffs / cilium.sock (when `mode=cilium`)

## Still not a CNI

FluxVM is not a cluster CNI or kube-proxy replacement. WireGuard datapath, L7
Envoy parsers, and a full Hubble UI remain out of this runbook.

**Service load balancing** is a separate plane: Service Fabric **v6 (BPF schema 4 /
program generation 8)** (Maglev / NAT / DSR / affinity / health / EDT / FluxScope /
host-routing / HA deltas + mutation queue / identity+L7 policy / cgroup connect) — see
[service-fabric.md](service-fabric.md). Do not conflate it with per-VM Network
Fabric schema v4 policy.

## Validation

```bash
python3 scripts/test-production-dataplane.py
sudo -E ./scripts/test-production-dataplane-e2e.sh
```

Related: `python3 scripts/test-network-policy.py`,
`sudo -E ./scripts/test-security-groups-e2e.sh`.

## See also

- [tutorials/network-policy/](tutorials/network-policy/README.md)
- [network-groups.md](network-groups.md)
- [network-policy.md](network-policy.md)
- [network-fabric.md](network-fabric.md)
- [service-fabric.md](service-fabric.md)
- [ebpf-cilium.md](ebpf-cilium.md)
