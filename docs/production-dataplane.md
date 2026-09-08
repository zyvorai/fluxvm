# Production dataplane runbook

Use this after **Network Fabric (GA; dataplane schema v4)** + network policy
(groups/CNP) are in place. See also [network-policy.md](network-policy.md).

For the **whole-project** bar (auth, `/readyz`, tenant, storage, k8s — not only
the dataplane), start with [PRODUCTION.md](PRODUCTION.md) and
`./scripts/release-checklist.sh`.

## Host checklist

1. `./scripts/build-ebpf.sh` and install both `.o` files under `/usr/lib/fluxvm/bpf/`.
2. `LimitMEMLOCK=infinity`, `ReadWritePaths` includes `/sys/fs/bpf` and `/run/fluxvm`.
3. Merge [`configs/network-fabric-prod.toml`](../configs/network-fabric-prod.toml).
4. Nodes with an existing CNI agent: `mode = "cilium"`, mount `/var/run/cilium` read-only, do not enable FluxVM XDP.
5. `curl -sf http://127.0.0.1:7788/readyz` and `fluxvm dataplane health` must report `"ok": true` before creating tenant VMs.
6. Prefer `tenant` on create (or token `tenant`) so `GET /v1/vms?tenant=` works for fleet filters.

## Operator loop

```bash
fluxvm dataplane health
fluxvm cnp apply --spec examples/cnp-web.json
fluxvm identity list
fluxvm observe
fluxvm dataplane ipcache
fluxvm dataplane refresh-dns   # after FQDN allowlist / DNS TTL change
```

REST: `GET /v1/network/health`, `/ipcache`, `/observe`; `POST /v1/network/refresh-dns`.

## What production now does

- Resolves CNP `toFQDNs` to IPv4 /32 and IPv6 /128 at apply/reconfigure
- Skips wildcard `*` patterns (still need an explicit name or CIDR)
- Writes guest IP → identity into a FluxVM ipcache (not foreign CNI maps)
- Reconciles running members when a group or CNP changes
- Health probe fails closed on missing BPF object / bpffs / cilium.sock (when `mode=cilium`)

## Still not a CNI

FluxVM is not a cluster CNI or kube-proxy replacement. WireGuard datapath, L7
Envoy parsers, and a full Hubble UI remain out of this runbook.

**Service load balancing** is a separate plane: Service Fabric **schema v4**
(Maglev / NAT / DSR / affinity / health / EDT / FluxScope / host-routing) — see
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
