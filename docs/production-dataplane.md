# Production dataplane runbook

Use this after Network Fabric v4 + network policy (groups/CNP) are in place.
See also [network-policy.md](network-policy.md).

## Host checklist

1. `./scripts/build-ebpf.sh` and install both `.o` files under `/usr/lib/fluxvm/bpf/`.
2. `LimitMEMLOCK=infinity`, `ReadWritePaths` includes `/sys/fs/bpf` and `/run/fluxvm`.
3. Merge [`configs/network-fabric-prod.toml`](../configs/network-fabric-prod.toml).
4. Nodes with an existing CNI agent: `mode = "cilium"`, mount `/var/run/cilium` read-only, do not enable FluxVM XDP.
5. `fluxvm dataplane health` must report `"ok": true` before creating tenant VMs.

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

No kube-proxy replacement, Maglev, WireGuard datapath, L7 Envoy, or full flow UI.
