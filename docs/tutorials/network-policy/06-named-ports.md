# 06 — Named ports

**Goal:** Use CNP port **names** (`https`, `dns`, …) in a policy document
and confirm they expand to numeric `proto/port` rules.

Supported names (case-insensitive): `http`→80, `https`→443, `dns`→53,
`ssh`→22, `smtp`→25, `ntp`→123, `ldap`→389, `ldaps`→636, `mysql`→3306,
`postgres`/`postgresql`→5432, `redis`→6379, `kube-apiserver`→6443.

## Apply

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp apply \
  --spec examples/cnp/cnp-named-ports.json

sudo fluxvm --config /etc/fluxvm.toml group get named-ports-demo \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);p=d["policy"]["allow_ports"];
assert "tcp/443" in p and "udp/53" in p, p; print("ok", p)'
```

## Unit check without a cluster

```bash
cargo test -p fluxvm-network named_ports_expand -- --nocapture
python3 scripts/test-network-policy.py
```

## Cleanup

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp delete named-ports-demo
```

## Next

- [07 — Entities and FQDNs](07-entities-and-fqdns.md)
