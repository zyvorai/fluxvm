# 10 — Multi-group merge

**Goal:** Attach more than one group (named + label) and verify Cilium-like
**union** semantics on the effective policy.

## Rules (FluxVM)

- Allow CIDRs / deny CIDRs / ports → **union**
- `default_allow` → `false` if **any** member fails closed
- `allow_icmp` → OR
- Mbps / PPS → **minimum** configured value
- `sample_rate` → **maximum**
- Cap: **8** group identities per VM (`fluxvm_gid`)

## Setup

```bash
sudo fluxvm --config /etc/fluxvm.toml group set web \
  --label app=web \
  --default-allow false \
  --allow-cidr 10.0.0.0/8 \
  --allow-port tcp/443 \
  --max-egress-mbps 250 \
  --allow-icmp

sudo fluxvm --config /etc/fluxvm.toml group set db \
  --label app=db --label tier=data \
  --priority 5 \
  --default-allow false \
  --allow-cidr 10.10.0.0/16 \
  --deny-cidr 10.10.99.0/24 \
  --allow-port tcp/5432 --allow-port tcp/443 \
  --max-egress-mbps 40 \
  --max-egress-pps 20000

sudo fluxvm --config /etc/fluxvm.toml group set egress-only \
  --default-allow false \
  --allow-cidr 1.1.1.1/32 \
  --deny-cidr 0.0.0.0/0 \
  --allow-port udp/53 \
  --allow-icmp
```

## Attach both named + labels

```bash
curl -s -X POST "http://127.0.0.1:7788/v1/vms/${ID}/network/policy" \
  -H 'Content-Type: application/json' \
  -d '{
    "default_allow": true,
    "allow_cidrs": ["192.168.1.0/24"],
    "allow_ports": ["tcp/22"],
    "groups": ["egress-only"],
    "labels": ["app=db", "tier=data"],
    "max_egress_mbps": 100,
    "max_egress_pps": 50000,
    "sample_rate": 10
  }'

curl -s "http://127.0.0.1:7788/v1/vms/${ID}/network/effective" | python3 - <<'PY'
import json,sys
d=json.load(sys.stdin)
eff=d["effective"]
names=sorted(g["name"] for g in d["membership"]["matched"])
assert names==["db","egress-only"], names
for c in ["192.168.1.0/24","10.10.0.0/16","1.1.1.1/32"]:
    assert c in eff["allow_cidrs"], c
for c in ["10.10.99.0/24","0.0.0.0/0"]:
    assert c in eff["deny_cidrs"], c
assert eff["max_egress_mbps"]==40
assert eff["max_egress_pps"]==20000
assert eff["sample_rate"]==10
assert eff["allow_icmp"] is True
assert eff["default_allow"] is False
print("multi-group merge ok")
PY
```

## Observe

```bash
sudo fluxvm --config /etc/fluxvm.toml observe \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(len(d["groups"]), "groups")'
```

## Cleanup

```bash
sudo fluxvm --config /etc/fluxvm.toml group delete web
sudo fluxvm --config /etc/fluxvm.toml group delete db
sudo fluxvm --config /etc/fluxvm.toml group delete egress-only
```

## Next

Back to the [tutorial index](README.md) or the parity matrix in
[cilium-parity.md](../../cilium-parity.md).
