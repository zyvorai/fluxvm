# 03 — Security groups (label-based policy)

**Goal:** Define a Cilium-style security group, attach it via labels, and
inspect the **effective** policy.

Cilium analogue: identity selectors + network policy without writing a full
CNP YAML.

## 1. Create a group

```bash
sudo fluxvm --config /etc/fluxvm.toml group set web \
  --label app=web --label env=prod \
  --priority 10 \
  --description "HTTPS + DNS egress" \
  --default-allow false \
  --allow-cidr 10.0.0.0/8 \
  --allow-cidr 172.16.0.0/12 \
  --deny-cidr 10.66.0.0/16 \
  --allow-port tcp/443 --allow-port tcp/80 --allow-port udp/53 --allow-port icmp/0 \
  --allow-icmp \
  --max-egress-mbps 250
```

Or apply the example JSON via API:

```bash
curl -s -X POST http://127.0.0.1:7788/v1/network/groups \
  -H 'Content-Type: application/json' \
  --data @examples/security-group-web.json | python3 -m json.tool
```

```bash
sudo fluxvm --config /etc/fluxvm.toml group list
sudo fluxvm --config /etc/fluxvm.toml group get web
```

## 2. Select the group from a VM

Membership is **label subset** and/or explicit `groups`:

```bash
curl -s -X POST "http://127.0.0.1:7788/v1/vms/${ID}/network/policy" \
  -H 'Content-Type: application/json' \
  -d '{
    "default_allow": true,
    "labels": ["app=web", "env=prod", "tier=front"],
    "groups": [],
    "allow_cidrs": [],
    "allow_ports": [],
    "max_egress_mbps": 500
  }'
```

## 3. Check effective merge

```bash
curl -s "http://127.0.0.1:7788/v1/vms/${ID}/network/effective" | python3 -m json.tool
```

**Expect:**

- `membership.matched` → `web`
- `effective.default_allow` → `false` (group fails closed)
- `effective.allow_cidrs` includes `10.0.0.0/8`
- `effective.deny_cidrs` includes `10.66.0.0/16`
- `effective.max_egress_mbps` → `250` (tightest of VM 500 and group 250)
- `effective.allow_icmp` → `true`

## 4. Named attachment (no labels on the group)

```bash
sudo fluxvm --config /etc/fluxvm.toml group set egress-only \
  --default-allow false \
  --allow-cidr 1.1.1.1/32 \
  --deny-cidr 0.0.0.0/0 \
  --allow-port udp/53 \
  --allow-icmp

curl -s -X POST "http://127.0.0.1:7788/v1/vms/${ID}/network/policy" \
  -H 'Content-Type: application/json' \
  -d '{"default_allow":true,"groups":["egress-only"],"labels":[],"allow_cidrs":[],"allow_ports":[]}'
```

## Cleanup

```bash
sudo fluxvm --config /etc/fluxvm.toml group delete web
sudo fluxvm --config /etc/fluxvm.toml group delete egress-only
```

## Next

- [04 — Network policy (CNP)](04-network-policy.md)
- [10 — Multi-group merge](10-multi-group-merge.md)
