# 05 — Default deny and deny CIDRs

**Goal:** Fail closed on egress, then punch holes — the usual Cilium
zero-trust pattern — and confirm deny lists win over allow.

## Pattern

1. `enableDefaultDeny.egress: true` → `default_allow=false`
2. Explicit `toCIDR` / `toPorts` allowlists
3. `egressDeny` / `deny_cidrs` evaluated **before** allow in the TC program

## 1. Apply a lock-down CNP

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp apply \
  --spec examples/cilium/cnp-default-deny-dns.json

sudo fluxvm --config /etc/fluxvm.toml group get dns-only | python3 -m json.tool
```

**Expect:** `default_allow=false`, allow ports include `udp/53` (and/or
`tcp/53`), deny may include a broad CIDR depending on the example.

## 2. Attach to a VM

```bash
curl -s -X POST "http://127.0.0.1:7788/v1/vms/${ID}/network/policy" \
  -H 'Content-Type: application/json' \
  -d '{"default_allow":true,"labels":["app=resolver"],"groups":[],"allow_cidrs":[],"allow_ports":[]}'

curl -s "http://127.0.0.1:7788/v1/vms/${ID}/network/effective" \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);e=d["effective"];
assert e["default_allow"] is False
print("deny", e.get("deny_cidrs")); print("allow_ports", e.get("allow_ports"))'
```

## 3. Inspect deny maps (live VM)

With the dataplane attached:

```bash
SIMPLE=$(python3 -c "import uuid; print(uuid.UUID('${ID}').hex)")
PIN=/sys/fs/bpf/fluxvm/vms/${SIMPLE}/maps
sudo bpftool map dump pinned ${PIN}/fluxvm_deny4 | head
sudo bpftool map dump pinned ${PIN}/fluxvm_l4 | head
```

**Expect:** deny LPM keys present when `deny_cidrs` is non-empty; L4 allow
entries for DNS.

## Cleanup

```bash
sudo fluxvm --config /etc/fluxvm.toml cnp delete dns-only
```

## Next

- [08 — Audit mode](08-audit-mode.md) (try the policy without enforcing drops)
- [06 — Named ports](06-named-ports.md)
