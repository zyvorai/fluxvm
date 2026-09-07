# 02 — Identities

**Goal:** Understand numeric identities on the FluxVM Network Fabric edge.

## Why identities matter

FluxVM tags every endpoint and “special” destination with a stable integer.
The **reserved** space backs `toEntities` and observe so policy and
telemetry share one dialect:

| ID | Name | Typical use |
|----|------|-------------|
| 0 | `reserved:unknown` | Unclassified |
| 1 | `reserved:host` | Host / node |
| 2 | `reserved:world` | Outside the cluster |
| 6 | `reserved:remote-node` | Other nodes |
| 7 | `reserved:kube-apiserver` | API server entity |
| ≥ `0x10000` | Security-group FNV | Shared label groups |
| `1..=0xffff` (VM) | Per-VM hash | `ebpf::identity_for(uuid)` |

Group identities live **above** `0xffff` so flow telemetry can tell a VM id
from a shared group id. See [`identity.rs`](../../../crates/fluxvm-network/src/identity.rs)
and [`groups.rs`](../../../crates/fluxvm-network/src/groups.rs).

## Hands-on

```bash
sudo fluxvm --config /etc/fluxvm.toml identity list | python3 -m json.tool
```

Create a security group and note its identity:

```bash
sudo fluxvm --config /etc/fluxvm.toml group set demo-id \
  --label app=demo \
  --default-allow false \
  --allow-cidr 10.0.0.0/8 \
  --allow-port tcp/443

sudo fluxvm --config /etc/fluxvm.toml group get demo-id \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["identity"]); assert d["identity"]>=0x10000'
```

Label a VM policy and read effective membership:

```bash
# ID = running VM uuid
curl -s -X POST "http://127.0.0.1:7788/v1/vms/${ID}/network/policy" \
  -H 'Content-Type: application/json' \
  -d '{"default_allow":true,"labels":["app=demo"],"groups":[],"allow_cidrs":[],"allow_ports":[]}'

curl -s "http://127.0.0.1:7788/v1/vms/${ID}/network/effective" | python3 -m json.tool
```

**Expect:** `membership.matched` includes `demo-id`, `group_identities`
contains the same `≥0x10000` value, `vm_identity` is in `1..=0xffff`.

Cleanup:

```bash
sudo fluxvm --config /etc/fluxvm.toml group delete demo-id
```

## Next

- [03 — Security groups](03-security-groups.md)
- [09 — Observe](09-observe.md)
