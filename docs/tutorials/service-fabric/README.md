# Service Fabric tutorial (FluxVM)

Stand up a Maglev VIP on a single FluxVM host — schema **4** ABI / program
generation **6** (Service Fabric **v6**).

**Level:** Intermediate · **Time:** ~30 minutes  
**Prerequisites:** [Getting started](../../user/getting-started.md), eBPF
dataplane enabled, bridged/tap VM or north-south uplink configured.

Operator reference: [service-fabric.md](../service-fabric.md) ·
Fabric fan-out: [ebpf-service-fabric.md](https://github.com/zyvorai/fabric/blob/main/docs/ebpf-service-fabric.md).

## What you will learn

1. Confirm Service Fabric host status (`schema_version`)
2. Upsert an east-west Maglev service
3. Run health reconcile and inspect ads/flows
4. (Optional) Apply an identity policy (v6)

## Setup

```bash
export API=http://127.0.0.1:7788
export AUTH=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

# /etc/fluxvm.toml needs [sandbox.dataplane] mode = "ebpf"
# and [sandbox.dataplane.service] as required for your exposure mode
curl -sf "$API/readyz" | jq .
```

## 1. Host status

```bash
curl -sf "${AUTH[@]}" "$API/v1/network/services/status" | jq '{
  schema_version, program_generation, interfaces, xdp
}'
```

Expect BPF schema **4**. Program generation **6** after a v6-capable build.

## 2. Upsert Maglev service

```bash
curl -sf "${AUTH[@]}" -d @docs/examples/service-fabric-v4-east-west.json \
  "$API/v1/network/services" | jq .
curl -sf "${AUTH[@]}" "$API/v1/network/services" | jq .
```

Backend JSON uses `"address"` (not `"ip"`). States: `ready` / `draining` /
`unhealthy`.

## 3. Health and advertisements

```bash
curl -sf -X POST "${AUTH[@]}" "$API/v1/network/services/health/reconcile" | jq .
curl -sf "${AUTH[@]}" "$API/v1/network/services/health" | jq .
curl -sf "${AUTH[@]}" "$API/v1/network/services/advertisements" | jq .
```

North-south ads need `north_south_interfaces` and matching `exposure`.

## 4. Identity policy (v6)

```bash
curl -sf "${AUTH[@]}" -d @examples/service-fabric-v6/identity-policy.json \
  "$API/v1/network/services/policies" | jq .
curl -sf "${AUTH[@]}" "$API/v1/network/services/policies" | jq .
curl -sf -X POST "${AUTH[@]}" "$API/v1/network/services/policies/reconcile" | jq .
```

Policy fields: `service`, `default_action`, `allow_identities`,
`deny_identities`, `audit_only`, optional `l7`.

## 5. Cleanup

```bash
NAME=payments   # or whatever the example used
curl -sf -X DELETE "${AUTH[@]}" "$API/v1/network/services/$NAME/policy"
curl -sf -X DELETE "${AUTH[@]}" "$API/v1/network/services/$NAME"
```

## Next

- [service-fabric-phase6.md](../service-fabric-phase6.md) — shipped vs remaining
- [Network policy tutorials](../tutorials/network-policy/README.md) — orthogonal per-VM edge
- Fabric: Edge Dataplane → **Services** + `zyvorctl dataplane service …`
