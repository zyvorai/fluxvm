# FluxVM eBPF Service Fabric v1

FluxVM Service Fabric v1 is an east-west VM-edge L4 service load balancer for native `ebpf`
and Cilium-coexistence dataplane modes. It is intentionally separate from the
existing security-policy BPF ABI.

## Architecture

```text
VM packet -> service TC ingress (pref 49140) -> security TC ingress (49152)
          -> Linux routing
return    -> service TC egress -> VM
```

The control plane writes a service catalog. FluxVM compiles every service to a
Maglev lookup table and programs private BPF maps under the VM's FluxVM pin
root. Cilium-owned maps are never modified.

## API

Create/update:

```bash
curl -X POST http://127.0.0.1:7788/v1/network/services \
  -H 'content-type: application/json' \
  -d '{
    "name":"payments",
    "vip":"10.40.0.100",
    "port":443,
    "protocol":"tcp",
    "algorithm":"maglev",
    "mode":"nat",
    "maglev_table_size":4093,
    "backends":[
      {"address":"10.40.1.21","port":8443,"weight":1,"enabled":true},
      {"address":"10.40.1.22","port":8443,"weight":1,"enabled":true}
    ]
  }'
```

List/get/delete:

```bash
curl http://127.0.0.1:7788/v1/network/services
curl http://127.0.0.1:7788/v1/network/services/payments
curl -X DELETE http://127.0.0.1:7788/v1/network/services/payments
```

## v1 semantics

- IPv4 TCP and UDP.
- NAT mode with stateful reverse NAT.
- Maglev consistent hashing.
- Backend weights use deterministic virtual backends.
- Disabled backends receive no Maglev slots.
- A configured service with a missing backend/table entry fails closed.
- DSR is reserved in the schema but rejected in v1.
- The security policy runs after service DNAT and therefore sees the selected
  backend destination. Permit backend CIDRs/L4 ports accordingly.

## Build

`make bpf` now builds `fluxvm_service.bpf.o` alongside the existing TC and XDP
objects. Install all three under `/usr/lib/fluxvm/bpf/`, or override the service
object with `FLUXVM_SERVICE_BPF_OBJECT`.

## Fabric boundary

FluxVM owns packet mechanics, BPF programs/maps, Maglev and reverse NAT. Zyvor
Fabric owns distributed VIP/service intent, backend membership, node fan-out,
HA/DR decisions and audit policy.
