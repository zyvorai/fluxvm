# FluxVM Service Fabric v2

FluxVM owns node-local VM service mechanics; Zyvor Fabric owns distributed intent and rollout.

## v2 dataplane

- IPv4 and IPv6 TCP/UDP VIPs.
- Weighted Maglev backend selection.
- NAT with stateful reverse NAT.
- Optional per-service SNAT for non-routable client networks.
- Routed DSR: the packet keeps VIP:port and client source; FluxVM performs a FIB lookup using the selected backend address as the forwarding next hop, rewrites L2, and redirects. The backend must accept the VIP locally and return directly to the client.
- East-west VM-edge TC ingress for service selection plus a same-map TC egress reverse-NAT hook.
- North-south physical-uplink TC ingress plus TC egress reverse-NAT for local-backend return traffic.
- Optional north-south XDP accelerator. XDP shares the host TC maps; reverse traffic falls through to the shared TC ingress/egress return path. The XDP object keeps a private per-CPU `fluxvm_fib_scratch` map so `bpf_fib_lookup` fits the kernel’s 512-byte BPF stack.
- Fail-closed update guard while service/backend/Maglev/NAT maps are replaced.

## Scope ownership

Fabric sends `ServiceSpec` through the FluxVM REST API. Fabric never edits BPF maps. FluxVM validates, persists and compiles the catalog into BPF maps.

## Service model

```json
{
  "name": "payments",
  "vip": "203.0.113.20",
  "port": 443,
  "protocol": "tcp",
  "algorithm": "maglev",
  "mode": "nat",
  "exposure": "both",
  "snat_address": "192.0.2.10",
  "maglev_table_size": 4093,
  "backends": [
    {"address":"10.40.1.21","port":8443,"weight":2,"enabled":true},
    {"address":"10.40.2.21","port":8443,"weight":1,"enabled":true}
  ]
}
```

`north-south` NAT requires `snat_address`. DSR forbids SNAT and requires backend port == service port because the destination tuple is preserved.

## Host configuration

```toml
[sandbox.dataplane]
mode = "ebpf"
required = true

[sandbox.dataplane.service]
north_south_interfaces = ["eno1"]
xdp_acceleration = true
xdp_object = "/usr/lib/fluxvm/bpf/fluxvm_service_xdp.bpf.o"
```

Do not enable FluxVM service XDP in `mode = "cilium"`; Cilium may already own the physical-NIC XDP hook. TC service handling remains available.

## APIs

- `GET/POST /v1/network/services`
- `GET/DELETE /v1/network/services/{name}`
- `GET /v1/network/services/status`
- `GET /v1/network/services/stats`
- `GET /v1/vms/{id}/network/services/stats`

## DSR backend requirement

The chosen backend address is used only as the routing next hop. The packet itself retains the VIP. Each backend path must therefore deliver the VIP packet to the backend and the guest/workload must own the VIP (for example on loopback) and avoid ARP/NDP conflicts for that VIP. Fabric should configure this as part of backend admission.

## Symmetric NAT return path

NAT state is created in the map instance attached to the client/uplink edge. Replies are restored on that same interface's TC egress hook (`fvm_svc_rev`). Remote-backend replies that re-enter a north-south uplink can also be restored on TC ingress. This keeps east-west, local north-south, and XDP-accelerated NAT symmetric without a global userspace conntrack service.

## Failure behavior

A service frontend hit never silently bypasses on a missing Maglev/backend entry. During catalog replacement `fluxvm_sguard=1`; TCP/UDP service traffic is over-denied until the full map transaction succeeds. XDP falls back to TC when FIB lookup cannot accelerate a route, without modifying the packet first.
