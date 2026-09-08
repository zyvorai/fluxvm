# CiliumEndpoint views and Hubble-lite

FluxVM still does **not** write Cilium-private maps. It now persists a
CiliumEndpoint-*shaped* object per VM and serves Hubble-like JSON flows.

```bash
fluxvm hubble endpoints
fluxvm hubble observe                  # colorful one-liners
fluxvm hubble observe --output plain   # normal, no ANSI
fluxvm hubble flow --output color      # detailed packet path
# UI (Colorful / Normal toggle)
curl -sS http://127.0.0.1:7788/v1/network/hubble/ui
```

REST: `GET /v1/network/endpoints`, `GET /v1/network/hubble/flows`,
`GET /v1/network/hubble/flows/text`, `GET /v1/network/hubble/ui`.

Packet-path design and fields: [packet-flow.md](packet-flow.md).

Identity numbers default to the FluxVM UUID hash (`identity_source=fluxvm-hash`).
When `sandbox.dataplane.mode = "cilium"` and the agent socket
`/var/run/cilium/cilium.sock` is visible, FluxVM **reads** SecurityIdentity /
endpoint metadata from the agent HTTP API and may set
`identity_source=cilium-agent` on the CEP view. FluxVM still never writes
Cilium private maps.

`reserved:world=2`. Point real Hubble UI at Cilium on the node; use this UI
for VM-edge samples.
