# CiliumEndpoint views and Hubble-lite

FluxVM still does **not** write Cilium-private maps. It now persists a
CiliumEndpoint-*shaped* object per VM and serves Hubble-like JSON flows.

```bash
fluxvm hubble endpoints
fluxvm hubble observe
# UI
curl -sS http://127.0.0.1:7788/v1/network/hubble/ui
```

REST: `GET /v1/network/endpoints`, `GET /v1/network/hubble/flows`,
`GET /v1/network/hubble/ui`.

Identity numbers match FluxVM (`identity.rs` + groups). `reserved:world=2`.
Point real Hubble UI at Cilium on the node; use this UI for VM-edge samples.
