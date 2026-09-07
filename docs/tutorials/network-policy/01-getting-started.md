# 01 — Getting started (Network Fabric)

**Goal:** Turn on the Fabric eBPF edge, confirm schema **v4**, and
take a first observe glance at identities and network status.

**You will use:** `fluxvm identity list`, `fluxvm observe`, REST
`/v1/network/status`.

## 1. Enable the dataplane

```bash
sudo ./scripts/build-ebpf.sh
sudo install -D -m0644 dist/bpf/fluxvm_tc.bpf.o /usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o
sudo install -D -m0644 dist/bpf/fluxvm_xdp.bpf.o /usr/lib/fluxvm/bpf/fluxvm_xdp.bpf.o
```

Ensure `[sandbox.dataplane] mode = "ebpf"` in `/etc/fluxvm.toml`, then:

```bash
sudo systemctl restart fluxvm
curl -sf http://127.0.0.1:7788/v1/vms >/dev/null && echo API_OK
```

## 2. List reserved identities

`fluxvm identity list` shows reserved destinations such as `reserved:world`,
`reserved:host`, and related fabric identities:

```bash
sudo fluxvm --config /etc/fluxvm.toml identity list
```

**Expect:** entries with `id` 0–8 plus world-ipv4/ipv6 (19/20),
`reserved: true`, labels like `reserved:world`.

```bash
curl -s http://127.0.0.1:7788/v1/network/identities | python3 -m json.tool | head -40
```

## 3. First observe snapshot

```bash
sudo fluxvm --config /etc/fluxvm.toml observe
# or
curl -s http://127.0.0.1:7788/v1/network/observe | python3 -m json.tool
```

**Expect:** JSON with `identities`, `groups`, `policies`, `endpoints`
(endpoints fill in after VMs have a network policy file).

## 4. Optional — attach a VM and check status

Create a FluxVm with TAP + netns, then:

```bash
ID=<vm-uuid>
curl -s "http://127.0.0.1:7788/v1/vms/${ID}/network/status" | python3 -m json.tool
```

**Expect:** `mode=ebpf`, `attached=true`, `schema_version=4`,
`schema_compatible=true`.

## Next

- [02 — Identities](02-identities.md)
- [03 — Security groups](03-security-groups.md)
