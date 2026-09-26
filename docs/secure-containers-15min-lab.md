# 15-minute Secure Containers lab

Goal: RuntimeClass `fluxvm` smoke on a single Linux/KVM host (k3s or
containerd) without inventing new gates.

## Steps

1. Start FluxVM API (`fluxctl serve` or DaemonSet) on `:7788`.
2. From a fluxvm checkout:

```bash
sudo FLUXVM_SC_RESTART_K3S=1 ./scripts/provision-secure-containers-lab.sh
```

3. Follow [secure-containers-flip-runtimeclass.md](secure-containers-flip-runtimeclass.md)
   smoke Pod **or** run:

```bash
FLUXVM_SECURE_CONTAINERS_E2E=1 \
  FLUXVM_SC_DEMO_MULTI=1 FLUXVM_SC_DEMO_SELINUX=1 FLUXVM_SC_DEMO_POLICY=1 \
  ./scripts/demo-secure-containers-wow.sh
```

4. Read the supported profile:
   [secure-containers-supported-profile.md](secure-containers-supported-profile.md).

## Cilium survival tips

- Absolute `BinaryName` for the shim (provision script writes this).
- Do **not** set `sandboxer=shim`.
- Prefer unique Pod names; delete zombie sandboxes before retries.
- Full CNI is the supported profile; `FLUXVM_CONTAINER_CNI=0` / hostNetwork is
  debug-only.

Evidence pack: [benchmarks/evidence/sc-hotcake-bundle-20260926.txt](benchmarks/evidence/sc-hotcake-bundle-20260926.txt)
(includes wow demo + CNI churn + S2 nftables re-run on 175.110.122.71).
