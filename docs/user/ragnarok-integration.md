# Using FluxVM with Ragnarok

[Ragnarok](https://zyvor.dev/ragnarok) is the primary product UI/API that consumes FluxVM’s Kubernetes path (`DisposableVm` + `fluxvm-kube`). FluxVM stays a focused disposable-VM engine; Ragnarok is the operator console, RBAC, and SSO layer on top.

## Roles

| Layer | Owns |
|-------|------|
| **FluxVM** | QEMU / Cloud Hypervisor / Firecracker VMs, TTL reaper, `fluxvm serve`, `DisposableVm` CRD + node DaemonSet |
| **Ragnarok** | KubeVirt fleet + FluxVM Hub UI/API, JWT/OIDC/LDAP auth, RBAC, audit |

Ragnarok never calls `fluxvm serve` over the host REST API from the product path — it creates/reads/deletes `DisposableVm` CRs and lets the per-node operator talk to a **local** `fluxvm serve`.

## Install order (user / lab)

0. **Optional — Ragnarok binary trial** (proprietary; FluxVM stays free):

   ```bash
   VER=0.5.1
   curl -LO "https://github.com/zyvorai/fluxvm/releases/download/ragnarok-v${VER}/ragnarok-${VER}-linux-amd64.tar.gz"
   tar xzf "ragnarok-${VER}-linux-amd64.tar.gz" && cd "ragnarok-${VER}-linux-amd64"
   ls -l trial.token    # signed evaluation token — keep beside ./ragnarok
   ./install.sh
   # edit ragnarok.env — then: set -a && source ragnarok.env && set +a && ./ragnarok
   curl -s http://127.0.0.1:5010/api/v1/license/status
   ```

   Or install Ragnarok via Helm / `deploy-remote.sh` from the private repo with
   `--set license.key=<jwt>` (same JWT as `trial.token`). After expiry:
   **sales@zyvor.dev** for a renewed token.

1. **FluxVM on capable nodes** — see `deploy/k8s/` in this repo (and [Kubernetes deployment](https://zyvor.dev/docs/fluxvm-manual/kubernetes-deployment) on the site):

   ```bash
   kubectl apply -f deploy/k8s/namespace.yaml
   kubectl apply -f deploy/k8s/crd.yaml
   kubectl apply -f deploy/k8s/rbac.yaml
   kubectl apply -f deploy/k8s/daemonset.yaml
   kubectl label node <node> ragnarok.io/fluxvm-capable=true
   # Stage VM images under the DaemonSet state_dir hostPath on each node
   ```

2. **Ragnarok** — install KubeVirt first, then Ragnarok (Helm / Kustomize / `./scripts/deploy-remote.sh`). Docs:
   - Technical: [zyvor.dev Ragnarok docs](https://zyvor.dev/docs/ragnarok)
   - User manual: [Ragnarok manual](https://zyvor.dev/docs/ragnarok-manual)
   - OIDC/SSO: Ragnarok repo `docs/OIDC.md` and deploy `--with-oidc` (IdP proxy is Ragnarok’s concern; FluxVM does not terminate SSO)

3. **Open Ragnarok UI** → **FluxVM VMs** (or Confidential / FluxVM Hub). If the operator is missing, Ragnarok shows an explicit “operator not detected” banner instead of a silent empty list.

## What Ragnarok adds

- `GET /api/v1/fluxvm/capability` — CRD present?
- `GET /api/v1/fluxvm/nodes` — nodes labeled `ragnarok.io/fluxvm-capable=true`
- CRUD under `/api/v1/fluxvm/vms` — namespace-scoped to the caller’s RBAC

No Ragnarok-specific CRD fields: anything you can `kubectl apply` as a `DisposableVm`, Ragnarok can create.

## User manuals (published)

| Product | Manual |
|---------|--------|
| FluxVM | https://zyvor.dev/docs/fluxvm-manual |
| Ragnarok | https://zyvor.dev/docs/ragnarok-manual |
| Suite index | https://zyvor.dev/docs/user-manuals |

## Auth note

**FluxVM is free** (Apache-2.0) — no Ragnarok license token applies to it.

SSO (Keycloak OIDC), local break-glass, LDAP, and the Ragnarok signed
`trial.token` / commercial JWT live entirely in **Ragnarok** (proprietary).
FluxVM’s own REST API uses optional bearer tokens for direct `fluxvm serve`
callers; that is separate from the Ragnarok dashboard login and from Ragnarok
trial tokens (`scripts/trial-tool.py` stays in the private Ragnarok repo only).

See also the longer integration notes in the [root README — Using FluxVM through Ragnarok](../../README.md#using-fluxvm-through-ragnarok).

## Operate from the console (UX)

1. Open this route from the nav or command palette and wait for live API data.
2. Use filters/search when present; drill into a row for detail.
3. For mutating actions: confirm role gates and impact before applying.
4. **Empty / fail:** Check service health, auth, and that required CRDs/backends for this domain are installed.
5. **Success:** Live data loads; created/updated objects appear without error toasts.

