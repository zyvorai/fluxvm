# macOS 27 / Virtualization.framework full-stack plan

This change closes the largest correctness gap in FluxVM's macOS 27 support: `apple.custom_virtio=true` now configures an actual `VZCustomVirtioDeviceDelegateProvider`, retains its delegate, drains virtqueues, reads guest memory once per descriptor chain, writes bounded responses, and exposes a safe guest-memory mapping probe.

## What this PR implements

- **Custom Virtio host device:** device `0x3F` (`0xFF00` was wrong; see below), two queues, provider/delegate lifecycle, queue draining, bounded JSON request/response protocol, ping/echo/capabilities/stats/map-probe operations.
- **TOCTOU-safe queue handling:** every request buffer is consumed once with `readBytes(withExactLength:)`; every element is returned exactly once.
- **Guest-memory mapping plumbing:** the host can validate whether a guest physical range is mappable without leaking a host pointer.
- **vmnet broker primitives:** wrappers for Apple's supported `vmnet_network_copy_serialization` and `vmnet_network_create_with_serialization` XPC objects. These are the required primitives for the separate `fluxvm-vmnetd` process described in `docs/VMNET_BROKER.md`.
- **Cross-platform tests:** source-contract tests run in normal Linux CI; the protocol codec is Foundation-only and can be syntax/behavior tested without Virtualization.framework.
- **Hardware gate:** `scripts/macos-vz27-live-test.sh` validates the runner configuration on an Apple-silicon macOS 27 host.

## What already exists on main

FluxVM already has VZ Linux/macOS boot, IPSW restore, unattended macOS 27 account provisioning, APFS clones, DiskImageKit ASIF overlays, save/restore snapshots, warm pools, vmnet per-VM networks, NAT/bridge/private networks, TCP forwarding, virtiofs, vsock, NBD/NVMe/USB storage, USB mass-storage hotplug, displays/audio/microphone, Rosetta, nested virtualization, OCI VM sandboxes, and Apple-host placement logic.

## Explicit platform gates

Two macOS 27 capabilities cannot truthfully be declared end-to-end tested by generic CI:

1. **Physical USB passthrough.** `VZUSBPassthroughDeviceConfiguration` consumes an `AAUSBAccessory`, while `AAUSBAccessoryManager` requires a foreground UI application and user approval. FluxVM's runner is a headless helper, so production passthrough needs a small signed UI/XPC broker. Existing USB mass-storage hotplug remains independent and tested by the existing VZ device suite.
2. **Shared custom vmnet across separate runner processes.** Apple requires the network's XPC serialization object to cross process boundaries. This PR adds the correct serialization/import primitives; `fluxvm-vmnetd` still needs its signed XPC service lifecycle and a real multi-Mac hardware run before it should replace the already-working userspace private switch.

## Hardware status (2026-10-10, one Apple M4, macOS 27.2)

Recorded in full in [macos-architecture.md](macos-architecture.md#14-what-is-verified). In short:

- Verified: unit tests and clippy; `host-capabilities` on the M4; loopback fleet placement with one real node and two fake ones; the custom Virtio control queue (ping, echo, stats, capabilities) after PR #200.
- Fixed in PR #200: the device id (`0xFF00` gave PCI `1af4:0f40`, which Linux does not bind; it is now `0x3F`), `virtio_flux.c` on kernel 6.12, and the fmt gate.
- Open: the bulk queue (`bulk-test`, queue 1) hangs and even control requests hang afterwards; root cause not found.
- Blocked: `fluxvm-vmnetd` and `FluxVMUSBAccess.app` were killed at launch (SIGKILL) when ad-hoc signed with their entitlements on a SIP-on host, so two-runner vmnet sharing and physical USB attach were not run.
- Not run: placement across two real Macs.

## Test matrix

| Area | Linux CI | macOS 27 compile | macOS 27 hardware |
|---|---:|---:|---:|
| Protocol codec | yes | yes | n/a |
| Custom Virtio source contract | yes | yes | config gate |
| Queue provider/delegate | source contract | yes | required |
| Guest memory mapping probe | source contract | yes | required |
| vmnet serialization wrappers | source contract | yes | broker test required |
| ASIF overlay | existing tests | existing | existing Mac test |
| macOS provisioning | existing tests | existing | existing/manual gate |
| Physical USB Accessory Access | n/a | separate UI target needed | user-consent test needed |

Do not mark the last two brokered paths production-ready until the macOS hardware tests are recorded in the PR.
