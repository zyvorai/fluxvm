# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Builds one image with two entrypoints: `fluxvm serve` (the VMM control
# plane REST API) and `fluxvm-kube` (the DisposableVm operator). They run
# as two containers in the same DaemonSet pod — see deploy/k8s/daemonset.yaml
# — sharing this image, selected via each container's `command:`.
#
# fluxvm-image depends on the sibling `guestkit` repo via a relative path
# (`../../../guestkit` from crates/fluxvm-image — see its Cargo.toml), so
# this build needs guestkit supplied as an additional build context, the same
# way .github/workflows/ci.yml checks it out as a sibling directory. Build
# with BuildKit's named build-context support (Docker >= 20.10 / buildx):
#
#   docker buildx build \
#     --build-context guestkit=../guestkit \
#     -t fluxvm:latest .
#
# (run from the FluxVM repo root, with guestkit checked out as its usual
# sibling at ../guestkit — matching every other path in this repo that
# assumes that layout).

FROM docker.io/library/rust:1.89-bookworm AS builder

# guestkit's default feature set pulls in libsystemd-sys (journal-native
# logging), which needs libsystemd-dev's pkg-config file to build — this
# repo's own CI hits and works around the exact same gap (see
# .github/workflows/ci.yml).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsystemd-dev libhivex-dev pkg-config clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . ./fluxvm
COPY --from=guestkit . ./guestkit

WORKDIR /build/fluxvm
RUN cargo build --locked --release -p fluxvm-cli -p fluxvm-kube -p fluxvm-hypervisor
RUN ./scripts/build-ebpf.sh

FROM docker.io/library/debian:bookworm-slim AS runtime

# qemu-system-x86 / qemu-utils / cloud-image-utils: QEMU backend + qcow2
# tooling + cloud-localds (NoCloud seed generation).
# iproute2 / dnsmasq: TAP/bridge setup and per-VM-netns DHCP.
# python3: scripts/install-{cloud-hypervisor,firecracker}.sh parse the
# GitHub Releases API response with it (see those scripts).
# ca-certificates / curl: release-asset download + SHA-256 verification.
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-system-x86 qemu-utils cloud-image-utils iproute2 dnsmasq nftables bpftool \
    python3 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/install-cloud-hypervisor.sh scripts/install-firecracker.sh /tmp/
RUN bash /tmp/install-cloud-hypervisor.sh \
    && bash /tmp/install-firecracker.sh \
    && rm -f /tmp/install-cloud-hypervisor.sh /tmp/install-firecracker.sh

COPY --from=builder /build/fluxvm/target/release/fluxvm /usr/local/bin/fluxvm
COPY --from=builder /build/fluxvm/target/release/fluxvm-kube /usr/local/bin/fluxvm-kube
COPY --from=builder /build/fluxvm/target/release/fluxvm-hypervisor /usr/local/bin/fluxvm-hypervisor
COPY --from=builder /build/fluxvm/dist/bpf/fluxvm_tc.bpf.o /usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o
COPY --from=builder /build/fluxvm/dist/bpf/fluxvm_xdp.bpf.o /usr/lib/fluxvm/bpf/fluxvm_xdp.bpf.o

ENTRYPOINT []
