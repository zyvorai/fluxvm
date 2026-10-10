#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Build the boot artifacts for FluxVM OCI sandboxes on vz:
#   oci-kernel   uncompressed arm64 Image (VZLinuxBootLoader cannot boot a compressed one)
#   oci-initrd   zstd cpio: /init (fluxvm-oci-init), /fluxvm/fluxvm-guest-agent, /fluxvm/mke2fs, /dev/console
# plus a .sha256 for each. Runs on Linux arm64 (CI: ubuntu-24.04-arm).
#
# Usage: scripts/build-oci-boot.sh [out-dir]          (default: dist/oci-boot)
# Env:   KERNEL_VERSION  kernel.org release to build (default 6.12)
#        E2FSPROGS_VERSION (default 1.47.1)
#        JOBS            parallel make jobs (default: nproc)
# Needs: build-essential flex bison bc libelf-dev libssl-dev cpio zstd xz-utils curl musl-tools,
#        rustup target aarch64-unknown-linux-musl.
#
# Install on the Mac afterwards (or publish with `fluxctl catalog add` + `catalog sign`, see docs/oci-sandboxes.md):
#   mkdir -p ~/Library/Application\ Support/FluxVM/oci/boot && cp dist/oci-boot/oci-* "$_"
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(mkdir -p "${1:-${PROJECT_DIR}/dist/oci-boot}" && cd "${1:-${PROJECT_DIR}/dist/oci-boot}" && pwd)"
KERNEL_VERSION="${KERNEL_VERSION:-6.12}"
E2FSPROGS_VERSION="${E2FSPROGS_VERSION:-1.47.1}"
JOBS="${JOBS:-$(nproc)}"
TARGET=aarch64-unknown-linux-musl
WORK="${WORK_DIR:-${PROJECT_DIR}/target/oci-boot}"
FRAGMENT="${PROJECT_DIR}/crates/fluxvm-hypervisor/guest/oci-vz.config.fragment"

[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = aarch64 ] || {
  echo "build-oci-boot.sh runs on Linux arm64 (got $(uname -s) $(uname -m))" >&2
  exit 2
}
mkdir -p "$WORK"

fetch() { # url dest
  [ -s "$2" ] && return 0
  curl -fsSL --retry 3 -o "$2.part" "$1"
  mv "$2.part" "$2"
}

# ---- kernel ----
major="${KERNEL_VERSION%%.*}"
ktar="linux-${KERNEL_VERSION}.tar.xz"
kbase="https://cdn.kernel.org/pub/linux/kernel/v${major}.x"
fetch "${kbase}/${ktar}" "${WORK}/${ktar}"
fetch "${kbase}/sha256sums.asc" "${WORK}/kernel-sha256sums.asc"
want="$(awk -v f="$ktar" '$2 == f { print $1 }' "${WORK}/kernel-sha256sums.asc")"
[ -n "$want" ] || { echo "no checksum for ${ktar} in sha256sums.asc" >&2; exit 1; }
echo "${want}  ${WORK}/${ktar}" | sha256sum -c --quiet -

ksrc="${WORK}/linux-${KERNEL_VERSION}"
[ -d "$ksrc" ] || tar -C "$WORK" -xf "${WORK}/${ktar}"
make -C "$ksrc" ARCH=arm64 KCONFIG_ALLCONFIG="$FRAGMENT" allnoconfig >/dev/null
missing=0
while IFS= read -r line; do
  case "$line" in CONFIG_*=y|CONFIG_*=[0-9]*) ;; *) continue ;; esac
  grep -qx "$line" "${ksrc}/.config" || { echo "kernel config: ${line} did not survive Kconfig" >&2; missing=1; }
done <"$FRAGMENT"
[ "$missing" = 0 ] || exit 1
make -C "$ksrc" ARCH=arm64 -j"$JOBS" Image >/dev/null
cc -O2 -o "${ksrc}/usr/gen_init_cpio" "${ksrc}/usr/gen_init_cpio.c"
install -m644 "${ksrc}/arch/arm64/boot/Image" "${OUT}/oci-kernel"

# ---- static mke2fs ----
etar="e2fsprogs-${E2FSPROGS_VERSION}.tar.xz"
ebase="https://cdn.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v${E2FSPROGS_VERSION}"
fetch "${ebase}/${etar}" "${WORK}/${etar}"
fetch "${ebase}/sha256sums.asc" "${WORK}/e2fsprogs-sha256sums.asc"
want="$(awk -v f="$etar" '$2 == f { print $1 }' "${WORK}/e2fsprogs-sha256sums.asc")"
[ -n "$want" ] || { echo "no checksum for ${etar}" >&2; exit 1; }
echo "${want}  ${WORK}/${etar}" | sha256sum -c --quiet -
esrc="${WORK}/e2fsprogs-${E2FSPROGS_VERSION}"
if [ ! -x "${esrc}/misc/mke2fs" ]; then
  [ -d "$esrc" ] || tar -C "$WORK" -xf "${WORK}/${etar}"
  (cd "$esrc" && ./configure --quiet --disable-nls --disable-fuse2fs --disable-elf-shlibs \
      --disable-debugfs --disable-imager --disable-resizer --disable-defrag --disable-e2initrd-helper \
      LDFLAGS=-static >/dev/null && make -j"$JOBS" libs >/dev/null && make -C misc mke2fs >/dev/null)
fi
file "${esrc}/misc/mke2fs" | grep -q 'statically linked' || { echo "mke2fs is not static" >&2; exit 1; }

# ---- init and agent (static musl) ----
# zstd-sys compiles C; cc-rs looks for aarch64-linux-musl-gcc, which distros ship as musl-gcc.
if [ -z "${CC_aarch64_unknown_linux_musl:-}" ] && command -v musl-gcc >/dev/null; then
  export CC_aarch64_unknown_linux_musl=musl-gcc
fi
(cd "$PROJECT_DIR" && cargo build --release --locked --target "$TARGET" -p fluxvm-oci-init -p fluxvm-guest-agent)
bin="${CARGO_TARGET_DIR:-${PROJECT_DIR}/target}/${TARGET}/release"
for b in fluxvm-oci-init fluxvm-guest-agent; do
  file "${bin}/${b}" | grep -qE 'statically linked|static-pie linked' || { echo "${b} is not static" >&2; exit 1; }
done

# ---- initramfs (gen_init_cpio: device nodes without root) ----
spec="${WORK}/initramfs.list"
cat >"$spec" <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
nod /dev/null 0666 0 0 c 1 3
dir /proc 0755 0 0
dir /sys 0755 0 0
dir /tmp 1777 0 0
dir /fluxvm 0755 0 0
dir /fluxvm/meta 0755 0 0
file /init ${bin}/fluxvm-oci-init 0755 0 0
file /fluxvm/fluxvm-guest-agent ${bin}/fluxvm-guest-agent 0755 0 0
file /fluxvm/mke2fs ${esrc}/misc/mke2fs 0755 0 0
EOF
"${ksrc}/usr/gen_init_cpio" "$spec" | zstd -q -19 -f -o "${OUT}/oci-initrd"

(cd "$OUT" && for f in oci-kernel oci-initrd; do sha256sum "$f" >"$f.sha256"; done)
echo "OCI boot artifacts in ${OUT}:"
(cd "$OUT" && ls -l oci-kernel oci-initrd && cat oci-kernel.sha256 oci-initrd.sha256)
