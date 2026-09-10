#!/usr/bin/env bash
set -euo pipefail

# Host/guest preflight for Secure Containers Set 11 security features.
# Run inside the Secure Containers guest image (or an equivalent chroot) for
# authoritative results. CHECK_SELINUX=1 makes SELinux mount-label support a
# required gate instead of an informational probe.

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }
info() { printf 'INFO: %s\n' "$*"; }

if [[ -r /proc/sys/kernel/seccomp/actions_avail ]]; then
  actions=$(cat /proc/sys/kernel/seccomp/actions_avail)
  grep -qw user_notif <<<"$actions" || fail "kernel seccomp actions do not advertise user_notif"
  pass "kernel advertises seccomp user_notif"
else
  fail "/proc/sys/kernel/seccomp/actions_avail is unavailable"
fi

command -v python3 >/dev/null || fail "python3 is required for the dynamic-library symbol probe"
python3 - <<'PY'
import ctypes
for soname, symbols in {
    "libseccomp.so.2": [
        "seccomp_notify_fd", "seccomp_notify_alloc", "seccomp_notify_free",
        "seccomp_notify_receive", "seccomp_notify_respond", "seccomp_notify_id_valid",
    ],
}.items():
    try:
        lib = ctypes.CDLL(soname)
    except OSError as exc:
        raise SystemExit(f"FAIL: cannot load {soname}: {exc}")
    missing = [name for name in symbols if not hasattr(lib, name)]
    if missing:
        raise SystemExit(f"FAIL: {soname} is missing: {', '.join(missing)}")
print("PASS: libseccomp notification API is available")
PY

if [[ "${CHECK_SELINUX:-0}" == "1" ]]; then
  python3 - <<'PY'
import ctypes
try:
    lib = ctypes.CDLL("libselinux.so.1")
except OSError as exc:
    raise SystemExit(f"FAIL: cannot load libselinux.so.1: {exc}")
lib.is_selinux_enabled.restype = ctypes.c_int
if lib.is_selinux_enabled() <= 0:
    raise SystemExit("FAIL: SELinux mountLabel requested but SELinux is not enabled")
print("PASS: SELinux and libselinux are available for mountLabel")
PY
else
  if [[ -e /sys/fs/selinux/enforce ]]; then
    info "SELinux filesystem is present; set CHECK_SELINUX=1 to make mountLabel a required gate"
  else
    info "SELinux is not detected; this is valid when OCI linux.mountLabel is not requested"
  fi
fi

pass "Secure Containers Set 11 preflight complete"
