#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Behavior tests for the Set 14 pod-policy rule matching in bpf/fluxvm_tc.bpf.c,
# written for the Linux 7.x verifier fix: the rule scan and prefix match were
# restructured (global per-rule function, branch-free prefix compare) so the
# egress program fits the verifier's 1,000,000-insn limit. Root + Linux + bpftool,
# no netns and no KVM (BPF_PROG_TEST_RUN).
#
#   1. prefix-match equivalence: the ORIGINAL implementation (kept verbatim in
#      bpf/tests/prefix_match_equiv.bpf.c) vs the shipped one vs a Python
#      reference, over every prefix length for many address pairs, both families.
#   2. rule-scan verdicts: the REAL fluxvm_tc.bpf.o is loaded, real pod rules are
#      written, crafted IPv4/IPv6 packets are run through it, and the verdicts
#      are compared with what the rule semantics require (partial-byte prefixes
#      such as /12 and /45, protocol and port filters, /0, /32, both families).
#
#   sudo ./scripts/test-pod-policy-verdict.py
#   FLUXVM_BPF_DIR=dist/bpf sudo ./scripts/test-pod-policy-verdict.py
import os
import platform
import random
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from typing import NoReturn

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TC_ACT_OK, TC_ACT_SHOT = 0, 2
POD = 7
FAILS = 0


def say(msg):
    print("test-pod-policy-verdict: " + msg)


def skip(msg) -> NoReturn:
    say("SKIP: " + msg)
    sys.exit(0)


def check(ok, msg):
    global FAILS
    if ok:
        print("  ✅ " + msg)
    else:
        FAILS += 1
        print("  ❌ " + msg, file=sys.stderr)


def hexb(b):
    return ["%02x" % x for x in b]


def bpftool(*args, check_rc=True):
    r = subprocess.run(["bpftool", *args], capture_output=True, text=True)
    if check_rc and r.returncode != 0:
        raise RuntimeError("bpftool %s failed: %s" % (" ".join(args), r.stderr.strip()[-600:]))
    return r


class Loaded:
    """A pinned classifier program plus its pinned maps."""

    def __init__(self, obj, name):
        self.dir = "/sys/fs/bpf/fvpp%d_%s" % (os.getpid(), name)
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir + "/maps")
        self.prog = self.dir + "/prog"
        r = bpftool("-d", "prog", "load", obj, self.prog, "type", "classifier",
                    "pinmaps", self.dir + "/maps", check_rc=False)
        self.ok = r.returncode == 0
        self.log = r.stderr
        self.processed = None
        for line in r.stderr.splitlines():
            if line.startswith("processed ") and " insns" in line:
                self.processed = int(line.split()[1])

    def update(self, m, key, value):
        bpftool("map", "update", "pinned", "%s/maps/%s" % (self.dir, m),
                "key", "hex", *hexb(key), "value", "hex", *hexb(value))

    def run(self, data):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            path = f.name
        try:
            r = bpftool("-j", "prog", "run", "pinned", self.prog, "data_in", path, "repeat", "1")
        finally:
            os.unlink(path)
        import json
        out = json.loads(r.stdout)
        out = out[0] if isinstance(out, list) else out
        return out["retval"] & 0xFFFFFFFF

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


# ── packet builders ─────────────────────────────────────────────────
def eth(ethertype):
    return bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + struct.pack("!H", ethertype)


def ipv4(proto, dst, l4):
    return eth(0x0800) + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0,
                                     socket.inet_aton("10.98.0.2"), socket.inet_aton(dst)) + l4


def ipv6(proto, dst, l4):
    return eth(0x86DD) + struct.pack("!IHBB16s16s", 6 << 28, len(l4), proto, 64,
                                     socket.inet_pton(socket.AF_INET6, "fd98::2"),
                                     socket.inet_pton(socket.AF_INET6, dst)) + l4


def tcp(sport, dport):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x02, 1024, 0, 0)


def udp(sport, dport):
    return struct.pack("!HHHH", sport, dport, 8, 0)


def pad(p):
    return p + b"\0" * max(0, 64 - len(p))


# ── 1. prefix-match equivalence ─────────────────────────────────────
def ref_match(pkt, net, bits, fam):
    if bits > (32 if fam == 4 else 128):
        return False
    full, rem = bits >> 3, bits & 7
    if pkt[:full] != net[:full]:
        return False
    if rem == 0:
        return True
    mask = (0xFF << (8 - rem)) & 0xFF
    return (pkt[full] & mask) == (net[full] & mask)


def test_prefix_equivalence(clang_cflags):
    print("== 1. prefix-match: original vs shipped vs reference ==")
    work = tempfile.mkdtemp(prefix="fvpp-equiv.")
    try:
        obj = os.path.join(work, "equiv.bpf.o")
        r = subprocess.run(["clang", *clang_cflags, "-c",
                            os.path.join(ROOT, "bpf/tests/prefix_match_equiv.bpf.c"), "-o", obj],
                           capture_output=True, text=True)
        if r.returncode != 0:
            check(False, "oracle object failed to compile: " + r.stderr.strip()[-400:])
            return
        prog = Loaded(obj, "equiv")
        try:
            if not prog.ok:
                check(False, "oracle object rejected by the verifier: " + prog.log.strip()[-500:])
                return
            rnd = random.Random(0xF1C5)
            base = bytes(rnd.getrandbits(8) for _ in range(16))
            pairs = [(base, base), (bytes(16), bytes(16)), (b"\xff" * 16, b"\xff" * 16),
                     (bytes(16), b"\xff" * 16)]
            for k in range(128):  # one flipped bit at every position: exercises every boundary
                n = bytearray(base)
                n[k // 8] ^= 0x80 >> (k % 8)
                pairs.append((base, bytes(n)))
            for _ in range(40):
                pairs.append((bytes(rnd.getrandbits(8) for _ in range(16)),
                              bytes(rnd.getrandbits(8) for _ in range(16))))
            bad, runs, total_matches = 0, 0, 0
            for pkt, net in pairs:
                for fam in (4, 6):
                    r = prog.run(pkt + net + bytes([fam]) + b"\0" * 31)
                    disagree, matches = r & 0xFFFF, r >> 16
                    expect = sum(ref_match(pkt, net, b, fam) for b in range(256))
                    runs += 1
                    total_matches += matches
                    if disagree != 0 or matches != expect:
                        bad += 1
                        if bad <= 3:
                            print("     mismatch fam=%d pkt=%s net=%s disagree=%d matches=%d expect=%d"
                                  % (fam, pkt.hex(), net.hex(), disagree, matches, expect), file=sys.stderr)
            check(bad == 0, "shipped == original == reference on %d inputs x 256 prefix lengths "
                            "(%d matching cases seen, so the check is not vacuous)" % (runs, total_matches))
            check(total_matches > 1000, "oracle produced plenty of matches (%d)" % total_matches)
        finally:
            prog.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ── 2. real-object rule-scan verdicts ───────────────────────────────
RULES = [
    # (dir, family, proto, prefix_len, port_start, port_end, address)
    (1, 4, 0, 12, 0, 0, "10.96.0.0"),          # 0: any proto, /12 = partial byte
    (1, 4, 6, 24, 443, 443, "192.168.5.0"),    # 1: TCP/443 only
    (1, 4, 17, 32, 0, 0, "172.16.0.1"),        # 2: UDP any port, exact host
    (1, 6, 0, 32, 0, 0, "fd00:1::"),           # 3: any proto, byte-aligned v6
    (1, 6, 6, 45, 8000, 8100, "2001:db8:1234::"),  # 4: TCP 8000-8100, /45 = partial byte
    (1, 4, 17, 0, 53, 53, "0.0.0.0"),          # 5: UDP/53 to anywhere (/0)
]


def rule_bytes(r):
    d, fam, proto, plen, ps, pe, addr = r
    a = socket.inet_pton(socket.AF_INET if fam == 4 else socket.AF_INET6, addr)
    return struct.pack("<IBBBBHH16s", POD, d, fam, proto, plen, ps, pe, a.ljust(16, b"\0"))


CASES = [
    # (name, packet, allowed)
    ("v4 udp 10.96.1.1 (in /12)",        ipv4(17, "10.96.1.1", udp(1001, 9)), True),
    ("v4 udp 10.111.255.255 (last in /12)", ipv4(17, "10.111.255.255", udp(1002, 9)), True),
    ("v4 udp 10.112.0.1 (just past /12)", ipv4(17, "10.112.0.1", udp(1003, 9)), False),
    ("v4 udp 10.95.255.255 (just before /12)", ipv4(17, "10.95.255.255", udp(1004, 9)), False),
    ("v4 udp 11.96.0.1 (first octet differs)", ipv4(17, "11.96.0.1", udp(1005, 9)), False),
    ("v4 tcp 192.168.5.9:443",           ipv4(6, "192.168.5.9", tcp(1006, 443)), True),
    ("v4 tcp 192.168.5.9:444 (port miss)", ipv4(6, "192.168.5.9", tcp(1007, 444)), False),
    ("v4 tcp 192.168.6.9:443 (prefix miss)", ipv4(6, "192.168.6.9", tcp(1008, 443)), False),
    ("v4 udp 192.168.5.9:443 (proto miss)", ipv4(17, "192.168.5.9", udp(1009, 443)), False),
    ("v4 udp 172.16.0.1 (/32 exact)",    ipv4(17, "172.16.0.1", udp(1010, 9)), True),
    ("v4 udp 172.16.0.2 (/32 miss)",     ipv4(17, "172.16.0.2", udp(1011, 9)), False),
    ("v4 udp 8.8.8.8:53 (/0 + port)",    ipv4(17, "8.8.8.8", udp(1012, 53)), True),
    ("v4 udp 8.8.8.8:54 (/0, port miss)", ipv4(17, "8.8.8.8", udp(1013, 54)), False),
    ("v6 tcp fd00:1::5 (byte-aligned /32)", ipv6(6, "fd00:1::5", tcp(1014, 80)), True),
    ("v6 udp fd00:1::5 (any proto)",     ipv6(17, "fd00:1::5", udp(1015, 80)), True),
    ("v6 tcp fd00:2::5 (miss)",          ipv6(6, "fd00:2::5", tcp(1016, 80)), False),
    ("v6 tcp fd01:1::5 (miss)",          ipv6(6, "fd01:1::5", tcp(1017, 80)), False),
    ("v6 tcp 2001:db8:1234::1:8050 (/45 in)", ipv6(6, "2001:db8:1234::1", tcp(1018, 8050)), True),
    ("v6 tcp 2001:db8:1237:ffff::1:8050 (last in /45)", ipv6(6, "2001:db8:1237:ffff::1", tcp(1019, 8050)), True),
    ("v6 tcp 2001:db8:1238::1:8050 (just past /45)", ipv6(6, "2001:db8:1238::1", tcp(1020, 8050)), False),
    ("v6 tcp 2001:db8:122f::1:8050 (just before /45)", ipv6(6, "2001:db8:122f::1", tcp(1021, 8050)), False),
    ("v6 tcp 2001:db8:1234::1:7999 (port low)", ipv6(6, "2001:db8:1234::1", tcp(1022, 7999)), False),
    ("v6 tcp 2001:db8:1234::1:8101 (port high)", ipv6(6, "2001:db8:1234::1", tcp(1023, 8101)), False),
]


def test_rule_scan(bpf_dir):
    print("== 2. real fluxvm_tc.bpf.o: pod rule-scan verdicts ==")
    obj = os.path.join(bpf_dir, "fluxvm_tc.bpf.o")
    prog = Loaded(obj, "tc")
    try:
        if not prog.ok:
            tail = [ln for ln in prog.log.splitlines() if ln.strip()][-3:]
            check(False, "real fluxvm_tc.bpf.o rejected by this kernel's verifier: " + " | ".join(tail))
            return
        check(True, "real fluxvm_tc.bpf.o passes the verifier (%s insns processed)"
                    % (prog.processed if prog.processed is not None else "?"))
        lo = socket.if_nametoindex("lo")
        # identity=1 default_allow=1 no cidr/l4 enforcement, pod_id=POD -> the pod verdict decides
        prog.update("fluxvm_id", struct.pack("<I", lo),
                    struct.pack("<IIIIIIQQII", 1, 1, 0, 0, 0, 0, 0, 0, POD, 0))
        flags = (1 << 0) | (1 << 3) | (1 << 4)  # ENABLED | RICH_RULES | EGRESS_ISOLATED
        prog.update("fluxvm_pspol", struct.pack("<I", POD), struct.pack("<IIII", flags, len(RULES), 0, 0))
        masks = {}
        for i, r in enumerate(RULES):
            prog.update("fluxvm_prules", struct.pack("<I", i), rule_bytes(r))
            masks[(r[0], r[1], r[2])] = masks.get((r[0], r[1], r[2]), 0) | (1 << i)
        for (d, fam, proto), mask in masks.items():
            prog.update("fluxvm_pridx", struct.pack("<IBBBB", POD, d, fam, proto, 0), struct.pack("<Q", mask))
        for name, pkt, allowed in CASES:
            got = prog.run(pad(pkt))
            want = TC_ACT_OK if allowed else TC_ACT_SHOT
            check(got == want, "%-52s -> %s" % (name, "allow" if allowed else "deny")
                  + ("" if got == want else "  (got retval %d, want %d)" % (got, want)))
    finally:
        prog.close()


def main():
    if platform.system() != "Linux":
        skip("Linux required")
    if os.geteuid() != 0:
        skip("root required (run with sudo)")
    if not shutil.which("bpftool"):
        skip("bpftool not found")
    r = subprocess.run(["findmnt", "-n", "-o", "FSTYPE", "/sys/fs/bpf"], capture_output=True, text=True)
    if r.stdout.strip() != "bpf":
        skip("bpffs is not mounted at /sys/fs/bpf")
    if not shutil.which("clang"):
        skip("clang not found")

    arch = {"x86_64": "x86", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        skip("unsupported architecture " + platform.machine())
    cflags = ["-target", "bpf", "-O2", "-g", "-Wall", "-Werror", "-D__TARGET_ARCH_" + arch]
    if shutil.which("gcc"):
        multi = subprocess.run(["gcc", "-print-multiarch"], capture_output=True, text=True).stdout.strip()
        if multi and os.path.isdir("/usr/include/" + multi):
            cflags.append("-I/usr/include/" + multi)

    bpf_dir = os.environ.get("FLUXVM_BPF_DIR")
    tmp = None
    if not bpf_dir:
        tmp = tempfile.mkdtemp(prefix="fvpp-bpf.")
        b = subprocess.run(["bash", os.path.join(ROOT, "scripts/build-ebpf.sh"), tmp],
                           capture_output=True, text=True)
        if b.returncode != 0:
            say("FAIL: build-ebpf.sh: " + b.stderr.strip()[-400:])
            sys.exit(1)
        bpf_dir = tmp
    try:
        test_prefix_equivalence(cflags)
        test_rule_scan(bpf_dir)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    print()
    if FAILS == 0:
        print("🎉 pod policy verdict test PASS")
    else:
        print("pod policy verdict test: %d FAILED" % FAILS, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
