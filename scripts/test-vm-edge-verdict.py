#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Behavior tests for the Kairon VM-edge checks in bpf/fluxvm_tc.bpf.c
# (schema v12): anti-spoof, learn-IP, the egress token bucket, and the DNS
# and TLS SNI allow lists. Loads the real fluxvm_tc.bpf.o, writes the edge
# maps, and runs crafted frames through BPF_PROG_TEST_RUN. Root + Linux +
# bpftool, no netns and no KVM.
#
#   sudo ./scripts/test-vm-edge-verdict.py
#   FLUXVM_BPF_DIR=dist/bpf sudo ./scripts/test-vm-edge-verdict.py
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
from typing import NoReturn

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TC_ACT_OK, TC_ACT_SHOT = 0, 2
IDENTITY = 1
GUEST_MAC = bytes.fromhex("020000000001")
PEER_MAC = bytes.fromhex("020000000002")
GUEST_IP4 = "10.98.0.2"
GUEST_IP6 = "fd98::2"

ANTI_SPOOF, LEARN_IP, SNI, DNS, ROUTED = 1, 2, 4, 8, 16
ROUTER_IP4 = "10.98.0.254"
NAME_SNI, NAME_DNS = 1, 2
EXACT, SUFFIX = 1, 2
REASON = {"rate_limit": 7, "spoof_mac": 13, "spoof_ip": 14, "dns_deny": 15, "sni_deny": 16}
FAILS = 0


def say(msg):
    print("test-vm-edge-verdict: " + msg)


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
    def __init__(self, obj):
        self.dir = "/sys/fs/bpf/fvedge%d" % os.getpid()
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir + "/maps")
        self.prog = self.dir + "/prog"
        r = bpftool("prog", "load", obj, self.prog, "type", "classifier",
                    "pinmaps", self.dir + "/maps", check_rc=False)
        self.ok = r.returncode == 0
        self.log = r.stderr

    def map(self, name):
        return "%s/maps/%s" % (self.dir, name)

    def update(self, m, key, value):
        bpftool("map", "update", "pinned", self.map(m), "key", "hex", *hexb(key),
                "value", "hex", *hexb(value))

    def delete(self, m, key):
        bpftool("map", "delete", "pinned", self.map(m), "key", "hex", *hexb(key), check_rc=False)

    def dump(self, m):
        return json.loads(bpftool("-j", "map", "dump", "pinned", self.map(m)).stdout)

    def run(self, data):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data + b"\0" * max(0, 64 - len(data)))
            path = f.name
        try:
            r = bpftool("-j", "prog", "run", "pinned", self.prog, "data_in", path, "repeat", "1")
        finally:
            os.unlink(path)
        out = json.loads(r.stdout)
        out = out[0] if isinstance(out, list) else out
        return out["retval"] & 0xFFFFFFFF

    def reasons(self):
        seen = set()
        for e in self.dump("fluxvm_drop_reasons"):
            key = bytes(int(x, 16) for x in e["key"])
            seen.add(struct.unpack_from("<I", key, 44)[0])
        return seen

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def name_hash(name):
    h = 0xCBF29CE484222325
    for c in reversed(name.lower().encode()):
        h ^= c
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def edge_config(flags, mac=GUEST_MAC, ip4=GUEST_IP4, ip6=GUEST_IP6, bps=0, pps=0, router=None):
    ip4b = socket.inet_aton(ip4) if ip4 else b"\0" * 4
    ip6b = socket.inet_pton(socket.AF_INET6, ip6) if ip6 else b"\0" * 16
    rtr = socket.inet_aton(router) if router else b"\0" * 4
    return struct.pack("<I4s6s2x16sQQ4s4x", flags, ip4b, mac, ip6b, bps, pps, rtr)


# ── packet builders ─────────────────────────────────────────────────
def eth(ethertype, src=GUEST_MAC):
    return PEER_MAC + src + struct.pack("!H", ethertype)


def ipv4(proto, l4, src=GUEST_IP4, dst="10.98.0.1", mac=GUEST_MAC):
    return eth(0x0800, mac) + struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64,
                                          proto, 0, socket.inet_aton(src),
                                          socket.inet_aton(dst)) + l4


def ipv6(proto, l4, src=GUEST_IP6, dst="fd98::1"):
    return eth(0x86DD) + struct.pack("!IHBB16s16s", 6 << 28, len(l4), proto, 64,
                                     socket.inet_pton(socket.AF_INET6, src),
                                     socket.inet_pton(socket.AF_INET6, dst)) + l4


def arp(spa, sha=GUEST_MAC, mac=GUEST_MAC):
    body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2, sha, socket.inet_aton(spa),
                       PEER_MAC, socket.inet_aton("10.98.0.1"))
    return eth(0x0806, mac) + body


def udp(sport, dport, payload=b""):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, payload=b"", flags=0x18):
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 1024, 0, 0) + payload


def dns_query(name):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def client_hello(sni=None):
    exts = b""
    exts += struct.pack("!HH", 0x000a, 4) + struct.pack("!HH", 2, 0x001d)  # groups first
    if sni is not None:
        n = sni.encode()
        entry = struct.pack("!BH", 0, len(n)) + n
        exts += struct.pack("!HH", 0, len(entry) + 2) + struct.pack("!H", len(entry)) + entry
    body = (struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def run_cases(prog, cases):
    for name, pkt, allowed in cases:
        got = prog.run(pkt)
        want = TC_ACT_OK if allowed else TC_ACT_SHOT
        check(got == want, "%-50s -> %s" % (name, "allow" if allowed else "drop")
              + ("" if got == want else "  (got retval %d)" % got))


def test(bpf_dir):
    obj = os.path.join(bpf_dir, "fluxvm_tc.bpf.o")
    prog = Loaded(obj)
    try:
        if not prog.ok:
            tail = [ln for ln in prog.log.splitlines() if ln.strip()][-3:]
            check(False, "fluxvm_tc.bpf.o rejected by the verifier: " + " | ".join(tail))
            return
        check(True, "fluxvm_tc.bpf.o passes the verifier")
        lo = struct.pack("<I", socket.if_nametoindex("lo"))
        # identity=1 default_allow=1, no CIDR/L4 policy: only the edge decides.
        prog.update("fluxvm_id", lo, struct.pack("<IIIIIIQQII", IDENTITY, 1, 0, 0, 0, 0, 0, 0, 0, 0))

        print("== no edge entry: nothing is enforced ==")
        run_cases(prog, [
            ("spoofed MAC without an edge spec", ipv4(17, udp(1000, 80), mac=PEER_MAC), True),
        ])

        print("== anti-spoof ==")
        prog.update("fluxvm_edge", lo, edge_config(ANTI_SPOOF))
        run_cases(prog, [
            ("IPv4 from the assigned MAC and IP", ipv4(17, udp(1000, 80)), True),
            ("IPv4 from another MAC", ipv4(17, udp(1000, 80), mac=PEER_MAC), False),
            ("IPv4 from another source IP", ipv4(17, udp(1000, 80), src="10.98.0.9"), False),
            ("DHCP discover from 0.0.0.0", ipv4(17, udp(68, 67), src="0.0.0.0",
                                               dst="255.255.255.255"), True),
            ("UDP from 0.0.0.0 that is not DHCP", ipv4(17, udp(1000, 80), src="0.0.0.0"), False),
            ("ARP for the assigned IP", arp(GUEST_IP4), True),
            ("ARP claiming another IP", arp("10.98.0.9"), False),
            ("ARP with another sender MAC", arp(GUEST_IP4, sha=PEER_MAC), False),
            ("IPv6 from the assigned address", ipv6(17, udp(1000, 80)), True),
            ("IPv6 from another global address", ipv6(17, udp(1000, 80), src="fd98::9"), False),
            ("IPv6 from link-local", ipv6(17, udp(1000, 80), src="fe80::1"), True),
        ])
        got = prog.reasons()
        check(REASON["spoof_mac"] in got, "spoof_mac recorded in fluxvm_drop_reasons")
        check(REASON["spoof_ip"] in got, "spoof_ip recorded in fluxvm_drop_reasons")

        print("== learn-IP ==")
        prog.update("fluxvm_edge", lo, edge_config(ANTI_SPOOF | LEARN_IP, ip4=None, ip6=None))
        prog.delete("fluxvm_learn", lo)
        run_cases(prog, [
            ("IPv4 before anything is learned", ipv4(17, udp(1000, 80), src="10.98.0.8"), True),
            ("ARP announces 10.98.0.7", arp("10.98.0.7"), True),
            ("IPv4 from the learned address", ipv4(17, udp(1000, 80), src="10.98.0.7"), True),
            ("IPv4 from another address after learning",
             ipv4(17, udp(1000, 80), src="10.98.0.8"), False),
        ])
        learned = prog.dump("fluxvm_learn")
        ip4 = bytes(int(x, 16) for x in learned[0]["value"])[:4] if learned else b""
        check(ip4 == socket.inet_aton("10.98.0.7"), "fluxvm_learn holds 10.98.0.7 from ARP")

        print("== routed hook (netns VM host veth) ==")
        prog.delete("fluxvm_learn", lo)
        prog.update("fluxvm_edge", lo, edge_config(ANTI_SPOOF | ROUTED | LEARN_IP, router=ROUTER_IP4))
        run_cases(prog, [
            ("guest IPv4 behind the router's MAC", ipv4(17, udp(1000, 80), mac=PEER_MAC), True),
            ("router's own IPv4 (forwarded DNS)", ipv4(17, udp(1000, 53), src=ROUTER_IP4,
                                                       mac=PEER_MAC), True),
            ("router ARP for its gateway", arp(ROUTER_IP4, sha=PEER_MAC, mac=PEER_MAC), True),
            ("IPv4 from a third address", ipv4(17, udp(1000, 80), src="10.98.0.9",
                                               mac=PEER_MAC), False),
        ])
        check(not prog.dump("fluxvm_learn"), "routed hook does not learn from the router's ARP")

        print("== DNS allow list ==")
        prog.update("fluxvm_edge", lo, edge_config(DNS))
        prog.update("fluxvm_names", struct.pack("<IIQ", IDENTITY, NAME_DNS, name_hash("allowed.test")),
                    struct.pack("<I", EXACT))
        prog.update("fluxvm_names", struct.pack("<IIQ", IDENTITY, NAME_DNS, name_hash("example.com")),
                    struct.pack("<I", SUFFIX))
        q = lambda n: ipv4(17, udp(40000, 53, dns_query(n)))
        run_cases(prog, [
            ("query allowed.test (exact)", q("allowed.test"), True),
            ("query ALLOWED.Test (case-insensitive)", q("ALLOWED.Test"), True),
            ("query api.example.com (*.example.com)", q("api.example.com"), True),
            ("query a.b.example.com (*.example.com)", q("a.b.example.com"), True),
            ("query example.com (apex is not *.)", q("example.com"), False),
            ("query notexample.com (label boundary)", q("notexample.com"), False),
            ("query evil.test", q("evil.test"), False),
            ("query over TCP/53 for evil.test",
             ipv4(6, tcp(40000, 53, struct.pack("!H", len(dns_query("evil.test")))
                         + dns_query("evil.test"))), False),
            ("UDP to port 5353 is not checked", ipv4(17, udp(40000, 5353, dns_query("evil.test"))),
             True),
        ])
        check(REASON["dns_deny"] in prog.reasons(), "dns_deny recorded in fluxvm_drop_reasons")

        print("== TLS SNI allow list ==")
        prog.update("fluxvm_edge", lo, edge_config(SNI))
        prog.update("fluxvm_names", struct.pack("<IIQ", IDENTITY, NAME_SNI, name_hash("example.com")),
                    struct.pack("<I", SUFFIX))
        h = lambda sni: ipv4(6, tcp(40000, 443, client_hello(sni)))
        run_cases(prog, [
            ("ClientHello SNI api.example.com", h("api.example.com"), True),
            ("ClientHello SNI evil.test", h("evil.test"), False),
            ("ClientHello without server_name", h(None), False),
            ("TCP SYN to 443 (no payload)", ipv4(6, tcp(40000, 443, flags=0x02)), True),
            ("application data to 443", ipv4(6, tcp(40000, 443, b"\x17\x03\x03\x00\x05hello")),
             True),
            ("ClientHello SNI evil.test over IPv6",
             ipv6(6, tcp(40000, 443, client_hello("evil.test"))), False),
        ])
        check(REASON["sni_deny"] in prog.reasons(), "sni_deny recorded in fluxvm_drop_reasons")

        print("== egress token bucket ==")
        prog.update("fluxvm_edge", lo, edge_config(0, pps=2))
        prog.delete("fluxvm_edge_rate", lo)
        run_cases(prog, [
            ("packet 1 of a 2 pps bucket", ipv4(17, udp(1000, 80)), True),
            ("packet 2 of a 2 pps bucket", ipv4(17, udp(1000, 80)), True),
            ("packet 3 of a 2 pps bucket", ipv4(17, udp(1000, 80)), False),
        ])
        check(REASON["rate_limit"] in prog.reasons(), "rate_limit recorded in fluxvm_drop_reasons")
        tuples = [bytes(int(x, 16) for x in e["key"]) for e in prog.dump("fluxvm_drop_reasons")]
        rate = [k for k in tuples if struct.unpack_from("<I", k, 44)[0] == REASON["rate_limit"]]
        check(any(k[4:8] == socket.inet_aton(GUEST_IP4) for k in rate),
              "rate_limit drop carries the packet's source address")
    finally:
        prog.close()


def main():
    if platform.system() != "Linux":
        skip("Linux required")
    if os.geteuid() != 0:
        skip("root required for BPF_PROG_TEST_RUN")
    if not shutil.which("bpftool"):
        skip("bpftool not found")
    bpf_dir = os.environ.get("FLUXVM_BPF_DIR", os.path.join(ROOT, "dist", "bpf"))
    if not os.path.exists(os.path.join(bpf_dir, "fluxvm_tc.bpf.o")):
        skip("fluxvm_tc.bpf.o not built; run scripts/build-ebpf.sh")
    test(bpf_dir)
    if FAILS:
        say("%d check(s) failed" % FAILS)
        sys.exit(1)
    say("all checks passed")


if __name__ == "__main__":
    main()
