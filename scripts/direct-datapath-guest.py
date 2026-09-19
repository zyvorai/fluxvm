#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Minimal "guest" for scripts/test-direct-datapath.sh: attaches to an existing
# tap and answers ARP requests and ICMP echo for one IPv4 address, standing in
# for a VM's virtio-net so the redirect path can be exercised with no KVM.
#
#   direct-datapath-guest.py <tap|fd:N> <guest-ip> <guest-mac> <stats-file> [ping=<ip>]
#
# The stats file is rewritten after every handled frame as key=value lines
# (rx_frames, arp_replies, icmp_replies, echo_sent, echo_replies_rx) so the test can assert on them.
# With ping=<ip> the guest also INITIATES traffic: it ARPs for that address, learns its MAC and then
# sends ICMP echo requests, counting the replies (guest -> LAN and guest <-> guest tests).
import fcntl
import os
import select
import socket
import struct
import sys
import time

TUNSETIFF = 0x400454CA
IFF_TAP, IFF_NO_PI = 0x0002, 0x1000


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def open_tap(name: str) -> int:
    # "fd:N" adopts a tap fd inherited from the parent -- exactly how QEMU receives a direct
    # tap that lives in a foreign netns. The fd is already bound to that namespace, so this
    # process never has to enter it.
    if name.startswith("fd:"):
        return int(name[3:])
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH22x", name.encode(), IFF_TAP | IFF_NO_PI))
    return fd


def main() -> None:
    tap, ip_s, mac_s, stats_path = sys.argv[1:5]
    # A tap adopted by fd is the daemon's direct tap, opened with IFF_VNET_HDR (so a real VMM can
    # negotiate checksum/TSO offloads): every frame read or written carries a 10-byte
    # virtio_net_hdr. A tap opened by name here has no such header.
    vnet = 10 if tap.startswith("fd:") else 0
    gip = socket.inet_aton(ip_s)
    gmac = bytes.fromhex(mac_s.replace(":", ""))
    target = None
    for extra in sys.argv[5:]:
        if extra.startswith("ping="):
            target = socket.inet_aton(extra[5:])
    stats = {"rx_frames": 0, "arp_replies": 0, "icmp_replies": 0, "echo_sent": 0, "echo_replies_rx": 0}
    target_mac = None
    seq = 0
    last_tx = 0.0
    fd = open_tap(tap)

    def flush() -> None:
        tmp = stats_path + ".tmp"
        with open(tmp, "w") as f:
            f.writelines("%s=%d\n" % kv for kv in stats.items())
        os.replace(tmp, stats_path)

    def send_arp_request() -> None:
        pkt = (
            b"\xff" * 6 + gmac + b"\x08\x06"
            + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
            + gmac + gip + b"\0" * 6 + target
        )
        os.write(fd, b"\0" * vnet + pkt)

    def send_echo_request() -> None:
        nonlocal seq
        seq += 1
        icmp = bytearray(struct.pack("!BBHHH", 8, 0, 0, 0x4655, seq) + b"fluxvm-direct-datapath")
        struct.pack_into("!H", icmp, 2, checksum(bytes(icmp)))
        iph = bytearray(20)
        iph[0] = 0x45
        struct.pack_into("!H", iph, 2, 20 + len(icmp))
        iph[8], iph[9] = 64, 1
        iph[12:16], iph[16:20] = gip, target
        struct.pack_into("!H", iph, 10, checksum(bytes(iph)))
        os.write(fd, b"\0" * vnet + target_mac + gmac + b"\x08\x00" + bytes(iph) + bytes(icmp))
        stats["echo_sent"] += 1

    flush()
    while True:
        if target is not None and time.monotonic() - last_tx > 0.3:
            last_tx = time.monotonic()
            if target_mac is None:
                send_arp_request()
            else:
                send_echo_request()
            flush()
        if not select.select([fd], [], [], 0.1)[0]:
            continue
        frame = os.read(fd, 65535)[vnet:]
        stats["rx_frames"] += 1
        if len(frame) >= 14:
            src, etype = frame[6:12], struct.unpack("!H", frame[12:14])[0]
            if etype == 0x0806 and len(frame) >= 42:  # ARP
                op = struct.unpack("!H", frame[20:22])[0]
                sha, spa, tpa = frame[22:28], frame[28:32], frame[38:42]
                if op == 2 and target is not None and spa == target and tpa == gip:
                    target_mac = sha  # learned the peer's MAC from its reply
                if op == 1 and tpa == gip:
                    reply = (
                        src + gmac + b"\x08\x06"
                        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
                        + gmac + gip + sha + spa
                    )
                    os.write(fd, b"\0" * vnet + reply)
                    stats["arp_replies"] += 1
            elif etype == 0x0800 and len(frame) >= 34:  # IPv4
                ihl = (frame[14] & 0x0F) * 4
                if frame[23] == 1 and frame[30:34] == gip and frame[14 + ihl] == 0:
                    stats["echo_replies_rx"] += 1
                if frame[23] == 1 and frame[30:34] == gip and frame[14 + ihl] == 8:
                    ip_src = frame[26:30]
                    icmp = bytearray(frame[14 + ihl:])
                    icmp[0], icmp[2], icmp[3] = 0, 0, 0
                    struct.pack_into("!H", icmp, 2, checksum(bytes(icmp)))
                    iph = bytearray(20)
                    iph[0] = 0x45
                    struct.pack_into("!H", iph, 2, 20 + len(icmp))
                    iph[8], iph[9] = 64, 1
                    iph[12:16], iph[16:20] = gip, ip_src
                    struct.pack_into("!H", iph, 10, checksum(bytes(iph)))
                    os.write(fd, b"\0" * vnet + src + gmac + b"\x08\x00" + bytes(iph) + bytes(icmp))
                    stats["icmp_replies"] += 1
        flush()


if __name__ == "__main__":
    main()
