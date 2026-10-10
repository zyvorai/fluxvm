#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Minimal NBD server (fixed newstyle, one export) for live tests of `vz` NBD disks; not for real use.

Usage: scripts/nbd-test-server.py FILE PORT [EXPORT]
Serves FILE read-write on 127.0.0.1:PORT as EXPORT (default "disk"): NBD_OPT_GO / INFO / EXPORT_NAME, then
READ, WRITE, FLUSH, TRIM (ignored) and DISC. Other options are answered NBD_REP_ERR_UNSUP.
"""

import os
import socket
import struct
import sys
import threading

OPTS_MAGIC = 0x49484156454F5054  # "IHAVEOPT"
REPLY_MAGIC = 0x3E889045565A9
REQ_MAGIC = 0x25609513
SIMPLE_REPLY = 0x67446698
OPT_EXPORT_NAME, OPT_ABORT, OPT_INFO, OPT_GO = 1, 2, 6, 7
REP_ACK, REP_INFO, REP_ERR_UNSUP, REP_ERR_UNKNOWN = 1, 3, 0x80000001, 0x80000006
CMD_READ, CMD_WRITE, CMD_DISC, CMD_FLUSH, CMD_TRIM = 0, 1, 2, 3, 4
FLAG_FIXED_NEWSTYLE, FLAG_NO_ZEROES = 1, 2
TX_FLAGS = 1 | 4 | 32  # HAS_FLAGS | SEND_FLUSH | SEND_TRIM
EIO, EINVAL = 5, 22


def recv_exact(c, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return bytes(buf)


def opt_reply(c, opt, typ, data=b""):
    c.sendall(struct.pack(">QIII", REPLY_MAGIC, opt, typ, len(data)) + data)


def handle(c, path, export):
    size = os.path.getsize(path)
    c.sendall(b"NBDMAGIC" + struct.pack(">QH", OPTS_MAGIC, FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES))
    (client_flags,) = struct.unpack(">I", recv_exact(c, 4))
    while True:
        magic, opt, length = struct.unpack(">QII", recv_exact(c, 16))
        if magic != OPTS_MAGIC:
            return
        data = recv_exact(c, length)
        if opt == OPT_EXPORT_NAME:
            if data.decode() != export:
                return
            c.sendall(struct.pack(">QH", size, TX_FLAGS) + (b"" if client_flags & FLAG_NO_ZEROES else b"\0" * 124))
            break
        if opt in (OPT_INFO, OPT_GO):
            (n,) = struct.unpack(">I", data[:4])
            if data[4 : 4 + n].decode() not in (export, ""):
                opt_reply(c, opt, REP_ERR_UNKNOWN)
                continue
            opt_reply(c, opt, REP_INFO, struct.pack(">HQH", 0, size, TX_FLAGS))
            opt_reply(c, opt, REP_ACK)
            if opt == OPT_GO:
                break
            continue
        if opt == OPT_ABORT:
            opt_reply(c, opt, REP_ACK)
            return
        opt_reply(c, opt, REP_ERR_UNSUP)

    fd = os.open(path, os.O_RDWR)
    try:
        while True:
            magic, _flags, typ, cookie, offset, length = struct.unpack(">IHHQQI", recv_exact(c, 28))
            if magic != REQ_MAGIC:
                return
            if typ == CMD_WRITE:
                payload = recv_exact(c, length)
            if typ == CMD_DISC:
                return
            err, body = 0, b""
            if offset + length > size:
                err = EINVAL
            elif typ == CMD_READ:
                body = os.pread(fd, length, offset)
            elif typ == CMD_WRITE:
                os.pwrite(fd, payload, offset)
            elif typ == CMD_FLUSH:
                os.fsync(fd)
            elif typ != CMD_TRIM:
                err = EINVAL
            if err:
                body = b""
            c.sendall(struct.pack(">IIQ", SIMPLE_REPLY, err, cookie) + body)
    finally:
        os.close(fd)


def main():
    path, port = sys.argv[1], int(sys.argv[2])
    export = sys.argv[3] if len(sys.argv) > 3 else "disk"
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen()
    while True:
        c, _ = s.accept()

        def run(c=c):
            try:
                handle(c, path, export)
            except (ConnectionError, OSError):
                pass
            finally:
                c.close()

        threading.Thread(target=run, daemon=True).start()


if __name__ == "__main__":
    main()
