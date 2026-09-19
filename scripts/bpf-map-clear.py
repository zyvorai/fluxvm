#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Delete every entry of a pinned BPF map:  bpf-map-clear.py <pinned-map-path>
#
# Enumerates with `bpftool map getnext` (BTF-formatted `dump` output carries no raw
# key bytes), collects all keys first, then deletes them. Accepts both byte
# encodings bpftool -j uses ("0x0a" strings and plain ints). Used by the test
# scripts to mimic ebpf.rs, which clears fluxvm_ct on every policy change.
import json
import subprocess
import sys


def hx(b):
    return b[2:] if isinstance(b, str) else "%02x" % b


def main() -> int:
    m = sys.argv[1]
    keys, key = [], None
    while True:
        cmd = ["bpftool", "-j", "map", "getnext", "pinned", m]
        if key:
            cmd += ["key", "hex"] + key
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            break  # ENOENT after the last key
        nk = json.loads(r.stdout).get("next_key")
        if not nk:
            break
        key = [hx(x) for x in nk]
        keys.append(key)
    for k in keys:
        subprocess.run(["bpftool", "map", "delete", "pinned", m, "key", "hex"] + k, check=False)
    print("cleared %d entries from %s" % (len(keys), m), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
