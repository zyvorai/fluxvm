#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""Export FluxVM network-flow changes as NDJSON without extra dependencies.

This intentionally consumes the stable REST flow-map API rather than the
kernel ring buffer, so an exporter restart does not lose the current flow
state. Each line is emitted when a flow is first seen or its packet/byte/
last_seen counters advance.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Iterable


def flow_key(flow: dict[str, Any]) -> tuple[Any, ...]:
    return (
        flow.get("identity"),
        flow.get("family"),
        flow.get("source"),
        flow.get("destination"),
        flow.get("source_port"),
        flow.get("destination_port"),
        flow.get("protocol"),
        flow.get("verdict"),
    )


def flow_version(flow: dict[str, Any]) -> tuple[int, int, int]:
    return (
        int(flow.get("packets", 0)),
        int(flow.get("bytes", 0)),
        int(flow.get("last_seen_ns", 0)),
    )


def changed_flows(
    flows: Iterable[dict[str, Any]],
    seen: dict[tuple[Any, ...], tuple[int, int, int]],
) -> list[dict[str, Any]]:
    changed: list[dict[str, Any]] = []
    for flow in flows:
        key = flow_key(flow)
        version = flow_version(flow)
        if seen.get(key) != version:
            seen[key] = version
            changed.append(flow)
    return changed


def fetch_flows(base: str, vm_id: str, limit: int, token: str | None) -> list[dict[str, Any]]:
    url = f"{base.rstrip('/')}/v1/vms/{vm_id}/network/flows?limit={limit}"
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as response:
        doc = json.load(response)
    items = doc.get("items")
    if not isinstance(items, list):
        raise ValueError("FluxVM flow response does not contain an items array")
    return [x for x in items if isinstance(x, dict)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Export FluxVM flow changes as NDJSON")
    parser.add_argument("vm_id")
    parser.add_argument("--base", default="http://127.0.0.1:7788")
    parser.add_argument("--token")
    parser.add_argument("--limit", type=int, default=4096)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.limit < 1 or args.limit > 4096:
        parser.error("--limit must be 1..4096")
    if args.interval <= 0:
        parser.error("--interval must be > 0")

    seen: dict[tuple[Any, ...], tuple[int, int, int]] = {}
    while True:
        try:
            flows = fetch_flows(args.base, args.vm_id, args.limit, args.token)
        except (urllib.error.URLError, ValueError, json.JSONDecodeError) as exc:
            print(f"flux export error: {exc}", file=sys.stderr)
            if args.once:
                return 1
            time.sleep(args.interval)
            continue

        for flow in changed_flows(flows, seen):
            event = {"type": "fluxvm.network.flow", "vm_id": args.vm_id, "flow": flow}
            print(json.dumps(event, separators=(",", ":")), flush=True)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
