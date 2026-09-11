#!/usr/bin/env python3
"""Deterministic observer sizing model; use --vms/--rules for fleet envelopes."""
import argparse, json
p=argparse.ArgumentParser(); p.add_argument('--vms',type=int,default=1000); p.add_argument('--rules',type=int,default=64); p.add_argument('--cpus',type=int,default=64); a=p.parse_args()
# Set17 prhit worst case: one allow series/rule + two miss outcomes/direction; rough exposition bytes, not RSS.
series=a.vms*(a.rules+8); exposition=series*180; map_entries=a.vms*(a.rules+4); percpu_bytes=map_entries*a.cpus*8
print(json.dumps({'vms':a.vms,'rules_per_vm':a.rules,'estimated_metric_series':series,'estimated_exposition_bytes':exposition,'estimated_percpu_counter_bytes':percpu_bytes,'note':'capacity model; measure real RSS/scrape latency on target nodes before GA'},indent=2))
