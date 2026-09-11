#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""FluxVM Sentinel GA certification and recovery helper.

Stdlib-only by design. It never loads or replaces a BPF program. Mutation is
limited to stale directories that contain a FluxVM ownership manifest created
by this tool or a FluxVM service using the same manifest contract.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable

SCHEMA_VERSION = 1
OWNER_MAGIC = "zyvor-fluxvm-sentinel-state-v1"
DEFAULT_BPF_ROOT = pathlib.Path("/sys/fs/bpf/fluxvm")
DEFAULT_RUN_ROOT = pathlib.Path("/run/fluxvm")


def _run(argv: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    try:
        p = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def _which(name: str) -> bool:
    return shutil.which(name) is not None


def _read(path: pathlib.Path) -> str:
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return ""


def _kernel_version_tuple() -> tuple[int, int, int]:
    raw = platform.release().split("-", 1)[0]
    parts: list[int] = []
    for p in raw.split(".")[:3]:
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)  # type: ignore[return-value]


def probe_capabilities() -> dict[str, Any]:
    lsm = _read(pathlib.Path("/sys/kernel/security/lsm"))
    sched_ext = pathlib.Path("/sys/kernel/sched_ext").exists()
    if not sched_ext:
        rc, out, _ = _run(["grep", "-q", "CONFIG_SCHED_CLASS_EXT=y", "/boot/config-" + platform.release()])
        sched_ext = rc == 0
    # TCX kernel support: `bpftool feature probe` does not report it at all,
    # in any mode (full or unprivileged) or privilege level -- confirmed
    # empirically against a real kernel that does support TCX (this
    # session's own crates/fluxvm-network/src/tcx.rs relies on it via
    # tools/fluxvm-tcx.c's bpf_link_create(BPF_TCX_*)). The substring check
    # this probe originally used would therefore always report `False`,
    # unconditionally, on every host. Use the same kernel-version-heuristic
    # pattern already established below for `af_xdp` instead: TCX merged in
    # Linux 6.6.
    tcx = _kernel_version_tuple() >= (6, 6, 0)
    xdp = False
    bpftool_feature: dict[str, Any] | None = None
    bpftool_feature_error: str | None = None
    if _which("bpftool"):
        # A non-root caller gets a nonzero exit (confirmed empirically:
        # `rc=255`) plus a `{"error": "missing CAP_..."}` body on stdout, so
        # the `rc == 0` guard below already keeps that case out of the
        # blob-parsing path -- `xdp` correctly stays at its conservative
        # `False` default (fail-closed for `gate`) rather than claiming a
        # check that could not actually run. The `"error"` key check just
        # below is defensive for the same shape appearing with rc=0 on a
        # different bpftool version/build (the CLI does document a
        # separate `unprivileged` probe mode that behaves differently); it
        # is not known to trigger on the host this was validated against.
        rc, out, _ = _run(["bpftool", "feature", "probe", "kernel", "-j"], timeout=10)
        if rc == 0:
            try:
                parsed = json.loads(out)
                if isinstance(parsed, dict) and "error" in parsed and len(parsed) == 1:
                    bpftool_feature_error = str(parsed["error"])
                elif isinstance(parsed, dict):
                    bpftool_feature = parsed
                    xdp = bool(parsed.get("program_types", {}).get("have_xdp_prog_type", False))
            except json.JSONDecodeError:
                pass
    cgroup2 = pathlib.Path("/sys/fs/cgroup/cgroup.controllers").exists()
    bpffs = False
    if pathlib.Path("/sys/fs/bpf").exists():
        rc, out, _ = _run(["findmnt", "-n", "-o", "FSTYPE", "/sys/fs/bpf"])
        bpffs = rc == 0 and out == "bpf"
    af_xdp = pathlib.Path("/proc/net/xdp").exists() or _kernel_version_tuple() >= (4, 18, 0)
    caps = {
        "cgroup_v2": cgroup2,
        "bpffs": bpffs,
        "kernel_btf": pathlib.Path("/sys/kernel/btf/vmlinux").exists(),
        "bpf_lsm": "bpf" in {x.strip() for x in lsm.split(",") if x.strip()},
        "tcx": tcx,
        "xdp": xdp,
        "sched_ext": sched_ext,
        "af_xdp": af_xdp,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "capabilities": caps,
        "tools": {name: _which(name) for name in ["bpftool", "clang", "llc", "tc", "ip", "ethtool", "fio", "iperf3", "jq", "systemctl"]},
        "lsm": lsm,
        "bpftool_feature": bpftool_feature,
        "bpftool_feature_error": bpftool_feature_error,
    }


def load_json(path: pathlib.Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def evaluate(profile: str, budgets_path: pathlib.Path, measurements_path: pathlib.Path | None,
             require_all_metrics: bool = False) -> dict[str, Any]:
    budgets_doc = load_json(budgets_path)
    if budgets_doc.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported budget schema {budgets_doc.get('schema_version')}")
    profiles = budgets_doc.get("profiles", {})
    if profile not in profiles:
        raise ValueError(f"unknown profile {profile!r}; choose one of {', '.join(sorted(profiles))}")
    cfg = profiles[profile]
    probe = probe_capabilities()
    caps = probe["capabilities"]
    cap_results = []
    for name in cfg.get("required_capabilities", []):
        cap_results.append({"name": name, "required": True, "present": bool(caps.get(name, False)), "pass": bool(caps.get(name, False))})
    for name in cfg.get("optional_capabilities", []):
        cap_results.append({"name": name, "required": False, "present": bool(caps.get(name, False)), "pass": True})

    measurements: dict[str, Any] = {}
    metadata: dict[str, Any] = {}
    if measurements_path:
        mdoc = load_json(measurements_path)
        if mdoc.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"unsupported measurement schema {mdoc.get('schema_version')}")
        measurements = mdoc.get("metrics", {})
        metadata = mdoc.get("metadata", {})

    metric_results = []
    for name, rule in cfg.get("budgets", {}).items():
        if name not in measurements:
            metric_results.append({"name": name, "status": "missing", "pass": not require_all_metrics, "rule": rule})
            continue
        value = float(measurements[name])
        passed = True
        if "max" in rule:
            passed = passed and value <= float(rule["max"])
        if "min" in rule:
            passed = passed and value >= float(rule["min"])
        metric_results.append({"name": name, "status": "pass" if passed else "fail", "pass": passed, "value": value, "rule": rule})

    passed = all(x["pass"] for x in cap_results) and all(x["pass"] for x in metric_results)
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": profile,
        "pass": passed,
        "probe": probe,
        "measurement_metadata": metadata,
        "capabilities": cap_results,
        "metrics": metric_results,
    }


def _pid_alive(pid: int) -> bool:
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


DEFAULT_MANIFEST_ROOT = DEFAULT_RUN_ROOT / "sentinel-owners"


def _iter_manifests(manifest_root: pathlib.Path) -> Iterable[pathlib.Path]:
    if not manifest_root.exists():
        return []
    return manifest_root.glob("**/.fluxvm-owner.json")


def _target_for_manifest(manifest_path: pathlib.Path, manifest_root: pathlib.Path, target_root: pathlib.Path) -> pathlib.Path:
    rel = manifest_path.parent.resolve().relative_to(manifest_root.resolve())
    return target_root / rel


def _manifest_path_for(target: pathlib.Path, target_root: pathlib.Path, manifest_root: pathlib.Path) -> pathlib.Path:
    rel = target.resolve().relative_to(target_root.resolve())
    return manifest_root / rel / ".fluxvm-owner.json"


def reconcile(target_root: pathlib.Path, *, manifest_root: pathlib.Path = DEFAULT_MANIFEST_ROOT,
              min_age_seconds: int, dry_run: bool) -> dict[str, Any]:
    # bpffs (the real target_root in production, e.g. /sys/fs/bpf/fluxvm) has
    # no create() for regular files -- confirmed on a real kernel: `mkdir`
    # and BPF-object pins (via bpf_obj_pin) both work, but a plain
    # open(O_CREAT)/write() into a bpffs directory fails EPERM. Ownership
    # manifests therefore live in a mirrored tree under manifest_root (a
    # normal writable filesystem, /run/fluxvm by default -- see
    # crates/fluxvm-network/src/ebpf.rs's own vm_meta_dir()/DEFAULT_RUN_ROOT
    # for the exact same constraint already handled this way elsewhere in
    # FluxVM), preserving target_root-relative paths so a manifest at
    # `<manifest_root>/vms/<uuid>/.fluxvm-owner.json` tracks the real bpffs
    # directory `<target_root>/vms/<uuid>`.
    now = time.time()
    actions: list[dict[str, Any]] = []
    for manifest_path in _iter_manifests(manifest_root):
        try:
            raw = load_json(manifest_path)
        except (OSError, json.JSONDecodeError) as exc:
            actions.append({"manifest": str(manifest_path), "action": "skip", "reason": f"invalid manifest: {exc}"})
            continue
        if raw.get("owner_magic") != OWNER_MAGIC:
            actions.append({"manifest": str(manifest_path), "action": "skip", "reason": "ownership magic mismatch"})
            continue
        pid = int(raw.get("owner_pid", 0) or 0)
        created = float(raw.get("created_unix", 0) or 0)
        age = max(0.0, now - created) if created else 0.0
        if _pid_alive(pid):
            actions.append({"manifest": str(manifest_path), "action": "keep", "reason": f"pid {pid} alive"})
            continue
        if not created or age < min_age_seconds:
            actions.append({"manifest": str(manifest_path), "action": "keep", "reason": f"age {age:.0f}s below threshold"})
            continue
        try:
            target = _target_for_manifest(manifest_path, manifest_root, target_root)
        except ValueError:
            actions.append({"manifest": str(manifest_path), "action": "skip", "reason": "manifest escaped manifest_root"})
            continue
        if dry_run:
            actions.append({"manifest": str(manifest_path), "target": str(target), "action": "would-remove", "reason": f"dead pid {pid}, age {age:.0f}s"})
            continue
        try:
            # bpffs pins are unlinkable files; directories are removed
            # bottom-up. The target directory may already be gone (removed
            # by some other path) -- that is not an error, only a no-op.
            if target.exists():
                for p in sorted(target.rglob("*"), key=lambda x: len(x.parts), reverse=True):
                    try:
                        p.unlink() if p.is_file() or p.is_symlink() else p.rmdir()
                    except OSError:
                        pass
                target.rmdir()
            manifest_path.unlink(missing_ok=True)
            # Prune now-empty manifest-mirror parent directories up to (but
            # not including) manifest_root, so a long-lived reconciler
            # doesn't accumulate empty directories forever.
            parent = manifest_path.parent
            while parent != manifest_root and parent.exists() and not any(parent.iterdir()):
                parent.rmdir()
                parent = parent.parent
            actions.append({"manifest": str(manifest_path), "target": str(target), "action": "removed", "reason": f"dead pid {pid}, age {age:.0f}s"})
        except OSError as exc:
            actions.append({"manifest": str(manifest_path), "target": str(target), "action": "error", "reason": str(exc)})
    return {"schema_version": SCHEMA_VERSION, "root": str(target_root), "manifest_root": str(manifest_root),
            "dry_run": dry_run, "actions": actions, "errors": sum(1 for x in actions if x["action"] == "error")}


def write_owner_manifest(target: pathlib.Path, owner_pid: int, component: str, *,
                          target_root: pathlib.Path = DEFAULT_BPF_ROOT,
                          manifest_root: pathlib.Path = DEFAULT_MANIFEST_ROOT) -> pathlib.Path:
    # `target` itself is never written to -- see reconcile()'s comment on
    # why a real bpffs directory can't hold a plain manifest file. Callers
    # still pass the real bpffs directory they're marking as owned; this
    # computes and writes the mirrored manifest path instead.
    path = _manifest_path_for(target, target_root, manifest_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"owner_magic": OWNER_MAGIC, "owner_pid": owner_pid, "component": component,
               "created_unix": time.time(), "host": socket.gethostname(), "target": str(target)}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def evidence(output: pathlib.Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    probe = probe_capabilities()
    (output / "probe.json").write_text(json.dumps(probe, indent=2, sort_keys=True) + "\n")
    commands = {
        "uname.txt": ["uname", "-a"],
        "lscpu.txt": ["lscpu"],
        "mounts.txt": ["findmnt"],
        "ip-link.json": ["ip", "-j", "-details", "link", "show"],
        "tc-qdisc.txt": ["tc", "qdisc", "show"],
        "bpftool-map.json": ["bpftool", "-j", "map", "show"],
        "bpftool-prog.json": ["bpftool", "-j", "prog", "show"],
        "systemd-failed.txt": ["systemctl", "--failed", "--no-pager", "--plain"],
    }
    command_results = {}
    for filename, argv in commands.items():
        if not _which(argv[0]):
            command_results[filename] = {"status": "skipped", "reason": f"{argv[0]} unavailable"}
            continue
        rc, out, err = _run(argv, timeout=15)
        text = out + (("\nSTDERR:\n" + err) if err else "") + "\n"
        (output / filename).write_text(text, encoding="utf-8")
        command_results[filename] = {"status": "ok" if rc == 0 else "error", "rc": rc}
    manifest: dict[str, str] = {}
    for p in sorted(output.iterdir()):
        if p.is_file() and p.name != "SHA256SUMS":
            manifest[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text("".join(f"{sha}  {name}\n" for name, sha in manifest.items()))
    return {"schema_version": SCHEMA_VERSION, "output": str(output), "files": manifest, "commands": command_results}


def render_markdown(result: dict[str, Any]) -> str:
    lines = [f"# FluxVM Sentinel certification — {result['profile']}", "", f"**Result:** {'PASS' if result['pass'] else 'FAIL'}", "",
             f"Kernel: `{result['probe']['kernel']}`  ", f"Host: `{result['probe']['host']}`", "", "## Capabilities", ""]
    for item in result["capabilities"]:
        req = "required" if item["required"] else "optional"
        state = "PASS" if item["pass"] else "FAIL"
        lines.append(f"- **{state}** `{item['name']}` ({req}; present={str(item['present']).lower()})")
    lines.extend(["", "## Budgets", ""])
    for item in result["metrics"]:
        value = f" value={item['value']}" if "value" in item else ""
        lines.append(f"- **{item['status'].upper()}** `{item['name']}`{value} rule={json.dumps(item['rule'], sort_keys=True)}")
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser(description="FluxVM Sentinel GA certification helper")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("probe")
    ev = sub.add_parser("evidence"); ev.add_argument("output", type=pathlib.Path)
    own = sub.add_parser("write-owner-manifest"); own.add_argument("directory", type=pathlib.Path); own.add_argument("--pid", type=int, required=True); own.add_argument("--component", required=True); own.add_argument("--target-root", type=pathlib.Path, default=DEFAULT_BPF_ROOT); own.add_argument("--manifest-root", type=pathlib.Path, default=DEFAULT_MANIFEST_ROOT)
    rec = sub.add_parser("reconcile"); rec.add_argument("--root", type=pathlib.Path, default=DEFAULT_BPF_ROOT); rec.add_argument("--manifest-root", type=pathlib.Path, default=DEFAULT_MANIFEST_ROOT); rec.add_argument("--min-age-seconds", type=int, default=300); rec.add_argument("--apply", action="store_true")
    gate = sub.add_parser("gate"); gate.add_argument("--profile", default="baseline"); gate.add_argument("--budgets", type=pathlib.Path, required=True); gate.add_argument("--measurements", type=pathlib.Path); gate.add_argument("--require-all-metrics", action="store_true"); gate.add_argument("--json-out", type=pathlib.Path); gate.add_argument("--markdown-out", type=pathlib.Path)
    args = p.parse_args()
    try:
        if args.cmd == "probe":
            print(json.dumps(probe_capabilities(), indent=2, sort_keys=True)); return 0
        if args.cmd == "evidence":
            print(json.dumps(evidence(args.output), indent=2, sort_keys=True)); return 0
        if args.cmd == "write-owner-manifest":
            print(write_owner_manifest(args.directory, args.pid, args.component,
                                        target_root=args.target_root, manifest_root=args.manifest_root)); return 0
        if args.cmd == "reconcile":
            out = reconcile(args.root, manifest_root=args.manifest_root, min_age_seconds=args.min_age_seconds, dry_run=not args.apply)
            print(json.dumps(out, indent=2, sort_keys=True)); return 1 if out["errors"] else 0
        if args.cmd == "gate":
            result = evaluate(args.profile, args.budgets, args.measurements, args.require_all_metrics)
            text = json.dumps(result, indent=2, sort_keys=True) + "\n"
            if args.json_out: args.json_out.write_text(text, encoding="utf-8")
            else: print(text, end="")
            if args.markdown_out: args.markdown_out.write_text(render_markdown(result), encoding="utf-8")
            return 0 if result["pass"] else 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"fluxvm-sentinel-certify: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
