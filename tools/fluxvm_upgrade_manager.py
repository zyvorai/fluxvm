#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""FluxVM Sentinel Set 14E stateful upgrade and compatibility manager.

The manager is intentionally conservative:
* plans are immutable after a transaction begins (SHA-256 pinned in journal);
* commands are argv arrays and are never executed through a shell;
* only map pins explicitly listed in a plan and rooted under the configured
  FluxVM bpffs root may be snapshotted/restored;
* map state is restored only when type/key/value ABI is compatible;
* every state transition is atomically journaled and fsync'd;
* rollback runs in reverse component order and records partial failures;
* evidence is hashed and may be signed with OpenSSH ssh-keygen -Y sign.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Iterable, Optional

SCHEMA_VERSION = 1
MANAGER_VERSION = "14e.1"
DEFAULT_STATE_DIR = "/var/lib/fluxvm/sentinel-upgrades"
DEFAULT_BPFFS_ROOT = "/sys/fs/bpf/fluxvm"
RESTORABLE_MAP_TYPES = {"hash", "lru_hash", "lpm_trie"}
DELETABLE_MAP_TYPES = {"hash", "lru_hash", "lpm_trie"}
TXID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class UpgradeError(RuntimeError):
    pass


class CommandError(UpgradeError):
    def __init__(self, argv: list[str], rc: int, stdout: str, stderr: str):
        self.argv = argv
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(f"command failed rc={rc}: {argv!r}: {stderr.strip() or stdout.strip()}")


@dataclass
class CmdResult:
    rc: int
    stdout: str
    stderr: str


class Runner:
    def run(self, argv: list[str], *, check: bool = True, timeout: Optional[float] = None,
            input_text: Optional[str] = None) -> CmdResult:
        if not argv or any(not isinstance(v, str) or "\x00" in v for v in argv):
            raise UpgradeError("command must be a non-empty argv string array without NUL bytes")
        cp = subprocess.run(
            argv,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        out = CmdResult(cp.returncode, cp.stdout, cp.stderr)
        if check and cp.returncode != 0:
            raise CommandError(argv, cp.returncode, cp.stdout, cp.stderr)
        return out


RUNNER = Runner()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_write(path: pathlib.Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp_path = pathlib.Path(tmp)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        dfd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def atomic_json(path: pathlib.Path, obj: Any, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(obj, indent=2, sort_keys=True).encode("utf-8") + b"\n", mode)


def load_json(path: pathlib.Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_rel_path(value: str) -> pathlib.PurePosixPath:
    p = pathlib.PurePosixPath(value)
    if p.is_absolute() or any(part in ("", ".", "..") for part in p.parts):
        raise UpgradeError(f"path must be clean and relative: {value!r}")
    return p


def resolve_under(root: pathlib.Path, relative: str) -> pathlib.Path:
    rel = safe_rel_path(relative)
    root_real = root.resolve(strict=False)
    candidate = (root / pathlib.Path(*rel.parts)).resolve(strict=False)
    try:
        candidate.relative_to(root_real)
    except ValueError as e:
        raise UpgradeError(f"path escapes root: {relative!r}") from e
    return candidate


def ensure_txid(value: str) -> str:
    if not TXID_RE.fullmatch(value):
        raise UpgradeError("transaction_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    return value


def normalize_argv(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not value or any(not isinstance(x, str) or not x for x in value):
        raise UpgradeError(f"{field} must be a non-empty string argv array")
    if any("\x00" in x for x in value):
        raise UpgradeError(f"{field} contains NUL")
    return list(value)


def validate_plan(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise UpgradeError("plan must be a JSON object")
    if int(plan.get("schema_version", 0)) != SCHEMA_VERSION:
        raise UpgradeError(f"unsupported schema_version; expected {SCHEMA_VERSION}")
    ensure_txid(str(plan.get("transaction_id", "")))
    if not isinstance(plan.get("components"), list) or not plan["components"]:
        raise UpgradeError("components must be a non-empty array")
    seen: set[str] = set()
    for i, comp in enumerate(plan["components"]):
        if not isinstance(comp, dict):
            raise UpgradeError(f"components[{i}] must be an object")
        name = str(comp.get("name", ""))
        if not TXID_RE.fullmatch(name):
            raise UpgradeError(f"invalid component name: {name!r}")
        if name in seen:
            raise UpgradeError(f"duplicate component: {name}")
        seen.add(name)
        for fld in ("preflight", "apply", "health", "rollback", "rollback_health"):
            if fld in comp:
                normalize_argv(comp[fld], f"component {name}.{fld}")
        logical = comp.get("state_abi")
        if logical is not None:
            if not isinstance(logical, dict):
                raise UpgradeError(f"component {name}.state_abi must be an object")
            current = logical.get("current")
            target = logical.get("target")
            compatible = logical.get("target_compatible_from", [])
            if not isinstance(current, int) or current < 1 or not isinstance(target, int) or target < 1:
                raise UpgradeError(f"component {name}.state_abi current/target must be positive integers")
            if not isinstance(compatible, list) or any(not isinstance(v, int) or v < 1 for v in compatible):
                raise UpgradeError(f"component {name}.state_abi.target_compatible_from must be positive integers")
            if current != target and current not in compatible:
                raise UpgradeError(
                    f"component {name} logical state ABI {current} is not compatible with target ABI {target}; "
                    "use a component-specific state migration before Set 14E"
                )
        maps = comp.get("maps", [])
        if not isinstance(maps, list):
            raise UpgradeError(f"component {name}.maps must be an array")
        map_seen: set[str] = set()
        for j, ms in enumerate(maps):
            if not isinstance(ms, dict):
                raise UpgradeError(f"component {name}.maps[{j}] must be an object")
            pin = str(ms.get("pin", ""))
            safe_rel_path(pin)
            if pin in map_seen:
                raise UpgradeError(f"duplicate map pin in {name}: {pin}")
            map_seen.add(pin)
            mode = ms.get("state", "metadata-only")
            if mode not in ("metadata-only", "merge", "replace"):
                raise UpgradeError(f"invalid map state mode for {pin}: {mode}")
            abi = ms.get("abi", {})
            if not isinstance(abi, dict):
                raise UpgradeError(f"map {pin}.abi must be an object")
            for fld in ("key_size", "value_size"):
                if fld in abi and (not isinstance(abi[fld], int) or abi[fld] <= 0):
                    raise UpgradeError(f"map {pin}.abi.{fld} must be a positive integer")
            if "type" in abi and not isinstance(abi["type"], str):
                raise UpgradeError(f"map {pin}.abi.type must be a string")
        files = comp.get("files", [])
        if not isinstance(files, list):
            raise UpgradeError(f"component {name}.files must be an array")
        for f in files:
            if not isinstance(f, str):
                raise UpgradeError(f"component {name}.files entries must be strings")
            safe_rel_path(f)
    signing = plan.get("signing")
    if signing is not None:
        if not isinstance(signing, dict) or not isinstance(signing.get("ssh_private_key"), str):
            raise UpgradeError("signing.ssh_private_key is required when signing is configured")
        ns = signing.get("namespace", "fluxvm-upgrade")
        if not isinstance(ns, str) or not ns or any(c.isspace() for c in ns):
            raise UpgradeError("signing.namespace must be a non-empty token")
    return copy.deepcopy(plan)


def plan_hash(plan: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(plan))


def tx_dir(plan: dict[str, Any], override_state_dir: Optional[str] = None) -> pathlib.Path:
    state = pathlib.Path(override_state_dir or plan.get("state_dir") or DEFAULT_STATE_DIR)
    return state / ensure_txid(plan["transaction_id"])


class TxLock:
    def __init__(self, directory: pathlib.Path):
        self.directory = directory
        self.fd: Optional[int] = None

    def __enter__(self) -> "TxLock":
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / ".lock"
        self.fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            os.close(self.fd)
            self.fd = None
            raise UpgradeError(f"transaction is already locked: {self.directory.name}") from e
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


def initial_journal(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "manager_version": MANAGER_VERSION,
        "transaction_id": plan["transaction_id"],
        "plan_sha256": plan_hash(plan),
        "status": "running",
        "phase": "created",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "components": {c["name"]: {"preflight": False, "snapshotted": False, "applied": False,
                                       "state_restored": False, "healthy": False, "rolled_back": False, "restore_ok": None,
                                       "error": None} for c in plan["components"]},
        "events": [],
        "error": None,
    }


def add_event(j: dict[str, Any], event: str, **fields: Any) -> None:
    rec = {"time": utc_now(), "event": event}
    rec.update(fields)
    j.setdefault("events", []).append(rec)
    # Bound the journal without losing terminal history.
    if len(j["events"]) > 2048:
        j["events"] = j["events"][-2048:]
    j["updated_at"] = utc_now()


def save_journal(directory: pathlib.Path, journal: dict[str, Any]) -> None:
    atomic_json(directory / "journal.json", journal)


def load_or_create_journal(directory: pathlib.Path, plan: dict[str, Any]) -> dict[str, Any]:
    p = directory / "journal.json"
    if p.exists():
        j = load_json(p)
        if j.get("plan_sha256") != plan_hash(plan):
            raise UpgradeError("plan changed after transaction began; refusing to continue")
        return j
    directory.mkdir(parents=True, exist_ok=True)
    atomic_json(directory / "plan.json", plan)
    j = initial_journal(plan)
    save_journal(directory, j)
    return j


def run_cmd(argv: Any, field: str, *, timeout: float = 120.0, check: bool = True) -> CmdResult:
    cmd = normalize_argv(argv, field)
    if not cmd:
        return CmdResult(0, "", "")
    return RUNNER.run(cmd, check=check, timeout=timeout)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def bpftool_json(argv: list[str]) -> Any:
    res = RUNNER.run(["bpftool", "-j", *argv], timeout=60.0)
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError as e:
        raise UpgradeError(f"bpftool returned invalid JSON for {argv!r}") from e


def pick_map_meta(obj: Any) -> dict[str, Any]:
    if isinstance(obj, list):
        if len(obj) != 1:
            raise UpgradeError(f"expected one bpftool map object, got {len(obj)}")
        obj = obj[0]
    if not isinstance(obj, dict):
        raise UpgradeError("invalid bpftool map metadata")
    return obj


def map_metadata(pin: pathlib.Path) -> dict[str, Any]:
    return pick_map_meta(bpftool_json(["map", "show", "pinned", str(pin)]))


def map_dump(pin: pathlib.Path) -> list[dict[str, Any]]:
    obj = bpftool_json(["map", "dump", "pinned", str(pin)])
    if not isinstance(obj, list):
        raise UpgradeError("invalid bpftool map dump")
    return obj


def byte_seq(value: Any, *, field: str) -> list[int]:
    if isinstance(value, list) and all(isinstance(x, int) and 0 <= x <= 255 for x in value):
        return list(value)
    # Real `bpftool -j map dump pinned <path>` (confirmed against bpftool
    # v7.4.0) encodes each byte as a hex *string* token, e.g.
    # ["0x01","0x00","0x00","0x00"], not as a list of small integers or a
    # single delimited string -- without this branch every real map dump
    # hits the final `raise` below.
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        try:
            out = [int(x, 16) for x in value]
        except ValueError as e:
            raise UpgradeError(f"unsupported bpftool {field} encoding") from e
        if out and all(0 <= x <= 255 for x in out):
            return out
    if isinstance(value, str):
        toks = value.replace("0x", "").replace(":", " ").split()
        try:
            out = [int(t, 16) for t in toks]
        except ValueError as e:
            raise UpgradeError(f"unsupported bpftool {field} encoding") from e
        if out and all(0 <= x <= 255 for x in out):
            return out
    raise UpgradeError(f"unsupported bpftool {field} encoding; expected byte array")


def flatten_percpu_value(value: Any) -> Optional[list[int]]:
    # bpftool often emits per-cpu values as an array of objects. Restoring
    # those safely is kernel/tool-version sensitive, so Set 14E deliberately
    # records them but refuses generic byte-level restore. A plain (non-
    # per-cpu) value is a flat list of either small integers or hex-string
    # tokens (real `bpftool -j map dump`, confirmed against bpftool v7.4.0,
    # uses the latter, e.g. ["0x11","0x22","0x33","0x44"]) -- either is
    # handed to byte_seq, which accepts both encodings.
    if isinstance(value, list) and all(isinstance(x, (int, str)) for x in value):
        return byte_seq(value, field="value")
    return None


def validate_meta(expected: dict[str, Any], actual: dict[str, Any], *, pin: str) -> None:
    # `bpftool -j map show pinned <path>` (real output, confirmed against
    # bpftool v7.4.0) reports map size fields as `bytes_key`/`bytes_value`,
    # not `key`/`key_size`/`value`/`value_size` -- those older alias names
    # are kept as fallbacks only, since without the `bytes_key`/`bytes_value`
    # alias every ABI check here would silently compare against `None` and
    # every state-restoring (merge/replace) upgrade would fail outright.
    aliases = {
        "key_size": ("bytes_key", "key", "key_size"),
        "value_size": ("bytes_value", "value", "value_size"),
        "type": ("type",),
    }
    for fld, names in aliases.items():
        if fld not in expected:
            continue
        got = None
        for n in names:
            if n in actual:
                got = actual[n]
                break
        if got != expected[fld]:
            raise UpgradeError(f"map ABI mismatch for {pin}: expected {fld}={expected[fld]!r}, got {got!r}")


def snapshot_map(bpffs_root: pathlib.Path, map_spec: dict[str, Any], out_dir: pathlib.Path) -> dict[str, Any]:
    pin_rel = map_spec["pin"]
    pin = resolve_under(bpffs_root, pin_rel)
    if not pin.exists():
        if map_spec.get("optional", False):
            return {"pin": pin_rel, "present": False, "optional": True}
        raise UpgradeError(f"required map pin does not exist: {pin}")
    meta = map_metadata(pin)
    validate_meta(map_spec.get("abi", {}), meta, pin=pin_rel)
    state_mode = map_spec.get("state", "metadata-only")
    snap: dict[str, Any] = {"pin": pin_rel, "present": True, "state": state_mode, "metadata": meta}
    if state_mode != "metadata-only":
        if meta.get("type") not in RESTORABLE_MAP_TYPES:
            raise UpgradeError(f"map type {meta.get('type')!r} is not generically restorable: {pin_rel}")
        snap["entries"] = map_dump(pin)
    outfile = out_dir / (sha256_bytes(pin_rel.encode())[:16] + ".json")
    atomic_json(outfile, snap)
    snap["snapshot_file"] = outfile.name
    return snap


def current_keys(pin: pathlib.Path) -> list[list[int]]:
    keys = []
    for entry in map_dump(pin):
        if "key" not in entry:
            continue
        keys.append(byte_seq(entry["key"], field="key"))
    return keys


def bpftool_delete_key(pin: pathlib.Path, key: list[int]) -> None:
    RUNNER.run(["bpftool", "map", "delete", "pinned", str(pin), "key", "hex", *[f"{b:02x}" for b in key]], timeout=30.0)


def bpftool_update_entry(pin: pathlib.Path, key: list[int], value: list[int]) -> None:
    RUNNER.run(["bpftool", "map", "update", "pinned", str(pin), "key", "hex",
                *[f"{b:02x}" for b in key], "value", "hex", *[f"{b:02x}" for b in value], "any"], timeout=30.0)


def restore_map(bpffs_root: pathlib.Path, snapshot: dict[str, Any], map_spec: dict[str, Any]) -> str:
    if not snapshot.get("present"):
        return "skipped-absent"
    mode = snapshot.get("state", "metadata-only")
    if mode == "metadata-only":
        return "metadata-only"
    pin = resolve_under(bpffs_root, snapshot["pin"])
    if not pin.exists():
        raise UpgradeError(f"cannot restore map; replacement pin absent: {pin}")
    meta = map_metadata(pin)
    old = snapshot["metadata"]
    compat = {
        "type": old.get("type"),
        "key_size": old.get("bytes_key", old.get("key", old.get("key_size"))),
        "value_size": old.get("bytes_value", old.get("value", old.get("value_size"))),
    }
    compat = {k: v for k, v in compat.items() if v is not None}
    validate_meta(compat, meta, pin=snapshot["pin"])
    entries = snapshot.get("entries", [])
    max_entries = meta.get("max_entries")
    if isinstance(max_entries, int) and len(entries) > max_entries:
        raise UpgradeError(f"replacement map too small for snapshot {snapshot['pin']}: {len(entries)}>{max_entries}")
    if mode == "replace":
        if meta.get("type") not in DELETABLE_MAP_TYPES:
            raise UpgradeError(f"replace restore unsupported for map type {meta.get('type')}")
        for key in current_keys(pin):
            bpftool_delete_key(pin, key)
    restored = 0
    for entry in entries:
        if "key" not in entry or "value" not in entry:
            continue
        key = byte_seq(entry["key"], field="key")
        value = flatten_percpu_value(entry["value"])
        if value is None:
            raise UpgradeError(f"generic restore cannot encode per-cpu/nested value for {snapshot['pin']}")
        bpftool_update_entry(pin, key, value)
        restored += 1
    return f"restored-{restored}"


def snapshot_files(repo_root: pathlib.Path, files: Iterable[str], out_dir: pathlib.Path) -> list[dict[str, Any]]:
    result = []
    for rel in files:
        src = resolve_under(repo_root, rel)
        rec: dict[str, Any] = {"path": rel, "present": src.exists()}
        if src.exists():
            if not src.is_file():
                raise UpgradeError(f"snapshot file is not a regular file: {src}")
            data = src.read_bytes()
            rec.update({"mode": src.stat().st_mode & 0o7777, "sha256": sha256_bytes(data)})
            dst = out_dir / (sha256_bytes(rel.encode())[:16] + ".bin")
            atomic_write(dst, data, mode=rec["mode"] or 0o600)
            rec["snapshot_file"] = dst.name
        result.append(rec)
    return result


def restore_files(repo_root: pathlib.Path, records: list[dict[str, Any]], out_dir: pathlib.Path) -> None:
    for rec in records:
        dst = resolve_under(repo_root, rec["path"])
        if rec.get("present"):
            src = out_dir / rec["snapshot_file"]
            data = src.read_bytes()
            if sha256_bytes(data) != rec["sha256"]:
                raise UpgradeError(f"file snapshot checksum mismatch: {rec['path']}")
            atomic_write(dst, data, mode=int(rec.get("mode", 0o600)))
        else:
            if dst.exists():
                if not dst.is_file():
                    raise UpgradeError(f"refusing to remove non-file rollback target: {dst}")
                dst.unlink()


def component_snapshot(plan: dict[str, Any], comp: dict[str, Any], directory: pathlib.Path) -> dict[str, Any]:
    bpffs_root = pathlib.Path(plan.get("bpffs_root") or DEFAULT_BPFFS_ROOT)
    repo_root = pathlib.Path(plan.get("repo_root") or ".").resolve()
    snap_dir = directory / "snapshots" / comp["name"]
    maps_dir = snap_dir / "maps"
    files_dir = snap_dir / "files"
    maps_dir.mkdir(parents=True, exist_ok=True)
    files_dir.mkdir(parents=True, exist_ok=True)
    maps = [snapshot_map(bpffs_root, ms, maps_dir) for ms in comp.get("maps", [])]
    files = snapshot_files(repo_root, comp.get("files", []), files_dir)
    manifest = {"component": comp["name"], "created_at": utc_now(), "state_abi": comp.get("state_abi"), "maps": maps, "files": files}
    atomic_json(snap_dir / "manifest.json", manifest)
    return manifest


def component_restore_maps(plan: dict[str, Any], comp: dict[str, Any], directory: pathlib.Path) -> list[str]:
    bpffs_root = pathlib.Path(plan.get("bpffs_root") or DEFAULT_BPFFS_ROOT)
    snap_dir = directory / "snapshots" / comp["name"]
    manifest = load_json(snap_dir / "manifest.json")
    if manifest.get("state_abi") != comp.get("state_abi"):
        raise UpgradeError(f"component {comp['name']} state ABI declaration changed after snapshot")
    by_pin = {m["pin"]: m for m in comp.get("maps", [])}
    outcomes: list[str] = []
    for snap in manifest.get("maps", []):
        spec = by_pin.get(snap["pin"])
        if spec is None:
            raise UpgradeError(f"snapshot contains map no longer present in plan: {snap['pin']}")
        outcomes.append(f"{snap['pin']}:{restore_map(bpffs_root, snap, spec)}")
    return outcomes


def component_restore(plan: dict[str, Any], comp: dict[str, Any], directory: pathlib.Path) -> list[str]:
    repo_root = pathlib.Path(plan.get("repo_root") or ".").resolve()
    snap_dir = directory / "snapshots" / comp["name"]
    outcomes = component_restore_maps(plan, comp, directory)
    manifest = load_json(snap_dir / "manifest.json")
    restore_files(repo_root, manifest.get("files", []), snap_dir / "files")
    return outcomes


def dry_run_component(comp: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": comp["name"],
        "commands": {k: comp.get(k) for k in ("preflight", "apply", "health", "rollback") if comp.get(k)},
        "maps": comp.get("maps", []),
        "files": comp.get("files", []),
    }


def run_upgrade(plan: dict[str, Any], *, state_dir: Optional[str] = None, resume: bool = False) -> dict[str, Any]:
    directory = tx_dir(plan, state_dir)
    with TxLock(directory):
        journal = load_or_create_journal(directory, plan)
        preflight_signing(plan)
        if journal.get("status") == "committed":
            return journal
        if journal.get("status") == "rolled-back":
            raise UpgradeError("transaction has already been rolled back")
        if journal.get("status") == "manual-intervention":
            raise UpgradeError("transaction requires manual intervention; inspect journal/evidence")
        try:
            for comp in plan["components"]:
                st = journal["components"][comp["name"]]
                name = comp["name"]
                if not st["preflight"]:
                    journal["phase"] = f"preflight:{name}"; save_journal(directory, journal)
                    run_cmd(comp.get("preflight"), f"{name}.preflight", timeout=float(comp.get("timeout_seconds", 120)))
                    st["preflight"] = True; add_event(journal, "preflight-ok", component=name); save_journal(directory, journal)
                if not st["snapshotted"]:
                    journal["phase"] = f"snapshot:{name}"; save_journal(directory, journal)
                    component_snapshot(plan, comp, directory)
                    st["snapshotted"] = True; add_event(journal, "snapshot-ok", component=name); save_journal(directory, journal)
                if not st["applied"]:
                    journal["phase"] = f"apply:{name}"; save_journal(directory, journal)
                    run_cmd(comp.get("apply"), f"{name}.apply", timeout=float(comp.get("timeout_seconds", 120)))
                    st["applied"] = True; add_event(journal, "apply-ok", component=name); save_journal(directory, journal)
                if not st.get("state_restored", False):
                    journal["phase"] = f"restore-state:{name}"; save_journal(directory, journal)
                    outcomes = component_restore_maps(plan, comp, directory)
                    st["state_restored"] = True
                    add_event(journal, "upgrade-state-restore-ok", component=name, outcomes=outcomes)
                    save_journal(directory, journal)
                if not st["healthy"]:
                    journal["phase"] = f"health:{name}"; save_journal(directory, journal)
                    run_cmd(comp.get("health"), f"{name}.health", timeout=float(comp.get("health_timeout_seconds", 60)))
                    st["healthy"] = True; add_event(journal, "health-ok", component=name); save_journal(directory, journal)
            journal["phase"] = "commit"
            journal["status"] = "committed"
            add_event(journal, "upgrade-committed")
            save_journal(directory, journal)
            finalize_evidence(plan, directory, journal)
            return journal
        except Exception as exc:
            journal["error"] = str(exc)
            add_event(journal, "upgrade-failed", error=str(exc))
            save_journal(directory, journal)
            try:
                rollback_upgrade(plan, state_dir=state_dir, _journal=journal, _directory=directory, _locked=True)
            except Exception as rb:
                journal["status"] = "manual-intervention"
                journal["phase"] = "rollback-failed"
                journal["error"] = f"upgrade error: {exc}; rollback error: {rb}"
                add_event(journal, "rollback-failed", error=str(rb))
                save_journal(directory, journal)
                finalize_evidence(plan, directory, journal)
                raise UpgradeError(journal["error"]) from rb
            finalize_evidence(plan, directory, journal)
            raise


def rollback_upgrade(plan: dict[str, Any], *, state_dir: Optional[str] = None,
                     _journal: Optional[dict[str, Any]] = None, _directory: Optional[pathlib.Path] = None,
                     _locked: bool = False) -> dict[str, Any]:
    directory = _directory or tx_dir(plan, state_dir)

    def body() -> dict[str, Any]:
        journal = _journal or load_or_create_journal(directory, plan)
        if journal.get("status") == "rolled-back":
            return journal
        errors = []
        for comp in reversed(plan["components"]):
            st = journal["components"][comp["name"]]
            name = comp["name"]
            if not st.get("applied"):
                continue
            if st.get("rolled_back") and st.get("restore_ok") is True:
                continue
            journal["phase"] = f"rollback:{name}"; save_journal(directory, journal)
            try:
                if not st.get("rolled_back"):
                    run_cmd(comp.get("rollback"), f"{name}.rollback", timeout=float(comp.get("timeout_seconds", 120)))
                    st["rolled_back"] = True
                    add_event(journal, "rollback-command-ok", component=name); save_journal(directory, journal)
                outcomes = component_restore(plan, comp, directory) if st.get("snapshotted") else []
                st["restore_ok"] = True
                add_event(journal, "state-restore-ok", component=name, outcomes=outcomes); save_journal(directory, journal)
                if comp.get("rollback_health"):
                    run_cmd(comp["rollback_health"], f"{name}.rollback_health", timeout=float(comp.get("health_timeout_seconds", 60)))
                    add_event(journal, "rollback-health-ok", component=name); save_journal(directory, journal)
            except Exception as exc:
                st["error"] = str(exc); st["restore_ok"] = False
                errors.append(f"{name}: {exc}")
                add_event(journal, "component-rollback-failed", component=name, error=str(exc)); save_journal(directory, journal)
        if errors:
            journal["status"] = "manual-intervention"; journal["phase"] = "rollback-failed"
            journal["error"] = "; ".join(errors); save_journal(directory, journal)
            raise UpgradeError(journal["error"])
        journal["status"] = "rolled-back"; journal["phase"] = "rolled-back"
        add_event(journal, "rollback-complete"); save_journal(directory, journal)
        return journal

    if _locked:
        return body()
    with TxLock(directory):
        out = body()
        finalize_evidence(plan, directory, out)
        return out


def preflight_signing(plan: dict[str, Any]) -> None:
    signing = plan.get("signing")
    if not signing:
        return
    key = pathlib.Path(signing["ssh_private_key"])
    if not key.is_file():
        raise UpgradeError(f"signing key not found: {key}")
    if not command_exists("ssh-keygen"):
        raise UpgradeError("ssh-keygen required for configured evidence signing")


def evidence_files(directory: pathlib.Path) -> list[pathlib.Path]:
    out = []
    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        if path.name in ("EVIDENCE.sha256", "EVIDENCE.sha256.sig", ".lock"):
            continue
        out.append(path)
    return sorted(out)


def finalize_evidence(plan: dict[str, Any], directory: pathlib.Path, journal: dict[str, Any]) -> None:
    atomic_json(directory / "journal.final.json", journal, 0o600)
    lines = []
    for path in evidence_files(directory):
        rel = path.relative_to(directory).as_posix()
        lines.append(f"{file_sha256(path)}  {rel}")
    manifest = ("\n".join(lines) + "\n").encode()
    atomic_write(directory / "EVIDENCE.sha256", manifest, 0o600)
    signing = plan.get("signing")
    if signing:
        key = pathlib.Path(signing["ssh_private_key"])
        if not key.is_file():
            raise UpgradeError(f"signing key not found: {key}")
        if not command_exists("ssh-keygen"):
            raise UpgradeError("ssh-keygen required for configured evidence signing")
        sig = directory / "EVIDENCE.sha256.sig"
        try:
            sig.unlink()
        except FileNotFoundError:
            pass
        ns = signing.get("namespace", "fluxvm-upgrade")
        RUNNER.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", ns, str(directory / "EVIDENCE.sha256")], timeout=30.0)
        generated = pathlib.Path(str(directory / "EVIDENCE.sha256") + ".sig")
        if not generated.is_file():
            raise UpgradeError("ssh-keygen did not create evidence signature")
        os.chmod(generated, 0o600)


def verify_hash_manifest(directory: pathlib.Path) -> list[str]:
    manifest = directory / "EVIDENCE.sha256"
    if not manifest.is_file():
        raise UpgradeError("EVIDENCE.sha256 not found")
    errors = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            digest, rel = line.split("  ", 1)
        except ValueError:
            errors.append(f"malformed manifest line: {line!r}"); continue
        try:
            path = resolve_under(directory, rel)
        except UpgradeError as e:
            errors.append(str(e)); continue
        if not path.is_file():
            errors.append(f"missing evidence file: {rel}")
        elif file_sha256(path) != digest:
            errors.append(f"checksum mismatch: {rel}")
    return errors


def verify_evidence(directory: pathlib.Path, allowed_signers: Optional[pathlib.Path], identity: Optional[str], namespace: str) -> None:
    errs = verify_hash_manifest(directory)
    if errs:
        raise UpgradeError("evidence verification failed: " + "; ".join(errs))
    sig = directory / "EVIDENCE.sha256.sig"
    if allowed_signers or identity:
        if not (allowed_signers and identity):
            raise UpgradeError("--allowed-signers and --identity must be supplied together")
        if not sig.is_file():
            raise UpgradeError("evidence signature missing")
        data = (directory / "EVIDENCE.sha256").read_text(encoding="utf-8")
        RUNNER.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed_signers), "-I", identity,
                    "-n", namespace, "-s", str(sig)], input_text=data, timeout=30.0)


def path_status(path: pathlib.Path) -> Any:
    # pathlib.Path.exists() only swallows ENOENT-style errors; it re-raises
    # PermissionError. FluxVM's real bpffs pin roots are 0700 root-owned by
    # design (see e.g. /sys/fs/bpf/fluxvm on a hardened host), so an
    # unprivileged `probe` -- the whole point of which is to let an operator
    # check host readiness *before* deciding to escalate to root for `run`
    # -- would otherwise crash instead of reporting a useful tri-state.
    try:
        return path.exists()
    except PermissionError:
        return "permission-denied"


def probe_host(plan: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    bpffs_root = pathlib.Path((plan or {}).get("bpffs_root") or DEFAULT_BPFFS_ROOT)
    info = {
        "manager_version": MANAGER_VERSION,
        "time": utc_now(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "bpftool": command_exists("bpftool"),
        "ssh_keygen": command_exists("ssh-keygen"),
        "bpffs_root": str(bpffs_root),
        "bpffs_root_exists": path_status(bpffs_root),
        "bpf_fs": path_status(pathlib.Path("/sys/fs/bpf")),
        "systemd": command_exists("systemctl"),
    }
    if command_exists("bpftool"):
        res = RUNNER.run(["bpftool", "feature", "probe", "kernel"], check=False, timeout=20.0)
        info["bpftool_feature_probe_rc"] = res.rc
    return info


def status_for(plan: dict[str, Any], state_dir: Optional[str]) -> dict[str, Any]:
    directory = tx_dir(plan, state_dir)
    j = directory / "journal.json"
    if not j.is_file():
        return {"transaction_id": plan["transaction_id"], "status": "not-started"}
    return load_json(j)


def parse_time(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def reconcile(state_dir: pathlib.Path, stale_minutes: int) -> list[dict[str, Any]]:
    if not state_dir.exists():
        return []
    now = dt.datetime.now(dt.timezone.utc)
    results = []
    for child in sorted(state_dir.iterdir()):
        if not child.is_dir() or not (child / "journal.json").is_file() or not (child / "plan.json").is_file():
            continue
        try:
            journal = load_json(child / "journal.json")
            if journal.get("status") != "running":
                continue
            updated = parse_time(journal["updated_at"])
            age = (now - updated).total_seconds() / 60.0
            if age < stale_minutes:
                continue
            plan = validate_plan(load_json(child / "plan.json"))
            rollback_upgrade(plan, state_dir=str(state_dir))
            results.append({"transaction_id": child.name, "action": "rolled-back", "age_minutes": round(age, 1)})
        except Exception as exc:
            results.append({"transaction_id": child.name, "action": "error", "error": str(exc)})
    return results


def print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="fluxvm-upgrade", description="FluxVM Sentinel stateful upgrade manager")
    p.add_argument("--state-dir", default=None, help="override transaction state directory")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "probe", "plan", "run", "resume", "rollback", "status"):
        sp = sub.add_parser(name)
        sp.add_argument("plan", type=pathlib.Path)
    rec = sub.add_parser("reconcile")
    rec.add_argument("--stale-minutes", type=int, default=15)
    ver = sub.add_parser("verify-evidence")
    ver.add_argument("directory", type=pathlib.Path)
    ver.add_argument("--allowed-signers", type=pathlib.Path)
    ver.add_argument("--identity")
    ver.add_argument("--namespace", default="fluxvm-upgrade")
    args = p.parse_args(argv)
    try:
        if args.cmd == "reconcile":
            if args.stale_minutes < 1:
                raise UpgradeError("--stale-minutes must be >= 1")
            print_json(reconcile(pathlib.Path(args.state_dir or DEFAULT_STATE_DIR), args.stale_minutes)); return 0
        if args.cmd == "verify-evidence":
            verify_evidence(args.directory.resolve(), args.allowed_signers, args.identity, args.namespace)
            print_json({"ok": True, "directory": str(args.directory.resolve())}); return 0
        plan = validate_plan(load_json(args.plan))
        if args.cmd == "validate":
            print_json({"ok": True, "transaction_id": plan["transaction_id"], "plan_sha256": plan_hash(plan)}); return 0
        if args.cmd == "probe":
            print_json(probe_host(plan)); return 0
        if args.cmd == "plan":
            print_json({"transaction_id": plan["transaction_id"], "plan_sha256": plan_hash(plan),
                        "components": [dry_run_component(c) for c in plan["components"]]}); return 0
        if args.cmd in ("run", "resume"):
            print_json(run_upgrade(plan, state_dir=args.state_dir, resume=(args.cmd == "resume"))); return 0
        if args.cmd == "rollback":
            print_json(rollback_upgrade(plan, state_dir=args.state_dir)); return 0
        if args.cmd == "status":
            print_json(status_for(plan, args.state_dir)); return 0
    except (UpgradeError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"fluxvm-upgrade: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
