#!/usr/bin/env python3
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""FluxVM Sentinel Set 17E release admission controller.

This is a read-only release gate. It verifies the candidate artifact and evidence,
probes fleet capabilities over strict SSH, checks current->candidate state ABI
compatibility, evaluates fleet/cohort budgets, and only then writes a short-lived,
tamper-evident admission record. It never deploys, upgrades, quarantines, or rolls
back a node.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Optional

SCHEMA_VERSION = 1
VERSION = "17e.1"
DEFAULT_STATE_DIR = "/var/lib/fluxvm/sentinel-admission"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{64}$")
OPS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "lt": lambda a, b: a < b,
    "le": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "ge": lambda a, b: a >= b,
    "contains": lambda a, b: b in a,
    "matches": lambda a, b: bool(re.fullmatch(str(b), str(a))),
}

class AdmissionError(RuntimeError):
    pass

@dataclasses.dataclass
class Result:
    rc: int
    stdout: str
    stderr: str

class Runner:
    def run(self, argv: list[str], *, check: bool = True, timeout: Optional[float] = None,
            input_text: Optional[str] = None) -> Result:
        if not argv or any(not isinstance(x, str) or "\x00" in x for x in argv):
            raise AdmissionError("invalid argv")
        cp = subprocess.run(argv, input=input_text, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
        r = Result(cp.returncode, cp.stdout, cp.stderr)
        if check and r.rc:
            raise AdmissionError(f"command failed rc={r.rc}: {argv!r}: {(r.stderr or r.stdout).strip()}")
        return r

RUNNER = Runner()

def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

def parse_time(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))

def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def sha_obj(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()

def sha_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def load(path: os.PathLike[str] | str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def safe_regular(path: pathlib.Path) -> pathlib.Path:
    if path.is_symlink():
        raise AdmissionError(f"refusing symlink: {path}")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise AdmissionError(f"not a regular file: {path}")
    return path

def atomic_json(path: pathlib.Path, obj: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass

def json_pointer(doc: Any, pointer: str) -> Any:
    if pointer == "":
        return doc
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise AdmissionError(f"invalid JSON pointer: {pointer!r}")
    cur = doc
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            try:
                cur = cur[int(token)]
            except (ValueError, IndexError) as e:
                raise AdmissionError(f"JSON pointer missing: {pointer}") from e
        elif isinstance(cur, dict) and token in cur:
            cur = cur[token]
        else:
            raise AdmissionError(f"JSON pointer missing: {pointer}")
    return cur

def compare(op: str, actual: Any, expected: Any) -> bool:
    if op not in OPS:
        raise AdmissionError(f"unsupported assertion op: {op}")
    try:
        return bool(OPS[op](actual, expected))
    except (TypeError, ValueError) as e:
        raise AdmissionError(f"assertion type error for op {op}") from e

def validate(plan: Any) -> dict[str, Any]:
    if not isinstance(plan, dict) or plan.get("schema_version") != SCHEMA_VERSION:
        raise AdmissionError("unsupported schema_version")
    aid = str(plan.get("admission_id", ""))
    if not NAME_RE.fullmatch(aid):
        raise AdmissionError("invalid admission_id")
    c = plan.get("candidate")
    if not isinstance(c, dict):
        raise AdmissionError("candidate must be object")
    for key in ("release_id", "artifact_path", "artifact_sha256"):
        if not str(c.get(key, "")):
            raise AdmissionError(f"candidate.{key} required")
    if not SHA_RE.fullmatch(str(c["artifact_sha256"])):
        raise AdmissionError("candidate.artifact_sha256 must be SHA-256 hex")
    if c.get("manifest_sha256") and not SHA_RE.fullmatch(str(c["manifest_sha256"])):
        raise AdmissionError("candidate.manifest_sha256 must be SHA-256 hex")
    abis = c.get("state_abis", {})
    if not isinstance(abis, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in abis.items()):
        raise AdmissionError("candidate.state_abis must be object of strings")
    nodes = plan.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise AdmissionError("nodes must be non-empty")
    seen: set[str] = set()
    for n in nodes:
        if not isinstance(n, dict):
            raise AdmissionError("node must be object")
        name, host = str(n.get("name", "")), str(n.get("host", ""))
        if not NAME_RE.fullmatch(name) or not host or "\x00" in host:
            raise AdmissionError("invalid node")
        if name in seen:
            raise AdmissionError(f"duplicate node {name}")
        seen.add(name)
        cohort = str(n.get("cohort", "default"))
        if not NAME_RE.fullmatch(cohort):
            raise AdmissionError(f"invalid cohort for {name}")
        caps = n.get("required_capabilities", [])
        if not isinstance(caps, list) or any(not isinstance(x, str) for x in caps):
            raise AdmissionError(f"invalid required_capabilities for {name}")
        if n.get("kernel_regex"):
            try:
                re.compile(str(n["kernel_regex"]))
            except re.error as e:
                raise AdmissionError(f"invalid kernel_regex for {name}") from e
    evidence = plan.get("evidence", [])
    if not isinstance(evidence, list):
        raise AdmissionError("evidence must be array")
    evnames: set[str] = set()
    for e in evidence:
        if not isinstance(e, dict):
            raise AdmissionError("evidence entry must be object")
        name, kind, path = str(e.get("name", "")), str(e.get("kind", "json")), str(e.get("path", ""))
        if not NAME_RE.fullmatch(name) or name in evnames or kind not in ("json", "evidence-dir") or not path:
            raise AdmissionError("invalid evidence entry")
        evnames.add(name)
        if e.get("sha256") and not SHA_RE.fullmatch(str(e["sha256"])):
            raise AdmissionError(f"invalid evidence SHA-256 for {name}")
        assertions = e.get("assertions", [])
        if not isinstance(assertions, list):
            raise AdmissionError(f"assertions must be array for {name}")
        for a in assertions:
            if not isinstance(a, dict) or str(a.get("op", "eq")) not in OPS or not isinstance(a.get("pointer", ""), str):
                raise AdmissionError(f"invalid assertion for {name}")
    comp = plan.get("compatibility", {})
    if not isinstance(comp, dict):
        raise AdmissionError("compatibility must be object")
    allowed = comp.get("allowed_from_state_abis", {})
    if not isinstance(allowed, dict) or any(not isinstance(v, list) or any(not isinstance(x, str) for x in v) for v in allowed.values()):
        raise AdmissionError("compatibility.allowed_from_state_abis must be object of arrays")
    pol = plan.get("policy", {})
    if not isinstance(pol, dict):
        raise AdmissionError("policy must be object")
    bounds = (
        ("min_reachable_percent", 100.0, 0.0, 100.0),
        ("min_compatible_percent", 100.0, 0.0, 100.0),
        ("max_unreachable_nodes", 0, 0, 10**9),
        ("min_nodes_per_cohort", 1, 1, 10**9),
        ("max_parallel", 8, 1, 1024),
        ("admission_ttl_seconds", 3600, 60, 7 * 24 * 3600),
    )
    for key, default, lo, hi in bounds:
        val = float(pol.get(key, default))
        if val < lo or val > hi:
            raise AdmissionError(f"invalid policy.{key}")
    caps = pol.get("required_capabilities", [])
    if not isinstance(caps, list) or any(not isinstance(x, str) for x in caps):
        raise AdmissionError("policy.required_capabilities must be array of strings")
    return plan

def ssh_base(node: dict[str, Any], plan: dict[str, Any]) -> list[str]:
    args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if not plan.get("allow_insecure_host_key", False):
        args += ["-o", "StrictHostKeyChecking=yes"]
    if node.get("port"):
        args += ["-p", str(int(node["port"]))]
    if node.get("identity_file"):
        args += ["-i", str(node["identity_file"])]
    target = (str(node.get("user")) + "@" if node.get("user") else "") + str(node["host"])
    return args + [target]

def remote_capture(node: dict[str, Any], plan: dict[str, Any], argv: list[str], timeout: float = 45) -> Result:
    payload = json.dumps(argv)
    py = ("import json,subprocess,sys; a=json.loads(sys.stdin.read()); "
          "r=subprocess.run(a,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True); "
          "sys.stdout.write(r.stdout); sys.stderr.write(r.stderr); sys.exit(r.returncode)")
    return RUNNER.run(ssh_base(node, plan) + ["python3 -c " + shlex.quote(py)], check=False,
                      timeout=timeout, input_text=payload)

def verify_manifest_dir(path: pathlib.Path) -> tuple[dict[str, Any], dict[str, str]]:
    if path.is_symlink() or not path.is_dir():
        raise AdmissionError(f"evidence directory invalid: {path}")
    mf = safe_regular(path / "manifest.json")
    manifest = load(mf)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise AdmissionError(f"invalid evidence manifest: {mf}")
    hashes: dict[str, str] = {}
    for ent in manifest["files"]:
        if not isinstance(ent, dict):
            raise AdmissionError("invalid manifest entry")
        name, expected = str(ent.get("file", "")), str(ent.get("sha256", ""))
        if not name or name in (".", "..") or "/" in name or "\\" in name or not SHA_RE.fullmatch(expected):
            raise AdmissionError("unsafe/invalid manifest entry")
        p = safe_regular(path / name)
        got = sha_file(p)
        if got.lower() != expected.lower():
            raise AdmissionError(f"evidence manifest hash mismatch: {name}")
        hashes[name] = got
    return manifest, hashes

def evaluate_assertions(doc: Any, assertions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for a in assertions:
        pointer, op, expected = str(a.get("pointer", "")), str(a.get("op", "eq")), a.get("value")
        try:
            actual = json_pointer(doc, pointer)
            ok = compare(op, actual, expected)
            out.append({"pointer": pointer, "op": op, "expected": expected, "actual": actual, "ok": ok})
        except AdmissionError as e:
            out.append({"pointer": pointer, "op": op, "expected": expected, "actual": None, "ok": False, "error": str(e)})
    return out

def verify_evidence_entry(entry: dict[str, Any]) -> dict[str, Any]:
    path = pathlib.Path(str(entry["path"]))
    kind = str(entry.get("kind", "json"))
    rec: dict[str, Any] = {"name": entry["name"], "kind": kind, "path": str(path), "ok": False}
    if kind == "json":
        p = safe_regular(path)
        got = sha_file(p)
        if entry.get("sha256") and got.lower() != str(entry["sha256"]).lower():
            rec.update({"sha256": got, "error": "evidence SHA-256 mismatch"})
            return rec
        doc = load(p)
        rec["sha256"] = got
    else:
        manifest, hashes = verify_manifest_dir(path)
        manifest_hash = sha_file(path / "manifest.json")
        if entry.get("sha256") and manifest_hash.lower() != str(entry["sha256"]).lower():
            rec.update({"sha256": manifest_hash, "error": "manifest SHA-256 mismatch"})
            return rec
        document = str(entry.get("document", "run.json"))
        if not document or "/" in document or "\\" in document or document not in hashes:
            rec.update({"sha256": manifest_hash, "error": "assertion document is not verified by manifest"})
            return rec
        doc = load(path / document)
        rec.update({"sha256": manifest_hash, "verified_files": hashes, "document": document})
        # Keep enough metadata to make the evidence fingerprint deterministic.
        rec["manifest_schema_version"] = manifest.get("schema_version")
    checks = evaluate_assertions(doc, entry.get("assertions", []))
    rec["assertions"] = checks
    rec["ok"] = all(x["ok"] for x in checks)
    if not checks:
        rec["ok"] = True
    return rec

def verify_candidate(plan: dict[str, Any]) -> dict[str, Any]:
    c = plan["candidate"]
    artifact = safe_regular(pathlib.Path(str(c["artifact_path"])))
    got = sha_file(artifact)
    ok = got.lower() == str(c["artifact_sha256"]).lower()
    rec: dict[str, Any] = {"artifact_path": str(artifact), "artifact_sha256": got, "ok": ok}
    if c.get("manifest_path"):
        mp = safe_regular(pathlib.Path(str(c["manifest_path"])))
        mh = sha_file(mp)
        manifest_ok = not c.get("manifest_sha256") or mh.lower() == str(c["manifest_sha256"]).lower()
        doc = load(mp)
        # Candidate manifest is self-consistent if it declares these fields.
        declared_release = doc.get("release_id") if isinstance(doc, dict) else None
        declared_artifact = doc.get("artifact_sha256") if isinstance(doc, dict) else None
        if declared_release is not None:
            manifest_ok = manifest_ok and declared_release == c["release_id"]
        if declared_artifact is not None:
            manifest_ok = manifest_ok and str(declared_artifact).lower() == got.lower()
        rec.update({"manifest_path": str(mp), "manifest_sha256": mh, "manifest_ok": manifest_ok})
        rec["ok"] = rec["ok"] and manifest_ok
    return rec

def node_probe(node: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    script = r'''import json,os,platform,shutil
p="/var/lib/fluxvm/sentinel-release.json"
try:
    release=json.load(open(p)) if os.path.exists(p) else {}
except Exception:
    release={"_invalid":True}
lsm=""
try:
    lsm=open("/sys/kernel/security/lsm").read().strip()
except Exception:
    pass
caps={
 "kernel_btf":os.path.exists("/sys/kernel/btf/vmlinux"),
 "bpftool":bool(shutil.which("bpftool")),
 "bpffs":os.path.isdir("/sys/fs/bpf"),
 "cgroup_v2":os.path.exists("/sys/fs/cgroup/cgroup.controllers"),
 "kvm":os.path.exists("/dev/kvm"),
 "sched_ext":os.path.exists("/sys/kernel/sched_ext") or os.path.exists("/sys/kernel/debug/sched/ext"),
 "bpf_lsm":"bpf" in [x.strip() for x in lsm.split(",") if x.strip()],
}
print(json.dumps({"kernel":platform.release(),"arch":platform.machine(),"capabilities":caps,"release":release},sort_keys=True))'''
    r = remote_capture(node, plan, ["python3", "-c", script], timeout=float(plan.get("policy", {}).get("probe_timeout_seconds", 45)))
    rec: dict[str, Any] = {"name": node["name"], "host": node["host"], "cohort": node.get("cohort", "default"), "reachable": False, "compatible": False, "reasons": []}
    if r.rc:
        rec["reasons"].append({"kind": "unreachable", "detail": (r.stderr or r.stdout)[-1000:]})
        return rec
    try:
        inv = json.loads(r.stdout.strip())
    except Exception:
        rec["reasons"].append({"kind": "invalid-inventory"})
        return rec
    rec["reachable"] = True
    rec["inventory"] = inv
    if node.get("arch") and inv.get("arch") != node["arch"]:
        rec["reasons"].append({"kind": "arch-mismatch", "expected": node["arch"], "observed": inv.get("arch")})
    if node.get("kernel_regex") and not re.fullmatch(str(node["kernel_regex"]), str(inv.get("kernel", ""))):
        rec["reasons"].append({"kind": "kernel-mismatch", "expected": node["kernel_regex"], "observed": inv.get("kernel")})
    required = set(plan.get("policy", {}).get("required_capabilities", [])) | set(node.get("required_capabilities", []))
    caps = inv.get("capabilities", {}) if isinstance(inv.get("capabilities"), dict) else {}
    for cap in sorted(required):
        if not caps.get(cap, False):
            rec["reasons"].append({"kind": "missing-capability", "capability": cap})
    release = inv.get("release", {}) if isinstance(inv.get("release"), dict) else {}
    current_abis = release.get("state_abis", {}) if isinstance(release.get("state_abis"), dict) else {}
    target_abis = plan["candidate"].get("state_abis", {})
    allowed = plan.get("compatibility", {}).get("allowed_from_state_abis", {})
    allow_missing = bool(plan.get("compatibility", {}).get("allow_missing_current_state_abi", False))
    for component, target in target_abis.items():
        current = current_abis.get(component)
        if current is None:
            if not allow_missing:
                rec["reasons"].append({"kind": "missing-current-state-abi", "component": component})
        elif current != target and current not in allowed.get(component, []):
            rec["reasons"].append({"kind": "incompatible-state-abi", "component": component, "current": current, "target": target})
    rec["compatible"] = not rec["reasons"]
    return rec

def cohort_summary(plan: dict[str, Any], observations: list[dict[str, Any]]) -> dict[str, Any]:
    by: dict[str, dict[str, Any]] = {}
    for o in observations:
        c = str(o.get("cohort", "default"))
        x = by.setdefault(c, {"nodes": 0, "reachable": 0, "compatible": 0, "members": []})
        x["nodes"] += 1
        x["reachable"] += int(bool(o.get("reachable")))
        x["compatible"] += int(bool(o.get("compatible")))
        x["members"].append(o["name"])
    return by

def evaluate(plan: dict[str, Any], observations: list[dict[str, Any]], candidate: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    pol = plan.get("policy", {})
    n = len(observations)
    reachable = sum(1 for o in observations if o.get("reachable"))
    compatible = sum(1 for o in observations if o.get("compatible"))
    unreachable = n - reachable
    reachable_pct = (100.0 * reachable / n) if n else 0.0
    compatible_pct = (100.0 * compatible / n) if n else 0.0
    cohorts = cohort_summary(plan, observations)
    reasons: list[dict[str, Any]] = []
    if not candidate.get("ok"):
        reasons.append({"kind": "candidate-integrity-failed"})
    for e in evidence:
        if not e.get("ok"):
            reasons.append({"kind": "evidence-failed", "name": e.get("name")})
    if unreachable > int(pol.get("max_unreachable_nodes", 0)):
        reasons.append({"kind": "too-many-unreachable", "observed": unreachable, "limit": int(pol.get("max_unreachable_nodes", 0))})
    if reachable_pct < float(pol.get("min_reachable_percent", 100)):
        reasons.append({"kind": "reachable-percent", "observed": reachable_pct, "minimum": float(pol.get("min_reachable_percent", 100))})
    if compatible_pct < float(pol.get("min_compatible_percent", 100)):
        reasons.append({"kind": "compatible-percent", "observed": compatible_pct, "minimum": float(pol.get("min_compatible_percent", 100))})
    min_cohort = int(pol.get("min_nodes_per_cohort", 1))
    for name, c in cohorts.items():
        if c["nodes"] < min_cohort:
            reasons.append({"kind": "cohort-too-small", "cohort": name, "observed": c["nodes"], "minimum": min_cohort})
        if bool(pol.get("require_each_cohort_compatible", True)) and c["compatible"] == 0:
            reasons.append({"kind": "cohort-no-compatible-node", "cohort": name})
    return {
        "ok": not reasons,
        "release_id": plan["candidate"]["release_id"],
        "reachable": reachable,
        "compatible": compatible,
        "total_nodes": n,
        "reachable_percent": reachable_pct,
        "compatible_percent": compatible_pct,
        "cohorts": cohorts,
        "reasons": reasons,
    }

def state_dir(plan: dict[str, Any], root: str) -> pathlib.Path:
    return pathlib.Path(root) / plan["admission_id"]

def signing_preflight(plan: dict[str, Any]) -> None:
    key = plan.get("evidence_signing_key")
    if key and (not pathlib.Path(str(key)).is_file() or not shutil.which("ssh-keygen")):
        raise AdmissionError("evidence signing preflight failed")

def collect(plan: dict[str, Any]) -> dict[str, Any]:
    # Integrity/evidence first: do not touch the network if local release proof is already invalid.
    candidate = verify_candidate(plan)
    evidence = [verify_evidence_entry(e) for e in plan.get("evidence", [])]
    if not candidate.get("ok") or any(not e.get("ok") for e in evidence):
        observations = [{"name": n["name"], "host": n["host"], "cohort": n.get("cohort", "default"), "reachable": False, "compatible": False, "reasons": [{"kind": "probe-skipped-local-gate"}]} for n in plan["nodes"]]
    else:
        maxp = int(plan.get("policy", {}).get("max_parallel", 8))
        with concurrent.futures.ThreadPoolExecutor(max_workers=maxp) as ex:
            observations = list(ex.map(lambda n: node_probe(n, plan), plan["nodes"]))
    decision = evaluate(plan, observations, candidate, evidence)
    return {"candidate": candidate, "evidence": evidence, "observations": observations, "decision": decision}

def stable_fleet_fingerprint(observations: list[dict[str, Any]]) -> str:
    stripped = []
    for o in observations:
        inv = o.get("inventory", {}) if isinstance(o.get("inventory"), dict) else {}
        stripped.append({"name": o.get("name"), "cohort": o.get("cohort"), "kernel": inv.get("kernel"), "arch": inv.get("arch"), "capabilities": inv.get("capabilities", {}), "release": inv.get("release", {}), "reachable": o.get("reachable"), "compatible": o.get("compatible"), "reasons": o.get("reasons", [])})
    return sha_obj(sorted(stripped, key=lambda x: str(x["name"])))

def write_bundle(plan: dict[str, Any], root: str, collected: dict[str, Any], admitted: bool) -> pathlib.Path:
    d = state_dir(plan, root)
    d.mkdir(parents=True, exist_ok=True)
    evidence_fp = sha_obj([{"name": e.get("name"), "sha256": e.get("sha256"), "ok": e.get("ok")} for e in collected["evidence"]])
    record: dict[str, Any] = {
        "schema_version": 1,
        "admission_id": plan["admission_id"],
        "release_id": plan["candidate"]["release_id"],
        "artifact_sha256": collected["candidate"]["artifact_sha256"],
        "plan_sha256": sha_obj(plan),
        "fleet_fingerprint": stable_fleet_fingerprint(collected["observations"]),
        "evidence_fingerprint": evidence_fp,
        "decision": collected["decision"],
        "created_at": now(),
        "admitted": admitted,
        "signature_required": bool(plan.get("evidence_signing_key")),
        "signer_identity": str(plan.get("evidence_signing_identity", "fluxvm-admission")),
    }
    if admitted:
        ttl = int(plan.get("policy", {}).get("admission_ttl_seconds", 3600))
        record["expires_at"] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=ttl)).isoformat(timespec="seconds")
    atomic_json(d / "plan.json", plan, 0o640)
    atomic_json(d / "evaluation.json", collected, 0o640)
    atomic_json(d / "admission.json", record, 0o640)
    files = []
    for p in sorted(d.glob("*.json")):
        if p.name == "manifest.json":
            continue
        files.append({"file": p.name, "sha256": sha_file(p)})
    manifest = {"schema_version": 1, "generated_at": now(), "files": files}
    atomic_json(d / "manifest.json", manifest, 0o640)
    key = plan.get("evidence_signing_key")
    if key:
        r = RUNNER.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "fluxvm-sentinel-admission", str(d / "manifest.json")], check=False, timeout=30)
        produced = pathlib.Path(str(d / "manifest.json") + ".sig")
        if r.rc or not produced.exists():
            raise AdmissionError("admission evidence signing failed")
        os.replace(produced, d / "manifest.json.sig")
    return d

def with_lock(plan: dict[str, Any], root: str):
    d = state_dir(plan, root)
    d.mkdir(parents=True, exist_ok=True)
    return open(d / "lock", "a+")

def do_evaluate(plan: dict[str, Any], root: str, admit: bool) -> dict[str, Any]:
    signing_preflight(plan)
    with with_lock(plan, root) as lf:
        try:
            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise AdmissionError("admission evaluation already running") from e
        collected = collect(plan)
        if admit and not collected["decision"]["ok"]:
            # Keep a denied evidence bundle, but do not produce an admitted token.
            d = write_bundle(plan, root, collected, False)
            raise AdmissionError(f"release denied; evidence: {d}")
        d = write_bundle(plan, root, collected, bool(admit and collected["decision"]["ok"]))
        out = dict(collected["decision"])
        out["bundle"] = str(d)
        out["admitted"] = bool(admit and collected["decision"]["ok"])
        return out

def verify_bundle(path: os.PathLike[str] | str, *, require_admitted: bool = False, allowed_signers: Optional[str] = None) -> dict[str, Any]:
    d = pathlib.Path(path)
    manifest_path = safe_regular(d / "manifest.json")
    manifest = load(manifest_path)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise AdmissionError("invalid admission manifest")
    for x in manifest["files"]:
        name, expected = str(x.get("file", "")), str(x.get("sha256", ""))
        if not name or "/" in name or "\\" in name or not SHA_RE.fullmatch(expected):
            raise AdmissionError("invalid admission manifest entry")
        p = safe_regular(d / name)
        if sha_file(p).lower() != expected.lower():
            raise AdmissionError(f"admission bundle hash mismatch: {name}")
    record = load(safe_regular(d / "admission.json"))
    if require_admitted and not record.get("admitted"):
        raise AdmissionError("release is not admitted")
    if record.get("admitted"):
        exp = record.get("expires_at")
        if not exp or parse_time(str(exp)) <= dt.datetime.now(dt.timezone.utc):
            raise AdmissionError("admission has expired")
    sig = d / "manifest.json.sig"
    signature_required = bool(record.get("signature_required"))
    signature_verified = False
    if signature_required and not sig.is_file():
        raise AdmissionError("admission signature required but missing")
    if allowed_signers:
        allowed = safe_regular(pathlib.Path(allowed_signers))
        if not sig.is_file():
            raise AdmissionError("allowed-signers verification requested but signature missing")
        identity = str(record.get("signer_identity", "fluxvm-admission"))
        r = RUNNER.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", identity, "-n", "fluxvm-sentinel-admission", "-s", str(sig)], check=False, timeout=30, input_text=manifest_path.read_text(encoding="utf-8"))
        if r.rc:
            raise AdmissionError("admission signature verification failed")
        signature_verified = True
    elif signature_required and require_admitted:
        raise AdmissionError("strict verification of a signed admission requires --allowed-signers")
    return {"ok": True, "admitted": bool(record.get("admitted")), "release_id": record.get("release_id"), "expires_at": record.get("expires_at"), "signature_present": sig.is_file(), "signature_verified": signature_verified}

def main() -> None:
    ap = argparse.ArgumentParser(prog="fluxvm-admit", description="FluxVM Sentinel Set 17E release admission controller")
    ap.add_argument("--state-dir", default=DEFAULT_STATE_DIR)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for cmd in ("validate", "probe", "evaluate", "admit"):
        sub.add_parser(cmd).add_argument("plan")
    v = sub.add_parser("verify-admission")
    v.add_argument("directory")
    v.add_argument("--require-admitted", action="store_true")
    v.add_argument("--allowed-signers", help="OpenSSH allowed_signers file used to verify a signed admission")
    args = ap.parse_args()
    if args.cmd == "verify-admission":
        print(json.dumps(verify_bundle(args.directory, require_admitted=args.require_admitted, allowed_signers=args.allowed_signers), indent=2, sort_keys=True))
        return
    plan = validate(load(args.plan))
    if args.cmd == "validate":
        print(json.dumps({"ok": True, "plan_sha256": sha_obj(plan), "nodes": len(plan["nodes"]), "evidence": len(plan.get("evidence", []))}, indent=2))
        return
    if args.cmd == "probe":
        signing_preflight(plan)
        collected = collect(plan)
        print(json.dumps({"candidate": collected["candidate"], "evidence": collected["evidence"], "observations": collected["observations"]}, indent=2, sort_keys=True))
        return
    print(json.dumps(do_evaluate(plan, args.state_dir, args.cmd == "admit"), indent=2, sort_keys=True))

if __name__ == "__main__":
    try:
        main()
    except AdmissionError as e:
        print(f"fluxvm-admit: {e}", file=os.sys.stderr)
        raise SystemExit(1)
