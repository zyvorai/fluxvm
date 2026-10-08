#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end guest<->host network throughput and host CPU for the in-tree KVM
# engine's virtio-net, across datapaths:
#
#   vhost      kernel vhost-net, one queue pair      (FLUXVM_VHOST_NET unset)
#   userspace  userspace TAP pump                    (FLUXVM_VHOST_NET=0)
#   mq         kernel vhost-net, N queue pairs       (FLUXVM_NET_QUEUE_PAIRS=N)
#
# For each mode and run it boots the golden agent guest on a tap in a throwaway
# network namespace (same harness as scripts/test-kvm-net.sh), then measures
#   - guest->host and host->guest TCP throughput
#   - guest->host and host->guest UDP throughput and loss (needs iperf3 in the guest)
#   - host CPU during each transfer: hypervisor process, vhost kernel threads
#     (`vhost-<pid>`), whole-host busy share. Sampled from /proc (always) and, if
#     installed, `mpstat`/`pidstat` raw output is kept next to the JSON.
# and writes one JSON document. It also records the datapath the hypervisor
# *reports* (Metrics `net_datapath`), so a silent fallback to the userspace pump
# shows up as a mode whose `datapath` does not match its name. Check that field
# before reading any number.
#
#   FLUXVM_KVM_BENCH=1 sudo -E scripts/bench-kvm-vhost.sh        # lab host, root
#
# Opt-in, root-only; needs /dev/kvm, netns/tap, dnsmasq, python3, curl in the
# guest and the golden agent image (scripts/setup-native-agent-template.sh). With
# iperf3 on the host and in the guest it uses iperf3 for TCP and UDP; without
# it, TCP falls back to an HTTP transfer and UDP is reported as skipped. Nothing
# outside the per-run namespace is touched.
#
# Env: MODES ("vhost userspace mq"), RUNS (3), VCPUS (4), MEMORY_MIB (1024),
#      DURATION (15, seconds per iperf3 case), STREAMS (4, parallel streams),
#      SIZE_MIB (256, HTTP fallback transfer), MQ_PAIRS (4),
#      OUT (bench-kvm-vhost.json), FLUXVM_HYPERVISOR, KERNEL, GOLDEN.
# The mq mode needs a guest kernel with CONFIG_VIRTIO_NET and >= MQ_PAIRS vCPUs
# to be interesting (VCPUS defaults to 4).
set -uo pipefail

if [ "${FLUXVM_KVM_BENCH:-0}" != "1" ]; then
  echo "SKIP: opt-in benchmark; set FLUXVM_KVM_BENCH=1 (needs root, KVM, dnsmasq, the golden agent image)"
  exit 0
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODES="${MODES:-vhost userspace mq}"
RUNS="${RUNS:-3}"
VCPUS="${VCPUS:-4}"
MEMORY_MIB="${MEMORY_MIB:-1024}"
DURATION="${DURATION:-15}"
STREAMS="${STREAMS:-4}"
SIZE_MIB="${SIZE_MIB:-256}"
MQ_PAIRS="${MQ_PAIRS:-4}"
OUT="${OUT:-${PROJECT_DIR}/bench-kvm-vhost.json}"
KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux-5.10.225-no-acpi}"
GOLDEN="${GOLDEN:-/var/lib/fluxvm/images/linux-agent.raw}"
HV="${FLUXVM_HYPERVISOR:-${PROJECT_DIR}/target/release/fluxvm-hypervisor}"
HOST_IP=192.168.100.1
TAP=fvbenchtap0
HTTP_PORT=18080
IPERF_PORT=15201

[ "$(uname -s)" = "Linux" ] && [ -e /dev/kvm ] || { echo "SKIP: needs Linux/KVM"; exit 0; }
[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 2; }
for t in ip dnsmasq python3 sha256sum; do
  command -v "$t" >/dev/null || { echo "missing tool: $t" >&2; exit 2; }
done
for f in "$KERNEL" "$GOLDEN" "$HV"; do
  [ -e "$f" ] || { echo "missing: $f" >&2; exit 2; }
done
HOST_IPERF=0; command -v iperf3 >/dev/null && HOST_IPERF=1
HAVE_MPSTAT=0; command -v mpstat >/dev/null && HAVE_MPSTAT=1
HAVE_PIDSTAT=0; command -v pidstat >/dev/null && HAVE_PIDSTAT=1
CLK_TCK="$(getconf CLK_TCK)"
HOST_CPUS="$(nproc)"

ROOT_TMP="$(mktemp -d)"
RAW_DIR="${OUT%.json}.raw"
mkdir -p "$RAW_DIR"
RESULTS="$ROOT_TMP/results.ndjson"; : >"$RESULTS"
NS=""; TMP=""; HV_PID=""; HTTP_PID=""; IPERF_PID=""

cleanup_run() {
  set +e
  for p in "$HV_PID" "$HTTP_PID" "$IPERF_PID"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  [ -n "$TMP" ] && [ -f "$TMP/dnsmasq.pid" ] && kill "$(cat "$TMP/dnsmasq.pid" 2>/dev/null)" 2>/dev/null
  sleep 1
  for p in "$HV_PID" "$HTTP_PID" "$IPERF_PID"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null; done
  [ -n "$TMP" ] && [ -f "$TMP/dnsmasq.pid" ] && kill -9 "$(cat "$TMP/dnsmasq.pid" 2>/dev/null)" 2>/dev/null
  [ -n "$NS" ] && ip netns delete "$NS" 2>/dev/null
  sleep 1
  HV_PID=""; HTTP_PID=""; IPERF_PID=""
}
on_exit() { cleanup_run; rm -rf "$ROOT_TMP"; }
trap on_exit EXIT
trap "exit 143" INT TERM HUP

cat >"$ROOT_TMP/server.py" <<'PY'
import http.server, sys
down, up = sys.argv[1], sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        data = open(down, "rb").read()
        self.send_response(200); self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)
    def do_PUT(self):
        n = int(self.headers.get("Content-Length") or 0)
        left = n
        while left:
            chunk = self.rfile.read(min(1 << 20, left))
            if not chunk: break
            left -= len(chunk)
        self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[3])), H).serve_forever()
PY

# CPU sampler: prints "<hv_ticks> <vhost_ticks> <total_ticks> <idle_ticks>".
cat >"$ROOT_TMP/cpu.py" <<'PY'
import os, sys
pid = sys.argv[1]
def ticks(path):
    try:
        f = open(path).read().rsplit(")", 1)[1].split()
        return int(f[11]) + int(f[12])          # utime + stime
    except Exception:
        return 0
hv = ticks(f"/proc/{pid}/stat")                  # all threads of the process
vh = 0
for d in os.listdir("/proc"):
    if d.isdigit():
        try:
            if open(f"/proc/{d}/comm").read().strip() == f"vhost-{pid}":
                vh += ticks(f"/proc/{d}/stat")
        except Exception:
            pass
cpu = open("/proc/stat").readline().split()[1:]
print(hv, vh, sum(int(x) for x in cpu), int(cpu[3]) + int(cpu[4]))
PY

# Parse one measurement into a JSON object (stdin: tool output).
cat >"$ROOT_TMP/parse.py" <<'PY'
import json, sys
kind, proto = sys.argv[1], sys.argv[2]
raw = sys.stdin.read()
out = {"mbit_per_s": None}
try:
    if kind == "iperf3":
        j = json.loads(raw[raw.index("{"):])
        e = j.get("end", {})
        if proto == "tcp":
            s = e.get("sum_received") or e.get("sum") or {}
            out["mbit_per_s"] = round(s.get("bits_per_second", 0) / 1e6, 1)
            sent = e.get("sum_sent") or {}
            out["retransmits"] = sent.get("retransmits")
        else:
            s = e.get("sum") or {}
            out["mbit_per_s"] = round(s.get("bits_per_second", 0) / 1e6, 1)
            out["loss_percent"] = s.get("lost_percent")
            out["jitter_ms"] = s.get("jitter_ms")
    else:                                         # curl -w '%{speed_*}' bytes/s
        out["mbit_per_s"] = round(float(raw.strip().split()[-1]) * 8 / 1e6, 1)
except Exception as exc:
    out["error"] = f"{type(exc).__name__}: {exc}"
print(json.dumps(out))
PY

agent() {   # agent "<shell command>" [timeout]
  python3 - "$TMP/vsock.sock" "$1" "${2:-40}" <<'PY'
import json, socket, sys
sock, cmd, t = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = socket.socket(socket.AF_UNIX); s.settimeout(t + 10); s.connect(sock)
f = s.makefile("rwb")
f.write(b"CONNECT 17777\n"); f.flush()
ack = f.readline()
if not ack.upper().startswith(b"OK"): print("AGENT-ERR " + ack.decode()); sys.exit(97)
f.write((json.dumps({"op": "exec", "command": cmd, "timeout_seconds": t}) + "\n").encode()); f.flush()
r = json.loads(f.readline())
sys.stdout.write(r.get("stdout", "") + r.get("stderr", ""))
sys.exit(0 if r.get("exit_code", 1) == 0 else 96)
PY
}

api_datapath() {   # the datapath the hypervisor reports for this run
  python3 - "$TMP/api.sock" <<'PY'
import json, socket, sys
try:
    s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1])
    s.sendall(b'{"action":"metrics"}\n')
    r = json.loads(s.makefile().readline())
    print(r.get("net_datapath") or "unreported")
except Exception as exc:
    print(f"unreported ({type(exc).__name__})")
PY
}

nsx() { ip netns exec "$NS" "$@"; }

mode_env() {
  case "$1" in
    vhost)     echo "FLUXVM_VHOST_NET=1 FLUXVM_NET_QUEUE_PAIRS=1" ;;
    userspace) echo "FLUXVM_VHOST_NET=0 FLUXVM_NET_QUEUE_PAIRS=1" ;;
    mq)        echo "FLUXVM_VHOST_NET=1 FLUXVM_NET_QUEUE_PAIRS=${MQ_PAIRS}" ;;
    *)         echo "unknown mode $1" >&2; return 1 ;;
  esac
}

# measure <mode> <run> <case> <kind iperf3|http> <proto> <guest command> <timeout>
measure() {
  local mode="$1" run="$2" name="$3" kind="$4" proto="$5" cmd="$6" to="$7"
  local raw="$RAW_DIR/${mode}-run${run}-${name}"
  local s0 s1 t0 t1 out parsed
  s0="$(python3 "$ROOT_TMP/cpu.py" "$HV_PID")"; t0="$(date +%s.%N)"
  local mp_pid="" ps_pid=""
  if [ "$HAVE_MPSTAT" = 1 ]; then mpstat -P ALL 1 "$to" >"$raw.mpstat.txt" 2>&1 & mp_pid=$!; fi
  if [ "$HAVE_PIDSTAT" = 1 ]; then pidstat -u -t -p "$HV_PID" 1 "$to" >"$raw.pidstat.txt" 2>&1 & ps_pid=$!; fi
  out="$(agent "$cmd" "$to" 2>&1)"
  s1="$(python3 "$ROOT_TMP/cpu.py" "$HV_PID")"; t1="$(date +%s.%N)"
  # Stop only the samplers started here; the hypervisor and servers keep running.
  for p in $mp_pid $ps_pid; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
  printf '%s\n' "$out" >"$raw.txt"
  parsed="$(printf '%s' "$out" | python3 "$ROOT_TMP/parse.py" "$kind" "$proto")"
  python3 - "$mode" "$run" "$name" "$parsed" "$s0" "$s1" "$t0" "$t1" "$CLK_TCK" "$HOST_CPUS" >>"$RESULTS" <<'PY'
import json, sys
mode, run, name, parsed, s0, s1, t0, t1, tck, ncpu = sys.argv[1:]
a = [int(x) for x in s0.split()]; b = [int(x) for x in s1.split()]
secs = max(float(t1) - float(t0), 1e-6); tck = float(tck); ncpu = int(ncpu)
d = [y - x for x, y in zip(a, b)]
rec = json.loads(parsed)
rec.update({
    "mode": mode, "run": int(run), "case": name, "seconds": round(secs, 2),
    "host_cpu": {
        "hypervisor_cores": round(d[0] / tck / secs, 3),
        "vhost_threads_cores": round(d[1] / tck / secs, 3),
        "host_busy_percent": round(100.0 * (d[2] - d[3]) / max(d[2], 1), 1),
        "host_cpus": ncpu,
    },
})
mbit = rec.get("mbit_per_s")
cores = rec["host_cpu"]["hypervisor_cores"] + rec["host_cpu"]["vhost_threads_cores"]
rec["host_cpu"]["datapath_cores"] = round(cores, 3)
rec["mbit_per_s_per_datapath_core"] = round(mbit / cores, 1) if mbit and cores > 0 else None
print(json.dumps(rec))
PY
  echo "  ${mode} run ${run} ${name}: $(tail -1 "$RESULTS" | python3 -c 'import json,sys; r=json.loads(sys.stdin.read()); print(r.get("mbit_per_s"), "Mbit/s,", r["host_cpu"]["datapath_cores"], "datapath cores")')"
}

one_run() {  # one_run <mode> <run>
  local mode="$1" run="$2" menv
  menv="$(mode_env "$mode")" || return 1
  NS="fvbench${mode}${run}"
  TMP="$ROOT_TMP/run-${mode}-${run}"; mkdir -p "$TMP"
  echo ""; echo "=== mode=${mode} run ${run}/${RUNS} (${menv}) ==="
  if ip netns list | grep -qw "$NS"; then echo "  namespace ${NS} already exists" >&2; return 1; fi
  ip netns add "$NS" && nsx ip link set lo up

  head -c $((SIZE_MIB * 1024 * 1024)) /dev/urandom >"$TMP/down.bin"
  nsx dnsmasq --conf-file=/dev/null --no-resolv --no-hosts --port=0 --bind-dynamic --interface="$TAP" \
    --except-interface=lo --dhcp-range=192.168.100.50,192.168.100.60,12h \
    --dhcp-option=3,${HOST_IP} --dhcp-leasefile="$TMP/leases" --pid-file="$TMP/dnsmasq.pid" \
    --log-facility="$TMP/dnsmasq.log" || { echo "  dnsmasq failed to start" >&2; return 1; }
  nsx python3 "$ROOT_TMP/server.py" "$TMP/down.bin" "$TMP/up.bin" "$HTTP_PORT" >"$TMP/server.log" 2>&1 &
  HTTP_PID=$!
  if [ "$HOST_IPERF" = 1 ]; then
    nsx iperf3 -s -p "$IPERF_PORT" >"$TMP/iperf3.log" 2>&1 &
    IPERF_PID=$!
  fi

  cp --sparse=always "$GOLDEN" "$TMP/root.raw"; chmod 0600 "$TMP/root.raw"
  cat >"$TMP/boot.json" <<JSON
{
  "kernel": "$KERNEL",
  "rootfs": "$TMP/root.raw",
  "vcpus": ${VCPUS},
  "memory_mib": ${MEMORY_MIB},
  "engine": "kvm",
  "tap": "$TAP",
  "mac": "02:fa:ce:00:00:01",
  "vsock_cid": 3,
  "vsock_uds": "$TMP/vsock.sock",
  "kernel_args": "console=ttyS0 earlyprintk=serial,ttyS0,115200 ignore_loglevel reboot=k panic=1 pci=off root=/dev/vda rw random.trust_cpu=on rdrand=force virtio_mmio.device=0x200@0xfeb00000:5 virtio_mmio.device=0x200@0xfeb00200:6"
}
JSON
  # shellcheck disable=SC2086
  nsx env $menv FLUXVM_KVM_RUN_SECS=3600 "$HV" --api-sock "$TMP/api.sock" --boot-config "$TMP/boot.json" >"$TMP/hv.log" 2>&1 &
  HV_PID=$!

  local ready=0 i
  for i in $(seq 1 120); do
    if [ -S "$TMP/vsock.sock" ] && agent "true" 8 >/dev/null 2>&1; then ready=1; break; fi
    kill -0 "$HV_PID" 2>/dev/null || break
    sleep 2
  done
  if [ "$ready" != 1 ]; then echo "  guest agent never answered" >&2; tail -20 "$TMP/hv.log" >&2; return 1; fi

  local ip="" out
  for i in $(seq 1 15); do
    out="$(agent "ip -4 -o addr show scope global | awk '{print \$4}'" 8 2>&1)"
    if echo "$out" | grep -q "^192\.168\.100\."; then ip="${out%%/*}"; break; fi
    sleep 2
  done
  [ -n "$ip" ] || { echo "  no DHCP lease" >&2; return 1; }

  local datapath guest_queues guest_iperf=0
  datapath="$(api_datapath)"
  guest_queues="$(agent "ls -d /sys/class/net/e*/queues/rx-* 2>/dev/null | wc -l" 10 2>&1 | tr -d '[:space:]')"
  [ "$HOST_IPERF" = 1 ] && agent "command -v iperf3" 8 >/dev/null 2>&1 && guest_iperf=1
  echo "  guest ${ip}; reported datapath: ${datapath}; guest rx queues: ${guest_queues}; iperf3 guest=${guest_iperf} host=${HOST_IPERF}"
  grep -E "^\[net\] datapath" "$TMP/hv.log" | tail -3 | sed 's/^/  hv: /'
  python3 - "$mode" "$run" "$datapath" "${guest_queues:-0}" >>"$ROOT_TMP/runs.ndjson" <<'PY'
import json, sys
print(json.dumps({"mode": sys.argv[1], "run": int(sys.argv[2]), "datapath": sys.argv[3],
                  "guest_rx_queues": int(sys.argv[4] or 0)}))
PY

  agent "ping -c 3 -W 2 ${HOST_IP} >/dev/null" 15 >/dev/null 2>&1   # warm ARP / neighbour caches
  local to=$((DURATION + 30))
  if [ "$guest_iperf" = 1 ]; then
    measure "$mode" "$run" tcp_guest_to_host iperf3 tcp "iperf3 -c ${HOST_IP} -p ${IPERF_PORT} -t ${DURATION} -P ${STREAMS} -J" "$to"
    measure "$mode" "$run" tcp_host_to_guest iperf3 tcp "iperf3 -c ${HOST_IP} -p ${IPERF_PORT} -t ${DURATION} -P ${STREAMS} -R -J" "$to"
    measure "$mode" "$run" udp_guest_to_host iperf3 udp "iperf3 -c ${HOST_IP} -p ${IPERF_PORT} -u -b 0 -t ${DURATION} -P ${STREAMS} -J" "$to"
    measure "$mode" "$run" udp_host_to_guest iperf3 udp "iperf3 -c ${HOST_IP} -p ${IPERF_PORT} -u -b 0 -t ${DURATION} -P ${STREAMS} -R -J" "$to"
  else
    echo "  no iperf3 on both ends: TCP via HTTP transfer (${SIZE_MIB} MiB), UDP skipped"
    measure "$mode" "$run" tcp_host_to_guest http tcp "curl -sS --max-time 300 -o /dev/null -w '%{speed_download}' http://${HOST_IP}:${HTTP_PORT}/down.bin" 320
    measure "$mode" "$run" tcp_guest_to_host http tcp "head -c $((SIZE_MIB * 1024 * 1024)) /dev/zero > /tmp/u.bin; curl -sS --max-time 300 -T /tmp/u.bin -o /dev/null -w '%{speed_upload}' http://${HOST_IP}:${HTTP_PORT}/up.bin" 320
  fi
  grep -Eq "Kernel panic|panicked at|Oops:|BUG:" "$TMP/hv.log" && echo "  WARNING: panic/oops in the hypervisor log" >&2
  return 0
}

: >"$ROOT_TMP/runs.ndjson"
FAILED_RUNS=0
for mode in $MODES; do
  for run in $(seq 1 "$RUNS"); do
    one_run "$mode" "$run" || FAILED_RUNS=$((FAILED_RUNS + 1))
    cleanup_run
    NS=""; TMP=""
  done
done

python3 - "$RESULTS" "$ROOT_TMP/runs.ndjson" "$OUT" <<PY
import json, platform, statistics, sys, datetime
results = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
runs = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
modes = {}
for r in runs:
    m = modes.setdefault(r["mode"], {"runs": [], "datapaths": [], "guest_rx_queues": []})
    m["runs"].append(r["run"]); m["datapaths"].append(r["datapath"]); m["guest_rx_queues"].append(r["guest_rx_queues"])
for name, m in modes.items():
    cases = {}
    for r in results:
        if r["mode"] == name:
            cases.setdefault(r["case"], []).append(r)
    summary = {}
    for case, rs in cases.items():
        def med(f):
            v = [f(x) for x in rs if f(x) is not None]
            return round(statistics.median(v), 3) if v else None
        summary[case] = {
            "samples": len(rs),
            "median_mbit_per_s": med(lambda x: x.get("mbit_per_s")),
            "median_datapath_cores": med(lambda x: x["host_cpu"]["datapath_cores"]),
            "median_hypervisor_cores": med(lambda x: x["host_cpu"]["hypervisor_cores"]),
            "median_vhost_threads_cores": med(lambda x: x["host_cpu"]["vhost_threads_cores"]),
            "median_host_busy_percent": med(lambda x: x["host_cpu"]["host_busy_percent"]),
            "median_mbit_per_s_per_datapath_core": med(lambda x: x.get("mbit_per_s_per_datapath_core")),
            "median_loss_percent": med(lambda x: x.get("loss_percent")),
        }
    m["summary"] = summary
doc = {
    "benchmark": "kvm-vhost-end-to-end",
    "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "host": {"kernel": platform.release(), "cpus": $HOST_CPUS},
    "config": {"vcpus": $VCPUS, "memory_mib": $MEMORY_MIB, "duration_s": $DURATION,
               "streams": $STREAMS, "runs": $RUNS, "mq_pairs": $MQ_PAIRS,
               "http_fallback_size_mib": $SIZE_MIB, "iperf3_host": bool($HOST_IPERF)},
    "note": "End-to-end guest<->host numbers. Compare modes only when each mode's reported datapath matches its name; do not mix with host microbenchmarks.",
    "modes": modes,
    "samples": results,
}
json.dump(doc, open(sys.argv[3], "w"), indent=2)
print("wrote", sys.argv[3])
PY
[ "$FAILED_RUNS" -eq 0 ] || { echo "$FAILED_RUNS run(s) failed; see output above" >&2; exit 1; }
exit 0
