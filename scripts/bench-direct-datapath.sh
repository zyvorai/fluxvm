#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Baseline for the direct (bridge-less) datapath plan: how much does the CURRENT
# bridge chain cost between an outer device and a VM's tap?
#
# netns mode (default, Linux root, no KVM): rebuild today's topologies out of
# netns + veth + bridge devices, and measure ping latency (p50/p99), TCP
# throughput and small-packet UDP rate through each.
#
#   floor              client ⇄ guest, one veth pair, no bridge. Ceiling for what
#                      any direct path can approach with these stand-in devices.
#   cni-bridge         node → lxc ⇄ eth0 → fvcb → fvn ⇄ fvh → fvbh → tap → guest
#                      (what containerd-shim prepare_cni_l2 builds today)
#   standalone-bridge  LAN peer → uplink → vmbr0 → tap → guest
#
# The same two paths with FluxVM's real eBPF programs (needs built objects: FLUXVM_BPF_DIR, or
# `scripts/build-ebpf.sh` output in dist/bpf), so bridge and direct are compared like for like:
#   cni-bridge-fx / standalone-bridge-fx   the bridge chains PLUS fluxvm_egress (allow-all) on the
#                                          tap stand-in -- what production bridge VMs run
#   cni-direct / standalone-direct         no bridge: fluxvm_egress + the direct redirect, and
#                                          fluxvm_direct_in on the outer device (bpf_redirect_peer /
#                                          bpf_redirect between the veth stand-ins)
# A veth pair stands in for the tap in every topology.
#
# HONESTY BOUNDS: a veth stands in for the tap, so this measures host forwarding
# cost only (bridge hops, fdb lookups, netfilter-bridge hooks, extra veth hops).
# It does NOT include virtio-net / QEMU / vhost cost. It is a same-host,
# single-flow microbenchmark: use it to compare topologies, not as an absolute
# throughput claim. Real guests: set BENCH_TARGET_IP (see below).
#
# Real-guest mode: boot the pod/VM yourself with iperf3 -s running in the guest,
# then measure from this host:
#   BENCH_TARGET_IP=10.0.0.5 BENCH_LABEL=cni-bridge-vm ./scripts/bench-direct-datapath.sh
#
#   sudo ./scripts/bench-direct-datapath.sh
#   sudo BENCH_RUNS=5 BENCH_DURATION=10 BENCH_TOPOLOGIES="floor cni-bridge" ./scripts/bench-direct-datapath.sh
#   sudo BENCH_OUT=docs/benchmarks/evidence/direct-datapath-baseline.txt ./scripts/bench-direct-datapath.sh
#
# Knobs: BENCH_INTERLEAVE=1 (one run of every topology per round, so load drift cannot favour one)
# BENCH_RUNS (3) BENCH_DURATION seconds per iperf3 run (5) BENCH_PING_COUNT
# (500) BENCH_PING_INTERVAL (0.01) BENCH_UDP_LEN bytes (64) BENCH_MTU (1500)
# BENCH_TOPOLOGIES BENCH_OUT BENCH_JSON BENCH_TARGET_IP BENCH_LABEL BENCH_IPERF_PORT
#
set -euo pipefail

RUNS="${BENCH_RUNS:-3}"
DURATION="${BENCH_DURATION:-5}"
PING_COUNT="${BENCH_PING_COUNT:-500}"
PING_INTERVAL="${BENCH_PING_INTERVAL:-0.01}"
UDP_LEN="${BENCH_UDP_LEN:-64}"
MTU="${BENCH_MTU:-1500}"
TOPOLOGIES="${BENCH_TOPOLOGIES:-floor cni-bridge standalone-bridge}"
BPF_DIR="${FLUXVM_BPF_DIR:-}"
OUT="${BENCH_OUT:-}"
JSON_OUT="${BENCH_JSON:-}"
TARGET_IP="${BENCH_TARGET_IP:-}"
LABEL="${BENCH_LABEL:-external}"
PORT="${BENCH_IPERF_PORT:-5201}"

CLIENT_IP=10.99.0.1
GUEST_IP=10.99.0.2
NSP="fvbd$$"
WORKDIR="${TMPDIR:-/tmp}/bench-direct-datapath-$$"
PIN="/sys/fs/bpf/fvbd$$"
RESULTS="${WORKDIR}/results.tsv"

say() { echo "bench-direct-datapath: $*"; }
skip() { say "SKIP: $*" >&2; exit 0; }

if [[ "$(uname -s)" != "Linux" ]]; then
  skip "Linux required (on $(uname -s))"
fi

# Hop counts are static facts about each topology (devices a packet crosses,
# counting bridges); printed next to the numbers so they can be compared.
declare -A HOPS=([floor]=2 [cni-bridge]=8 [standalone-bridge]=5 [cni-bridge-fx]=8 [standalone-bridge-fx]=5 [cni-direct]=4 [standalone-direct]=4)

if [[ -z "$TARGET_IP" ]]; then
  [[ "$(id -u)" -eq 0 ]] || skip "root required for netns mode (run with sudo)"
  command -v ip >/dev/null || skip "iproute2 'ip' not found"
  ip netns list >/dev/null 2>&1 || skip "'ip netns' unavailable"
fi
command -v ping >/dev/null || skip "ping not found"
if [[ "$(id -u)" -ne 0 && -z "${BENCH_PING_INTERVAL:-}" ]]; then
  PING_INTERVAL=0.2; PING_COUNT="${BENCH_PING_COUNT:-100}"   # ping needs root below 0.2s
fi
command -v python3 >/dev/null || skip "python3 not found"
HAVE_IPERF=0
command -v iperf3 >/dev/null && HAVE_IPERF=1
[[ "$HAVE_IPERF" -eq 1 ]] || say "iperf3 not found: throughput/pps will be skipped (latency only)" >&2

mkdir -p "$WORKDIR"
: >"$RESULTS"

# Namespaces are found by prefix (not tracked in a variable) so this also works
# when the measurement runs in the `| tee` subshell and the script is interrupted.
del_namespaces() {
  local n
  [[ -n "$TARGET_IP" ]] && return 0
  for n in $(ip netns list 2>/dev/null | awk '{print $1}' | grep "^${NSP}-" || true); do
    ip netns del "$n" 2>/dev/null || true
  done
}

cleanup() {
  local rc=$?
  local pf
  for pf in "$WORKDIR"/iperf-*.pid; do
    if [[ -f "$pf" ]]; then kill "$(cat "$pf")" 2>/dev/null || true; fi
  done
  del_namespaces
  rm -rf "$WORKDIR" "$PIN"
  exit "$rc"
}
trap cleanup EXIT INT TERM

# ── topology helpers ────────────────────────────────────────────────
mkns() {
  local n
  for n in "$@"; do
    ip netns add "${NSP}-${n}"
    ip -n "${NSP}-${n}" link set lo up
    ip netns exec "${NSP}-${n}" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  done
}
ipn() { local n="$1"; shift; ip -n "${NSP}-${n}" "$@"; }
# veth NS_A DEV_A NS_B DEV_B: create DEV_A in NS_A with its peer DEV_B directly in NS_B
veth() {
  ipn "$1" link add "$2" mtu "$MTU" type veth peer name "$4" netns "${NSP}-$3"
  ipn "$3" link set "$4" mtu "$MTU"
}
up() { local n="$1"; shift; local d; for d in "$@"; do ipn "$n" link set "$d" up; done; }
teardown_topology() { del_namespaces; }

# Each setup_* leaves CLIENT_NS (where the client runs) and SERVER_NS (guest) set.
setup_floor() {
  mkns client guest
  veth client f0 guest eth0
  ipn client addr add "${CLIENT_IP}/24" dev f0
  ipn guest addr add "${GUEST_IP}/24" dev eth0
  up client f0; up guest eth0
  CLIENT_NS=client; SERVER_NS=guest
}

# Mirrors containerd-shim prepare_cni_l2: pod eth0 and fvn are ports of fvcb;
# fvh and the tap are ports of the host bridge fvbh. The node-side client sends
# through lxc0 (the Cilium host-side veth peer).
setup_cni_bridge() {
  mkns host pod guest
  veth host lxc0 pod eth0
  ipn pod link add fvcb type bridge
  ipn pod link set eth0 master fvcb
  veth host fvh pod fvn
  ipn pod link set fvn master fvcb
  ipn host link add fvbh type bridge
  ipn host link set fvh master fvbh
  veth host tap0h guest eth0
  ipn host link set tap0h master fvbh
  ipn host addr add "${CLIENT_IP}/24" dev lxc0
  ipn guest addr add "${GUEST_IP}/24" dev eth0
  up host lxc0 fvh fvbh tap0h; up pod eth0 fvn fvcb; up guest eth0
  CLIENT_NS=host; SERVER_NS=guest
}

# guest → tap → vmbr0 → uplink, with a LAN peer on the far side of the uplink.
setup_standalone_bridge() {
  mkns lan host guest
  veth lan up0 host nic0
  ipn host link add vmbr0 type bridge
  ipn host link set nic0 master vmbr0
  veth host tap0h guest eth0
  ipn host link set tap0h master vmbr0
  ipn lan addr add "${CLIENT_IP}/24" dev up0
  ipn guest addr add "${GUEST_IP}/24" dev eth0
  up lan up0; up host nic0 vmbr0 tap0h; up guest eth0
  CLIENT_NS=lan; SERVER_NS=guest
}

# ── FluxVM programs on the stand-ins (the *-fx and *-direct topologies) ─────────
tcn()   { local n="$1"; shift; nsenter --net="/run/netns/${NSP}-${n}" -- tc "$@"; }
le32()  { printf '%02x %02x %02x %02x' $(($1 & 255)) $((($1 >> 8) & 255)) $((($1 >> 16) & 255)) $((($1 >> 24) & 255)); }
Z8='00 00 00 00 00 00 00 00'
# struct iface_config: identity default_allow enforce_cidr enforce_l4 sample_rate allow_icmp rate rate pod_id pad
IFACE_ALLOW() { echo "$(le32 1) $(le32 1) $(le32 0) $(le32 0) $(le32 0) $(le32 1) $Z8 $Z8 $(le32 0) $(le32 0)"; }
mapupd() { # shellcheck disable=SC2086
  bpftool map update pinned "$1" key hex $2 value hex $3; }
ifidx() { ipn "$1" -o link show "$2" | cut -d: -f1; }
have_bpf() {
  [[ -n "$BPF_DIR" && -f "$BPF_DIR/fluxvm_tc.bpf.o" && -f "$BPF_DIR/fluxvm_direct.bpf.o" ]] && command -v bpftool >/dev/null && command -v tc >/dev/null && command -v nsenter >/dev/null
}
# load_fx NS DEV [PEER MODE]: fluxvm_egress on DEV's ingress (guest -> out); with PEER, also the redirect
# tail (MODE 1 = redirect_peer, 2 = redirect). Allow-all policy, like a production VM with no rules.
load_fx() {
  local ns="$1" dev="$2" peer="${3:-}" mode="${4:-}" d idx
  d="$PIN/$dev"; mkdir -p "$d/maps"
  bpftool prog load "$BPF_DIR/fluxvm_tc.bpf.o" "$d/prog" type classifier pinmaps "$d/maps"
  idx="$(ifidx "$ns" "$dev")"
  mapupd "$d/maps/fluxvm_id" "$(le32 "$idx")" "$(IFACE_ALLOW)"
  if [[ -n "$peer" ]]; then
    mapupd "$d/maps/fluxvm_direct" "$(le32 "$idx")" "$(le32 "$(ifidx "$ns" "$peer")") $(le32 "$mode") $(le32 0) $(le32 0)"
  fi
  tcn "$ns" qdisc add dev "$dev" clsact
  tcn "$ns" filter add dev "$dev" ingress bpf da pinned "$d/prog"
}
# load_direct_in NS OUTER TAP MODE [GUEST_MAC [GUEST_IP]]: fluxvm_direct_in on OUTER's ingress
# (MODE 1 = all to the tap, 2 = steer by destination MAC, and ARP requests by target IP -- a LAN
# peer can only discover the guest through the declared GUEST_IP, as `direct.guest_ips` does).
load_direct_in() {
  local ns="$1" outer="$2" tap="$3" mode="$4" mac="${5:-}" ip="${6:-}" d a b c e
  d="$PIN/in-$outer"; mkdir -p "$d/maps"
  bpftool prog load "$BPF_DIR/fluxvm_direct.bpf.o" "$d/prog" type classifier pinmaps "$d/maps"
  mapupd "$d/maps/fluxvm_direct_in" "$(le32 "$(ifidx "$ns" "$outer")")" "$(le32 "$(ifidx "$ns" "$tap")") $(le32 "$mode")"
  if [[ -n "$mac" ]]; then
    mapupd "$d/maps/fluxvm_dmac" "$(echo "$mac" | tr ':' ' ') 00 00" "$(le32 "$(ifidx "$ns" "$tap")")"
  fi
  if [[ -n "$ip" ]]; then
    IFS=. read -r a b c e <<<"$ip"
    mapupd "$d/maps/fluxvm_dip" "$(printf '%02x %02x %02x %02x' "$a" "$b" "$c" "$e")" "$(le32 "$(ifidx "$ns" "$tap")")"
  fi
  tcn "$ns" qdisc add dev "$outer" clsact 2>/dev/null || true
  tcn "$ns" filter add dev "$outer" ingress bpf da pinned "$d/prog"
}
guest_mac() { ipn "$1" link show "$2" | awk '/link\/ether/{print $2}'; }

setup_cni_bridge_fx() {
  setup_cni_bridge
  have_bpf || { say "SKIP cni-bridge-fx: set FLUXVM_BPF_DIR to built objects" >&2; return 1; }
  load_fx host tap0h                      # allow-all; no direct entry -> TC_ACT_OK -> the bridge
}
setup_standalone_bridge_fx() {
  setup_standalone_bridge
  have_bpf || { say "SKIP standalone-bridge-fx: set FLUXVM_BPF_DIR to built objects" >&2; return 1; }
  load_fx host tap0h
}

# node → lxc0 ⇄ eth0 [direct_in → redirect] tap ⇄ guest: no bridge, no second veth pair.
setup_cni_direct() {
  have_bpf || { say "SKIP cni-direct: set FLUXVM_BPF_DIR to built objects" >&2; return 1; }
  mkns host pod guest
  veth host lxc0 pod eth0
  veth pod tap0 guest eth0                # the tap stand-in lives in the pod netns
  ipn host addr add "${CLIENT_IP}/24" dev lxc0
  ipn guest addr add "${GUEST_IP}/24" dev eth0
  up host lxc0; up pod eth0 tap0; up guest eth0
  load_fx pod tap0 eth0 1                 # guest -> eth0 : redirect_peer
  load_direct_in pod eth0 tap0 1          # eth0 -> tap0  : redirect
  CLIENT_NS=host; SERVER_NS=guest
}

# LAN peer → uplink [direct_in steers by MAC] tap ⇄ guest: no vmbr0.
setup_standalone_direct() {
  have_bpf || { say "SKIP standalone-direct: set FLUXVM_BPF_DIR to built objects" >&2; return 1; }
  mkns lan host guest
  veth lan up0 host nic0
  veth host tap0h guest eth0
  ipn lan addr add "${CLIENT_IP}/24" dev up0
  ipn guest addr add "${GUEST_IP}/24" dev eth0
  up lan up0; up host nic0 tap0h; up guest eth0
  load_fx host tap0h nic0 2               # guest -> uplink : redirect
  load_direct_in host nic0 tap0h 2 "$(guest_mac guest eth0)" "$GUEST_IP"
  CLIENT_NS=lan; SERVER_NS=guest
}

# ── measurement ─────────────────────────────────────────────────────
# run_client: run a command in CLIENT_NS, or locally in external-target mode.
run_client() {
  if [[ -n "$CLIENT_NS" ]]; then ip netns exec "${NSP}-${CLIENT_NS}" "$@"; else "$@"; fi
}

record() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >>"$RESULTS"; }

# ping_stats: read ping output on stdin → "p50_ms p99_ms loss_pct"
ping_stats() {
  python3 -c '
import math, re, sys
text = sys.stdin.read()
t = sorted(float(x) for x in re.findall(r"time=([0-9.]+)", text))
m = re.search(r"([0-9.]+)% packet loss", text)
loss = float(m.group(1)) if m else 100.0
def pct(p):
    if not t:
        return float("nan")
    return t[min(len(t) - 1, max(0, math.ceil(p / 100.0 * len(t)) - 1))]
print("%.4f %.4f %.1f" % (pct(50), pct(99), loss))
'
}

# iperf_metric: read iperf3 -J on stdin, argument tcp|udp → "value extra"
#   tcp: Gbit/s          udp: Mpps and loss percent
iperf_metric() {
  python3 -c '
import json, sys
mode = sys.argv[1]
try:
    d = json.load(sys.stdin)
    e = d["end"]
    if mode == "tcp":
        print("%.3f 0" % (e["sum_received"]["bits_per_second"] / 1e9))
    else:
        s = e["sum"]
        secs = s["seconds"] or 1.0
        print("%.4f %.2f" % (s["packets"] / secs / 1e6, s.get("lost_percent", 0.0)))
except Exception as ex:
    print("nan nan")
    sys.stderr.write("iperf3 parse error: %s\n" % ex)
' "$1"
}

start_iperf_server() {
  local pidf="${WORKDIR}/iperf-$1.pid"
  if [[ -n "$SERVER_NS" ]]; then
    ip netns exec "${NSP}-${SERVER_NS}" iperf3 -s -D -p "$PORT" -I "$pidf" >/dev/null
    sleep 0.5
  fi
}
stop_iperf_server() {
  local pidf="${WORKDIR}/iperf-$1.pid"
  [[ -f "$pidf" ]] && { kill "$(cat "$pidf")" 2>/dev/null || true; rm -f "$pidf"; }
}

# measure TOPO TARGET [FIRST_RUN [COUNT]]: COUNT runs numbered from FIRST_RUN (default: all RUNS).
measure() {
  local topo="$1" target="$2" first="${3:-1}" count="${4:-$RUNS}" i out p50 p99 loss val extra tcpv
  say "== ${topo} (hops=${HOPS[$topo]:-?}, target=${target}) =="
  if ! run_client ping -c 3 -W 2 -q "$target" >/dev/null 2>&1; then
    say "FAIL ${topo}: no connectivity to ${target}" >&2
    record "$topo" connectivity 0 fail
    return 1
  fi
  run_client ping -c 20 -i 0.01 -W 1 -q "$target" >/dev/null 2>&1 || true   # warm fdb/neigh
  for ((i = first; i < first + count; i++)); do
    out=$(run_client ping -c "$PING_COUNT" -i "$PING_INTERVAL" -W 1 "$target" 2>&1 || true)
    read -r p50 p99 loss <<<"$(ping_stats <<<"$out")"
    record "$topo" ping_p50_ms "$i" "$p50"
    record "$topo" ping_p99_ms "$i" "$p99"
    record "$topo" ping_loss_pct "$i" "$loss"
    say "  run ${i}: ping p50=${p50}ms p99=${p99}ms loss=${loss}%"
  done
  if [[ "$HAVE_IPERF" -eq 1 ]]; then
    start_iperf_server "$topo"
    for ((i = first; i < first + count; i++)); do
      out=$(run_client iperf3 -c "$target" -p "$PORT" -t "$DURATION" -J 2>/dev/null || true)
      read -r val extra <<<"$(iperf_metric tcp <<<"$out")"
      tcpv="$val"
      record "$topo" tcp_gbps "$i" "$tcpv"
      out=$(run_client iperf3 -c "$target" -p "$PORT" -u -b 0 -l "$UDP_LEN" -t "$DURATION" -J 2>/dev/null || true)
      read -r val extra <<<"$(iperf_metric udp <<<"$out")"
      record "$topo" "udp${UDP_LEN}_mpps" "$i" "$val"
      record "$topo" "udp${UDP_LEN}_loss_pct" "$i" "$extra"
      say "  run ${i}: tcp=${tcpv} Gbit/s udp${UDP_LEN}=${val} Mpps loss=${extra}%"
    done
    stop_iperf_server "$topo"
  fi
}

report() {
  python3 - "$RESULTS" "$JSON_OUT" "$RUNS" <<'PY'
import json, statistics, sys
path, json_out, runs = sys.argv[1], sys.argv[2], sys.argv[3]
rows = {}
order = []
for line in open(path):
    topo, metric, run, val = line.rstrip("\n").split("\t")
    if topo not in order:
        order.append(topo)
    try:
        v = float(val)
        if v != v:          # nan (failed parse) -> null, keeps the JSON strict
            v = None
    except ValueError:
        v = None
    rows.setdefault(topo, {}).setdefault(metric, []).append(v)
summary = {}
for topo in order:
    summary[topo] = {}
    for metric, vals in rows[topo].items():
        good = [x for x in vals if x is not None and x == x]
        summary[topo][metric] = {
            "median": statistics.median(good) if good else None,
            "runs": vals,
        }
metrics = sorted({m for t in summary.values() for m in t if m != "connectivity"})
print()
print("== summary (median of %s runs; lower is better for ping, higher for tcp/udp) ==" % runs)
print("%-28s" % "metric" + "".join("%-20s" % t for t in order))
for m in metrics:
    cells = []
    for t in order:
        med = summary[t].get(m, {}).get("median")
        cells.append("%-20s" % ("n/a" if med is None else "%.4g" % med))
    print("%-28s" % m + "".join(cells))
if json_out:
    with open(json_out, "w") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
    print("json: " + json_out)
PY
}

banner() {
  echo "== FluxVM direct-datapath baseline =="
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(uname -srm) cpus=$(nproc 2>/dev/null || echo ?)"
  echo "loadavg(1/5/15m at start): $(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo ?)  (other workloads inflate variance)"
  echo "iproute2: $(ip -V 2>&1 | head -1)"
  [[ "$HAVE_IPERF" -eq 1 ]] && echo "iperf3: $(iperf3 --version 2>&1 | head -1)"
  if [[ -d /proc/sys/net/bridge ]]; then echo "br_netfilter: loaded (bridge-nf-call-iptables=$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>/dev/null || echo ?))"; else echo "br_netfilter: not loaded"; fi
  echo "runs=${RUNS} duration=${DURATION}s ping_count=${PING_COUNT} udp_len=${UDP_LEN} mtu=${MTU}"
  echo "scope: host forwarding cost only; veth stands in for the tap (no virtio/QEMU)"
  if have_bpf; then echo "bpf objects: $BPF_DIR (fluxvm_egress + fluxvm_direct_in for the *-fx / *-direct topologies)"; else echo "bpf objects: not set (the *-fx / *-direct topologies are skipped)"; fi
}

main() {
  if [[ -n "$TARGET_IP" ]]; then
    CLIENT_NS=""; SERVER_NS=""
    HOPS[$LABEL]="${BENCH_HOPS:-?}"
    measure "$LABEL" "$TARGET_IP" || true
    return
  fi
  local t r
  # Sequential (default): all runs of one topology, then the next. On a shared machine load drifts
  # during a long benchmark and biases whichever topology happened to run in a busy stretch.
  # BENCH_INTERLEAVE=1 instead makes each ROUND measure every topology once (set up, one run,
  # torn down), so drift lands on all of them equally.
  if [[ "${BENCH_INTERLEAVE:-0}" == 1 ]]; then
    for ((r = 1; r <= RUNS; r++)); do
      for t in $TOPOLOGIES; do
        run_topology "$t" "$r" 1 || true
      done
    done
  else
    for t in $TOPOLOGIES; do
      run_topology "$t" 1 "$RUNS" || true
    done
  fi
}

# run_topology TOPO FIRST_RUN COUNT: set up, measure, tear down.
run_topology() {
  local t="$1" first="$2" count="$3"
  case "$t" in
    floor) setup_floor ;;
    cni-bridge) setup_cni_bridge ;;
    standalone-bridge) setup_standalone_bridge ;;
    cni-bridge-fx) setup_cni_bridge_fx || { teardown_topology; return 0; } ;;
    standalone-bridge-fx) setup_standalone_bridge_fx || { teardown_topology; return 0; } ;;
    cni-direct) setup_cni_direct || { teardown_topology; return 0; } ;;
    standalone-direct) setup_standalone_direct || { teardown_topology; return 0; } ;;
    *) say "unknown topology '${t}' (floor|cni-bridge|standalone-bridge|cni-bridge-fx|standalone-bridge-fx|cni-direct|standalone-direct)" >&2; return 0 ;;
  esac
  measure "$t" "$GUEST_IP" "$first" "$count" || true
  rm -rf "$PIN"
  teardown_topology
}

if [[ -n "$OUT" ]]; then
  mkdir -p "$(dirname "$OUT")"
  { banner; main; report; } 2>&1 | tee "$OUT"
else
  banner; main; report
fi
