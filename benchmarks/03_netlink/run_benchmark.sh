#!/bin/bash
set -euo pipefail

RUNS_A=5
RUNS_B=5
RUNS_C=5
EVENTS_PER_RUN_A=20
EVENTS_PER_RUN_B=30
EVENTS_PER_RUN_C=50

TEST_IP="192.168.99.99"
TEST_IF="lo"

OUTPUT_BASE="output"
RAW_CSV="$OUTPUT_BASE/netlink_raw.csv"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

rm -rf "$OUTPUT_BASE"
mkdir -p "$OUTPUT_BASE"

echo "run,scenario,events_generated,events_captured,completeness_pct,latency_mean_ms,latency_median_ms,latency_stdev_ms,latency_p95_ms" > "$RAW_CSV"

echo "============================================================"
echo " Benchmark 3 — Précision et latence du monitoring Netlink"
echo " IP de test : $TEST_IP sur $TEST_IF"
echo "============================================================"
echo ""

cleanup_ip() {
    sudo ip addr del "${TEST_IP}/32" dev "$TEST_IF" 2>/dev/null || true
}
trap cleanup_ip EXIT

progress() {
    local current=$1 total=$2 label=$3
    local pct=$(( current * 100 / total ))
    local filled=$(( current * 30 / total ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=filled; i<30; i++)); do bar+="░"; done
    printf "\r  [%s] %3d%% (%d/%d) %s" "$bar" "$pct" "$current" "$total" "$label"
}

analyze_netlink_json() {
    local folder=$1
    local run=$2
    local scenario=$3
    local expected_add=$4
    local expected_del=$5
    local timestamps_file=$6

    local netlink_file
    netlink_file=$(find "$folder" -maxdepth 3 -name "netlink_events.jsonl" 2>/dev/null | head -1)

    if [ -z "$netlink_file" ]; then
        echo "$run,$scenario,0,0,0,0,0,0,0" >> "$RAW_CSV"
        return
    fi

    python3 - "$netlink_file" "$run" "$scenario" "$expected_add" "$expected_del" "${timestamps_file:-}" "$RAW_CSV" << 'PYEOF'
import json, sys, os, statistics

netlink_file, run, scenario, exp_add, exp_del, ts_file, csv_path = sys.argv[1:]
expected_total = int(exp_add) + int(exp_del)

new_addr_count = 0
del_addr_count = 0
timestamps_json = []

with open(netlink_file) as f:
    for line in f:
        if not line.strip(): continue
        try:
            ev = json.loads(line)
            msg = ev.get("details", {}).get("msg_type", "")
            ip  = ev.get("details", {}).get("ip", "")
            if ip != "192.168.99.99": continue
            if msg == "NEW_ADDR":
                new_addr_count += 1
                timestamps_json.append(ev.get("timestamp_usec", 0))
            elif msg == "DEL_ADDR":
                del_addr_count += 1
                timestamps_json.append(ev.get("timestamp_usec", 0))
        except: pass

captured = new_addr_count + del_addr_count
completeness = round(captured / expected_total * 100, 1) if expected_total > 0 else 0

lat_mean = lat_median = lat_stdev = lat_p95 = 0

if ts_file and os.path.exists(ts_file) and timestamps_json:
    shell_timestamps = []
    with open(ts_file) as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 2:
                try: shell_timestamps.append(int(parts[1]))
                except ValueError: pass

    n_pairs = min(len(shell_timestamps), len(timestamps_json))
    latencies_ms = []
    for i in range(n_pairs):
        delta_us = timestamps_json[i] - shell_timestamps[i]
        if 0 <= delta_us < 5000000:
            latencies_ms.append(delta_us / 1000)

    if latencies_ms:
        lat_mean   = round(statistics.mean(latencies_ms), 2)
        lat_median = round(statistics.median(latencies_ms), 2)
        lat_stdev  = round(statistics.stdev(latencies_ms), 2) if len(latencies_ms) > 1 else 0
        sorted_l   = sorted(latencies_ms)
        p95_idx    = int(len(sorted_l) * 0.95)
        lat_p95    = round(sorted_l[min(p95_idx, len(sorted_l)-1)], 2)

with open(csv_path, "a") as f:
    f.write(f"{run},{scenario},{expected_total},{captured},{completeness},{lat_mean},{lat_median},{lat_stdev},{lat_p95}\n")
PYEOF
}

# --- SCÉNARIOS PYTHON ---

PY_SCRIPT_A="/tmp/netlink_test_a.py"
cat << 'EOF' > $PY_SCRIPT_A
import socket, time, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(0.5)
events = int(os.environ.get("EVENTS", 20))
ip = os.environ.get("TEST_IP")
iface = os.environ.get("TEST_IF")
for i in range(events):
    os.system(f"ip addr add {ip}/32 dev {iface} 2>/dev/null")
    time.sleep(0.05)
    os.system(f"ip addr del {ip}/32 dev {iface} 2>/dev/null")
    time.sleep(0.05)
time.sleep(0.5)
EOF

PY_SCRIPT_B="/tmp/netlink_test_b.py"
cat << 'EOF' > $PY_SCRIPT_B
import socket, time, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(0.5)
events = int(os.environ.get("EVENTS", 30))
ip = os.environ.get("TEST_IP")
iface = os.environ.get("TEST_IF")
ts_file = os.environ.get("TS_FILE")
with open(ts_file, "w") as f:
    for i in range(events):
        ts_add = int(time.time() * 1000000)
        os.system(f"ip addr add {ip}/32 dev {iface} 2>/dev/null")
        f.write(f"add,{ts_add}\n")
        time.sleep(0.1)
        ts_del = int(time.time() * 1000000)
        os.system(f"ip addr del {ip}/32 dev {iface} 2>/dev/null")
        f.write(f"del,{ts_del}\n")
        time.sleep(0.1)
time.sleep(0.5)
EOF

PY_SCRIPT_C="/tmp/netlink_test_c.py"
cat << 'EOF' > $PY_SCRIPT_C
import socket, time, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
time.sleep(0.5)
events = int(os.environ.get("EVENTS", 50))
ip = os.environ.get("TEST_IP")
iface = os.environ.get("TEST_IF")
for i in range(events):
    os.system(f"ip addr add {ip}/32 dev {iface} 2>/dev/null")
    os.system(f"ip addr del {ip}/32 dev {iface} 2>/dev/null")
time.sleep(1)
EOF

export TEST_IP
export TEST_IF

echo "── Scénario A : Complétude ───────────────────────────────"
mkdir -p "$OUTPUT_BASE/scenario_A"
export EVENTS=$EVENTS_PER_RUN_A
for i in $(seq 1 $RUNS_A); do
    progress $i $RUNS_A "run $i/$RUNS_A"
    cleanup_ip
    sudo -E tcpsnitch -l 0 -u 100000 -d "$OUTPUT_BASE/scenario_A/run_${i}" -- python3 "$PY_SCRIPT_A" >/dev/null 2>&1 || true
    analyze_netlink_json "$OUTPUT_BASE/scenario_A/run_${i}" "$i" "A" "$EVENTS_PER_RUN_A" "$EVENTS_PER_RUN_A" ""
done
echo -e "\n  ✅ Scénario A terminé\n"

echo "── Scénario B : Latence ───────────────────────────────────"
mkdir -p "$OUTPUT_BASE/scenario_B"
export EVENTS=$EVENTS_PER_RUN_B
for i in $(seq 1 $RUNS_B); do
    progress $i $RUNS_B "run $i/$RUNS_B"
    cleanup_ip
    export TS_FILE="$OUTPUT_BASE/scenario_B/timestamps_${i}.csv"
    sudo -E tcpsnitch -l 0 -u 100000 -d "$OUTPUT_BASE/scenario_B/run_${i}" -- python3 "$PY_SCRIPT_B" >/dev/null 2>&1 || true
    analyze_netlink_json "$OUTPUT_BASE/scenario_B/run_${i}" "$i" "B" "$EVENTS_PER_RUN_B" "$EVENTS_PER_RUN_B" "$TS_FILE"
done
echo -e "\n  ✅ Scénario B terminé\n"

echo "── Scénario C : Rafale ────────────────────────────────────"
mkdir -p "$OUTPUT_BASE/scenario_C"
export EVENTS=$EVENTS_PER_RUN_C
for i in $(seq 1 $RUNS_C); do
    progress $i $RUNS_C "run $i/$RUNS_C"
    cleanup_ip
    sudo -E tcpsnitch -l 0 -u 100000 -d "$OUTPUT_BASE/scenario_C/run_${i}" -- python3 "$PY_SCRIPT_C" >/dev/null 2>&1 || true
    analyze_netlink_json "$OUTPUT_BASE/scenario_C/run_${i}" "$i" "C" "$EVENTS_PER_RUN_C" "$EVENTS_PER_RUN_C" ""
done
echo -e "\n  ✅ Scénario C terminé\n"