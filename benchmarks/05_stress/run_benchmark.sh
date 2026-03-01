#!/bin/bash
set -euo pipefail

OUTPUT_BASE="output"
RAW_CSV="$OUTPUT_BASE/stress_raw.csv"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

rm -rf "$OUTPUT_BASE"
mkdir -p "$OUTPUT_BASE"

echo "run,scenario,metric,value,h0_threshold,h0_ok" > "$RAW_CSV"

echo "============================================================"
echo " Benchmark 5 — Robustesse sous charge"
echo "============================================================"
echo ""

progress() {
    local current=$1 total=$2 label=$3
    local pct=$(( current * 100 / total ))
    local filled=$(( current * 30 / total ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=filled; i<30; i++)); do bar+="░"; done
    printf "\r  [%s] %3d%% (%d/%d) %-40s" "$bar" "$pct" "$current" "$total" "$label"
}

# ── Scénario A : Intégrité JSON (100 connexions simultanées) ──
echo "── Scénario A : Intégrité JSON (100 connexions simultanées) ──"
mkdir -p "$OUTPUT_BASE/scenario_A"

cat > /tmp/stress_a.py << 'PYEOF'
import threading, urllib.request, sys
URL = "https://httpbin.org/get"
N = 100
results = {"ok": 0, "err": 0}
lock = threading.Lock()

def fetch():
    try:
        with urllib.request.urlopen(URL, timeout=10) as r: r.read()
        with lock: results["ok"] += 1
    except:
        with lock: results["err"] += 1

threads = [threading.Thread(target=fetch) for _ in range(N)]
for t in threads: t.start()
for t in threads: t.join()
PYEOF

RUNS_A=30
for i in $(seq 1 $RUNS_A); do
    progress $i $RUNS_A "run $i/$RUNS_A"
    { sudo tcpsnitch -e -l 0 -u 500000 -d "$OUTPUT_BASE/scenario_A/run_${i}" -- python3 /tmp/stress_a.py >/dev/null 2>&1 || true; }
    
    python3 - "$OUTPUT_BASE/scenario_A/run_${i}" "$i" "$RAW_CSV" << 'PYEOF'
import json, sys, os, glob
session_dir, run, csv_path = sys.argv[1:]
actual = next((root for root, dirs, files in os.walk(session_dir) if any(f.endswith(".json") and f[0].isdigit() for f in files)), None)

if not actual:
    with open(csv_path, "a") as f:
        f.write(f"{run},A,json_validity_pct,0,100,0\n{run},A,socket_ratio,0,1.0,0\n")
    sys.exit(0)

json_files = glob.glob(os.path.join(actual, "[0-9]*.json"))
valid, socket_events = 0, 0
for jf in json_files:
    try:
        with open(jf) as f:
            lines = f.readlines()
            if lines and json.loads(lines[0]).get("type") == "socket": socket_events += 1
            for line in lines:
                if line.strip(): json.loads(line)
        valid += 1
    except: pass

validity_pct = round(valid / len(json_files) * 100, 1) if json_files else 0
ratio = round(socket_events / len(json_files), 3) if json_files else 0

with open(csv_path, "a") as f:
    f.write(f"{run},A,json_validity_pct,{validity_pct},100,{'1' if validity_pct==100 else '0'}\n")
    f.write(f"{run},A,socket_ratio,{ratio},0.99,{'1' if ratio>=0.99 else '0'}\n")
PYEOF
done
echo -e "\n  ✅ Scénario A terminé\n"

# ── Scénario B : Ratio 1:1 (50 connexions séquentielles) ─────
echo "── Scénario B : Ratio 1:1 (50 connexions séquentielles) ─────"
mkdir -p "$OUTPUT_BASE/scenario_B"

cat > /tmp/stress_b.py << 'PYEOF'
import urllib.request
URL = "https://httpbin.org/get"
for i in range(50):
    try:
        with urllib.request.urlopen(URL, timeout=5) as r: r.read()
    except: pass
PYEOF

RUNS_B=30
for i in $(seq 1 $RUNS_B); do
    progress $i $RUNS_B "run $i/$RUNS_B"
    { sudo tcpsnitch -e -l 0 -u 500000 -d "$OUTPUT_BASE/scenario_B/run_${i}" -- python3 /tmp/stress_b.py >/dev/null 2>&1 || true; }
    
    python3 - "$OUTPUT_BASE/scenario_B/run_${i}" "$i" "$RAW_CSV" << 'PYEOF'
import json, sys, os, glob
session_dir, run, csv_path = sys.argv[1:]
actual = next((root for root, dirs, files in os.walk(session_dir) if any(f.endswith(".json") and f[0].isdigit() for f in files)), None)

if not actual:
    with open(csv_path, "a") as f: f.write(f"{run},B,socket_file_ratio,0,1.0,0\n")
    sys.exit(0)

json_files = glob.glob(os.path.join(actual, "[0-9]*.json"))
tcp_sockets = 0
for jf in json_files:
    try:
        with open(jf) as f:
            first = json.loads(f.readline())
            si = first.get("details", {}).get("sock_info", {})
            if first.get("type") == "socket" and si.get("domain") in ("AF_INET", "AF_INET6") and si.get("type") == "SOCK_STREAM":
                tcp_sockets += 1
    except: pass

ratio = round(tcp_sockets / len(json_files), 3) if json_files else 0
with open(csv_path, "a") as f:
    f.write(f"{run},B,tcp_files,{len(json_files)},50,{'1' if len(json_files) >= 50 else '0'}\n")
    f.write(f"{run},B,socket_file_ratio,{ratio},0.99,{'1' if ratio >= 0.99 else '0'}\n")
PYEOF
done
echo -e "\n  ✅ Scénario B terminé\n"

# ── Scénario C : Mémoire (10 minutes) ────────────────────
echo "── Scénario C : Stabilité mémoire (10 min de transferts) ────"
mkdir -p "$OUTPUT_BASE/scenario_C"
DURATION_SEC=600
MEM_LOG="$OUTPUT_BASE/scenario_C/memory_log.csv"
echo "timestamp_s,rss_kb,pid" > "$MEM_LOG"

cat > /tmp/stress_c.py << 'PYEOF'
import urllib.request, time, sys
DURATION = 600
start = time.time()
while time.time() - start < DURATION:
    try:
        with urllib.request.urlopen("https://httpbin.org/get", timeout=5) as r: r.read()
    except: pass
    time.sleep(0.5)
PYEOF

sudo tcpsnitch -e -l 0 -u 500000 -d "$OUTPUT_BASE/scenario_C/session" -- python3 /tmp/stress_c.py >/dev/null 2>&1 &
SUDO_PID=$!

sleep 3
START_TIME=$(date +%s)
RSS_INIT=0

while kill -0 $SUDO_PID 2>/dev/null; do
    NOW=$(date +%s)
    ELAPSED=$(( NOW - START_TIME ))
    
    TPID=$(pgrep -P $SUDO_PID 2>/dev/null | head -n 1)
    if [ -z "$TPID" ]; then
        TPID=$(pgrep tcpsnitch | head -n 1 || echo "")
    fi

    if [ -n "$TPID" ]; then
        RSS=$(awk '/VmRSS/{print $2}' /proc/$TPID/status 2>/dev/null || echo "0")
        
        if [ "$RSS_INIT" -eq 0 ] && [ "$RSS" -gt 0 ]; then RSS_INIT=$RSS; fi
        
        if [ "$RSS" -gt 0 ]; then
            echo "$ELAPSED,$RSS,$TPID" >> "$MEM_LOG"
            printf "\r  [%ds/%ds] RSS=%s KB (init=%s KB) PID=%s" "$ELAPSED" "$DURATION_SEC" "$RSS" "$RSS_INIT" "$TPID"
        fi
    fi
    sleep 15
done
echo -e "\n  ✅ Données brutes collectées, intégration au rapport...\n"

# ---> LE BLOC MANQUANT QUI INJECTE DANS LE CSV <---
python3 - "$MEM_LOG" "$RAW_CSV" << 'PYEOF'
import csv, sys, os

mem_log, csv_path = sys.argv[1:]
rss_values = []

if os.path.exists(mem_log):
    with open(mem_log) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                rss_values.append(int(row["rss_kb"]))
            except: pass

if not rss_values:
    with open(csv_path, "a") as f:
        f.write("1,C,rss_ratio,0,2.0,0\n")
    sys.exit(0)

rss_init = rss_values[0]
rss_max  = max(rss_values)
rss_final = rss_values[-1]
ratio    = round(rss_max / rss_init, 3) if rss_init > 0 else 0

ok = "1" if ratio <= 2.0 else "0"
with open(csv_path, "a") as f:
    f.write(f"1,C,rss_init_kb,{rss_init},0,1\n")
    f.write(f"1,C,rss_max_kb,{rss_max},0,1\n")
    f.write(f"1,C,rss_final_kb,{rss_final},0,1\n")
    f.write(f"1,C,rss_ratio,{ratio},2.0,{ok}\n")
    f.write(f"1,C,n_samples,{len(rss_values)},10,{'1' if len(rss_values)>=10 else '0'}\n")
PYEOF

echo -e "  ✅ Scénario C terminé\n"

# ── Scénario D : close_range ───────────────────────────────────
echo "── Scénario D : close_range() — 500 sockets en masse ────────"
mkdir -p "$OUTPUT_BASE/scenario_D"

cat > /tmp/stress_d.py << 'PYEOF'
import socket, ctypes, ctypes.util
sockets = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for _ in range(500)]
fds = [s.fileno() for s in sockets]
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
if fds: libc.close_range(ctypes.c_uint(min(fds)), ctypes.c_uint(max(fds)), ctypes.c_uint(0))
PYEOF

RUNS_D=30
for i in $(seq 1 $RUNS_D); do
    progress $i $RUNS_D "run $i/$RUNS_D"
    { sudo tcpsnitch -e -l 0 -u 500000 -d "$OUTPUT_BASE/scenario_D/run_${i}" -- python3 /tmp/stress_d.py >/dev/null 2>&1 || true; }
    
    python3 - "$OUTPUT_BASE/scenario_D/run_${i}" "$i" "$RAW_CSV" << 'PYEOF'
import json, sys, os, glob
session_dir, run, csv_path = sys.argv[1:]
actual = next((root for root, dirs, files in os.walk(session_dir) if any(f.endswith(".json") and f[0].isdigit() for f in files)), None)

if not actual:
    with open(csv_path, "a") as f: f.write(f"{run},D,close_coverage_pct,0,100,0\n")
    sys.exit(0)

json_files = glob.glob(os.path.join(actual, "[0-9]*.json"))
sockets_with_close, sockets_without, corrupted = 0, 0, 0

for jf in json_files:
    has_close, has_socket = False, False
    try:
        with open(jf) as f:
            for line in f:
                if not line.strip(): continue
                ev = json.loads(line)
                if ev.get("type") == "socket": has_socket = True
                if ev.get("type") in ("close", "close_range"): has_close = True
        if has_socket and has_close: sockets_with_close += 1
        elif has_socket: sockets_without += 1
    except: corrupted += 1

total = sockets_with_close + sockets_without
coverage = round(sockets_with_close / total * 100, 1) if total > 0 else 0

with open(csv_path, "a") as f:
    f.write(f"{run},D,n_files,{len(json_files)},450,{'1' if len(json_files)>=450 else '0'}\n")
    f.write(f"{run},D,close_coverage_pct,{coverage},95,{'1' if coverage>=95 else '0'}\n")
    f.write(f"{run},D,corrupted_json,{corrupted},0,{'1' if corrupted==0 else '0'}\n")
PYEOF
done
echo -e "\n  ✅ Scénario D terminé\n"