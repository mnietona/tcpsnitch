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
echo " Benchmark 5 — Robustesse sous charge & Faille Architecturale"
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
echo -e "\n  Scénario A terminé\n"

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
echo -e "\n  Scénario B terminé\n"

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

echo -e "\n  Scénario C terminé\n"

echo "── Scénario E : close_range() — Fermeture PARTIELLE (100 sockets) ──"
DIR_E="$OUTPUT_BASE/scenario_E_partiel"
mkdir -p "$DIR_E"

cat > /tmp/stress_e.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <syscall.h>

#ifndef SYS_close_range
#define SYS_close_range 436 
#endif

int main() {
    int fds[100];
    
    // 1. Création de 100 sockets
    for(int i = 0; i < 100; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM, 0);
    }

    // 2. Fermeture MASSIVE MAIS PARTIELLE via close_range
    // On ferme uniquement la première moitié (les 50 premiers sockets)
    if (fds[0] != -1 && fds[49] != -1) {
         syscall(SYS_close_range, fds[0], fds[49], 0);
    }

    // On laisse le temps à l'outil de générer les traces
    sleep(1); 
    
    // Fermeture propre du reste
    for(int i = 50; i < 100; i++) {
        if(fds[i] != -1) close(fds[i]);
    }

    return 0;
}
EOF

gcc -O2 /tmp/stress_e.c -o /tmp/stress_e

RUNS_E=30
for i in $(seq 1 $RUNS_E); do
    progress $i $RUNS_E "Run $i/$RUNS_E (Partiel)"
    { sudo tcpsnitch -e -l 0 -f 5 -u 500000 -d "$DIR_E/run_${i}" -- /tmp/stress_e 2>> "$LOG_E" || true; }
    sleep 2 
done
echo -e "\n  Scénario E terminé\n"

echo "── Scénario D : close_range() — Fermeture TOTALE (300 sockets) ─────"
DIR_D="$OUTPUT_BASE/scenario_D_total"
mkdir -p "$DIR_D"

cat > /tmp/stress_d.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <syscall.h>

#ifndef SYS_close_range
#define SYS_close_range 436 
#endif

int main() {
    int fds[300];
    int min_fd = 999999;
    int max_fd = -1;

    for(int i = 0; i < 300; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM, 0);
        if(fds[i] != -1) {
            if(fds[i] < min_fd) min_fd = fds[i];
            if(fds[i] > max_fd) max_fd = fds[i];
        }
    }

    // Tir de barrage massif
    if(max_fd != -1) {
        syscall(SYS_close_range, min_fd, max_fd, 0);
    }

    return 0; 
}
EOF

gcc -O2 /tmp/stress_d.c -o /tmp/stress_d

RUNS_D=30
for i in $(seq 1 $RUNS_D); do
    progress $i $RUNS_D "Run $i/$RUNS_D (Total)"
    { sudo tcpsnitch -e -l 0 -u 500000 -d "$DIR_D/run_${i}" -- /tmp/stress_d 2>> "$LOG_D" || true; }
    sleep 2 
done
echo -e "\n  Scénario D terminé\n"