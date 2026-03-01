#!/bin/bash
set -euo pipefail

RUNS=30
OUTPUT_BASE="output"
RAW_CSV="$OUTPUT_BASE/correlation_raw.csv"
PYTHON_TEST="/tmp/bench_stress.py"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

rm -rf "$OUTPUT_BASE"
mkdir -p "$OUTPUT_BASE"
echo "run,scenario,loss_pct,total_retrans,correlated,noise,correlation_rate" > "$RAW_CSV"

# --- LE SCRIPT PYTHON DE TEST MULTITHREAD ---
cat << 'EOF' > $PYTHON_TEST
import threading
import urllib.request
import os
import sys

# Génère 500 Ko de données aléatoires en RAM
data = os.urandom(500 * 1024)
req = urllib.request.Request("http://httpbin.org/post", data=data)

def upload():
    try:
        urllib.request.urlopen(req)
    except Exception as e:
        pass

# On lit le nombre de threads depuis les arguments (1, 3 ou 10)
num_threads = int(sys.argv[1])
threads = [threading.Thread(target=upload) for _ in range(num_threads)]

for t in threads: t.start()
for t in threads: t.join()
EOF

progress() {
    local current=$1 total=$2 label=$3
    local pct=$(( current * 100 / total ))
    local filled=$(( current * 30 / total ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=filled; i<30; i++)); do bar+="░"; done
    printf "\r  [%s] %3d%% (%d/%d) %s" "$bar" "$pct" "$current" "$total" "$label"
}

apply_netem() {
    local loss=$1
    local iface=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
    sudo tc qdisc del dev "$iface" root 2>/dev/null || true
    sudo tc qdisc add dev "$iface" root netem loss "${loss}%" delay 20ms
}

remove_netem() {
    local iface=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
    sudo tc qdisc del dev "$iface" root 2>/dev/null || true
}

analyze_session() {
    local session_dir=$1
    local scenario=$2
    local run=$3
    local loss=$4

    local actual_dir=$(find "$session_dir" -maxdepth 2 -name "ebpf_events.jsonl" -exec dirname {} \; 2>/dev/null | head -1)

    if [ -z "$actual_dir" ]; then
        echo "$run,$scenario,$loss,0,0,0,0" >> "$RAW_CSV"
        return
    fi

    python3 - "$actual_dir" "$run" "$scenario" "$loss" "$RAW_CSV" << 'PYEOF'
import json, sys, os
folder, run, scenario, loss, csv_path = sys.argv[1:]
ebpf_file = os.path.join(folder, "ebpf_events.jsonl")

total = correlated = noise = 0

if os.path.exists(ebpf_file):
    with open(ebpf_file) as f:
        for line in f:
            if not line.strip(): continue
            try:
                e = json.loads(line)
                if e.get("type") == "tcp_retransmit":
                    total += 1
                    if e.get("session_id") == 9999:
                        noise += 1
                    else:
                        correlated += 1
            except: pass

rate = round((correlated / total * 100), 1) if total > 0 else 100.0
with open(csv_path, "a") as f:
    f.write(f"{run},{scenario},{loss},{total},{correlated},{noise},{rate}\n")
PYEOF
}

run_scenario() {
    local label=$1
    local scen_id=$2
    local loss=$3
    local num_threads=$4
    
    echo "── Scénario $scen_id : $label (Perte=$loss%) ────────────────"
    mkdir -p "$OUTPUT_BASE/scenario_$scen_id"

    for i in $(seq 1 $RUNS); do
        progress $i $RUNS "run $i/$RUNS"
        apply_netem "$loss"
        
        sudo tcpsnitch -e -l 0 -u 500000 -d "$OUTPUT_BASE/scenario_$scen_id/run_${i}" -- python3 "$PYTHON_TEST" "$num_threads" >/dev/null 2>&1 || true
        
        remove_netem
        analyze_session "$OUTPUT_BASE/scenario_$scen_id/run_${i}" "$scen_id" "$i" "$loss"
    done
    echo -e "\n  ✅ Scénario $scen_id terminé\n"
}

run_scenario "Upload nominal (1 socket)" "A" "5" "1"
run_scenario "Upload stressé (1 socket)" "B" "15" "1"
run_scenario "Upload simultané (3 sockets)" "C" "10" "3"
run_scenario "Upload massif (10 sockets)" "D" "5" "10"