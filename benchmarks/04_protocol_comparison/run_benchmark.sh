#!/bin/bash
set -euo pipefail

RUNS=30
LOSS_RATES=(2 5 10 20)
PAYLOAD_FILE="/tmp/bench4_payload.bin"
URL_UPLOAD="https://httpbin.org/post"

OUTPUT_BASE="output"
RAW_CSV="$OUTPUT_BASE/protocol_raw.csv"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"g

rm -rf "$OUTPUT_BASE"
mkdir -p "$OUTPUT_BASE/runs"

echo "Création du payload 1MB..."
dd if=/dev/urandom of="$PAYLOAD_FILE" bs=1M count=1 2>/dev/null

echo "run,protocol,loss_pct,retrans_correlated,retrans_noise,retrans_total,sockets_count,transfer_ok" > "$RAW_CSV"

echo "============================================================"
echo " Benchmark 4 — Comparaison HTTP/1.1 vs HTTP/2 vs HTTP/3"
echo " Taux de perte : ${LOSS_RATES[*]}%"
echo " Runs par cellule : $RUNS"
echo " Total runs : $(( ${#LOSS_RATES[@]} * 3 * RUNS ))"
echo "============================================================"
echo ""

progress() {
    local current=$1 total=$2 label=$3
    local pct=$(( current * 100 / total ))
    local filled=$(( current * 30 / total ))
    local bar=""
    for ((idx=0; idx<filled; idx++)); do bar+="█"; done
    for ((idx=filled; idx<30; idx++)); do bar+="░"; done
    printf "\r  [%s] %3d%% (%d/%d) %-40s" "$bar" "$pct" "$current" "$total" "$label"
}

get_iface() {
    ip route get 8.8.8.8 | awk '{print $5; exit}'
}

apply_netem() {
    local loss=$1
    local iface=$(get_iface)
    sudo tc qdisc del dev "$iface" root 2>/dev/null || true
    sudo tc qdisc add dev "$iface" root netem loss "${loss}%" delay 20ms
}

remove_netem() {
    local iface=$(get_iface)
    sudo tc qdisc del dev "$iface" root 2>/dev/null || true
}

analyze_session() {
    local session_dir=$1
    local run_num=$2
    local protocol=$3
    local loss=$4

    local actual_dir=$(find "$session_dir" -maxdepth 1 -type d -name "curl_*" 2>/dev/null | head -1)

    if [ -z "$actual_dir" ]; then
        echo "$run_num,$protocol,$loss,0,0,0,0,0" >> "$RAW_CSV"
        return
    fi

    python3 - "$actual_dir" "$run_num" "$protocol" "$loss" "$RAW_CSV" << 'PYEOF'
import json, sys, os, glob

folder, run, protocol, loss, csv_path = sys.argv[1:]
ebpf_file = os.path.join(folder, "ebpf_events.jsonl")
correlated = noise = total = 0

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

json_files = [f for f in os.listdir(folder) if f.endswith(".json") and f[0].isdigit()]
sockets    = len(json_files)
ok         = 1 if sockets > 0 else 0

with open(csv_path, "a") as f:
    f.write(f"{run},{protocol},{loss},{correlated},{noise},{total},{sockets},{ok}\n")
PYEOF
}

TOTAL_RUNS=$(( ${#LOSS_RATES[@]} * 3 * RUNS ))
current_run=0

for loss in "${LOSS_RATES[@]}"; do
    echo "━━━━ Taux de perte : ${loss}% ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    for proto_flag in "--http1.1" "--http2" "--http3"; do
        case "$proto_flag" in
            "--http1.1") proto_label="http1" ;;
            "--http2")   proto_label="http2" ;;
            "--http3")   proto_label="http3" ;;
        esac

        echo "  ── ${proto_label} (perte=${loss}%) ──────────────────────"
        
        for run_idx in $(seq 1 $RUNS); do
            current_run=$(( current_run + 1 ))
            progress $run_idx $RUNS "run $run_idx/$RUNS (global: $current_run/$TOTAL_RUNS)"

            RUN_DIR="$OUTPUT_BASE/runs/${proto_label}_loss${loss}/run_${run_idx}"
            mkdir -p "$RUN_DIR"

            apply_netem "$loss"

            {
                sudo tcpsnitch -e -l 0 -u 500000 \
                    -d "$RUN_DIR" -- \
                    curl -4 "$proto_flag" -m 20 -s -S -X POST \
                    --data-binary "@${PAYLOAD_FILE}" \
                    "$URL_UPLOAD"
            } > /dev/null 2>&1 || true

            remove_netem
            sleep 0.5 
            
            analyze_session "$RUN_DIR" "$run_idx" "$proto_label" "$loss"
        done
        
        echo ""
    done
    echo ""
done

echo "============================================================"
echo " ✅ Collecte terminée"
echo "============================================================"