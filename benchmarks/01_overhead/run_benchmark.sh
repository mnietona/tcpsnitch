#!/bin/bash
set -euo pipefail

RUNS=30
URL="http://speedtest.tele2.net/10MB.zip"
TCPSNITCH="sudo tcpsnitch"
OUTPUT_BASE="output"
OUTPUT_SANS_EBPF="$OUTPUT_BASE/sans_ebpf"
OUTPUT_AVEC_EBPF="$OUTPUT_BASE/avec_ebpf"
TIMINGS_CSV="$OUTPUT_BASE/timings.csv"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

rm -rf "$OUTPUT_BASE"
mkdir -p "$OUTPUT_SANS_EBPF"
mkdir -p "$OUTPUT_AVEC_EBPF"

echo "run,condition,elapsed_ms,exit_code" > "$TIMINGS_CSV"

measure_ms() {
    local start end elapsed
    start=$(date +%s%N)
    "$@" >/dev/null 2>&1
    local exit_code=$?
    end=$(date +%s%N)
    elapsed=$(( (end - start) / 1000000 ))
    echo "$elapsed $exit_code"
}

progress() {
    local current=$1 total=$2 label=$3
    local pct=$(( current * 100 / total ))
    local filled=$(( current * 30 / total ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=filled; i<30; i++)); do bar+="░"; done
    printf "\r  [%s] %3d%% (%d/%d) %s" "$bar" "$pct" "$current" "$total" "$label"
}

echo "── Condition 1/4 : Baseline (curl seul) ──────────────────"
for i in $(seq 1 $RUNS); do
    progress $i $RUNS "run $i/$RUNS"
    read elapsed exit_code <<< $(measure_ms curl --http1.1 -s -o /dev/null "$URL")
    echo "$i,baseline,$elapsed,$exit_code" >> "$TIMINGS_CSV"
    sleep 0.5
done
echo -e "\n  ✅ Baseline terminée\n"

echo "── Condition 2/4 : strace (état de l'art) ────────────────"
for i in $(seq 1 $RUNS); do
    progress $i $RUNS "run $i/$RUNS"
    # strace intercepte les mêmes appels réseau que tcpsnitch
    read elapsed exit_code <<< $(measure_ms strace -f -e trace=network,read,write,close -o /dev/null curl --http1.1 -s -o /dev/null "$URL")
    echo "$i,strace,$elapsed,$exit_code" >> "$TIMINGS_CSV"
    sleep 0.5
done
echo -e "\n  ✅ strace terminé\n"

echo "── Condition 3/4 : tcpsnitch sans eBPF ───────────────────"
for i in $(seq 1 $RUNS); do
    progress $i $RUNS "run $i/$RUNS"
    read elapsed exit_code <<< $(measure_ms sudo tcpsnitch -l 0 -u 500000 -d "$OUTPUT_SANS_EBPF/run_${i}" -- curl --http1.1 -s -o /dev/null "$URL")
    echo "$i,sans_ebpf,$elapsed,$exit_code" >> "$TIMINGS_CSV"
    sleep 0.5
done
echo -e "\n  ✅ Sans eBPF terminé\n"

echo "── Condition 4/4 : tcpsnitch avec eBPF ───────────────────"
for i in $(seq 1 $RUNS); do
    progress $i $RUNS "run $i/$RUNS"
    read elapsed exit_code <<< $(measure_ms sudo tcpsnitch -e -l 0 -u 500000 -d "$OUTPUT_AVEC_EBPF/run_${i}" -- curl --http1.1 -s -o /dev/null "$URL")
    echo "$i,avec_ebpf,$elapsed,$exit_code" >> "$TIMINGS_CSV"
    sleep 0.5
done
echo -e "\n  ✅ Avec eBPF terminé\n"