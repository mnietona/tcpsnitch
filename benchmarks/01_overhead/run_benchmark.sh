#!/bin/bash

set -euo pipefail

# CONFIGURATION
RUNS=30 
URL="http://127.0.0.1:8080/100MB.bin"
INTERFACE="lo" # localhost

OUTPUT_BASE="output"
TIMINGS_CSV="$OUTPUT_BASE/timings.csv"
OUTPUT_STD="$OUTPUT_BASE/standard"
OUTPUT_EBPF="$OUTPUT_BASE/ebpf"
OUTPUT_LOSS="$OUTPUT_BASE/ebpf_loss"
DL_FILE="$OUTPUT_BASE/downloaded.bin" # Fichier de destination local

rm -rf "$OUTPUT_BASE"
mkdir -p "$OUTPUT_STD" "$OUTPUT_EBPF" "$OUTPUT_LOSS"

echo "run,condition,elapsed_ms,cpu_pct,mem_kb,exit_code" > "$TIMINGS_CSV"

echo "── Préparation du serveur local ──"
# 1. Création d'un fichier de 100Mo avec des données aléatoires
if [ ! -f 100MB.bin ]; then
    echo "Génération de 100MB.bin"
    dd if=/dev/urandom of=100MB.bin bs=1M count=100 2>/dev/null
fi

# 2. Lancement du serveur Python en arrière-plan
python3 -m http.server 8080 >/dev/null 2>&1 &
SERVER_PID=$!
echo "Serveur local démarré sur http://127.0.0.1:8080 (PID: $SERVER_PID)"
sleep 2

# 3.Nettoyage
cleanup() {
    echo -e "\n[!] Nettoyage..."
    kill $SERVER_PID 2>/dev/null || true
    sudo tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
    sudo rm -f "$DL_FILE"
}
trap cleanup EXIT

# Commande de téléchargement
CURL_CMD="curl --fail -s -o $DL_FILE $URL"

measure() {
    local condition=$1
    local run_id=$2
    local cmd=$3
    
    local log_file=$(mktemp)
    sudo rm -f "$DL_FILE"
    
    # Exécution silencieuse
    /usr/bin/time -f "%e %P %M" -o "$log_file" bash -c "$cmd" >/dev/null 2>&1 || true
    local exit_code=$?
    
    # Vérification propre basée sur la vraie taille du fichier sur le disque
    local dl_size=0
    if [ -f "$DL_FILE" ]; then
        dl_size=$(stat -c %s "$DL_FILE")
    fi
    
    if [ "$dl_size" -lt 100000000 ]; then
        echo -e "\n Avertissement: Taille incorrecte ($dl_size octets). tcpsnitch a bloqué la connexion."
        exit_code=99
    fi
    
    if [ -s "$log_file" ]; then
        read elapsed_s cpu_pct mem_kb < "$log_file"
        local elapsed_ms=$(python3 -c "print(int(float('$elapsed_s') * 1000))")
        cpu_pct=${cpu_pct%\%}
        echo "$run_id,$condition,$elapsed_ms,$cpu_pct,$mem_kb,$exit_code" >> "$TIMINGS_CSV"
    else
        echo "$run_id,$condition,0,0,0,1" >> "$TIMINGS_CSV"
    fi
    rm -f "$log_file"
}

progress() {
    local current=$1 total=$2 label=$3
    printf "\r  [RUN %2d/%2d] %s" "$current" "$total" "$label"
}

echo -e "\n=== DÉMARRAGE DU BENCHMARK ($RUNS itérations) ==="

echo -e "\n1/4 : Baseline (Sans outil)..."
for i in $(seq 1 $RUNS); do
    progress $i $RUNS "Baseline"
    start=$(date +%s%N)
    
    sudo rm -f "$DL_FILE"
    bash -c "$CURL_CMD" >/dev/null 2>&1 || true
    exit_code=$?
    
    dl_size=0
    if [ -f "$DL_FILE" ]; then
        dl_size=$(stat -c %s "$DL_FILE")
    fi
    if [ "$dl_size" -lt 100000000 ]; then exit_code=99; fi
    
    elapsed=$(( ($(date +%s%N) - start) / 1000000 ))
    echo "$i,baseline,$elapsed,0,0,$exit_code" >> "$TIMINGS_CSV"
done

echo -e "\n\n2/4 : TCPSnitch Standard..."
for i in $(seq 1 $RUNS); do
    progress $i $RUNS "Standard"
    measure "standard" "$i" "sudo tcpsnitch -l 0 -u 500000 -d $OUTPUT_STD -- bash -c \"$CURL_CMD\""
done

echo -e "\n\n3/4 : TCPSnitch + eBPF..."
for i in $(seq 1 $RUNS); do
    progress $i $RUNS "eBPF"
    measure "ebpf" "$i" "sudo tcpsnitch -e -l 0 -u 500000 -d $OUTPUT_EBPF -- bash -c \"$CURL_CMD\""
done

echo -e "\n\n4/4 : TCPSnitch + eBPF + Congestion (Loss 10% sur localhost)..."
# On applique la perte réseau virtuelle directement sur la boucle locale
sudo tc qdisc add dev "$INTERFACE" root netem loss 10% delay 20ms
for i in $(seq 1 $RUNS); do
    progress $i $RUNS "eBPF + Loss"
    measure "ebpf_loss" "$i" "sudo tcpsnitch -e -l 0 -u 500000 -d $OUTPUT_LOSS -- bash -c \"$CURL_CMD\""
done
# Le trap s'occupe de retirer la règle tc

echo -e "\n\n Benchmark terminé"