#!/bin/bash
set -euo pipefail

OUTPUT_BASE="output"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

mkdir -p "$OUTPUT_BASE"

progress() {
    local current=$1 total=$2 label=$3
    local pct=$(( current * 100 / total ))
    local filled=$(( current * 30 / total ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=filled; i<30; i++)); do bar+="░"; done
    printf "\r  [%s] %3d%% (%d/%d) %-40s" "$bar" "$pct" "$current" "$total" "$label"
}

echo "===================================================================="
echo " Benchmark 5 — Validation algorithmique vs Faille architecturale"
echo "===================================================================="
echo ""

# ========================================================================
# ── Scénario E : close_range (Fermeture Partielle - Validation du code)
# ========================================================================
echo "── 1. Scénario E : close_range() — Fermeture PARTIELLE (100 sockets) ──"
DIR_E="$OUTPUT_BASE/scenario_E_partiel"
mkdir -p "$DIR_E"
LOG_E="$DIR_E/tcpsnitch_errors.log"
> "$LOG_E"

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
echo -e "\n  ✅ Scénario E (Partiel) terminé.\n"


# ========================================================================
# ── Scénario D : close_range (Fermeture Totale - Suicide applicatif)
# ========================================================================
echo "── 2. Scénario D : close_range() — Fermeture TOTALE (300 sockets) ─────"
DIR_D="$OUTPUT_BASE/scenario_D_total"
mkdir -p "$DIR_D"
LOG_D="$DIR_D/tcpsnitch_errors.log"
> "$LOG_D"

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
echo -e "\n  ✅ Scénario D (Total) terminé.\n"


# ========================================================================
# ── Bilan Rapide des Crashs
# ========================================================================
echo "===================================================================="
echo "  📊 BILAN DES CRASHS eBPF (Bad file descriptor) :"
echo "===================================================================="
CRASH_E=$(grep -c "Bad file descriptor" "$LOG_E" || echo "0")
CRASH_D=$(grep -c "Bad file descriptor" "$LOG_D" || echo "0")

echo "  -> Scénario E (Partiel - Normal) : $CRASH_E crashs sur $RUNS_E exécutions."
echo "  -> Scénario D (Total - Suicide)  : $CRASH_D crashs sur $RUNS_D exécutions."
echo "===================================================================="