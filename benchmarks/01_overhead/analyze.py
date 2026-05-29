import csv, os, sys, statistics

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
TIMINGS_CSV = os.path.join(OUTPUT_DIR, "timings.csv")
REPORT_TXT  = os.path.join(OUTPUT_DIR, "report_final.txt")

def load_data(filepath):
    data = {"baseline": [], "standard": [], "ebpf": [], "ebpf_loss": []}
    if not os.path.exists(filepath):
        print(f"Erreur: {filepath} introuvable.")
        sys.exit(1)
    with open(filepath) as f:
        for row in csv.DictReader(f):
            if int(row["exit_code"]) == 0:
                data[row["condition"]].append({
                    "ms": int(row["elapsed_ms"]),
                    "cpu": float(row["cpu_pct"]),
                    "mem": int(row["mem_kb"])
                })
    return data

def main():
    raw_data = load_data(TIMINGS_CSV)
    
    stats = {}
    for cond, values in raw_data.items():
        if not values: continue
        stats[cond] = {
            "duration": statistics.mean([v["ms"] for v in values]) / 1000.0,
            "cpu": statistics.mean([v["cpu"] for v in values]),
            "mem": statistics.mean([v["mem"] for v in values]) / 1024.0
        }

    # Génération d'un Tableau + Rapport
    
    table = [
        "| Condition de test               | Durée (s) | Usage CPU (%) | Usage RAM (MB) |",
        "|--------------------------------|-----------|---------------|----------------|",
        f"| 1. Baseline (Sans outil)       | {stats['baseline']['duration']:>9.2f} |      N/A      |      N/A       |",
        f"| 2. TCPSnitch (Standard)        | {stats['standard']['duration']:>9.2f} | {stats['standard']['cpu']:>12.2f}% | {stats['standard']['mem']:>13.2f}  |",
        f"| 3. TCPSnitch (+ eBPF)          | {stats['ebpf']['duration']:>9.2f} | {stats['ebpf']['cpu']:>12.2f}% | {stats['ebpf']['mem']:>13.2f}  |",
        f"| 4. TCPSnitch (+ eBPF + Loss 5%)| {stats['ebpf_loss']['duration']:>9.2f} | {stats['ebpf_loss']['cpu']:>12.2f}% | {stats['ebpf_loss']['mem']:>13.2f}  |",
    ]

    report = [
        "=== BENCHMARK RESULTS (N=30) ===",
        "\n".join(table),
        "\nMETRICS DERIVATIONS:",
        f"  - Delta CPU (eBPF vs Standard) : {stats['ebpf']['cpu'] - stats['standard']['cpu']:+.3f}%",
        f"  - Delta CPU (Loss 5% vs eBPF)  : {stats['ebpf_loss']['cpu'] - stats['ebpf']['cpu']:+.3f}%"
    ]

    with open(REPORT_TXT, "w") as f:
        f.write("\n".join(report) + "\n")
    
    print("\n".join(report))

if __name__ == "__main__":
    main()