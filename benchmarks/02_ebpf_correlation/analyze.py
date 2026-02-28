import csv, os, sys, statistics

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR  = os.path.join(SCRIPT_DIR, "output")
RAW_CSV     = os.path.join(OUTPUT_DIR, "correlation_raw.csv")
REPORT_TXT  = os.path.join(OUTPUT_DIR, "report.txt")

SCENARIO_META = {
    "A": "A: Upload Nominal (5%)",
    "B": "B: Upload Stressé (15%)",
    "C": "C: 3 Uploads Parallèles (10%)",
    "D": "D: 10 Downloads Courts (5%)",
}

def main():
    if not os.path.exists(RAW_CSV): sys.exit(1)
    
    data = {s: {"runs": 0, "total": 0, "corr": 0, "noise": 0} for s in SCENARIO_META}
    
    with open(RAW_CSV) as f:
        for r in csv.DictReader(f):
            s = r["scenario"]
            if s in data:
                data[s]["runs"] += 1
                data[s]["total"] += int(r["total_retrans"])
                data[s]["corr"] += int(r["correlated"])
                data[s]["noise"] += int(r["noise"])

    lines = ["=== BENCHMARK 2 : PRÉCISION DE LA CORRÉLATION EBPF ==="]
    lines.append("Méthode : Analyse interne (Marquage 9999) sur des flux sortants (Uploads)\n")
    
    for s, st in data.items():
        if st["runs"] == 0: continue
        rate = (st["corr"] / st["total"] * 100) if st["total"] > 0 else 100.0
        
        lines.append(f"[{s}] {SCENARIO_META[s]}")
        lines.append(f" -> Événements eBPF totaux : {st['total']}")
        lines.append(f" -> Retransmissions bien corrélées : {st['corr']}")
        lines.append(f" -> Bruit système (9999) : {st['noise']}")
        lines.append(f" -> Taux de précision applicatif : {rate:.1f}%\n")

    with open(REPORT_TXT, "w") as f:
        f.write("\n".join(lines))
        
    print(f"\n✅ Analyse terminée. Lisez {REPORT_TXT}")

if __name__ == "__main__":
    main()