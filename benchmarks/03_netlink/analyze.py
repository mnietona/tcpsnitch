import csv, os, sys, statistics

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR  = os.path.join(SCRIPT_DIR, "output")
RAW_CSV     = os.path.join(OUTPUT_DIR, "netlink_raw.csv")
REPORT_TXT  = os.path.join(OUTPUT_DIR, "report.txt")

SCENARIO_META = {
    "A": {"label": "A (Nominal)", "desc": "20 cycles add/del (50ms délai)"},
    "B": {"label": "B (Latence)", "desc": "30 events avec timestamps précis"},
    "C": {"label": "C (Rafale) ", "desc": "50 events en rafale (sans délai)"},
}

def load_raw():
    data = {s: [] for s in SCENARIO_META}
    if not os.path.exists(RAW_CSV): sys.exit(1)
    with open(RAW_CSV) as f:
        for r in csv.DictReader(f):
            if r["scenario"] in data:
                data[r["scenario"]].append({
                    "run": int(r["run"]),
                    "gen": int(r["events_generated"]),
                    "cap": int(r["events_captured"]),
                    "comp": float(r["completeness_pct"]),
                    "lat": float(r["latency_median_ms"])
                })
    return data

def main():
    data = load_raw()
    
    lines = ["=== BENCHMARK 3 : PRÉCISION ET LATENCE NETLINK ===\n"]
    
    all_comp_ok = True
    all_lat_ok = True
    
    for s, runs in data.items():
        if not runs: continue
        total_gen = sum(r["gen"] for r in runs)
        total_cap = sum(r["cap"] for r in runs)
        global_comp = (total_cap / total_gen * 100) if total_gen > 0 else 0
        
        if global_comp < 100: all_comp_ok = False
        
        lines.append(f"[{SCENARIO_META[s]['label']}] {SCENARIO_META[s]['desc']}")
        lines.append(f" -> Événements générés (Shell) : {total_gen}")
        lines.append(f" -> Événements capturés (JSON) : {total_cap}")
        lines.append(f" -> Complétude : {global_comp:.1f}%")
        
        if s == "B":
            lats = [r["lat"] for r in runs if r["lat"] > 0]
            if lats:
                mean_lat = statistics.mean(lats)
                if mean_lat > 50: all_lat_ok = False
                lines.append(f" -> Latence médiane moyenne  : {mean_lat:.2f} ms")
            else:
                lines.append(" -> Latence : ERREUR DE MESURE")
        lines.append("")

    with open(REPORT_TXT, "w") as f:
        f.write("\n".join(lines))
        
    print(f"\nAnalyse terminée")

if __name__ == "__main__":
    main()
