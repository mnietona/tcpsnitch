import csv, os, sys, statistics, math

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
TIMINGS_CSV = os.path.join(OUTPUT_DIR, "timings.csv")
RESULTS_CSV = os.path.join(OUTPUT_DIR, "overhead_results.csv")
GRAPH_PNG   = os.path.join(OUTPUT_DIR, "overhead_graph.png")
REPORT_TXT  = os.path.join(OUTPUT_DIR, "report.txt")

def load_timings(filepath):
    data = {"baseline": [], "strace": [], "sans_ebpf": [], "avec_ebpf": []}
    if not os.path.exists(filepath):
        sys.exit(1)
    with open(filepath) as f:
        for row in csv.DictReader(f):
            if int(row["exit_code"]) == 0:
                data[row["condition"]].append(int(row["elapsed_ms"]))
    return data

def compute_stats(values):
    n = len(values)
    if n == 0: return None
    s_vals = sorted(values)
    return {
        "n": n, "mean": statistics.mean(values), "median": statistics.median(values),
        "stdev": statistics.stdev(values) if n > 1 else 0,
        "p5": s_vals[max(0, int((n-1)*0.05))], "p95": s_vals[min(n-1, int((n-1)*0.95))],
        "min": min(values), "max": max(values)
    }

def main():
    data = load_timings(TIMINGS_CSV)
    stats_dict = {c: compute_stats(v) for c, v in data.items() if v}
    baseline_mean = stats_dict["baseline"]["mean"]
    
    overheads = {}
    for c in ["strace", "sans_ebpf", "avec_ebpf"]:
        d_ms = stats_dict[c]["mean"] - baseline_mean
        overheads[c] = {"ms": d_ms, "pct": (d_ms / baseline_mean) * 100}

    # Generate Report
    lines = ["=== BENCHMARK 1 : OVERHEAD VS ÉTAT DE L'ART ==="]
    for c, s in stats_dict.items():
        lines.append(f"\n[{c.upper()}] N={s['n']} | Moy: {s['mean']:.1f}ms | Med: {s['median']:.1f}ms | StdDev: {s['stdev']:.1f}ms")
        if c != "baseline":
            lines.append(f" -> Overhead: +{overheads[c]['pct']:.1f}% (+{overheads[c]['ms']:.1f}ms)")
    
    lines.append("\n=== CONCLUSION SCIENTIFIQUE ===")
    tcpsnitch_ov = overheads["avec_ebpf"]["pct"]
    strace_ov = overheads["strace"]["pct"]
    
    if tcpsnitch_ov < strace_ov:
        lines.append(f"✅ SUCCÈS : tcpsnitch (+{tcpsnitch_ov:.1f}%) est bien plus performant que strace (+{strace_ov:.1f}%).")
        lines.append(f"L'architecture LD_PRELOAD + eBPF divise l'overhead par {strace_ov/tcpsnitch_ov:.1f} par rapport à ptrace.")
    else:
        lines.append("❌ ÉCHEC : tcpsnitch est plus lent que strace.")

    with open(REPORT_TXT, "w") as f:
        f.write("\n".join(lines))
        
    print(f"\n✅ Analyse terminée. Lisez {REPORT_TXT}")

if __name__ == "__main__":
    main()