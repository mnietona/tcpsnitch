import csv
import os
import sys
import statistics
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.style.use('seaborn-v0_8-whitegrid')
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("⚠️  matplotlib absent — graphique désactivé")

# ── Chemins ───────────────────────────────────────────────────────────────────

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR  = os.path.join(SCRIPT_DIR, "output")
RAW_CSV     = os.path.join(OUTPUT_DIR, "stress_raw.csv")
RESULTS_CSV = os.path.join(OUTPUT_DIR, "stress_results.csv")
GRAPH_PNG   = os.path.join(OUTPUT_DIR, "stress_graph.png")
MEM_LOG     = os.path.join(OUTPUT_DIR, "scenario_C", "memory_log.csv")
REPORT_TXT  = os.path.join(OUTPUT_DIR, "report.txt")

SCENARIO_META = {
    "A": {"desc": "Intégrité JSON — 100 connexions simultanées"},
    "B": {"desc": "Ratio 1:1 socket/fichier — 50 connexions séquentielles"},
    "C": {"desc": "Stabilité mémoire — 10 min transferts continus"},
    "D": {"desc": "close_range() — 500 sockets en masse"},
}

HYPOTHESES = {
    "json_validity_pct":  ("H0-A", "JSON valides",         100.0, ">="),
    "socket_ratio":       ("H0-A", "Ratio socket/fichier", 0.99,  ">="),
    "socket_file_ratio":  ("H0-B", "Ratio socket/fichier", 0.99,  ">="),
    "tcp_files":          ("H0-B", "Fichiers TCP créés",   50.0,  ">="),
    "rss_ratio":          ("H0-C", "Ratio RSS max/init",   2.0,   "<="),
    "close_coverage_pct": ("H0-D", "Couverture close()",   95.0,  ">="),
    "corrupted_json":     ("H0-D", "JSON corrompus",       0.0,   "<="),
}

COLORS = {"A": "#5DADE2", "B": "#48C9B0", "C": "#F5B041", "D": "#F4D03F"}

# ── Lecture ───────────────────────────────────────────────────────────────────

def load_raw(filepath):
    """Retourne un dict scenario → metric → liste de valeurs."""
    data = defaultdict(lambda: defaultdict(list))

    if not os.path.exists(filepath):
        print(f"❌ Fichier non trouvé : {filepath}")
        print("   Lance d'abord : bash run_benchmark.sh")
        sys.exit(1)

    with open(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            s      = row["scenario"]
            metric = row["metric"]
            try:
                val = float(row["value"])
                data[s][metric].append({
                    "run":   int(row["run"]),
                    "value": val,
                    "h0_ok": row["h0_ok"] == "1",
                })
            except ValueError:
                pass
    return data

def load_memory_log(filepath):
    """Charge le log mémoire pour le graphique RSS."""
    timestamps = []
    rss_values = []
    if not os.path.exists(filepath):
        return timestamps, rss_values

    with open(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                timestamps.append(int(row["timestamp_s"]))
                # Convertir KB en MB
                rss_values.append(int(row["rss_kb"]) / 1024.0)
            except (ValueError, KeyError):
                pass
    return timestamps, rss_values

# ── Statistiques ──────────────────────────────────────────────────────────────

def compute_stats(data):
    """Retourne stats par scénario/métrique."""
    stats = {}
    for s, metrics in data.items():
        stats[s] = {}
        for metric, entries in metrics.items():
            values   = [e["value"] for e in entries]
            h0_ok_all = all(e["h0_ok"] for e in entries)
            n = len(values)
            stats[s][metric] = {
                "n":       n,
                "mean":    statistics.mean(values) if n > 0 else 0,
                "median":  statistics.median(values) if n > 0 else 0,
                "stdev":   statistics.stdev(values) if n > 1 else 0,
                "min":     min(values) if n > 0 else 0,
                "max":     max(values) if n > 0 else 0,
                "h0_ok":   h0_ok_all,
                "values":  values,
            }
    return stats

# ── Export CSV ────────────────────────────────────────────────────────────────

def export_results_csv(stats, filepath):
    fields = [
        "scenario", "metric", "n_runs",
        "mean", "median", "stdev", "min", "max", "h0_ok"
    ]
    with open(filepath, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for s in sorted(stats):
            for metric, st in stats[s].items():
                w.writerow({
                    "scenario": s,
                    "metric":   metric,
                    "n_runs":   st["n"],
                    "mean":     round(st["mean"],   3),
                    "median":   round(st["median"], 3),
                    "stdev":    round(st["stdev"],  3),
                    "min":      round(st["min"],     3),
                    "max":      round(st["max"],     3),
                    "h0_ok":    "✅" if st["h0_ok"] else "⚠️",
                })

# ── Graphiques ─────────────────────────────────────────────────────────────────

def generate_main_graph(stats, filepath):
    if not HAS_MATPLOTLIB:
        return

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(
        "Benchmark 5 — Robustesse sous charge\n"
        "tcpsnitch — Intégrité, ratio 1:1, mémoire, close_range()",
        fontsize=14, fontweight="bold", y=0.98
    )

    # ── Panneau A : Validité JSON par run ────────────────────────────────────
    ax1 = axes[0][0]
    if "A" in stats and "json_validity_pct" in stats["A"]:
        st  = stats["A"]["json_validity_pct"]
        runs = range(1, st["n"] + 1)
        ax1.bar(runs, st["values"], color=COLORS["A"], alpha=0.8, edgecolor="white")
        ax1.axhline(y=100, color="black", linewidth=2, linestyle="--",
                    label="H0-A : 100%")
        ax1.set_xlabel("Run")
        ax1.set_ylabel("% fichiers JSON valides")
        ax1.set_title("Scénario A — Intégrité JSON\n100 connexions simultanées")
        ax1.set_ylim([90, 101])
        ax1.set_xticks(runs)
        ax1.legend(loc="lower right")

    # ── Panneau B : Ratio socket/fichier ─────────────────────────────────────
    ax2 = axes[0][1]
    if "B" in stats and "socket_file_ratio" in stats["B"]:
        st   = stats["B"]["socket_file_ratio"]
        runs = range(1, st["n"] + 1)
        bars = ax2.bar(runs, st["values"],
                       color=[COLORS["B"] if v >= 0.99 else "#E74C3C"
                              for v in st["values"]],
                       alpha=0.85, edgecolor="white")
        ax2.axhline(y=1.0, color="black", linewidth=2, linestyle="--",
                    label="H0-B : ratio = 1.0")
        ax2.axhline(y=0.99, color="#E67E22", linewidth=1, linestyle=":",
                    label="Seuil acceptable : 0.99")
        for bar, val in zip(bars, st["values"]):
            ax2.text(bar.get_x() + bar.get_width()/2,
                     bar.get_height() + 0.002,
                     f"{val:.3f}",
                     ha="center", fontsize=9, fontweight="bold")
        ax2.set_xlabel("Run")
        ax2.set_ylabel("Ratio sockets TCP / fichiers JSON")
        ax2.set_title("Scénario B — Ratio 1:1\n50 connexions séquentielles")
        ax2.set_ylim([0.9, 1.05])
        ax2.set_xticks(runs)
        ax2.legend(loc="lower right", fontsize=9)

    # ── Panneau C : Courbe RSS mémoire ───────────────────────────────────────
    ax3 = axes[1][0]
    timestamps, rss_mb = load_memory_log(MEM_LOG)
    if timestamps and rss_mb:
        ax3.plot(timestamps, rss_mb, color="#E67E22", linewidth=2.5, label="RSS (MB)")
        ax3.fill_between(timestamps, rss_mb, alpha=0.2, color="#F5B041")
        
        if rss_mb:
            initial_mb = rss_mb[0]
            threshold_mb = initial_mb * 2
            
            max_y = max(max(rss_mb) * 1.5, threshold_mb * 1.2)
            ax3.set_ylim([0, max_y])
            
            ax3.axhline(y=threshold_mb, color="black", linewidth=1.5,
                        linestyle="--", label=f"H0-C seuil : 2× init ({threshold_mb:.1f} MB)")
            ax3.axhline(y=initial_mb, color="#27AE60", linewidth=1.5,
                        linestyle=":", label=f"Valeur initiale ({initial_mb:.1f} MB)")

        ax3.set_xlabel("Temps (secondes)")
        ax3.set_ylabel("RSS mémoire (MB)")
        ax3.set_title("Scénario C — Stabilité mémoire\n10 min de transferts continus")
        ax3.legend(loc="upper right", fontsize=9)
    else:
        ax3.text(0.5, 0.5, "Données mémoire\nnon disponibles",
                 ha="center", va="center", transform=ax3.transAxes,
                 fontsize=12, color="#7f8c8d")
        ax3.set_title("Scénario C — Stabilité mémoire")

    # ── Panneau D : Couverture close() ────────────────────────────────────────
    ax4 = axes[1][1]
    if "D" in stats and "close_coverage_pct" in stats["D"]:
        st   = stats["D"]["close_coverage_pct"]
        runs = range(1, st["n"] + 1)
        bars = ax4.bar(runs, st["values"],
                       color=[COLORS["D"] if v >= 95 else "#E74C3C"
                              for v in st["values"]],
                       alpha=0.85, edgecolor="white")
        ax4.axhline(y=100, color="black", linewidth=2, linestyle="--",
                    label="Idéal : 100%")
        ax4.axhline(y=95, color="#E67E22", linewidth=1.5, linestyle=":",
                    label="H0-D seuil : 95%")
        for bar, val in zip(bars, st["values"]):
            ax4.text(bar.get_x() + bar.get_width()/2,
                     bar.get_height() + 0.5,
                     f"{val:.1f}%",
                     ha="center", fontsize=10, fontweight="bold")
        ax4.set_xlabel("Run")
        ax4.set_ylabel("% sockets avec close() journalisé")
        ax4.set_title("Scénario D — close_range()\n500 sockets en masse")
        ax4.set_ylim([0, 110]) # On met de 0 à 110 pour bien voir les échecs (66%)
        ax4.set_xticks(runs)
        ax4.legend(loc="lower right", fontsize=9)

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    
    plt.savefig(filepath, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"✅ Graphique principal généré dans {filepath}")

# ── Rapport texte ─────────────────────────────────────────────────────────────

def generate_report(stats, filepath):
    sep = "=" * 65
    lines = [
        sep,
        "  BENCHMARK 5 — ROBUSTESSE SOUS CHARGE",
        sep,
        "",
        "CONTEXTE",
        "  Validation de la stabilité de tcpsnitch sous des conditions",
        "  extrêmes : connexions massives simultanées, fermetures en",
        "  rafale via close_range(), et transferts continus longue durée.",
        "",
        "RÉSULTATS PAR SCÉNARIO",
        "-" * 65,
    ]

    h0_global = {}

    # Scénario A
    lines.append("  Scénario A — Intégrité JSON (100 connexions simultanées)")
    lines.append("  " + "─" * 50)
    for metric in ["json_validity_pct", "socket_ratio"]:
        if "A" in stats and metric in stats["A"]:
            st = stats["A"][metric]
            h0_name, h0_desc, h0_thresh, _ = HYPOTHESES.get(metric, ("?","?",0,">="))
            verdict = "✅" if st["h0_ok"] else "⚠️ "
            lines.append(
                f"  {verdict} {h0_desc}: {st['mean']:.2f} "
                f"(seuil: {h0_thresh}) n={st['n']}"
            )
            h0_global[h0_name] = h0_global.get(h0_name, True) and st["h0_ok"]
    lines.append("")

    # Scénario B
    lines.append("  Scénario B — Ratio 1:1 (50 connexions séquentielles)")
    lines.append("  " + "─" * 50)
    for metric in ["tcp_files", "socket_file_ratio"]:
        if "B" in stats and metric in stats["B"]:
            st = stats["B"][metric]
            h0_name, h0_desc, h0_thresh, _ = HYPOTHESES.get(metric, ("?","?",0,">="))
            verdict = "✅" if st["h0_ok"] else "⚠️ "
            lines.append(
                f"  {verdict} {h0_desc}: {st['mean']:.2f} "
                f"(seuil: {h0_thresh}) n={st['n']}"
            )
            h0_global[h0_name] = h0_global.get(h0_name, True) and st["h0_ok"]
    lines.append("")

    # Scénario C
    lines.append("  Scénario C — Stabilité mémoire (10 min)")
    lines.append("  " + "─" * 50)
    if "C" in stats:
        for metric in ["rss_init_kb", "rss_max_kb", "rss_final_kb", "rss_ratio"]:
            if metric in stats["C"]:
                st = stats["C"][metric]
                if metric == "rss_ratio":
                    h0_name, h0_desc, h0_thresh, _ = HYPOTHESES.get(metric, ("?","?",0,"<="))
                    verdict = "✅" if st["h0_ok"] else "⚠️ "
                    lines.append(
                        f"  {verdict} Ratio RSS max/init: {st['mean']:.3f}× "
                        f"(seuil: ≤{h0_thresh}×)"
                    )
                    h0_global["H0-C"] = h0_global.get("H0-C", True) and st["h0_ok"]
                elif metric == "rss_init_kb":
                    lines.append(f"    RSS initial : {st['mean']:.0f} KB")
                elif metric == "rss_max_kb":
                    lines.append(f"    RSS maximum : {st['mean']:.0f} KB")
                elif metric == "rss_final_kb":
                    lines.append(f"    RSS final   : {st['mean']:.0f} KB")
    lines.append("")

    # Scénario D
    lines.append("  Scénario D — close_range() (500 sockets)")
    lines.append("  " + "─" * 50)
    for metric in ["n_files", "close_coverage_pct", "corrupted_json"]:
        if "D" in stats and metric in stats["D"]:
            st = stats["D"][metric]
            if metric in HYPOTHESES:
                h0_name, h0_desc, h0_thresh, _ = HYPOTHESES[metric]
                verdict = "✅" if st["h0_ok"] else "⚠️ "
                lines.append(
                    f"  {verdict} {h0_desc}: {st['mean']:.1f} "
                    f"(seuil: {h0_thresh}) n={st['n']}"
                )
                h0_global[h0_name] = h0_global.get(h0_name, True) and st["h0_ok"]
            else:
                lines.append(f"    {metric}: {st['mean']:.1f}")
    lines.append("")

    # Conclusion
    lines += ["CONCLUSION GLOBALE", "-" * 65]
    all_ok = all(h0_global.values()) if h0_global else False

    for h0_name in ["H0-A", "H0-B", "H0-C", "H0-D"]:
        ok = h0_global.get(h0_name, None)
        if ok is None:
            lines.append(f"  ❓ {h0_name} : non mesurée")
        elif ok:
            lines.append(f"  ✅ {h0_name} : vérifiée")
        else:
            lines.append(f"  ⚠️  {h0_name} : non vérifiée")

    lines.append("")
    if all_ok:
        lines += [
            "  tcpsnitch est robuste sous charge. L'intégrité des données",
            "  est maintenue sur 100 connexions simultanées, le ratio 1:1",
            "  socket/fichier est respecté, la mémoire est stable et",
            "  close_range() est correctement intercepté.",
        ]
    else:
        lines += [
            "  Certaines hypothèses ne sont pas vérifiées.",
            "  Voir le détail par scénario ci-dessus.",
        ]

    lines += ["", sep]
    report = "\n".join(lines)
    with open(filepath, "w") as f:
        f.write(report)
    print(f"✅ Rapport généré dans {filepath}")
    return report

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print(" Analyse Benchmark 5 — Robustesse sous charge")
    print("=" * 55)
    print()

    data  = load_raw(RAW_CSV)
    stats = compute_stats(data)

    # Résumé terminal
    for s in sorted(stats):
        print(f"  Scénario {s} — {SCENARIO_META.get(s, {}).get('desc', '')}")
        for metric, st in stats[s].items():
            verdict = "✅" if st["h0_ok"] else "⚠️ "
            print(f"    {verdict} {metric}: {st['mean']:.3f} (n={st['n']})")
        print()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    export_results_csv(stats, RESULTS_CSV)
    generate_main_graph(stats, GRAPH_PNG)
    report = generate_report(stats, REPORT_TXT)


if __name__ == "__main__":
    main()