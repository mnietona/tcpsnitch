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
}

HYPOTHESES = {
    "json_validity_pct":      ("H0-A", "JSON valides",             100.0, ">="),
    "socket_ratio":           ("H0-A", "Ratio socket/fichier",     0.99,  ">="),
    "socket_file_ratio":      ("H0-B", "Ratio socket/fichier",     0.99,  ">="),
    "tcp_files":              ("H0-B", "Fichiers TCP créés",       50.0,  ">="),
    "rss_ratio":              ("H0-C", "Ratio RSS max/init",       2.0,   "<="),
}

COLORS = {"A": "#5DADE2", "B": "#48C9B0", "C": "#E67E22"}

# ── Lecture Robuste ───────────────────────────────────────────────────────────

def load_raw(filepath):
    """Retourne un dict scenario → metric → liste de valeurs (Exclut le Scénario D)."""
    data = defaultdict(lambda: defaultdict(list))

    if not os.path.exists(filepath):
        print(f"❌ Fichier non trouvé : {filepath}")
        print("   Lance d'abord : bash run_benchmark.sh")
        sys.exit(1)

    with open(filepath, mode="r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        try:
            headers = next(reader)
        except StopIteration:
            return data
            
        headers = [h.strip().lower() for h in headers]
        
        try:
            idx_run = headers.index("run")
            idx_scenario = headers.index("scenario")
            idx_metric = headers.index("metric")
            idx_value = headers.index("value")
            idx_h0_ok = headers.index("h0_ok")
        except ValueError as e:
            print(f"❌ Erreur d'en-tête dans le CSV : {e}")
            sys.exit(1)

        for row in reader:
            if not row or len(row) <= max(idx_run, idx_scenario, idx_metric, idx_value, idx_h0_ok):
                continue
            
            s = row[idx_scenario].strip().upper()
            if s == "D" or not s:
                continue
                
            try:
                run_val = int(row[idx_run].strip())
                metric_val = row[idx_metric].strip()
                value_val = float(row[idx_value].strip())
                h0_ok_val = row[idx_h0_ok].strip() == "1"
                
                data[s][metric_val].append({
                    "run": run_val,
                    "value": value_val,
                    "h0_ok": h0_ok_val,
                })
            except ValueError:
                continue
                
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
                # Conversion KB en MB
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

    import matplotlib.gridspec as gridspec

    # Création de la figure avec une taille adaptée pour une page A4
    fig = plt.figure(figsize=(12, 9))
    
    # Définition de la grille : 2 lignes, 2 colonnes
    gs = gridspec.GridSpec(2, 2, height_ratios=[1, 1.2], hspace=0.35, wspace=0.2)

    fig.suptitle(
        "Benchmark 5 — Robustesse sous charge\n"
        "tcpsnitch — Intégrité, ratio 1:1 et stabilité mémoire",
        fontsize=15, fontweight="bold", y=0.98
    )

    # ── Panneau A : Validité JSON par run (Ligne 0, Colonne 0) ───────────────
    ax1 = fig.add_subplot(gs[0, 0])
    if "A" in stats and "json_validity_pct" in stats["A"]:
        st  = stats["A"]["json_validity_pct"]
        runs = range(1, st["n"] + 1)
        ax1.bar(runs, st["values"], color="#5DADE2", alpha=0.8, edgecolor="white")
        ax1.axhline(y=100, color="black", linewidth=2, linestyle="--", label="H0-A : 100%")
        ax1.set_xlabel("Run")
        ax1.set_ylabel("% fichiers JSON valides")
        ax1.set_title("Scénario A — Intégrité JSON\n(100 connexions simultanées)")
        ax1.set_ylim([90, 101])
        ax1.legend(loc="lower right")

    # ── Panneau B : Ratio socket/fichier (Ligne 0, Colonne 1) ────────────────
    ax2 = fig.add_subplot(gs[0, 1])
    if "B" in stats and "socket_file_ratio" in stats["B"]:
        st   = stats["B"]["socket_file_ratio"]
        runs = range(1, st["n"] + 1)
        colors = ["#48C9B0" if v >= 0.99 else "#E74C3C" for v in st["values"]]
        ax2.bar(runs, st["values"], color=colors, alpha=0.85, edgecolor="white")
        ax2.axhline(y=1.0, color="black", linewidth=2, linestyle="--", label="H0-B : Ratio = 1.0")
        ax2.set_xlabel("Run")
        ax2.set_ylabel("Ratio sockets / fichiers JSON")
        ax2.set_title("Scénario B — Fiabilité du Tracking\n(50 connexions séquentielles)")
        ax2.set_ylim([0.9, 1.05])
        ax2.legend(loc="lower right", fontsize=9)

    # ── Panneau C : Courbe RSS mémoire (Ligne 1, Colonnes 0 ET 1) ────────────
    ax3 = fig.add_subplot(gs[1, :])
    
    # CORRECTION : On charge les vraies données du fichier memory_log.csv
    timestamps, rss_mb = load_memory_log(MEM_LOG) 
    
    if timestamps and rss_mb:
        ax3.plot(timestamps, rss_mb, color="#E67E22", linewidth=2.5, label="Mémoire consommée (Mo)")
        ax3.fill_between(timestamps, rss_mb, alpha=0.2, color="#F5B041")
        if rss_mb:
            threshold_mb = rss_mb[0] * 2
            ax3.axhline(y=threshold_mb, color="black", linewidth=1.5, linestyle="--", label="H0-C seuil critique (2x init)")
        ax3.set_xlabel("Temps écoulé (secondes)")
        ax3.set_ylabel("Mémoire Résidente - RSS (Mo)")
        ax3.set_title("Scénario C — Stabilité mémoire\n(10 minutes de transferts en continu)")
        ax3.legend(loc="lower right", fontsize=10)
    else:
        ax3.text(0.5, 0.5, "Données mémoire\nnon disponibles dans " + os.path.basename(MEM_LOG),
                 ha="center", va="center", transform=ax3.transAxes,
                 fontsize=12, color="#7f8c8d")
        ax3.set_title("Scénario C — Stabilité mémoire\n(Données manquantes)")

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(filepath, dpi=250, bbox_inches="tight")
    plt.close()
    print(f"✅ Graphique principal généré dans {filepath}")
    
# ── Rapport texte ─────────────────────────────────────────────────────────────

def generate_report(stats, filepath):
    sep = "=" * 65
    lines = [
        sep,
        "  BENCHMARK 5 — ROBUSTESSE SOUS CHARGE (A, B, C)",
        sep,
        "",
        "CONTEXTE",
        "  Validation de la stabilité de tcpsnitch sous des conditions",
        "  extrêmes : connexions massives simultanées et transferts",
        "  continus de longue durée.",
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
            lines.append(f"  {verdict} {h0_desc}: {st['mean']:.2f} (seuil: {h0_thresh}) n={st['n']}")
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
            lines.append(f"  {verdict} {h0_desc}: {st['mean']:.2f} (seuil: {h0_thresh}) n={st['n']}")
            h0_global[h0_name] = h0_global.get(h0_name, True) and st["h0_ok"]
    lines.append("")

    # Scénario C
    lines.append("  Scénario C — Stabilité mémoire (10 min)")
    lines.append("  " + "─" * 50)
    if "C" in stats:
        for metric in ["rss_init_kb", "rss_max_kb", "rss_final_kb", "rss_ratio", "n_samples"]:
            if metric in stats["C"]:
                st = stats["C"][metric]
                if metric == "rss_ratio":
                    h0_name, h0_desc, h0_thresh, _ = HYPOTHESES.get(metric, ("?","?",0,"<="))
                    verdict = "✅" if st["h0_ok"] else "⚠️ "
                    lines.append(f"  {verdict} Ratio RSS max/init: {st['mean']:.3f}× (seuil: ≤{h0_thresh}×)")
                    h0_global["H0-C"] = h0_global.get("H0-C", True) and st["h0_ok"]
                elif metric == "rss_init_kb":
                    lines.append(f"    RSS initial : {st['mean']:.0f} KB")
                elif metric == "rss_max_kb":
                    lines.append(f"    RSS maximum : {st['mean']:.0f} KB")
                elif metric == "rss_final_kb":
                    lines.append(f"    RSS final   : {st['mean']:.0f} KB")
                elif metric == "n_samples":
                    verdict = "✅" if st["h0_ok"] else "⚠️ "
                    lines.append(f"  {verdict} Échantillons valides : {st['mean']:.0f} relevés")
    lines.append("")

    # Conclusion Globale
    lines += ["CONCLUSION GLOBALE", "-" * 65]
    all_ok = all(h0_global.values()) if h0_global else False

    for h0_name in ["H0-A", "H0-B", "H0-C"]:
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
            "  est maintenue, le ratio 1:1 est respecté, et la consommation",
            "  mémoire reste stable sur de longs transferts."
        ]
    else:
        lines += [
            "  Certaines hypothèses ne sont pas vérifiées.",
            "  Voir le détail par scénario ci-dessus."
        ]

    lines += ["", sep]
    report = "\n".join(lines)
    with open(filepath, "w") as f:
        f.write(report)
    return report

# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print(" Analyse Benchmark 5 — Robustesse sous charge")
    print("=" * 55)
    print()

    data  = load_raw(RAW_CSV)
    stats = compute_stats(data)

    for s in sorted(stats):
        print(f"  Scénario {s} — {SCENARIO_META.get(s, {}).get('desc', '')}")
        for metric, st in stats[s].items():
            verdict = "✅" if st["h0_ok"] else "⚠️ "
            
            if metric in HYPOTHESES:
                name = HYPOTHESES[metric][1]
            else:
                name = metric

            print(f"    {verdict} {name}: {st['mean']:.1f} (n={st['n']})")
        print()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    export_results_csv(stats, RESULTS_CSV)
    generate_main_graph(stats, GRAPH_PNG)
    generate_report(stats, REPORT_TXT)
    print(f"✅ Rapport généré dans {REPORT_TXT}")


if __name__ == "__main__":
    main()