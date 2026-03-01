import csv, os, sys, statistics
from collections import defaultdict

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("⚠️  matplotlib absent — graphique désactivé")

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR  = os.path.join(SCRIPT_DIR, "output")
RAW_CSV     = os.path.join(OUTPUT_DIR, "protocol_raw.csv")
RESULTS_CSV = os.path.join(OUTPUT_DIR, "protocol_results.csv")
GRAPH_PNG   = os.path.join(OUTPUT_DIR, "protocol_graph.png")
REPORT_TXT  = os.path.join(OUTPUT_DIR, "report.txt")

PROTOCOLS = ["http1", "http2", "http3"]
LOSS_RATES = [2, 5, 10, 20]

PROTO_LABELS = {"http1": "HTTP/1.1", "http2": "HTTP/2", "http3": "HTTP/3 (QUIC/UDP)"}
PROTO_COLORS = {"http1": "#e74c3c", "http2": "#3498db", "http3": "#2ecc71"}

def load_raw(filepath):
    data = defaultdict(list)
    if not os.path.exists(filepath): sys.exit(1)
    with open(filepath) as f:
        for row in csv.DictReader(f):
            if int(row["transfer_ok"]):
                data[(row["protocol"], int(row["loss_pct"]))].append(int(row["retrans_correlated"]))
    return data

def compute_stats(data):
    stats = {}
    for key, values in data.items():
        if not values: continue
        stats[key] = {
            "n": len(values), "mean": statistics.mean(values),
            "median": statistics.median(values),
            "stdev": statistics.stdev(values) if len(values) > 1 else 0,
            "min": min(values), "max": max(values)
        }
    return stats

def check_hypotheses(stats):
    results = {}
    
    # H0-A : HTTP/2 <= HTTP/1.1 à 10% et 20%
    h0a_ok = True; h0a_details = []
    for loss in [10, 20]:
        k1, k2 = ("http1", loss), ("http2", loss)
        if k1 in stats and k2 in stats:
            m1, m2 = stats[k1]["mean"], stats[k2]["mean"]
            if m2 > m1: h0a_ok = False
            h0a_details.append({"loss": loss, "http1": m1, "http2": m2, "delta": m2 - m1, "ok": m2 <= m1})
    results["H0-A"] = {"verified": h0a_ok, "details": h0a_details}

    # H0-B : Monotonie
    h1_mono = h2_mono = True
    p1 = p2 = -1
    for loss in LOSS_RATES:
        if ("http1", loss) in stats:
            m = stats[("http1", loss)]["mean"]
            if m < p1: h1_mono = False
            p1 = m
        if ("http2", loss) in stats:
            m = stats[("http2", loss)]["mean"]
            if m < p2: h2_mono = False
            p2 = m
    results["H0-B"] = {"verified": h1_mono and h2_mono, "http1_monotone": h1_mono, "http2_monotone": h2_mono}

    # H0-C : HTTP/3 = 0 TCP
    h3_means = [stats.get(("http3", l), {}).get("mean", 0) for l in LOSS_RATES]
    results["H0-C"] = {"verified": all(v == 0 for v in h3_means), "means": h3_means}

    return results

def generate_graph(stats, hypotheses, filepath):
    if not HAS_MATPLOTLIB: return
    fig, axes = plt.subplots(2, 2, figsize=(16, 11))
    fig.suptitle("Benchmark 4 — Comparaison Protocoles TCP/UDP", fontsize=14, fontweight="bold")

    # Panel 1: Courbes
    ax1 = axes[0][0]
    for proto in ["http1", "http2"]:
        means = [stats.get((proto, l), {}).get("mean", 0) for l in LOSS_RATES]
        stdevs = [stats.get((proto, l), {}).get("stdev", 0) for l in LOSS_RATES]
        ax1.errorbar([f"{l}%" for l in LOSS_RATES], means, yerr=stdevs, marker="o" if proto=="http1" else "s",
                     color=PROTO_COLORS[proto], label=f"{PROTO_LABELS[proto]}", capsize=5, linewidth=2)
    ax1.set_title("Retransmissions = f(taux de perte)"); ax1.legend(); ax1.grid(alpha=0.4)

    # Panel 2: Barres groupées
    ax2 = axes[0][1]
    width = 0.35
    for i, proto in enumerate(["http1", "http2"]):
        means = [stats.get((proto, l), {}).get("mean", 0) for l in LOSS_RATES]
        ax2.bar([x + (i*width) for x in range(len(LOSS_RATES))], means, width, color=PROTO_COLORS[proto], label=PROTO_LABELS[proto])
    ax2.set_xticks([x + width/2 for x in range(len(LOSS_RATES))])
    ax2.set_xticklabels([f"{l}%" for l in LOSS_RATES])
    ax2.set_title("Comparaison par taux de perte"); ax2.legend(); ax2.grid(alpha=0.4)

    # Panel 3: Ratio
    ax3 = axes[1][0]
    ratios = []
    for l in LOSS_RATES:
        if ("http1", l) in stats and ("http2", l) in stats and stats[("http1", l)]["mean"] > 0:
            ratios.append(stats[("http2", l)]["mean"] / stats[("http1", l)]["mean"])
        else: ratios.append(0)
    colors = ["#27ae60" if r <= 1 else "#c0392b" for r in ratios]
    ax3.bar([f"{l}%" for l in LOSS_RATES], ratios, color=colors)
    ax3.axhline(1.0, color="black", linestyle="--", label="Égalité")
    ax3.set_title("Ratio HTTP/2 vs HTTP/1.1 (<1 = HTTP/2 gagne)"); ax3.legend(); ax3.grid(alpha=0.4)

    # Panel 4: HTTP/3
    ax4 = axes[1][1]
    h3_means = [stats.get(("http3", l), {}).get("mean", 0) for l in LOSS_RATES]
    ax4.bar([f"{l}%" for l in LOSS_RATES], h3_means, color=PROTO_COLORS["http3"], label="HTTP/3")
    ax4.set_title("HTTP/3 (QUIC/UDP) : 0 Retransmissions TCP"); ax4.legend(); ax4.grid(alpha=0.4)

    plt.tight_layout()
    plt.savefig(filepath)

def main():
    data = load_raw(RAW_CSV)
    stats = compute_stats(data)
    hypotheses = check_hypotheses(stats)
    
    lines = ["=== BENCHMARK 4 : COMPARAISON DE PROTOCOLES ===\n"]
    for h, res in hypotheses.items():
        v = "✅" if res["verified"] else "⚠️"
        lines.append(f"{v} {h} vérifiée: {res['verified']}")
    
    with open(REPORT_TXT, "w") as f: f.write("\n".join(lines))
    generate_graph(stats, hypotheses, GRAPH_PNG)
    print(f"\n✅ Analyse terminée. Consultez {GRAPH_PNG} et {REPORT_TXT}")

if __name__ == "__main__":
    main()