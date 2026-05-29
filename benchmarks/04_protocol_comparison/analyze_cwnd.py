import os
import sys
import json
import glob

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.style.use('seaborn-v0_8-whitegrid')
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
HTTP2_DIR  = os.path.join(OUTPUT_DIR, "runs", "http2_loss10")

def find_best_run():
    max_tcp_info = 0
    best_run_dir = None
    if not os.path.exists(HTTP2_DIR): return None, 0

    for run_folder in glob.glob(os.path.join(HTTP2_DIR, "run_*")):
        actual_dirs = glob.glob(os.path.join(run_folder, "curl_*"))
        if not actual_dirs: continue
        actual_dir = actual_dirs[0]
        json_files = glob.glob(os.path.join(actual_dir, "[0-9]*.json"))
        for jf in json_files:
            try:
                count = sum(1 for line in open(jf) if '"tcp_info"' in line)
                if count > max_tcp_info:
                    max_tcp_info = count; best_run_dir = actual_dir
            except: pass
    return best_run_dir, max_tcp_info

def main():
    if not HAS_MATPLOTLIB: return

    res = find_best_run()
    if not res or res[1] < 5: return
        
    target_dir, _ = res
    print(f" Extraction des données brutes séparées depuis : {os.path.basename(target_dir)}")

    json_files = glob.glob(os.path.join(target_dir, "[0-9]*.json"))
    ebpf_file = os.path.join(target_dir, "ebpf_events.jsonl")

    # Polling
    timestamps_cwnd = []
    for jf in json_files:
        with open(jf) as f:
            for line in f:
                if not line.strip(): continue
                try:
                    ev = json.loads(line)
                    if ev.get("type") == "tcp_info":
                        ts = ev.get("timestamp_usec")
                        if ts is None:
                            ts = ev.get("timestamp_ns")
                            if ts: ts = ts / 1000.0 # On convertit ns en usec
                        cwnd = ev.get("details", {}).get("snd_cwnd", 0)
                        if ts: timestamps_cwnd.append((ts, cwnd))
                except: pass

    timestamps_cwnd.sort(key=lambda x: x[0])
    
    # Noyau (eBPF)
    ebpf_events = []
    if os.path.exists(ebpf_file):
        with open(ebpf_file) as f:
            for line in f:
                if not line.strip(): continue
                try:
                    ev = json.loads(line)
                    if ev.get("type") == "tcp_retransmit" and ev.get("session_id") != 9999:
                        ts_ns = ev.get("timestamp_ns")
                        cwnd = ev.get("snd_cwnd")
                        if ts_ns and cwnd is not None:
                            ebpf_events.append((ts_ns, cwnd))
                except: pass
                
    ebpf_events.sort(key=lambda x: x[0])


    # Temps synchroniser
    
    if timestamps_cwnd:
        start_tcp_usec = timestamps_cwnd[0][0]
        t_tcp_ms = [(t - start_tcp_usec) / 1000.0 for t, c in timestamps_cwnd]
        c_tcp_val = [c for t, c in timestamps_cwnd]
    else:
        t_tcp_ms, c_tcp_val = [], []

    if ebpf_events:
        start_ebpf_ns = ebpf_events[0][0]
        t_ebpf_ms = [(t - start_ebpf_ns) / 1000000.0 for t, c in ebpf_events]
        c_ebpf_val = [c for t, c in ebpf_events]
    else:
        t_ebpf_ms, c_ebpf_val = [], []


    fig1, ax1 = plt.subplots(figsize=(14, 6))
    
    if t_tcp_ms:
        ax1.step(t_tcp_ms, c_tcp_val, where='post', color='#2980b9', linewidth=2.5, label="snd_cwnd (tcp_info)")
        ax1.fill_between(t_tcp_ms, c_tcp_val, step="post", alpha=0.15, color='#3498db')
        
    ax1.axhline(y=10, color='#95a5a6', linestyle='--', linewidth=1.5, label="Initial cwnd (10)")
    ax1.set_title("Capture de la Fenêtre de Congestion TCP\n(Mesure User-Space 'tcp_info')", fontsize=14, fontweight='bold', pad=15)
    ax1.set_xlabel("Temps écoulé (millisecondes)", fontsize=12, fontweight='bold')
    ax1.set_ylabel("Taille de la fenêtre (Paquets MSS)", fontsize=12, fontweight='bold')
    ax1.grid(True, linestyle=':', alpha=0.7)
    ax1.legend(loc='upper right', frameon=True, shadow=True)
    
    plt.tight_layout()
    out_tcp = os.path.join(OUTPUT_DIR, "graph_tcp_cwnd.png")
    fig1.savefig(out_tcp, dpi=200)
    plt.close(fig1)

    fig2, ax2 = plt.subplots(figsize=(14, 6))
    
    if t_ebpf_ms:
        ax2.step(t_ebpf_ms, c_ebpf_val, where='post', color='#8e44ad', linewidth=2.5, label="snd_cwnd lu au moment de la perte")
        ax2.fill_between(t_ebpf_ms, c_ebpf_val, step="post", alpha=0.15, color='#9b59b6')
        
        ax2.plot(t_ebpf_ms, c_ebpf_val, marker='o', color='#c0392b', markersize=8, markeredgecolor='white', linestyle='None', zorder=5, label="Événement eBPF (tcp_retransmit)")
        
    ax2.axhline(y=10, color='#95a5a6', linestyle='--', linewidth=1.5, label="Initial cwnd (10)")
    ax2.set_title("Captures de la Fenêtre de Congestion par eBPF\n(Valeurs exactes de snd_cwnd lues dans le noyau lors des pertes de paquets)", fontsize=14, fontweight='bold', pad=15)
    ax2.set_xlabel("Temps écoulé (millisecondes)", fontsize=12, fontweight='bold')
    ax2.set_ylabel("Taille de la fenêtre (Paquets MSS)", fontsize=12, fontweight='bold')
    ax2.grid(True, linestyle=':', alpha=0.7)
    ax2.legend(loc='upper right', frameon=True, shadow=True)
    
    plt.tight_layout()
    out_ebpf = os.path.join(OUTPUT_DIR, "graph_ebpf_cwnd.png")
    fig2.savefig(out_ebpf, dpi=200)
    plt.close(fig2)
    
    fig3, ax3 = plt.subplots(figsize=(14, 6))

    if t_tcp_ms:
        ax3.step(t_tcp_ms, c_tcp_val, where='post', color='#2980b9', alpha=0.4, linewidth=1.5, label="Polling (Espace Utilisateur)")
        
    if t_ebpf_ms:
        ax3.step(t_ebpf_ms, c_ebpf_val, where='post', color='#8e44ad', linewidth=2, label="Capture noyau (eBPF)")
        ax3.plot(t_ebpf_ms, c_ebpf_val, marker='o', color='#c0392b', markersize=6, markeredgecolor='white', linestyle='None', zorder=5, label="Instant de retransmission")

    ax3.axhline(y=10, color='#95a5a6', linestyle='--', linewidth=1, label="Init CWND")
    ax3.set_title("Réconciliation des mesures de congestion (Polling vs eBPF)", fontsize=14, fontweight='bold')
    ax3.set_xlabel("Temps écoulé (ms)", fontsize=12)
    ax3.set_ylabel("Taille de la fenêtre (MSS)", fontsize=12)
    ax3.legend(loc='upper right', frameon=True, shadow=True)
    ax3.grid(True, linestyle=':', alpha=0.6)

    plt.tight_layout()
    out_comp = os.path.join(OUTPUT_DIR, "graph_comparison_cwnd.png")
    fig3.savefig(out_comp, dpi=250) # Haute résolution pour le mémoire
    plt.close(fig3)

    print(f"Graphique 1 (TCP Info) généré : {out_tcp}")
    print(f"Graphique 2 (eBPF) généré     : {out_ebpf}")
    print(f"Graphique de comparaison généré : {out_comp}")

if __name__ == "__main__":
    main()