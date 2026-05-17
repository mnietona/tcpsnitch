import os
import glob
import json
import csv

# --- Configuration ---
SCENARIOS = {
    "E_Partiel": "output/scenario_E_partiel",
    "D_Total": "output/scenario_D_total"
}
OUTPUT_CSV = "output/analyse_globale_benchmark5.csv"

def analyze_all_scenarios():
    print("🚀 Démarrage de l'analyse croisée des Scénarios D et E...\n")
    
    all_results = []

    for scenario_name, base_dir in SCENARIOS.items():
        print(f"==========================================================")
        print(f"🔍 ANALYSE DU SCÉNARIO : {scenario_name}")
        print(f"📂 Dossier : {base_dir}")
        print(f"==========================================================")
        
        run_dirs = glob.glob(os.path.join(base_dir, "run_*"))
        
        if not run_dirs:
            print(f"❌ Aucun dossier 'run_X' trouvé dans {base_dir}.\n")
            continue

        total_global_files = 0
        total_global_empty = 0
        total_global_sockets = 0
        total_global_closes = 0

        # Tri des runs par numéro
        sorted_runs = sorted(run_dirs, key=lambda x: int(os.path.basename(x).split('_')[1]) if '_' in os.path.basename(x) else 0)

        for run_dir in sorted_runs:
            run_name = os.path.basename(run_dir)
            json_files = glob.glob(os.path.join(run_dir, "**", "[0-9]*.json"), recursive=True)
            
            total_files = len(json_files)
            empty_files = 0
            valid_sockets = 0
            valid_closes = 0

            for jf in json_files:
                # 1. Fichier mort (0 octet)
                if os.path.getsize(jf) == 0:
                    empty_files += 1
                    continue

                has_socket = False
                has_close = False
                is_empty_content = True

                # 2. Lecture du contenu JSON
                try:
                    with open(jf, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            
                            is_empty_content = False
                            try:
                                ev = json.loads(line)
                                ev_type = ev.get("type")
                                if ev_type == "socket":
                                    has_socket = True
                                elif ev_type in ("close", "close_range"):
                                    has_close = True
                            except json.JSONDecodeError:
                                pass # Crash en milieu d'écriture
                except Exception:
                    pass

                # 3. Bilan individuel du fichier
                if is_empty_content:
                    empty_files += 1
                else:
                    if has_socket: valid_sockets += 1
                    if has_close: valid_closes += 1

            corruption_rate = round((empty_files / total_files * 100), 2) if total_files > 0 else 0

            # Sauvegarde de la ligne pour le CSV
            all_results.append({
                "scenario": scenario_name,
                "run_id": run_name,
                "total_fichiers": total_files,
                "fichiers_vides_corrompus": empty_files,
                "traces_socket_valides": valid_sockets,
                "traces_close_valides": valid_closes,
                "taux_corruption_pct": corruption_rate
            })
            
            total_global_files += total_files
            total_global_empty += empty_files
            total_global_sockets += valid_sockets
            total_global_closes += valid_closes

        # --- Résumé pour le scénario en cours ---
        global_rate = round((total_global_empty / total_global_files * 100), 2) if total_global_files > 0 else 0
        
        print(f"📊 BILAN {scenario_name} (sur {len(sorted_runs)} itérations) :")
        print(f"   - Fichiers générés au total     : {total_global_files}")
        print(f"   - Fichiers victimes (0 octet)   : {total_global_empty} ({global_rate} % de corruption)")
        print(f"   - Fichiers survivants (Socket)  : {total_global_sockets}")
        print(f"   - Événements CLOSE capturés     : {total_global_closes}")
        
        if scenario_name == "E_Partiel":
            print("   💡 Note Mémoire : On s'attend à environ 50% de corruption (victimes de l'entrelacement)")
            print("      et à ce que le reste contienne de beaux événements 'close' valides.")
        elif scenario_name == "D_Total":
            print("   🚨 Note Mémoire : On s'attend à une forte corruption (suicide applicatif)")
            print("      et surtout à ZERO événement 'close' capturé !")
        print("\n")

    # --- Écriture du fichier CSV global ---
    if all_results:
        print(f"💾 Sauvegarde de l'analyse combinée dans {OUTPUT_CSV}...")
        with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["scenario", "run_id", "total_fichiers", "fichiers_vides_corrompus", "traces_socket_valides", "traces_close_valides", "taux_corruption_pct"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for row in all_results:
                writer.writerow(row)
        print("✅ Terminé !")

if __name__ == "__main__":
    analyze_all_scenarios()