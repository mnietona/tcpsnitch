import subprocess
import os
import time
import shutil

# --- CONFIGURATION ---
TCPSNITCH_BIN = "./bin/tcpsnitch"
DATASET_DIR = "/home/matias/share-vm/dataset_rich"
INTERFACE_LOGS = 3 # Niveau INFO pour voir Netlink

# Liste des scénarios
SCENARIOS = [
    # 1. WEB : Simulation de navigation
    ("web_wikipedia", ["wget", "--no-check-certificate", "-r", "-l", "1", "-nd", "--delete-after", "https://www.wikipedia.org"]),
    
    # 2. STREAMING : Téléchargement d'une vidéo
    ("media_youtube", ["yt-dlp", "--no-check-certificate", "-f", "worst", "--max-downloads", "1", "https://www.youtube.com/watch?v=BaW_jenozKc"]),
    
    # 3. DEV : Clonage Git
    ("dev_git", ["git", "clone", "https://github.com/octocat/Hello-World.git", "/tmp/hello_world_test"]),
    
    # 4. DNS : Résolution
    ("net_dns", ["dig", "+trace", "google.com"]),
    
    # 5. SYSTÈME : Mise à jour paquets
    ("sys_apt", ["apt-get", "update"]),
    
    # 6. NETLINK : Test de mobilité
    ("sys_netlink", ["python3", "-c", "import time, socket; s=socket.socket(); time.sleep(5)"])
]

def run_trace(name, command):
    print(f"\n[+] Lancement du scénario : {name}")
    print(f"    Commande : {' '.join(command)}")
    
    # Dossier de sortie pour ce scénario
    output_path = os.path.join(DATASET_DIR, name)
    
    # --- CORRECTION ICI : Création du dossier AVANT l'exécution ---
    if not os.path.exists(output_path):
        os.makedirs(output_path)
        # On donne les droits max pour éviter les soucis avec sudo
        os.chmod(output_path, 0o777) 
    
    # Construction de la commande TCPSnitch
    full_cmd = ["sudo", TCPSNITCH_BIN, "-n", "-d", output_path, "-f", str(INTERFACE_LOGS)] + command
    
    print(full_cmd)
    try:
        # Exécution
        start_time = time.time()
        subprocess.run(full_cmd, check=False, timeout=120) 
        duration = time.time() - start_time
        print(f"    -> Terminé en {duration:.2f} secondes.")
        
    except Exception as e:
        print(f"    -> Erreur : {e}")

def main():
    # 1. Nettoyage
    if os.path.exists(DATASET_DIR):
        print(f"Nettoyage du dossier {DATASET_DIR}...")
        shutil.rmtree(DATASET_DIR)
    os.makedirs(DATASET_DIR)
    os.chmod(DATASET_DIR, 0o777) # Permissions larges pour le dossier parent

    # 2. Exécution des scénarios
    print(f"Génération du dataset dans {DATASET_DIR}...")
    
    for name, cmd in SCENARIOS:
        run_trace(name, cmd)
        time.sleep(1) # Pause

    # 3. Nettoyage des fichiers temporaires
    if os.path.exists("/tmp/hello_world_test"):
        shutil.rmtree("/tmp/hello_world_test")
    
    print("\n--- GÉNÉRATION TERMINÉE ---")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Ce script doit être lancé avec sudo !")
        exit(1)
    main()