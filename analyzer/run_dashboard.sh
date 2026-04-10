#!/bin/bash
# ── tcpsnitch 2026 Dashboard — Installation & Lancement ──────────────────────
set -e
GREEN='\033[0;32m'; NC='\033[0m'

echo -e "${GREEN}=== Préparation de l'environnement virtuel ===${NC}"
# 1. On crée un environnement virtuel nommé ".venv" s'il n'existe pas déjà
if [ ! -d ".venv" ]; then
    echo "Création du dossier .venv..."
    python3 -m venv .venv
fi

# 2. On active l'environnement virtuel
source .venv/bin/activate

echo -e "${GREEN}=== Installation des dépendances ===${NC}"
# 3. Installation des paquets requis
pip install streamlit plotly pandas numpy --quiet

echo -e "${GREEN}=== Lancement du dashboard ===${NC}"
echo "👉 Ouvre http://localhost:8501 dans ton navigateur"
echo "🌐 Pour y accéder via Tailscale : http://100.81.46.75:8501"
echo "--------------------------------------------------------"

# 4. On lance l'application modulaire
streamlit run app.py \
    --server.port 8501 \
    --server.headless true \
    --browser.gatherUsageStats false