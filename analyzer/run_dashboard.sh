#!/bin/bash

set -e
GREEN='\033[0;32m'; NC='\033[0m'

echo -e "${GREEN}=== Préparation de l'environnement virtuel ===${NC}"

if [ ! -d ".venv" ]; then
    echo "Création du dossier .venv..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo -e "${GREEN}=== Installation des dépendances ===${NC}"
pip install streamlit plotly pandas numpy --quiet


streamlit run app.py \
    --server.port 8501 \
    --server.headless true \
    --browser.gatherUsageStats false