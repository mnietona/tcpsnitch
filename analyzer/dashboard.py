import streamlit as st
import pandas as pd
import os
import glob
import json
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

# Configuration de la page : Layout large, titre pro
st.set_page_config(page_title="TCPSnitch Analytics", layout="wide")

# CSS pour masquer les éléments inutiles
st.markdown(
    """
<style>
    .reportview-container { background: #f0f2f6 }
    h1 { color: #1f2937; font-family: 'Helvetica Neue', sans-serif; }
    h2 { color: #374151; font-family: 'Helvetica Neue', sans-serif; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px; }
    .stMetric { background-color: #ffffff; padding: 15px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
</style>
""",
    unsafe_allow_html=True,
)

# SIDEBAR : Configuration
st.sidebar.title("Configuration")
# Valeur par défaut pointant vers le dossier décompressé
default_path = st.sidebar.text_input("Dataset Directory", value=".")


@st.cache_data
def load_dataset(directory):
    """
    Parcourt récursivement le dossier pour trouver les traces TCPSnitch.
    Structure attendue : Dossier_Scenario/X.json
    """
    records = []

    if not os.path.exists(directory):
        return pd.DataFrame()

    # Recherche de tous les fichiers JSON dans les sous-dossiers
    # pattern : root/*/0.json, root/*/1.json, etc.
    json_files = glob.glob(os.path.join(directory, "*", "*.json"))

    status_text = st.sidebar.empty()
    status_text.text(f"Processing {len(json_files)} trace files...")

    for jf in json_files:
        # Extraction du nom du scénario (ex: git-remote-https_000)
        folder_path = os.path.dirname(jf)
        scenario_name = os.path.basename(folder_path)
        socket_id = os.path.splitext(os.path.basename(jf))[0]

        try:
            with open(jf, "r") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        event = json.loads(line)

                        # Aplatissement des données pour le DataFrame
                        row = {
                            "scenario": scenario_name,
                            "socket_id": socket_id,
                            "timestamp": event.get("timestamp_usec", 0),
                            "type": event.get("type"),
                            "return_value": event.get("return_value"),
                            "errno": event.get("errno"),
                            "elapsed": event.get("elapsed_usec", 0),
                        }

                        # Extraction des détails spécifiques (args)
                        details = event.get("details", {})
                        if details:
                            # Protocole / Famille (souvent dans socket() ou accept())
                            if "sock_info" in details:
                                row["domain"] = details["sock_info"].get("domain")
                                row["protocol"] = details["sock_info"].get("type")

                            # Transfert de données
                            if "len" in details:
                                row["bytes"] = details["len"]

                            # Options de socket
                            if "optname" in details:
                                row["option"] = details["optname"]

                        records.append(row)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            continue

    status_text.empty()
    return pd.DataFrame(records)


# Chargement initial
df = load_dataset(default_path)

if df.empty:
    st.info(
        "No trace data found. Please select a valid directory containing trace subfolders."
    )
    st.stop()

# Nettoyage et typage
df["timestamp"] = pd.to_datetime(df["timestamp"], unit="us")
df["bytes"] = df["bytes"].fillna(0)

st.title("TCPSnitch Analysis Report")
st.markdown(
    f"**Dataset loaded:** {len(df)} system calls across {df['scenario'].nunique()} scenarios."
)
