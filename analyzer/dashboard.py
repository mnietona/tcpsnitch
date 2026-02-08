import streamlit as st
import pandas as pd
import os
import json
import zipfile
import plotly.express as px

# Configuration de la page
st.set_page_config(page_title="TCPSnitch Analytics", layout="wide")

# CSS personnalisé
st.markdown("""
<style>
    .reportview-container { background: #f0f2f6 }
    h1 { color: #1f2937; font-family: 'Helvetica Neue', sans-serif; }
    h2 { color: #374151; font-family: 'Helvetica Neue', sans-serif; border-bottom: 1px solid #e5e7eb; padding-bottom: 10px; }
    .stMetric { background-color: #ffffff; padding: 15px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR : UPLOAD ---
st.sidebar.title("Configuration")
st.sidebar.info("Veuillez compresser votre dossier de résultats en .zip et l'uploader ici.")
uploaded_file = st.sidebar.file_uploader("Upload Dataset (.zip)", type="zip")

@st.cache_data
def load_data_from_zip(zip_file):
    """
    Lit le fichier ZIP en mémoire et extrait les traces JSON.
    Structure attendue dans le zip : Dossier_Scenario/X.json
    """
    records = []
    
    try:
        with zipfile.ZipFile(zip_file) as z:
            # On parcourt tous les fichiers contenus dans le ZIP
            for filename in z.namelist():
                # On ne traite que les fichiers .json et on ignore les fichiers cachés macOS
                if filename.endswith(".json") and not filename.startswith("__MACOSX") and not os.path.basename(filename).startswith("._"):
                    
                    # Logique pour trouver le nom du scénario basé sur le dossier parent dans le ZIP
                    # Ex: "mon_dossier/curl_google/3.json" -> scenario="curl_google", socket="3"
                    parts = filename.strip("/").split("/")
                    if len(parts) < 2:
                        continue
                        
                    scenario_name = parts[-2]
                    socket_id = os.path.splitext(parts[-1])[0]

                    try:
                        # Lecture du fichier directement depuis le ZIP (bytes -> string)
                        with z.open(filename) as f:
                            content = f.read().decode('utf-8')
                            
                            # Lecture ligne par ligne (Format NDJSON)
                            for line in content.splitlines():
                                if not line.strip(): continue
                                try:
                                    event = json.loads(line)
                                    
                                    # Aplatissement des données
                                    row = {
                                        "scenario": scenario_name,
                                        "socket_id": socket_id,
                                        "timestamp": event.get("timestamp_usec", 0),
                                        "type": event.get("type"),
                                        "return_value": event.get("return_value"),
                                        "errno": event.get("errno"),
                                        "elapsed": event.get("elapsed_usec", 0)
                                    }

                                    # Détails spécifiques
                                    details = event.get("details", {})
                                    if details:
                                        if "sock_info" in details:
                                            row["domain"] = details["sock_info"].get("domain")
                                            row["protocol"] = details["sock_info"].get("type")
                                        if "len" in details:
                                            row["bytes"] = details["len"]
                                        if "optname" in details:
                                            row["option"] = details["optname"]
                                            
                                    records.append(row)
                                except json.JSONDecodeError:
                                    continue
                    except Exception:
                        continue
    except Exception as e:
        st.error(f"Erreur lors de la lecture du ZIP : {e}")
        return pd.DataFrame()

    return pd.DataFrame(records)

# --- LOGIQUE PRINCIPALE ---

if uploaded_file is not None:
    with st.spinner('Extraction et analyse des données en cours...'):
        df = load_data_from_zip(uploaded_file)

    if df.empty:
        st.warning("Le fichier ZIP ne contient aucune trace JSON valide.")
        st.stop()

    # Nettoyage et typage final
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='us')
    if 'bytes' not in df.columns:
        df['bytes'] = 0
    else:
        df['bytes'] = df['bytes'].fillna(0)

    st.title("TCPSnitch Analysis Report")
    st.markdown(f"**Dataset chargé :** {len(df)} appels système détectés à travers {df['scenario'].nunique()} scénarios.")
    
    # Debug rapide pour vérifier que ça marche
    st.dataframe(df.head())

else:
    st.title("Bienvenue sur TCPSnitch Analytics ")
    st.markdown("""
    Cette application permet d'analyser les traces générées par l'outil TCPSnitch.
    
    **Instructions :**
    1. Exécutez vos tests avec TCPSnitch.
    2. Compressez le dossier contenant les résultats (les sous-dossiers de scénarios) en un fichier **.zip**.
    3. Uploadez le fichier ZIP dans la barre latérale à gauche.
    """)
