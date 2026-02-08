import streamlit as st
import pandas as pd
import os
import json
import zipfile
import tarfile
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

# Sidebar for file upload
st.sidebar.title("Configuration")
st.sidebar.info("Upload your trace archive (zip, tar, tar.gz, tgz).")
# Accept multiple compression formats
uploaded_file = st.sidebar.file_uploader("Upload Dataset", type=["zip", "tar", "gz", "tgz"])

def process_single_trace(filename, content_str):
    """
    Parses a single JSON trace file content and returns a list of records.
    Helper function used by both ZIP and TAR extractors.
    """
    records = []
    # Logic to extract scenario name from path: "scenario_folder/X.json"
    parts = filename.strip("/").split("/")
    if len(parts) < 2:
        return []
        
    scenario_name = parts[-2]
    # Remove extension to get socket ID
    socket_id = os.path.splitext(parts[-1])[0]

    try:
        # NDJSON parsing (New Line Delimited JSON)
        for line in content_str.splitlines():
            if not line.strip(): continue
            try:
                event = json.loads(line)
                
                row = {
                    "scenario": scenario_name,
                    "socket_id": socket_id,
                    "timestamp": event.get("timestamp_usec", 0),
                    "type": event.get("type"),
                    "return_value": event.get("return_value"),
                    "errno": event.get("errno"),
                    "elapsed": event.get("elapsed_usec", 0)
                }

                # Extract details
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
        pass
        
    return records

@st.cache_data
def load_data_from_archive(file_obj):
    """
    Detects archive type (ZIP or TAR) and extracts traces.
    """
    all_records = []
    filename = file_obj.name.lower()
    
    try:
        # CAS 1 : ZIP FILE
        if filename.endswith(".zip"):
            with zipfile.ZipFile(file_obj) as z:
                for fname in z.namelist():
                    if fname.endswith(".json") and not fname.startswith("__MACOSX") and not os.path.basename(fname).startswith("._"):
                        with z.open(fname) as f:
                            content = f.read().decode('utf-8', errors='ignore')
                            all_records.extend(process_single_trace(fname, content))

        # CAS 2 : TAR FILE (supports .tar, .tar.gz, .tgz, .gz)
        elif filename.endswith((".tar", ".tar.gz", ".tgz", ".gz")):
            # mode="r:*" allows automatic transparency (detects gzip, bz2, or uncompressed)
            with tarfile.open(fileobj=file_obj, mode="r:*") as tar:
                for member in tar:
                    if member.isfile() and member.name.endswith(".json") and not os.path.basename(member.name).startswith("._"):
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode('utf-8', errors='ignore')
                            all_records.extend(process_single_trace(member.name, content))
                            
    except Exception as e:
        st.error(f"Error reading archive: {e}")
        return pd.DataFrame()

    return pd.DataFrame(all_records)

# Main Application Logic

if uploaded_file is not None:
    with st.spinner('Extracting and analyzing traces...'):
        df = load_data_from_archive(uploaded_file)

    if df.empty:
        st.warning("No valid JSON traces found in the archive.")
        st.stop()

    # Final Typing
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='us')
    if 'bytes' not in df.columns:
        df['bytes'] = 0
    else:
        df['bytes'] = df['bytes'].fillna(0)

    st.title("TCPSnitch Analysis Report")
    st.markdown(f"**Dataset loaded:** {len(df)} system calls across {df['scenario'].nunique()} scenarios.")
    
    # Debug preview
    with st.expander("Preview Raw Data"):
        st.dataframe(df.head())

else:
    st.title("Welcome to TCPSnitch Analytics Dashboard")
    st.markdown("""
    **Instructions:**
    1. Run your tests using TCPSnitch.
    2. Compress your result folder (containing scenario subfolders).
    3. Upload the archive here.
    
    **Supported Formats:** `.zip`, `.tar.gz`, `.tgz`, `.tar`
    """)