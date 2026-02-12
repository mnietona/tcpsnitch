import streamlit as st
import pandas as pd
import os
import json
import zipfile
import tarfile
import plotly.express as px

# Page configuration
st.set_page_config(page_title="TCPSnitch Analytics", layout="wide")

# -----------------------------------------------------------------------------
# 1. DATA LOADING & PARSING FUNCTIONS
# -----------------------------------------------------------------------------


def process_single_trace(filename, content_str):
    """
    Parses a single JSON trace file content and returns a list of records.
    """
    records = []
    parts = filename.strip("/").split("/")
    if len(parts) < 2:
        return []

    scenario_name = parts[-2]
    socket_id = os.path.splitext(parts[-1])[0]

    try:
        # Parse NDJSON (New Line Delimited JSON)
        for line in content_str.splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)

                # Basic fields
                row = {
                    "scenario": scenario_name,
                    "socket_id": socket_id,
                    "timestamp": event.get("timestamp_usec", 0),
                    "type": event.get("type"),
                    "return_value": event.get("return_value"),
                    "errno": event.get("errno"),  # Can be None, int, or string code
                    "elapsed": event.get("elapsed_usec", 0),
                }

                # Extract nested details if available
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
    Detects archive type (ZIP or TAR) and extracts traces into a DataFrame.
    """
    all_records = []
    filename = file_obj.name.lower()

    try:
        # Handle ZIP files
        if filename.endswith(".zip"):
            with zipfile.ZipFile(file_obj) as z:
                for fname in z.namelist():
                    if fname.endswith(".json") and not fname.startswith("__MACOSX"):
                        with z.open(fname) as f:
                            content = f.read().decode("utf-8", errors="ignore")
                            all_records.extend(process_single_trace(fname, content))

        # Handle TAR files (including .gz, .tgz)
        elif filename.endswith((".tar", ".tar.gz", ".tgz", ".gz")):
            with tarfile.open(fileobj=file_obj, mode="r:*") as tar:
                for member in tar:
                    if member.isfile() and member.name.endswith(".json"):
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode("utf-8", errors="ignore")
                            all_records.extend(
                                process_single_trace(member.name, content)
                            )

    except Exception as e:
        st.error(f"Error reading archive: {e}")
        return pd.DataFrame()

    return pd.DataFrame(all_records)


def preprocess_data(df):
    """
    Enriches the DataFrame with necessary columns for analysis.
    """
    if df.empty:
        return df

    # Convert timestamp to datetime objects
    df["dt_timestamp"] = pd.to_datetime(df["timestamp"], unit="us")

    # Calculate relative time in seconds (for trace duration)
    start_time = df["timestamp"].min()
    df["rel_time"] = (df["timestamp"] - start_time) / 1_000_000.0

    # Ensure bytes column exists and is numeric
    if "bytes" not in df.columns:
        df["bytes"] = 0
    else:
        df["bytes"] = df["bytes"].fillna(0)

    # Determine success status
    # If errno is None or 0, it is a success. Otherwise, it is an error.
    df["success"] = df["errno"].isna() | (df["errno"] == 0) | (df["errno"] == "0")

    return df


# -----------------------------------------------------------------------------
# 2. UI RENDERING FUNCTIONS
# -----------------------------------------------------------------------------


def render_overview(df):
    """
    Displays the Global Overview tab with KPIs and Charts.
    """
    st.subheader("Overview")

    # --- KPI Section ---
    duration = df["rel_time"].max()
    total_calls = len(df)

    # Filter for real errors (excluding non-blocking waits)
    errors = df[~df["success"]]
    # Assuming errno contains strings like 'EAGAIN'. If pure ints, adjust logic.
    non_blocking_codes = ["EAGAIN", "EWOULDBLOCK", "EINPROGRESS"]
    real_errors_count = errors[~errors["errno"].isin(non_blocking_codes)].shape[0]

    # Calculate volume
    vol_mb = df["bytes"].sum() / (1024 * 1024)

    # Display Metrics
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Trace Duration", f"{duration:.2f} s")
    k2.metric("System Calls", f"{total_calls:,}")
    k3.metric("Blocking Errors", real_errors_count, delta_color="inverse")
    k4.metric("Total I/O Volume", f"{vol_mb:.2f} MB")

    st.markdown("---")

    # --- Charts Section ---
    st.subheader("System Call Analysis")
    col_chart1, col_chart2 = st.columns(2)

    # Chart 1: Pie Chart (Global Distribution)
    with col_chart1:
        st.markdown("**Distribution by Call Type**")
        call_counts = df["type"].value_counts().reset_index()
        call_counts.columns = ["Call Type", "Count"]

        # Aggregate small values to 'Other' for cleaner visualization
        if len(call_counts) > 10:
            top_calls = call_counts.head(9)
            other_count = call_counts.iloc[9:]["Count"].sum()
            other_row = pd.DataFrame({"Call Type": ["Other"], "Count": [other_count]})
            call_counts = pd.concat([top_calls, other_row])

        fig_pie = px.pie(
            call_counts,
            values="Count",
            names="Call Type",
            hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Prism,
        )
        fig_pie.update_traces(textposition="inside", textinfo="percent+label")
        fig_pie.update_layout(margin=dict(t=20, b=20, l=20, r=20))
        st.plotly_chart(fig_pie, use_container_width=True)

    # Chart 2: Bar Chart (Function Usage & Success Rate)
    with col_chart2:
        st.markdown("**Function Usage (Success vs Error)**")

        # Group by type and success status
        usage_df = df.groupby(["type", "success"]).size().reset_index(name="count")
        usage_df["status"] = usage_df["success"].map(
            {True: "Success", False: "Error/Wait"}
        )

        # Sort order based on frequency
        order = df["type"].value_counts().index.tolist()

        fig_bar = px.bar(
            usage_df,
            x="count",
            y="type",
            color="status",
            orientation="h",
            labels={"count": "Count", "type": "Function"},
            color_discrete_map={"Success": "#00cc96", "Error/Wait": "#ef553b"},
            category_orders={"type": order},
        )
        fig_bar.update_layout(margin=dict(t=20, b=20, l=20, r=20))
        st.plotly_chart(fig_bar, use_container_width=True)


# -----------------------------------------------------------------------------
# 3. MAIN APPLICATION LOGIC
# -----------------------------------------------------------------------------

# Sidebar
st.sidebar.title("Configuration")
st.sidebar.info("Upload your trace archive (zip, tar, tar.gz, tgz).")
uploaded_file = st.sidebar.file_uploader(
    "Upload Dataset", type=["zip", "tar", "gz", "tgz"]
)

if uploaded_file is not None:
    # 1. Load Data
    with st.spinner("Processing uploaded archive..."):
        raw_df = load_data_from_archive(uploaded_file)

    if raw_df.empty:
        st.error(
            "No valid traces found. Please ensure your archive contains .json files."
        )
        st.stop()

    # 2. Preprocess Data (Enrichment)
    df = preprocess_data(raw_df)

    # 3. Header
    st.title("TCPSnitch Analytics Report")
    st.markdown(
        f"**Dataset loaded:** {len(df):,} system calls across {df['scenario'].nunique()} scenarios."
    )

    # 4. Tabs
    tab1, tab2, tab3 = st.tabs(
        ["Global Overview", "Connection Inspector", "Advanced Analysis"]
    )

    with tab1:
        render_overview(df)

    with tab2:
        st.info("Autre.")

    with tab3:
        st.info("Autre.")

else:
    # Welcome Screen
    st.title("Welcome to TCPSnitch Analytics Dashboard")
    st.markdown("""
    **Instructions:**
    1. Run your tests using TCPSnitch.
    2. Compress your result folder (containing scenario subfolders).
    3. Upload the archive here.
    
    **Supported Formats:** `.zip`, `.tar.gz`, `.tgz`, `.tar`
    """)
