import streamlit as st
import pandas as pd
import os
import json
import zipfile
import tarfile
import plotly.express as px

# Configuration de la page
st.set_page_config(page_title="TCPSnitch Analytics", layout="wide")


# Sidebar for file upload
st.sidebar.title("Configuration")
st.sidebar.info("Upload your trace archive (zip, tar, tar.gz, tgz).")
# Accept multiple compression formats
uploaded_file = st.sidebar.file_uploader(
    "Upload Dataset", type=["zip", "tar", "gz", "tgz"]
)


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
            if not line.strip():
                continue
            try:
                event = json.loads(line)

                row = {
                    "scenario": scenario_name,
                    "socket_id": socket_id,
                    "timestamp": event.get("timestamp_usec", 0),
                    "type": event.get("type"),
                    "return_value": event.get("return_value"),
                    "errno": event.get("errno"),
                    "elapsed": event.get("elapsed_usec", 0),
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
                    if (
                        fname.endswith(".json")
                        and not fname.startswith("__MACOSX")
                        and not os.path.basename(fname).startswith("._")
                    ):
                        with z.open(fname) as f:
                            content = f.read().decode("utf-8", errors="ignore")
                            all_records.extend(process_single_trace(fname, content))

        # CAS 2 : TAR FILE (supports .tar, .tar.gz, .tgz, .gz)
        elif filename.endswith((".tar", ".tar.gz", ".tgz", ".gz")):
            # mode="r:*" allows automatic transparency (detects gzip, bz2, or uncompressed)
            with tarfile.open(fileobj=file_obj, mode="r:*") as tar:
                for member in tar:
                    if (
                        member.isfile()
                        and member.name.endswith(".json")
                        and not os.path.basename(member.name).startswith("._")
                    ):
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


# Main Application Logic

if uploaded_file is not None:
    # 1. Extract and Load Data
    with st.spinner("Processing uploaded archive..."):
        df = load_data_from_archive(uploaded_file)

    if df.empty:
        st.error(
            "No valid traces found. Please ensure your archive contains .json files in subfolders."
        )
        st.stop()

    # 2. Data Cleaning
    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="us")
    if "bytes" not in df.columns:
        df["bytes"] = 0
    else:
        df["bytes"] = df["bytes"].fillna(0)

    # 3. Dataset Title and Info
    st.title("TCPSnitch Analytics Report")
    st.markdown(
        f"**Dataset loaded:** {len(df):,} system calls across {df['scenario'].nunique()} scenarios."
    )

    # 4. Tabs for different analysis sections
    tab1, tab2, tab3 = st.tabs(
        ["Global Overview", "Connection Inspector", "Advanced Analysis"]
    )

    # Tab 1: Global Overview with KPIs and Distribution Graphs
    with tab1:
        st.header("Executive Summary")

        # A. Key Performance Indicators (KPIs)
        # Using 4 columns to display important figures
        kpi1, kpi2, kpi3, kpi4 = st.columns(4)

        total_calls = len(df)
        # Count unique pairs (Scenario + SocketID) to get the true number of connections
        total_sockets = df.groupby(["scenario", "socket_id"]).ngroups
        total_data_mb = df["bytes"].sum() / (1024 * 1024)
        avg_calls = total_calls / total_sockets if total_sockets > 0 else 0

        kpi1.metric("Total System Calls", f"{total_calls:,}")
        kpi2.metric("Total Connections", f"{total_sockets:,}")
        kpi3.metric("Data Volume", f"{total_data_mb:.2f} MB")
        kpi4.metric("Avg Calls / Socket", f"{avg_calls:.0f}")

        st.markdown("---")

        # B. Distribution Graphs
        col_g1, col_g2 = st.columns(2)

        with col_g1:
            st.subheader("System Call Distribution")
            # Count by call type (send, recv, connect, etc.)
            call_counts = df["type"].value_counts().reset_index()
            call_counts.columns = ["Call Type", "Count"]

            # Group "small" calls to avoid cluttering the pie chart
            if len(call_counts) > 10:
                top_calls = call_counts.head(9)
                other_count = call_counts.iloc[9:]["Count"].sum()
                other_row = pd.DataFrame(
                    {"Call Type": ["Other"], "Count": [other_count]}
                )
                call_counts = pd.concat([top_calls, other_row])

            # Pie Chart with Plotly Express
            fig_pie = px.pie(
                call_counts,
                values="Count",
                names="Call Type",
                hole=0.4,
                color_discrete_sequence=px.colors.qualitative.Prism,
            )
            fig_pie.update_traces(textposition="inside", textinfo="percent+label")
            fig_pie.update_layout(margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig_pie, use_container_width=True)

        with col_g2:
            st.subheader("Top Scenarios (Data Volume)")
            # Which scenarios consumed the most bandwidth?
            scenario_vol = (
                df.groupby("scenario")["bytes"]
                .sum()
                .sort_values(ascending=False)
                .head(10)
                .reset_index()
            )
            scenario_vol["MB"] = scenario_vol["bytes"] / (1024 * 1024)

            # Horizontal Bar Chart with Plotly Express
            fig_bar = px.bar(
                scenario_vol,
                x="MB",
                y="scenario",
                orientation="h",
                text_auto=".2f",
                labels={"MB": "Volume (MB)", "scenario": "Scenario"},
                color="MB",
                color_continuous_scale="Blues",
            )
            # Reverse the Y-axis to have the largest on top
            fig_bar.update_layout(
                yaxis={"categoryorder": "total ascending"},
                margin=dict(t=0, b=0, l=0, r=0),
            )
            st.plotly_chart(fig_bar, use_container_width=True)

    #
    with tab2:
        st.info("Connection Inspector : Coming in next update...")

    with tab3:
        st.info("Advanced Analysis : Coming in next update...")

else:
    st.title("Welcome to TCPSnitch Analytics Dashboard")
    st.markdown("""
    **Instructions:**
    1. Run your tests using TCPSnitch.
    2. Compress your result folder (containing scenario subfolders).
    3. Upload the archive here.
    
    **Supported Formats:** `.zip`, `.tar.gz`, `.tgz`, `.tar`
    """)
