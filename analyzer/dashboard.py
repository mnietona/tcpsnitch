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
# 1. PARSING & NORMALIZATION
# -----------------------------------------------------------------------------


def process_single_trace(filename, content_str):
    """
    Parses a single JSON trace file content and returns a list of records.
    """
    records = []
    parts = filename.strip("/").split("/")

    # Extract context from filename (Scenario / Socket ID)
    scenario_name = parts[-2] if len(parts) > 1 else "Unknown"
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
                    "type": event.get("type", "unknown"),
                    "return_value": event.get("return_value"),
                    "errno": event.get("errno"),
                    "elapsed": event.get("elapsed_usec", 0),
                }

                # Error Handling Logic
                err = row["errno"]
                row["success"] = (err is None) or (err == 0) or (err == "0")

                # Extract nested details if available
                details = event.get("details", {})

                # IO Category & Bytes Logic
                call_type = row["type"]
                row["io_category"] = "Other"

                if call_type in ["read", "recv", "recvfrom", "recvmsg"]:
                    row["io_category"] = "RX (Download)"
                elif call_type in ["write", "send", "sendto", "sendmsg"]:
                    row["io_category"] = "TX (Upload)"

                # Determine effective bytes
                bytes_val = details.get("len", 0)
                if (
                    row["success"]
                    and isinstance(row["return_value"], int)
                    and row["return_value"] > 0
                ):
                    # For I/O functions, return value is often the bytes transferred
                    if row["io_category"] != "Other":
                        row["bytes"] = row["return_value"]
                    else:
                        row["bytes"] = bytes_val
                else:
                    row["bytes"] = bytes_val

                # Extract Socket Info if available
                if "sock_info" in details:
                    row["domain"] = details["sock_info"].get("domain")
                    row["protocol"] = details["sock_info"].get("type")
                if "optname" in details:
                    row["option"] = details["optname"]

                records.append(row)
            except json.JSONDecodeError:
                continue
    except Exception:
        pass

    return records


# -----------------------------------------------------------------------------
# 2. DATA LOADING (ARCHIVE HANDLING)
# -----------------------------------------------------------------------------


@st.cache_data
def load_data_from_archive(file_obj):
    """
    Detects archive type (ZIP or TAR) and extracts traces into a DataFrame.
    """
    all_records = []
    metadata = {}  # Store keys as filenames (e.g., 'cmd', 'kernel', 'args')
    filename = file_obj.name.lower()

    try:
        # Handle ZIP files
        if filename.endswith(".zip"):
            with zipfile.ZipFile(file_obj) as z:
                for fname in z.namelist():
                    # Read Traces
                    if fname.endswith(".json") and not fname.startswith("__MACOSX"):
                        with z.open(fname) as f:
                            content = f.read().decode("utf-8", errors="ignore")
                            all_records.extend(process_single_trace(fname, content))

                    # Read Metadata (files in meta/ or specific names)
                    # We store them using the filename as the key
                    elif (
                        os.path.basename(fname)
                        in ["args", "cmd", "command", "kernel_release", "uname"]
                        or "meta/" in fname
                    ):
                        try:
                            if not fname.endswith("/"):  # Ignore folders
                                with z.open(fname) as f:
                                    content = (
                                        f.read()
                                        .decode("utf-8", errors="ignore")
                                        .strip()
                                    )
                                    key_name = os.path.basename(fname)
                                    metadata[key_name] = content
                        except:
                            pass

        # Handle TAR files
        elif filename.endswith((".tar", ".tar.gz", ".tgz", ".gz")):
            with tarfile.open(fileobj=file_obj, mode="r:*") as tar:
                for member in tar:
                    if member.isfile():
                        # Read Traces
                        if member.name.endswith(".json"):
                            f = tar.extractfile(member)
                            if f:
                                content = f.read().decode("utf-8", errors="ignore")
                                all_records.extend(
                                    process_single_trace(member.name, content)
                                )

                        # Read Metadata
                        elif (
                            os.path.basename(member.name)
                            in ["args", "cmd", "command", "kernel_release", "uname"]
                            or "meta/" in member.name
                        ):
                            f = tar.extractfile(member)
                            if f:
                                content = (
                                    f.read().decode("utf-8", errors="ignore").strip()
                                )
                                key_name = os.path.basename(member.name)
                                metadata[key_name] = content

    except Exception as e:
        st.error(f"Error reading archive: {e}")
        return pd.DataFrame(), metadata

    return pd.DataFrame(all_records), metadata


def preprocess_data(df):
    """
    Enriches the DataFrame with necessary columns for analysis.
    """
    if df.empty:
        return df

    # Convert timestamp
    df["dt_timestamp"] = pd.to_datetime(df["timestamp"], unit="us")

    # Relative time (Start = 0s)
    start_time = df["timestamp"].min()
    df["rel_time"] = (df["timestamp"] - start_time) / 1_000_000.0

    return df


# -----------------------------------------------------------------------------
# 3. UI RENDERING
# -----------------------------------------------------------------------------


def render_overview(df, metadata):
    """
    Displays the Global Overview: Command line, KPIs, and Charts.
    """
    st.subheader("Overview")

    # 1. Command Line Display (Dynamic Priority)
    # We look for 'cmd', then 'args', then 'command'
    cmd_text = (
        metadata.get("cmd")
        or metadata.get("args")
        or metadata.get("command")
        or "Unknown command"
    )

    st.caption("Test Command Executed:")
    st.code(cmd_text, language="bash")

    # Optional: Display Kernel if available (to verify it's not mixed up)
    if "kernel_release" in metadata or "uname" in metadata:
        kernel = metadata.get("kernel_release") or metadata.get("uname")
        st.caption(f"Kernel: {kernel}")

    st.markdown("---")

    # 2. KPIs
    duration = df["rel_time"].max()
    total_calls = len(df)

    # Filter for real blocking errors (exclude EAGAIN/Wait)
    errors = df[~df["success"]]
    non_blocking = ["EAGAIN", "EWOULDBLOCK", "EINPROGRESS"]

    real_errors_count = 0
    if not errors.empty:
        # Convert errno to string to safely compare with the list
        real_errors_count = errors[
            ~errors["errno"].astype(str).isin(non_blocking)
        ].shape[0]

    vol_mb = df["bytes"].sum() / (1024 * 1024)

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Trace Duration", f"{duration:.2f} s")
    k2.metric("System Calls", f"{total_calls:,}")
    k3.metric("Blocking Errors", real_errors_count, delta_color="inverse")
    k4.metric("Total I/O Volume", f"{vol_mb:.2f} MB")

    st.markdown("---")

    # 3. Charts Section (Same as before)
    st.subheader("System Call Analysis")
    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.markdown("**Distribution by Call Type**")
        call_counts = df["type"].value_counts().reset_index()
        call_counts.columns = ["Call Type", "Count"]

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

    with col_chart2:
        st.markdown("**Function Usage (Success vs Error)**")

        usage_df = df.groupby(["type", "success"]).size().reset_index(name="count")
        usage_df["status"] = usage_df["success"].map(
            {True: "Success", False: "Error/Wait"}
        )

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
# 4. MAIN APPLICATION LOGIC
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
        raw_df, metadata = load_data_from_archive(uploaded_file)

    if raw_df.empty:
        st.error(
            "No valid traces found. Please ensure your archive contains .json files."
        )
        st.stop()

    # 2. Preprocess
    df = preprocess_data(raw_df)

    # 3. Header
    st.title("TCPSnitch Analytics Report")
    st.markdown(
        f"**Dataset loaded:** {len(df):,} system calls across {df['scenario'].nunique()} scenarios."
    )

    # 4. Tabs
    tab1, tab2 = st.tabs(["Global Overview", "Coming Soon"])

    with tab1:
        render_overview(df, metadata)

    with tab2:
        st.info("...?")

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
