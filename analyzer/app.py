# app.py
import streamlit as st
import pandas as pd
from collections import Counter
import os

# --- Internal Imports ---
from config import PLOTLY_THEME, SEND_TYPES, RECV_TYPES, ASYNC_TYPES, CTRL_TYPES
from loaders import load_session, load_ebpf, load_netlink, load_meta, find_sessions
from tabs import tab_overview

st.set_page_config(page_title="Tcpsnitch", page_icon="🔬", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');
html, body, [class*="css"] { font-family: 'IBM Plex Sans', sans-serif; }
.main { background-color: #0d1117; }
.metric-card { background:#161b22;border:1px solid #30363d;border-radius:6px;padding:20px 24px;margin-bottom:12px; }
.metric-card .value { font-family:'IBM Plex Mono',monospace;font-size:2.2rem;font-weight:600;color:#58a6ff;line-height:1; }
.metric-card .label { font-size:0.78rem;color:#8b949e;margin-top:4px;text-transform:uppercase;letter-spacing:0.08em; }
.section-header { font-family:'IBM Plex Mono',monospace;font-size:0.7rem;color:#3fb950;text-transform:uppercase;letter-spacing:0.15em;border-bottom:1px solid #21262d;padding-bottom:8px;margin-bottom:16px;margin-top:8px; }
.event-tag { display:inline-block;padding:2px 8px;border-radius:3px;font-family:'IBM Plex Mono',monospace;font-size:0.72rem;margin:2px; }
.tag-tcp  { background:#0d4a6e;color:#79c0ff; }
.tag-ebpf { background:#3d1f6e;color:#d2a8ff; }
.tag-warn { background:#4a2d0d;color:#f0a04b; }
.tag-ok   { background:#0d3d20;color:#56d364; }
[data-testid="stSidebar"] { background-color:#0d1117 !important;border-right:1px solid #21262d; }
[data-testid="stSidebar"] .stSelectbox label,
[data-testid="stSidebar"] .stRadio label,
[data-testid="stSidebar"] p { color:#c9d1d9 !important; }
h1,h2,h3 { color:#e6edf3 !important; }
p,li { color:#c9d1d9; }
.stTabs [data-baseweb="tab"] { font-family:'IBM Plex Mono',monospace;font-size:0.8rem;color:#8b949e; }
.stTabs [aria-selected="true"] { color:#58a6ff !important; }
div[data-testid="metric-container"] { background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px; }
div[data-testid="metric-container"] label { color:#8b949e !important;font-size:0.75rem; }
div[data-testid="metric-container"] div[data-testid="stMetricValue"] { font-family:'IBM Plex Mono',monospace;color:#58a6ff !important; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ─────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔬 Tcpsnitch")
    st.markdown("<p style='color:#8b949e;font-size:0.78rem;'>Network Stack Analyzer</p>", unsafe_allow_html=True)
    st.divider()

    if "base_dir" not in st.session_state:
        st.session_state.base_dir = "/tmp/tcpsnitch_output"

    base_dir = st.text_input("Trace Directory", value=st.session_state.base_dir)
    st.session_state.base_dir = base_dir

    if st.button("Refresh", use_container_width=True):
        st.cache_data.clear()

    st.divider()
    sessions = find_sessions(base_dir)

    if not sessions:
        st.error("No traces found. Please check the directory path.")
        st.stop()

    session_labels = [os.path.basename(s) for s in sessions]
    selected_label = st.selectbox("Select Session", session_labels)
    selected_session = sessions[session_labels.index(selected_label)]
    st.divider()
    st.caption(f"Path: `{selected_session}`")

# ── Loading & Time Synchronization ───────────────────────────────────────────────
with st.spinner("Loading traces and synchronizing clocks..."):
    all_events  = load_session(selected_session)
    ebpf_events = load_ebpf(selected_session)
    netlink_events = load_netlink(selected_session) 
    meta_data = load_meta(selected_session)

df = pd.DataFrame(all_events) if all_events else pd.DataFrame()

# 1. Global T0 Discovery
t0_candidates = []
if not df.empty and "timestamp_usec" in df.columns:
    df["timestamp_usec"] = pd.to_numeric(df["timestamp_usec"], errors="coerce")
    t0_candidates.append(df["timestamp_usec"].min())
if ebpf_events:
    ebpf_min_ns = min(e.get("timestamp_ns", float('inf')) for e in ebpf_events if "timestamp_ns" in e)
    if ebpf_min_ns != float('inf'): t0_candidates.append(ebpf_min_ns / 1000.0)
if netlink_events:
    nl_min_us = min(e.get("timestamp_usec", float('inf')) for e in netlink_events if "timestamp_usec" in e)
    if nl_min_us != float('inf'): t0_candidates.append(nl_min_us)

global_t0_usec = min(t0_candidates) if t0_candidates else 0

# 2. CENTRAL SYNCHRONIZATION (Convert all to 't_ms' based on T0)
if not df.empty:
    df["t_ms"] = (df["timestamp_usec"] - global_t0_usec) / 1000.0

for ev in ebpf_events:
    if "timestamp_ns" in ev:
        ev["t_ms"] = ((ev["timestamp_ns"] / 1000.0) - global_t0_usec) / 1000.0

for ev in netlink_events:
    if "timestamp_usec" in ev:
        ev["t_ms"] = (ev["timestamp_usec"] - global_t0_usec) / 1000.0

type_counts = Counter(df["type"].tolist()) if not df.empty else Counter()
n_retrans = sum(1 for e in ebpf_events if e.get("type") == "tcp_retransmit")

# ── Dynamic Header ───────────────────────────────────────────────────────────
app_name = meta_data.get("app", "Unknown Application")
os_name = meta_data.get("os", "Unknown OS")
kernel_ver = meta_data.get("kernel", "")
header_title = f"Analysis of '{app_name}' on {os_name} {kernel_ver}"

st.markdown(f"""
<div style="border-bottom:1px solid #21262d;padding-bottom:16px;margin-bottom:24px;">
  <div style="font-family:'IBM Plex Mono',monospace;font-size:0.7rem;color:#3fb950;text-transform:uppercase;letter-spacing:0.1em;">
    tcpsnitch — Network Stack Observatory
  </div>
  <h1 style="margin:4px 0 0 0;font-size:1.6rem;">{header_title}</h1>
  <div style="margin-top:6px;">
    <span class="event-tag tag-tcp">LD_PRELOAD {len(all_events):,} events</span>
    <span class="event-tag tag-ebpf">eBPF {len(ebpf_events):,} events · {n_retrans} retransmits</span>
    <span class="event-tag tag-ok">Netlink {len(netlink_events):,} événements</span>
  </div>
</div>
""", unsafe_allow_html=True)

# ── Navigation (Tabs) ────────────────────────────────────────────────────────
tabs = st.tabs([
    "📊  Overview",
    "🔌  Sockets",
    "📤  Send & Receive",
    "📈  CWND & RTT",
    "🔄  Async I/O",
    "🧠  eBPF",
    "🌐  Netlink",
    "⚙️  Control Plane",
])

with tabs[0]:
    tab_overview.render(df, all_events, type_counts, n_retrans, meta_data)

with tabs[1]:
    st.info("Tab 1 (Sockets) logic under construction. File: tabs/tab_sockets.py")

with tabs[2]:
    st.info("Tab 2 (Send & Receive) logic under construction. File: tabs/tab_send_recv.py")

with tabs[3]:
    st.info("Tab 3 (CWND & RTT) logic under construction. File: tabs/tab_cwnd_rtt.py")

with tabs[4]:
    st.info("Tab 4 (Async I/O) logic under construction. File: tabs/tab_async.py")

with tabs[5]:
    st.info("Tab 5 (eBPF) logic under construction. File: tabs/tab_ebpf.py")

with tabs[6]:
    st.info("Tab 6 (Netlink) logic under construction. File: tabs/tab_netlink.py")

with tabs[7]:
    st.info("Tab 7 (Control Plane) logic under construction. File: tabs/tab_control.py")