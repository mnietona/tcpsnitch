# tabs/tab_global.py
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter
from plotly.subplots import make_subplots
from loaders import load_session, load_ebpf, load_netlink, load_meta
from config import PLOTLY_THEME, SEND_TYPES, RECV_TYPES, ASYNC_TYPES, CTRL_TYPES


@st.cache_data
def load_all_sessions(base_dir, sessions, platform_filter="ALL"):
    """Load all sessions and return unified DataFrames filtered by platform."""
    all_dfs = []
    all_ebpf = []
    all_netlink = []
    session_meta = []

    for session_path in sessions:
        import os
        session_name = os.path.basename(session_path)
        meta = load_meta(session_path)
        
        is_android = "android" in session_name.lower() or "android" in meta.get("os", "").lower()
        
        if platform_filter == "ANDROID" and not is_android:
            continue
        if platform_filter == "LINUX" and is_android:
            continue

        events = load_session(session_path)
        ebpf = load_ebpf(session_path)
        netlink = load_netlink(session_path)

        if events:
            temp_df = pd.DataFrame(events)
            is_fake = temp_df.get("fake_call", pd.Series(False, index=temp_df.index)).fillna(False).astype(bool)
            if "details" in temp_df.columns:
                is_fake = is_fake | temp_df["details"].apply(
                    lambda d: d.get("fake_call", False) if isinstance(d, dict) else False
                )
            temp_df = temp_df[~is_fake].copy()
            
            if "return_value" in temp_df.columns:
                temp_df["return_value"] = pd.to_numeric(temp_df["return_value"], errors="coerce").fillna(0)
            if "timestamp_usec" in temp_df.columns:
                temp_df["timestamp_usec"] = pd.to_numeric(temp_df["timestamp_usec"], errors="coerce")
            temp_df["_session"] = session_name
            temp_df["_app"] = meta.get("app", session_name)
            temp_df["_os"] = "Android" if is_android else "Linux"
            all_dfs.append(temp_df)

        if ebpf:
            df_e = pd.DataFrame(ebpf)
            df_e["_session"] = session_name
            all_ebpf.append(df_e)

        if netlink:
            df_n = pd.DataFrame(netlink)
            df_n["_session"] = session_name
            all_netlink.append(df_n)

        session_meta.append({
            "session": session_name,
            "app": meta.get("app", session_name),
            "os": "Android" if is_android else "Linux",
            "kernel": meta.get("kernel", ""),
            "n_events": len(events),
            "n_sockets": len(set(e.get("_socket_id", 0) for e in events)) if events else 0,
            "n_ebpf": len(ebpf),
            "n_netlink": len(netlink),
            "has_ebpf": len(ebpf) > 0,
            "has_netlink": len(netlink) > 0,
        })

    df_global = pd.concat(all_dfs, ignore_index=True) if all_dfs else pd.DataFrame()
    df_ebpf_all = pd.concat(all_ebpf, ignore_index=True) if all_ebpf else pd.DataFrame()
    df_nl_all = pd.concat(all_netlink, ignore_index=True) if all_netlink else pd.DataFrame()
    df_meta = pd.DataFrame(session_meta)

    return df_global, df_ebpf_all, df_nl_all, df_meta


def render(base_dir, sessions):
    st.markdown('<div class="section-header">Cross-Session Dataset Analysis</div>', unsafe_allow_html=True)

    platform_choice = st.radio(
        "Filter Dataset by Platform:",
        options=["All Platforms", "Android Only", "Linux Only"],
        horizontal=True,
        index=0
    )
    
    filter_val = "ALL"
    if platform_choice == "Android Only": filter_val = "ANDROID"
    elif platform_choice == "Linux Only": filter_val = "LINUX"

    with st.spinner(f"Aggregating {platform_choice.lower()} traces..."):
        df_global, df_ebpf_all, df_nl_all, df_meta = load_all_sessions(base_dir, sessions, filter_val)

    if df_global.empty:
        st.warning(f"No data found for the selected filter: {platform_choice}.")
        return

    theme = PLOTLY_THEME.copy()
    if "margin" in theme:
        del theme["margin"]

    total_sessions = len(df_meta)
    total_events = len(df_global)
    total_sockets = df_global.groupby(["_session", "_socket_id"]).ngroups
    total_ebpf = len(df_ebpf_all)
    total_netlink = len(df_nl_all)
    n_with_ebpf = df_meta["has_ebpf"].sum()
    n_with_netlink = df_meta["has_netlink"].sum()

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1: st.metric("Sessions", total_sessions)
    with c2: st.metric("LD_PRELOAD Events", f"{total_events:,}")
    with c3: st.metric("Sockets Tracked", f"{total_sockets:,}")
    with c4: st.metric("eBPF Events", f"{total_ebpf:,}", delta=f"{n_with_ebpf}/{total_sessions} sessions", delta_color="off")
    with c5: st.metric("Netlink Events", f"{total_netlink:,}", delta=f"{n_with_netlink}/{total_sessions} sessions", delta_color="off")

    st.divider()

    st.markdown('<div class="section-header">Session Registry</div>', unsafe_allow_html=True)
    display_meta = df_meta[["session", "app", "os", "kernel", "n_events", "n_sockets", "n_ebpf", "n_netlink"]].copy()
    display_meta.columns = ["Session", "Application", "OS", "Kernel", "API Events", "Sockets", "eBPF Events", "Netlink Events"]
    st.dataframe(display_meta.sort_values(by="API Events", ascending=False), use_container_width=True, hide_index=True)

    st.divider()

    st.markdown('<div class="section-header">Protocol Distribution</div>', unsafe_allow_html=True)

    def get_proto(row):
        d = row.get("details")
        if isinstance(d, dict) and "sock_info" in d:
            t = str(d["sock_info"].get("type", ""))
            if "STREAM" in t or t == "1": return "TCP (SOCK_STREAM)"
            if "DGRAM" in t or t == "2": return "UDP (SOCK_DGRAM)"
        return None

    proto_df = df_global[df_global["type"].isin(["socket", "forked_socket"])].copy()
    proto_df["Protocol"] = proto_df.apply(get_proto, axis=1)
    proto_df = proto_df.dropna(subset=["Protocol"])

    col_proto_pie, col_proto_bar = st.columns(2)

    with col_proto_pie:
        proto_counts = proto_df["Protocol"].value_counts()
        if not proto_counts.empty:
            fig_proto = go.Figure(go.Pie(
                labels=proto_counts.index.tolist(),
                values=proto_counts.values.tolist(),
                hole=0.4,
                marker_colors=["#58a6ff", "#3fb950", "#8b949e"],
                textinfo="label+percent+value",
                textfont_size=11,
            ))
            fig_proto.update_layout(**theme, height=320, margin=dict(l=20, r=20, t=20, b=20), showlegend=False)
            st.plotly_chart(fig_proto, use_container_width=True)

    with col_proto_bar:
        proto_per_session = proto_df.groupby(["_app", "Protocol"]).size().reset_index(name="count")
        if not proto_per_session.empty:
            fig_proto_bar = px.bar(
                proto_per_session, x="_app", y="count", color="Protocol",
                barmode="stack", color_discrete_map={"TCP (SOCK_STREAM)": "#58a6ff", "UDP (SOCK_DGRAM)": "#3fb950"},
            )
            fig_proto_bar.update_layout(
                **theme, height=320, margin=dict(l=40, r=20, t=20, b=80),
                xaxis_title="Application", yaxis_title="Socket Count", xaxis_tickangle=-45,
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
            )
            st.plotly_chart(fig_proto_bar, use_container_width=True)

    st.divider()

    st.markdown('<div class="section-header">System Call Frequency Ranking</div>', unsafe_allow_html=True)

    real_df = df_global.copy()
    if "fake_call" in real_df.columns:
        real_df = real_df[real_df["fake_call"] != True]
    elif "details" in real_df.columns:
        real_df["_is_fake"] = real_df["details"].apply(lambda d: d.get("fake_call", False) if isinstance(d, dict) else False)
        real_df = real_df[~real_df["_is_fake"]]

    syscall_counts = real_df["type"].value_counts().head(20).reset_index()
    syscall_counts.columns = ["System Call", "Count"]

    fig_calls = go.Figure(go.Bar(
        x=syscall_counts["Count"],
        y=syscall_counts["System Call"],
        orientation="h", marker_color="#d2a8ff",
        text=[f"{v:,}" for v in syscall_counts["Count"]], textposition="outside",
    ))
    fig_calls.update_layout(
        **theme, height=max(400, len(syscall_counts) * 28),
        margin=dict(l=120, r=60, t=20, b=40), xaxis_title="Total Calls",
    )
    fig_calls.update_yaxes(categoryorder="total ascending")
    st.plotly_chart(fig_calls, use_container_width=True)

    st.divider()

    st.markdown('<div class="section-header">Aggregated Data Transfer Volume</div>', unsafe_allow_html=True)

    df_io = real_df[(real_df["type"].isin(SEND_TYPES + RECV_TYPES)) & (real_df["return_value"] > 0)].copy()

    if not df_io.empty:
        df_io["Direction"] = df_io["type"].apply(lambda x: "TX" if x in SEND_TYPES else "RX")

        col_vol_bar, col_vol_per_app = st.columns(2)

        with col_vol_bar:
            vol_by_dir = df_io.groupby("Direction")["return_value"].sum().reset_index()
            vol_by_dir.columns = ["Direction", "Bytes"]
            fig_vol = go.Figure(go.Bar(
                x=vol_by_dir["Direction"], y=vol_by_dir["Bytes"],
                marker_color=["#58a6ff", "#3fb950"],
                text=[f"{v:,.0f} B" for v in vol_by_dir["Bytes"]], textposition="auto",
            ))
            fig_vol.update_layout(**theme, height=300, margin=dict(l=40, r=20, t=20, b=40), yaxis_title="Total Bytes",
                                  yaxis_type="log" if vol_by_dir["Bytes"].max() > 10 * vol_by_dir["Bytes"].min() else "linear")
            st.plotly_chart(fig_vol, use_container_width=True)

        with col_vol_per_app:
            vol_per_app = df_io.groupby(["_app", "Direction"])["return_value"].sum().reset_index()
            vol_per_app.columns = ["Application", "Direction", "Bytes"]
            fig_vol_app = px.bar(
                vol_per_app, x="Application", y="Bytes", color="Direction",
                barmode="group", log_y=True, color_discrete_map={"TX": "#58a6ff", "RX": "#3fb950"},
            )
            fig_vol_app.update_layout(**theme, height=300, margin=dict(l=40, r=20, t=20, b=80), xaxis_tickangle=-45,
                                      legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5))
            st.plotly_chart(fig_vol_app, use_container_width=True)

        st.markdown("#### CDF of Payload Sizes")
        fig_cdf = px.ecdf(
            df_io, x="return_value", color="Direction", log_x=True,
            labels={"return_value": "Payload Size (Bytes)"},
            color_discrete_map={"TX": "#58a6ff", "RX": "#3fb950"},
        )
        fig_cdf.add_vline(x=1448, line_dash="dot", line_color="gray", annotation_text="TCP MSS (1448B)", annotation_position="top left")
        fig_cdf.update_layout(**theme, height=400, margin=dict(l=40, r=20, t=20, b=40), yaxis_title="CDF",
                              xaxis_title="Payload Size (Bytes, Log Scale)", legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5))
        st.plotly_chart(fig_cdf, use_container_width=True)

    st.divider()

    st.markdown('<div class="section-header">Socket Lifecycle Patterns</div>', unsafe_allow_html=True)

    sock_behaviors = []
    for (session, sid), group in real_df.groupby(["_session", "_socket_id"]):
        types_used = set(group["type"].unique())
        has_connect = "connect" in types_used
        has_send = bool(types_used.intersection(set(SEND_TYPES)))
        has_recv = bool(types_used.intersection(set(RECV_TYPES)))
        has_data = has_send or has_recv

        if not has_connect and not has_data: behavior = "Config-only (no data, no connect)"
        elif has_connect and not has_data: behavior = "Connected but no data transfer"
        elif has_send and not has_recv: behavior = "TX-only (send without receive)"
        elif has_recv and not has_send: behavior = "RX-only (receive without send)"
        elif has_send and has_recv: behavior = "Bidirectional (send + receive)"
        else: behavior = "Other"

        sock_behaviors.append(behavior)

    if sock_behaviors:
        behavior_counts = Counter(sock_behaviors)
        fig_behavior = go.Figure(go.Pie(
            labels=list(behavior_counts.keys()), values=list(behavior_counts.values()), hole=0.4,
            marker_colors=["#8b949e", "#f0a04b", "#58a6ff", "#3fb950", "#d2a8ff", "#ff7b72"],
            textinfo="label+percent", textfont_size=10,
        ))
        fig_behavior.update_layout(**theme, height=380, margin=dict(l=20, r=20, t=20, b=20),
                                   showlegend=True, legend=dict(font=dict(size=10), bgcolor="rgba(22,27,34,0.8)"))
        st.plotly_chart(fig_behavior, use_container_width=True)