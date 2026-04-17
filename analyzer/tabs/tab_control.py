import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from collections import Counter
from config import PLOTLY_THEME, CTRL_TYPES


def render(df, meta_data):
    st.markdown('<div class="section-header">Control Plane & Socket Configuration Analysis</div>', unsafe_allow_html=True)

    st.markdown("""
    <p style="font-size:0.82rem;color:#8b949e;margin-bottom:16px;">
    Analysis of socket options, ioctl/fcntl commands, and configuration patterns.
    This tab examines how applications configure the TCP/IP stack.
    </p>
    """, unsafe_allow_html=True)

    if df.empty:
        st.info("No data available for control plane analysis.")
        return

    theme = PLOTLY_THEME.copy()
    if "margin" in theme:
        del theme["margin"]

    # Filter real events only
    real_df = df.copy()
    if "fake_call" in real_df.columns:
        real_df = real_df[real_df["fake_call"] != True]
    elif "details" in real_df.columns:
        real_df["_is_fake"] = real_df["details"].apply(
            lambda d: d.get("fake_call", False) if isinstance(d, dict) else False
        )
        real_df = real_df[~real_df["_is_fake"]]

    ctrl_df = real_df[real_df["type"].isin(CTRL_TYPES)].copy()

    # =====================================================================
    # SECTION 1: SOCKET OPTIONS (setsockopt / getsockopt)
    # =====================================================================
    st.markdown('<div class="section-header">Socket Options Usage</div>', unsafe_allow_html=True)

    sockopt_df = real_df[real_df["type"].isin(["setsockopt", "getsockopt"])].copy()

    if not sockopt_df.empty:
        # Extract option details
        def extract_sockopt(row):
            d = row.get("details", {})
            if not isinstance(d, dict):
                return pd.Series({"level": "UNKNOWN", "optname": "UNKNOWN", "optval": None})
            return pd.Series({
                "level": d.get("level", "UNKNOWN"),
                "optname": d.get("optname", "UNKNOWN"),
                "optval": d.get("optval", None),
            })

        opt_details = sockopt_df.apply(extract_sockopt, axis=1)
        sockopt_df = pd.concat([sockopt_df, opt_details], axis=1)
        sockopt_df = sockopt_df[sockopt_df["optname"] != "UNKNOWN"]

        # Metrics
        n_set = len(sockopt_df[sockopt_df["type"] == "setsockopt"])
        n_get = len(sockopt_df[sockopt_df["type"] == "getsockopt"])
        n_unique_opts = sockopt_df["optname"].nunique()
        n_levels = sockopt_df["level"].nunique()

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("setsockopt() Calls", f"{n_set:,}")
        with c2:
            st.metric("getsockopt() Calls", f"{n_get:,}")
        with c3:
            st.metric("Unique Options", f"{n_unique_opts}")
        with c4:
            st.metric("Option Levels", f"{n_levels}")

        st.divider()

        # --- 1a. Top Socket Options by Frequency ---
        col_opts, col_levels = st.columns(2)

        with col_opts:
            st.markdown("#### Most Used Socket Options")
            opt_freq = sockopt_df["optname"].value_counts().head(15).reset_index()
            opt_freq.columns = ["Option", "Count"]
            opt_freq = opt_freq.sort_values(by="Count", ascending=True)

            fig_opts = go.Figure(go.Bar(
                x=opt_freq["Count"],
                y=opt_freq["Option"],
                orientation="h",
                marker_color="#d2a8ff",
                text=[f"{v:,}" for v in opt_freq["Count"]],
                textposition="auto",
            ))
            fig_opts.update_layout(
                **theme, height=max(300, len(opt_freq) * 28),
                margin=dict(l=160, r=20, t=20, b=40),
                xaxis_title="Call Count",
            )
            st.plotly_chart(fig_opts, use_container_width=True)

        with col_levels:
            st.markdown("#### Option Level Distribution")
            level_counts = sockopt_df["level"].value_counts()
            fig_levels = go.Figure(go.Pie(
                labels=level_counts.index.tolist(),
                values=level_counts.values.tolist(),
                hole=0.4,
                marker_colors=["#58a6ff", "#3fb950", "#d2a8ff", "#f0a04b", "#ff7b72"],
                textinfo="label+percent",
                textfont_size=11,
            ))
            fig_levels.update_layout(
                **theme, height=350,
                margin=dict(l=20, r=20, t=20, b=20),
                showlegend=False,
            )
            st.plotly_chart(fig_levels, use_container_width=True)

        # --- 1b. Set vs Get Comparison (Grouped Bar Chart) ---
        st.markdown("#### setsockopt vs getsockopt per Option")
        st.markdown(
            "<p style='font-size:0.72rem;color:#8b949e;'>"
            "Options that are only set but never read may indicate fire-and-forget configuration. "
            "Options that are only read (getsockopt) are used for introspection (e.g., TCP_INFO).</p>",
            unsafe_allow_html=True,
        )

        pivot = sockopt_df.groupby(["optname", "type"]).size().reset_index(name="count")
        pivot_wide = pivot.pivot_table(index="optname", columns="type", values="count", fill_value=0)

        if not pivot_wide.empty:
            # Calculate total for sorting
            pivot_wide["_total"] = pivot_wide.sum(axis=1)
            pivot_wide = pivot_wide.sort_values(by="_total", ascending=True).drop(columns=["_total"])
            pivot_wide = pivot_wide.tail(20)  # Top 20 options

            # Prepare traces
            fig_compare = go.Figure()
            
            if "setsockopt" in pivot_wide.columns:
                fig_compare.add_trace(go.Bar(
                    y=pivot_wide.index,
                    x=pivot_wide["setsockopt"],
                    name="setsockopt (Write)",
                    orientation="h",
                    marker_color="#d2a8ff", # Purple for configuration
                    text=pivot_wide["setsockopt"].replace(0, ""), # Hide 0s
                    textposition="auto"
                ))
                
            if "getsockopt" in pivot_wide.columns:
                fig_compare.add_trace(go.Bar(
                    y=pivot_wide.index,
                    x=pivot_wide["getsockopt"],
                    name="getsockopt (Read)",
                    orientation="h",
                    marker_color="#58a6ff", # Blue for introspection
                    text=pivot_wide["getsockopt"].replace(0, ""), # Hide 0s
                    textposition="auto"
                ))

            fig_compare.update_layout(
                **theme, 
                height=max(350, len(pivot_wide) * 35),
                margin=dict(l=160, r=20, t=20, b=40),
                barmode='group', # Group bars side by side
                xaxis_title="Call Count",
                yaxis_title="",
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            
            # Optional: Use log scale if there's a huge discrepancy in counts (e.g., 10k gets vs 2 sets)
            max_val = pivot_wide.max().max()
            if max_val > 1000:
                 fig_compare.update_xaxes(type="log", title="Call Count (Log Scale)")
                 
            st.plotly_chart(fig_compare, use_container_width=True)
            
        # --- 1c. Per-Socket Option Patterns ---
        if "_socket_id" in sockopt_df.columns:
            st.markdown("#### Socket Option Configuration Patterns")
            st.markdown(
                "<p style='font-size:0.72rem;color:#8b949e;'>"
                "Options configured per socket. Sockets with many option calls indicate "
                "fine-tuned network configuration (common in high-performance applications).</p>",
                unsafe_allow_html=True,
            )

            per_sock_opts = sockopt_df.groupby("_socket_id")["optname"].apply(list).reset_index()
            per_sock_opts["n_opts"] = per_sock_opts["optname"].apply(len)
            per_sock_opts["unique_opts"] = per_sock_opts["optname"].apply(lambda x: len(set(x)))
            per_sock_opts = per_sock_opts.sort_values(by="n_opts", ascending=False).head(15)

            fig_patterns = go.Figure(go.Bar(
                x=[f"Socket {s}" for s in per_sock_opts["_socket_id"]],
                y=per_sock_opts["n_opts"],
                marker_color="#58a6ff",
                text=[f"{v} ({u} unique)" for v, u in zip(per_sock_opts["n_opts"], per_sock_opts["unique_opts"])],
                textposition="auto",
            ))
            fig_patterns.update_layout(
                **theme, height=300,
                margin=dict(l=40, r=20, t=20, b=40),
                xaxis_title="Socket", yaxis_title="Option Calls",
            )
            st.plotly_chart(fig_patterns, use_container_width=True)
    else:
        st.info("No setsockopt/getsockopt calls found in this trace.")

    # =====================================================================
    # SECTION 2: fcntl ANALYSIS
    # =====================================================================
    st.divider()
    st.markdown('<div class="section-header">fcntl() Command Analysis</div>', unsafe_allow_html=True)

    fcntl_df = real_df[real_df["type"] == "fcntl"].copy()

    if not fcntl_df.empty:
        def extract_fcntl_cmd(row):
            d = row.get("details", {})
            if isinstance(d, dict):
                return d.get("cmd", "UNKNOWN")
            return "UNKNOWN"

        fcntl_df["cmd"] = fcntl_df.apply(extract_fcntl_cmd, axis=1)

        cmd_counts = fcntl_df["cmd"].value_counts()

        col_fcntl_bar, col_fcntl_info = st.columns([2, 1])

        with col_fcntl_bar:
            fig_fcntl = go.Figure(go.Bar(
                x=cmd_counts.values.tolist(),
                y=cmd_counts.index.tolist(),
                orientation="h",
                marker_color="#f0a04b",
                text=[f"{v:,}" for v in cmd_counts.values],
                textposition="auto",
            ))
            fig_fcntl.update_layout(
                **theme, height=max(200, len(cmd_counts) * 35),
                margin=dict(l=140, r=20, t=20, b=40),
                xaxis_title="Call Count",
            )
            st.plotly_chart(fig_fcntl, use_container_width=True)

        with col_fcntl_info:
            st.metric("Total fcntl() Calls", f"{len(fcntl_df):,}")
            st.metric("Unique Commands", f"{fcntl_df['cmd'].nunique()}")

            # Check for non-blocking pattern
            n_nonblock = len(fcntl_df[fcntl_df["cmd"].str.contains("NONBLOCK", na=False)])
            if n_nonblock > 0:
                st.markdown(
                    f"<p style='font-size:0.78rem;color:#3fb950;'>"
                    f"Non-blocking mode set {n_nonblock} time(s) via F_SETFL/O_NONBLOCK.</p>",
                    unsafe_allow_html=True,
                )
    else:
        st.info("No fcntl() calls found in this trace.")

    # =====================================================================
    # SECTION 3: ioctl ANALYSIS
    # =====================================================================
    st.divider()
    st.markdown('<div class="section-header">ioctl() Request Analysis</div>', unsafe_allow_html=True)

    ioctl_df = real_df[real_df["type"] == "ioctl"].copy()

    if not ioctl_df.empty:
        def extract_ioctl_req(row):
            d = row.get("details", {})
            if isinstance(d, dict):
                return d.get("request", "UNKNOWN")
            return "UNKNOWN"

        ioctl_df["request"] = ioctl_df.apply(extract_ioctl_req, axis=1)

        req_counts = ioctl_df["request"].value_counts()

 #       st.markdown(
   #           "<p style='font-size:0.75rem;color:#8b949e;'>"
    #          "ioctl() calls on sockets are used for low-level interface queries. "
     #         "On Android, ioctl(SIOCGIFADDR) is commonly used to retrieve the IP address "
     #         "of an interface, as noted in the 2017 analysis.</p>",
    #          unsafe_allow_html=True,
    #      )

        col_ioctl, col_ioctl_stats = st.columns([2, 1])

        with col_ioctl:
            fig_ioctl = go.Figure(go.Bar(
                x=req_counts.values.tolist(),
                y=req_counts.index.tolist(),
                orientation="h",
                marker_color="#79c0ff",
                text=[f"{v:,}" for v in req_counts.values],
                textposition="auto",
            ))
            fig_ioctl.update_layout(
                **theme, height=max(200, len(req_counts) * 35),
                margin=dict(l=180, r=20, t=20, b=40),
                xaxis_title="Call Count",
            )
            st.plotly_chart(fig_ioctl, use_container_width=True)

        with col_ioctl_stats:
            st.metric("Total ioctl() Calls", f"{len(ioctl_df):,}")
            st.metric("Unique Requests", f"{ioctl_df['request'].nunique()}")
            error_rate = len(ioctl_df[ioctl_df["return_value"] < 0]) / len(ioctl_df) * 100 if len(ioctl_df) > 0 else 0
            st.metric("Error Rate", f"{error_rate:.1f}%")
    else:
        st.info("No ioctl() calls found in this trace.")

    # =====================================================================
    # SECTION 4: CONFIGURATION TIMELINE
    # =====================================================================
    st.divider()
    st.markdown('<div class="section-header">Control Plane Activity Timeline</div>', unsafe_allow_html=True)
    st.markdown(
        "<p style='font-size:0.75rem;color:#8b949e;'>"
        "Temporal distribution of control plane calls. Configuration calls clustered "
        "at trace start indicate socket setup phase. Calls during data transfer indicate "
        "dynamic reconfiguration.</p>",
        unsafe_allow_html=True,
    )

    if not ctrl_df.empty and "t_ms" in ctrl_df.columns:
        color_map = {
            "setsockopt": "#d2a8ff", "getsockopt": "#79c0ff",
            "fcntl": "#f0a04b", "ioctl": "#58a6ff",
        }

        fig_ctrl_timeline = go.Figure()
        for call_type in CTRL_TYPES:
            subset = ctrl_df[ctrl_df["type"] == call_type]
            if subset.empty:
                continue
            fig_ctrl_timeline.add_trace(go.Scatter(
                x=subset["t_ms"],
                y=subset["type"],
                mode="markers",
                name=call_type,
                marker=dict(
                    size=8,
                    color=color_map.get(call_type, "#8b949e"),
                    line=dict(width=0.5, color="#0d1117"),
                ),
                hovertemplate="<b>%{y}</b><br>Time: %{x:.2f} ms<extra></extra>",
            ))

        fig_ctrl_timeline.update_layout(
            **theme, height=250,
            margin=dict(l=100, r=20, t=20, b=40),
            xaxis_title="Time (ms, relative to trace start)",
            showlegend=False,
        )
        st.plotly_chart(fig_ctrl_timeline, use_container_width=True)
    else:
        st.info("No control plane events with timing data.")

    # =====================================================================
    # SECTION 5: ERROR ANALYSIS
    # =====================================================================
    ctrl_errors = ctrl_df[ctrl_df["return_value"] < 0].copy() if not ctrl_df.empty else pd.DataFrame()

    if not ctrl_errors.empty:
        st.divider()
        st.markdown('<div class="section-header">Control Plane Errors</div>', unsafe_allow_html=True)

        if "errno" not in ctrl_errors.columns and "details" in ctrl_errors.columns:
            ctrl_errors["errno"] = ctrl_errors["details"].apply(
                lambda d: d.get("errno", "UNKNOWN") if isinstance(d, dict) else "UNKNOWN"
            )

        if "errno" in ctrl_errors.columns:
            err_counts = ctrl_errors.groupby(["type", "errno"]).size().reset_index(name="count")
            err_counts = err_counts.sort_values(by="count", ascending=False)

            st.dataframe(err_counts, use_container_width=True, hide_index=True)

    # --- Raw Data ---
    with st.expander("View Raw Control Plane Events"):
        if not ctrl_df.empty:
            display_cols = ["t_ms", "type", "return_value", "_socket_id", "details"]
            display_cols = [c for c in display_cols if c in ctrl_df.columns]
            st.dataframe(ctrl_df[display_cols].head(500), use_container_width=True, hide_index=True)
        else:
            st.info("No control plane events.")
