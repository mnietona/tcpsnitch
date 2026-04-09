import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from collections import Counter
import numpy as np

from config import PLOTLY_THEME, SEND_TYPES, RECV_TYPES


def render(df, all_events, type_counts_raw, n_retrans, meta_data):
    st.markdown('<div class="section-header">Overview</div>', unsafe_allow_html=True)

    if df.empty:
        st.warning("No data available.")
        return

    df["is_fake"] = df["details"].apply(
        lambda d: d.get("fake_call", False) if isinstance(d, dict) else False
    )
    df["errno"] = df["details"].apply(
        lambda d: d.get("errno", None) if isinstance(d, dict) else None
    )

    real_df = df[~df["is_fake"]].copy()
    type_counts = Counter(real_df["type"].tolist())

    n_sockets = type_counts.get("socket", 0) + type_counts.get("forked_socket", 0)

    tcp_count = udp_count = other_count = 0
    if not real_df.empty and "type" in real_df.columns:
        sock_events = real_df[real_df["type"].isin(["socket", "forked_socket"])]
        for _, row in sock_events.iterrows():
            d = row.get("details", {})
            if isinstance(d, dict) and "sock_info" in d:
                sock_type = d["sock_info"].get("type", "")
                if sock_type == "SOCK_STREAM":
                    tcp_count += 1
                elif sock_type == "SOCK_DGRAM":
                    udp_count += 1
                else:
                    other_count += 1

    def get_req_size(row):
        """
        Cherche la taille du buffer dans les champs du JSON tcpsnitch,
        en priorité dans 'details', puis en fallback sur 'return_value'.
        """
        d = row.get("details", {})
        if isinstance(d, dict):
            for key in ["len", "size", "count", "buflen", "bytes"]:
                if key in d and isinstance(d[key], (int, float)):
                    return d[key]
        val = row.get("return_value", 0)
        return val if val and val > 0 else 0

    bytes_sent = 0
    bytes_recv = 0

    if not real_df.empty:
        send_df = real_df[real_df["type"].isin(SEND_TYPES)].copy()
        recv_df = real_df[real_df["type"].isin(RECV_TYPES)].copy()

        if not send_df.empty:
            send_df["req_size"] = send_df.apply(get_req_size, axis=1)
            bytes_sent = int(send_df["req_size"].sum())

        if not recv_df.empty:
            recv_df["req_size"] = recv_df.apply(get_req_size, axis=1)
            bytes_recv = int(recv_df["req_size"].sum())

    async_errnos = {"EAGAIN", "EWOULDBLOCK", "EINPROGRESS"}
    n_errors = len(
        real_df[
            (real_df["return_value"] < 0)
            & (~real_df["errno"].isin(async_errnos))
        ]
    )

    def format_bytes(size):
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"

    duration_sec = (
        (real_df["t_ms"].max() - real_df["t_ms"].min()) / 1000
        if not real_df.empty
        else 0.0
    )

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1: st.metric("Total duration (sec)", f"{duration_sec:.2f}")
    with c2: st.metric("Total sockets created", f"{n_sockets:,}")
    with c3: st.metric("Total bytes received", format_bytes(bytes_recv))
    with c4: st.metric("Total bytes sent", format_bytes(bytes_sent))
    with c5: st.metric("eBPF Retransmits", f"{n_retrans:,}")
    with c6: st.metric("Syscall Errors", n_errors)

    st.divider()

    col_pie, col_bar = st.columns([1, 1.5])

    with col_pie:
        st.markdown('<div class="section-header">Connections created by type</div>',
                    unsafe_allow_html=True)
        pie_labels, pie_values = [], []
        if tcp_count   > 0: pie_labels.append("SOCK_STREAM (TCP)");       pie_values.append(tcp_count)
        if udp_count   > 0: pie_labels.append("SOCK_DGRAM (UDP/QUIC)");   pie_values.append(udp_count)
        if other_count > 0: pie_labels.append("Other");                    pie_values.append(other_count)

        if pie_values:
            fig_pie = go.Figure(go.Pie(
                labels=pie_labels,
                values=pie_values,
                hole=0.4,
                marker_colors=["#58a6ff", "#3fb950", "#8b949e"],
                textinfo="label+percent",
                textfont_size=12,
            ))
            fig_pie.update_layout(
                **PLOTLY_THEME,
                height=350,
                showlegend=False,
                margin=dict(l=20, r=20, t=20, b=20),
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("No sockets created in this trace.")

    with col_bar:
        st.markdown('<div class="section-header">Interception functions used</div>',
                    unsafe_allow_html=True)
        if type_counts:
            sorted_calls  = sorted(type_counts.items(), key=lambda x: x[1])
            total_calls   = sum(type_counts.values())
            threshold     = 0.005 * total_calls
            filtered_calls, others = [], 0

            for k, v in sorted_calls:
                if v < threshold:
                    others += v
                else:
                    filtered_calls.append((k, v))

            if others > 0:
                filtered_calls.insert(0, ("other_micro_calls", others))

            fig_bar = go.Figure(go.Bar(
                x=[v for _, v in filtered_calls],
                y=[k for k, _ in filtered_calls],
                orientation="h",
                marker_color="#d2a8ff",
                text=[f" {v:,}" for _, v in filtered_calls],
                textposition="outside",
            ))
            theme_bar = {**PLOTLY_THEME, "margin": dict(l=100, r=40, t=20, b=20)}
            fig_bar.update_layout(**theme_bar, height=350)
            st.plotly_chart(fig_bar, use_container_width=True)

    st.divider()

    st.markdown('<div class="section-header">Data Volume (Bytes)</div>',
                unsafe_allow_html=True)

    if bytes_sent > 0 or bytes_recv > 0:
        max_val = max(bytes_sent, bytes_recv)
        if max_val > 1024 ** 2:
            unit, divisor = "MB", 1024 ** 2
        elif max_val > 1024:
            unit, divisor = "KB", 1024
        else:
            unit, divisor = "B", 1

        fig3 = go.Figure(go.Bar(
            x=["Sent", "Received"],
            y=[bytes_sent / divisor, bytes_recv / divisor],
            marker_color=["#58a6ff", "#3fb950"],
            text=[
                f"{bytes_sent  / divisor:.1f} {unit}",
                f"{bytes_recv  / divisor:.1f} {unit}",
            ],
            textposition="auto",
            width=0.5,
        ))
        fig3.update_layout(
            **PLOTLY_THEME,
            height=280,
            yaxis_title=f"Volume ({unit})",
            xaxis_title="Direction",
        )
        st.plotly_chart(fig3, use_container_width=True)
    else:
        st.info("No TX/RX data found in this trace.")

    st.markdown('<div class="section-header">Throughput over time</div>',
                unsafe_allow_html=True)

    if not real_df.empty:
        df_io = real_df[real_df["type"].isin(SEND_TYPES + RECV_TYPES)].copy()

        if not df_io.empty:
            df_io["req_size"] = df_io.apply(get_req_size, axis=1)
            df_io = df_io[df_io["req_size"] > 0].dropna(subset=["t_ms"])

            if not df_io.empty:
                df_io["sec"] = (df_io["t_ms"] // 1000).astype(int)

                tx_df = (
                    df_io[df_io["type"].isin(SEND_TYPES)]
                    .groupby("sec")["req_size"]
                    .sum()
                    .reset_index()
                )
                rx_df = (
                    df_io[df_io["type"].isin(RECV_TYPES)]
                    .groupby("sec")["req_size"]
                    .sum()
                    .reset_index()
                )

                fig_flow = make_subplots(specs=[[{"secondary_y": True}]])

                if not rx_df.empty:
                    fig_flow.add_trace(
                        go.Scatter(
                            x=rx_df["sec"],
                            y=rx_df["req_size"],
                            name="Download (Rx)",
                            mode="lines",
                            line=dict(color="#3fb950", width=2, shape="spline"),
                            fill="tozeroy",
                            fillcolor="rgba(63,185,80,0.15)",
                        ),
                        secondary_y=False,
                    )

                if not tx_df.empty:
                    fig_flow.add_trace(
                        go.Scatter(
                            x=tx_df["sec"],
                            y=tx_df["req_size"],
                            name="Upload (Tx)",
                            mode="lines",
                            line=dict(color="#58a6ff", width=2, shape="spline"),
                            fill="tozeroy",
                            fillcolor="rgba(88,166,255,0.15)",
                        ),
                        secondary_y=True,
                    )

                theme_flow = {k: v for k, v in PLOTLY_THEME.items() if k != "margin"}
                fig_flow.update_layout(
                    **theme_flow,
                    height=350,
                    margin=dict(l=20, r=20, t=20, b=30),
                    xaxis_title="Time (seconds)",
                    hovermode="x unified",
                    legend=dict(
                        orientation="h",
                        yanchor="bottom",
                        y=1.05,
                        xanchor="center",
                        x=0.5,
                    ),
                )
                fig_flow.update_yaxes(
                    title_text="Download (Bytes/s)",
                    secondary_y=False,
                    color="#3fb950",
                    showgrid=True,
                    gridcolor="#21262d",
                )
                fig_flow.update_yaxes(
                    title_text="Upload (Bytes/s)",
                    secondary_y=True,
                    color="#58a6ff",
                    showgrid=False,
                )
                st.plotly_chart(fig_flow, use_container_width=True)
            else:
                st.info("No transfers with measurable size found.")
        else:
            st.info("No send/receive events in this trace.")
    else:
        st.info("No data to compute throughput.")