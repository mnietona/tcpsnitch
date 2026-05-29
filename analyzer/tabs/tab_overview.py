import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from collections import Counter
import numpy as np
import pandas as pd

from config import PLOTLY_THEME, SEND_TYPES, RECV_TYPES


def _detect_android_iface_enum(real_df):
    """Detect Android interface enumeration pattern: many UDP sockets opened,
    used only for ioctl(), no data transferred, immediately closed."""
    if real_df.empty or "_socket_id" not in real_df.columns:
        return None

    udp_ioctl_only = 0
    udp_socks = real_df[real_df["type"] == "socket"]
    for _, row in udp_socks.iterrows():
        d = row.get("details", {})
        if not isinstance(d, dict):
            continue
        sock_info = d.get("sock_info", {})
        if sock_info.get("type", "") != "SOCK_DGRAM":
            continue
        sid = row.get("_socket_id")
        sock_events = real_df[real_df["_socket_id"] == sid]
        types_used = set(sock_events["type"].unique())
        # Only ioctl and close calls, no data
        data_calls = types_used.intersection(set(SEND_TYPES + RECV_TYPES + ["connect", "bind"]))
        if not data_calls and "ioctl" in types_used:
            udp_ioctl_only += 1

    if udp_ioctl_only >= 3:
        return {
            "icon": "info",
            "label": "Android interface enumeration",
            "detail": (
                f"{udp_ioctl_only} UDP socket(s) opened and immediately closed after ioctl() — "
                "a known Android pattern for querying network interface addresses "
                "(getifaddrs equivalent via SIOCGIFADDR). No data transferred on these sockets."
            ),
        }
    return None


def _detect_tcp_congestion(n_retrans, ebpf_events):
    """Detect severe TCP congestion from eBPF retransmissions."""
    if n_retrans == 0:
        return None

    msg = f"{n_retrans} TCP retransmission(s) detected at the kernel level (eBPF tcp_retransmit_skb)."

    severity = "warning" if n_retrans < 10 else "error"
    return {
        "icon": severity,
        "label": "TCP congestion",
        "detail": msg,
    }


def _detect_network_outage(netlink_events):
    """Detect a WiFi/LTE disconnect+reconnect from Netlink events."""
    if not netlink_events:
        return None

    dels, news = [], []
    for ev in netlink_events:
        d = ev.get("details", {}) if isinstance(ev.get("details"), dict) else {}
        msg_type = d.get("msg_type", "")
        if_index = d.get("if_index", 1)
        t = ev.get("t_ms")
        if t is None or if_index == 1:
            continue
        if msg_type in ("DEL_ADDR", "DEL_ROUTE") and t > 500:
            dels.append(t)
        elif msg_type in ("NEW_ADDR", "NEW_ROUTE") and t > 500:
            news.append(t)

    if not dels or not news:
        return None

    disconnect_t = min(dels)
    reconnect_candidates = [t for t in news if t > disconnect_t]
    if not reconnect_candidates:
        return None

    reconnect_t = min(reconnect_candidates)
    duration_s = (reconnect_t - disconnect_t) / 1000.0

    if duration_s > 1.0:
        return {
            "icon": "warning",
            "label": "Network disruption",
            "detail": (
                f"Network interface lost connectivity at t = {disconnect_t/1000:.2f}s "
                f"and was restored at t = {reconnect_t/1000:.2f}s "
                f"(outage duration: {duration_s:.1f}s). "
                "Sockets active during the outage are expected to have received "
                "ECONNABORTED or ETIMEDOUT errors."
            ),
        }
    return None


def _detect_connection_errors(real_df):
    """Detect significant transport-layer errors (ECONNABORTED, ETIMEDOUT, ECONNRESET)."""
    if real_df.empty:
        return None

    fatal_errnos = {"ECONNABORTED", "ETIMEDOUT", "ECONNRESET", "EHOSTUNREACH"}
    errno_col = real_df.get("errno") if hasattr(real_df, "get") else real_df["errno"] if "errno" in real_df.columns else None
    if errno_col is None:
        return None

    err_events = real_df[real_df["errno"].isin(fatal_errnos)] if "errno" in real_df.columns else pd.DataFrame()
    if err_events.empty:
        return None

    err_counts = err_events["errno"].value_counts().to_dict()
    detail_parts = [f"{v}x {k}" for k, v in err_counts.items()]
    return {
        "icon": "error",
        "label": "Connection errors",
        "detail": (
            "Fatal socket errors observed: " + ", ".join(detail_parts) + ". "
            "These typically indicate forced connection termination by the remote peer "
            "or a local network event."
        ),
    }


def _detect_splice_usage(real_df):
    """Detect splice() usage (sendfile is the user-space equivalent)."""
    if real_df.empty:
        return None
    splice_count = (real_df["type"] == "sendfile").sum()
    if splice_count > 0:
        return {
            "icon": "info",
            "label": "sendfile() / zero-copy",
            "detail": (
                f"{splice_count} sendfile() call(s) detected — the application uses "
                "kernel zero-copy data transfer, avoiding user-space buffer copies."
            ),
        }
    return None


def _build_narrative(real_df, n_retrans, ebpf_events, netlink_events):
    """Return a list of narrative findings, ordered by time significance."""
    findings = []

    android = _detect_android_iface_enum(real_df)
    if android:
        findings.append(android)

    outage = _detect_network_outage(netlink_events)
    if outage:
        findings.append(outage)

    congestion = _detect_tcp_congestion(n_retrans, ebpf_events)
    if congestion:
        findings.append(congestion)

    conn_err = _detect_connection_errors(real_df)
    if conn_err:
        findings.append(conn_err)

    splice = _detect_splice_usage(real_df)
    if splice:
        findings.append(splice)

    return findings


def render(df, all_events, type_counts_raw, n_retrans, meta_data, ebpf_events=None, netlink_events=None):
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

    findings = _build_narrative(
        real_df,
        n_retrans,
        ebpf_events or [],
        netlink_events or [],
    )

    if findings:
        st.markdown(
            '<div class="section-header">Trace Narrative — Auto-detected Events</div>',
            unsafe_allow_html=True,
        )
        icon_style = {
            "info":    ("rgba(88,166,255,0.08)",  "#58a6ff", "#1b3a5c"),
            "warning": ("rgba(227,179,65,0.08)",  "#e3b341", "#4a3500"),
            "error":   ("rgba(255,123,114,0.08)", "#ff7b72", "#5c1a1a"),
        }
        for f in findings:
            bg, fg, border_color = icon_style.get(f["icon"], icon_style["info"])
            st.markdown(
                f"""<div style="background:{bg};border-left:3px solid {fg};
                padding:10px 16px;border-radius:4px;margin-bottom:10px;">
                <span style="font-family:'IBM Plex Mono',monospace;font-size:0.7rem;
                color:{fg};text-transform:uppercase;letter-spacing:0.1em;">
                {f['label']}</span><br/>
                <span style="color:#c9d1d9;font-size:0.82rem;">{f['detail']}</span>
                </div>""",
                unsafe_allow_html=True,
            )
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