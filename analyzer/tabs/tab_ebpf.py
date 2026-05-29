import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
from config import PLOTLY_THEME


def render(df, ebpf_events, meta_data):
    st.markdown('<div class="section-header">eBPF Kernel-Space Event Analysis</div>', unsafe_allow_html=True)

    st.markdown("""
    <p style="font-size:0.82rem;color:#8b949e;margin-bottom:16px;">
    Events captured directly from kernel tracepoints via eBPF ring buffer.
    These complement LD_PRELOAD user-space traces with low-level TCP stack visibility.
    <br/>
    <span class="event-tag tag-ebpf">tcp_retransmit</span> Packet retransmissions (tcp_retransmit_skb tracepoint)
    <span class="event-tag tag-ebpf">iouring_complete</span> io_uring async completions
    </p>
    """, unsafe_allow_html=True)

    if not ebpf_events:
        st.warning(
            "No eBPF events in this trace. "
            "Use `sudo tcpsnitch -e <command>` to enable eBPF kernel probes."
        )
        return

    df_ebpf = pd.DataFrame(ebpf_events)

    if df_ebpf.empty or "type" not in df_ebpf.columns:
        st.warning("eBPF event data is empty or malformed.")
        return

    if "session_id" in df_ebpf.columns:
        def norm_sid(val):
            s = str(val)
            if s.startswith("sess_"):
                s = s.replace("sess_", "")
            return int(s) if s.isdigit() else val
        df_ebpf["norm_sid"] = df_ebpf["session_id"].apply(norm_sid)

  
    type_counts = df_ebpf["type"].value_counts()
    n_retrans = type_counts.get("tcp_retransmit", 0)
    n_iouring = type_counts.get("iouring_complete", 0)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total eBPF Events", f"{len(df_ebpf):,}")
    with c2:
        st.metric("TCP Retransmissions", f"{n_retrans:,}")
    with c3:
        st.metric("io_uring Completions", f"{n_iouring:,}")

    st.divider()

    theme = PLOTLY_THEME.copy()
    if "margin" in theme:
        del theme["margin"]

    st.markdown('<div class="section-header">Event Type Distribution</div>', unsafe_allow_html=True)

    fig_dist = go.Figure(go.Bar(
        x=type_counts.index.tolist(),
        y=type_counts.values.tolist(),
        marker_color=["#d2a8ff", "#58a6ff", "#3fb950"][:len(type_counts)],
        text=[f"{v:,}" for v in type_counts.values],
        textposition="auto",
    ))
    fig_dist.update_layout(
        **theme, height=280,
        margin=dict(l=40, r=20, t=20, b=40),
        xaxis_title="Event Type", yaxis_title="Count",
    )
    st.plotly_chart(fig_dist, use_container_width=True)

    df_retrans = df_ebpf[df_ebpf["type"] == "tcp_retransmit"].copy()

    if not df_retrans.empty:
        st.divider()
        st.markdown('<div class="section-header">TCP Retransmission Analysis</div>', unsafe_allow_html=True)

        st.markdown("""
        <p style="font-size:0.78rem;color:#8b949e;">
        Retransmissions are captured at the kernel level via the <code>tcp_retransmit_skb</code> tracepoint.
        Each event records the sequence number, congestion window (snd_cwnd) and smoothed RTT (srtt)
        at the moment of retransmission. These are ground-truth kernel observations, not inferences.
        </p>
        """, unsafe_allow_html=True)

        # Metrics
        r1, r2, r3, r4 = st.columns(4)
        with r1:
            st.metric("Retransmissions", f"{len(df_retrans):,}")
        with r2:
            if "snd_cwnd" in df_retrans.columns:
                avg_cwnd = df_retrans["snd_cwnd"].mean()
                st.metric("Mean CWND at Retransmit", f"{avg_cwnd:.1f} MSS")
            else:
                st.metric("Mean CWND at Retransmit", "N/A")
        with r3:
            if "srtt_us" in df_retrans.columns:
                avg_srtt = df_retrans["srtt_us"].mean() / 1000.0
                st.metric("Mean sRTT at Retransmit", f"{avg_srtt:.2f} ms")
            else:
                st.metric("Mean sRTT at Retransmit", "N/A")
        with r4:
            if "norm_sid" in df_retrans.columns:
                n_affected = df_retrans["norm_sid"].nunique()
                st.metric("Affected Sockets", f"{n_affected}")
            else:
                st.metric("Affected Sockets", "N/A")

        st.markdown("#### Retransmission Timeline")
        if "t_ms" in df_retrans.columns:
            fig_timeline = go.Figure()

            if "norm_sid" in df_retrans.columns:
                for sid in sorted(df_retrans["norm_sid"].unique()):
                    d = df_retrans[df_retrans["norm_sid"] == sid]
                    fig_timeline.add_trace(go.Scatter(
                        x=d["t_ms"], y=d.get("snd_cwnd", pd.Series([0]*len(d))),
                        mode="markers+lines",
                        name=f"Socket {sid}",
                        marker=dict(size=8, symbol="x"),
                        line=dict(width=1, dash="dot"),
                        hovertemplate=(
                            "<b>Retransmit</b><br>"
                            "Time: %{x:.1f} ms<br>"
                            "CWND: %{y} MSS<br>"
                            "<extra>Socket %{fullData.name}</extra>"
                        ),
                    ))
            else:
                fig_timeline.add_trace(go.Scatter(
                    x=df_retrans["t_ms"],
                    y=df_retrans.get("snd_cwnd", pd.Series([0]*len(df_retrans))),
                    mode="markers", marker=dict(size=8, color="#e74c3c", symbol="x"),
                    name="Retransmit",
                ))

            fig_timeline.update_layout(
                **theme, height=350,
                margin=dict(l=40, r=20, t=30, b=40),
                xaxis_title="Time (ms, relative to trace start)",
                yaxis_title="snd_cwnd at retransmission (MSS)",
                hovermode="closest",
            )
            st.plotly_chart(fig_timeline, use_container_width=True)


        if "snd_cwnd" in df_retrans.columns and len(df_retrans) > 1:
            col_cdf1, col_cdf2 = st.columns(2)

            with col_cdf1:
                st.markdown("#### CDF of CWND at Retransmission")
                st.markdown(
                    "<p style='font-size:0.72rem;color:#8b949e;'>"
                    "Read as: 'X% of retransmissions occurred when CWND was below Y MSS'. "
                    "Low CWND at retransmission indicates congestion-driven loss.</p>",
                    unsafe_allow_html=True,
                )
                cwnd_sorted = df_retrans["snd_cwnd"].sort_values().values
                cdf_y = np.arange(1, len(cwnd_sorted) + 1) / len(cwnd_sorted)

                fig_cdf_cwnd = go.Figure(go.Scatter(
                    x=cwnd_sorted, y=cdf_y, mode="lines",
                    line=dict(color="#d2a8ff", width=2.5),
                    hovertemplate="CWND: %{x} MSS<br>CDF: %{y:.2%}<extra></extra>",
                ))
                fig_cdf_cwnd.add_hline(
                    y=0.5, line_dash="dash", line_color="#484f58",
                    annotation_text="Median", annotation_position="bottom right",
                )
                fig_cdf_cwnd.add_vline(
                    x=10, line_dash="dot", line_color="#484f58",
                    annotation_text="IW=10", annotation_position="top left",
                )
                fig_cdf_cwnd.update_layout(
                    **theme, height=350,
                    margin=dict(l=40, r=20, t=30, b=40),
                    xaxis_title="snd_cwnd (MSS)", yaxis_title="CDF",
                    xaxis_type="log" if cwnd_sorted.max() > 100 else "linear",
                )
                st.plotly_chart(fig_cdf_cwnd, use_container_width=True)

            with col_cdf2:
                if "srtt_us" in df_retrans.columns:
                    st.markdown("#### CDF of sRTT at Retransmission")
                    st.markdown(
                        "<p style='font-size:0.72rem;color:#8b949e;'>"
                        "Read as: 'X% of retransmissions occurred when smoothed RTT was below Y ms'. "
                        "High sRTT at retransmission may indicate bufferbloat or path congestion.</p>",
                        unsafe_allow_html=True,
                    )
                    srtt_ms = (df_retrans["srtt_us"] / 1000.0).sort_values().values
                    cdf_y_rtt = np.arange(1, len(srtt_ms) + 1) / len(srtt_ms)

                    fig_cdf_rtt = go.Figure(go.Scatter(
                        x=srtt_ms, y=cdf_y_rtt, mode="lines",
                        line=dict(color="#3fb950", width=2.5),
                        hovertemplate="sRTT: %{x:.2f} ms<br>CDF: %{y:.2%}<extra></extra>",
                    ))
                    fig_cdf_rtt.add_hline(
                        y=0.5, line_dash="dash", line_color="#484f58",
                        annotation_text="Median", annotation_position="bottom right",
                    )
                    fig_cdf_rtt.update_layout(
                        **theme, height=350,
                        margin=dict(l=40, r=20, t=30, b=40),
                        xaxis_title="Smoothed RTT (ms)", yaxis_title="CDF",
                        xaxis_type="log" if len(srtt_ms) > 0 and srtt_ms.max() > 500 else "linear",
                    )
                    st.plotly_chart(fig_cdf_rtt, use_container_width=True)

        if "t_ms" in df_retrans.columns and len(df_retrans) > 2:
            st.markdown("#### CDF of Inter-Retransmission Intervals")
            st.markdown(
                "<p style='font-size:0.72rem;color:#8b949e;'>"
                "Time between consecutive retransmissions. Clustered retransmissions "
                "(short intervals) indicate burst losses, while dispersed retransmissions "
                "suggest independent random losses.</p>",
                unsafe_allow_html=True,
            )
            sorted_times = df_retrans["t_ms"].sort_values()
            inter_retrans = sorted_times.diff().dropna()
            inter_retrans = inter_retrans[inter_retrans > 0]

            if len(inter_retrans) > 1:
                vals = inter_retrans.sort_values().values
                cdf_y_ir = np.arange(1, len(vals) + 1) / len(vals)

                fig_ir = go.Figure(go.Scatter(
                    x=vals, y=cdf_y_ir, mode="lines",
                    line=dict(color="#f0a04b", width=2.5),
                    hovertemplate="Interval: %{x:.2f} ms<br>CDF: %{y:.2%}<extra></extra>",
                ))
                fig_ir.update_layout(
                    **theme, height=300,
                    margin=dict(l=40, r=20, t=20, b=40),
                    xaxis_title="Inter-Retransmission Interval (ms, Log Scale)",
                    yaxis_title="CDF",
                    xaxis_type="log",
                )
                st.plotly_chart(fig_ir, use_container_width=True)


        if "norm_sid" in df_retrans.columns:
            st.markdown("#### Per-Socket Retransmission Count")
            per_sock = df_retrans.groupby("norm_sid").agg(
                count=("type", "count"),
                mean_cwnd=("snd_cwnd", "mean") if "snd_cwnd" in df_retrans.columns else ("type", "count"),
                mean_srtt=("srtt_us", "mean") if "srtt_us" in df_retrans.columns else ("type", "count"),
            ).reset_index()

            if "snd_cwnd" in df_retrans.columns:
                per_sock["mean_cwnd"] = df_retrans.groupby("norm_sid")["snd_cwnd"].mean().values
            if "srtt_us" in df_retrans.columns:
                per_sock["mean_srtt_ms"] = df_retrans.groupby("norm_sid")["srtt_us"].mean().values / 1000.0

            per_sock = per_sock.sort_values(by="count", ascending=True)

            fig_sock = go.Figure(go.Bar(
                x=per_sock["count"],
                y=[f"Socket {s}" for s in per_sock["norm_sid"]],
                orientation="h",
                marker_color="#ff7b72",
                text=[f"{v:,}" for v in per_sock["count"]],
                textposition="auto",
            ))
            fig_sock.update_layout(
                **theme, height=max(200, len(per_sock) * 35),
                margin=dict(l=80, r=20, t=20, b=40),
                xaxis_title="Retransmission Count",
            )
            st.plotly_chart(fig_sock, use_container_width=True)

        

    df_iouring = df_ebpf[df_ebpf["type"] == "iouring_complete"].copy()

    if not df_iouring.empty:
        st.divider()
        st.markdown('<div class="section-header">io_uring Async Completion Analysis</div>', unsafe_allow_html=True)

        st.markdown("""
        <p style="font-size:0.78rem;color:#8b949e;">
        io_uring completions captured from kernel space. These events represent completed
        asynchronous I/O operations that bypass the traditional syscall path.
        The <code>res</code> field indicates the operation result (bytes transferred or error code).
        </p>
        """, unsafe_allow_html=True)

        iu1, iu2, iu3 = st.columns(3)
        with iu1:
            st.metric("io_uring Completions", f"{len(df_iouring):,}")
        with iu2:
            if "res" in df_iouring.columns:
                success = len(df_iouring[df_iouring["res"] >= 0])
                st.metric("Successful", f"{success:,}")
            else:
                st.metric("Successful", "N/A")
        with iu3:
            if "res" in df_iouring.columns:
                errors = len(df_iouring[df_iouring["res"] < 0])
                st.metric("Errors", f"{errors:,}")
            else:
                st.metric("Errors", "N/A")

        if "t_ms" in df_iouring.columns:
            st.markdown("#### Completion Timeline")
            color_vals = df_iouring["res"].apply(lambda x: "#3fb950" if x >= 0 else "#ff7b72") if "res" in df_iouring.columns else "#58a6ff"

            fig_iu = go.Figure(go.Scatter(
                x=df_iouring["t_ms"],
                y=df_iouring.get("res", pd.Series([0]*len(df_iouring))),
                mode="markers",
                marker=dict(
                    size=6,
                    color=color_vals if isinstance(color_vals, str) else color_vals.tolist(),
                ),
                hovertemplate="Time: %{x:.1f} ms<br>Result: %{y}<extra></extra>",
            ))
            fig_iu.update_layout(
                **theme, height=300,
                margin=dict(l=40, r=20, t=20, b=40),
                xaxis_title="Time (ms)", yaxis_title="Completion Result (res)",
            )
            st.plotly_chart(fig_iu, use_container_width=True)

        if "res" in df_iouring.columns:
            success_res = df_iouring[df_iouring["res"] > 0]["res"].sort_values().values
            if len(success_res) > 1:
                st.markdown("#### CDF of Bytes per io_uring Completion")
                cdf_y_iu = np.arange(1, len(success_res) + 1) / len(success_res)
                fig_cdf_iu = go.Figure(go.Scatter(
                    x=success_res, y=cdf_y_iu, mode="lines",
                    line=dict(color="#58a6ff", width=2.5),
                ))
                fig_cdf_iu.update_layout(
                    **theme, height=300,
                    margin=dict(l=40, r=20, t=20, b=40),
                    xaxis_title="Bytes Transferred (Log Scale)", yaxis_title="CDF",
                    xaxis_type="log",
                )
                st.plotly_chart(fig_cdf_iu, use_container_width=True)

    with st.expander("View Raw eBPF Events"):
        display_cols = [c for c in df_ebpf.columns if c not in ("norm_sid", "bin_ms")]
        st.dataframe(df_ebpf[display_cols].head(500), use_container_width=True, hide_index=True)
