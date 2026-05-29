# tabs/tab_cwnd_rtt.py
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from config import PLOTLY_THEME

def render(df, ebpf_events, meta_data):
    st.markdown('<div class="section-header">TCP Congestion Window (CWND) & RTT</div>', unsafe_allow_html=True)

    st.markdown("""
    <p style="font-size:0.82rem;color:#8b949e;margin-bottom:16px;">
    <span class="event-tag tag-tcp">Solid Blue/Green Lines (tcp_info)</span> : Window and RTT evolution via kernel polling.<br/>
    <span class="event-tag tag-ebpf">Red/Orange Markers (eBPF)</span> : Exact drops and SRTT caught by kernel retransmissions.
    </p>
    """, unsafe_allow_html=True)

    if df.empty or "_socket_id" not in df.columns:
        st.info("No TCP data available in this trace.")
        return

    df_tcp_info = df[df['type'] == 'tcp_info'].copy()
    tcp_info_per_sock = {}
    
    if not df_tcp_info.empty:
        def extract_metrics(row):
            d = row.get('details', {})
            if isinstance(d, dict):
                return pd.Series([d.get('snd_cwnd'), d.get('rtt', 0) / 1000.0])
            return pd.Series([None, None])
        
        df_tcp_info[['cwnd', 'rtt_ms']] = df_tcp_info.apply(extract_metrics, axis=1)
        df_tcp_info = df_tcp_info.dropna(subset=['cwnd'])
        
        for sid, group in df_tcp_info.groupby('_socket_id'):
            tcp_info_per_sock[sid] = group

    df_ebpf = pd.DataFrame(ebpf_events) if ebpf_events else pd.DataFrame()
    ebpf_cwnd_per_sock = {}
    
    if not df_ebpf.empty and 'type' in df_ebpf.columns:
        df_retrans = df_ebpf[df_ebpf['type'] == 'tcp_retransmit'].copy()
        if not df_retrans.empty:
            if 'srtt_us' in df_retrans.columns:
                df_retrans['srtt_ms'] = pd.to_numeric(df_retrans['srtt_us'], errors='coerce') / 1000.0
            elif 'srtt' in df_retrans.columns:
                df_retrans['srtt_ms'] = pd.to_numeric(df_retrans['srtt'], errors='coerce') / 1000.0
            else:
                df_retrans['srtt_ms'] = float('nan')
            
            def norm_sid(val):
                val_str = str(val)
                if val_str.startswith("sess_"):
                    val_str = val_str.replace("sess_", "")
                return int(val_str) if val_str.isdigit() else val
            
            df_retrans['norm_sid'] = df_retrans['session_id'].apply(norm_sid)
            
            for sid, group in df_retrans.groupby('norm_sid'):
                if sid != 9999: # Double securité
                    ebpf_cwnd_per_sock[sid] = group


    all_sids = set(tcp_info_per_sock.keys()).union(set(ebpf_cwnd_per_sock.keys()))
    all_sids = sorted(list(all_sids), key=str)

    if not all_sids:
        st.info("No TCP (cwnd/RTT) data available in this trace.\n\n"
                "**tcp_info**: use `-u 100000` during capture.\n"
                "**eBPF**: use `sudo tcpsnitch -e`.")
        return

    selected_socks = st.multiselect(
        "Select Sockets to display simultaneously:",
        options=all_sids,
        default=all_sids[:min(3, len(all_sids))],
        format_func=lambda x: f"Socket {x}"
    )

    if not selected_socks:
        st.warning("Please select at least one socket to view the charts.")
        return

    theme_cwnd = PLOTLY_THEME.copy()
    if "margin" in theme_cwnd: del theme_cwnd["margin"]

    for sid in selected_socks:
        st.markdown(f"### Analysis of Socket {sid}")
        
        tdata = tcp_info_per_sock.get(sid)
        edata = ebpf_cwnd_per_sock.get(sid)
        
        ebpf_x = None
        if edata is not None and not edata.empty:
            ebpf_x = edata["t_ms"].copy()
            if tdata is not None and not tdata.empty:
                time_diff = abs(tdata["t_ms"].min() - ebpf_x.min())
                if time_diff > 1000000: 
                    offset = tdata["t_ms"].min() - ebpf_x.min()
                    ebpf_x = ebpf_x + offset

        fig_cwnd = go.Figure()
        has_cwnd_data = False
        
        if tdata is not None and not tdata.empty:
            fig_cwnd.add_trace(go.Scatter(
                x=tdata["t_ms"], y=tdata["cwnd"], mode="lines",
                name="tcp_info (Polling)", line=dict(color="#58a6ff", width=2.5, shape="hv"),
                fill="tozeroy", fillcolor="rgba(88,166,255,0.1)",
                hovertemplate="<b>tcp_info</b><br>Time: %{x:.1f} ms<br>CWND: %{y} MSS<extra></extra>"
            ))
            has_cwnd_data = True
            
        if edata is not None and not edata.empty and "snd_cwnd" in edata.columns:
            fig_cwnd.add_trace(go.Scatter(
                x=ebpf_x, y=edata["snd_cwnd"], mode="markers+lines",
                name="eBPF (Retransmit)",
                marker=dict(color="#e74c3c", size=10, symbol="x", line=dict(color="white", width=1.5)),
                line=dict(color="#ff7b72", width=1.5, dash="dot"),
                hovertemplate="<b>eBPF Drop</b><br>CWND: %{y} MSS<extra></extra>"
            ))
            has_cwnd_data = True
            
        if has_cwnd_data:
            fig_cwnd.add_hline(y=10, line_dash="dash", line_color="#484f58", annotation_text="Initial cwnd (10 MSS)")
            fig_cwnd.update_layout(**theme_cwnd, height=350, margin=dict(l=40, r=20, t=30, b=30),
                xaxis_title="Time (ms)", yaxis_title="snd_cwnd (MSS)",
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5))
            st.plotly_chart(fig_cwnd, use_container_width=True)
        else:
            st.info(f"No CWND data for Socket {sid}")

        fig_rtt = go.Figure()
        has_rtt_data = False

        if tdata is not None and not tdata.empty and "rtt_ms" in tdata.columns:
            valid_rtt = tdata[tdata["rtt_ms"] > 0]
            if not valid_rtt.empty:
                fig_rtt.add_trace(go.Scatter(
                    x=valid_rtt["t_ms"], y=valid_rtt["rtt_ms"], mode="lines",
                    name="tcp_info RTT", line=dict(color="#3fb950", width=2),
                    fill="tozeroy", fillcolor="rgba(63,185,80,0.1)",
                    hovertemplate="<b>tcp_info RTT</b><br>Time: %{x:.1f} ms<br>RTT: %{y:.2f} ms<extra></extra>"
                ))
                has_rtt_data = True

        if edata is not None and not edata.empty and "srtt_ms" in edata.columns:
            valid_srtt = edata[edata["srtt_ms"] > 0]
            if not valid_srtt.empty:
                fig_rtt.add_trace(go.Scatter(
                    x=ebpf_x[valid_srtt.index], y=valid_srtt["srtt_ms"], mode="markers",
                    name="eBPF SRTT (at loss)", 
                    marker=dict(color="#ffa657", size=9, symbol="diamond", line=dict(color="white", width=1)),
                    hovertemplate="<b>eBPF SRTT</b><br>Time: %{x:.1f} ms<br>SRTT: %{y:.2f} ms<extra></extra>"
                ))
                has_rtt_data = True

        if has_rtt_data:
            fig_rtt.update_layout(**theme_cwnd, height=250, margin=dict(l=40, r=20, t=10, b=30), 
                                  xaxis_title="Time (ms)", yaxis_title="Measured RTT (ms)", 
                                  legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5))
            st.plotly_chart(fig_rtt, use_container_width=True)

        st.markdown('<div class="section-header">Latency & Congestion Metrics</div>', unsafe_allow_html=True)
        c1, c2, c3, c4, c5 = st.columns(5)
        
        n_retrans_sock = len(edata) if edata is not None else 0
        
        avg_rtt_tcp = tdata['rtt_ms'][tdata['rtt_ms'] > 0].mean() if (tdata is not None and "rtt_ms" in tdata.columns) else None
        max_rtt_tcp = tdata['rtt_ms'].max() if (tdata is not None and "rtt_ms" in tdata.columns) else None
        max_cwnd = tdata['cwnd'].max() if (tdata is not None and "cwnd" in tdata.columns) else None
        
        avg_srtt_ebpf = edata['srtt_ms'][edata['srtt_ms'] > 0].mean() if (edata is not None and "srtt_ms" in edata.columns) else None

        with c1: st.metric("Avg RTT (tcp_info)", f"{avg_rtt_tcp:.2f} ms" if pd.notna(avg_rtt_tcp) else "N/A")
        with c2: st.metric("Max RTT (tcp_info)", f"{max_rtt_tcp:.2f} ms" if pd.notna(max_rtt_tcp) else "N/A")
        with c3: st.metric("Avg SRTT (eBPF)", f"{avg_srtt_ebpf:.2f} ms" if pd.notna(avg_srtt_ebpf) else "N/A")
        with c4: st.metric("Max CWND", f"{max_cwnd:.0f} MSS" if pd.notna(max_cwnd) else "N/A")
        with c5: st.metric("Retransmissions", n_retrans_sock, delta_color="inverse" if n_retrans_sock > 0 else "normal")

        if edata is not None and not edata.empty and "snd_cwnd" in edata.columns:
            cwnd_vals = edata["snd_cwnd"].dropna().values
            if len(cwnd_vals) >= 2:
                peak_cwnd = int(cwnd_vals.max())
                min_cwnd  = int(cwnd_vals.min())
                if peak_cwnd >= 5 and min_cwnd <= 2:
                    collapse_ratio = round((peak_cwnd - min_cwnd) / peak_cwnd * 100)
                    st.markdown(
                        f"""<div style="background:rgba(255,123,114,0.08);border-left:3px solid #ff7b72;
                        padding:10px 16px;border-radius:4px;margin-top:8px;">
                        <span style="font-family:'IBM Plex Mono',monospace;font-size:0.7rem;
                        color:#ff7b72;text-transform:uppercase;letter-spacing:0.1em;">
                        CWND collapse detected</span><br/>
                        <span style="color:#c9d1d9;font-size:0.82rem;">
                        Congestion window dropped from <b>{peak_cwnd} MSS</b> to <b>{min_cwnd} MSS</b>
                        ({collapse_ratio}% reduction) under repeated retransmissions.
                        This is consistent with TCP's multiplicative decrease (AIMD) reacting to
                        sustained packet loss.
                        </span>
                        </div>""",
                        unsafe_allow_html=True,
                    )

        st.divider()