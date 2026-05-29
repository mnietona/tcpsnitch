import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import numpy as np
from config import PLOTLY_THEME, SEND_TYPES, RECV_TYPES

def render(df, all_events):
    st.markdown('<div class="section-header">Socket API Usage & Lifecycle Analysis</div>', unsafe_allow_html=True)

    if df.empty or "_socket_id" not in df.columns:
        st.info("No socket data available in this trace.")
        return

    if "errno" not in df.columns and "details" in df.columns:
        df["errno"] = df["details"].apply(
            lambda d: d.get("errno", None) if isinstance(d, dict) else None
        )

    sockets_summary = []
    grouped = df.groupby("_socket_id")
    
    global_tcp_count = 0
    global_udp_count = 0

    for sid, group in grouped:
        t_start = group["t_ms"].min()
        t_end   = group["t_ms"].max()
        lifespan = t_end - t_start
        
        domain = "Unknown"
        protocol = "Unknown"
        for _, row in group.dropna(subset=['details']).iterrows():
            details = row['details']
            if isinstance(details, dict) and 'sock_info' in details:
                domain   = details['sock_info'].get('domain', domain)
                protocol = details['sock_info'].get('type', protocol)
                if str(protocol) == "0":
                    sock_type_raw = str(details['sock_info'].get('type', ''))
                    if "SOCK_STREAM" in sock_type_raw:
                        protocol = "SOCK_STREAM"
                break

        if str(protocol) == "1": protocol = "SOCK_STREAM"
        if str(protocol) == "2": protocol = "SOCK_DGRAM"

        if protocol == "SOCK_STREAM": global_tcp_count += 1
        if protocol == "SOCK_DGRAM":  global_udp_count += 1
        
        ip = "Unknown/Unbound"
        for _, row in group[group["type"].isin(["connect", "bind", "sendto"])].iterrows():
            d = row.get("details", {})
            if isinstance(d, dict) and "addr" in d:
                ip = d["addr"].get("ip", ip)
                break
        
        if "fake_call" in group.columns:
            real_events = group[group["fake_call"] != True]
        else:
            real_events = group[group["details"].apply(
                lambda d: not (isinstance(d, dict) and d.get("fake_call", False))
            )]
        
        sent_ev = real_events[(real_events["type"].isin(SEND_TYPES)) & (real_events["return_value"] > 0)]
        recv_ev = real_events[(real_events["type"].isin(RECV_TYPES)) & (real_events["return_value"] > 0)]
        
        sent = sent_ev["return_value"].sum()
        recv = recv_ev["return_value"].sum()
        errors = len(real_events[real_events["return_value"] < 0])
        
        t_first_tx = sent_ev["t_ms"].min() if not sent_ev.empty else None
        t_first_rx = recv_ev["t_ms"].min() if not recv_ev.empty else None
        
        t_connect = real_events.loc[real_events["type"] == "connect", "t_ms"].min()
        setup_delay = None
        if pd.notna(t_connect):
            valid_firsts = [t for t in [t_first_tx, t_first_rx] if pd.notna(t)]
            if valid_firsts:
                setup_delay = min(valid_firsts) - t_connect
                
        sorted_times = real_events["t_ms"].sort_values()
        max_idle_ms = sorted_times.diff().max() if len(sorted_times) > 1 else 0

        sockets_summary.append({
            "socket_id": sid, "ip": ip, "domain": domain, "protocol": protocol,
            "events": len(group), "lifespan_ms": lifespan,
            "sent_b": sent, "recv_b": recv, "errors": errors,
            "setup_delay": setup_delay, "t_first_tx": t_first_tx, "t_first_rx": t_first_rx,
            "max_idle_ms": max_idle_ms, "t_start": t_start, "t_end": t_end
        })

    summary_df = pd.DataFrame(sockets_summary).sort_values(by=["sent_b", "recv_b"], ascending=[False, False])
    
    st.markdown("### Trace Overview")
    col_a, col_b, col_c, col_d = st.columns(4)
    with col_a: st.metric("Total Sockets", len(summary_df))
    with col_b: 
        proto_label = f"{global_tcp_count} TCP | {global_udp_count} UDP"
        if len(proto_label) > 15:
            st.metric("Protocols", proto_label[:13] + "...", help=proto_label)
        else:
            st.metric("Protocols", proto_label)
    with col_c: st.metric("Total Bytes Sent", f"{summary_df['sent_b'].sum():,} B")
    with col_d: st.metric("Total Bytes Recv", f"{summary_df['recv_b'].sum():,} B")
    st.divider()

    st.markdown("### Detailed Socket Analysis")
    selected_sid = st.selectbox(
        "Select a socket to inspect:",
        options=summary_df["socket_id"].tolist(),
        format_func=lambda x: f"Socket {x} | {summary_df[summary_df['socket_id']==x]['protocol'].iloc[0].replace('SOCK_','')} | IP: {summary_df[summary_df['socket_id']==x]['ip'].iloc[0]}"
    )

    if selected_sid is not None:
        sock_data = summary_df[summary_df["socket_id"] == selected_sid].iloc[0]
        events = df[df["_socket_id"] == selected_sid].copy()
        
        c1, c2, c3, c4 = st.columns(4)
        with c1: 
            ip_label = str(sock_data['ip'])
            if len(ip_label) > 15:
                st.metric("Target IP", ip_label[:13] + "...", help=ip_label)
            else:
                st.metric("Target IP", ip_label)
        with c2: st.metric("Domain", sock_data['domain'].replace('AF_', ''))
        with c3: st.metric("Bytes Sent", f"{sock_data['sent_b']:,} B")
        with c4: st.metric("Bytes Recv", f"{sock_data['recv_b']:,} B")
        
        findings = []
        total_data = sock_data['sent_b'] + sock_data['recv_b']

        if sock_data['protocol'] == "SOCK_STREAM":
            findings.append(f"TCP flow — lifespan {sock_data['lifespan_ms']:.1f} ms, {total_data:,} bytes exchanged.")
        elif sock_data['protocol'] == "SOCK_DGRAM":
            # Detecte Pattern Android
            types_in_sock = set(events["type"].unique())
            data_calls = types_in_sock.intersection(set(SEND_TYPES + RECV_TYPES))
            if not data_calls and "ioctl" in types_in_sock:
                findings.append(
                    "UDP socket used exclusively for ioctl() — "
                    "typical Android pattern for network interface enumeration (SIOCGIFADDR). "
                    "No data transferred."
                )
            else:
                findings.append(f"UDP/QUIC flow — lifespan {sock_data['lifespan_ms']:.1f} ms, {total_data:,} bytes exchanged.")

        if "errno" in events.columns:
            fatal_errnos = {"ECONNABORTED", "ETIMEDOUT", "ECONNRESET", "EHOSTUNREACH"}
            fatal_ev = events[events["errno"].isin(fatal_errnos)]
            if not fatal_ev.empty:
                for errno_val, grp in fatal_ev.groupby("errno"):
                    t_err = grp["t_ms"].min()
                    findings.append(
                        f"{errno_val} at t = {t_err:.0f} ms — connection forcibly terminated "
                        "(possible network disruption or remote RST)."
                    )

        if "errno" in events.columns:
            einprog = events[events["errno"] == "EINPROGRESS"]
            if not einprog.empty:
                findings.append(
                    "Non-blocking connect() detected (EINPROGRESS) — "
                    "socket was set to O_NONBLOCK before connect; completion signaled by poll/epoll."
                )

        for msg in findings:
            st.info(msg)

        st.markdown('<div class="section-header">Timing & Performance Profiling</div>', unsafe_allow_html=True)
        t1, t2, t3, t4 = st.columns(4)
        
        ttfb_tx = (sock_data['t_first_tx'] - sock_data['t_start']) if pd.notna(sock_data['t_first_tx']) else "N/A"
        ttfb_rx = (sock_data['t_first_rx'] - sock_data['t_start']) if pd.notna(sock_data['t_first_rx']) else "N/A"
        
        str_ttfb_tx = f"{ttfb_tx:.1f} ms" if isinstance(ttfb_tx, float) else "None"
        str_ttfb_rx = f"{ttfb_rx:.1f} ms" if isinstance(ttfb_rx, float) else "None"
        str_setup = f"{sock_data['setup_delay']:.1f} ms" if pd.notna(sock_data['setup_delay']) else "N/A"
        
        with t1: 
            st.metric("App Setup Delay (Handshake)", str_setup, help="Time between connect() and first TX/RX. Approximates TCP/TLS Handshake + App prep time.")
        with t2: 
            st.metric("Time to First Byte (TX)", str_ttfb_tx, help="Time from socket() creation to first successful send.")
        with t3: 
            st.metric("Time to First Byte (RX)", str_ttfb_rx, help="Time from socket() creation to first successful receive.")
        with t4: 
            st.metric("Max Idle Time", f"{sock_data['max_idle_ms']:.1f} ms", help="Longest period of API inactivity. High values mean the connection was kept alive but unused.")

        def categorize_event(row):
            if row.get('fake_call', False): return 'Noise (Hidden)'
            t = row['type']
            if row['return_value'] < 0 and t not in ['poll', 'epoll_wait', 'select']: return 'Error'
            if t in ['socket', 'setsockopt', 'fcntl', 'bind', 'getsockname', 'getpeername', 'getsockopt', 'ioctl']: return '1. Configuration'
            if t in ['connect', 'accept', 'listen']: return '2. Connection'
            if t in SEND_TYPES: return '3. Transmit (TX)'
            if t in RECV_TYPES: return '4. Receive (RX)'
            if t in ['close', 'shutdown']: return '5. Termination'
            return 'Noise (Hidden)'

        events['Phase'] = events.apply(categorize_event, axis=1)
        
        st.markdown('<div class="section-header">API Call Chronology</div>', unsafe_allow_html=True)
        
        graph_events = events[events['Phase'] != 'Noise (Hidden)'].copy()
        
        if not graph_events.empty:
            phase_order = ['5. Termination', '4. Receive (RX)', '3. Transmit (TX)', '2. Connection', '1. Configuration', 'Error']
            fig_timeline = go.Figure()

            color_map = {
                '1. Configuration': '#8b949e', '2. Connection': '#58a6ff',
                '3. Transmit (TX)': '#d2a8ff', '4. Receive (RX)': '#3fb950',
                '5. Termination': '#f85149', 'Error': '#ff7b72'
            }
            
            for phase in phase_order:
                df_phase = graph_events[graph_events['Phase'] == phase]
                if not df_phase.empty:
                    fig_timeline.add_trace(go.Scatter(
                        x=df_phase['t_ms'], y=df_phase['Phase'],
                        mode='markers', name=phase,
                        marker=dict(size=12, color=color_map.get(phase, '#ffffff'), line=dict(width=1, color='#0d1117')),
                        text=df_phase['type'], customdata=df_phase['return_value'],
                        hovertemplate="<b>%{text}</b><br>Time: %{x:.2f} ms<br>Return Val: %{customdata}<extra></extra>"
                    ))

            theme_custom = PLOTLY_THEME.copy()
            theme_custom["margin"] = dict(l=150, r=20, t=20, b=40)
            fig_timeline.update_layout(
                **theme_custom, height=350, showlegend=False,
                xaxis_title="Time relative to trace start (ms)"
            )
            fig_timeline.update_yaxes(categoryorder='array', categoryarray=phase_order, title="")
            
            st.plotly_chart(fig_timeline, use_container_width=True)
        else:
            st.warning("No significant API events logged for this socket.")

        with st.expander("View Raw POSIX Logs for this Socket"):
            display_df = events[['t_ms', 'type', 'return_value', 'fake_call', 'details']].copy()
            display_df['t_ms'] = display_df['t_ms'].apply(lambda x: f"{x:.2f}")
            st.dataframe(display_df, use_container_width=True)