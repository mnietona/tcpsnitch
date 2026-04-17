import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from config import PLOTLY_THEME, SEND_TYPES, RECV_TYPES

def render(df):
    st.markdown('<div class="section-header">Data Transfer Analysis (Send & Receive)</div>', unsafe_allow_html=True)
    
    st.markdown("""
    <p style="font-size:0.85rem; color:#8b949e;">
        Analysis of payload sizes and inter-arrival times. 
        Charts use the Empirical Cumulative Distribution Function (CDF) with a logarithmic scale.
    </p>
    """, unsafe_allow_html=True)

    if df.empty or "_socket_id" not in df.columns:
        st.info("No data available for analysis.")
        return

    # ---  Robust Protocol Inference ---
    protocol_map = {}
    for sid, group in df.groupby("_socket_id"):
        proto_raw = "Unknown"
        
        # Tenter de lire depuis les métadonnées sock_info
        for _, row in group.dropna(subset=['details']).iterrows():
            details = row['details']
            if isinstance(details, dict) and 'sock_info' in details:
                proto_raw = str(details['sock_info'].get('type', proto_raw))
                break
        
        # Nettoyage 
        proto = "Unknown"
        if "SOCK_STREAM" in proto_raw or proto_raw == "1": 
            proto = "SOCK_STREAM"
        elif "SOCK_DGRAM" in proto_raw or proto_raw == "2": 
            proto = "SOCK_DGRAM"

        # Heuristique 
        if proto == "Unknown":
            types_used = set(group['type'].unique())
            if types_used.intersection({'listen', 'accept'}):
                proto = "SOCK_STREAM"
            elif types_used.intersection({'sendmmsg', 'recvmmsg'}):
                proto = "SOCK_DGRAM"
            elif 'connect' in types_used:
                proto = "SOCK_STREAM" # Cas général

        if proto == "SOCK_STREAM": protocol_map[sid] = "TCP"
        elif proto == "SOCK_DGRAM": protocol_map[sid] = "UDP"
        else: protocol_map[sid] = "Other"

    # --- Filter valid data transfers ---
    # On ne garde que les appels de lecture/écriture qui ont retourné un nombre d'octets > 0
    df_data = df[
        (df['type'].isin(SEND_TYPES + RECV_TYPES)) & 
        (df['return_value'] > 0) & 
        (df.get('fake_call', False) == False)
    ].copy()

    if df_data.empty:
        st.warning("No successful data transfer events (send/recv > 0) found in this trace.")
        return

    # Enrichissement du DataFrame avec nos nouvelles colonnes
    df_data['Protocol'] = df_data['_socket_id'].map(protocol_map)
    df_data['Direction'] = df_data['type'].apply(lambda x: 'TX (Send)' if x in SEND_TYPES else 'RX (Receive)')
    df_data['Payload Size (Bytes)'] = df_data['return_value']

    # On trie d'abord par socket, puis par direction, puis chronologiquement
    df_data = df_data.sort_values(by=['_socket_id', 'Direction', 't_ms'])
    
    # diff() calcule la différence de temps écoulé avec la ligne précédente (donc le paquet précédent)
    df_data['Inter-arrival Time (ms)'] = df_data.groupby(['_socket_id', 'Direction'])['t_ms'].diff()
    
    # Si deux événements se produisent dans la même milliseconde, on les sépare artificiellement de 1 microseconde (0.001 ms).
    df_data.loc[df_data['Inter-arrival Time (ms)'] == 0.0, 'Inter-arrival Time (ms)'] = 0.001

    # --- 4. KPIs ---
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("Total Calls (TX/RX)", f"{len(df_data):,}")
    with c2: st.metric("Avg Payload Size", f"{df_data['Payload Size (Bytes)'].mean():.0f} B")
    with c3: st.metric("Median Payload Size", f"{df_data['Payload Size (Bytes)'].median():.0f} B")
    with c4: 
        valid_inter = df_data['Inter-arrival Time (ms)'].dropna()
        avg_inter = valid_inter.mean() if not valid_inter.empty else 0
        st.metric("Avg Inter-arrival", f"{avg_inter:.2f} ms")

    st.divider()

    # --- LÉGENDE GLOBALE POUR LES GRAPHIQUES ---
    st.markdown(
        "<p style='font-size:0.75rem;color:#8b949e;'>"
        "<b>Legend:</b> Colors = protocol (Blue = TCP, Orange = UDP). "
        "Line style = direction (Solid = TX/Send, Dashed = RX/Receive).</p>",
        unsafe_allow_html=True,
    )

    # ---  Graph 1 : Payload Sizes CDF ---
    st.markdown("### Cumulative Distribution of Payload Sizes")
    st.markdown("<p style='font-size:0.75rem; color:#8b949e;'>Read as: 'X% of API calls transfer fewer than Y bytes'. The X-axis is logarithmic.</p>", unsafe_allow_html=True)
    
    fig_size = px.ecdf(
        df_data, 
        x="Payload Size (Bytes)", 
        color="Protocol", 
        line_dash="Direction",
        log_x=True,
        category_orders={"Protocol": ["TCP", "UDP", "Other"], "Direction": ["TX (Send)", "RX (Receive)"]}
    )

    fig_size.update_layout(
        **PLOTLY_THEME,
        yaxis_title="CDF (Probability)",
        xaxis_title="Payload Size in Bytes (Log Scale)",
        height=450,
        showlegend=True,
        legend=dict(
            title="Legend",
            yanchor="top", y=0.95, xanchor="left", x=0.01,
            bgcolor="rgba(22, 27, 34, 0.8)" # Fond semi-transparent pour ne pas cacher les lignes
        )
    )
    # Ligne verticale pour montrer la limite classique d'un segment TCP (MSS)
    #–—fig_size.add_vline(x=1448, line_dash="dot", line_color="gray", annotation_text="Typical TCP MSS (1448B)", annotation_position="top left")
    
    st.plotly_chart(fig_size, use_container_width=True)

    # --- Graph 2 : Inter-arrival CDF ---
    st.markdown("### Cumulative Distribution of Inter-arrival Times")
    st.markdown("<p style='font-size:0.75rem; color:#8b949e;'>Read as: 'Time elapsed between two consecutive TX (or RX) calls on the same socket'.</p>", unsafe_allow_html=True)
    
    df_inter = df_data.dropna(subset=['Inter-arrival Time (ms)'])
    
    if not df_inter.empty:
        fig_inter = px.ecdf(
            df_inter, 
            x="Inter-arrival Time (ms)", 
            color="Protocol",
            line_dash="Direction",
            log_x=True,
            category_orders={"Protocol": ["TCP", "UDP", "Other"], "Direction": ["TX (Send)", "RX (Receive)"]}
        )

        fig_inter.update_layout(
            **PLOTLY_THEME,
            yaxis_title="CDF (Probability)",
            xaxis_title="Inter-arrival Time in ms (Log Scale)",
            height=450,
            showlegend=True,
            legend=dict(
                title="Legend",
                yanchor="top", y=0.95, xanchor="left", x=0.01,
                bgcolor="rgba(22, 27, 34, 0.8)"
            )
        )
        
        st.plotly_chart(fig_inter, use_container_width=True)
    else:
        st.info("No consecutive packets on the same socket/direction found (e.g., app only made single isolated requests).")

    # --- Breakdown Table ---
    with st.expander("View Detailed Transfer Statistics"):
        stats_df = df_data.groupby(['Protocol', 'Direction']).agg(
            Count=('type', 'count'),
            Total_Bytes=('Payload Size (Bytes)', 'sum'),
            Mean_Bytes=('Payload Size (Bytes)', 'mean'),
            Median_Bytes=('Payload Size (Bytes)', 'median'),
            Max_Bytes=('Payload Size (Bytes)', 'max')
        ).reset_index()
        
        stats_df['Mean_Bytes'] = stats_df['Mean_Bytes'].round(1)
        st.dataframe(stats_df.sort_values(by="Total_Bytes", ascending=False), use_container_width=True, hide_index=True)