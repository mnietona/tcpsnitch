import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter
from config import PLOTLY_THEME, ASYNC_TYPES, CTRL_TYPES, SEND_TYPES, RECV_TYPES

def render(df):
    st.markdown('<div class="section-header">Asynchronous I/O, Control Plane & Zero-Copy</div>', unsafe_allow_html=True)

    if df.empty:
        st.info("No data available.")
        return

    # Extraction
    async_df = df[df["type"].isin(ASYNC_TYPES)].copy()
    ctrl_df  = df[df["type"].isin(CTRL_TYPES)].copy()
    
    zero_copy_types = ["splice", "vmsplice", "sendfile", "tee"]
    zc_df = df[df["type"].isin(zero_copy_types)].copy()
    
    polling_df = async_df[async_df["type"].isin(["poll", "select", "epoll_wait", "epoll_pwait", "ppoll", "pselect6"])]
    
    def extract_optname(details):
        if isinstance(details, dict): return details.get('optname', 'UNKNOWN')
        return 'UNKNOWN'
        
    sockopt_df = df[df['type'].isin(['setsockopt', 'getsockopt'])].copy()
    if not sockopt_df.empty:
        sockopt_df['optname'] = sockopt_df['details'].apply(extract_optname)
        sockopt_df = sockopt_df[sockopt_df['optname'] != 'UNKNOWN']

    # Metrics
    c1, c2, c3, c4 = st.columns(4)
    
    n_polls = len(polling_df)
    with c1: 
        st.metric("Multiplexing Calls", f"{n_polls:,}")
    
    if n_polls > 0:
        zero_yield = len(polling_df[polling_df["return_value"] == 0])
        errors     = len(polling_df[polling_df["return_value"] < 0])
        thrash_rate = (zero_yield / n_polls) * 100
        
        with c2: 
            st.metric("Timeouts (0 FD)", f"{zero_yield:,}", delta=f"{thrash_rate:.1f}%", delta_color="inverse")
        
        success_polls = polling_df[polling_df["return_value"] > 0]
        avg_fds = success_polls["return_value"].mean() if not success_polls.empty else 0
        with c3: 
            st.metric("Avg Sockets Ready", f"{avg_fds:.2f}")
    else:
        with c2: st.metric("Timeouts (0 FD)", "N/A")
        with c3: st.metric("Avg Sockets Ready", "N/A")

    with c4: 
        st.metric("Zero-Copy Calls", f"{len(zc_df):,}")

    st.divider()

    col1, col2 = st.columns(2)
    theme_async = PLOTLY_THEME.copy()
    if "margin" in theme_async: del theme_async["margin"]
    theme_async["margin"] = dict(l=40, r=20, t=40, b=20)

    with col1:
        st.markdown('<div class="section-header">Polling Efficiency</div>', unsafe_allow_html=True)
        if n_polls > 0:
            success_count = n_polls - zero_yield - errors
            fig_eff = go.Figure(go.Bar(
                x=["Timeouts (0 FD)", "Success (>0 FDs)", "Errors (<0)"], 
                y=[zero_yield, success_count, errors],
                marker_color=["#f0a04b", "#3fb950", "#ff7b72"],
                text=[f"{zero_yield:,}", f"{success_count:,}", f"{errors:,}"],
                textposition="auto"
            ))
            fig_eff.update_layout(**theme_async, height=300, yaxis_title="Call Count", xaxis_title="")
            st.plotly_chart(fig_eff, use_container_width=True)
        else:
            st.info("No polling data.")

    with col2:
        st.markdown('<div class="section-header">Multiplexing API Distribution</div>', unsafe_allow_html=True)
        if not async_df.empty:
            async_counts = async_df['type'].value_counts().reset_index()
            async_counts.columns = ['API', 'Count']
            
            fig_api = px.bar(
                async_counts, x='API', y='Count', text='Count', 
                color='API', color_discrete_sequence=["#58a6ff", "#d2a8ff", "#79c0ff", "#1f6feb"]
            )
            fig_api.update_layout(**theme_async, height=300, showlegend=False, yaxis_title="Call Count", xaxis_title="")
            fig_api.update_traces(texttemplate='%{text:,}', textposition='auto')
            st.plotly_chart(fig_api, use_container_width=True)
        else:
            st.info("No multiplexing data.")

    st.divider()

    col3, col4 = st.columns(2)

    with col3:
        st.markdown('<div class="section-header">Control Plane Calls</div>', unsafe_allow_html=True)
        if not ctrl_df.empty:
            ctrl_counts = Counter(ctrl_df["type"].tolist())
            fig_ctrl = go.Figure(go.Bar(
                x=list(ctrl_counts.keys()), y=list(ctrl_counts.values()), 
                marker_color="#d2a8ff", 
                text=[f"{v:,}" for v in ctrl_counts.values()], 
                textposition="auto"
            ))
            fig_ctrl.update_layout(**theme_async, height=300, yaxis_title="Call Count", xaxis_title="")
            st.plotly_chart(fig_ctrl, use_container_width=True)
        else:
            st.info("No control plane data.")

    with col4:
        st.markdown('<div class="section-header">Top Socket Options</div>', unsafe_allow_html=True)
        if not sockopt_df.empty:
            opt_counts = sockopt_df['optname'].value_counts().head(10).reset_index()
            opt_counts.columns = ['Option', 'Count']
            opt_counts = opt_counts.sort_values(by='Count', ascending=True)
            
            fig_opt = px.bar(
                opt_counts, x='Count', y='Option', text='Count', 
                orientation='h', color_discrete_sequence=["#58a6ff"]
            )
            fig_opt.update_layout(**theme_async, height=300, showlegend=False, xaxis_title="Call Count", yaxis_title="")
            fig_opt.update_traces(texttemplate='%{text:,}', textposition='auto')
            st.plotly_chart(fig_opt, use_container_width=True)
        else:
            st.info("No socket options data.")

    if n_polls > 0 and 'success_polls' in locals() and not success_polls.empty:
        st.divider()
        st.markdown('<div class="section-header">Throughput Capacity (Simultaneous Ready Sockets)</div>', unsafe_allow_html=True)
        
        fds_ready = success_polls["return_value"].sort_values()
        if len(fds_ready) > 1:
            cdf_y = np.arange(1, len(fds_ready) + 1) / len(fds_ready) * 100
            fig_fds = go.Figure(go.Scatter(x=fds_ready.values, y=cdf_y, mode="lines", line=dict(color="#58a6ff", width=2.5)))
            
            log_x = True if fds_ready.max() > 50 else False
            fig_fds.update_layout(
                **theme_async, height=300,
                xaxis_title="Number of Ready File Descriptors (FDs)" + (" (Log Scale)" if log_x else ""),
                yaxis_title="CDF (%)",
                xaxis_type="log" if log_x else "linear"
            )
            fig_fds.update_xaxes(tickformat="d", dtick=1)
            st.plotly_chart(fig_fds, use_container_width=True)