import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from config import PLOTLY_THEME


def _extract_details(df_nl):
    if "details" not in df_nl.columns:
        return df_nl

    df_nl = df_nl.copy()

    def _get(d, key, default=""):
        return d.get(key, default) if isinstance(d, dict) else default

    df_nl["msg_type"]  = df_nl["details"].apply(lambda d: _get(d, "msg_type", "UNKNOWN"))
    df_nl["if_index"]  = df_nl["details"].apply(lambda d: _get(d, "if_index", -1))
    df_nl["family"]    = df_nl["details"].apply(lambda d: _get(d, "family",   "Unknown"))
    df_nl["ip"]        = df_nl["details"].apply(lambda d: _get(d, "ip",       ""))
    df_nl["if_name"]   = df_nl["details"].apply(lambda d: _get(d, "if_name",  ""))

    df_nl["dst"]       = df_nl["details"].apply(lambda d: _get(d, "dst",      ""))
    df_nl["gateway"]   = df_nl["details"].apply(lambda d: _get(d, "gateway",  ""))

    return df_nl


def _build_iface_label(if_index, ips):
    if if_index == 1:
        return "lo"
    has_link_local = any(
        str(ip).startswith("fe80:") or str(ip).startswith("169.254") for ip in ips
    )
    has_private = any(
        str(ip).startswith("192.168") or str(ip).startswith("10.") or
        str(ip).startswith("172.") for ip in ips
    )
    has_lte = any(str(ip).startswith("100.") or str(ip).startswith("fd7a") for ip in ips)
    if has_lte:
        return f"if{if_index} (LTE)"
    if has_private and has_link_local:
        return f"if{if_index} (wlan/eth)"
    return f"if{if_index}"


def _detect_network_events(df_nl, gap_ms=2000):
    events = []

    addr_route = df_nl[
        df_nl["msg_type"].isin(["DEL_ADDR", "DEL_ROUTE", "NEW_ADDR", "NEW_ROUTE"])
        & (df_nl["if_index"] != 1)
        & (df_nl["t_ms"].notna())
    ].copy().sort_values("t_ms")

    if addr_route.empty:
        return events

    dels = addr_route[addr_route["msg_type"].str.startswith("DEL")]["t_ms"].values
    news = addr_route[addr_route["msg_type"].str.startswith("NEW")]["t_ms"].values

    if len(dels) == 0 or len(news) == 0:
        return events

    real_dels = dels[dels > 500]
    if len(real_dels) == 0:
        return events

    disconnect_t = real_dels.min()

    reconnect_candidates = news[news > disconnect_t]
    if len(reconnect_candidates) == 0:
        return events

    reconnect_t = reconnect_candidates.min()

    duration_ms = reconnect_t - disconnect_t
    if duration_ms > gap_ms:
        events.append({
            "type": "network_outage",
            "t_start_ms": disconnect_t,
            "t_end_ms": reconnect_t,
            "label": f"Network disruption ({duration_ms/1000:.1f}s)",
        })
    return events


def render(netlink_events, df, meta_data):
    st.markdown(
        '<div class="section-header">Netlink Network Configuration Events</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """<p style="font-size:0.82rem;color:#8b949e;margin-bottom:16px;">
        The Netlink subsystem delivers real-time notifications of IP address assignments
        (NEW_ADDR / DEL_ADDR) and routing table changes (NEW_ROUTE / DEL_ROUTE).
        Events clustered at <em>t&nbsp;=&nbsp;0</em> are an initial kernel state dump (not real
        changes). Subsequent events reveal live network reconfigurations: DHCP renewals,
        WiFi disconnections, LTE handovers.
        </p>""",
        unsafe_allow_html=True,
    )

    if not netlink_events:
        st.warning(
            "No Netlink events recorded in this trace. "
            "Netlink monitoring is enabled by default in tcpsnitch-2026."
        )
        return

    df_nl = pd.DataFrame(netlink_events)
    if df_nl.empty or "t_ms" not in df_nl.columns:
        st.warning("Netlink event data is empty or missing timestamps.")
        return

    df_nl = _extract_details(df_nl)

    theme = PLOTLY_THEME.copy()
    theme.pop("margin", None)


    n_new_addr  = (df_nl["msg_type"] == "NEW_ADDR").sum()
    n_del_addr  = (df_nl["msg_type"] == "DEL_ADDR").sum()
    n_new_route = (df_nl["msg_type"] == "NEW_ROUTE").sum()
    n_del_route = (df_nl["msg_type"] == "DEL_ROUTE").sum()
    n_interfaces = df_nl["if_index"].nunique()

    disruptions = _detect_network_events(df_nl)
    disruption_label = (
        disruptions[0]["label"] if disruptions else "None detected"
    )

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1: st.metric("Total Events",  f"{len(df_nl):,}")
    with c2: st.metric("NEW_ADDR",      f"{n_new_addr:,}")
    with c3: st.metric("DEL_ADDR",      f"{n_del_addr:,}")
    with c4: st.metric("NEW/DEL ROUTE", f"{n_new_route} / {n_del_route}")
    with c5: st.metric("Interfaces",    f"{n_interfaces}")
    with c6:
        max_len = 15
        if len(disruption_label) > max_len:
            short_label = disruption_label[:max_len] + "..."
        else:
            short_label = disruption_label
            
        st.metric("Disruption", short_label, help=disruption_label)

    st.divider()

    if disruptions:
        d = disruptions[0]
        st.markdown(
            f"""<div style="background:#1c2128;border-left:3px solid #e3b341;
            padding:12px 16px;border-radius:4px;margin-bottom:16px;">
            <span style="font-family:'IBM Plex Mono',monospace;font-size:0.72rem;
            color:#e3b341;text-transform:uppercase;letter-spacing:0.1em;">
            Network disruption detected</span><br/>
            <span style="color:#c9d1d9;">
            Interface connectivity lost at <b>t&nbsp;=&nbsp;{d['t_start_ms']/1000:.2f}s</b>
            and restored at <b>t&nbsp;=&nbsp;{d['t_end_ms']/1000:.2f}s. </b>
            Outage duration: <b>{(d['t_end_ms']-d['t_start_ms'])/1000:.1f}s</b>.
            Socket connections active during this window are expected to receive
            ECONNABORTED or ETIMEDOUT errors.
            </span>
            </div>""",
            unsafe_allow_html=True,
        )

    st.markdown(
        '<div class="section-header">Network Event Timeline</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        "<p style='font-size:0.75rem;color:#8b949e;'>"
        "All Netlink events plotted chronologically per interface. "
        "Events at <em>t&nbsp;&asymp;&nbsp;0</em> are the initial kernel state dump. "
        "Green = network attachment (NEW_*). Red = network removal (DEL_*). "
        "Triangles = address events. Diamonds = route events.</p>",
        unsafe_allow_html=True,
    )

    iface_labels = {}
    for iface, grp in df_nl.groupby("if_index"):
        ips = grp["ip"].dropna().unique().tolist()
        # Try to get if_name from data if present
        names = grp["if_name"].dropna().unique().tolist()
        names = [n for n in names if n]
        if names:
            iface_labels[iface] = f"{names[0]} (if{iface})"
        else:
            iface_labels[iface] = _build_iface_label(iface, ips) or f"if{iface}"

    df_nl["iface_label"] = df_nl["if_index"].map(iface_labels)

    style_map = {
        "NEW_ADDR":  {"color": "#3fb950", "symbol": "triangle-up",   "size": 14},
        "DEL_ADDR":  {"color": "#ff7b72", "symbol": "triangle-down", "size": 14},
        "NEW_ROUTE": {"color": "#56d364", "symbol": "diamond",        "size": 10},
        "DEL_ROUTE": {"color": "#e74c3c", "symbol": "diamond-open",   "size": 10},
    }

    fig_tl = go.Figure()

    for msg_type, style in style_map.items():
        subset = df_nl[df_nl["msg_type"] == msg_type]
        if subset.empty:
            continue

        hover_text = subset.apply(
            lambda r: (
                f"{r['msg_type']}<br>"
                f"Interface: {r['iface_label']}<br>"
                f"{'IP: ' + r['ip'] if r['ip'] else ''}"
                f"{'Dst: ' + r['dst'] if r.get('dst') else ''}"
                f"<br>Family: {r['family']}"
                f"<br>t = {r['t_ms']:.1f} ms"
            ),
            axis=1,
        )

        fig_tl.add_trace(go.Scatter(
            x=subset["t_ms"],
            y=subset["iface_label"],
            mode="markers",
            name=msg_type,
            marker=dict(
                size=style["size"],
                color=style["color"],
                symbol=style["symbol"],
                line=dict(width=1, color="#0d1117"),
            ),
            hovertemplate="%{text}<extra></extra>",
            text=hover_text,
        ))

    for d in disruptions:
        fig_tl.add_vrect(
            x0=d["t_start_ms"], x1=d["t_end_ms"],
            fillcolor="rgba(227,179,65,0.08)",
            layer="below", line_width=0,
            annotation_text="Outage",
            annotation_position="top left",
            annotation_font=dict(size=10, color="#e3b341"),
        )

    n_ifaces = df_nl["iface_label"].nunique()
    fig_tl.update_layout(
        **theme,
        height=max(280, n_ifaces * 65 + 60),
        margin=dict(l=160, r=20, t=20, b=50),
        xaxis_title="Time relative to trace start (ms)",
        yaxis_title="",
        legend=dict(
            orientation="h", yanchor="bottom", y=1.05,
            xanchor="center", x=0.5,
        ),
    )
    st.plotly_chart(fig_tl, use_container_width=True)

    st.divider()

    st.markdown(
        '<div class="section-header">Per-Interface Summary</div>',
        unsafe_allow_html=True,
    )

    iface_rows = []
    for iface, grp in df_nl.groupby("if_index"):
        label = iface_labels.get(iface, f"if{iface}")
        ips = [ip for ip in grp["ip"].dropna().unique() if ip]
        families = ", ".join(grp["family"].dropna().unique().tolist())
        iface_rows.append({
            "Interface": label,
            "NEW_ADDR":  (grp["msg_type"] == "NEW_ADDR").sum(),
            "DEL_ADDR":  (grp["msg_type"] == "DEL_ADDR").sum(),
            "NEW_ROUTE": (grp["msg_type"] == "NEW_ROUTE").sum(),
            "DEL_ROUTE": (grp["msg_type"] == "DEL_ROUTE").sum(),
            "Families":  families,
            "IPs Observed": ", ".join(ips[:4]) + ("…" if len(ips) > 4 else ""),
        })

    if iface_rows:
        st.dataframe(
            pd.DataFrame(iface_rows).sort_values("Interface"),
            use_container_width=True, hide_index=True,
        )

    st.divider()

    st.markdown(
        '<div class="section-header">Event Type Distribution</div>',
        unsafe_allow_html=True,
    )
    type_counts = df_nl["msg_type"].value_counts()
    fig_bar = go.Figure(go.Bar(
        x=type_counts.index.tolist(),
        y=type_counts.values.tolist(),
        marker_color=[style_map.get(t, {}).get("color", "#8b949e") for t in type_counts.index],
        text=[f"{v}" for v in type_counts.values],
        textposition="auto",
    ))
    fig_bar.update_layout(
        **theme, height=260,
        margin=dict(l=40, r=20, t=10, b=40),
        xaxis_title="Event Type", yaxis_title="Count",
    )
    st.plotly_chart(fig_bar, use_container_width=True)

    if not df.empty and "t_ms" in df.columns:
        st.divider()
        st.markdown(
            '<div class="section-header">Netlink Events vs Socket API Activity</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            "<p style='font-size:0.75rem;color:#8b949e;'>"
            "Socket API call density (500 ms bins) overlaid with network configuration events. "
            "A drop in socket activity after a DEL burst, followed by a recovery after a NEW burst, "
            "is the signature of an application-layer reconnection strategy.</p>",
            unsafe_allow_html=True,
        )

        df_copy = df.copy()
        df_copy["bin_ms"] = (df_copy["t_ms"] // 500) * 500
        sock_activity = df_copy.groupby("bin_ms").size().reset_index(name="api_calls")

        fig_corr = go.Figure()

        fig_corr.add_trace(go.Bar(
            x=sock_activity["bin_ms"],
            y=sock_activity["api_calls"],
            name="Socket API Calls (500ms bins)",
            marker_color="rgba(88,166,255,0.3)",
        ))

        real_nl = df_nl[df_nl["t_ms"] > 100]
        for _, row in real_nl.iterrows():
            color = style_map.get(row["msg_type"], {}).get("color", "#8b949e")
            fig_corr.add_vline(
                x=row["t_ms"], line_dash="dash",
                line_color=color, line_width=1, opacity=0.8,
            )

        for d in disruptions:
            fig_corr.add_vrect(
                x0=d["t_start_ms"], x1=d["t_end_ms"],
                fillcolor="rgba(227,179,65,0.08)",
                layer="below", line_width=0,
            )

        fig_corr.update_layout(
            **theme, height=300,
            margin=dict(l=40, r=20, t=10, b=40),
            xaxis_title="Time (ms)",
            yaxis_title="API Call Count",
            showlegend=True,
            legend=dict(
                orientation="h", yanchor="bottom", y=1.05,
                xanchor="center", x=0.5,
            ),
        )
        st.plotly_chart(fig_corr, use_container_width=True)

    with st.expander("View Raw Netlink Events"):
        cols_show = [c for c in ["t_ms", "msg_type", "iface_label", "family", "ip", "dst", "gateway"]
                     if c in df_nl.columns]
        st.dataframe(df_nl[cols_show].sort_values("t_ms"), use_container_width=True, hide_index=True)
