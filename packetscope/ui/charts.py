"""Capture-derived charts, with consistent themes, units and evidence tooltips."""
from collections import Counter
import pandas as pd
import plotly.express as px
import streamlit as st
from packetscope.analysis.capture import endpoints, summarize, timeline
from packetscope.ui.theme import ACCENTS, style_chart

CONFIG = dict(displayModeBar="hover", displaylogo=False, modeBarButtonsToRemove=["lasso2d", "select2d", "autoScale2d"])


def plot(fig, key, height=320):
    st.plotly_chart(style_chart(fig, height), width="stretch", key=key, config=CONFIG, theme="streamlit")


def traffic_charts(rows, transactions):
    if not rows:
        st.info("No packets match these filters.")
        return
    summary = summarize(rows)
    left, right = st.columns([1.5, 1])
    with left, st.container(border=True):
        st.subheader("Traffic over time")
        st.caption("Captured traffic volume across the selected time range.")
        series = timeline(rows)
        if series:
            fig = px.area(pd.DataFrame(series), x="seconds", y="bytes", color_discrete_sequence=[ACCENTS[0]],
                labels={"seconds":"Seconds from first matching packet", "bytes":"Original packet bytes"})
            fig.update_traces(line_width=2.5, hovertemplate="%{x:.3f} s<br>%{y:,} bytes<extra></extra>")
            plot(fig,"timeline")
            st.caption(f"{series[0]['bin_seconds']:.6f} s per bin · empty bins included · not throughput")
        else:
            st.info("No timestamps are available for these packets.")
    with right, st.container(border=True):
        st.subheader("Protocol mix")
        st.caption("One primary protocol per packet.")
        protocol_data = pd.DataFrame(summary["protocols"])
        fig = px.pie(protocol_data, names="protocol", values="packets", hole=.72,
                     color_discrete_sequence=ACCENTS)
        fig.update_traces(textinfo="percent", textposition="outside",
                          hovertemplate="%{label}<br>%{value:,} packets · %{percent}<extra></extra>")
        fig.update_layout(annotations=[dict(text=f"<b>{len(rows):,}</b><br>packets",x=.5,y=.5,showarrow=False,font_size=17)])
        plot(fig,"protocols")
    with st.container(border=True):
        st.subheader("Busiest endpoints")
        data = pd.DataFrame(endpoints(rows)[:8])
        fig = px.bar(data, x="bytes", y="address", orientation="h", color_discrete_sequence=[ACCENTS[1]],
            labels={"bytes":"Original packet bytes", "address":""}, custom_data=["packets"])
        fig.update_yaxes(autorange="reversed")
        fig.update_traces(hovertemplate="%{y}<br>%{x:,} bytes · %{customdata[0]:,} packets<extra></extra>")
        plot(fig,"endpoint_volume",300)
        st.caption("A packet may involve two endpoints, so endpoint totals can count it twice.")
    http_charts(transactions)


def http_charts(transactions):
    if not transactions:
        return
    st.subheader("HTTP performance")
    st.caption("Full-capture HTTP metrics. Packet filters above do not change these charts.")
    left, right = st.columns([1.5,1])
    timed = sorted([t for t in transactions if t["response_time_ms"] is not None],
                   key=lambda t: t["response_time_ms"], reverse=True)[:15]
    with left, st.container(border=True):
        st.subheader("Slowest completed requests")
        if timed:
            data = pd.DataFrame([dict(label=f"#{t['transaction_id']} {t['method']} {t['uri'][:60]}",
                ms=t["response_time_ms"], status=str(t["status_code"]), request=t["request_frame"], response=t["response_frame"]) for t in timed])
            fig=px.bar(data,x="ms",y="label",orientation="h",color="status",custom_data=["request","response","status"],
                labels={"ms":"Response time (ms)","label":"","status":"Status"}, color_discrete_sequence=ACCENTS)
            fig.update_yaxes(autorange="reversed")
            fig.update_traces(hovertemplate="%{y}<br>%{x:.3f} ms · HTTP %{customdata[2]}<br>Frames %{customdata[0]} → %{customdata[1]}<extra></extra>")
            fig.update_layout(showlegend=False)
            plot(fig,"http_latency",max(280,min(520,len(timed)*32+70)))
        else:
            st.info("No safely measured complete response times.")
    with right, st.container(border=True):
        st.subheader("Response outcomes")
        counts=Counter(str(t["status_code"]) if t["match_status"]=="Matched" else t["match_status"] for t in transactions)
        data=pd.DataFrame([dict(outcome=k,count=v) for k,v in counts.items()])
        fig=px.bar(data,y="outcome",x="count",orientation="h",color="outcome",text="count",color_discrete_sequence=ACCENTS,
                   labels={"outcome":"","count":"HTTP entries"})
        fig.update_layout(showlegend=False)
        fig.update_xaxes(dtick=1)
        fig.update_yaxes(autorange="reversed")
        plot(fig,"http_outcomes")
