"""PacketScope. Run: python -m streamlit run app.py"""
import csv
import hashlib
import io
import json
from packetscope.paths import PROJECT_ROOT
import pandas as pd
import streamlit as st
from packetscope.analysis.capture import ANALYSIS_VERSION, CaptureError, analyze_capture, endpoints, iso_time, summarize
from packetscope.ui.http import render_http
from packetscope.ui.charts import traffic_charts
from packetscope.ui.theme import install_style
from packetscope.ai.settings import render_settings

ROOT = PROJECT_ROOT


def human_bytes(value):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:,.1f} {unit}"
        value /= 1024


def csv_bytes(rows):
    if not rows:
        return b""
    out=io.StringIO(newline="")
    writer=csv.DictWriter(out,fieldnames=list(rows[0]))
    writer.writeheader()
    for row in rows:
        writer.writerow({k:"'"+v if isinstance(v,str) and v.startswith(("=","+","-","@")) else v for k,v in row.items()})
    return out.getvalue().encode("utf-8-sig")


def render():
    st.set_page_config(page_title="PacketScope | Capture intelligence", page_icon=":material/hub:", layout="wide")
    install_style()

    title_col, settings_col, appearance_col=st.columns([5,1.3,1.3],vertical_alignment="center")
    with title_col:
        st.title("PacketScope")
        st.caption("Capture intelligence · Explore traffic. Inspect conversations. Ask with evidence.")
    with settings_col:
        render_settings()
    with appearance_col:
        with st.popover("Appearance",icon=":material/contrast:"):
            st.write("**Light & Dark mode**")
            st.caption("Choose Light, Dark or System in the ⋮ menu at the top right. Tables, charts and message viewers follow your theme.")

    with st.expander("Open a capture",expanded=False):
        upload_col,sample_col=st.columns([2,1])
        with upload_col:
            uploaded=st.file_uploader("Choose a PCAP or PCAPNG file",type=["pcap","pcapng","cap"],
                help="Up to 100 MiB and 250,000 packets. PNG images are not capture files.")
        with sample_col:
            demo=st.toggle("Use sample capture",value=uploaded is None,disabled=uploaded is not None)
            sample_choice=st.selectbox("Sample capture",["Overview","HTTP transactions"],key="sample_choice") if demo and uploaded is None else "Overview"

    data=None
    if uploaded is not None:
        data,filename,is_demo=uploaded.getvalue(),uploaded.name,False
    elif demo:
        path=ROOT/"sample_data"/("http_transactions.pcap" if sample_choice=="HTTP transactions" else "demo.pcap")
        if path.exists():
            data,filename,is_demo=path.read_bytes(),path.name,True
        else:
            st.error("Sample file missing. Run python scripts/make_demo.py or upload a capture.")
    if data is None:
        st.info("Choose a capture file above or turn on the sample.")
        st.stop()

    digest=hashlib.sha256(data).hexdigest()
    if st.session_state.get("capture_hash") != digest or st.session_state.get("analysis_version") != ANALYSIS_VERSION:
        try:
            with st.spinner("Reading packets and reconstructing HTTP..."):
                st.session_state.capture=analyze_capture(data)
            st.session_state.capture_hash=digest
            st.session_state.analysis_version=ANALYSIS_VERSION
            for key in ("selected_protocols","selected_endpoint","http_host","http_state"):
                st.session_state.pop(key,None)
        except CaptureError as exc:
            st.error(f"This file could not be analyzed: {exc}")
            st.stop()
    capture=st.session_state.capture
    all_rows=capture.rows
    overall=summarize(all_rows)
    suffix=digest[:16]

    st.caption(f"{filename}  /  {capture.format}  /  {human_bytes(len(data))}")
    if is_demo:
        st.info("Synthetic sample capture · practice data with known answers, not your manual capture.",icon=":material/science:")
    for warning in capture.warnings:
        st.warning(warning)
    cards=st.columns(4)
    cards[0].metric("Total packets",f"{overall['packet_count']:,}")
    cards[1].metric("Duration",f"{overall['duration_seconds']:.2f} s" if overall["duration_seconds"] is not None else "N/A")
    cards[2].metric("Traffic volume",human_bytes(overall["wire_bytes"]))
    cards[3].metric("Endpoints",f"{len(endpoints(all_rows)):,}")
    with st.expander("Capture times & scope"):
        st.text(f"Start (UTC): {overall['start'] or 'Not available'}")
        st.text(f"End (UTC): {overall['end'] or 'Not available'}")
        if overall["duration_seconds"] is not None:
            st.caption(f"Exact duration: {overall['duration_seconds']:.6f} seconds.")
        st.caption("Overview metrics always cover the full capture. Volume uses original recorded packet lengths.")
    if not all_rows:
        st.info("This valid capture contains no packets.")
        st.stop()

    traffic_tab,http_tab,packet_tab,report_tab=st.tabs(["Traffic overview","HTTP & AI","Packets & endpoints","Reports"],
        key="main_view",on_change="rerun")

    with traffic_tab:
        st.subheader("Traffic overview")
        filter1,filter2=st.columns([1.4,1])
        with filter1:
            options=sorted({r["protocol"] for r in all_rows})
            chosen=st.multiselect("Protocols",options,default=options,key="selected_protocols")
        with filter2:
            addresses=sorted({r[k] for r in all_rows for k in ("source","destination") if r[k]})
            address=st.selectbox("Source or destination address",["All endpoints"]+addresses,key="selected_endpoint")
        rows=[r for r in all_rows if r["protocol"] in chosen and
              (address=="All endpoints" or address in (r["source"],r["destination"]))]
        summary=summarize(rows)
        st.caption(f"{len(rows):,} of {len(all_rows):,} packets · {human_bytes(summary['wire_bytes'])} · filters also apply to packet tables and exports")
        with st.container(key="traffic_visuals"):
            traffic_charts(rows,capture.http_transactions)

    with http_tab:
        render_http(capture)

    filter_tag=hashlib.sha256(json.dumps([chosen,address]).encode()).hexdigest()[:8]
    table_scope=f"{suffix}_{filter_tag}"
    with packet_tab:
        st.subheader("Explore the evidence")
        endpoint_tab,protocol_tab,frames_tab=st.tabs(["Endpoints","Protocols","Packets"])
        if not rows:
            st.info("No packets match the traffic filters. Change them in Traffic overview.")
        else:
            with endpoint_tab:
                st.caption("Select an endpoint to isolate its traffic or export its packets.")
                limit=st.selectbox("Addresses to show",[10,25,50,100],key="endpoint_limit")
                endpoint_rows=endpoints(rows)[:limit]
                selected=st.dataframe(pd.DataFrame(endpoint_rows),hide_index=True,width="stretch",row_height=40,
                    key=f"endpoint_table_{table_scope}",on_select="rerun",selection_mode="single-row",
                    column_order=["address","address_type","packets","sent_packets","received_packets","bytes","first_frame"],
                    column_config={"address":"Address","address_type":"Type","packets":"Packets","sent_packets":"Sent",
                                   "received_packets":"Received","bytes":"Total bytes","first_frame":"First frame"})
                if selected.selection.rows:
                    endpoint=endpoint_rows[selected.selection.rows[0]]["address"]
                    st.text(f"Selected endpoint: {endpoint}")
                    def focus_endpoint():
                        st.session_state.selected_endpoint=endpoint
                        st.session_state.main_view="Traffic overview"
                    st.button("Filter traffic to this endpoint",on_click=focus_endpoint,icon=":material/filter_alt:")
                    selected_rows=[r for r in rows if endpoint in (r["source"],r["destination"])]
                    st.download_button("Export endpoint packets",csv_bytes(selected_rows),"endpoint_packets.csv","text/csv")
                st.caption("Endpoint involvement can count a packet twice across different endpoints.")
            with protocol_tab:
                st.dataframe(pd.DataFrame(summary["protocols"]),hide_index=True,width="stretch",row_height=40,
                    column_config={"protocol":"Protocol","packets":"Packets","percent":"Share (%)","first_frame":"First frame"})
            with frames_tab:
                st.caption("Select a frame to inspect its metadata, export it or open its HTTP conversation.")
                page=int(st.number_input("Page (200 packets per page)",min_value=1,max_value=max(1,(len(rows)+199)//200),
                                         value=1,key=f"packet_page_{table_scope}"))
                visible=[dict(r,time_utc=iso_time(r["timestamp"])) for r in rows[(page-1)*200:page*200]]
                selected=st.dataframe(pd.DataFrame(visible),hide_index=True,width="stretch",row_height=38,
                    key=f"packet_table_{table_scope}_{page}",on_select="rerun",selection_mode="single-row",
                    column_order=["frame","time_utc","source","destination","protocol","wire_bytes","source_port","destination_port","layers"],
                    column_config={"frame":"Frame","time_utc":"Time (UTC)","source":"Source","destination":"Destination",
                        "protocol":"Protocol","wire_bytes":"Bytes","source_port":"Source port","destination_port":"Destination port","layers":"Layers"})
                if selected.selection.rows:
                    packet=visible[selected.selection.rows[0]]
                    with st.container(border=True):
                        st.subheader(f"Frame {packet['frame']}")
                        st.json(packet,expanded=True)
                        st.download_button("Download selected frame metadata",json.dumps(packet,indent=2),"selected_frame.json","application/json")
                        related=[t for t in capture.http_transactions if any(packet["frame"] in (t[side] or {}).get("frames",[]) for side in ("request","response"))]
                        if related:
                            tx_id=st.selectbox("Related HTTP transaction",[t["transaction_id"] for t in related])
                            def open_related():
                                tx=next(t for t in related if t["transaction_id"]==tx_id)
                                st.session_state[f"qa_connection_{suffix}"]=tx["connection_id"]
                                st.session_state[f"http_transaction_{suffix}"]=tx_id
                                st.session_state[f"http_view_{suffix}"]="Request & response"
                                st.session_state.main_view="HTTP & AI"
                                st.session_state.http_host="All hosts"
                                st.session_state.http_state="All states"
                                epoch_key=f"http_table_epoch_{suffix}"
                                st.session_state[epoch_key]=st.session_state.get(epoch_key,0)+1
                            st.button("Open full HTTP exchange",on_click=open_related,icon=":material/code:")

    with report_tab:
        st.subheader("Export & methodology")
        st.caption("Exports include the current filters. Gemini credentials and AI session settings are excluded.")
        report=dict(schema_version=2,filename=filename,sha256=digest,capture_format=capture.format,
            synthetic_demo=is_demo,full_capture=overall,filtered_summary=summary,
            filters=dict(protocols=chosen,endpoint=address),warnings=capture.warnings,
            filtered_endpoints=endpoints(rows),http_transactions=capture.http_transactions,http_warnings=capture.http_warnings)
        left,right=st.columns(2)
        left.download_button("Download summary (JSON)",json.dumps(report,ensure_ascii=False,indent=2),"capture_summary.json","application/json",width="stretch")
        right.download_button("Download packets (CSV)",csv_bytes(rows),"filtered_packets.csv","text/csv",width="stretch")
        with st.expander("How these results are calculated"):
            st.write("Every valid packet record is counted. Duration is the difference between the earliest and latest available UTC timestamps. Traffic volume uses original recorded lengths. Each packet receives one primary protocol label; endpoint totals can count a packet twice.")
            st.write("HTTP/1.x is reconstructed from captured TCP bytes. Response time measures request completion to final-response completion. Gaps, conflicting overlaps and ambiguous framing disable pairing. Missing timestamps and incomplete messages have no completion time. HTTP/2, HTTP/3, HTTPS decryption and IP-fragment reassembly are not supported.")
            st.write("Limits: 100 MiB per file, 250,000 packets, 4 MiB TCP payload per direction, 32 MiB total payload and 10,000 HTTP entries. Raw message downloads preserve the captured bytes, including chunk framing and compressed or binary bodies. A partial capture cannot provide missing bytes.")
            st.code(f"SHA-256: {digest}",language=None)
        with st.expander("Assignment coverage"):
            st.dataframe(pd.DataFrame([
                {"Requirements":"23–26","Location":"Capture source, metrics, Traffic overview"},
                {"Requirements":"27–29","Location":"HTTP & AI: transaction selection, raw messages and evidence"},
                {"Requirements":"30–32","Location":"Ask AI: Gemini or local Qwen with frame evidence"},
                {"Requirements":"33–34","Location":"Reference questions, recorded validation and documented mistakes"}]),hide_index=True,width="stretch")
            st.caption("Reference questions use synthetic data. Compare with your own manual capture before submission. See README.md, docs/AI_VALIDATION.md and docs/GEMINI.md.")
    st.caption("PacketScope  /  Dashboard V1  /  Evidence-first capture analysis")
