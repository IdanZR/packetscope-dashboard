"""English HTTP transaction view using the dashboard's existing Streamlit theme."""
import json
import pandas as pd
import streamlit as st
from analyzer import iso_time
from qa_ui import render_qa
from http_content import DISPLAY_LIMIT, message_bytes, message_text

TABLE_COLUMNS = ["transaction_id", "method", "host", "uri", "source", "source_port",
                 "destination", "destination_port", "status_code", "response_time_ms",
                 "request_frame", "response_frame", "match_status", "connection_id"]


def transaction_rows(transactions):
    return [{key: tx.get(key) for key in TABLE_COLUMNS} for tx in transactions]


def _message_view(message, title):
    st.subheader(title)
    if message is None:
        st.info(f"No {title.lower()} was safely matched in this capture.")
        return
    raw_tab, headers_tab, body_tab = st.tabs(["Raw message", "Headers", "Body preview"])
    with raw_tab:
        raw = message_bytes(message)
        full = False
        if len(raw) > DISPLAY_LIMIT:
            full = st.checkbox("Show entire captured message", key=f"full_{title}_{message['frame']}")
        text, shortened = message_text(message, full)
        code_height = min(400, max(180, (min(text.count("\n")+1,16))*22+30))
        st.code(text or message["start_line"], language="http", line_numbers=True, height=code_height)
        if shortened:
            st.caption(f"Showing the first {DISPLAY_LIMIT//1024} KiB. Enable the full view or download all {len(raw):,} captured bytes.")
        if not message["body_complete"]:
            st.warning("This message is incomplete in the capture. Missing bytes cannot be displayed.")
        st.caption("Original captured HTTP bytes, including headers and wire body. Binary or compressed bodies may not be readable as text.")
        st.download_button(f"Download {title.lower()} (.http)", raw, f"{title.lower()}_frame_{message['frame']}.http",
                           "application/octet-stream", key=f"wire_{title}_{message['frame']}")
    st.caption(f"First-byte frame: {message['frame']} · Header complete in frame: {message['header_complete_frame']}")
    st.caption(f"Message complete in frame: {message['complete_frame'] or 'Not fully captured'}")
    st.caption(f"First-byte time (UTC): {iso_time(message['timestamp']) or 'Not available'}")
    with headers_tab:
        if message["headers"]:
            st.dataframe(pd.DataFrame(message["headers"], columns=["Header", "Value"]),
                         hide_index=True, width="stretch", row_height=38)
        else:
            st.caption("No headers were present.")
    state = "Complete" if message["body_complete"] else "Incomplete"
    st.caption(f"Body: {state.lower()} · {message['body_bytes_captured']:,} captured bytes")
    for note in message["notes"]:
        st.warning(note)
    with body_tab:
        st.caption("Up to 2 KiB, displayed as plain UTF-8 text. Chunk framing is removed; content encodings such as gzip are not decoded.")
        st.code(message["body_preview"] or "No body bytes captured.", language=None)
        if message["body_preview_truncated"]:
            st.caption("The preview is shortened; the captured body contains more bytes.")


def render_http(capture):
    st.header("HTTP analysis")
    st.caption("Choose a stream and transaction, then ask a question or inspect its details. All HTTP tools are here.")
    transactions = capture.http_transactions
    for warning in capture.http_warnings:
        st.warning(warning)
    if not transactions:
        st.info("No readable HTTP/1.x messages were found. HTTPS is encrypted; HTTP/2, HTTP/3 and IP-fragment reassembly are not supported here.")
        return
    matched = sum(tx["match_status"] == "Matched" for tx in transactions)
    st.caption(f"{matched:,} matched transactions · {len(transactions) - matched:,} unmatched or uncertain entries")
    with st.expander("Browse and filter transactions"):
        host_col, state_col = st.columns(2)
        with host_col:
            hosts = sorted({tx["host"] for tx in transactions if tx["host"]})
            host = st.selectbox("HTTP host", ["All hosts"] + hosts, key="http_host")
        with state_col:
            state = st.selectbox("Transaction state", ["All states", "Matched", "No response captured", "No request captured", "Uncertain"], key="http_state")
        visible = [tx for tx in transactions if (host == "All hosts" or tx["host"] == host)
                   and (state == "All states" or tx["match_status"] == state)]
        if visible:
            _transaction_table(visible)
        st.caption("These filters narrow the selection below. Capture-wide questions still use all parsed HTTP transactions.")
    if not visible:
        st.info("No HTTP entries match these filters. Open Browse and filter transactions to change them.")
        return
    digest = st.session_state.get("capture_hash", "capture")
    suffix = digest[:16]
    connections = sorted({tx["connection_id"] for tx in visible})
    stream_key = f"qa_connection_{suffix}"
    transaction_key = f"http_transaction_{suffix}"
    if st.session_state.get(stream_key) not in connections:
        st.session_state[stream_key] = connections[0]
    def clear_table_selection():
        epoch_key=f"http_table_epoch_{suffix}"
        st.session_state[epoch_key]=st.session_state.get(epoch_key,0)+1
    with st.container(border=True):
        stream_col, transaction_col = st.columns(2)
        with stream_col:
            selected_connection = st.selectbox("Stream for questions", connections,
                format_func=lambda n: f"HTTP connection #{n}", key=stream_key,on_change=clear_table_selection)
        lookup = {tx["transaction_id"]: tx for tx in visible if tx["connection_id"] == selected_connection}
        if st.session_state.get(transaction_key) not in lookup:
            st.session_state[transaction_key] = next(iter(lookup))
        def label(identifier):
            tx = lookup[identifier]
            return f"#{identifier} · {tx['method'] or 'Response'} {tx['uri'] or ''} · {tx['status_code'] or tx['match_status']}"
        with transaction_col:
            selected_id = st.selectbox("Select a transaction", list(lookup), format_func=label,
                                      key=transaction_key,on_change=clear_table_selection)
        tx = lookup[selected_id]
        st.text(f"{tx['method'] or 'Response'} {tx['host'] or ''}{tx['uri'] or ''}")
        first, second, third = st.columns(3)
        first.metric("HTTP status", str(tx["status_code"]) if tx["status_code"] is not None else "N/A")
        second.metric("Response time", f"{tx['response_time_ms']:.3f} ms" if tx["response_time_ms"] is not None else "N/A")
        third.metric("Frames (req / res)", f"{tx['request_frame'] or '—'} / {tx['response_frame'] or '—'}")
        st.caption("Questions and details use this selection.")
        ask_tab, details_tab, evidence_tab = st.tabs(["Ask AI", "Request & response", "Packet evidence"],
                                                    key=f"http_view_{suffix}", on_change="rerun")
        with ask_tab:
            render_qa(capture, digest, selected_id, selected_connection)
        with details_tab:
            _transaction_details(tx)
        with evidence_tab:
            _transaction_evidence(capture, tx)


def _transaction_table(visible):
    suffix = st.session_state.get("capture_hash", "capture")[:16]
    table_key = f"http_table_{suffix}_{st.session_state.get(f'http_table_epoch_{suffix}',0)}"
    def select_row():
        selected = st.session_state[table_key]["selection"]["rows"]
        if selected:
            tx = visible[selected[0]]
            st.session_state[f"qa_connection_{suffix}"] = tx["connection_id"]
            st.session_state[f"http_transaction_{suffix}"] = tx["transaction_id"]
    st.caption("Select a row to inspect it, ask a question, or download its full request and response below.")
    st.dataframe(pd.DataFrame(transaction_rows(visible)), hide_index=True, width="stretch",
                 key=table_key, on_select=select_row, selection_mode="single-row", row_height=40,
                 column_order=["transaction_id", "method", "host", "uri", "status_code", "response_time_ms", "request_frame", "response_frame", "match_status"],
                 column_config={"transaction_id": "ID", "method": "Method", "host": "Host", "uri": "URI",
                                "source": "Client IP", "source_port": st.column_config.NumberColumn("Client port", format="%d"),
                                "destination": "Server IP", "destination_port": st.column_config.NumberColumn("Server port", format="%d"),
                                "status_code": st.column_config.NumberColumn("Status", format="%d"),
                                "response_time_ms": st.column_config.NumberColumn("Response time (ms)", format="%.3f"),
                                "request_frame": "Request frame", "response_frame": "Response frame",
                                "match_status": "State", "connection_id": "Connection"})
    st.caption("Response time and frames use message completion. First-byte evidence is available in Request & response.")


def _transaction_details(tx):
    st.subheader(f"Transaction #{tx['transaction_id']}")
    st.text(f"{tx['source']}:{tx['source_port']} → {tx['destination']}:{tx['destination_port']}")
    st.caption(f"Connection {tx['connection_id']} · {tx['match_status']} · Host: {tx['host'] or 'Not captured'}")
    for note in tx["notes"]:
        st.warning(note)
    if tx["first_byte_delay_ms"] is not None:
        st.caption(f"First-byte delay: {tx['first_byte_delay_ms']:.3f} ms (first request byte to first final-response byte).")
    request_col, response_col = st.columns(2)
    with request_col:
        _message_view(tx["request"], "Request")
    with response_col:
        _message_view(tx["response"], "Response")
    if tx["informational_responses"]:
        with st.expander("Informational responses (1xx)"):
            for response in tx["informational_responses"]:
                st.code(f"Frame {response['frame']}: {response['start_line']}", language=None)


def _transaction_evidence(capture, tx):
    st.write("**Packet evidence**")
    roles = {}
    for role, message in [("Request", tx["request"]), ("Response", tx["response"])]:
        if message:
            for frame in message["frames"]:
                roles.setdefault(frame, []).append(role)
    for message in tx["informational_responses"]:
        for frame in message["frames"]:
            roles.setdefault(frame, []).append("Informational response")
    evidence = [dict(frame=r["frame"], role=", ".join(roles[r["frame"]]), time_utc=iso_time(r["timestamp"]),
                     source=r["source"], destination=r["destination"], bytes=r["wire_bytes"])
                for r in capture.rows if r["frame"] in roles]
    st.dataframe(pd.DataFrame(evidence), hide_index=True, width="stretch",
                 column_config={"frame": "Frame", "role": "Role", "time_utc": "Time (UTC)",
                                "source": "Source", "destination": "Destination", "bytes": "Bytes"})
    st.download_button("Download selected transaction (JSON)", json.dumps(tx, ensure_ascii=False, indent=2),
                       file_name=f"http_transaction_{tx['transaction_id']}.json", mime="application/json")
