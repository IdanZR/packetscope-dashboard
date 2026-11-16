"""Free local Q&A in the existing light dashboard design."""
import json
import pandas as pd
import streamlit as st
from packetscope.ai.local import availability
from packetscope.ai.queries import ask
from packetscope.ai.model_setup import LocalAIError
from packetscope.ai.settings import active_provider

from packetscope.paths import REPORTS_DIR

ROOT = REPORTS_DIR


def render_qa(capture, digest, selected_tx, selected_connection):
    provider = active_provider()
    if provider == "gemini":
        from packetscope.ai.gemini import availability as gemini_availability
        ready, message = gemini_availability()
        ready = ready or bool(st.session_state.get("gemini_key_override"))
        label = "Ask Gemini"
    else:
        ready, message = availability()
        label = "Ask local AI"
    st.caption(message)
    if not ready:
        st.info(message)
        with st.expander("Set up free local AI") if provider == "local" else st.expander("Gemini setup"):
            if provider == "local":
                st.write("On Windows, run scripts/setup_ai.bat once. It installs the CPU library and downloads a free model (about 640 MB). Then restart the dashboard. See docs/LOCAL_AI.md for terminal commands.")
            else:
                st.write("Open AI settings to enter an API key for this session, or set GEMINI_API_KEY before starting the app. See docs/GEMINI.md.")
    txs = capture.http_transactions
    if not txs:
        st.info("No readable HTTP transactions are available for these questions. Upload a plaintext HTTP capture or choose the HTTP transactions sample.")
        return
    suffix = digest[:16]
    question = st.text_input("Your question", max_chars=1200, key=f"qa_question_{suffix}",
                             placeholder="What status did the selected request return?")
    st.caption("Try: Which request was slowest? · How many requests were sent to Host example.test? · What happened in the selected stream?")
    submitted = st.button(label, type="primary", disabled=not ready, key=f"qa_ask_{suffix}")
    state_key = f"qa_answer_{suffix}"
    previous = st.session_state.get(state_key)
    if previous and ((previous.get("selected_transaction"), previous.get("selected_connection")) != (selected_tx, selected_connection)
                     or previous.get("provider", "local") != provider
                     or provider == "gemini" and previous.get("model") != st.session_state.get("gemini_model")):
        st.session_state.pop(state_key, None)
    if submitted:
        try:
            with st.spinner("Interpreting your question..."):
                if provider == "gemini":
                    result = ask(capture, question, selected_tx, selected_connection, digest, provider="gemini",
                                 model=st.session_state.get("gemini_model"), api_key=st.session_state.get("gemini_key_override") or None)
                else:
                    result = ask(capture, question, selected_tx, selected_connection, digest)
            result["selected_transaction"] = selected_tx
            result["selected_connection"] = selected_connection
            st.session_state[state_key] = result
        except LocalAIError as exc:
            st.session_state.pop(state_key, None)
            st.error(str(exc))
    result = st.session_state.get(state_key)
    if result:
        st.subheader("Answer")
        st.caption(f"Question: {result['question']}")
        # Packet strings stay plain text, never Markdown/HTML instructions or links.
        st.text(result["answer"])
        st.caption(f"Answer context: transaction #{result['selected_transaction']} · connection #{result['selected_connection']}")
        answer_transactions = [t for t in txs if t["transaction_id"] in result["transaction_ids"]]
        if answer_transactions:
            answer_tx = st.selectbox("Inspect a transaction from this answer", [t["transaction_id"] for t in answer_transactions],
                                     key=f"qa_inspect_{suffix}")
            def inspect_answer():
                tx = next(t for t in answer_transactions if t["transaction_id"] == answer_tx)
                st.session_state[f"qa_connection_{suffix}"] = tx["connection_id"]
                st.session_state[f"http_transaction_{suffix}"] = tx["transaction_id"]
                st.session_state[f"http_view_{suffix}"] = "Request & response"
                st.session_state.http_host = "All hosts"
                st.session_state.http_state = "All states"
                epoch_key=f"http_table_epoch_{suffix}"
                st.session_state[epoch_key]=st.session_state.get(epoch_key,0)+1
            st.button("Open full request & response", on_click=inspect_answer)
        if result["evidence"]:
            st.write("**Packet evidence**")
            st.dataframe(pd.DataFrame(result["evidence"][:500]), hide_index=True, width="stretch")
            if len(result["evidence"]) > 500:
                st.caption("Showing the first 500 evidence rows. Download the answer for all rows.")
        else:
            st.caption("No packet evidence for this result. Zero counts describe the parsed capture, not traffic outside it.")
        with st.expander("How this answer was produced"):
            st.caption(message)
            st.write("The selected model interprets your question. Python computes the answer from all parsed HTTP transactions and selects the original packet evidence. Browse filters only narrow the selection; capture-wide questions use all transactions. The model receives extracted fields, never the PCAP file, headers or bodies.")
            st.json(result["plan"])
            st.caption("Check the interpretation if the answer looks unexpected. HTTPS contents and unsupported questions cannot be answered here.")
        st.download_button("Download answer and evidence", json.dumps(result, indent=2).encode(),
                           "packetscope_answer.json", "application/json", key=f"qa_export_{suffix}")
    with st.expander("Validation: six reference questions"):
        st.caption("Synthetic practice capture with known reference answers. These checks do not replace comparison with your own manual capture.")
        report_path = ROOT/("validation_gemini.json" if provider == "gemini" else "validation_ai.json")
        report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else None
        if report:
            st.caption(f"Recorded {provider} run: {report['created_utc']} · {report['passed']}/{report['total']} passed")
            st.dataframe(pd.DataFrame([dict(Question=c["question"], Reference=json.dumps(c["expected"]),
                Actual=json.dumps(c["actual"]), Frames=", ".join(map(str, c["actual_frames"])),
                Result="Pass" if c["passed"] else "Fail") for c in report["cases"]]), hide_index=True, width="stretch")
            st.caption("The report always refers to sample_data/http_transactions.pcap, regardless of the open file.")
            st.download_button("Download validation report", report_path.read_bytes(), "validation_ai.json", "application/json")
        if st.button("Run six checks on the practice capture", disabled=not ready):
            from packetscope.ai.validation import run_checks
            try:
                bar = st.progress(0, text="Testing local AI on the synthetic capture...")
                live = run_checks(lambda i, n: bar.progress(i/n), provider=provider,
                                  model=st.session_state.get("gemini_model"), api_key=st.session_state.get("gemini_key_override") or None)
                bar.progress(1.0)
                st.write(f"Live result: {live['passed']}/{live['total']} passed")
                st.json(live, expanded=False)
            except LocalAIError as exc:
                st.error(str(exc))
    with st.expander("A documented AI mistake and its fix"):
        error_path = ROOT/"ai_error_case.json"
        if error_path.exists():
            error = json.loads(error_path.read_text(encoding="utf-8"))
            st.write("In the baseline experiment, only matched transactions were sent to the model. It counted three requests to example.test. The complete capture has four: /pending in frame 8 had no response and was omitted from that context.")
            st.write("The corrected version asks AI for a structured query and counts all parsed requests in Python, including unanswered requests. The six-question report checks this correction.")
            st.code(error["raw_model_output"], language="json")
            st.download_button("Download the recorded error case", error_path.read_bytes(), "ai_error_case.json", "application/json")
        else:
            st.caption("Run python qa_validation.py --baseline to record the experiment.")
