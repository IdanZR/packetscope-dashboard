"""Explicit provider choice and session-only credential override."""
import streamlit as st
from credentials import load_key
from gemini_client import MODEL_NAME, check_connection
from setup_local_ai import LocalAIError


def render_settings():
    with st.popover("AI settings", icon=":material/tune:"):
        st.selectbox("AI provider", ["Gemini", "Local Qwen"],
                     index=0 if load_key() else 1, key="ai_provider")
        if st.session_state.ai_provider == "Gemini":
            st.selectbox("Gemini model", [MODEL_NAME, "gemini-3.6-flash", "gemini-2.5-flash"], key="gemini_model")
            st.text_input("API key for this session", type="password", key="gemini_key_override",
                          help="Optional override. It stays in this session and is excluded from exports.")
            st.caption("Environment credential configured." if load_key() else "Enter a key above or launch with start_gemini.bat.")
            st.caption("When you ask, your question and extracted HTTP metadata are sent to Google. The PCAP file, headers and bodies stay local. Usage is subject to your Google account's quota and pricing.")
            if st.button("Test Gemini connection"):
                try:
                    models=check_connection(st.session_state.get("gemini_key_override") or None)
                    selected=st.session_state.gemini_model
                    if selected in models:
                        st.success("Connected. The selected model is available.")
                    else:
                        st.warning("Connected, but the selected model was not listed for this key.")
                except LocalAIError as exc:
                    st.error(str(exc))
        else:
            st.caption("Qwen runs on this computer without an API key. See LOCAL_AI.md for the one-time model setup.")


def active_provider():
    return "gemini" if st.session_state.get("ai_provider", "Local Qwen") == "Gemini" else "local"
