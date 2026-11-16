"""Credentials are read from process memory, never source or exports."""
import os


def load_key():
    return os.environ.get("GEMINI_API_KEY", "").strip()
