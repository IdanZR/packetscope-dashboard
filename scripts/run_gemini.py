"""Prompt without echo, then launch Streamlit with an in-memory credential."""
import getpass
import os
from pathlib import Path
import subprocess
import sys

if __name__ == "__main__":
    key = os.environ.get("GEMINI_API_KEY") or getpass.getpass("Gemini API key (hidden): ").strip()
    if not key:
        raise SystemExit("No key supplied. Use start.bat for local analysis.")
    environment = os.environ.copy()
    environment["GEMINI_API_KEY"] = key
    del key
    raise SystemExit(subprocess.call([sys.executable,"-m","streamlit","run","app.py"],
                                    cwd=Path(__file__).resolve().parents[1],env=environment))
