# Free local AI

PacketScope uses **Qwen3-0.6B-Q8_0** on your CPU through **llama-cpp-python 0.3.36**. No account, API key, paid service or inference server is required. Questions and extracted capture data stay inside the Python process. Internet is needed for installation and the one-time model download (639,446,688 bytes, about 640 MB). Model files are excluded from the source ZIP.

## Windows

Run `setup_ai.bat` once, then `start.bat`. Alternatively, in the same virtual environment used by Streamlit:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-ai.txt
.\.venv\Scripts\python.exe setup_local_ai.py
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Use Python 3.12 or 3.13, 64-bit. The tested machine runs Windows x64 with an Intel CPU and 16 GB RAM. The small model is intended for a local course demo; allow several seconds to tens of seconds per question, depending on hardware. Loading is lazy, so opening the dashboard does not load the model. Restart Streamlit after installation if it was already open. Core capture analysis works without the optional AI library/model.

For macOS/Linux use `.venv/bin/python` in the same commands. Official CPU wheels cover common platforms, but those platforms have not been tested for this project. If no compatible wheel exists, use the library's official build instructions; do not disable operating-system security controls. A standalone llama.cpp executable was blocked by Application Control on the development PC, so the delivered implementation uses the working Python library instead.

## How questions work

1. Python parses the capture and reconstructs plaintext HTTP/1.x transactions.
2. The local model receives the question, totals, selection context, and a catalog of at most 12 extracted transaction summaries. Long strings are shortened to 160 characters. It does not receive the capture file, headers or bodies.
3. Grammar-constrained inference produces a JSON query: operation, Host, URI, method and optional IDs. The model chooses the operation; Python verifies types and accepts selectors only if they occur explicitly in the question. Implicit selection is resolved from the dashboard.
4. Python executes the query against **all** parsed transactions, not the catalog sample. It generates the factual answer and original frame/timestamp evidence. Evidence tables show up to 500 rows; the answer download contains all rows.

Supported questions include slowest completed request, status of a URI or selected transaction, count to an exact Host, selected HTTP connection summary, and unanswered requests. UI and tested questions are in English. This is a small intent model, so review the interpreted query in **How this answer was produced**. Unsupported questions request a different question; ambiguous status queries request a unique transaction. It cannot decrypt HTTPS or analyze HTTP/2/3, DNS contents, arbitrary headers or bodies.

In **HTTP analysis**, **Stream for questions** and **Select a transaction** sit together above the **Ask AI**, **Request & response**, and **Packet evidence** tabs. All tabs share that selection. Changing streams selects a transaction from the new stream; changing either selection clears the previous answer so it cannot be mistaken for the new context. The question text stays available to ask again. Browse filters narrow the selection, while capture-wide questions still use all transactions. Dashboard connection IDs are not Wireshark `tcp.stream` indices. Response time is measured from request completion to response completion, rather than time to first byte. Counts concern reconstructed requests within the capture and its documented parsing limits; absence of a response is not proof that the server never responded.

## Reproduce the recorded experiments

```powershell
.\.venv\Scripts\python.exe qa_validation.py
# Also reproduce the intentionally flawed baseline retrieval:
.\.venv\Scripts\python.exe qa_validation.py --baseline
```

The command writes `validation_ai.json`; `--baseline` additionally writes `ai_error_case.json`. The dashboard can rerun the six checks without writing files. Reference results use the synthetic practice capture, not a student's manual capture. See `AI_VALIDATION.md` for the comparison and actual errors.

## Sources and licenses

- [Official Qwen GGUF model and Apache 2.0 license](https://huggingface.co/Qwen/Qwen3-0.6B-GGUF). Download is pinned to commit `23749fefcc72300e3a2ad315e1317431b06b590a` and checked against SHA-256 `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031` before loading.
- [Official llama-cpp-python CPU installation instructions](https://github.com/abetlen/llama-cpp-python#installation), [MIT license](https://github.com/abetlen/llama-cpp-python/blob/main/LICENSE.md). `requirements-ai.txt` pins the CPU wheel version; pip verifies any hash supplied by its index.
- [Official Qwen3 usage and non-thinking mode](https://huggingface.co/Qwen/Qwen3-0.6B). `local_ai.py` uses ChatML and an empty thinking prefix for the constrained query.

No model or third-party binaries are redistributed in the source archive. Downloaded model data stays in `.local_ai/`. Keep the model's license with any model redistribution.
