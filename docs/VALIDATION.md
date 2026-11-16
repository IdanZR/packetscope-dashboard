# Validation — Dashboard V1, requirements 23–34

The repository is organized into `packetscope/` (application), `docs/`, `reports/`, `scripts/`, `requirements/`, `sample_data/` and `tests/`. The root `app.py` remains the Streamlit entry point. After moving the modules, all 55 tests passed again, and sample/report/model paths, documentation links and the source archive were checked. Recorded model reports were moved without changing their contents; no new cloud inference was needed for this reorganization.

All 55 automated tests passed on Windows with Python 3.12, Streamlit 1.67.0, Scapy 2.8.0, Plotly 7.1.0 and pandas 2.3.3. They include capture/HTTP reconstruction, UI, query execution, lossless raw message retention, bounded display, Gemini provider routing and error redaction. Cloud tests use mocks and never use a real key.

- 14 capture analyzer tests, 21 HTTP reconstruction tests, 7 interface tests, 8 Q&A engine tests and 5 cloud/raw-message tests (55 total).
- Interface tests cover uploading both formats, filters, empty states, selecting different HTTP transactions, request/response details and corrupt-file rejection.
- HTTP tests cover segmentation, out-of-order delivery, retransmissions, persistent connections, pipelining, chunked bodies, HEAD, 1xx, 204/304, CONNECT/101, connection reuse, missing timestamps, gaps, conflicting overlaps, malformed framing, truncated bodies, IPv6, sequence wrap and payload limits.
- TShark 4.6.9 independently matched all three completed transactions in both `http_transactions.pcap` and `http_transactions.pcapng`: request/response frames 1/3, 4/5, 6/7; status codes 200, 404, 201; response times 500, 250, 250 milliseconds. A fourth request has no captured response. See `reports/validation_http.json`.
- The earlier overview demo still contains 10 packets spanning 9 seconds and 700 original bytes.

Frame numbers in the main HTTP table identify captured message completion. First-byte and header-completion evidence are also retained. An incomplete body has no message-completion response time. These definitions are explicit in the interface and README.

A user-supplied HTTPS capture was inspected separately (29,092 frames over about 74.61 seconds). It contained encrypted TLS/QUIC traffic and no readable HTTP/1.x transactions; connection 104 also reached the reconstruction payload limit. The capture is not distributed here. Comparison against the students' manual HTTP answers and validation in the course environment remain pending. HTTPS decryption, HTTP/2, HTTP/3 and IP-fragment reassembly are outside this version's scope.

Reproduce from the project directory:

```text
python -m unittest discover -s tests -v
```

Browser verification also confirmed switching to the HTTP sample and selecting POST /form: status 201, response time 250 ms, request/response frames 6/7. The file-scoped selector resets correctly when the capture changes. Screenshots: `docs/screenshots/archive/http_preview.png` and `docs/screenshots/archive/http_details.png`.

## Live local model validation

Six reference questions passed (6/6) with Qwen3-0.6B-Q8_0 and llama-cpp-python 0.3.36 on CPU. This run uses real local inference, not mocked responses. Values, operation and exact evidence frames are compared. See `reports/validation_ai.json`, `docs/AI_VALIDATION.md` and `packetscope/ai/validation.py`. Unit/interface tests mock the interpretation layer separately so that the normal suite requires no model download.

The initial run passed 4/6 (`reports/validation_ai_before_fix.json`); invented selection filters caused two failures. Selector grounding fixed these cases. A second recorded baseline returned three requests instead of four because it received matched transactions only (`reports/ai_error_case.json`). The final system computes against all parsed requests, including unanswered requests. These are synthetic reference comparisons, not a claim to have reproduced the user's own manual answers.

Browser verification with real local inference confirmed four requests to Host example.test and evidence frames 1, 4, 6 and 8 with UTC timestamps. The recorded comparison disclosure displayed 6/6 passed. Screenshots: `docs/screenshots/archive/qa_preview.png`, `docs/screenshots/archive/qa_evidence.png`, `docs/screenshots/archive/qa_validation.png`.

## Unified HTTP workspace

The redesigned version adds four main navigation tabs, native Light/Dark/System themes, responsive traffic/protocol/endpoint/latency/outcome charts, row selection and targeted actions for HTTP transactions, endpoints and packets. The raw HTTP pane preserves all captured bytes within reconstruction limits, offers a bounded text view and a lossless .http download. Incomplete messages stay explicitly marked. No TLS decryption was added.

The supplied Gemini key was verified with Google's model listing, then all six synthetic reference questions passed using gemini-3.5-flash-lite (`reports/validation_gemini.json`). This is separate from the historical Qwen experiments below. The configured key stays in process/session memory and is excluded from source, logs and reports. The source packager excludes secret paths and scans for credential patterns.

Browser verification confirmed native Light/Dark switching, selectable HTTP rows (POST /form → transaction 3), lossless request/response download controls, a real Gemini selected-request answer (201), packet frame selection and navigation from frame 1 to its request/response pane. Older screenshots document earlier layouts; `docs/screenshots/redesign_dark.png` and `docs/screenshots/redesign_messages.png` show the redesign.

HTTP analysis now places stream and transaction selection, status/timing/frame metrics and the Ask AI, Request & response and Packet evidence tabs in one card. The full transaction table and filters are available in a collapsed disclosure. The new interface test verifies that switching streams selects a transaction from that stream, routes a selected-request question to it, and clears the previous answer when the context changes. Capture-wide computations still use all parsed transactions. See `docs/screenshots/redesign_messages.png` for the current layout; `docs/screenshots/archive/http_workspace.png` and earlier HTTP/Q&A screenshots document previous layouts.
