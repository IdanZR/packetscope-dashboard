"""Reproducible live-model checks on explicitly synthetic reference data."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from packetscope.analysis.capture import analyze_capture
from packetscope.ai.queries import ask
from packetscope.ai.local import complete

from packetscope.paths import PROJECT_ROOT, REPORTS_DIR
from packetscope.ai.model_setup import LocalAIError

ROOT = PROJECT_ROOT
CASES = [
    dict(question="Which HTTP request was the slowest?", expected=500.0, frames=[1, 2, 3], operation="slowest"),
    dict(question="What status code did GET /missing return?", expected=404, frames=[4, 5], operation="status"),
    dict(question="How many requests were sent to Host example.test?", expected=4, frames=[1, 4, 6, 8], operation="host_count"),
    dict(question="What happened in the selected stream?", expected=dict(requests=4, matched_responses=3, unanswered=1), frames=list(range(1, 9)), operation="stream_summary"),
    dict(question="Which requests had no response?", expected=1, frames=[8], operation="unanswered"),
    dict(question="What status code did POST /form return?", expected=201, frames=[6, 7], operation="status"),
]


def run_checks(progress=None, provider="local", model=None, api_key=None):
    raw = (ROOT/"sample_data/http_transactions.pcap").read_bytes()
    capture = analyze_capture(raw)
    digest = hashlib.sha256(raw).hexdigest()
    results = []
    for i, case in enumerate(CASES):
        if progress:
            progress(i, len(CASES))
        try:
            answer = ask(capture, case["question"], 1, 1, digest, provider=provider, model=model, api_key=api_key)
        except LocalAIError as exc:
            answer = dict(state="error",value=None,evidence=[],plan={"operation":"error"},error=str(exc),provider=provider)
        actual_frames = [e["frame"] for e in answer["evidence"]]
        passed = (answer["state"] == "answered" and answer["value"] == case["expected"]
                  and actual_frames == case["frames"] and answer["plan"]["operation"] == case["operation"])
        results.append(dict(**case, actual=answer["value"], actual_frames=actual_frames,
                            passed=passed, result=answer))
    return dict(created_utc=datetime.now(timezone.utc).isoformat(), capture_sha256=digest,
                provenance="Synthetic fixture created for this project; reference packet contents and timing verified separately with TShark. Not the user's manual capture.",
                selected_transaction=1, selected_connection=1, cases=results,
                passed=sum(r["passed"] for r in results), total=len(results))


def baseline():
    raw = (ROOT/"sample_data/http_transactions.pcap").read_bytes()
    capture = analyze_capture(raw)
    # Deliberately reproduce the initial retrieval mistake: only matched rows reach AI.
    extracted = [{k: t[k] for k in ("method", "host", "uri", "status_code")}
                 for t in capture.http_transactions if t["match_status"] == "Matched"]
    question = "How many HTTP requests were sent to Host example.test in the entire capture?"
    system = "Answer the user's question from the extracted HTTP rows. Return JSON with request_count (an integer)."
    user = json.dumps(dict(question=question, http_rows=extracted))
    schema = dict(type="object", properties=dict(request_count=dict(type="integer")),
                  required=["request_count"], additionalProperties=False)
    actual = complete(system, user, schema)
    return dict(question=question, system_prompt=system, user_prompt=json.loads(user),
                raw_model_output=actual, reference_request_count=4,
                observed_error=json.loads(actual).get("request_count") != 4,
                omitted_request_frame=8, omitted_uri="/pending",
                explanation="Baseline retrieval gave AI only three matched transactions and omitted an unanswered request. Fixed by querying all parsed requests in Python, not asking AI to count a partial catalog.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", action="store_true")
    args = parser.parse_args()
    if args.baseline:
        result = baseline()
        (REPORTS_DIR/"ai_error_case.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print("Observed baseline:", result["raw_model_output"], flush=True)
    report = run_checks(lambda i, n: print(f"Live model check {i+1}/{n}", flush=True))
    (REPORTS_DIR/"validation_ai.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Passed {report['passed']}/{report['total']}", flush=True)
    for case in report["cases"]:
        print(case["question"], case["actual"], case["result"]["plan"], flush=True)
    raise SystemExit(0 if report["passed"] == report["total"] else 1)
