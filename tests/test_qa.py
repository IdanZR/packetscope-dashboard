"""Verify factual queries/evidence without pretending mock output is a live AI run."""
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch
from analyzer import analyze_capture
from qa_engine import ask, context, execute, ground_selectors, validate_plan
from setup_local_ai import LocalAIError

ROOT = Path(__file__).resolve().parents[1]


def plan(operation, **kwargs):
    return dict(operation=operation, host=kwargs.get("host", ""), uri=kwargs.get("uri", ""),
                method=kwargs.get("method", ""), transaction_id=kwargs.get("transaction_id", 0),
                connection_id=kwargs.get("connection_id", 0))


class QATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = analyze_capture((ROOT/"sample_data/http_transactions.pcap").read_bytes())

    def test_slowest_uses_completion_and_original_segment_evidence(self):
        result = execute(self.capture, plan("slowest"))
        self.assertEqual(result["value"], 500)
        self.assertEqual([e["frame"] for e in result["evidence"]], [1, 2, 3])
        self.assertTrue(all(e["timestamp_utc"] for e in result["evidence"]))

    def test_host_counts_unanswered_and_case_insensitive_host(self):
        result = execute(self.capture, plan("host_count", host="EXAMPLE.TEST"))
        self.assertEqual(result["value"], 4)
        self.assertEqual([e["frame"] for e in result["evidence"]], [1, 4, 6, 8])
        self.assertEqual(execute(self.capture, plan("host_count", host="absent.test"))["value"], 0)
        self.assertEqual(execute(self.capture, plan("host_count"))["state"], "clarification")

    def test_status_selected_explicit_and_missing_response(self):
        self.assertEqual(execute(self.capture, plan("status"), selected_transaction=2)["value"], 404)
        self.assertEqual(execute(self.capture, plan("status", uri="/form", method="POST"))["value"], 201)
        missing = execute(self.capture, plan("status", transaction_id=4))
        self.assertIsNone(missing["value"])
        self.assertEqual(missing["state"], "no_data")
        self.assertEqual(execute(self.capture, plan("status", host="example.test"))["state"], "clarification")

    def test_stream_and_unanswered_are_different_operations(self):
        stream = execute(self.capture, plan("stream_summary"), selected_connection=1)
        self.assertEqual(stream["value"], dict(requests=4, matched_responses=3, unanswered=1))
        self.assertEqual([e["frame"] for e in stream["evidence"]], list(range(1, 9)))
        pending = execute(self.capture, plan("unanswered"))
        self.assertEqual(pending["value"], 1)
        self.assertEqual([e["frame"] for e in pending["evidence"]], [8])

    def test_partial_catalog_does_not_truncate_calculation(self):
        capture = copy.deepcopy(self.capture)
        capture.http_transactions *= 5
        self.assertEqual(len(context(capture)["catalog"]), 12)
        self.assertTrue(context(capture)["catalog_is_partial"])
        self.assertEqual(execute(capture, plan("host_count", host="example.test"))["value"], 20)
        self.assertNotIn("body_preview", json.dumps(context(capture)))

    def test_plan_validation_rejects_extra_keys_bool_and_code(self):
        for bad in [dict(plan("status"), frames=[999]), dict(plan("status"), transaction_id=True),
                    plan("eval"), dict(plan("status"), connection_id=-1)]:
            with self.subTest(bad=bad), self.assertRaises(LocalAIError):
                validate_plan(bad)
        self.assertEqual(execute(self.capture, plan("unsupported"))["state"], "unsupported")

    def test_selected_stream_does_not_inherit_a_catalog_transaction(self):
        hallucinated = plan("stream_summary", host="example.test", uri="/home", method="GET", transaction_id=1, connection_id=1)
        grounded = ground_selectors(hallucinated, "What happened in the selected stream?")
        self.assertEqual(grounded, plan("stream_summary"))
        self.assertEqual(execute(self.capture, grounded, selected_connection=1)["value"]["requests"], 4)
        explicit = plan("status", uri="/form", method="POST", transaction_id=1, connection_id=1)
        self.assertEqual(ground_selectors(explicit, "What status did POST /form return?"), plan("status", uri="/form", method="POST"))
        self.assertEqual(ground_selectors(plan("status", transaction_id=2), "Status of transaction #2?"), plan("status", transaction_id=2))

    def test_ask_accepts_only_a_typed_plan_and_propagates_failure(self):
        with patch("local_ai.complete", return_value=json.dumps(plan("status", uri="/missing"))):
            result = ask(self.capture, "What status for /missing?", capture_hash="fixture-hash")
        self.assertEqual(result["value"], 404)
        self.assertEqual(result["capture_sha256"], "fixture-hash")
        with patch("local_ai.complete", side_effect=LocalAIError("Model unavailable")):
            with self.assertRaisesRegex(LocalAIError, "unavailable"):
                ask(self.capture, "Which request was slowest?")
        with self.assertRaises(LocalAIError):
            ask(self.capture, " ")


if __name__ == "__main__":
    unittest.main()
