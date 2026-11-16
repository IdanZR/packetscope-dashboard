import sys
import unittest
from unittest.mock import patch
from pathlib import Path

# Load native dataframe extensions before AppTest starts its script thread.
import pandas  # noqa: F401
import plotly.express  # noqa: F401
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def transaction_selector(app):
    return next(item for item in app.selectbox if item.label == "Select a transaction")


class AppTests(unittest.TestCase):
    def setUp(self):
        # Interface tests never use the developer's real cloud credential.
        self.enterContext(patch("ai_settings.load_key", return_value=""))

    @patch("qa_ui.availability", return_value=(True, "Test model availability"))
    def test_shared_stream_selection_routes_questions_and_clears_old_answer(self, _availability):
        import json
        import struct
        from test_http import Wire, GET, OK
        wire = Wire().send(0, GET).send(1, OK)
        wire.send(0, GET.replace(b"/one", b"/two"), port=51000)
        wire.send(1, OK.replace(b"200 OK", b"201 Created"), port=51000)
        raw = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        for packet, stamp in wire.packets:
            payload = bytes(packet)
            raw += struct.pack("<IIII", int(stamp), round((stamp-int(stamp))*1_000_000), len(payload), len(payload)) + payload
        app = AppTest.from_file(str(ROOT/"app.py"), default_timeout=30).run()
        app.file_uploader[0].set_value(("two_streams.pcap", raw, "application/octet-stream")).run()
        stream = next(s for s in app.selectbox if s.label == "Stream for questions")
        stream.set_value(2).run()
        self.assertFalse(app.exception)
        self.assertEqual(transaction_selector(app).value, 2)
        next(i for i in app.text_input if i.label == "Your question").set_value("What status did the selected request return?")
        typed = dict(operation="status", host="", uri="", method="", transaction_id=0, connection_id=0)
        with patch("local_ai.complete", return_value=json.dumps(typed)):
            next(b for b in app.button if b.label == "Ask local AI").click().run()
        self.assertTrue(any("returned HTTP 201" in t.value for t in app.text))
        next(s for s in app.selectbox if s.label == "Stream for questions").set_value(1).run()
        self.assertFalse(app.exception)
        self.assertEqual(transaction_selector(app).value, 1)
        self.assertFalse(any("returned HTTP 201" in t.value for t in app.text))

    @patch("qa_ui.availability", return_value=(True, "Test model availability"))
    def test_qa_answer_and_evidence_from_interpreted_query(self, _availability):
        import json
        from setup_local_ai import LocalAIError
        app = AppTest.from_file(str(ROOT/"app.py"), default_timeout=30).run()
        app.selectbox(key="sample_choice").set_value("HTTP transactions").run()
        question = next(i for i in app.text_input if i.label == "Your question")
        question.set_value("How many requests were sent to Host example.test?")
        typed = dict(operation="host_count", host="example.test", uri="", method="", transaction_id=0, connection_id=0)
        with patch("local_ai.complete", return_value=json.dumps(typed)):
            next(b for b in app.button if b.label == "Ask local AI").click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any("4 HTTP request(s)" in t.value for t in app.text))
        evidence = next(d.value for d in app.dataframe if "timestamp_utc" in d.value.columns)
        self.assertEqual(evidence["frame"].tolist(), [1, 4, 6, 8])
        with patch("local_ai.complete", side_effect=LocalAIError("Model unavailable")):
            next(b for b in app.button if b.label == "Ask local AI").click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any("Model unavailable" in e.value for e in app.error))
        self.assertFalse(any("4 HTTP request(s)" in t.value for t in app.text))

    def test_demo_filter_and_empty_filter(self):
        app = AppTest.from_file(str(ROOT/"app.py"), default_timeout=30).run()
        self.assertFalse(app.exception)
        self.assertEqual(app.metric[0].value, "10")
        app.multiselect(key="selected_protocols").set_value(["HTTP"]).run()
        self.assertFalse(app.exception)
        self.assertEqual(app.metric[0].value, "10")
        # Protocol table and evidence each contain only the two HTTP frames.
        protocol_table = next(d.value for d in app.dataframe if "percent" in d.value.columns)
        packet_table = next(d.value for d in app.dataframe if "layers" in d.value.columns)
        self.assertEqual(protocol_table["packets"].sum(), 2)
        self.assertEqual(packet_table["frame"].tolist(), [6, 7])
        app.multiselect(key="selected_protocols").set_value([]).run()
        self.assertFalse(app.exception)
        self.assertFalse(any("layers" in d.value.columns or "percent" in d.value.columns for d in app.dataframe))
        self.assertTrue(any("transaction_id" in d.value.columns for d in app.dataframe))

    def test_demo_can_be_disabled(self):
        app = AppTest.from_file(str(ROOT/"app.py"), default_timeout=30).run()
        app.toggle[0].set_value(False).run()
        self.assertFalse(app.exception)
        self.assertEqual(len(app.metric), 0)

    def test_upload_both_formats_and_reject_corrupt_file(self):
        app = AppTest.from_file(str(ROOT/"app.py"), default_timeout=30).run()
        for name in ("demo.pcap", "demo.pcapng"):
            data = (ROOT/"sample_data"/name).read_bytes()
            app.file_uploader[0].set_value((name, data, "application/octet-stream")).run()
            self.assertFalse(app.exception)
            self.assertEqual(app.metric[0].value, "10")
            self.assertEqual(len(app.error), 0)
        app.file_uploader[0].set_value(("broken.pcap", b"bad capture", "application/octet-stream")).run()
        self.assertFalse(app.exception)
        self.assertEqual(len(app.error), 1)
        self.assertEqual(len(app.metric), 0)

    def test_http_transaction_details_and_filters(self):
        app = AppTest.from_file(str(ROOT/"app.py"), default_timeout=30).run()
        table = next(d.value for d in app.dataframe if "transaction_id" in d.value.columns)
        self.assertEqual(table["status_code"].tolist(), [200])
        self.assertEqual(table["request_frame"].tolist(), [6])
        self.assertEqual(table["response_frame"].tolist(), [7])
        self.assertEqual(table["response_time_ms"].tolist(), [1000])
        self.assertEqual(transaction_selector(app).value, 1)
        self.assertTrue(any(code.value.startswith("GET /demo HTTP/1.1") for code in app.code))
        app.selectbox(key="http_state").set_value("No response captured").run()
        self.assertFalse(app.exception)
        self.assertFalse(any("transaction_id" in d.value.columns for d in app.dataframe))

    def test_http_multiple_transactions_selection_and_both_formats(self):
        app = AppTest.from_file(str(ROOT/"app.py"), default_timeout=30).run()
        app.selectbox(key="sample_choice").set_value("HTTP transactions").run()
        self.assertFalse(app.exception)
        table = next(d.value for d in app.dataframe if "transaction_id" in d.value.columns)
        self.assertEqual(len(table), 4)
        for suffix in ("pcap", "pcapng"):
            name = "http_transactions." + suffix
            app.file_uploader[0].set_value((name, (ROOT/"sample_data"/name).read_bytes(), "application/octet-stream")).run()
            self.assertFalse(app.exception)
            table = next(d.value for d in app.dataframe if "transaction_id" in d.value.columns)
            self.assertEqual(table["uri"].tolist(), ["/home", "/missing", "/form", "/pending"])
            self.assertEqual(table["response_frame"].iloc[0], 3)
            self.assertEqual(table["response_time_ms"].iloc[0], 500)
            transaction_selector(app).set_value(3).run()
            self.assertFalse(app.exception)
            self.assertTrue(any(code.value == "Saved" for code in app.code))
            transaction_selector(app).set_value(4).run()
            self.assertFalse(app.exception)
            self.assertTrue(any("No response" in info.value for info in app.info))


if __name__ == "__main__":
    unittest.main()
