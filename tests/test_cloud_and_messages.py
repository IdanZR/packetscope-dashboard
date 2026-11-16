"""Verify secret-safe cloud behavior and lossless HTTP content without API calls."""
import json
import unittest
import urllib.error
from io import BytesIO
from unittest.mock import patch, Mock
from pathlib import Path
from analyzer import analyze_capture
from http_content import message_bytes, message_text, DISPLAY_LIMIT
from qa_engine import ask, context
from setup_local_ai import LocalAIError
from test_http import Wire, GET, OK


class CloudAndMessageTests(unittest.TestCase):
    def test_large_body_and_chunk_framing_are_preserved_exactly(self):
        body=b"A"*5000
        response=b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n"+body
        capture=Wire().send(0,GET).send(1,response[:1200]).send(1,response[1200:]).capture()
        tx=capture.http_transactions[0]
        self.assertEqual(message_bytes(tx["response"]),response)
        self.assertEqual(message_bytes(tx["request"]),GET)
        self.assertTrue(tx["response"]["body_preview_truncated"])
        self.assertNotIn("raw_message",json.dumps(context(capture)))
        chunk=b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nSaved\r\n0\r\n\r\n"
        message=Wire().send(0,GET).send(1,chunk).capture().http_transactions[0]["response"]
        self.assertEqual(message_bytes(message),chunk)
        self.assertIn("5\r\nSaved",message_text(message)[0])

    def test_incomplete_body_is_not_presented_as_complete(self):
        partial=b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort"
        msg=Wire().send(0,GET).send(1,partial).capture().http_transactions[0]["response"]
        self.assertFalse(msg["body_complete"])
        self.assertEqual(message_bytes(msg),partial)

    def test_large_message_has_optional_bounded_view_and_lossless_download(self):
        import base64
        raw=b"x"*(DISPLAY_LIMIT+1)
        message=dict(raw_message_b64=base64.b64encode(raw).decode())
        self.assertTrue(message_text(message)[1])
        self.assertEqual(len(message_text(message)[0]),DISPLAY_LIMIT)
        self.assertEqual(message_bytes(message),raw)
        self.assertFalse(message_text(message,True)[1])

    def test_gemini_query_uses_the_same_factual_engine_without_exporting_a_key(self):
        capture=Wire().send(0,GET).send(1,OK).capture()
        typed=dict(operation="status",host="",uri="",method="",transaction_id=0,connection_id=0)
        with patch("gemini_client.complete",return_value=json.dumps(typed)) as complete:
            result=ask(capture,"What status did the selected request return?",1,1,provider="gemini",api_key="test-secret")
        self.assertEqual(result["value"],200)
        self.assertEqual(result["provider"],"gemini")
        self.assertNotIn("test-secret",json.dumps(result))
        self.assertNotIn("raw_message",complete.call_args.args[1])

    def test_cloud_errors_never_include_secret_vendor_error_text(self):
        from gemini_client import _request
        error=urllib.error.HTTPError("https://example.invalid",403,"test-secret",{},BytesIO(b'{"error":{"message":"test-secret"}}'))
        opener=Mock()
        opener.open.side_effect=error
        with patch("urllib.request.build_opener",return_value=opener):
            with self.assertRaises(LocalAIError) as raised:
                _request("models",key="test-secret")
        self.assertNotIn("test-secret",str(raised.exception))
        self.assertIn("denied",str(raised.exception))


if __name__=="__main__":
    unittest.main()
