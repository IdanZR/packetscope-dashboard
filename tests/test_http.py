"""Known-wire fixtures test framing, pairing, evidence and uncertain cases."""
import struct
import unittest
from unittest.mock import patch
from scapy.all import Ether, IP, IPv6, Raw, TCP
from packetscope.analysis.capture import analyze_capture


GET = b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n"
OK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"


class Wire:
    def __init__(self, ipv6=False):
        self.packets = []
        self.seq = [1000, 9000]
        self.ipv6 = ipv6

    def send(self, side, data=b"", seq=None, ack=None, flags="PA", stamp=None, port=50000):
        position = self.seq[side] if seq is None else seq
        acknowledged = self.seq[1-side] if ack is None else ack
        if self.ipv6:
            source, dest = ("2001:db8::1", "2001:db8::2") if side == 0 else ("2001:db8::2", "2001:db8::1")
            network = IPv6(src=source, dst=dest)
        else:
            source, dest = ("192.0.2.1", "198.51.100.2") if side == 0 else ("198.51.100.2", "192.0.2.1")
            network = IP(src=source, dst=dest)
        packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/network/TCP(sport=port if side == 0 else 80,
                                     dport=80 if side == 0 else port, flags=flags,
                                     seq=position % 2**32, ack=acknowledged % 2**32)
        if data:
            packet /= Raw(data)
        self.seq[side] = max(self.seq[side], position + len(data) + bool(int(packet[TCP].flags) & 2))
        self.packets.append((packet, stamp if stamp is not None else 100 + len(self.packets) / 10))
        return self

    def capture(self):
        data = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        for packet, stamp in self.packets:
            raw = bytes(packet)
            sec = int(stamp)
            data += struct.pack("<IIII", sec, round((stamp-sec)*1_000_000), len(raw), len(raw)) + raw
        return analyze_capture(data)


class HttpTests(unittest.TestCase):
    def test_request_response_fields_timing_and_evidence(self):
        tx = Wire().send(0, GET).send(1, OK).capture().http_transactions[0]
        self.assertEqual(tx["match_status"], "Matched")
        self.assertEqual((tx["method"], tx["host"], tx["uri"], tx["status_code"]), ("GET", "example.test", "/one", 200))
        self.assertEqual((tx["source"], tx["source_port"], tx["destination"], tx["destination_port"]), ("192.0.2.1", 50000, "198.51.100.2", 80))
        self.assertEqual((tx["request_frame"], tx["response_frame"], tx["response_time_ms"]), (1, 2, 100))
        self.assertEqual(tx["request"]["frames"], [1])
        self.assertEqual(tx["response"]["body_preview"], "OK")

    def test_split_headers_and_bodies_are_reassembled(self):
        request = b"POST /form HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nx=1"
        wire = Wire().send(0, request[:12]).send(0, request[12:])
        wire.send(1, OK[:24]).send(1, OK[24:])
        tx = wire.capture().http_transactions[0]
        self.assertEqual(tx["match_status"], "Matched")
        self.assertEqual(tx["request"]["frames"], [1, 2])
        self.assertEqual(tx["response"]["frames"], [3, 4])
        self.assertEqual(tx["request"]["header_complete_frame"], 2)
        self.assertEqual(tx["request"]["body_preview"], "x=1")
        self.assertEqual(tx["response_time_ms"], 200)
        self.assertEqual((tx["request_frame"], tx["response_frame"]), (2, 4))
        self.assertEqual((tx["request_first_byte_frame"], tx["response_first_byte_frame"]), (1, 3))

    def test_retransmissions_do_not_duplicate_transactions(self):
        wire = Wire().send(0, GET).send(0, GET, seq=1000).send(1, OK).send(1, OK, seq=9000)
        txs = wire.capture().http_transactions
        self.assertEqual(len(txs), 1)
        self.assertEqual(txs[0]["request"]["frames"], [1])
        self.assertEqual(txs[0]["response_frame"], 3)

    def test_out_of_order_bytes_and_sequence_wrap(self):
        wire = Wire().send(0, GET[12:], seq=1012).send(0, GET[:12], seq=1000).send(1, OK)
        tx = wire.capture().http_transactions[0]
        self.assertEqual(tx["match_status"], "Matched")
        self.assertEqual(tx["request_frame"], 2)
        wire = Wire()
        wire.seq[0] = 2**32-10
        wire.send(0, GET[:10]).send(0, GET[10:]).send(1, OK)
        self.assertEqual(wire.capture().http_transactions[0]["match_status"], "Matched")

    def test_pipelined_and_keepalive_requests_match_in_order(self):
        second = GET.replace(b"/one", b"/two")
        error = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        wire = Wire().send(0, GET + second).send(1, OK + error)
        txs = wire.capture().http_transactions
        self.assertEqual([(t["uri"], t["status_code"]) for t in txs], [("/one", 200), ("/two", 404)])
        wire = Wire().send(0, GET).send(1, OK).send(0, second).send(1, error)
        self.assertEqual(len(wire.capture().http_transactions), 2)

    def test_chunked_response_with_trailers_and_next_response(self):
        chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;ext=yes\r\nOK\r\n0\r\nX-End: true\r\n\r\n"
        txs = Wire().send(0, GET+GET).send(1, chunked+OK).capture().http_transactions
        self.assertEqual(len(txs), 2)
        self.assertEqual(txs[0]["response"]["body_preview"], "OK")
        self.assertTrue(txs[0]["response"]["body_complete"])

    def test_head_and_no_body_statuses_do_not_consume_next_message(self):
        request = GET.replace(b"GET", b"HEAD", 1)
        head = b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"
        txs = Wire().send(0, request+GET).send(1, head+OK).capture().http_transactions
        self.assertEqual([t["status_code"] for t in txs], [200, 200])
        self.assertEqual(txs[0]["response"]["body_bytes_captured"], 0)
        for status in (204, 304):
            response = f"HTTP/1.1 {status} No body\r\nContent-Length: 999\r\n\r\n".encode()
            self.assertEqual(len(Wire().send(0, GET+GET).send(1, response+OK).capture().http_transactions), 2)

    def test_informational_response_does_not_consume_request(self):
        interim = b"HTTP/1.1 100 Continue\r\n\r\n"
        tx = Wire().send(0, GET).send(1, interim+OK).capture().http_transactions[0]
        self.assertEqual(tx["status_code"], 200)
        self.assertEqual(tx["informational_responses"][0]["status_code"], 100)
        tx = Wire().send(0, GET).send(1, interim).capture().http_transactions[0]
        self.assertEqual(tx["match_status"], "No response captured")
        self.assertTrue(tx["notes"])

    def test_unmatched_request_and_orphan_response_are_explicit(self):
        tx = Wire().send(0, GET).capture().http_transactions[0]
        self.assertEqual(tx["match_status"], "No response captured")
        self.assertIsNone(tx["status_code"])
        tx = Wire().send(1, OK).capture().http_transactions[0]
        self.assertEqual(tx["match_status"], "No request captured")
        self.assertIsNone(tx["method"])

    def test_gaps_and_conflicting_overlaps_disable_pairing(self):
        for wire in (Wire().send(0, GET).send(0, GET, seq=1100).send(1, OK),
                     Wire().send(0, GET).send(0, GET.replace(b"/one", b"/bad"), seq=1000).send(1, OK)):
            cap = wire.capture()
            self.assertTrue(cap.http_warnings)
            self.assertFalse(any(t["match_status"] == "Matched" for t in cap.http_transactions))
            self.assertTrue(all(t["response_time_ms"] is None for t in cap.http_transactions))

    def test_invalid_length_and_ambiguous_framing_disable_pairing(self):
        for body_headers in (b"Content-Length: 2\r\nContent-Length: 3", b"Content-Length: nope",
                             b"Content-Length: 2\r\nTransfer-Encoding: chunked"):
            response = b"HTTP/1.1 200 OK\r\n"+body_headers+b"\r\n\r\n0\r\n\r\n"
            txs = Wire().send(0, GET).send(1, response).capture().http_transactions
            self.assertFalse(any(t["match_status"] == "Matched" for t in txs))

    def test_truncated_body_does_not_scan_payload_for_fake_requests(self):
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"+GET
        txs = Wire().send(0, GET).send(1, response).capture().http_transactions
        self.assertEqual(len(txs), 1)
        self.assertFalse(txs[0]["response"]["body_complete"])
        self.assertTrue(txs[0]["response"]["notes"])

    def test_close_delimited_body_and_upgrade(self):
        response = b"HTTP/1.0 200 OK\r\n\r\nHello"
        tx = Wire().send(0, GET).send(1, response).send(1, flags="FA").capture().http_transactions[0]
        self.assertTrue(tx["response"]["body_complete"])
        tx = Wire().send(0, GET).send(1, response).capture().http_transactions[0]
        self.assertFalse(tx["response"]["body_complete"])
        upgrade = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\nopaque tunnel bytes"
        tx = Wire().send(0, GET).send(1, upgrade).capture().http_transactions[0]
        self.assertEqual(tx["status_code"], 101)
        self.assertEqual(tx["response"]["body_bytes_captured"], 0)

    def test_reused_connection_tuple_starts_new_connection(self):
        wire = Wire().send(0, flags="S").send(1, flags="SA").send(0, GET).send(1, OK)
        wire.send(0, seq=5000, flags="S").send(1, seq=15000, flags="SA").send(0, GET).send(1, OK)
        txs = wire.capture().http_transactions
        self.assertEqual(len(txs), 2)
        self.assertNotEqual(txs[0]["connection_id"], txs[1]["connection_id"])

    def test_ipv6_nonstandard_ports_and_missing_host(self):
        request = b"PROPFIND /folder HTTP/1.1\r\n\r\n"
        tx = Wire(ipv6=True).send(0, request, port=50123).send(1, OK, port=50123).capture().http_transactions[0]
        self.assertEqual(tx["method"], "PROPFIND")
        self.assertIsNone(tx["host"])
        self.assertEqual(tx["source"], "2001:db8::1")

    def test_encrypted_or_non_http_data_is_not_invented(self):
        for data in (b"\x17\x03\x03\x00\x04demo", b"random bytes GET /one HTTP/1.1\r\n\r\n"):
            self.assertEqual(Wire().send(0, data).capture().http_transactions, [])

    def test_invalid_ack_and_reversed_times_do_not_fabricate_delay(self):
        txs = Wire().send(0, GET).send(1, OK, ack=999).capture().http_transactions
        self.assertFalse(any(t["match_status"] == "Matched" for t in txs))
        tx = Wire().send(0, GET, stamp=200).send(1, OK, stamp=100).capture().http_transactions[0]
        self.assertIsNone(tx["response_time_ms"])
        self.assertTrue(tx["notes"])

    def test_reconstruction_limit_is_explicit_without_affecting_packet_totals(self):
        with patch("packetscope.analysis.http.MAX_DIRECTION", 8):
            cap = Wire().send(0, GET).send(1, OK).capture()
        self.assertEqual(len(cap.rows), 2)
        self.assertEqual(cap.http_transactions, [])
        self.assertTrue(cap.http_warnings)

    def test_missing_timestamps_and_incomplete_header(self):
        def block(kind, body):
            body += b"\x00" * (-len(body) % 4)
            size = len(body) + 12
            return struct.pack("<II", kind, size) + body + struct.pack("<I", size)
        data = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        data += block(1, struct.pack("<HHI", 1, 0, 65535))
        for packet, _ in Wire().send(0, GET).send(1, OK).packets:
            raw = bytes(packet)
            data += block(3, struct.pack("<I", len(raw)) + raw)
        tx = analyze_capture(data).http_transactions[0]
        self.assertEqual(tx["match_status"], "Matched")
        self.assertIsNone(tx["response_time_ms"])
        self.assertIsNone(tx["first_byte_delay_ms"])
        cap = Wire().send(0, b"GET /one HTTP/1.1\r\nHost: example.test\r\n").capture()
        self.assertEqual(cap.http_transactions, [])
        self.assertTrue(cap.http_warnings)

    def test_invalid_chunk_and_connect_tunnel(self):
        bad = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nXYZ\r\n"
        txs = Wire().send(0, GET).send(1, bad).capture().http_transactions
        self.assertFalse(any(t["match_status"] == "Matched" for t in txs))
        connect = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n"
        response = b"HTTP/1.1 200 Connection Established\r\n\r\n\x17\x03\x03\x00\x04demo"
        txs = Wire().send(0, connect).send(1, response).capture().http_transactions
        self.assertEqual(len(txs), 1)
        self.assertEqual(txs[0]["match_status"], "Matched")
        self.assertEqual(txs[0]["response"]["body_bytes_captured"], 0)

    def test_body_preview_is_bounded_and_absolute_uri_supplies_host(self):
        request = b"GET http://example.test/absolute HTTP/1.0\r\n\r\n"
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n"+b"x"*4096
        tx = Wire().send(0, request).send(1, response).capture().http_transactions[0]
        self.assertEqual(tx["host"], "example.test")
        self.assertEqual(len(tx["response"]["body_preview"]), 2048)
        self.assertTrue(tx["response"]["body_preview_truncated"])


if __name__ == "__main__":
    unittest.main()
