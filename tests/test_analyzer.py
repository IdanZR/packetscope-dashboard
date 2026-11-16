import struct
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from packetscope.analysis.capture import CaptureError, analyze_capture, endpoints, summarize, timeline
from scripts.make_demo import demo_packets, generate


def pcap(raw=None, endian="<", nano=False, fraction=250000, wirelen=None, link=1):
    magic = (b"\x4d\x3c\xb2\xa1" if nano else b"\xd4\xc3\xb2\xa1")
    if endian == ">":
        magic = magic[::-1]
    header = magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, 65535, link)
    if raw is None:
        return header
    return header + struct.pack(endian + "IIII", 100, fraction, len(raw), wirelen or len(raw)) + raw


def block(kind, body, endian="<"):
    body += b"\x00" * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def section(endian="<"):
    return block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def interface(endian="<", options=b"", link=1):
    return block(1, struct.pack(endian + "HHI", link, 0, 65535) + options, endian)


def epb(raw, timestamp=1_000_000, index=0, endian="<"):
    return block(6, struct.pack(endian + "IIIII", index, timestamp >> 32,
                               timestamp & 0xFFFFFFFF, len(raw), len(raw)) + raw, endian)


class AnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.path = generate(cls.temp.name)
        cls.raw = bytes(demo_packets()[5])

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_both_formats_have_known_statistics_and_protocols(self):
        expected = Counter(ARP=1, DNS=2, TCP=2, HTTP=2, TLS=1, ICMP=1, UDP=1)
        for name in ("demo.pcap", "demo.pcapng"):
            with self.subTest(name=name):
                capture = analyze_capture((self.path / name).read_bytes())
                summary = summarize(capture.rows)
                self.assertEqual(summary["packet_count"], 10)
                self.assertEqual(summary["duration_seconds"], 9)
                self.assertEqual(summary["start_epoch"], 1_800_000_000)
                self.assertEqual(Counter(r["protocol"] for r in capture.rows), expected)
                self.assertEqual(summary["wire_bytes"], sum(len(bytes(p)) for p in demo_packets()))
                self.assertEqual(capture.warnings, [])
                self.assertEqual(capture.rows[-1]["source"], "2001:db8::10")
                self.assertEqual([r["frame"] for r in capture.rows], list(range(1, 11)))
                client = next(e for e in endpoints(capture.rows) if e["address"] == "192.0.2.10")
                self.assertEqual(client["packets"], 9)
                self.assertEqual(client["sent_packets"], 6)
                self.assertEqual(client["received_packets"], 3)

    def test_empty_and_single_packet(self):
        for data in (pcap(), section() + interface()):
            rows = analyze_capture(data).rows
            self.assertEqual(summarize(rows)["packet_count"], 0)
            self.assertIsNone(summarize(rows)["duration_seconds"])
            self.assertEqual(timeline(rows), [])
        rows = analyze_capture(pcap(self.raw)).rows
        self.assertEqual(summarize(rows)["duration_seconds"], 0)
        self.assertEqual(len(timeline(rows)), 1)

    def test_endianness_and_nanosecond_timestamps(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    rows = analyze_capture(pcap(self.raw, endian, nano, 123456)).rows
                    self.assertAlmostEqual(rows[0]["timestamp"], 100 + 123456/(1e9 if nano else 1e6))

    def test_pcapng_multiple_sections_interfaces_and_time_options(self):
        for endian in ("<", ">"):
            # Resolution: binary 2^-10; timestamp offset: +10 seconds.
            options = struct.pack(endian+"HH", 9, 1) + b"\x8a\x00\x00\x00"
            options += struct.pack(endian+"HHq", 14, 8, 10)
            data = section(endian) + interface(endian) + interface(endian, options)
            data += epb(self.raw, 1024, 1, endian)
            data += section() + interface() + epb(self.raw, 2_000_000)
            rows = analyze_capture(data).rows
            self.assertEqual([r["timestamp"] for r in rows], [11, 2])
            self.assertEqual(summarize(rows)["duration_seconds"], 9)

    def test_missing_timestamp_is_not_fabricated(self):
        data = section() + interface() + block(3, struct.pack("<I", len(self.raw)) + self.raw)
        capture = analyze_capture(data)
        self.assertIsNone(capture.rows[0]["timestamp"])
        self.assertIsNone(summarize(capture.rows)["start"])
        self.assertEqual(timeline(capture.rows), [])
        self.assertTrue(capture.warnings)

    def test_legacy_packet_block(self):
        data = section() + interface() + block(2, struct.pack("<HHIIII", 0, 0, 0, 1_000_000, len(self.raw), len(self.raw)) + self.raw)
        self.assertEqual(analyze_capture(data).rows[0]["timestamp"], 1)

    def test_corrupt_files_and_images_are_rejected(self):
        good = pcap(self.raw)
        ng = section() + interface() + epb(self.raw)
        for data in (b"", b"\x89PNG\r\n\x1a\n", b"bad capture", good[:-1], good[:28],
                     ng[:-1], ng[:-4] + b"\x00"*4,
                     section() + interface() + epb(self.raw, index=2)):
            with self.subTest(size=len(data)), self.assertRaises(CaptureError):
                analyze_capture(data)

    def test_unsupported_link_and_snaplen_truncation_remain_counted(self):
        capture = analyze_capture(pcap(self.raw, link=60000, wirelen=len(self.raw)+10))
        self.assertEqual(len(capture.rows), 1)
        self.assertEqual(capture.rows[0]["protocol"], "Unknown")
        self.assertEqual(len(capture.warnings), 2)

    def test_explicit_resource_limits(self):
        with patch("packetscope.analysis.capture.MAX_BYTES", 10), self.assertRaises(CaptureError):
            analyze_capture(pcap())
        with patch("packetscope.analysis.capture.MAX_PACKETS", 1), self.assertRaises(CaptureError):
            analyze_capture((self.path/"demo.pcap").read_bytes())

    def test_timeline_volume_is_conserved_and_idle_bins_exist(self):
        rows = analyze_capture((self.path/"demo.pcap").read_bytes()).rows
        series = timeline(rows)
        self.assertEqual(sum(x["bytes"] for x in series), summarize(rows)["wire_bytes"])
        self.assertEqual(len(series), 60)
        self.assertTrue(any(x["bytes"] == 0 for x in series))

    def test_port_443_does_not_prove_tls(self):
        from scapy.all import Ether, IP, TCP, Raw
        raw = bytes(Ether()/IP()/TCP(dport=443)/Raw(b"not TLS"))
        self.assertEqual(analyze_capture(pcap(raw)).rows[0]["protocol"], "TCP")

    def test_loopback_endpoint_is_counted_once(self):
        row = analyze_capture(pcap(self.raw)).rows[0]
        row["destination"] = row["source"]
        item = endpoints([row])[0]
        self.assertEqual(item["packets"], 1)
        self.assertEqual(item["sent_packets"], 1)
        self.assertEqual(item["received_packets"], 1)

    def test_raw_ip_and_linux_cooked_links(self):
        from scapy.all import CookedLinux, IP, UDP
        network = IP(src="192.0.2.1", dst="192.0.2.2")/UDP(sport=10000,dport=10001)
        for raw, link in ((bytes(network), 228), (bytes(CookedLinux()/network), 113)):
            row = analyze_capture(pcap(raw, link=link)).rows[0]
            self.assertEqual(row["source"], "192.0.2.1")
            self.assertEqual(row["protocol"], "UDP")

    def test_zero_captured_bytes_do_not_invent_addresses(self):
        capture = analyze_capture(pcap(b""))
        self.assertEqual(capture.rows[0]["protocol"], "Unknown")
        self.assertEqual(endpoints(capture.rows), [])


if __name__ == "__main__":
    unittest.main()
