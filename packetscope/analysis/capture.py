"""Offline capture analysis. No tshark process, network requests or AI calls."""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import re
import struct

from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, IPv6ExtHdrFragment, Padding, TCP, UDP, conf
from packetscope.analysis.http import HttpCollector

MAX_BYTES = 100 * 1024 * 1024
MAX_PACKETS = 250_000
ANALYSIS_VERSION = 4
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


class CaptureError(ValueError):
    """An invalid capture or an explicit resource limit, suitable for the UI."""


@dataclass
class Capture:
    format: str
    rows: list[dict]
    warnings: list[str]
    http_transactions: list[dict] = field(default_factory=list)
    http_warnings: list[str] = field(default_factory=list)


def _pcap_records(data):
    endian, resolution = PCAP_MAGIC[data[:4]]
    if len(data) < 24:
        raise CaptureError("PCAP header is truncated.")
    major, minor, _, _, snaplen, link = struct.unpack_from(endian + "HHiIII", data, 4)
    if (major, minor) != (2, 4) or snaplen == 0:
        raise CaptureError("Unsupported PCAP version or invalid snapshot length.")
    pos = 24
    while pos < len(data):
        if len(data) - pos < 16:
            raise CaptureError("Truncated PCAP packet header; no partial result is shown.")
        sec, fraction, caplen, wirelen = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        if caplen > snaplen or caplen > wirelen or fraction >= resolution:
            raise CaptureError("Invalid PCAP packet lengths or timestamp.")
        if pos + caplen > len(data):
            raise CaptureError("Truncated PCAP packet data; no partial result is shown.")
        yield data[pos:pos + caplen], sec + fraction / resolution, wirelen, link & 0xFFFF
        pos += caplen


def _options(body, start, endian):
    """Read aligned PCAPNG options, respecting the containing block boundary."""
    while start < len(body):
        if len(body) - start < 4:
            raise CaptureError("Truncated PCAPNG option.")
        code, length = struct.unpack_from(endian + "HH", body, start)
        start += 4
        if code == 0:
            if length != 0:
                raise CaptureError("Invalid PCAPNG end-of-options marker.")
            return
        end = start + ((length + 3) // 4) * 4
        if end > len(body):
            raise CaptureError("PCAPNG option exceeds its block.")
        yield code, body[start:start + length]
        start = end


def _pcapng_records(data):
    pos, endian, interfaces = 0, None, []
    while pos < len(data):
        if len(data) - pos < 12:
            raise CaptureError("Truncated PCAPNG block header.")
        section = data[pos:pos + 4] == b"\x0a\x0d\x0d\x0a"
        if section:
            bom = data[pos + 8:pos + 12]
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(bom)
            if endian is None:
                raise CaptureError("Invalid PCAPNG byte-order marker.")
        if endian is None:
            raise CaptureError("PCAPNG must begin with a section header.")
        kind, size = struct.unpack_from(endian + "II", data, pos)
        if size < 12 or size % 4 or pos + size > len(data):
            raise CaptureError("Invalid or truncated PCAPNG block length.")
        if struct.unpack_from(endian + "I", data, pos + size - 4)[0] != size:
            raise CaptureError("PCAPNG block length markers disagree.")
        body = data[pos + 8:pos + size - 4]
        pos += size
        if section:
            if len(body) < 16 or struct.unpack_from(endian + "H", body, 4)[0] != 1:
                raise CaptureError("Unsupported or truncated PCAPNG section.")
            interfaces = []
        elif kind == 1:  # Interface Description Block
            if len(body) < 8:
                raise CaptureError("Truncated PCAPNG interface description.")
            link, _, snaplen = struct.unpack_from(endian + "HHI", body)
            resolution, offset = 1_000_000, 0
            for code, value in _options(body, 8, endian):
                if code == 9:
                    if len(value) != 1:
                        raise CaptureError("Invalid PCAPNG timestamp resolution.")
                    resolution = (2 ** (value[0] & 127)) if value[0] & 128 else 10 ** value[0]
                elif code == 14:
                    if len(value) != 8:
                        raise CaptureError("Invalid PCAPNG timestamp offset.")
                    offset = struct.unpack(endian + "q", value)[0]
            interfaces.append((link, snaplen, resolution, offset))
        elif kind in (2, 3, 6):
            if kind == 3:  # Simple Packet Block: no timestamp by design
                if not interfaces or len(body) < 4:
                    raise CaptureError("Invalid PCAPNG simple packet block.")
                index, wirelen = 0, struct.unpack_from(endian + "I", body)[0]
                caplen = min(wirelen, interfaces[0][1] or wirelen)
                start, stamp = 4, None
            else:
                if len(body) < 20:
                    raise CaptureError("Truncated PCAPNG packet block.")
                index = struct.unpack_from(endian + ("H" if kind == 2 else "I"), body)[0]
                high, low, caplen, wirelen = struct.unpack_from(endian + "IIII", body, 4)
                if index >= len(interfaces):
                    raise CaptureError("PCAPNG packet references a missing interface.")
                stamp = ((high << 32) + low) / interfaces[index][2] + interfaces[index][3]
                start = 20
            link, snaplen, _, _ = interfaces[index]
            padded_end = start + ((caplen + 3) // 4) * 4
            if caplen > wirelen or (snaplen and caplen > snaplen) or padded_end > len(body):
                raise CaptureError("Invalid PCAPNG packet lengths.")
            if kind == 3 and padded_end != len(body):
                raise CaptureError("Invalid PCAPNG simple packet size.")
            if kind != 3:
                list(_options(body, padded_end, endian))
            yield body[start:start + caplen], stamp, wirelen, link
        # Other standard metadata blocks are skipped using their validated size.


def _packet_fields(raw, link):
    decoder = conf.l2types.num2layer.get(link)
    if decoder is None or not raw:
        return dict(source="", destination="", address_type="Unknown", source_port=None,
                    destination_port=None, protocol="Unknown", layers=f"Link type {link}"), True, None
    try:
        packet = decoder(raw)
        source = destination = ""
        address_type = "Unknown"
        if IP in packet or IPv6 in packet:
            network = packet[IP] if IP in packet else packet[IPv6]
            source, destination, address_type = network.src, network.dst, "IP"
        elif ARP in packet:
            source, destination, address_type = packet[ARP].psrc, packet[ARP].pdst, "IP"
        elif Ether in packet:
            source, destination, address_type = packet[Ether].src, packet[Ether].dst, "MAC"
        transport = packet[TCP] if TCP in packet else packet[UDP] if UDP in packet else None
        sport, dport = (int(transport.sport), int(transport.dport)) if transport else (None, None)
        layers = [layer.__name__ for layer in packet.layers()]
        if ARP in packet:
            protocol = "ARP"
        elif DNS in packet:
            protocol = "DNS"
        elif TCP in packet:
            payload = bytes(packet[TCP].payload)
            if re.match(rb"^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP/1\.[01]\r\n|^HTTP/1\.[01] \d{3} ", payload):
                protocol = "HTTP"
            elif len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3 and payload[2] <= 4 and 0 < int.from_bytes(payload[3:5], "big") <= 18432:
                protocol = "TLS"
            else:
                protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        elif any(name.startswith("ICMPv6") for name in layers):
            protocol = "ICMPv6"
        elif IPv6 in packet:
            protocol = "IPv6"
        elif IP in packet:
            protocol = "IPv4"
        else:
            protocol = "Other"
        segment = None
        fragmented = (IP in packet and (packet[IP].frag or int(packet[IP].flags) & 1)) or IPv6ExtHdrFragment in packet
        if TCP in packet and address_type == "IP" and not fragmented:
            tcp = packet[TCP]
            content = bytes(tcp.payload)
            if Padding in tcp:
                padding_size = len(bytes(tcp[Padding]))
                if padding_size:
                    content = content[:-padding_size]
            segment = dict(source=source, destination=destination, source_port=sport,
                           destination_port=dport, seq=int(tcp.seq), ack=int(tcp.ack),
                           flags=int(tcp.flags), payload=content)
        return dict(source=source, destination=destination, address_type=address_type,
                    source_port=sport, destination_port=dport, protocol=protocol,
                    layers=" / ".join(layers)), False, segment
    except Exception:
        # Keep the frame in totals even if its packet contents cannot be decoded.
        return dict(source="", destination="", address_type="Unknown", source_port=None,
                    destination_port=None, protocol="Unknown", layers=f"Link type {link}"), True, None


def analyze_capture(data: bytes) -> Capture:
    if len(data) > MAX_BYTES:
        raise CaptureError("File exceeds the 100 MiB limit.")
    if data[:4] in PCAP_MAGIC:
        fmt, records = "PCAP", _pcap_records(data)
    elif data[:4] == b"\x0a\x0d\x0d\x0a":
        fmt, records = "PCAPNG", _pcapng_records(data)
    else:
        raise CaptureError("Expected a PCAP or PCAPNG binary capture (not PNG or an image).")
    rows, warnings = [], []
    http = HttpCollector()
    unknown, truncated, missing, disorder = 0, 0, 0, 0
    previous = None
    for frame, (raw, stamp, wirelen, link) in enumerate(records, 1):
        if frame > MAX_PACKETS:
            raise CaptureError("Capture exceeds 250,000 packets; export a smaller capture first.")
        if stamp is not None and not math.isfinite(stamp):
            raise CaptureError("Invalid non-finite timestamp.")
        fields, failed, segment = _packet_fields(raw, link)
        http.add(segment, frame, stamp)
        unknown += failed
        truncated += len(raw) < wirelen
        missing += stamp is None
        if stamp is not None:
            disorder += previous is not None and stamp < previous
            previous = stamp
        rows.append(dict(frame=frame, timestamp=stamp, captured_bytes=len(raw),
                         wire_bytes=wirelen, link_type=link, **fields))
    if missing:
        warnings.append(f"{missing:,} frames have no timestamp. They remain in totals but are excluded from the timeline.")
    if truncated:
        warnings.append(f"{truncated:,} frames were captured with fewer bytes than their original length. Protocol identification may be incomplete.")
    if unknown:
        warnings.append(f"{unknown:,} frames could not be decoded or use an unsupported link type. They remain in totals as Unknown.")
    if disorder:
        warnings.append("Timestamps are out of file order. Start/end use minimum/maximum timestamps.")
    transactions, http_warnings = http.finish()
    return Capture(fmt, rows, warnings, transactions, http_warnings)


def iso_time(stamp):
    if stamp is None:
        return None
    try:
        return datetime.fromtimestamp(stamp, timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, OverflowError, OSError):
        return f"Unix seconds: {stamp} (outside calendar range)"


def summarize(rows):
    stamps = [r["timestamp"] for r in rows if r["timestamp"] is not None]
    start, end = (min(stamps), max(stamps)) if stamps else (None, None)
    counts = Counter(r["protocol"] for r in rows)
    return dict(packet_count=len(rows), captured_bytes=sum(r["captured_bytes"] for r in rows),
                wire_bytes=sum(r["wire_bytes"] for r in rows), start=iso_time(start), end=iso_time(end),
                start_epoch=start, end_epoch=end, duration_seconds=end - start if stamps else None,
                timestamped_packets=len(stamps),
                protocols=[dict(protocol=p, packets=n, percent=round(100*n/len(rows), 2),
                                first_frame=next(r["frame"] for r in rows if r["protocol"] == p))
                           for p, n in counts.most_common()])


def endpoints(rows):
    stats = defaultdict(lambda: dict(sent_packets=0, received_packets=0, packets=0,
                                     sent_bytes=0, received_bytes=0, bytes=0, first_frame=None))
    for r in rows:
        for field, direction in (("source", "sent"), ("destination", "received")):
            if r[field]:
                item = stats[(r["address_type"], r[field])]
                item[f"{direction}_packets"] += 1
                item[f"{direction}_bytes"] += r["wire_bytes"]
        # A loopback frame counts once as endpoint involvement, once in each direction.
        for address in {r["source"], r["destination"]} - {""}:
            item = stats[(r["address_type"], address)]
            item["packets"] += 1
            item["bytes"] += r["wire_bytes"]
            if item["first_frame"] is None:
                item["first_frame"] = r["frame"]
    return sorted([dict(address=a, address_type=t, **v) for (t, a), v in stats.items()],
                  key=lambda r: (-r["bytes"], r["address"]))


def timeline(rows, bins=60):
    stamped = [r for r in rows if r["timestamp"] is not None]
    if not stamped:
        return []
    start = min(r["timestamp"] for r in stamped)
    duration = max(r["timestamp"] for r in stamped) - start
    width = duration / bins if duration > 0 else 1.0
    totals = [0] * (bins if duration > 0 else 1)
    for r in stamped:
        index = min(int((r["timestamp"] - start) / width), len(totals) - 1)
        totals[index] += r["wire_bytes"]
    return [dict(seconds=i * width, bytes=n, bin_seconds=width) for i, n in enumerate(totals)]
