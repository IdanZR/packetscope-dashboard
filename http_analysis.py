"""Bounded HTTP/1.x reconstruction from captured TCP bytes (RFC 9112/9293).

No network activity. Missing bytes are never filled, and conflicting overlaps
disable pairing. Frame references describe bytes seen in this capture.
"""
from bisect import bisect_right
from collections import deque
from dataclasses import dataclass, field
import re
import base64
from urllib.parse import urlsplit

TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
REQUEST = re.compile(rb"(" + TOKEN + rb") ([^\x00-\x20]+) HTTP/(1\.[01])$")
RESPONSE = re.compile(rb"HTTP/(1\.[01]) ([1-9][0-9]{2})(?: ([^\r\n]*))?$")
HEADER = re.compile(TOKEN + rb"$")
MAX_HEADER = 64 * 1024
MAX_DIRECTION = 4 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_MESSAGES = 10_000
PREVIEW = 2048


@dataclass
class Direction:
    anchor: int | None = None
    segments: list = field(default_factory=list)
    fins: list = field(default_factory=list)
    size: int = 0


@dataclass
class Connection:
    number: int
    endpoints: tuple
    directions: list = field(default_factory=lambda: [Direction(), Direction()])
    syn: tuple | None = None
    reset: bool = False
    skipped: bool = False


class HttpCollector:
    def __init__(self):
        self.connections = []
        self.current = {}
        self.total = 0
        self.warnings = []

    def add(self, segment, frame, timestamp):
        if segment is None:
            return
        src = (segment["source"], segment["source_port"])
        dst = (segment["destination"], segment["destination_port"])
        key = tuple(sorted((src, dst)))
        conn = self.current.get(key)
        syn = (src, segment["seq"]) if segment["flags"] & 2 and not segment["flags"] & 16 else None
        if conn is None or (syn and (conn.syn != syn or conn.reset)):
            conn = Connection(len(self.connections) + 1, key, syn=syn)
            self.connections.append(conn)
            self.current[key] = conn
        side = 0 if src == key[0] else 1
        direction = conn.directions[side]
        seq = (segment["seq"] + bool(segment["flags"] & 2)) % 2**32
        if direction.anchor is None:
            direction.anchor = seq
        payload = segment["payload"]
        if payload and not conn.skipped:
            if direction.size + len(payload) > MAX_DIRECTION or self.total + len(payload) > MAX_TOTAL:
                conn.skipped = True
                self.warnings.append(f"Connection {conn.number}: HTTP reconstruction skipped after reaching the payload memory limit.")
                for d in conn.directions:
                    d.segments.clear()
                # Keep the accumulated budget: later traffic must not silently restart analysis.
            else:
                direction.segments.append(dict(seq=seq, data=payload, frame=frame,
                                               timestamp=timestamp, ack=segment["ack"]))
                direction.size += len(payload)
                self.total += len(payload)
        if segment["flags"] & 1:
            direction.fins.append((seq + len(payload)) % 2**32)
        if segment["flags"] & 4:
            conn.reset = True

    def finish(self):
        transactions = []
        for conn in self.connections:
            if conn.skipped:
                continue
            found, notes = _connection_transactions(conn)
            if notes:
                self.warnings.extend(f"Connection {conn.number}: {note}" for note in notes)
            available = MAX_MESSAGES - len(transactions)
            transactions.extend(found[:available])
            if len(found) > available or len(transactions) >= MAX_MESSAGES:
                self.warnings.append("HTTP transaction display is limited to 10,000 entries; the results are partial.")
                break
        for number, transaction in enumerate(transactions, 1):
            transaction["transaction_id"] = number
        return transactions, list(dict.fromkeys(self.warnings))


def _offset(seq, anchor):
    return (seq - anchor + 2**31) % 2**32 - 2**31


class Stream:
    def __init__(self, direction):
        self.data = bytearray()
        self.spans = []
        self.starts = []
        self.base = 0
        self.anchor = direction.anchor or 0
        self.gap = False
        self.conflict = False
        ordered = sorted([(_offset(s["seq"], self.anchor), s) for s in direction.segments],
                         key=lambda item: (item[0], item[1]["frame"]))
        if ordered:
            self.base = ordered[0][0]
            # A SYN/ACK-only anchor before the first payload exposes a missing prefix.
            self.gap = self.base > 0
        for position, segment in ordered:
            position -= self.base
            if position > len(self.data):
                self.gap = True
                break  # Never parse across a hole or scan bodies for another start line.
            payload = segment["data"]
            overlap = min(len(payload), len(self.data) - position)
            if self.data[position:position + overlap] != payload[:overlap]:
                self.conflict = True
            if overlap < len(payload):
                start = len(self.data)
                self.data.extend(payload[overlap:])
                self.starts.append(start)
                self.spans.append((start, len(self.data), segment))
        self.closed = any(_offset(fin, self.anchor) - self.base == len(self.data)
                          for fin in direction.fins) and not self.gap

    def evidence(self, start, end):
        first = max(0, bisect_right(self.starts, start) - 1)
        spans = []
        for index in range(first, len(self.spans)):
            span = self.spans[index]
            if span[0] >= end:
                break
            if span[1] > start:
                spans.append(span)
        return spans


def _header_values(headers, name):
    return [v for k, v in headers if k.lower() == name]


def _chunked(data, start):
    cursor, preview, size = start, bytearray(), 0
    while cursor < len(data):
        end = data.find(b"\r\n", cursor)
        if end < 0:
            break
        token = data[cursor:end].split(b";", 1)[0]
        if len(token) > 16 or not re.fullmatch(rb"[0-9A-Fa-f]+", token):
            return len(data), False, bytes(preview), size, "Invalid chunk size; later messages were not parsed."
        length = int(token, 16)
        cursor = end + 2
        if length == 0:
            if data[cursor:cursor + 2] == b"\r\n":
                return cursor + 2, True, bytes(preview), size, None
            trailer_end = data.find(b"\r\n\r\n", cursor)
            if trailer_end >= 0:
                return trailer_end + 4, True, bytes(preview), size, None
            break
        available = data[cursor:min(cursor + length, len(data))]
        preview.extend(available[:max(0, PREVIEW - len(preview))])
        size += len(available)
        if cursor + length + 2 > len(data):
            break
        if data[cursor + length:cursor + length + 2] != b"\r\n":
            return len(data), False, bytes(preview), size, "Invalid chunk terminator; later messages were not parsed."
        cursor += length + 2
    return len(data), False, bytes(preview), size, "Chunked body is incomplete in this capture."


def _body(data, start, headers, response, status, method, closed):
    notes = []
    lengths = [part.strip() for value in _header_values(headers, "content-length") for part in value.split(",")]
    transfer = [part.strip().lower() for value in _header_values(headers, "transfer-encoding") for part in value.split(",")]
    ambiguous = bool(transfer and lengths)
    if ambiguous:
        notes.append("Both Transfer-Encoding and Content-Length are present; pairing is disabled.")
    no_body = response and (method == "HEAD" or 100 <= status < 200 or status in (204, 304)
                            or method == "CONNECT" and 200 <= status < 300)
    if no_body:
        return start, True, b"", 0, notes, ambiguous
    if transfer and transfer[-1] == "chunked":
        end, complete, preview, size, note = _chunked(data, start)
        if note:
            notes.append(note)
        return end, complete, preview, size, notes, ambiguous or bool(note and note.startswith("Invalid"))
    if transfer:
        if not response:
            return len(data), False, bytes(data[start:start + PREVIEW]), len(data) - start, ["Unsupported request transfer coding; pairing is disabled."], True
        end, complete = len(data), closed
    elif lengths:
        if any(not re.fullmatch(r"[0-9]{1,18}", value) for value in lengths) or len(set(lengths)) != 1:
            return len(data), False, b"", 0, ["Invalid or conflicting Content-Length; pairing is disabled."], True
        expected = start + int(lengths[0])
        end, complete = min(expected, len(data)), expected <= len(data)
    elif response:
        end, complete = len(data), closed
        if not complete:
            notes.append("Close-delimited response: no complete FIN boundary was captured.")
    else:
        end, complete = start, True
    if not complete and not notes:
        notes.append("Message body is incomplete in this capture.")
    return end, complete, bytes(data[start:min(end, start + PREVIEW)]), end - start, notes, ambiguous


def _parse(stream, response=False, methods=None):
    data, position, messages, notes, request_index = stream.data, 0, [], [], 0
    while position < len(data) and len(messages) < MAX_MESSAGES:
        header_end = data.find(b"\r\n\r\n", position)
        if header_end < 0 or header_end - position > MAX_HEADER:
            if messages or data[position:].startswith((b"HTTP/", b"GET ", b"POST ", b"HEAD ")):
                notes.append("An incomplete or oversized HTTP header was not parsed.")
            break
        lines = bytes(data[position:header_end]).split(b"\r\n")
        match = (RESPONSE if response else REQUEST).fullmatch(lines[0])
        if not match:
            if messages:
                notes.append("Non-HTTP bytes follow the last parsed message; parsing stopped at that boundary.")
            break
        headers = []
        for line in lines[1:]:
            name, sep, value = line.partition(b":")
            if not sep or not HEADER.fullmatch(name):
                notes.append("Malformed or folded HTTP header; parsing stopped.")
                return messages, notes
            headers.append((name.decode("ascii"), value.strip().decode("latin-1")))
        status = int(match[2]) if response else None
        method = (methods[request_index] if methods and request_index < len(methods) else None) if response else match[1].decode("ascii")
        start_body = header_end + 4
        end, complete, preview, body_size, body_notes, unsafe = _body(
            data, start_body, headers, response, status, method, stream.closed)
        spans = stream.evidence(position, max(end, start_body))
        first = spans[0][2]
        header_spans = stream.evidence(position, start_body)
        completion = max((span[2] for span in spans), key=lambda segment: segment["frame"])
        message = dict(start_line=lines[0].decode("latin-1"), headers=[list(h) for h in headers],
                       raw_message_b64=base64.b64encode(bytes(data[position:end])).decode("ascii"),
                       raw_message_bytes=end-position,
                       frame=first["frame"], timestamp=first["timestamp"],
                       frames=sorted({span[2]["frame"] for span in spans}),
                       header_complete_frame=max(span[2]["frame"] for span in header_spans),
                       complete_frame=completion["frame"] if complete else None,
                       complete_timestamp=completion["timestamp"] if complete else None,
                       body_complete=complete, body_bytes_captured=body_size,
                       body_preview=preview.decode("utf-8", "replace"),
                       body_preview_truncated=body_size > len(preview), notes=body_notes,
                       framing_unsafe=unsafe, ack=first["ack"],
                       header_end_seq=(stream.anchor + stream.base + start_body) % 2**32)
        if response:
            message.update(status_code=status, http_version=match[1].decode("ascii"))
            if status >= 200 or status == 101:
                request_index += 1
        else:
            uri = match[2].decode("latin-1")
            hosts = _header_values(headers, "host")
            try:
                host = hosts[0] if hosts else (urlsplit(uri).netloc or None)
            except ValueError:
                host = None
            message.update(method=method, uri=uri, host=host, http_version=match[3].decode("ascii"))
        messages.append(message)
        if not complete or unsafe or response and (status == 101 or method == "CONNECT" and 200 <= status < 300):
            break
        position = end
    if len(messages) == MAX_MESSAGES:
        notes.append("HTTP parsing stopped at the message count limit.")
    return messages, notes


def _transaction(conn, client_side, request=None, response=None, interim=None, warning=None):
    source, destination = conn.endpoints[client_side], conn.endpoints[1 - client_side]
    delta, first_byte_delta = None, None
    notes = [warning] if warning else []
    if request and response and request["timestamp"] is not None and response["timestamp"] is not None:
        first_byte_delta = response["timestamp"] - request["timestamp"]
        if first_byte_delta < 0:
            first_byte_delta = None
            notes.append("Response timestamp precedes request timestamp; response time is unavailable.")
    if request and response and request["complete_timestamp"] is not None and response["complete_timestamp"] is not None:
        delta = response["complete_timestamp"] - request["complete_timestamp"]
        if delta < 0:
            delta = None
    request_frame = request["complete_frame"] or request["header_complete_frame"] if request else None
    response_frame = response["complete_frame"] or response["header_complete_frame"] if response else None
    state = "Uncertain" if warning else "Matched" if request and response else "No response captured" if request else "No request captured"
    return dict(connection_id=conn.number, method=request["method"] if request else None,
                host=request["host"] if request else None, uri=request["uri"] if request else None,
                source=source[0], source_port=source[1], destination=destination[0], destination_port=destination[1],
                status_code=response["status_code"] if response else None,
                response_time_ms=round(delta * 1000, 6) if delta is not None else None,
                first_byte_delay_ms=round(first_byte_delta * 1000, 6) if first_byte_delta is not None else None,
                request_frame=request_frame, response_frame=response_frame,
                request_first_byte_frame=request["frame"] if request else None,
                response_first_byte_frame=response["frame"] if response else None,
                match_status=state, request=request, response=response, informational_responses=interim or [], notes=notes)


def _connection_transactions(conn):
    streams = [Stream(d) for d in conn.directions]
    request_sides = [i for i, stream in enumerate(streams) if REQUEST.fullmatch(bytes(stream.data).split(b"\r\n", 1)[0])]
    response_sides = [i for i, stream in enumerate(streams) if RESPONSE.fullmatch(bytes(stream.data).split(b"\r\n", 1)[0])]
    if len(request_sides) == 1:
        client = request_sides[0]
    elif not request_sides and len(response_sides) == 1:
        client = 1 - response_sides[0]
    else:
        return [], []
    requests, notes1 = _parse(streams[client])
    responses, notes2 = _parse(streams[1 - client], response=True, methods=[r["method"] for r in requests])
    notes = notes1 + notes2
    unsafe = None
    if any(s.conflict for s in streams):
        unsafe = "Conflicting TCP overlaps: automatic pairing is disabled for this connection."
    elif any(s.gap for s in streams):
        unsafe = "Missing TCP bytes: automatic pairing is disabled for this connection."
    elif any(m["framing_unsafe"] for m in requests + responses):
        unsafe = "Ambiguous HTTP framing: automatic pairing is disabled for this connection."
    if unsafe:
        notes.append(unsafe)
        return ([_transaction(conn, client, request=r, warning=unsafe) for r in requests]
                + [_transaction(conn, client, response=r, warning=unsafe) for r in responses]), notes
    pending, results, interim = deque(requests), [], []
    for response in responses:
        if 100 <= response["status_code"] < 200 and response["status_code"] != 101:
            interim.append(response)
            continue
        request = pending[0] if pending else None
        if request and (response["frame"] < request["frame"] or
                        (response["ack"] - request["header_end_seq"]) % 2**32 >= 2**31):
            results.append(_transaction(conn, client, response=response, interim=interim,
                                        warning="The response order or TCP acknowledgement does not support a safe request match."))
        else:
            if request:
                pending.popleft()
            results.append(_transaction(conn, client, request=request, response=response, interim=interim))
        interim = []
    for request in pending:
        item = _transaction(conn, client, request=request, interim=interim)
        if interim:
            item["notes"].append("Only informational responses were captured; the final response is missing.")
        results.append(item)
        interim = []
    if interim:
        for response in interim:
            results.append(_transaction(conn, client, response=response))
    return results, notes
