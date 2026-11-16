"""Lossless captured HTTP bytes with explicitly bounded text presentation."""
import base64

DISPLAY_LIMIT = 256 * 1024


def message_bytes(message):
    if not message:
        return b""
    return base64.b64decode(message.get("raw_message_b64", ""), validate=True)


def message_text(message, full=False):
    raw = message_bytes(message)
    shown = raw if full else raw[:DISPLAY_LIMIT]
    return shown.decode("utf-8", "replace"), len(shown) < len(raw)
