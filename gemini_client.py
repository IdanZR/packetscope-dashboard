"""Bounded Google Gemini REST client; no capture files or raw messages are sent."""
import json
import os
import re
import time
import urllib.request
import urllib.error
from credentials import load_key
from setup_local_ai import LocalAIError

MODEL_NAME = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")
ORIGIN = "https://generativelanguage.googleapis.com/v1beta/"


def availability():
    return bool(load_key()), "Gemini · extracted HTTP metadata is sent to Google when you ask a question."


def _request(path, payload=None, key=None, retries=1):
    key = key or load_key()
    if not key:
        raise LocalAIError("Set GEMINI_API_KEY or save a key in AI settings.")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(ORIGIN + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json", "x-goog-api-key": key})
    try:
        with opener.open(request, timeout=45) as response:
            raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise LocalAIError("Gemini returned an oversized response.")
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        # Never display vendor response bodies, URLs or headers containing secrets.
        if 500 <= exc.code < 600 and retries:
            time.sleep(1)
            return _request(path,payload,key,retries-1)
        try:
            detail = json.loads(exc.read(100_000)).get("error", {})
            reasons = [d.get("reason") for d in detail.get("details", []) if isinstance(d, dict)]
            if "API_KEY_INVALID" in reasons:
                raise LocalAIError("Google rejected this API key as invalid.") from None
        except (ValueError, OSError):
            pass
        messages = {400: "Gemini rejected the request or API key. Check the key and selected model.",
                    401: "Gemini authentication failed. Check the API key.",
                    403: "Gemini access was denied. Check key restrictions and API access.",
                    404: "This Gemini model is unavailable. Choose another model in AI settings.",
                    429: "Gemini quota or rate limit reached. Try later or choose Local Qwen."}
        raise LocalAIError(messages.get(exc.code, f"Gemini service error ({exc.code}). Please try later.")) from None
    except (OSError, ValueError):
        raise LocalAIError("Could not reach Gemini. Check the internet connection and try again.") from None


def check_connection(key=None):
    data = _request("models?pageSize=100", key=key)
    return [m.get("name", "").removeprefix("models/") for m in data.get("models", [])
            if "generateContent" in m.get("supportedGenerationMethods", [])]


def complete(system, user, schema, model=None, key=None):
    model = model or MODEL_NAME
    if not re.fullmatch(r"gemini-[a-zA-Z0-9.\-]+", model):
        raise LocalAIError("Invalid Gemini model name.")
    result = _request(f"models/{model}:generateContent", dict(
        systemInstruction={"parts": [{"text": system}]},
        contents=[{"role": "user", "parts": [{"text": user}]}],
        generationConfig={"temperature": 0, "maxOutputTokens": 1024,
                          "responseMimeType": "application/json", "responseJsonSchema": schema}), key=key)
    candidates = result.get("candidates", [])
    if not candidates or candidates[0].get("finishReason") != "STOP":
        raise LocalAIError("Gemini did not return a complete answer. Please rephrase the question.")
    text = "".join(part.get("text", "") for part in candidates[0].get("content", {}).get("parts", []) if not part.get("thought"))
    if not text:
        raise LocalAIError("Gemini returned no query. Please rephrase the question.")
    return text
