"""Download the pinned free Qwen model once: python -m packetscope.ai.model_setup.

Inference uses llama-cpp-python on CPU. No account or API key is needed.
"""
import argparse
import hashlib
import json
import urllib.request

from packetscope.paths import PROJECT_ROOT

ROOT = PROJECT_ROOT
ASSETS = ROOT / ".local_ai"
MODEL = ASSETS / "Qwen3-0.6B-Q8_0.gguf"
MODEL_NAME = "Qwen3-0.6B-Q8_0"
MODEL_URL = "https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/resolve/23749fefcc72300e3a2ad315e1317431b06b590a/Qwen3-0.6B-Q8_0.gguf"
MODEL_HASH = "9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031"


class LocalAIError(RuntimeError):
    pass


def _digest(path):
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(1024*1024), b""):
            checksum.update(part)
    return checksum.hexdigest()


def setup():
    ASSETS.mkdir(exist_ok=True)
    if not MODEL.is_file() or _digest(MODEL) != MODEL_HASH:
        partial = MODEL.with_suffix(".gguf.part")
        request = urllib.request.Request(MODEL_URL, headers={"User-Agent": "PacketScope-local-setup"})
        downloaded, next_update = 0, 0
        print("Downloading the free model (about 640 MB)...", flush=True)
        with urllib.request.urlopen(request, timeout=60) as response, partial.open("wb") as output:
            while chunk := response.read(1024*1024):
                output.write(chunk)
                downloaded += len(chunk)
                if downloaded >= next_update:
                    print(f"  {downloaded/1_000_000:.0f} MB", flush=True)
                    next_update = downloaded + 50_000_000
        if _digest(partial) != MODEL_HASH:
            raise LocalAIError("Model checksum failed; the file will not be loaded.")
        partial.replace(MODEL)
    (ASSETS / "manifest.json").write_text(json.dumps(dict(model=MODEL_NAME,
        sha256=MODEL_HASH, license="Apache-2.0", url=MODEL_URL), indent=2), encoding="utf-8")
    print("Model verified. Free local AI is ready; no API key is needed.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        setup()
    except (OSError, ValueError, LocalAIError) as exc:
        parser.exit(1, f"Local AI setup failed: {exc}\n")
