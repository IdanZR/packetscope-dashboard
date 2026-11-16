"""Lazy CPU inference. No network calls, credentials, or capture bytes."""
from functools import lru_cache
import importlib.util
import json
import threading
from setup_local_ai import MODEL, MODEL_HASH, MODEL_NAME, LocalAIError, _digest

LOCK = threading.Lock()


def availability():
    if importlib.util.find_spec("llama_cpp") is None:
        return False, "Install the local AI library using setup_ai.bat or LOCAL_AI.md."
    if not MODEL.is_file():
        return False, "Download the free model once using setup_ai.bat or python setup_local_ai.py."
    return True, f"{MODEL_NAME} · CPU · no API key"


@lru_cache(maxsize=1)
def _model():
    ready, message = availability()
    if not ready:
        raise LocalAIError(message)
    if _digest(MODEL) != MODEL_HASH:
        raise LocalAIError("The model checksum changed. Run python setup_local_ai.py to restore it.")
    try:
        from llama_cpp import Llama
        return Llama(model_path=str(MODEL), n_ctx=4096, n_threads=4, n_threads_batch=4,
                     n_batch=256, n_gpu_layers=0, seed=7, verbose=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise LocalAIError(f"The local model could not load: {exc}") from exc


def complete(system, user, schema=None, max_tokens=220):
    """Use Qwen ChatML with thinking disabled. Serialize access across sessions."""
    with LOCK:
        model = _model()
        from llama_cpp import LlamaGrammar
        prompt = (f"<|im_start|>system\n{system}<|im_end|>\n"
                  f"<|im_start|>user\n{user}<|im_end|>\n"
                  "<|im_start|>assistant\n<think>\n\n</think>\n")
        if len(model.tokenize(prompt.encode("utf-8"))) + max_tokens > 4096:
            raise LocalAIError("This question or its context is too long. Try a shorter question.")
        grammar = LlamaGrammar.from_json_schema(json.dumps(schema), verbose=False) if schema else None
        try:
            result = model(prompt, max_tokens=max_tokens, temperature=0, grammar=grammar,
                           stop=["<|im_end|>", "<|endoftext|>"])
        except (OSError, RuntimeError, ValueError) as exc:
            raise LocalAIError(f"Local inference failed: {exc}") from exc
        choice = result["choices"][0]
        if choice.get("finish_reason") == "length":
            raise LocalAIError("The model did not finish interpreting the question. Try a shorter question.")
        return choice["text"].strip()
