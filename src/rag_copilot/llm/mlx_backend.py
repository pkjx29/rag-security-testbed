"""Local generator: 4-bit Qwen2.5-1.5B-Instruct on Apple MLX (Apple silicon only).

* The model is loaded lazily on the first request, from the local Hugging Face
  cache only. If it is missing, ModelUnavailableError says to run
  `make download-model`; nothing is downloaded implicitly.
* Generation streams tokens and stops at max_tokens or at the wall-clock timeout.
* With temperature 0 (greedy), the same prompt always gives the same answer, so
  generations are cached on disk, keyed by a hash of (model, settings, prompt).
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

from ..config import ModelConfig
from ..logging_config import get_logger
from .base import Generation, GenerationTimeout, Messages, ModelUnavailableError

log = get_logger(__name__)


def mlx_supported() -> bool:
    import platform
    return platform.system() == "Darwin" and platform.machine() == "arm64"


def download_model(model_id: str) -> str:
    """Explicit download step (make download-model). About 0.9 GB for the default model."""
    from huggingface_hub import snapshot_download
    return snapshot_download(model_id)


class MLXBackend:
    def __init__(self, cfg: ModelConfig, cache_dir: Path | None = None):
        self.cfg = cfg
        self.model_id = cfg.model_id
        self._model = None
        self._lock = threading.Lock()       # MLX inference is not re-entrant
        self.cache: dict[str, str] = {}
        self.cache_path = cache_dir / "generations.jsonl" if cache_dir else None
        if self.cache_path and self.cache_path.exists():
            for line in self.cache_path.read_text().splitlines():
                row = json.loads(line)
                self.cache[row["key"]] = row["output"]

    def _load(self):
        if self._model is not None:
            return self._model
        if not mlx_supported():
            raise ModelUnavailableError("MLX needs macOS on Apple silicon. Use RAG_BACKEND=openai_compatible "
                                        "with a local model server instead.")
        try:
            from huggingface_hub import snapshot_download
            from mlx_lm import load
            local = snapshot_download(self.model_id, local_files_only=True)
        except Exception as exc:   # missing package or files
            raise ModelUnavailableError(f"model {self.model_id} is not available locally "
                                        f"({type(exc).__name__}). Run: make download-model") from exc
        log.info("loading %s", self.model_id)
        self._model = load(local)
        return self._model

    def _key(self, prompt: str) -> str:
        c = self.cfg
        return hashlib.sha256(f"{c.model_id}|{c.max_tokens}|{c.temperature}|{prompt}".encode()).hexdigest()

    def generate(self, messages: Messages) -> Generation:
        from mlx_lm import stream_generate
        from mlx_lm.sample_utils import make_sampler

        model, tokenizer = self._load()
        prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        key = self._key(prompt)
        if key in self.cache:
            return Generation(self.cache[key], 0.0, cached=True)
        with self._lock:
            start = time.perf_counter()
            parts = []
            for resp in stream_generate(model, tokenizer, prompt, max_tokens=self.cfg.max_tokens,
                                        sampler=make_sampler(temp=self.cfg.temperature)):
                parts.append(resp.text)
                if time.perf_counter() - start > self.cfg.timeout_s:
                    raise GenerationTimeout(f"generation exceeded {self.cfg.timeout_s}s")
            latency = time.perf_counter() - start
        text = "".join(parts)
        if self.cfg.temperature == 0.0:      # only deterministic outputs are cacheable
            self.cache[key] = text
            if self.cache_path:
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.cache_path, "a") as f:
                    f.write(json.dumps({"key": key, "output": text}) + "\n")
        return Generation(text, latency, cached=False)
