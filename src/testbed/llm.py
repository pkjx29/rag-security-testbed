"""Local generator: a 4-bit quantised Qwen2.5-1.5B-Instruct running on Apple MLX.

Decoding is greedy (temperature 0), so the same prompt always gives the same
answer. That makes results reproducible, and lets us cache generations on disk
keyed by a hash of (model, prompt, max_tokens): re-running the evaluation, or
running a defence that leaves the prompt unchanged, costs no extra inference.
"""
import hashlib
import json
from functools import lru_cache

from . import config


@lru_cache(maxsize=1)
def _model():
    from mlx_lm import load
    return load(config.MODEL_ID)


class CachedLLM:
    def __init__(self):
        config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self.path = config.CACHE_DIR / "generations.jsonl"
        self.cache = {}
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                row = json.loads(line)
                self.cache[row["key"]] = row["output"]
        self.hits = self.misses = 0

    def __call__(self, messages: list[dict]) -> str:
        from mlx_lm import generate
        model, tokenizer = _model()
        prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        key = hashlib.sha256(f"{config.MODEL_ID}|{config.MAX_TOKENS}|{prompt}".encode()).hexdigest()
        if key in self.cache:
            self.hits += 1
            return self.cache[key]
        self.misses += 1
        out = generate(model, tokenizer, prompt=prompt, max_tokens=config.MAX_TOKENS, verbose=False)
        self.cache[key] = out
        with open(self.path, "a") as f:
            f.write(json.dumps({"key": key, "output": out}) + "\n")
        return out
