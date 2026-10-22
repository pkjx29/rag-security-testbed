"""The small interface every generator implements, so the pipeline never depends on MLX."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

Messages = list[dict[str, str]]   # [{"role": "system"|"user"|"assistant", "content": ...}]


class ModelUnavailableError(RuntimeError):
    """The model cannot be loaded or reached. The message says how to fix it."""


class GenerationTimeout(RuntimeError):
    pass


@dataclass
class Generation:
    text: str
    latency_s: float
    cached: bool


class LLM(Protocol):
    model_id: str

    def generate(self, messages: Messages) -> Generation: ...
