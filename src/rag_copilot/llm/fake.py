"""A deterministic stand-in model, for isolated unit tests only.

The real application and the benchmark always use a real local model; nothing in
src/ imports this module except the tests' fixtures.
"""
from __future__ import annotations

from collections.abc import Callable

from .base import Generation, Messages


class FakeLLM:
    model_id = "fake-llm"

    def __init__(self, respond: Callable[[Messages], str] | None = None):
        self.respond = respond or (lambda m: "Based on [1], see the cited guidance.")
        self.calls: list[Messages] = []

    def generate(self, messages: Messages) -> Generation:
        self.calls.append(messages)
        return Generation(text=self.respond(messages), latency_s=0.0, cached=False)
