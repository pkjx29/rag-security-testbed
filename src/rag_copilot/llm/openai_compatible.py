"""Backend for a model server on the local machine that speaks the OpenAI chat API,
for example `mlx_lm.server` running on the Mac host while the API runs in Docker.

It refuses any URL that is not loopback or the Docker host alias, so it cannot be
pointed at a hosted inference service by mistake.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse

import httpx

from ..config import ModelConfig
from .base import Generation, GenerationTimeout, Messages, ModelUnavailableError

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "host.docker.internal"}


class OpenAICompatibleBackend:
    def __init__(self, cfg: ModelConfig):
        host = urlparse(cfg.server_url).hostname
        if host not in LOCAL_HOSTS:
            raise ValueError(f"model server must be local, got host {host!r}")
        self.cfg = cfg
        self.model_id = cfg.model_id

    def generate(self, messages: Messages) -> Generation:
        start = time.perf_counter()
        try:
            r = httpx.post(f"{self.cfg.server_url}/chat/completions", timeout=self.cfg.timeout_s, json={
                "model": self.cfg.model_id, "messages": messages,
                "max_tokens": self.cfg.max_tokens, "temperature": self.cfg.temperature})
        except httpx.TimeoutException as exc:
            raise GenerationTimeout(str(exc)) from exc
        except httpx.HTTPError as exc:
            raise ModelUnavailableError(f"cannot reach model server at {self.cfg.server_url}") from exc
        r.raise_for_status()
        return Generation(r.json()["choices"][0]["message"]["content"], time.perf_counter() - start, False)
