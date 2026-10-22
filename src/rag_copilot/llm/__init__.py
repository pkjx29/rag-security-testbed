from ..config import Settings
from .base import LLM, Generation, GenerationTimeout, ModelUnavailableError


def make_llm(settings: Settings) -> LLM:
    if settings.model.backend == "openai_compatible":
        from .openai_compatible import OpenAICompatibleBackend
        return OpenAICompatibleBackend(settings.model)
    from .mlx_backend import MLXBackend
    return MLXBackend(settings.model, cache_dir=settings.paths.llm_cache)


__all__ = ["LLM", "Generation", "GenerationTimeout", "ModelUnavailableError", "make_llm"]
