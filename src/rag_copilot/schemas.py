"""Typed data models shared by the pipeline, the API and the evaluation."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import MAX_QUESTION_CHARS, DefenceConfig


class Principal(BaseModel):
    """An authenticated caller. Built by the application (API key lookup or the
    evaluation harness), never from text the caller writes."""
    model_config = ConfigDict(frozen=True)
    user_id: str
    role: str


class Chunk(BaseModel):
    chunk_id: str
    text: str
    metadata: dict[str, str | int | float | bool]


class Citation(BaseModel):
    ref: int                     # the [n] number shown to the model
    chunk_id: str
    doc_id: str
    title: str
    page: int | None = None
    url: str | None = None
    excerpt: str


class QueryRequest(BaseModel):
    question: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)
    defences: DefenceConfig = DefenceConfig()

    @field_validator("question")
    @classmethod
    def not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("question must not be blank")
        return v


class DefenceReport(BaseModel):
    """What each defence did for one request. Counts and IDs only: never raw values."""
    enabled: list[str]
    unauthorized_excluded: int = 0          # D2: chunks removed by the authorisation check
    injection_flagged: list[dict] = []      # D3: [{chunk_id, reasons}]
    injection_action: str | None = None     # D3: "excluded" | "blocked" | None
    output_actions: list[str] = []          # D4: e.g. ["removed_url", "redacted:EMAIL_ADDRESS"]


class QueryResponse(BaseModel):
    answer: str
    refused: bool
    citations: list[Citation]
    defences: DefenceReport
    latency_s: float
    model_id: str


class PipelineTrace(BaseModel):
    """Everything the evaluation needs. Not returned by the API, because it holds the
    raw model output and the IDs of every retrieved chunk, including unauthorised ones."""
    response: QueryResponse
    retrieved_ids: list[str]
    context_ids: list[str]
    raw_answer: str | None
    generation_latency_s: float | None
    generation_cached: bool | None
