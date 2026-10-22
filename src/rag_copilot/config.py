"""Configuration. Every value that affects results lives here.

Paths and the model can be overridden with environment variables (prefix RAG_),
for example RAG_DATA_DIR or RAG_MODEL_ID. Defence switches are per request or
per experiment (DefenceConfig), not global, so one process can run every
configuration side by side.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[2]


def _env_path(name: str, default: Path) -> Path:
    return Path(os.environ.get(f"RAG_{name}", default))


class Paths(BaseModel):
    data: Path = _env_path("DATA_DIR", ROOT / "data")
    storage: Path = _env_path("STORAGE_DIR", ROOT / "storage")
    results: Path = _env_path("RESULTS_DIR", ROOT / "results")

    @property
    def raw(self) -> Path:            # downloaded NIST PDFs (not committed)
        return self.data / "raw"

    @property
    def processed(self) -> Path:      # chunk manifest, ACL, redaction stats (not committed)
        return self.data / "processed"

    @property
    def synthetic(self) -> Path:      # fake records (committed, deterministic)
        return self.data / "synthetic"

    @property
    def benchmarks(self) -> Path:     # benchmark cases (committed)
        return self.data / "benchmarks"

    @property
    def chroma(self) -> Path:         # ChromaDB persistent store (not committed)
        return self.storage / "chroma"

    @property
    def llm_cache(self) -> Path:      # generation cache (not committed)
        return self.storage / "llm_cache"


class SourceDocument(BaseModel):
    doc_id: str
    title: str
    url: str
    sha256: str
    published: str


# Public corpus: NIST publications (US Government works, public domain).
# SHA-256 pins the exact bytes the committed results were produced from.
CORPUS: list[SourceDocument] = [
    SourceDocument(
        doc_id="sp800-66r2",
        title="NIST SP 800-66 Rev. 2: Implementing the HIPAA Security Rule: A Cybersecurity Resource Guide",
        url="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-66r2.pdf",
        sha256="3910c9b29e06d978bf17258d94e851d8d3d786ceb65beb352cc93271f4d3173e",
        published="2024-02"),
    SourceDocument(
        doc_id="privacy-framework",
        title="NIST Privacy Framework: A Tool for Improving Privacy through Enterprise Risk Management, Version 1.0",
        url="https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.01162020.pdf",
        sha256="58e1f2373e1c8a5782f7ddfce677fa9fc15e2d920ec0ab97ee754697e91bc2f0",
        published="2020-01"),
    SourceDocument(
        doc_id="ir8053",
        title="NISTIR 8053: De-Identification of Personal Information",
        url="https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.8053.pdf",
        sha256="ab7371fb6707a328ce6a75e7151b69e5c0442d3453ab4146decee328bf8b7628",
        published="2015-10"),
    SourceDocument(
        doc_id="ai100-2e2025",
        title="NIST AI 100-2 E2025: Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations",
        url="https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf",
        sha256="4811fb6ad73f9c9121843ab77e029b5adc6f2c86d33c2fc5b2099ef133847646",
        published="2025-03"),
]


class RetrievalConfig(BaseModel):
    chunk_size: int = Field(900, ge=200, le=4000)        # characters
    chunk_overlap: int = Field(150, ge=0, le=1000)
    top_k: int = Field(4, ge=1, le=20)
    # Chroma's built-in all-MiniLM-L6-v2 (ONNX, 384-d). Same weights as the
    # sentence-transformers model, but no PyTorch download (see docs/architecture.md).
    embedding_model: str = "chromadb-default/all-MiniLM-L6-v2-onnx"
    collection_plain: str = "nist_plain"
    collection_redacted: str = "nist_redacted"


class ModelConfig(BaseModel):
    backend: Literal["mlx", "openai_compatible"] = os.environ.get("RAG_BACKEND", "mlx")  # type: ignore[assignment]
    model_id: str = os.environ.get("RAG_MODEL_ID", "mlx-community/Qwen2.5-1.5B-Instruct-4bit")
    # Only used by the openai_compatible backend: a server on the local machine,
    # e.g. `mlx_lm.server` on the host when the API runs in Docker. Never a hosted API.
    server_url: str = os.environ.get("RAG_MODEL_SERVER_URL", "http://127.0.0.1:8080/v1")
    max_tokens: int = Field(200, ge=1, le=2048)
    temperature: float = Field(0.0, ge=0.0, le=2.0)     # 0 = greedy, deterministic and cacheable
    timeout_s: float = Field(60.0, gt=0)


class DefenceConfig(BaseModel):
    """The four defences. Each is independently switchable."""
    redaction: bool = False            # D1: read the Presidio-redacted index
    access_control: bool = False       # D2: document-level authorisation
    injection_filter: bool = False     # D3: screen retrieved chunks
    output_filter: bool = False        # D4: screen the answer
    injection_policy: Literal["exclude", "block"] = "exclude"
    output_policy: Literal["redact", "block"] = "redact"

    def enabled(self) -> list[str]:
        names = ("redaction", "access_control", "injection_filter", "output_filter")
        return [n for n in names if getattr(self, n)]


BASELINE = DefenceConfig()
PROTECTED = DefenceConfig(redaction=True, access_control=True, injection_filter=True, output_filter=True)

# The six experiment configurations (A-F in docs/evaluation_methodology.md).
EXPERIMENTS: dict[str, tuple[str, DefenceConfig]] = {
    "A": ("Baseline (no defences)", BASELINE),
    "B": ("D1 Presidio redaction at indexing", DefenceConfig(redaction=True)),
    "C": ("D2 Document-level access control", DefenceConfig(access_control=True)),
    "D": ("D3 Injection filter", DefenceConfig(injection_filter=True)),
    "E": ("D4 Output filter", DefenceConfig(output_filter=True)),
    "F": ("All four defences", PROTECTED),
}

# Roles -> document access levels. Unknown roles get nothing (deny by default).
ROLE_ACCESS: dict[str, frozenset[str]] = {
    "public": frozenset({"public"}),
    "clinician": frozenset({"public", "restricted"}),
    "admin": frozenset({"public"}),     # runs evaluations; no extra data access
}

# Synthetic data
SEED = 1337
N_PATIENT_RECORDS = 40   # access_level = restricted
N_HR_MEMOS = 10          # personal data wrongly filed as public

# Secret embedded in the system prompt, used to measure system-prompt leakage.
SYSTEM_CANARY = "NW-ASSIST-7731"
# Output filter: links to anything outside this list are removed.
URL_ALLOWLIST = ["nist.gov", "hhs.gov"]
MAX_QUESTION_CHARS = 1000


class Settings(BaseModel):
    paths: Paths = Paths()
    retrieval: RetrievalConfig = RetrievalConfig()
    model: ModelConfig = ModelConfig()


def get_settings() -> Settings:
    return Settings()
