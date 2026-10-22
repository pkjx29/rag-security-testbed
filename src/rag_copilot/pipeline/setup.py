"""Wiring: run ingestion, and assemble a ready-to-use pipeline."""
from __future__ import annotations

from ..config import Settings
from ..ingestion import corpus, synthetic
from ..llm import LLM, make_llm
from ..logging_config import get_logger
from ..retrieval import store as store_mod
from ..security.access_control import AccessPolicy
from .rag import RAGPipeline

log = get_logger(__name__)


def ingest(settings: Settings, rebuild: bool = False) -> dict:
    """Download + verify NIST PDFs, generate synthetic records, build both indexes and the ACL."""
    p, r = settings.paths, settings.retrieval
    hashes = corpus.download(p)
    nist = corpus.load_chunks(p, r)
    corpus.write_manifest(p, hashes, nist)
    syn = synthetic.write_and_load(p)
    chunks = nist + synthetic.as_chunks(syn)
    # The ACL is written from the ingestion pipeline's own records, separately from Chroma.
    AccessPolicy.from_chunks(chunks).save(p.processed / "acl.json")
    stats = store_mod.build(p, r, chunks, rebuild=rebuild)
    return {"nist_chunks": len(nist), "synthetic_chunks": len(chunks) - len(nist), "redaction": stats}


def is_ingested(settings: Settings) -> bool:
    return (settings.paths.processed / "acl.json").exists() and settings.paths.chroma.exists()


def load_pipeline(settings: Settings, llm: LLM | None = None) -> RAGPipeline:
    p, r = settings.paths, settings.retrieval
    stores = {False: store_mod.Store(p, r, redacted=False), True: store_mod.Store(p, r, redacted=True)}
    policy = AccessPolicy.load(p.processed / "acl.json")
    return RAGPipeline(settings, stores, policy, llm or make_llm(settings))  # type: ignore[arg-type]
