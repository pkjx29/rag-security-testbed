"""ChromaDB vector store with two collections built from the same documents:

  nist_plain     - documents indexed as-is (baseline; used only for controlled testing)
  nist_redacted  - every document passed through Presidio first (defence D1)

Embeddings come from Chroma's built-in all-MiniLM-L6-v2 ONNX model (384-d), which
runs on CPU without PyTorch. The embedder name is stored on each collection and
checked on open, so a collection is never queried with a different model than
the one that built it.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter

import chromadb
from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

from ..config import Paths, RetrievalConfig
from ..logging_config import get_logger
from ..privacy.redaction import redact_with_stats
from ..schemas import Chunk

log = get_logger(__name__)
PLANTED_KIND = "planted"   # documents added by the evaluation harness (attacks, look-alikes)


class EmbeddingMismatch(RuntimeError):
    pass


def fingerprint(chunks: list[Chunk]) -> str:
    payload = json.dumps([[c.chunk_id, c.text, c.metadata] for c in chunks], sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class Store:
    def __init__(self, paths: Paths, cfg: RetrievalConfig, redacted: bool):
        self.cfg = cfg
        self.redacted = redacted
        self.name = cfg.collection_redacted if redacted else cfg.collection_plain
        self.client = chromadb.PersistentClient(path=str(paths.chroma))
        self.col = self.client.get_or_create_collection(
            name=self.name, embedding_function=DefaultEmbeddingFunction(),  # type: ignore[arg-type]
            metadata={"hnsw:space": "cosine", "embedding_model": cfg.embedding_model},
        )
        stored = (self.col.metadata or {}).get("embedding_model")
        if stored != cfg.embedding_model:
            raise EmbeddingMismatch(f"collection {self.name} was built with {stored}, "
                                    f"config says {cfg.embedding_model}; rebuild the index")

    # --- ingestion -------------------------------------------------------
    def ingest_text(self, text: str) -> tuple[str, Counter]:
        """The ingestion transform applied to every document, including planted ones."""
        return redact_with_stats(text) if self.redacted else (text, Counter())

    def upsert(self, chunks: list[Chunk], batch: int = 256) -> Counter:
        """Idempotent: same chunk IDs overwrite, never duplicate. Returns redaction counts."""
        totals: Counter = Counter()
        for i in range(0, len(chunks), batch):
            part = chunks[i:i + batch]
            texts = []
            for c in part:
                text, counts = self.ingest_text(c.text)
                texts.append(text)
                totals.update(counts)
            self.col.upsert(ids=[c.chunk_id for c in part], documents=texts,
                            metadatas=[dict(c.metadata) for c in part])  # type: ignore[misc]
        return totals

    def count(self) -> int:
        return self.col.count()

    def get(self, chunk_id: str) -> Chunk | None:
        res = self.col.get(ids=[chunk_id])
        if not res["ids"]:
            return None
        return Chunk(chunk_id=res["ids"][0], text=res["documents"][0],  # type: ignore[index]
                     metadata=res["metadatas"][0])  # type: ignore[index,arg-type]

    # --- retrieval -------------------------------------------------------
    def query(self, question: str, k: int | None = None, where: dict | None = None) -> list[Chunk]:
        if self.count() == 0:
            return []
        res = self.col.query(query_texts=[question], n_results=k or self.cfg.top_k, where=where)
        return [Chunk(chunk_id=i, text=t, metadata=m)  # type: ignore[arg-type]
                for i, t, m in zip(res["ids"][0], res["documents"][0], res["metadatas"][0])]  # type: ignore[index]

    # --- evaluation harness ---------------------------------------------
    def plant(self, chunk: Chunk) -> None:
        self.upsert([chunk])

    def remove_planted(self) -> None:
        self.col.delete(where={"kind": PLANTED_KIND})

    def fingerprint(self) -> str | None:
        return (self.col.metadata or {}).get("fingerprint")  # type: ignore[return-value]

    def mark_built(self, fp: str) -> None:
        # Written last, so an interrupted build is never mistaken for a complete one.
        self.col.modify(metadata={"embedding_model": self.cfg.embedding_model, "fingerprint": fp})


def build(paths: Paths, cfg: RetrievalConfig, chunks: list[Chunk], rebuild: bool = False) -> dict:
    """(Re)build both collections unless they already hold exactly these chunks.
    Returns aggregate redaction counts for the protected index (no raw values)."""
    fp = fingerprint(chunks)
    stats_path = paths.processed / "redaction_stats.json"
    client = chromadb.PersistentClient(path=str(paths.chroma))
    for redacted in (False, True):
        name = cfg.collection_redacted if redacted else cfg.collection_plain
        if rebuild and name in {c.name for c in client.list_collections()}:
            client.delete_collection(name)
        store = Store(paths, cfg, redacted)
        store.remove_planted()                      # clean up after an interrupted run
        if store.fingerprint() == fp and store.count() == len(chunks):
            log.info("%s: %d chunks (up to date)", name, store.count())
            continue
        client.delete_collection(name)
        store = Store(paths, cfg, redacted)
        log.info("%s: embedding %d chunks%s", name, len(chunks), " after Presidio redaction" if redacted else "")
        counts = store.upsert(chunks)
        if redacted:
            paths.processed.mkdir(parents=True, exist_ok=True)
            stats_path.write_text(json.dumps({"detections_by_entity": dict(counts),
                                              "chunks": len(chunks)}, indent=2))
        store.mark_built(fp)
    return json.loads(stats_path.read_text()) if stats_path.exists() else {}
