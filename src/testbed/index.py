"""ChromaDB vector store with two collections built from the same documents:

  corpus_plain     - documents indexed as-is (the vulnerable baseline)
  corpus_redacted  - every document passed through Presidio first (defence D1)

Documents = NIST chunks (public) + fake patient incident reports (restricted)
+ fake HR memos (personal data wrongly labelled public). Embeddings come from
Chroma's default all-MiniLM-L6-v2 ONNX model, which runs on CPU without PyTorch.
"""
import hashlib
import json

import chromadb
from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

from . import config
from .defenses.redaction import redact

POISON_SOURCE = "poison"


def _client():
    return chromadb.PersistentClient(path=str(config.INDEX_DIR))


def _collection(name: str):
    return _client().get_or_create_collection(
        name=name, embedding_function=DefaultEmbeddingFunction(),
        metadata={"hnsw:space": "cosine"},
    )


class Store:
    def __init__(self, redacted: bool):
        self.redacted = redacted
        self.col = _collection("corpus_redacted" if redacted else "corpus_plain")

    def ingest_text(self, text: str) -> str:
        """The ingestion pipeline: applied to every document, including ones an attacker plants."""
        return redact(text) if self.redacted else text

    def add(self, docs: list[dict], batch: int = 256) -> None:
        for i in range(0, len(docs), batch):
            part = docs[i:i + batch]
            self.col.add(ids=[d["id"] for d in part],
                         documents=[self.ingest_text(d["text"]) for d in part],
                         metadatas=[d["metadata"] for d in part])

    def query(self, question: str, k: int, where: dict | None = None) -> list[dict]:
        res = self.col.query(query_texts=[question], n_results=k, where=where)
        return [{"id": i, "text": t, "metadata": m}
                for i, t, m in zip(res["ids"][0], res["documents"][0], res["metadatas"][0])]

    # --- attack harness helpers: each injection case plants exactly one document ---
    def plant(self, doc: dict) -> None:
        self.add([doc])

    def remove_poison(self) -> None:
        self.col.delete(where={"source": POISON_SOURCE})


def build(docs: list[dict], rebuild: bool = False) -> None:
    """(Re)build both collections unless an index built from exactly these documents exists."""
    fingerprint = hashlib.sha256(
        json.dumps([[d["id"], d["text"], d["metadata"]] for d in docs], sort_keys=True).encode()
    ).hexdigest()
    client = _client()
    for name, redacted in (("corpus_plain", False), ("corpus_redacted", True)):
        existing = {c.name for c in client.list_collections()}
        if name in existing and not rebuild:
            store = Store(redacted)
            store.remove_poison()          # clean up after an interrupted run
            if (store.col.metadata or {}).get("fingerprint") == fingerprint:
                print(f"  {name}: {store.col.count()} docs (cached)")
                continue
        if name in existing:
            client.delete_collection(name)
        print(f"  {name}: embedding {len(docs)} docs" + (" after Presidio redaction" if redacted else ""))
        store = Store(redacted)
        store.add(docs)
        # Written last, so an interrupted build is never mistaken for a complete one.
        store.col.modify(metadata={"fingerprint": fingerprint})
