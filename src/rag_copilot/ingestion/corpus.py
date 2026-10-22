"""Download the public NIST corpus, verify it, extract text and split it into chunks.

Downloaded PDFs are untrusted input: they are only parsed as text, and nothing in
them can change configuration. Chunk IDs are stable (document, page, position
and a hash of the text), so re-ingesting the same bytes produces the same IDs,
and upserting them cannot create duplicates.
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from langchain_text_splitters import RecursiveCharacterTextSplitter
from pypdf import PdfReader

from ..config import CORPUS, Paths, RetrievalConfig, SourceDocument
from ..logging_config import get_logger
from ..schemas import Chunk

log = get_logger(__name__)


class IntegrityWarning(UserWarning):
    pass


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def download(paths: Paths, docs: list[SourceDocument] = CORPUS) -> dict[str, str]:
    """Fetch any missing PDF. Returns {doc_id: actual sha256}. A hash mismatch
    (NIST re-issued a file) is logged, not fatal: results were produced from the pinned hash."""
    paths.raw.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for doc in docs:
        path = paths.raw / f"{doc.doc_id}.pdf"
        if not path.exists():
            log.info("downloading %s", doc.url)
            urllib.request.urlretrieve(doc.url, path)
        hashes[doc.doc_id] = sha256_file(path)
        if hashes[doc.doc_id] != doc.sha256:
            log.warning("%s: sha256 %s differs from pinned %s", doc.doc_id,
                        hashes[doc.doc_id][:12], doc.sha256[:12])
    return hashes


def normalise(text: str) -> str:
    text = re.sub(r"This publication is available free of charge from:?\s*\S+", " ", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def chunk_id(doc_id: str, page: int, index: int, text: str) -> str:
    return f"{doc_id}:p{page}:{index}:{hashlib.sha256(text.encode()).hexdigest()[:8]}"


def split_pages(doc: SourceDocument, pages: list[str], cfg: RetrievalConfig) -> list[Chunk]:
    splitter = RecursiveCharacterTextSplitter(chunk_size=cfg.chunk_size, chunk_overlap=cfg.chunk_overlap)
    chunks = []
    for page_no, raw in enumerate(pages, start=1):
        text = normalise(raw)
        if len(text) < 200:                    # blank or title-only pages
            continue
        for i, piece in enumerate(splitter.split_text(text)):
            chunks.append(Chunk(
                chunk_id=chunk_id(doc.doc_id, page_no, i, piece), text=piece,
                metadata={"doc_id": doc.doc_id, "title": doc.title, "url": doc.url,
                          "page": page_no, "sha256": doc.sha256, "published": doc.published,
                          "access_level": "public", "kind": "nist", "synthetic": False}))
    return chunks


def load_chunks(paths: Paths, cfg: RetrievalConfig, docs: list[SourceDocument] = CORPUS) -> list[Chunk]:
    chunks: list[Chunk] = []
    for doc in docs:
        reader = PdfReader(paths.raw / f"{doc.doc_id}.pdf")
        chunks += split_pages(doc, [p.extract_text() or "" for p in reader.pages], cfg)
    return chunks


def write_manifest(paths: Paths, hashes: dict[str, str], chunks: list[Chunk]) -> None:
    paths.processed.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for c in chunks:
        key = str(c.metadata["doc_id"])
        counts[key] = counts.get(key, 0) + 1
    manifest = {
        "ingested_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "documents": [{**d.model_dump(), "actual_sha256": hashes.get(d.doc_id),
                       "chunks": counts.get(d.doc_id, 0)} for d in CORPUS],
    }
    (paths.processed / "manifest.json").write_text(json.dumps(manifest, indent=2))
