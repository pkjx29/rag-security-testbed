"""Download the public NIST corpus, extract text, and split it into chunks."""
import hashlib
import re
import urllib.request

from langchain_text_splitters import RecursiveCharacterTextSplitter
from pypdf import PdfReader

from . import config


def download_corpus() -> None:
    config.RAW_DIR.mkdir(parents=True, exist_ok=True)
    for doc in config.CORPUS:
        path = config.RAW_DIR / f"{doc['id']}.pdf"
        if not path.exists():
            print(f"  downloading {doc['url']}")
            urllib.request.urlretrieve(doc["url"], path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != doc["sha256"]:
            # NIST occasionally re-issues PDFs. Warn rather than fail, but the
            # numbers in results/ were produced from the pinned hash.
            print(f"  WARNING: {path.name} sha256 {digest[:12]} != pinned {doc['sha256'][:12]}")


def _clean(text: str) -> str:
    text = re.sub(r"This publication is available free of charge from:?\s*\S+", " ", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def load_chunks() -> list[dict]:
    """Return chunks as dicts: {id, text, metadata}. All NIST chunks are public."""
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=config.CHUNK_SIZE, chunk_overlap=config.CHUNK_OVERLAP
    )
    chunks = []
    for doc in config.CORPUS:
        reader = PdfReader(config.RAW_DIR / f"{doc['id']}.pdf")
        for page_no, page in enumerate(reader.pages, start=1):
            text = _clean(page.extract_text() or "")
            if len(text) < 200:          # skip blank / title-only pages
                continue
            for i, piece in enumerate(splitter.split_text(text)):
                chunks.append({
                    "id": f"{doc['id']}-p{page_no}-{i}",
                    "text": piece,
                    "metadata": {"source": doc["id"], "page": page_no,
                                 "access_level": "public", "kind": "nist"},
                })
    return chunks
