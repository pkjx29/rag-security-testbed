# Troubleshooting

These are problems actually met while building the project, and their fixes.

| Symptom | Cause | Fix |
|---|---|---|
| `ModelUnavailableError: model ... is not available locally` (API returns 503) | The model is loaded from the local cache only, by design | `make download-model` |
| `MLX needs macOS on Apple silicon` | Running on Linux or Intel | `RAG_BACKEND=openai_compatible` with a model server on this machine |
| fda.gov PDFs download as a few bytes of HTML | Akamai bot detection | The corpus uses nvlpubs.nist.gov instead; do not try to bypass bot detection |
| `WARNING ... sha256 ... differs from pinned` | NIST re-issued a PDF | Results were produced from the pinned hash. Update `config.CORPUS` deliberately and re-run |
| `Changing the distance function of a collection once it is created is not supported` | Passing `hnsw:space` to `collection.modify` in Chroma 1.x | `store.mark_built` only writes the fingerprint and embedder name |
| `Validation error: name: Expected a name containing 3-512 characters` | Chroma collection names need at least 3 characters | Use longer names (seen in a test) |
| `EmbeddingMismatch` on start-up | Collection built with a different embedder setting | `make ingest` after deleting `storage/chroma`, or `python -m rag_copilot.cli ingest --rebuild` |
| Hundreds of `Entity CARDINAL is not mapped` warnings | Presidio logs every unmapped spaCy label | `logging_config.configure()` raises the Presidio log level to ERROR |
| `transformers: PyTorch was not found` | Harmless: `mlx-lm` imports the tokenizer utilities only | Ignore |
| Evaluation killed (exit 137) partway through | The parent process (or the terminal session) ended | Run with `nohup`; finished generations are cached in `storage/llm_cache`, so a re-run resumes fast |
| A metric differs by one case between runs with the same code | Approximate HNSW search after planting and deleting documents, most likely | Treat ±1 case as noise; see `evaluation_methodology.md` |
| Disk full during install | 8 GB M1 with a nearly full SSD | `pip install --no-cache-dir`; mypy's 100 MB cache is disabled in `pyproject.toml` |
| `ruff` B008 on `Depends(...)` | FastAPI idiom | Allowed in `pyproject.toml` (`extend-immutable-calls`) |
