# Implementation plan and status

Last updated: 22 Oct 2026.

## Environment audit (21 Oct 2026)

| Item | Finding | Decision |
|---|---|---|
| Hardware | Apple M1, 8 GB RAM, macOS 26 (arm64) | MLX backend for local inference |
| Python | Anaconda 3.13.9 (arm64); no `uv`, Homebrew or Ollama | stdlib `venv` + pinned `requirements.txt` + `requirements.lock` (pip freeze) |
| Disk | 7.5 GB free at start, falling to about 0.2–1 GB (shared with other projects) | ONNX embedder instead of sentence-transformers/PyTorch; `--no-cache-dir`; mypy cache disabled |
| Network | huggingface.co and nvlpubs.nist.gov reachable; fda.gov blocks scripted downloads | NIST corpus |
| Model cache | none at start | explicit `make download-model` (0.9 GB) |

## Phases

| Phase | Content | Status |
|---|---|---|
| 0 | Audit, plan | done |
| 1 | Package layout, `config.py`, `schemas.py`, safe logging | done |
| 2 | NIST ingestion with provenance and stable IDs; synthetic records; Presidio + MRN recognizer | done |
| 3 | Chroma persistence (plain + redacted), idempotent upsert, embedder check, baseline RAG | done |
| 4 | MLX backend (lazy load, timeout, cache), loopback-only HTTP backend, 10-step pipeline | done |
| 5 | D1–D4, each switchable; D2 with an independent ACL check; D3/D4 policies | done |
| 6 | 115-case JSONL benchmark (10 categories), runner, metrics with k/n and Wilson intervals, run metadata | done |
| 7 | FastAPI (8 endpoints, API-key principals, D2 forced on); Streamlit UI | done |
| 8 | 53 tests: unit, security, integration, evaluation; Hypothesis properties; ruff + mypy clean | done |
| 9 | Full benchmark on the real model; `results/latest/` | done |
| 10 | Docs, deployment (local verified; Docker drafted, not verified) | done, except Docker verification |

## Acceptance criteria

| Criterion | Status | Evidence |
|---|---|---|
| README lets a fresh user set up | done; not tested on a second machine | `README.md`, `make setup` |
| NIST ingestion with metadata | done | `data/processed/manifest.json`, `tests/unit` provenance test |
| Reproducible synthetic records | done | determinism test; committed `data/synthetic/` |
| Protected index stores redacted content | done | `static.protected_index_redaction` (287/290); integration test |
| Local model adapter works | done on M1 | benchmark run metadata |
| Baseline RAG answers with citations | done | NIST QA 9/10 in config A; citations in API response |
| Defences switch independently | done | configs B–E, unit test |
| Unauthorised content excluded before generation | done | security tests; config C/F exposure metric |
| Injection tests use the real path | done | runner plants into Chroma and calls MLX |
| Output filter vs synthetic values | done | unit + security tests; config E |
| Baseline, individual and combined compared | done | `results/latest/report.md` |
| Utility measured alongside security | done | NIST QA, authorised lookups, uncertainty, citations |
| Tests pass | 53/53 | `make check` |
| No raw sensitive values in logs or reports | done | masking filter + `answer_masked`; log test |
| Docs reflect the implementation | done | `docs/`, `KNOWLEDGE.md`, `CONTRIBUTING.md` |
| Local app starts | API + UI verified locally | `docs/deployment.md` |
| Deployment instructions verified | local verified; Docker not verified | `docs/deployment.md` |

## Deviations from the brief, and why

* **No separate assistant-instruction file.** At the owner's request, contributor and
  automation conventions, commands and security invariants are in `CONTRIBUTING.md`.
* **Sentence Transformers not used.** Same MiniLM weights via ONNX, because there was no
  disk for PyTorch. The owner approved this on 21 Oct.
* **scikit-learn and `uv` not used.** No metric needs scikit-learn, and `uv` is not
  installed. The lock file is a `pip freeze`.
* **Docker not verified** for lack of disk; it is marked as a draft.

## Next steps

1. LoRA-fine-tune a ~1B model (MLX) as an injection and personal-data detector, and compare
   it with the D3 rules on held-out carriers (the Spanish, letter-spaced and footnote
   carriers are where the rules fail).
2. A second, larger model, to test whether the low injection success rate is a property
   of the 1.5B model.
3. Multi-document and adaptive injection, and paraphrase-aware leak scoring.
4. Verify the Docker mode on a machine with disk to spare.
