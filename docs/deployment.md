# Deployment

## Mode A: local research deployment (primary, verified)

Requirements: macOS on Apple silicon (MLX), Python 3.11+, about 8 GB RAM, and about 3 GB of
free disk (1.4 GB virtual environment, 0.9 GB model, 0.2 GB embedder, PDFs and indexes).
Everything runs on the machine, and nothing is sent to a hosted API.

```bash
make setup            # .venv + pinned requirements (requirements.lock has the full freeze)
make verify           # platform, memory, disk, packages, model and index status
make download-model   # explicit: ~0.9 GB from Hugging Face (mlx-community/Qwen2.5-1.5B-Instruct-4bit)
make ingest           # NIST PDFs (~7 MB, SHA-256 checked) + synthetic records -> both Chroma indexes (~3 min)
make check            # ruff + mypy + pytest (offline, no model)
make api              # FastAPI on http://127.0.0.1:8000 (localhost only)
make ui               # Streamlit on http://127.0.0.1:8501 (second terminal)
```

First run: Chroma downloads its ONNX MiniLM embedder (~80 MB) to `~/.cache/chroma` during
`make ingest`.

Health check: `curl http://127.0.0.1:8000/health` returns `index_built` and `model_cached`.
A sample query uses the development public key from `.env.example`:

```bash
curl -s -X POST http://127.0.0.1:8000/query -H 'X-API-Key: dev-public-key' \
     -H 'Content-Type: application/json' -d '{"question": "What is k-anonymity?"}'
```

Verified on 22 Oct 2026 on a MacBook Air M1 (8 GB) running macOS 26: setup, ingest,
`make check`, the full benchmark, the API (health, config and query via curl) and the UI
(loaded in a browser and answered a query).

Generated data stays local and is git-ignored: `data/raw`, `data/processed`, `storage/`
and `results/runs/`. Only `results/latest/` is published, and it holds aggregate numbers
only.

## Mode B: containers (draft, NOT verified)

MLX does not run in a Linux container. The image therefore uses the `openai_compatible`
backend, which talks to a model server **on the host**. That backend refuses any host
other than loopback or `host.docker.internal`, so it cannot be pointed at a hosted API.

```bash
# on the Mac host (outside Docker): serve the same model locally
.venv/bin/mlx_lm.server --model mlx-community/Qwen2.5-1.5B-Instruct-4bit --port 8080
cp .env.example .env
docker compose up --build    # api on 127.0.0.1:8000, ui on 127.0.0.1:8501
```

The image runs as a non-root user, has a health check and resource limits, and binds ports
to localhost.

**Not verified.** The development machine did not have enough free disk to build the
image (python:3.13-slim plus dependencies is more than 1 GB). Before relying on this mode,
check three things:

1. the image builds;
2. a container can reach a server bound to the host's loopback address through
   `host.docker.internal` (on Docker Desktop for Mac it may need `--host 0.0.0.0` on
   `mlx_lm.server`, which then needs a firewall rule);
3. greedy outputs from `mlx_lm.server` match the in-process backend.

## Do not

* expose the API beyond localhost. It uses static development keys, with no TLS and no
  rate limiting;
* index real patient data. The redaction and filters are measured to be imperfect;
* publish `results/runs/*/cases.jsonl`. Seeded values are masked, but answers are kept
  for debugging.

## Optional: GitHub publication

The `.gitignore` already excludes model weights, indexes, caches, `.env` and run artefacts.
Before pushing, check:

```bash
git ls-files | xargs du -ch | tail -1                 # repository size
git grep -nE "BEGIN (RSA|OPENSSH)|api[_-]?key\s*=\s*['\"][A-Za-z0-9]{20,}" || echo "no secrets"
```
