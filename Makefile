# All targets run inside the project's virtual environment.
PY := .venv/bin/python
export PYTHONPATH := src

.PHONY: setup verify download-model ingest benchmark test lint typecheck check evaluate evaluate-quick api ui all

setup:            ## create .venv and install pinned dependencies
	test -x $(PY) || python3 -m venv .venv
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -r requirements.txt

verify:           ## platform, memory, disk, packages, model and index status
	$(PY) -m rag_copilot.cli verify-env

download-model:   ## explicit download of the 4-bit Qwen2.5-1.5B-Instruct MLX weights (~0.9 GB)
	$(PY) -m rag_copilot.cli download-model

ingest:           ## NIST PDFs + synthetic records -> plain and redacted Chroma indexes
	$(PY) -m rag_copilot.cli ingest

benchmark:        ## regenerate data/benchmarks/cases.jsonl from the case definitions
	$(PY) -m rag_copilot.cli benchmark

test:             ## fast offline tests (no model needed)
	$(PY) -m pytest

lint:
	.venv/bin/ruff check src tests ui

typecheck:
	.venv/bin/mypy

check: lint typecheck test

evaluate-quick:   ## every 4th case of each category, all six configurations
	$(PY) -m rag_copilot.cli evaluate --quick

evaluate:         ## full benchmark (~30 min on an 8 GB M1 the first time)
	$(PY) -m rag_copilot.cli evaluate

api:              ## FastAPI on localhost only
	.venv/bin/uvicorn rag_copilot.api.app:app --host 127.0.0.1 --port 8000

ui:               ## Streamlit UI on localhost only (needs `make api` running)
	.venv/bin/streamlit run ui/app.py --server.address 127.0.0.1 --server.port 8501

all: setup check download-model ingest evaluate
