# Portable image for the API and UI. MLX only runs on macOS/Apple silicon, so the
# container uses the openai_compatible backend and talks to a model server on the
# host (e.g. `mlx_lm.server`). See docs/deployment.md. Build and run are NOT yet
# verified on the development machine (not enough free disk); treat as a draft.
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src \
    RAG_BACKEND=openai_compatible \
    RAG_MODEL_SERVER_URL=http://host.docker.internal:8080/v1

RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
COPY ui ./ui
COPY data/benchmarks ./data/benchmarks
COPY data/synthetic ./data/synthetic
RUN mkdir -p storage results data/raw data/processed && chown -R app:app /app
USER app

EXPOSE 8000 8501
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')"
CMD ["uvicorn", "rag_copilot.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
