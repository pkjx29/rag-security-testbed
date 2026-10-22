"""FastAPI service.

Authentication: a caller presents X-API-Key; the server maps it to a Principal
(user id and role). Roles are never read from headers, the body or the question.
Keys come from RAG_API_KEYS ("key:user:role,..."); if unset, the development keys
in .env.example are used and a warning is logged. Bind to 127.0.0.1 only.

Security decision: interactive queries always run with access control ON. A
caller may switch the other three defences for experiments, but switching off
authorisation would let any caller read restricted records. The unprotected
baseline exists only inside the evaluation runner, with synthetic principals.
"""
from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Callable

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..config import EXPERIMENTS, ROLE_ACCESS, Settings, get_settings
from ..llm.base import GenerationTimeout, ModelUnavailableError
from ..logging_config import get_logger
from ..pipeline.rag import RAGPipeline
from ..schemas import Principal, QueryRequest, QueryResponse

log = get_logger(__name__)
MAX_BODY_BYTES = 16_384
RUN_ID_RX = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
DEV_KEYS = "dev-public-key:alice:public,dev-clinician-key:bob:clinician,dev-admin-key:ops:admin"


def parse_keys(spec: str) -> dict[str, Principal]:
    keys = {}
    for item in filter(None, (s.strip() for s in spec.split(","))):
        key, user, role = item.split(":")
        if role not in ROLE_ACCESS:
            raise ValueError(f"unknown role {role!r} in RAG_API_KEYS")
        keys[key] = Principal(user_id=user, role=role)
    return keys


class EvaluationRequest(BaseModel):
    quick: bool = True
    experiments: list[str] = Field(default_factory=lambda: list(EXPERIMENTS))


def create_app(settings: Settings | None = None,
               pipeline_factory: Callable[[Settings], RAGPipeline] | None = None) -> FastAPI:
    settings = settings or get_settings()
    spec = os.environ.get("RAG_API_KEYS")
    if not spec:
        log.warning("RAG_API_KEYS not set: using development API keys (local use only)")
    api_keys = parse_keys(spec or DEV_KEYS)
    app = FastAPI(title="RAG Copilot: Privacy & Security Testbed", version="0.2.0")
    state: dict = {"pipeline": None, "eval_lock": threading.Lock(), "eval_status": "idle"}

    def factory(s: Settings) -> RAGPipeline:
        from ..pipeline.setup import is_ingested, load_pipeline
        if not is_ingested(s):
            raise HTTPException(503, "index not built: run `make ingest`")
        return load_pipeline(s)

    def get_pipeline() -> RAGPipeline:
        if state["pipeline"] is None:
            state["pipeline"] = (pipeline_factory or factory)(settings)
        return state["pipeline"]

    def principal(x_api_key: str | None = Header(default=None)) -> Principal:
        p = api_keys.get(x_api_key or "")
        if p is None:
            raise HTTPException(401, "missing or invalid API key")
        return p

    def admin(p: Principal = Depends(principal)) -> Principal:
        if p.role != "admin":
            raise HTTPException(403, "evaluation endpoints need the admin role")
        return p

    @app.middleware("http")
    async def limit_body(request: Request, call_next):
        if int(request.headers.get("content-length") or 0) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "request body too large"}, status_code=413)
        return await call_next(request)

    @app.get("/health")
    def health() -> dict:
        from ..pipeline.setup import is_ingested
        try:
            from huggingface_hub import snapshot_download
            snapshot_download(settings.model.model_id, local_files_only=True)
            model_cached = True
        except Exception:
            model_cached = False
        return {"status": "ok", "index_built": is_ingested(settings), "model_cached": model_cached,
                "backend": settings.model.backend}

    @app.get("/config")
    def safe_config() -> dict:
        return {"model_id": settings.model.model_id, "backend": settings.model.backend,
                "max_tokens": settings.model.max_tokens, "temperature": settings.model.temperature,
                "retrieval": settings.retrieval.model_dump(), "roles": sorted(ROLE_ACCESS),
                "experiments": {k: {"label": v[0], "defences": v[1].model_dump()} for k, v in EXPERIMENTS.items()},
                "interactive_access_control": "always on"}

    @app.post("/query", response_model=QueryResponse)
    def query(req: QueryRequest, p: Principal = Depends(principal)) -> QueryResponse:
        req = req.model_copy(update={"defences": req.defences.model_copy(update={"access_control": True})})
        try:
            return get_pipeline().answer(req, p).response
        except ModelUnavailableError as exc:
            raise HTTPException(503, str(exc)) from exc
        except GenerationTimeout as exc:
            raise HTTPException(504, "generation timed out") from exc

    @app.post("/evaluation/run", status_code=202)
    def start_evaluation(body: EvaluationRequest, _: Principal = Depends(admin)) -> dict:
        unknown = set(body.experiments) - set(EXPERIMENTS)
        if unknown:
            raise HTTPException(422, f"unknown experiments: {sorted(unknown)}")
        if not state["eval_lock"].acquire(blocking=False):
            raise HTTPException(409, "an evaluation is already running")

        def work() -> None:
            from ..evaluation import benchmark, report, runner
            try:
                state["eval_status"] = "running"
                cases, version = benchmark.load(settings.paths.benchmarks / "cases.jsonl")
                if body.quick:
                    cases = benchmark.quick_subset(cases)
                res = runner.run(get_pipeline(), cases, version, runner.load_truth(settings.paths),
                                 experiments=body.experiments, quick=body.quick, progress=log.info)
                report.write(res, settings.paths.results)
                state["eval_status"] = f"finished {res['meta']['run_id']}"
            except Exception as exc:
                state["eval_status"] = f"failed: {type(exc).__name__}"
                log.error("evaluation failed: %s", type(exc).__name__)
            finally:
                state["eval_lock"].release()

        threading.Thread(target=work, daemon=True).start()
        return {"status": "started"}

    @app.get("/evaluation/status")
    def evaluation_status(_: Principal = Depends(admin)) -> dict:
        return {"status": state["eval_status"]}

    @app.post("/admin/ingest", status_code=202)
    def start_ingest(rebuild: bool = False, _: Principal = Depends(admin)) -> dict:
        """Download/verify the NIST PDFs, regenerate the synthetic records and (re)build both indexes.
        Shares the evaluation lock: the index must not change under a running benchmark."""
        if not state["eval_lock"].acquire(blocking=False):
            raise HTTPException(409, "an evaluation or ingestion is already running")

        def work() -> None:
            from ..pipeline.setup import ingest
            try:
                state["eval_status"] = "ingesting"
                stats = ingest(settings, rebuild=rebuild)
                state["pipeline"] = None             # reload stores and ACL on next query
                state["eval_status"] = f"ingested {stats['nist_chunks']} NIST + {stats['synthetic_chunks']} synthetic chunks"
            except Exception as exc:
                state["eval_status"] = f"ingest failed: {type(exc).__name__}"
            finally:
                state["eval_lock"].release()

        threading.Thread(target=work, daemon=True).start()
        return {"status": "started"}

    @app.get("/evaluation/runs")
    def list_runs(_: Principal = Depends(principal)) -> list[dict]:
        runs_dir = settings.paths.results / "runs"
        out = []
        for d in sorted(runs_dir.glob("*/meta.json"), reverse=True) if runs_dir.exists() else []:
            m = json.loads(d.read_text())
            out.append({k: m.get(k) for k in ("run_id", "status", "quick", "started_at", "finished_at",
                                              "model_id", "n_cases", "experiments")})
        return out

    @app.get("/evaluation/runs/{run_id}")
    def get_run(run_id: str, _: Principal = Depends(principal)) -> dict:
        if not RUN_ID_RX.match(run_id):           # also blocks path traversal
            raise HTTPException(404, "run not found")
        d = settings.paths.results / "runs" / run_id
        if not (d / "meta.json").exists():
            raise HTTPException(404, "run not found")
        summary = json.loads((d / "summary.json").read_text()) if (d / "summary.json").exists() else None
        return {"meta": json.loads((d / "meta.json").read_text()), "summary": summary}

    return app


app = create_app()
