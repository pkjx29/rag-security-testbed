"""Command line: python -m rag_copilot.cli <command>

  verify-env        report platform, memory, disk, packages and cached models
  download-model    explicit model download (about 0.9 GB)
  ingest            download NIST PDFs, generate synthetic records, build both indexes
  benchmark         regenerate data/benchmarks/cases.jsonl
  evaluate          run every case against configurations A-F
  query             ask one question
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys

from . import config
from .config import EXPERIMENTS, get_settings
from .logging_config import configure


def verify_env() -> int:
    import os
    s = get_settings()
    mem = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30
    free = shutil.disk_usage(s.paths.storage.parent).free / 2**30
    print(f"platform      {platform.system()} {platform.machine()} (Apple silicon: "
          f"{platform.system() == 'Darwin' and platform.machine() == 'arm64'})")
    print(f"python        {sys.version.split()[0]}")
    print(f"memory        {mem:.1f} GB    free disk {free:.1f} GB")
    from importlib import metadata
    for pkg in ["mlx", "mlx-lm", "chromadb", "presidio-analyzer", "langchain-core", "fastapi", "streamlit"]:
        try:
            print(f"{pkg:<18}{metadata.version(pkg)}")
        except metadata.PackageNotFoundError:
            print(f"{pkg:<18}MISSING")
    try:
        from huggingface_hub import snapshot_download
        snapshot_download(s.model.model_id, local_files_only=True)
        print(f"model         {s.model.model_id}: cached")
    except Exception:
        print(f"model         {s.model.model_id}: NOT cached (run: make download-model)")
    from .pipeline.setup import is_ingested
    print(f"index         {'built' if is_ingested(s) else 'NOT built (run: make ingest)'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    configure()
    ap = argparse.ArgumentParser(prog="rag_copilot", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verify-env")
    sub.add_parser("download-model")
    p_ing = sub.add_parser("ingest")
    p_ing.add_argument("--rebuild", action="store_true")
    sub.add_parser("benchmark")
    p_ev = sub.add_parser("evaluate")
    p_ev.add_argument("--quick", action="store_true", help="every 4th case of each category")
    p_ev.add_argument("--experiments", default=",".join(EXPERIMENTS), help="e.g. A,F")
    p_q = sub.add_parser("query")
    p_q.add_argument("question")
    p_q.add_argument("--role", default="public", choices=sorted(config.ROLE_ACCESS))
    p_q.add_argument("--protected", action="store_true", help="enable all four defences")
    args = ap.parse_args(argv)
    s = get_settings()

    if args.cmd == "verify-env":
        return verify_env()
    if args.cmd == "download-model":
        from .llm.mlx_backend import download_model
        print(download_model(s.model.model_id))
        return 0
    if args.cmd == "ingest":
        from .pipeline.setup import ingest
        print(json.dumps(ingest(s, rebuild=args.rebuild), indent=2))
        return 0
    if args.cmd == "benchmark":
        from .evaluation import benchmark
        from .ingestion import synthetic
        syn = synthetic.generate()
        cases = benchmark.build_cases(syn["truth"], syn["records"])
        benchmark.write(s.paths.benchmarks / "cases.jsonl", cases)
        print(f"wrote {len(cases)} cases")
        return 0

    from .pipeline.setup import is_ingested, load_pipeline
    if not is_ingested(s):
        print("index not built: run `make ingest` first", file=sys.stderr)
        return 2
    pipe = load_pipeline(s)
    if args.cmd == "query":
        from .schemas import Principal, QueryRequest
        d = config.PROTECTED if args.protected else config.BASELINE
        trace = pipe.answer(QueryRequest(question=args.question, defences=d),
                            Principal(user_id="cli", role=args.role))
        print(trace.response.model_dump_json(indent=2))
        return 0
    if args.cmd == "evaluate":
        from .evaluation import benchmark, report, runner
        cases, version = benchmark.load(s.paths.benchmarks / "cases.jsonl")
        if args.quick:
            cases = benchmark.quick_subset(cases)
        res = runner.run(pipe, cases, version, runner.load_truth(s.paths),
                         experiments=args.experiments.split(","), quick=args.quick)
        run_dir = report.write(res, s.paths.results)
        print(f"report: {run_dir / 'report.md'}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
