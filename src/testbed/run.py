"""Entry point: python -m testbed.run [--quick] [--rebuild]"""
import argparse
import time

from . import config, corpus, evaluate, index, synthetic_pii
from .llm import CachedLLM


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true", help="small subset of every suite (smoke test)")
    ap.add_argument("--rebuild", action="store_true", help="re-embed the vector store from scratch")
    args = ap.parse_args()
    t0 = time.time()

    print("1/4 corpus: downloading and verifying NIST PDFs")
    corpus.download_corpus()
    print("2/4 synthetic personal data (fake, seeded)")
    syn = synthetic_pii.write_and_load()
    print("3/4 vector index (plain + Presidio-redacted)")
    docs = corpus.load_chunks() + syn["records"] + syn["memos"]
    index.build(docs, rebuild=args.rebuild)
    print(f"4/4 attacks x defences with {config.MODEL_ID}")
    llm = CachedLLM()
    res = evaluate.run(syn, llm, quick=args.quick)
    evaluate.write_results(res, quick=args.quick)
    name = "results_quick.md" if args.quick else "results.md"
    print(f"done in {time.time() - t0:.0f}s -> results/{name}")


if __name__ == "__main__":
    main()
