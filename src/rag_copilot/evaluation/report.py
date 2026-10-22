"""Write a run to results/runs/<run_id>/ and render the comparison report.

Files: meta.json, summary.json, summary.csv, cases.jsonl (answers with every
seeded value masked), report.md. The full (non-quick) run is also copied to
results/latest/, which is the only results folder committed to git.
"""
from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

TABLE = [  # (summary key, column title)
    ("injection_asr", "Injection success"),
    ("indirect_extraction_success", "Indirect extraction"),
    ("pii_leak", "PII-leak queries"),
    ("unauthorized_context_exposure", "Unauthorised text in context"),
    ("utility_benign_qa", "NIST QA correct"),
    ("utility_authorized", "Authorised lookups"),
    ("uncertainty_when_unanswerable", "Says 'don't know' when unanswerable"),
]


def fmt(m: dict | None) -> str:
    if m is None:
        return "n/a"
    if m["rate"] is None:
        return "undefined (0/0)"
    lo, hi = m["ci95"]
    return f"{m['k']}/{m['n']} ({100 * m['rate']:.0f}%, {100 * lo:.0f}–{100 * hi:.0f})"


def pct(m: dict | None) -> str:
    return "n/a" if m is None or m["rate"] is None else f"{100 * m['rate']:.0f}%"


def render(res: dict) -> str:
    meta, S, st = res["meta"], res["summary"], res["static"]
    L = ["# Benchmark report", "",
         f"Run `{meta['run_id']}` ({meta['status']}), commit `{meta['git_commit']}`, "
         f"model `{meta['model_id']}` (temperature {meta['model']['temperature']}, "
         f"max {meta['model']['max_tokens']} tokens), top-k {meta['retrieval']['top_k']}, "
         f"dataset `{meta['dataset_version'][:12]}`, {meta['n_cases']} cases per configuration"
         f"{' (QUICK SUBSET)' if meta['quick'] else ''}.", "",
         "Cells show k/n (rate, 95% Wilson interval). Lower is better for the first four columns.", "",
         "## Baseline vs individual defences vs all four", "",
         "| Config | " + " | ".join(t for _, t in TABLE) + " |",
         "|---" * (len(TABLE) + 1) + "|"]
    for key, m in S.items():
        L.append(f"| **{key}** {m['label']} | " + " | ".join(fmt(m[k]) for k, _ in TABLE) + " |")

    L += ["", "## Defence behaviour", "",
          "| Config | Poison retrieved | Poison kept out of context | Injection detection | Look-alike false positives | Output filter changed benign answers | Role-override leaks | Distinct values leaked | Citation validity | Source support | Errors |",
          "|---" * 12 + "|"]
    for key, m in S.items():
        L.append(f"| {key} | {pct(m['poison_retrieved'])} | {pct(m['injection_kept_out_of_context'])} | "
                 f"{fmt(m['injection_detection'])} | {fmt(m['lookalike_false_positive'])} | "
                 f"{fmt(m['output_filter_changed_benign'])} | {pct(m['role_override_leak'])} | "
                 f"{m['distinct_values_leaked']} | {pct(m['citation_validity'])} | {pct(m['source_support'])} | "
                 f"{m['errors']} |")

    first = next(iter(S.values()))
    goals, carriers = list(first["injection_asr_by_goal"]), list(first["injection_asr_by_carrier"])
    L += ["", "## Injection success by attacker goal", "", "| Config | " + " | ".join(goals) + " |",
          "|---" * (len(goals) + 1) + "|"]
    L += [f"| {k} | " + " | ".join(pct(m["injection_asr_by_goal"][g]) for g in goals) + " |" for k, m in S.items()]
    L += ["", "## Injection success by carrier style", "", "| Config | " + " | ".join(carriers) + " |",
          "|---" * (len(carriers) + 1) + "|"]
    L += [f"| {k} | " + " | ".join(pct(m["injection_asr_by_carrier"][c]) for c in carriers) + " |"
          for k, m in S.items()]

    L += ["", "## Latency (seconds)", "", "| Config | End-to-end mean | p50 | p95 | Uncached generation mean (n) |",
          "|---|---|---|---|---|"]
    for k, m in S.items():
        e, g = m["latency_end_to_end_s"], m["latency_generation_uncached_s"]
        L.append(f"| {k} | {e['mean']} | {e['p50']} | {e['p95']} | {g['mean']} ({g['n']}) |")

    red, inj = st["protected_index_redaction"], st["injection_filter_on_clean_corpus"]
    L += ["", "## Checks without the model", "",
          f"- Protected index: {red['removed']}/{red['seeded_values']} seeded values absent after Presidio "
          f"redaction; survivors by field: {red['survived_by_field'] or 'none'}.",
          f"- Injection filter on the clean indexed corpus: {inj['flagged']}/{inj['n']} chunks flagged "
          f"(false positives); rules fired: {inj['rules'] or 'none'}.", ""]
    return "\n".join(L)


def write(res: dict, results_dir: Path) -> Path:
    run_dir = results_dir / "runs" / res["meta"]["run_id"]
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "meta.json").write_text(json.dumps(res["meta"], indent=2))
    (run_dir / "summary.json").write_text(json.dumps({"summary": res["summary"], "static": res["static"]}, indent=2))
    with open(run_dir / "cases.jsonl", "w") as f:
        for r in res["rows"]:
            f.write(json.dumps(r) + "\n")
    with open(run_dir / "summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["experiment", "label", "metric", "k", "n", "rate"])
        for key, m in res["summary"].items():
            for name, v in m.items():
                if isinstance(v, dict) and "k" in v:
                    w.writerow([key, m["label"], name, v["k"], v["n"], v["rate"]])
    (run_dir / "report.md").write_text(render(res))
    if not res["meta"]["quick"] and res["meta"]["status"] == "complete":
        latest = results_dir / "latest"
        latest.mkdir(parents=True, exist_ok=True)
        for name in ("meta.json", "summary.json", "summary.csv", "report.md"):
            shutil.copy(run_dir / name, latest / name)
    return run_dir
