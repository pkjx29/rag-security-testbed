"""Streamlit front end for the RAG Copilot testbed.

It is a thin client of the FastAPI service: every request carries the API key the
user enters, and the server decides the role. The UI cannot choose a role, cannot
switch off access control, and never sees unauthorised passages.

Run:  make api   (terminal 1)   then   make ui   (terminal 2)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pandas as pd
import streamlit as st

API = os.environ.get("RAG_API_URL", "http://127.0.0.1:8000")
LATEST = Path(__file__).resolve().parents[1] / "results" / "latest" / "summary.json"

st.set_page_config(page_title="RAG Copilot: Privacy & Security Testbed", layout="wide")
st.title("RAG Copilot: Privacy & Security Testbed")
st.warning("Research prototype. Not a HIPAA compliance tool and not certified for any real data. "
           "All personal records in this system are synthetic.")


def call(method: str, path: str, key: str, **kw) -> httpx.Response | None:
    try:
        return httpx.request(method, f"{API}{path}", headers={"X-API-Key": key}, timeout=180, **kw)
    except httpx.HTTPError:
        st.error(f"Cannot reach the API at {API}. Start it with `make api`.")
        return None


# ---- sidebar: identity, health, defences ------------------------------------
with st.sidebar:
    st.header("Session")
    key = st.text_input("API key", value="dev-public-key", type="password",
                        help="Development keys are in .env.example. The server maps the key to a role.")
    health = call("GET", "/health", key)
    if health is not None and health.status_code == 200:
        h = health.json()
        st.caption(f"Index built: {h['index_built']} · model cached: {h['model_cached']} · backend: {h['backend']}")
        if not h["model_cached"]:
            st.info("The model is not downloaded yet. Run `make download-model` (about 0.9 GB).")
        if not h["index_built"]:
            st.info("The index is not built yet. Use the Data tab (admin key) or run `make ingest`.")
    st.header("Defences")
    st.checkbox("D2 Document-level access control", value=True, disabled=True,
                help="Always on for interactive queries; the unprotected baseline exists only in the benchmark.")
    d1 = st.checkbox("D1 Presidio redaction at indexing", value=True)
    d3 = st.checkbox("D3 Injection filter", value=True)
    d3_policy = st.radio("D3 policy", ["exclude", "block"], horizontal=True, disabled=not d3)
    d4 = st.checkbox("D4 Output filter", value=True)
    d4_policy = st.radio("D4 policy", ["redact", "block"], horizontal=True, disabled=not d4)

chat, data, evaluation, results = st.tabs(["Ask", "Data", "Evaluation", "Results"])

# ---- chat --------------------------------------------------------------------
with chat:
    question = st.text_area("Question about NIST guidance", max_chars=1000,
                            placeholder="Is encryption of ePHI required under the HIPAA Security Rule?")
    if st.button("Ask", type="primary") and question.strip():
        body = {"question": question, "defences": {
            "redaction": d1, "injection_filter": d3, "injection_policy": d3_policy,
            "output_filter": d4, "output_policy": d4_policy}}
        with st.spinner("Retrieving and generating locally..."):
            r = call("POST", "/query", key, json=body)
        if r is not None and r.status_code == 200:
            res = r.json()
            (st.warning if res["refused"] else st.success)(res["answer"])
            rep = res["defences"]
            st.markdown(f"**Defences applied:** {', '.join(rep['enabled']) or 'none'} · "
                        f"unauthorised chunks removed: {rep['unauthorized_excluded']} · "
                        f"injection flags: {len(rep['injection_flagged'])} ({rep['injection_action'] or 'none'}) · "
                        f"output actions: {', '.join(rep['output_actions']) or 'none'} · "
                        f"{res['latency_s']} s")
            for f in rep["injection_flagged"]:
                st.caption(f"Flagged `{f['chunk_id']}`: {'; '.join(f['reasons'])}")
            st.subheader("Sources you are authorised to see")
            for c in res["citations"]:
                with st.expander(f"[{c['ref']}] {c['title']}" + (f", p. {c['page']}" if c["page"] else "")):
                    st.write(c["excerpt"] + " ...")
                    if c["url"]:
                        st.caption(c["url"])
        elif r is not None:
            st.error(f"{r.status_code}: {r.json().get('detail')}")

# ---- data --------------------------------------------------------------------
with data:
    st.write("Downloads and verifies the NIST PDFs, regenerates the synthetic records from a fixed seed, "
             "and builds the plain and Presidio-redacted indexes. Needs an admin key.")
    rebuild = st.checkbox("Rebuild from scratch")
    if st.button("Generate synthetic records and index"):
        r = call("POST", f"/admin/ingest?rebuild={str(rebuild).lower()}", key)
        if r is not None:
            st.write(r.json())

# ---- evaluation -------------------------------------------------------------------
with evaluation:
    st.write("Runs the benchmark through the real retrieval-to-generation path. Needs an admin key. "
             "The full run takes about 30 minutes on an 8 GB M1; the quick subset takes a few minutes.")
    quick = st.checkbox("Quick subset", value=True)
    exps = st.multiselect("Configurations", list("ABCDEF"), default=list("ABCDEF"))
    c1, c2 = st.columns(2)
    if c1.button("Start evaluation"):
        r = call("POST", "/evaluation/run", key, json={"quick": quick, "experiments": exps})
        if r is not None:
            st.write(r.json())
    if c2.button("Refresh status"):
        r = call("GET", "/evaluation/status", key)
        if r is not None:
            st.write(r.json())

# ---- results ----------------------------------------------------------------------
METRICS = {"injection_asr": "Injection success", "pii_leak": "PII-leak queries",
           "unauthorized_context_exposure": "Unauthorised text in context",
           "utility_benign_qa": "NIST QA correct", "utility_authorized": "Authorised lookups"}

with results:
    runs = call("GET", "/evaluation/runs", key)
    run_list = runs.json() if runs is not None and runs.status_code == 200 else []
    if run_list:
        st.subheader("Experiment runs")
        st.dataframe(pd.DataFrame(run_list), hide_index=True)
    options = (["latest (published)"] if LATEST.exists() else []) + [r["run_id"] for r in run_list]
    choice = st.selectbox("Show results for", options) if options else None
    summary = None
    if choice == "latest (published)":
        summary = json.loads(LATEST.read_text())["summary"]
    elif choice:
        r = call("GET", f"/evaluation/runs/{choice}", key)
        summary = r.json()["summary"]["summary"] if r is not None and r.status_code == 200 else None
    if summary:
        rows = []
        for exp, m in summary.items():
            for k, title in METRICS.items():
                if m[k]["rate"] is not None:
                    rows.append({"config": f"{exp} {m['label']}", "metric": title, "rate": m[k]["rate"],
                                 "k/n": f"{m[k]['k']}/{m[k]['n']}"})
        df = pd.DataFrame(rows)
        st.subheader("Baseline vs protected")
        st.dataframe(df.pivot(index="config", columns="metric", values="k/n"))
        for title in METRICS.values():
            part = df[df.metric == title].set_index("config")["rate"]
            if not part.empty:
                st.caption(title)
                st.bar_chart(part, horizontal=True)
        lat = pd.DataFrame({e: {"mean (s)": m["latency_end_to_end_s"]["mean"],
                                "p95 (s)": m["latency_end_to_end_s"]["p95"]} for e, m in summary.items()}).T
        st.caption("End-to-end latency (cached generations make re-runs faster; see report)")
        st.bar_chart(lat)
