"""Integration tests: the FastAPI app (FakeLLM pipeline) and a real temporary ChromaDB store."""
import pytest
from fastapi.testclient import TestClient

from conftest import PUBLIC, RESTRICTED
from rag_copilot.api.app import create_app
from rag_copilot.config import Paths, RetrievalConfig, Settings
from rag_copilot.llm.base import ModelUnavailableError


@pytest.fixture
def client(make_pipeline, tmp_path):
    pipe, llm, store = make_pipeline([RESTRICTED, PUBLIC])
    settings = Settings(paths=Paths(data=tmp_path / "data", storage=tmp_path / "st", results=tmp_path / "res"))
    app = create_app(settings, pipeline_factory=lambda s: pipe)
    return TestClient(app), llm


def test_health_and_safe_config(client):
    c, _ = client
    assert c.get("/health").json()["status"] == "ok"
    cfg = c.get("/config").json()
    assert "dev-public-key" not in str(cfg) and cfg["interactive_access_control"] == "always on"


def test_query_requires_valid_key(client):
    c, _ = client
    assert c.post("/query", json={"question": "hi"}).status_code == 401
    assert c.post("/query", json={"question": "hi"}, headers={"X-API-Key": "nope"}).status_code == 401


def test_query_rejects_bad_input(client):
    c, _ = client
    h = {"X-API-Key": "dev-public-key"}
    assert c.post("/query", json={"question": ""}, headers=h).status_code == 422
    assert c.post("/query", json={"question": "x" * 20000}, headers=h).status_code == 413


def test_caller_cannot_switch_off_access_control(client):
    """Regression test: a public caller sending access_control=false must still be filtered."""
    c, llm = client
    r = c.post("/query", headers={"X-API-Key": "dev-public-key"},
               json={"question": "Ada's SSN?", "defences": {"access_control": False}})
    assert r.status_code == 200
    assert all(cit["chunk_id"] != RESTRICTED.chunk_id for cit in r.json()["citations"])
    assert "912-34-5678" not in llm.calls[-1][1]["content"]


def test_role_header_is_not_trusted(client):
    c, llm = client
    c.post("/query", headers={"X-API-Key": "dev-public-key", "X-Role": "clinician"}, json={"question": "Ada?"})
    assert "912-34-5678" not in llm.calls[-1][1]["content"]


def test_evaluation_endpoints_need_admin(client):
    c, _ = client
    assert c.post("/evaluation/run", headers={"X-API-Key": "dev-clinician-key"}, json={}).status_code == 403
    assert c.get("/evaluation/runs", headers={"X-API-Key": "dev-public-key"}).json() == []
    assert c.get("/evaluation/runs/..%2F..%2Fetc", headers={"X-API-Key": "dev-public-key"}).status_code == 404


def test_model_unavailable_maps_to_503(make_pipeline, tmp_path):
    def broken(m):
        raise ModelUnavailableError("run make download-model")
    pipe, _, _ = make_pipeline([PUBLIC], respond=broken)
    app = create_app(Settings(paths=Paths(data=tmp_path, storage=tmp_path, results=tmp_path)),
                     pipeline_factory=lambda s: pipe)
    r = TestClient(app).post("/query", headers={"X-API-Key": "dev-public-key"}, json={"question": "q"})
    assert r.status_code == 503 and "download-model" in r.json()["detail"]


def test_chroma_store_persists_upserts_idempotently_and_filters(tmp_path):
    from rag_copilot.retrieval.store import Store
    paths = Paths(data=tmp_path / "d", storage=tmp_path / "s", results=tmp_path / "r")
    cfg = RetrievalConfig(collection_plain="t_plain", collection_redacted="t_red")
    s = Store(paths, cfg, redacted=False)
    assert s.query("anything") == []                                   # empty collection
    s.upsert([PUBLIC, RESTRICTED])
    s.upsert([PUBLIC, RESTRICTED])                                     # no duplicates
    assert s.count() == 2
    again = Store(paths, cfg, redacted=False)                          # persisted
    assert again.count() == 2
    hits = again.query("encryption", where={"access_level": {"$in": ["public"]}})
    assert [h.chunk_id for h in hits] == [PUBLIC.chunk_id]


def test_protected_store_contains_redacted_text(tmp_path):
    from rag_copilot.retrieval.store import Store
    paths = Paths(data=tmp_path / "d", storage=tmp_path / "s", results=tmp_path / "r")
    s = Store(paths, RetrievalConfig(collection_plain="plain2", collection_redacted="redacted2"), redacted=True)
    s.upsert([RESTRICTED])
    text = s.get(RESTRICTED.chunk_id).text
    assert "912-34-5678" not in text and "MRN-1234567" not in text and "<US_SSN>" in text
