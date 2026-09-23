"""API tests using the inline worker and a stubbed scanner (no network)."""
import os

os.environ.setdefault("CERTAINLY_USE_INLINE_WORKER", "true")
os.environ.setdefault("CERTAINLY_MAX_TARGETS_PER_REQUEST", "3")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from certainly import jobs  # noqa: E402
from certainly.config import get_settings  # noqa: E402
from certainly.models import HostResult  # noqa: E402


@pytest.fixture(autouse=True)
def _stub_scanner(monkeypatch):
    """Replace the real network scanner with a deterministic stub."""
    def fake_analyze_targets(raws, **kwargs):
        results = []
        for raw in raws:
            results.append(HostResult(
                target=raw, hostname=raw, port=443, reachable=True,
                score=95, grade="A+",
            ))
        return results

    monkeypatch.setattr(jobs, "analyze_targets", fake_analyze_targets)
    yield


@pytest.fixture
def client():
    get_settings.cache_clear()
    from certainly.main import app
    return TestClient(app)


def test_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_config_exposes_limit(client):
    res = client.get("/api/config")
    assert res.status_code == 200
    assert res.json()["max_targets_per_request"] == 3


def test_scan_end_to_end_inline(client):
    res = client.post("/api/scan", json={"targets": ["example.com", "test.com"]})
    assert res.status_code == 200
    body = res.json()
    job_id = body["job_id"]
    assert body["status"] in {"queued", "finished"}

    # Inline worker runs synchronously, so results are ready immediately.
    result = client.get(f"/api/jobs/{job_id}")
    assert result.status_code == 200
    job = result.json()
    assert job["status"] == "finished"
    assert len(job["results"]) == 2
    assert job["results"][0]["grade"] == "A+"


def test_scan_rejects_too_many_targets(client):
    res = client.post("/api/scan", json={"targets": ["a.com", "b.com", "c.com", "d.com"]})
    assert res.status_code == 422


def test_scan_rejects_empty(client):
    res = client.post("/api/scan", json={"targets": ["  "]})
    assert res.status_code == 422


def test_unknown_job_404(client):
    res = client.get("/api/jobs/does-not-exist")
    assert res.status_code == 404


def test_status_endpoint(client):
    res = client.post("/api/scan", json={"targets": ["example.com"]})
    job_id = res.json()["job_id"]
    status = client.get(f"/api/jobs/{job_id}/status")
    assert status.status_code == 200
    assert status.json()["status"] == "finished"
    assert status.json()["total"] == 1


# --- Public sharing --------------------------------------------------------
def test_config_exposes_sharing(client):
    cfg = client.get("/api/config").json()
    assert cfg["enable_sharing"] is True
    assert cfg["share_ttl_seconds"] > 0


def test_scan_not_shared_by_default(client):
    res = client.post("/api/scan", json={"targets": ["example.com"]})
    body = res.json()
    assert body["share_id"] is None
    assert body["share_url"] is None
    job = client.get(f"/api/jobs/{body['job_id']}").json()
    assert job["share_id"] is None


def test_scan_with_share_creates_public_share(client):
    res = client.post(
        "/api/scan", json={"targets": ["example.com", "test.com"], "share": True}
    )
    body = res.json()
    assert body["share_id"]
    assert body["share_url"].endswith(f"/s/{body['share_id']}")

    # The shared result is publicly retrievable and carries the full results.
    shared = client.get(f"/api/shares/{body['share_id']}")
    assert shared.status_code == 200
    payload = shared.json()
    assert payload["status"] == "finished"
    assert len(payload["results"]) == 2
    assert payload["share_expires_at"] is not None


def test_unknown_share_404(client):
    res = client.get("/api/shares/nonexistent-token")
    assert res.status_code == 404


def test_share_page_is_served(client):
    res = client.get("/s/whatever")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
