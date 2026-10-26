"""Web app guards, from the Codex review (reviews/004-review-web-codex.md). No API calls: the pipeline is stubbed."""

import json
import time

import pytest
from fastapi.testclient import TestClient

from proveit.web import app as web
from proveit.web import budget as budget_mod


@pytest.fixture()
def fresh_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(budget_mod, "STATE", tmp_path / "budget.json")
    monkeypatch.setattr(budget_mod, "RESERVE", 0.10)
    b = budget_mod.Budget()
    b.daily_dollars, b.per_ip, b.max_concurrent = 0.25, 5, 2
    monkeypatch.setattr(web, "budget", b)
    return b


def events(resp) -> list[tuple[str, dict]]:
    out = []
    for chunk in resp.text.split("\n\n"):
        lines = dict(line.split(": ", 1) for line in chunk.splitlines() if ": " in line and not line.startswith(":"))
        if "event" in lines:
            out.append((lines["event"], json.loads(lines["data"])))
    return out


def test_reservations_cap_concurrent_admissions(fresh_budget):
    # $0.25 budget, $0.10 reserved per run: only two runs fit, whatever their IPs.
    assert fresh_budget.admit("a") is None
    assert fresh_budget.admit("b") is None
    assert fresh_budget.admit("c") is not None
    fresh_budget.settle(0.02)
    fresh_budget.settle(0.02)
    assert fresh_budget.status()["spent_today"] == pytest.approx(0.04)


def test_failed_run_is_charged_its_full_reservation(fresh_budget):
    assert fresh_budget.admit("a") is None
    fresh_budget.settle(None)
    assert fresh_budget.status()["spent_today"] == pytest.approx(0.10)


def test_spoofed_forwarded_for_does_not_change_identity():
    class Req:
        headers = {"x-forwarded-for": "visitor-1, 203.0.113.7"}
        client = None

    assert web._client_ip(Req()) == "203.0.113.7"


def test_oversized_request_is_refused_before_parsing(fresh_budget):
    client = TestClient(web.app)
    resp = client.post("/api/live", content=json.dumps({"body": "x" * 200_000}), headers={"Content-Type": "application/json"})
    assert events(resp)[0][0] == "failed"


def test_exhausted_budget_stops_hackerone_fetch(fresh_budget, monkeypatch):
    fresh_budget.daily_dollars = 0.0

    async def must_not_fetch(h1_id):
        raise AssertionError("fetched HackerOne despite an exhausted budget")

    monkeypatch.setattr(web, "_fetch_h1", must_not_fetch)
    client = TestClient(web.app)
    resp = client.post("/api/live", json={"url": "https://hackerone.com/reports/12345"})
    assert events(resp) == [("failed", {"message": "Today's live-run budget is used up. Every curl report in judge mode still works."})]


def test_completed_run_is_settled_at_its_actual_cost(fresh_budget, monkeypatch):
    import proveit.judge.pipeline as pipeline

    def fake_triage(report, repo, progress=None):
        progress("grounding", {"verdict": "grounded", "rev": "x", "rev_source": "x", "counts": {}, "ungrounded": []})
        return {"final": "needs_human", "cost": 0.03, "grounding": {}, "claims": {}, "judgment": {}, "evidence": []}

    monkeypatch.setattr(pipeline, "triage", fake_triage)
    client = TestClient(web.app)
    resp = client.post("/api/live", json={"title": "t", "body": "curl_easy_escape mishandles negative lengths"})
    names = [e for e, _ in events(resp)]
    assert names[0] == "started" and names[-1] == "result"
    for _ in range(50):  # settlement runs in the worker's done-callback
        if fresh_budget.status()["spent_today"] == pytest.approx(0.03):
            break
        time.sleep(0.02)
    assert fresh_budget.status()["spent_today"] == pytest.approx(0.03)


def test_cached_report_url_redirects_without_admission(fresh_budget):
    fresh_budget.daily_dollars = 0.0
    client = TestClient(web.app)
    resp = client.post("/api/live", json={"url": "https://hackerone.com/reports/2887487"})
    assert events(resp) == [("cached", {"href": "/r/2887487"})]
