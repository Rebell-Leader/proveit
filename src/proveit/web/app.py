"""ProveIt web app. Run with: uv run uvicorn proveit.web.app:app --port 8000"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import re
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from proveit.grounding.repo import CURL_DIR, Repo
from proveit.web.budget import Budget
from proveit.web.demo import DEMO_DIR
from proveit.web.view import VERDICTS, to_view

HERE = Path(__file__).parent
MAX_BODY = 30_000
MAX_REQUEST_BYTES = 64_000
MAX_H1_BYTES = 1_000_000
FEATURED = [
    (2887487, "The code contradicts it", "An AI-written report claims a buffer overflow. Ultra finds the length check that runs before every copy."),
    (3392174, "Cites code that does not exist", "The report points at lib/ws.c line 1287. That file was never that long."),
    (3506159, "A fake quote, caught", "The report quotes nghttp2's docs. The judge believed it; the receipts check did not."),
    (4099618, "A real bug, confirmed", "Fourteen line citations across three files trace a connection-reuse flaw."),
    (3969300, "Fixed on master, live in the release", "Master already has the fix; ProveIt shows the release the reporter read."),
]
H1_URL = re.compile(r"^https?://(?:www\.)?hackerone\.com/reports/(\d{4,9})/?$")

@asynccontextmanager
async def lifespan(_app):
    if os.environ.get("PROVEIT_FETCH") == "1":
        threading.Thread(target=_keep_curl_fresh, daemon=True).start()
    yield


app = FastAPI(title="ProveIt", docs_url=None, redoc_url=None, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.globals["VERDICTS"] = VERDICTS
budget = Budget()
repo = Repo()


def _index() -> dict:
    return json.loads((DEMO_DIR / "index.json").read_text())


def _report(h1_id: int) -> dict | None:
    path = DEMO_DIR / "reports" / f"{h1_id}.json"
    return json.loads(path.read_text()) if path.exists() else None


def _client_ip(request: Request) -> str:
    """The address our nearest proxy saw. Its entry is the last one in X-Forwarded-For; earlier entries are
    whatever the client chose to send, so they are ignored."""
    forwarded = [part.strip() for part in request.headers.get("x-forwarded-for", "").split(",") if part.strip()]
    return (forwarded[-1] if forwarded else None) or (request.client.host if request.client else "unknown")


def _keep_curl_fresh() -> None:
    """In deployment, fetch curl every 6 hours so live reports are checked against today's master."""
    while True:
        subprocess.run(["git", "-C", str(CURL_DIR), "fetch", "-q", "--tags", "origin"], capture_output=True)
        repo.release_tags.cache_clear()
        time.sleep(6 * 3600)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/", response_class=HTMLResponse)
def home(request: Request, show: str = "all", verdict: str = "all"):
    idx = _index()
    reports = idx["reports"]
    if show in ("slop", "valid"):
        reports = [r for r in reports if r["truth_label"] == show]
    if verdict in VERDICTS:
        reports = [r for r in reports if r["final"] == verdict]
    test = idx["summaries"].get("test-v1", {})
    by_id = {r["id"]: r for r in idx["reports"]}
    featured = [{"id": i, "headline": h, "text": t, **by_id[i]} for i, h, t in FEATURED if i in by_id]
    return templates.TemplateResponse(request, "home.html", {
        "reports": reports, "show": show, "verdict": verdict, "total": len(idx["reports"]), "featured": featured,
        "test": test.get("overall", {}), "test_confusion": test.get("confusion", {}), "test_spend": test.get("spend", ""),
    })


@app.get("/r/{h1_id}", response_class=HTMLResponse)
def report_page(request: Request, h1_id: int):
    view = _report(h1_id)
    if not view:
        raise HTTPException(404, "This report is not in the judge-mode set. Try it in live mode.")
    return templates.TemplateResponse(request, "report.html", {"v": view})


@app.get("/live", response_class=HTMLResponse)
def live_page(request: Request):
    return templates.TemplateResponse(request, "live.html", {"budget": budget.status()})


@app.get("/results", response_class=HTMLResponse)
def results_page(request: Request):
    idx = _index()
    return templates.TemplateResponse(request, "results.html", {"summaries": idx["summaries"]})


def _sse(event: str, data: dict | str) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


async def _fetch_h1(h1_id: int) -> dict:
    async with httpx.AsyncClient(timeout=20, headers={"Accept": "application/json", "User-Agent": "ProveIt-live/0.1"}) as http:
        async with http.stream("GET", f"https://hackerone.com/reports/{h1_id}.json") as resp:
            raw = b""
            async for chunk in resp.aiter_bytes():
                raw += chunk
                if len(raw) > MAX_H1_BYTES:
                    raise ValueError("That HackerOne report is too large to check here.")
            status = resp.status_code
    try:
        data = json.loads(raw) if status == 200 else {}
    except json.JSONDecodeError:
        data = {}
    if not data.get("vulnerability_information"):
        raise ValueError("That HackerOne report is not public, or has no report text.")
    return {"title": str(data.get("title") or "")[:300], "body": str(data["vulnerability_information"])[:MAX_BODY],
            "submitted_at": str(data.get("submitted_at") or data.get("created_at") or "")}


async def _read_json_limited(request: Request) -> dict:
    """Parse the request body, refusing anything larger than MAX_REQUEST_BYTES before buffering it all."""
    if int(request.headers.get("content-length") or 0) > MAX_REQUEST_BYTES:
        raise ValueError("That report is too long. Paste at most about 30,000 characters.")
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > MAX_REQUEST_BYTES:
            raise ValueError("That report is too long. Paste at most about 30,000 characters.")
    try:
        data = json.loads(raw or b"{}")
    except json.JSONDecodeError:
        raise ValueError("The request was not valid JSON.")
    if not isinstance(data, dict) or not all(isinstance(data.get(k, ""), str) for k in ("url", "title", "body")):
        raise ValueError("The request had the wrong shape.")
    return data


@app.post("/api/live")
async def live_run(request: Request):
    try:
        payload = await _read_json_limited(request)
    except ValueError as e:
        message = str(e)

        async def refuse():
            yield _sse("failed", {"message": message})

        return StreamingResponse(refuse(), media_type="text/event-stream")
    ip = _client_ip(request)

    async def stream():
        admitted = False
        try:
            url = (payload.get("url") or "").strip()
            h1_id = None
            if url:
                m = H1_URL.match(url)
                if not m:
                    yield _sse("failed", {"message": "Use a public HackerOne report URL, like https://hackerone.com/reports/2887487"})
                    return
                h1_id = int(m.group(1))
                if _report(h1_id):
                    yield _sse("cached", {"href": f"/r/{h1_id}"})
                    return
            elif not (payload.get("body") or "").strip():
                yield _sse("failed", {"message": "Paste the report text, or give a HackerOne URL."})
                return
            # Admission (concurrency, daily dollars, per-visitor runs) before any outbound request or model call.
            refusal = budget.admit(ip)
            if refusal:
                yield _sse("failed", {"message": refusal})
                return
            admitted = True
            if h1_id:
                report = await _fetch_h1(h1_id)
            else:
                report = {"title": (payload.get("title") or "").strip()[:300] or "(untitled report)",
                          "body": payload["body"].strip()[:MAX_BODY], "submitted_at": dt.datetime.now(dt.UTC).isoformat()}

            from proveit.judge.pipeline import triage

            loop = asyncio.get_running_loop()
            queue: asyncio.Queue = asyncio.Queue()

            def progress(stage: str, data: dict) -> None:
                loop.call_soon_threadsafe(queue.put_nowait, (stage, data))

            yield _sse("started", {"title": report["title"], "submitted": report["submitted_at"][:10]})
            task = asyncio.create_task(asyncio.to_thread(triage, report, repo, progress=progress))
            # Settle when the worker finishes, even if the visitor disconnects first: the thread keeps paying for calls.
            task.add_done_callback(lambda t: budget.settle(None if t.cancelled() or t.exception() else t.result().get("cost", 0.0)))
            admitted = False  # the worker now owns the reservation
            while not task.done() or not queue.empty():
                try:
                    stage, data = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield _sse(stage, data)
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
            result = task.result()
            view = to_view(result, report, h1_id=h1_id)
            html = templates.get_template("_triage.html").render(v=view)
            yield _sse("result", {"html": html, "final": result["final"], "cost": result.get("cost", 0)})
        except ValueError as e:
            yield _sse("failed", {"message": str(e)})
        except Exception as e:  # never leak a stack trace to the page
            yield _sse("failed", {"message": f"The run failed ({type(e).__name__}). Judge mode still works."})
        finally:
            if admitted:  # refused or failed before the worker started: release the reservation at cost zero
                budget.settle(0.0)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
