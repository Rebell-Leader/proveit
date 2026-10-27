"""Pre-render judge mode to plain HTML files, for free static hosting that never sleeps.

Uses the same templates as the live app. Internal links become .html files; live mode links to the live server.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader, select_autoescape

from proveit.web.demo import DEMO_DIR
from proveit.web.view import VERDICTS
from proveit.web.presentation import present_report

HERE = Path(__file__).parent


def static_url(path: str) -> str:
    if path in ("/", ""):
        return "/"
    return f"{path.rstrip('/')}.html"


def build(out_dir: Path, live_url: str | None) -> dict:
    from proveit.web.app import home_context  # the same context the live app renders

    env = Environment(loader=FileSystemLoader(HERE / "templates"), autoescape=select_autoescape(["html"]))
    env.globals.update(VERDICTS=VERDICTS, u=static_url)

    def page(template: str, url_path: str, out: str, **ctx) -> None:
        request = SimpleNamespace(url=SimpleNamespace(path=url_path))
        target = out_dir / out
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(env.get_template(template).render(request=request, **ctx))

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    page("home.html", "/", "index.html", **home_context())
    summaries = json.loads((DEMO_DIR / "index.json").read_text())["summaries"]
    page("results.html", "/results", "results.html", summaries=summaries)
    page("live.html", "/live", "live.html", live_url=(live_url or "").rstrip("/") or None, budget={"spent_today": 0, "daily_budget": 0})
    reports = sorted((DEMO_DIR / "reports").glob("*.json"))
    for path in reports:
        view = present_report(json.loads(path.read_text()))
        page("report.html", f"/r/{view['id']}", f"r/{view['id']}.html", v=view)
    shutil.copytree(HERE / "static", out_dir / "static")
    return {"pages": 3 + len(reports), "bytes": sum(f.stat().st_size for f in out_dir.rglob("*") if f.is_file())}
