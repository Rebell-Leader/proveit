"""Export judge-mode data: the evaluated curl reports as view models, ready to serve without any API calls.

Reads the final evaluation runs (runs/triage/<name>/results.jsonl) and writes data/demo/. The demo data holds
report excerpts with links to the public HackerOne pages, never full report text.
"""

from __future__ import annotations

import json

from proveit import DATA_DIR, ROOT, dataset
from proveit.grounding.repo import Repo
from proveit.web.view import to_view

DEMO_DIR = DATA_DIR / "demo"
RUNS = ("dev-v4", "test-v1")
# Reports whose proof of concept is run offline in a Nebius sandbox and whose result is baked into the static demo.
# 4024222 is CVE-2026-92391: its PoC, built against curl 8.22.0, overflows the stack inside curl_mime_free and
# AddressSanitizer catches it. Needs sandbox access at export time (results cache on disk), so export skips it when
# NEBIUS_PROJECT_ID is absent.
REPRO_FEATURED = (4024222,)


def _reproductions(ids, rows) -> dict:
    from proveit.repro.sandbox import configured
    if not configured():
        return {}
    from proveit.repro.stage import reproduce
    out = {}
    for h1_id in ids:
        row = rows.get(h1_id)
        if row:
            out[h1_id] = reproduce(row["input"])
    return out


def export(runs: tuple[str, ...] = RUNS, reproduce_ids: tuple[int, ...] = REPRO_FEATURED) -> dict:
    rows = {r["h1_id"]: r for r in dataset.load()}
    repo = Repo()
    repro = _reproductions(reproduce_ids, rows)
    (DEMO_DIR / "reports").mkdir(parents=True, exist_ok=True)
    index, summaries = [], {}
    for run in runs:
        run_dir = ROOT / "runs" / "triage" / run
        summaries[run] = json.loads((run_dir / "summary.json").read_text())
        for line in (run_dir / "results.jsonl").read_text().split("\n"):
            if not line.strip():
                continue
            res = json.loads(line)
            if res["h1_id"] in repro:
                res["reproduction"] = repro[res["h1_id"]]
            row = rows[res["h1_id"]]
            truth = {"label": row["label"], "cve": row.get("cve", ""), "cve_summary": row.get("cve_summary", "")}
            view = to_view(res, row["input"], h1_id=res["h1_id"], truth=truth, repo=repo)
            view["split"] = res.get("split")
            (DEMO_DIR / "reports" / f"{res['h1_id']}.json").write_text(json.dumps(view, ensure_ascii=False))
            index.append({k: view.get(k) for k in ("id", "title", "submitted", "final", "final_label", "tone", "truth_label", "split")}
                         | {"cve": truth["cve"], "cost": view["cost"]})
    index.sort(key=lambda r: r["submitted"], reverse=True)
    (DEMO_DIR / "index.json").write_text(json.dumps({"reports": index, "summaries": summaries}, ensure_ascii=False))
    return {"reports": len(index), "bytes": sum(p.stat().st_size for p in (DEMO_DIR / "reports").iterdir())}
