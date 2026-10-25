"""Labeled curl dataset: AI-slop reports vs. reports behind real curl CVEs.

Labels come from two public sources:
- slop: Daniel Stenberg's list of AI-slop security reports submitted to curl (GitHub gist).
- valid: curl's own CVE feed (curl.se/docs/vuln.json), entries whose `issue` is a HackerOne report.

Report text is fetched from HackerOne's public JSON for disclosed reports and cached under data/cache/.
Only `input` fields may reach a checker or a model; `meta` holds triage outcomes and must never be shown to them.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import httpx

from proveit import CACHE_DIR, DATA_DIR

SLOP_GIST_ID = "07f7581f6e3d78ef37dfbfc81fd1d1cd"
VULN_JSON_URL = "https://curl.se/docs/vuln.json"
H1_REPORT_URL = "https://hackerone.com/reports/{id}.json"

LABELS_PATH = DATA_DIR / "curl_reports.jsonl"
REPORTS_CACHE = CACHE_DIR / "reports.jsonl"
H1_CACHE = CACHE_DIR / "h1"

_H1_LINK = re.compile(r"hackerone\.com/reports/(\d+)")
_USER_AGENT = "ProveIt-dataset/0.1 (hackathon research; polite 1 req/s)"


def _get(url: str, http: httpx.Client) -> httpx.Response:
    for attempt in range(4):
        resp = http.get(url)
        if resp.status_code != 429 and resp.status_code < 500:
            return resp
        time.sleep(2**attempt)
    return resp


def fetch_slop_ids(http: httpx.Client) -> list[tuple[int, str]]:
    """(report id, title as listed in the gist), in gist order."""
    gist = _get(f"https://api.github.com/gists/{SLOP_GIST_ID}", http).raise_for_status().json()
    text = next(iter(gist["files"].values()))["content"]
    out: list[tuple[int, str]] = []
    for line in text.splitlines():
        m = _H1_LINK.search(line)
        if m:
            title = re.sub(r"^\s*\d+\.\s*", "", line.split("[#")[0]).strip()
            out.append((int(m.group(1)), title))
    return out


def fetch_cve_reports(http: httpx.Client) -> list[dict]:
    """curl CVEs whose advisory links a HackerOne report."""
    vulns = _get(VULN_JSON_URL, http).raise_for_status().json()
    out = []
    for v in vulns:
        ds = v.get("database_specific", {})
        m = _H1_LINK.search(ds.get("issue") or "")
        if not m:
            continue
        versions = [ver for a in v.get("affected", []) for ver in a.get("versions", [])]
        out.append(
            {
                "h1_id": int(m.group(1)),
                "cve": (v.get("aliases") or [v["id"]])[0],
                "cve_summary": v.get("summary"),
                "cve_severity": ds.get("severity"),
                "cwe": (ds.get("CWE") or {}).get("id"),
                "last_affected": ds.get("last_affected"),
                "affected_versions": versions,
                "published": v.get("published"),
            }
        )
    return out


def fetch_h1_report(h1_id: int, http: httpx.Client) -> dict | None:
    """Public JSON for a disclosed HackerOne report, cached on disk. None if not public."""
    H1_CACHE.mkdir(parents=True, exist_ok=True)
    path = H1_CACHE / f"{h1_id}.json"
    if path.exists():
        cached = json.loads(path.read_text())
        return cached or None
    resp = _get(H1_REPORT_URL.format(id=h1_id), http)
    time.sleep(1.0)
    data = resp.json() if resp.status_code == 200 else {}
    if not data.get("vulnerability_information"):
        data = {}
    path.write_text(json.dumps(data))
    return data or None


def build(limit: int | None = None) -> dict:
    """Fetch everything and write the label file and the report cache. Returns counts."""
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    with httpx.Client(headers=headers, timeout=30, follow_redirects=True) as http:
        slop = fetch_slop_ids(http)
        cves = fetch_cve_reports(http)

        rows: dict[int, dict] = {}
        for h1_id, listed_title in slop:
            rows[h1_id] = {"h1_id": h1_id, "label": "slop", "source": "bagder-slop-gist", "listed_title": listed_title}
        conflicts = []
        for c in cves:
            if c["h1_id"] in rows:
                conflicts.append(c["h1_id"])
                continue
            rows[c["h1_id"]] = {"h1_id": c["h1_id"], "label": "valid", "source": "curl-vuln-json", **c}

        items = list(rows.values())[:limit] if limit else list(rows.values())
        labels, reports = [], []
        for row in items:
            raw = fetch_h1_report(row["h1_id"], http)
            row["public"] = raw is not None
            if raw:
                row["meta"] = {
                    "substate": raw.get("substate"),
                    "severity_rating": raw.get("severity_rating"),
                    "weakness": (raw.get("weakness") or {}).get("name"),
                    "disclosed_at": raw.get("disclosed_at"),
                    "h1_cve_ids": raw.get("cve_ids") or [],
                }
                reports.append(
                    {
                        "h1_id": row["h1_id"],
                        "input": {
                            "title": raw.get("title") or "",
                            "body": raw.get("vulnerability_information") or "",
                            "submitted_at": raw.get("submitted_at") or raw.get("created_at"),
                            "attachments": [a.get("file_name") for a in raw.get("attachments") or []],
                        },
                    }
                )
            labels.append(row)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_CACHE.parent.mkdir(parents=True, exist_ok=True)
    _write_jsonl(LABELS_PATH, labels)
    _write_jsonl(REPORTS_CACHE, reports)
    public = [r for r in labels if r["public"]]
    return {
        "slop_listed": len(slop),
        "cve_with_h1": len(cves),
        "label_conflicts": conflicts,
        "rows": len(labels),
        "public_slop": sum(r["label"] == "slop" for r in public),
        "public_valid": sum(r["label"] == "valid" for r in public),
    }


def load() -> list[dict]:
    """Rows with public report text: {"h1_id", "label", "input", "meta", ...}."""
    texts = {r["h1_id"]: r["input"] for r in _read_jsonl(REPORTS_CACHE)}
    out = []
    for row in _read_jsonl(LABELS_PATH):
        if row["h1_id"] in texts:
            out.append({**row, "input": texts[row["h1_id"]]})
    return out


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    # Split on "\n" only: str.splitlines() also breaks on U+2028 and friends inside report text.
    return [json.loads(line) for line in path.read_text().split("\n") if line.strip()]
