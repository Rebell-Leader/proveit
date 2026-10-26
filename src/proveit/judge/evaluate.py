"""Score the full triage (grounding + Nano claims + Ultra judgment) on the labeled curl dataset.

Same dev/test split as the grounding eval. Results are also broken down by submission year: Nemotron 3 Ultra was
released in June 2026, so reports submitted in 2026 are a check that the judge reads code rather than recalling
famous CVEs or famous slop.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from proveit import ROOT, dataset, tf
from proveit.grounding.evaluate import _bootstrap_ci, split_of
from proveit.grounding.repo import Repo
from proveit.judge.pipeline import triage

FLAG = {"not_grounded", "likely_invalid"}  # reports the tool tells the maintainer to deprioritize
FINALS = ["not_grounded", "likely_invalid", "policy_question", "insufficient_info", "needs_human", "likely_valid"]


def _sample(rows: list[dict], per_label: int | None) -> list[dict]:
    if per_label is None:
        return rows
    out = []
    for label in ("slop", "valid"):
        group = sorted((r for r in rows if r["label"] == label), key=lambda r: hashlib.sha256(f"s{r['h1_id']}".encode()).hexdigest())
        out += group[:per_label]
    return out


def _rates(results: list[dict]) -> dict:
    slop = [r["final"] in FLAG for r in results if r["label"] == "slop"]
    valid = [r["final"] in FLAG for r in results if r["label"] == "valid"]
    confirmed = [r["final"] == "likely_valid" for r in results if r["label"] == "valid"]
    tp, fp = sum(slop), sum(valid)
    slop_pq = [r["final"] in FLAG | {"policy_question"} for r in results if r["label"] == "slop"]
    valid_pq = [r["final"] in FLAG | {"policy_question"} for r in results if r["label"] == "valid"]
    return {
        "slop_flagged_or_policy": sum(slop_pq), "valid_flagged_or_policy": sum(valid_pq),
        "n_slop": len(slop), "n_valid": len(valid),
        "slop_flagged": tp, "slop_ci": _bootstrap_ci(slop),
        "valid_flagged": fp, "valid_ci": _bootstrap_ci(valid),
        "valid_confirmed": sum(confirmed),
        "precision": tp / (tp + fp) if tp + fp else float("nan"),
    }


def run(split: str = "dev", per_label: int | None = None, thinking: bool = True, name: str | None = None, workers: int = 6) -> dict:
    rows = [r for r in dataset.load() if split == "all" or split_of(r["h1_id"]) == split]
    rows = _sample(rows, per_label)
    name = name or f"{split}{'-' + str(per_label) if per_label else ''}{'' if thinking else '-nothink'}"
    out_dir = ROOT / "runs" / "triage" / name
    out_dir.mkdir(parents=True, exist_ok=True)
    repo = Repo()
    repo.identifier_history()

    def one(row: dict) -> dict:
        try:
            res = triage(row["input"], repo, thinking=thinking)
        except Exception as e:  # one failed report should not sink the run
            res = {"final": "error", "error": f"{type(e).__name__}: {e}", "cost": 0.0}
        return {"h1_id": row["h1_id"], "label": row["label"], "split": split_of(row["h1_id"]),
                "year": (row["input"].get("submitted_at") or "")[:4], "title": row["input"]["title"], **res}

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool, open(out_dir / "results.jsonl", "w") as f:
        for r in pool.map(one, rows):
            results.append(r)
            f.write(json.dumps(r) + "\n")
            f.flush()
            print(f"  h1 {r['h1_id']:>8} {r['label']:5} -> {r['final']:17} ${r.get('cost', 0):.3f}", flush=True)

    summary = {"name": name, "split": split, "thinking": thinking, "n": len(results), "spend": str(tf.SPEND),
               "overall": _rates(results),
               "before_2026": _rates([r for r in results if r["year"] < "2026"]),
               "in_2026": _rates([r for r in results if r["year"] >= "2026"]),
               "confusion": {lab: dict(Counter(r["final"] for r in results if r["label"] == lab)) for lab in ("slop", "valid")},
               "receipts_overrides": sum(bool(r.get("receipts_override")) for r in results),
               "invalid_citations": sum(r.get("citations", {}).get("invalid", 0) for r in results),
               "valid_citations": sum(r.get("citations", {}).get("valid", 0) for r in results),
               "errors": [r["h1_id"] for r in results if r["final"] == "error"]}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    md = _markdown(summary, results)
    (out_dir / "summary.md").write_text(md)
    print(md)
    return summary


def _markdown(s: dict, results: list[dict]) -> str:
    def line(label: str, m: dict) -> str:
        if not m["n_slop"] and not m["n_valid"]:
            return f"| {label} | – | – | – | – |"
        lo, hi = m["slop_ci"]
        vlo, vhi = m["valid_ci"]
        return (f"| {label} | {m['slop_flagged']}/{m['n_slop']} ({lo:.0%}–{hi:.0%}) | {m['valid_flagged']}/{m['n_valid']} ({vlo:.0%}–{vhi:.0%}) "
                f"| {m['valid_confirmed']}/{m['n_valid']} | {m['precision']:.0%} |")

    out = [f"# Triage eval: {s['name']} ({s['n']} reports, judge reasoning {'on' if s['thinking'] else 'off'})", "",
           "Flagged = final verdict not_grounded or likely_invalid. 95% bootstrap intervals.",
           f"Counting policy_question as flagged too: slop {s['overall']['slop_flagged_or_policy']}/{s['overall']['n_slop']}, "
           f"real CVEs {s['overall']['valid_flagged_or_policy']}/{s['overall']['n_valid']}.", "",
           "| subset | slop flagged | real CVEs flagged (false alarms) | real CVEs confirmed likely_valid | precision |",
           "|---|---|---|---|---|",
           line("all", s["overall"]), line("submitted before 2026", s["before_2026"]), line("submitted in 2026", s["in_2026"]), "",
           "| final verdict | slop | valid |", "|---|---|---|"]
    for v in FINALS + ["error"]:
        a, b = s["confusion"]["slop"].get(v, 0), s["confusion"]["valid"].get(v, 0)
        if a or b:
            out.append(f"| {v} | {a} | {b} |")
    out += ["", f"Judge citations: {s['valid_citations']} point at code it was shown, {s['invalid_citations']} do not. "
                f"Receipts rule changed {s['receipts_overrides']} verdicts.", "", "Spend:", "```", s["spend"], "```", "",
            "## False alarms: real CVE reports flagged", ""]
    for r in results:
        if r["label"] == "valid" and r["final"] in FLAG:
            out.append(f"- h1 {r['h1_id']} ({r['year']}) {r['final']}: {r['title']}")
            out += [f"  - {k}" for k in r.get("judgment", {}).get("key_reasons", [])[:3]]
    out += ["", "## Slop not flagged", ""]
    for r in results:
        if r["label"] == "slop" and r["final"] not in FLAG:
            out.append(f"- h1 {r['h1_id']} ({r['year']}) {r['final']}: {r['title']}")
    return "\n".join(out) + "\n"
