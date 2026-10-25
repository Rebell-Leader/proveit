"""Run the grounding checker over the labeled curl dataset and report how well it separates slop from real CVEs.

Reports are split into dev and test by a hash of the HackerOne id (about one third test). Rules are designed by
looking at dev failures only; the test numbers are the ones to quote.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

from proveit import ROOT, dataset
from proveit.grounding.check import ground_report
from proveit.grounding.repo import Repo

# Two ways to turn a grounding verdict into "flag for the maintainer".
RULES = {
    "fabrication": {"not_grounded"},
    "fabrication_or_no_specifics": {"not_grounded", "nothing_to_check"},
}


def split_of(h1_id: int) -> str:
    return "test" if int(hashlib.sha256(str(h1_id).encode()).hexdigest(), 16) % 3 == 0 else "dev"


def _rate(flags: list[bool]) -> float:
    return sum(flags) / len(flags) if flags else float("nan")


def _bootstrap_ci(flags: list[bool], n: int = 2000, seed: int = 7) -> tuple[float, float]:
    if not flags:
        return float("nan"), float("nan")
    rng = random.Random(seed)
    stats = sorted(_rate([rng.choice(flags) for _ in flags]) for _ in range(n))
    return stats[int(0.025 * n)], stats[int(0.975 * n) - 1]


def _metrics(results: list[dict]) -> dict:
    by_label = {lab: [r for r in results if r["label"] == lab] for lab in ("slop", "valid")}
    out: dict = {"n": {k: len(v) for k, v in by_label.items()},
                 "verdicts": {lab: dict(Counter(r["verdict"] for r in rs)) for lab, rs in by_label.items()},
                 "rules": {}}
    for rule, flagged in RULES.items():
        slop_flags = [r["verdict"] in flagged for r in by_label["slop"]]
        valid_flags = [r["verdict"] in flagged for r in by_label["valid"]]
        tp, fp = sum(slop_flags), sum(valid_flags)
        out["rules"][rule] = {
            "slop_flagged": tp, "slop_flag_rate": _rate(slop_flags), "slop_flag_rate_ci95": _bootstrap_ci(slop_flags),
            "valid_flagged": fp, "valid_flag_rate": _rate(valid_flags), "valid_flag_rate_ci95": _bootstrap_ci(valid_flags),
            "precision": tp / (tp + fp) if tp + fp else float("nan"),
        }
    return out


def _check_table(results: list[dict]) -> list[tuple[str, int, int]]:
    """For each (check, severity) of ungrounded findings: how many slop / valid reports have at least one."""
    seen: dict[str, dict[str, set]] = defaultdict(lambda: {"slop": set(), "valid": set()})
    for r in results:
        for f in r["findings"]:
            if f["status"] == "ungrounded":
                seen[f"{f['check']}:{f['severity']}"][r["label"]].add(r["h1_id"])
    return sorted(((k, len(v["slop"]), len(v["valid"])) for k, v in seen.items()), key=lambda t: -t[1])


def run(out_dir: str = "runs/grounding") -> dict:
    rows = dataset.load()
    repo = Repo()
    repo.identifier_history()  # build the cross-release symbol index once, in parallel

    def one(row: dict) -> dict:
        res = ground_report(row["input"], repo)
        return {"h1_id": row["h1_id"], "label": row["label"], "split": split_of(row["h1_id"]),
                "title": row["input"]["title"], **res.to_dict()}

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(one, rows))

    out = ROOT / out_dir
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in results))
    summary = {split: _metrics([r for r in results if r["split"] == split]) for split in ("dev", "test")}
    summary["all"] = _metrics(results)
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    md = _markdown(summary, results)
    (out / "summary.md").write_text(md)
    print(md)
    return summary


def _rules_table(m: dict) -> list[str]:
    lines = ["| rule | slop flagged | real CVEs flagged (false alarms) | precision |", "|---|---|---|---|"]
    for rule, x in m["rules"].items():
        lo, hi = x["slop_flag_rate_ci95"]
        vlo, vhi = x["valid_flag_rate_ci95"]
        lines.append(
            f"| {rule} | {x['slop_flagged']}/{m['n']['slop']} = {x['slop_flag_rate']:.0%} ({lo:.0%}–{hi:.0%}) "
            f"| {x['valid_flagged']}/{m['n']['valid']} = {x['valid_flag_rate']:.0%} ({vlo:.0%}–{vhi:.0%}) "
            f"| {x['precision']:.0%} |"
        )
    return lines


def _markdown(summary: dict, results: list[dict]) -> str:
    lines = ["# Grounding checker on the curl dataset", ""]
    for split in ("test", "dev"):
        m = summary[split]
        lines += [f"## {split} split: {m['n']['slop']} AI slop, {m['n']['valid']} real CVE reports", "",
                  "Flag rates with 95% bootstrap intervals.", ""] + _rules_table(m) + [""]
        lines += ["| verdict | slop | valid |", "|---|---|---|"]
        for v in sorted(set(m["verdicts"]["slop"]) | set(m["verdicts"]["valid"])):
            lines.append(f"| {v} | {m['verdicts']['slop'].get(v, 0)} | {m['verdicts']['valid'].get(v, 0)} |")
        lines.append("")

    dev = [r for r in results if r["split"] == "dev"]
    lines += ["## Which checks fire (dev): reports with at least one ungrounded finding of each kind", "",
              "| check | slop | valid |", "|---|---|---|"]
    lines += [f"| {k} | {s} | {v} |" for k, s, v in _check_table(dev)]

    def strong(r: dict) -> list[str]:
        return [f"{f['check']}: {f['evidence']}" for f in r["findings"] if f["status"] == "ungrounded" and f["severity"] == "strong"]

    lines += ["", "## False alarms (dev): real CVE reports flagged as fabricated", ""]
    for r in dev:
        if r["label"] == "valid" and r["verdict"] == "not_grounded":
            lines.append(f"- h1 {r['h1_id']} — {r['title']}")
            lines += [f"  - {s}" for s in strong(r)[:4]]
    lines += ["", "## Misses (dev): slop reports the checker found nothing wrong with", ""]
    for r in dev:
        if r["label"] == "slop" and r["verdict"] in ("grounded", "partially_grounded"):
            lines.append(f"- h1 {r['h1_id']} ({r['verdict']}) — {r['title']}")
    return "\n".join(lines) + "\n"
