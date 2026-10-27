"""Turn a triage result into the view model the templates render. Shared by judge mode and live mode."""

from __future__ import annotations

from proveit.grounding.repo import Repo

VERDICTS = {
    "not_grounded": ("Cites code that does not exist", "bad", "The report names files, functions or code that are not in curl."),
    "likely_invalid": ("Code contradicts the report", "bad", "The real code disproves the report's central claim."),
    "policy_question": ("Real behavior, maybe not a security issue", "warn",
                        "The code does what the report says, but curl's own policy may exclude it. A maintainer decides."),
    "insufficient_info": ("Not enough to check", "muted", "The report does not name a concrete code path or reproduction."),
    "needs_human": ("Needs a human", "muted", "The evidence does not settle it either way."),
    "likely_valid": ("Confirmed by the code", "good", "The real code shows the flaw the report describes."),
    "error": ("Could not finish", "muted", "The pipeline did not complete for this report."),
}
STATUS = {"supported": ("supported", "good"), "contradicted": ("contradicted", "bad"), "not_verifiable": ("not verifiable", "muted")}

# Outcome of the Nebius-sandbox reproduction: (headline, tone, what it means).
REPRO = {
    "reproduced": ("Reproduced under AddressSanitizer", "good",
                   "The report's proof of concept, built against this curl release and run offline, tripped a sanitizer inside curl's code."),
    "fabricated_api": ("Proof of concept does not compile", "bad",
                       "The proof of concept calls libcurl functions that do not exist in this release: it cannot be the real API."),
    "crash_outside_curl": ("Crash, but not in curl", "warn",
                           "A sanitizer fired, but the failing code was the report's own, not curl's."),
    "ran_clean": ("Ran without tripping a sanitizer", "muted",
                  "The proof of concept built and ran against the real curl without a memory error. This alone does not clear the report."),
    "inconclusive": ("No clear signal offline", "muted",
                     "The offline run neither crashed nor completed cleanly enough to decide."),
}


def _reproduction_view(r: dict | None) -> dict | None:
    if not r or not r.get("attempted"):
        return {"attempted": False, "reason": r.get("reason", "")} if r else None
    headline, tone, explain = REPRO.get(r.get("outcome", ""), (r.get("outcome", "").replace("_", " "), "muted", ""))
    return {"attempted": True, "headline": headline, "tone": tone, "explain": explain,
            "outcome": r.get("outcome"), "version": r.get("version", ""), "language": r.get("language", ""),
            "detail": r.get("detail", ""), "expected": r.get("expected", ""), "script": r.get("script", ""),
            "stdout": r.get("stdout", ""), "stderr": r.get("stderr", ""), "missing_symbols": r.get("missing_symbols", []),
            "sandbox_cost": r.get("sandbox_cost", 0)}


def _snippet_lines(repo: Repo | None, ev: dict, fallback_rev: str | None) -> list[str]:
    if ev.get("lines"):
        return ev["lines"]
    if repo is None:
        return []
    path, _, tag = ev["path"].partition("@")
    rev = repo.resolve(tag) if tag else (ev.get("rev") or fallback_rev)
    if not rev:
        return []
    text = (repo.read(rev, path) or "").splitlines()
    return text[ev["start"] - 1 : ev["end"]]


def to_view(result: dict, report: dict, *, h1_id: int | None = None, truth: dict | None = None, repo: Repo | None = None,
            excerpt_chars: int = 2400) -> dict:
    """`report`: title, body, submitted_at. `truth`: optional {"label", "cve", "cve_summary"} for judge mode."""
    judgment = result.get("judgment", {})
    grounding = result.get("grounding", {})
    final = result.get("final", "error")
    label, tone, explain = VERDICTS.get(final, VERDICTS["error"])

    # Every citation the judge made, and whether it pointed at code it was shown.
    snippets = result.get("evidence", [])
    shown = {(e["path"], n) for e in snippets for n in range(e["start"], e["end"] + 1)}
    cited: dict[tuple[str, int], list[str]] = {}
    claims = []
    assessments = {a["id"]: a for a in judgment.get("claim_assessments", [])}
    for c in result.get("claims", {}).get("claims", []):
        a = assessments.get(c["id"], {})
        status, stone = STATUS.get(a.get("status", "not_verifiable"), STATUS["not_verifiable"])
        cites = []
        for e in a.get("evidence", []):
            if e["file"].replace(" ", "_").lower().startswith("deterministic_check"):
                # The judge pointing at a grounding result rather than code: show it as such (receipts never count it).
                cites.append({"file": "deterministic check", "line": 0, "note": e.get("note", ""), "valid": True, "check": True})
                continue
            ok = (e["file"], e["line"]) in shown or e["file"].startswith("http")
            cites.append({"file": e["file"], "line": e["line"], "note": e.get("note", ""), "valid": ok})
            if ok and not e["file"].startswith("http"):
                cited.setdefault((e["file"], e["line"]), []).append(f"{c['id']}: {e.get('note', '')}")
        claims.append({"id": c["id"], "kind": c["kind"], "text": c["text"], "status": status, "tone": stone,
                       "reasoning": a.get("reasoning", ""), "citations": cites})

    code = []
    for ev in snippets:
        lines = _snippet_lines(repo, ev, grounding.get("rev"))
        rows = [{"n": ev["start"] + i, "text": t, "notes": cited.get((ev["path"], ev["start"] + i), [])} for i, t in enumerate(lines)]
        code.append({"name": ev["path"], "start": ev["start"], "end": ev["end"], "reason": ev["reason"], "rows": rows,
                     "cited": any(r["notes"] for r in rows)})
    code.sort(key=lambda s: not s["cited"])

    body = report.get("body", "")
    stages = result.get("stages", {})
    view = {
        "id": h1_id,
        "title": report.get("title", "(untitled report)"),
        "submitted": (report.get("submitted_at") or "")[:10],
        "source_url": f"https://hackerone.com/reports/{h1_id}" if h1_id else None,
        "excerpt": body[:excerpt_chars],
        "excerpt_truncated": len(body) > excerpt_chars,
        "final": final, "final_label": label, "tone": tone, "explain": explain,
        "confidence": result.get("confidence"),
        "judge_verdict": result.get("judge_verdict"),
        "receipts_override": result.get("receipts_override", ""),
        "policy_section": result.get("policy_section", ""),
        "grounding": {
            "verdict": grounding.get("verdict"),
            "rev": (grounding.get("rev") or "")[:12],
            "rev_source": grounding.get("rev_source", ""),
            "counts": grounding.get("counts", {}),
            "problems": [f for f in grounding.get("findings", []) if f["status"] == "ungrounded"][:8],
        },
        "summary": result.get("claims", {}).get("summary", ""),
        "claims": claims,
        "external_checks": judgment.get("external_checks", []),
        "external_sources": result.get("external", []),
        "key_reasons": judgment.get("key_reasons", []),
        "missing_info": judgment.get("missing_info", []),
        "reply": judgment.get("reply_to_reporter", ""),
        "code": code,
        "reproduction": _reproduction_view(result.get("reproduction")),
        "citations": result.get("citations", {}),
        "stages": {k: {"model": v.get("model", "").split("/")[-1], "prompt_tokens": v.get("prompt_tokens", 0),
                       "completion_tokens": v.get("completion_tokens", 0), "seconds": v.get("seconds", 0),
                       "cost": v.get("cost", 0)} for k, v in stages.items()},
        "cost": result.get("cost", 0),
        # Model time as originally measured; a re-scored result from the cache would otherwise show ~1 second.
        "seconds": round(sum(v.get("seconds", 0) for v in stages.values()), 1) or result.get("seconds", 0),
    }
    if truth:
        if truth.get("label") == "slop":
            view["truth"] = {"tone": "bad", "text": "curl's maintainer lists this report as AI slop"}
        else:
            view["truth"] = {"tone": "good", "text": f"A real vulnerability: {truth.get('cve', '')} {truth.get('cve_summary') or ''}".strip()}
        view["truth_label"] = truth.get("label")
    return view
