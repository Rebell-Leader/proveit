"""The full triage of one report: grounding, claims (Nano), evidence, judgment (Ultra), receipts check."""

from __future__ import annotations

import re
import time
from collections.abc import Callable

from proveit import tf
from proveit.grounding.check import ground_report
from proveit.grounding.repo import Repo
from proveit.judge.claims import extract_claims
from proveit.judge.evidence import gather
from proveit.judge.external import search
from proveit.judge.verdict import check_citations, check_external_quotes, enforce_receipts, judge

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


def _stage(c: tf.Completion) -> dict:
    return {"model": c.model, "prompt_tokens": c.prompt_tokens, "completion_tokens": c.completion_tokens,
            "seconds": round(c.seconds, 1), "cost": round(c.cost, 5), "cached": c.cached, "parsed": c.data is not None}


def triage(report: dict, repo: Repo | None = None, *, thinking: bool = True, judge_model: str | None = None,
           progress: Callable[[str, dict], None] | None = None) -> dict:
    """`report` is a dataset `input` dict: title, body, submitted_at. `progress(stage, data)` is called as each
    stage finishes, for streaming UIs."""
    repo = repo or Repo()
    emit = progress or (lambda stage, data: None)
    t0 = time.monotonic()
    grounding = ground_report(report, repo).to_dict()
    emit("grounding", {"verdict": grounding["verdict"], "rev": grounding["rev"], "rev_source": grounding["rev_source"],
                       "counts": grounding["counts"],
                       "ungrounded": [f for f in grounding["findings"] if f["status"] == "ungrounded"][:8]})

    c = extract_claims(report)
    claims = c.data or {"claims": []}
    emit("claims", {"stage": _stage(c), "claims": claims.get("claims", []), "summary": claims.get("summary", ""),
                    "external_claims": claims.get("external_claims", [])})
    names = [m.group(0) for cl in claims.get("claims", []) for ref in cl.get("code_refs", []) for m in _NAME.finditer(ref)]
    release = None
    tag = repo.latest_release_before(report.get("submitted_at") or "2100-01-01")
    if tag and repo.resolve(tag):
        release = (repo.resolve(tag), tag)
    snippets = gather(repo, grounding["rev"], grounding, names, report.get("title", ""), release=release) if grounding["rev"] else []

    external = []
    for ec in claims.get("external_claims", [])[:2]:
        for src in search(ec["query"], max_results=3):
            if src["url"] not in {e["url"] for e in external}:
                external.append({**src, "for": ec["statement"][:200]})

    policy = repo.security_policy(grounding["rev"]) if grounding["rev"] else None
    emit("evidence", {"snippets": [{"path": s.name, "start": s.start, "end": s.end, "reason": s.reason} for s in snippets],
                      "external": [{"url": e["url"], "title": e["title"]} for e in external], "policy_shown": bool(policy)})
    j = judge(report, claims, grounding, snippets, external, policy=policy, thinking=thinking, model=judge_model)
    judgment = j.data or {"verdict": "needs_human", "claim_assessments": [], "confidence": 0.0,
                          "key_reasons": ["the judge returned no parsable answer"], "missing_info": [], "reply_to_reporter": ""}
    bad_quotes, verified_urls = check_external_quotes(judgment, external)
    citations = check_citations(judgment, snippets, verified_urls)
    model_verdict, override = enforce_receipts(judgment, citations, grounding, claims, bad_quotes, policy)
    if grounding["verdict"] == "not_grounded":
        # Fabricated references decide the report, unless the judge has receipts that the central flaw is real:
        # then the two kinds of evidence disagree and a human should look.
        final = "needs_human" if model_verdict == "likely_valid" else "not_grounded"
        if model_verdict == "likely_valid":
            override = "deterministic checks found fabricated references, but the judge cited code supporting the flaw"
    else:
        final = model_verdict

    return {
        "final": final,
        "model_verdict": model_verdict,
        "judge_verdict": judgment.get("verdict"),
        "policy_section": judgment.get("policy_section", ""),
        "policy_shown": bool(policy),
        "receipts_override": override,
        "confidence": judgment.get("confidence"),
        "grounding": grounding,
        "claims": claims,
        "evidence": [{"path": s.name, "start": s.start, "end": s.end, "reason": s.reason, "rev": s.rev, "lines": s.lines}
                     for s in snippets],
        "external": [{"url": e["url"], "title": e["title"], "for": e["for"]} for e in external],
        "judgment": judgment,
        "citations": {"valid": len(citations["valid"]), "invalid": len(citations["invalid"]),
                      "invalid_examples": citations["invalid"][:5], "bad_external_quotes": bad_quotes},
        "stages": {"claims": _stage(c), "judge": _stage(j)},
        "cost": round(c.cost + j.cost, 5),
        "seconds": round(time.monotonic() - t0, 1),
    }


def describe(result: dict) -> str:
    """Human-readable triage, the shape the web app will show."""
    g, jd, st = result["grounding"], result["judgment"], result["stages"]
    out = [f"VERDICT: {result['final']}  (judge said {result['judge_verdict']}, confidence {result['confidence']})"]
    if result["receipts_override"]:
        out.append(f"  receipts rule: {result['receipts_override']}")
    if result.get("policy_section"):
        out.append(f"  project policy: {result['policy_section']}")
    out.append(f"Revision: {g['rev'][:12] if g['rev'] else '-'} ({g['rev_source']})")
    out.append("")
    out.append(f"1. Grounding (deterministic, no model): {g['verdict']}")
    out += [f"   - {f['check']}: {f['evidence']}" for f in g["findings"] if f["status"] == "ungrounded"][:6]
    s = st["claims"]
    out.append(f"2. Claims: {s['model'].split('/')[-1]}, reasoning off, {s['prompt_tokens']}+{s['completion_tokens']} tokens, "
               f"${s['cost']:.4f}{' (cached)' if s['cached'] else ''}")
    out += [f"   {c['id']} [{c['kind']}] {c['text'][:110]}" for c in result["claims"].get("claims", [])]
    out.append(f"3. Evidence: {len(result['evidence'])} snippets of real curl code")
    out += [f"   - {e['path']}:{e['start']}-{e['end']} ({e['reason'][:60]})" for e in result["evidence"][:8]]
    if result.get("external"):
        out.append(f"   External sources (Tavily): {len(result['external'])}")
        out += [f"   - {e['url']}" for e in result["external"][:5]]
    s = st["judge"]
    out.append(f"4. Judgment: {s['model'].split('/')[-1]}, reasoning on, {s['prompt_tokens']}+{s['completion_tokens']} tokens, "
               f"{s['seconds']}s, ${s['cost']:.4f}{' (cached)' if s['cached'] else ''}")
    for a in jd.get("claim_assessments", []):
        cites = ", ".join(f"{e['file']}:{e['line']}" for e in a.get("evidence", []))
        out.append(f"   {a['id']} {a['status'].upper()} {('[' + cites + ']') if cites else ''}")
        out.append(f"      {a['reasoning'][:220]}")
    out.append(f"   citations: {result['citations']['valid']} point at code it was shown, {result['citations']['invalid']} do not")
    for x in jd.get("external_checks", []):
        out.append(f"   external: {x['status'].upper()} {x['statement'][:90]!r}")
        if x["quote"]:
            out.append(f"      {x['url']}: \"{x['quote'][:200]}\"")
    out.append("Key reasons:")
    out += [f"   - {r}" for r in jd.get("key_reasons", [])]
    if jd.get("missing_info"):
        out.append("Missing info:")
        out += [f"   - {r}" for r in jd["missing_info"]]
    out.append("Draft reply:")
    out.append("   " + jd.get("reply_to_reporter", "").replace("\n", "\n   "))
    out.append(f"Total: ${result['cost']:.4f}, {result['seconds']}s")
    return "\n".join(out)
