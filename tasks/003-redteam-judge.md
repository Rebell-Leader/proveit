---
owner: codex
status: done
worktree: none
---

# 003 — Review and red-team the Nemotron judgment stage

## Goal
Find ways the model stage can be fooled or can leak labels, before anyone relies on its verdicts. The worst outcome
is a real vulnerability report called `likely_invalid`; the second worst is slop called `likely_valid`.

## Context
- Pipeline: `src/proveit/judge/pipeline.py` (grounding -> Nano claims -> code evidence + Tavily sources -> Ultra
  judgment -> receipts checks). Prompts and schemas are in `judge/claims.py` and `judge/verdict.py`.
- Receipts rules (`judge/verdict.py`): citations must point at code or URLs the judge was shown; external quotes must
  appear verbatim in the fetched source; a likely_invalid/likely_valid verdict without receipts becomes needs_human.
- Evidence retrieval: `judge/evidence.py`. Tavily search and leakage guard: `judge/external.py`.
- Label hygiene rules are in AGENTS.md ("No label leakage").
- You cannot call the APIs from the sandbox. Write attack inputs; the lead will run them through the real pipeline.

## Acceptance criteria
- [ ] Code findings: each with file:line, a concrete input, and its effect on the final verdict.
- [ ] Any path by which labels, triage outcomes or the published answer could reach a model.
- [ ] Five adversarial report bodies (title + markdown body, each under 400 words) targeting different weaknesses:
      prompt injection, citations that point at real but irrelevant lines, a fake quote of a dependency's docs,
      a real bug described with deliberately weak wording, and one of your choice. For each, the verdict you expect a
      correct system to give.
- [ ] No code changes. Report only.

## Output
`reviews/003-redteam-judge-codex.md`

## Resolution (claude, 2026-10-26)
All five findings fixed; regression tests in `tests/test_receipts.py`, attack reports in `tests/fixtures/adversarial.json`
(run with `uv run proveit adversarial`).
1. Receipts must be on a central claim (flaw or trigger); a contradicted central claim also blocks likely_valid.
2. URL citations count only when the judge quoted that source verbatim in external_checks.
3. Fabricated references no longer override a judge that has receipts for the central flaw: final needs_human.
   Medium grounding findings alone no longer authorize likely_invalid.
4. Release-tag permalinks (blob/curl-8_3_0/...) select the revision.
5. Tavily is restricted to dependencies' own documentation and standards bodies (include_domains), on top of the
   outcome-site exclusions; fetched pages are labeled untrusted in the prompt.
Also from running the attacks: one unparsable judge answer on the injection case (retry added), and "</report>"
inside report text is neutralized. First live run: 4/5 adversarial cases handled as expected; the fifth (injection)
returned a correct verdict on retry.
