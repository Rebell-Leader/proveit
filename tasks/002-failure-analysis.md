---
owner: agy
status: done
worktree: none
---

# 002 — Independent failure analysis of the grounding eval

## Goal
Explain, case by case, why the grounding checker gets reports wrong, without relying on the lead's interpretation.

## Context
- Results: `runs/grounding/results.jsonl` (verdict and findings per report) and `runs/grounding/summary.md`.
- Report text: `data/cache/reports.jsonl` (field `input`). Labels: `data/curl_reports.jsonl` (`label` is `slop` or `valid`).
- `valid` means the report led to a published curl CVE. `slop` means curl's maintainer listed it as AI slop.

## Acceptance criteria
- [ ] Every `valid` report with verdict `not_grounded` gets a cause from this list: extractor bug, wrong revision,
      renamed or moved code, symbol from a dependency, quote reformatted, label issue, or other (explain).
- [ ] Every `slop` report with verdict `grounded` gets one sentence on what makes it slop that existence checks cannot see
      (for example: a real function with a wrong claim about it).
- [ ] A short table with counts per cause and the two or three fixes that would remove the most false alarms.
- [ ] No code changes. Report only.

## Output
`reviews/002-failure-analysis-agy.md`

## Resolution (claude, 2026-10-25)
agy ran without file access (headless mode denies shell commands), so it worked from `runs/grounding/agy_digest.md`.
Its causes were right; its code references (function names, `history.json`) and split counts were invented.
Verified against the data and fixed: dependency file paths (libssh's `src/knownhosts.c`), "tested at commit X" as the
revision, struct-member expressions for line checks, `Curl_` prefix slips and constant-family shorthand as medium.
Not adopted: letting many grounded claims outweigh one strong finding, because slop often hides one invented function
among real ones. Result: dev false alarms 2/89 -> 0/89; test unchanged at 0/59.
