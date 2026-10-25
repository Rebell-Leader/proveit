---
owner: codex
status: done
worktree: none
---

# 001 — Review and red-team the grounding checker

## Goal
Find bugs in the deterministic grounding checker. Prioritize anything that makes a real vulnerability report look
fabricated, because a false alarm costs a maintainer a real bug. Then find ways an AI-slop report can pass as grounded.

## Context
- Code: `src/proveit/grounding/{extract,repo,check,evaluate}.py`, tests in `tests/`.
- Latest results: `runs/grounding/summary.md` and `runs/grounding/results.jsonl` (one line per report, with findings).
- The checker only answers existence questions: do the cited files, lines, symbols, quoted code and versions exist in
  curl at the revision the report targets? Judging whether a flaw is exploitable is out of scope for this task.
- Report text is in `data/cache/reports.jsonl`; the curl checkout is `vendor/curl`.

## Acceptance criteria
- [ ] Each finding names a file:line, a concrete input that triggers it, and its effect on the verdict.
- [ ] Findings are ranked by severity, with false-alarm risks first.
- [ ] At least three red-team report patterns that fabricate something but still get `grounded`, each with a short example body.
- [ ] No code changes. Report only.

## Output
`reviews/001-review-grounding-codex.md`

## Resolution (claude, 2026-10-25)
All 10 findings in `reviews/001-review-grounding-codex.md` were fixed. Each red-team input is now a regression test in
`tests/test_check_redteam.py`. Fixes: release versions named in the report are tried as alternate revisions; PoC helpers,
proposed APIs and the reporter's own files no longer count as fabrications; hex tokens count as commits only with commit
context; range endpoints, single-line quotes and half-real quotes are checked; "X is in file Y" is checked in that file,
and the per-file dangerous-call check now runs before the repo-wide symbol lookup.
Headline eval unchanged on test (fabrication: 2/18 slop, 0/59 real); dev false alarms 3/89 -> 2/89.
