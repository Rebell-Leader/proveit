---
owner: codex
status: done
worktree: agent/codex/demo-polish
---

# 006 — Clear positioning and a recording-ready demo

## Goal
Make ProveIt's value understandable in one screen and give a presenter a short, evidence-led demo path.

## Context
User requested implementation of landing page, app copy, and README polish. Work in `/tmp/proveit-demo-polish`; keep verdict generation, saved evaluation results, and report text unchanged. Read `src/proveit/web/`, `README.md`, and the saved demo results first.

## Acceptance criteria
- [x] Landing page leads with the maintainer's problem and a real claim/code example.
- [x] Report pages explain the finding before model and evaluation details.
- [x] A short demo route shows a false alarm, a reproduced bug, and a withdrawn model judgment.
- [x] README gives a short introduction and accurate results, including failures.
- [x] App and static export render successfully; existing tests pass; desktop and mobile layouts are inspected.

## Output
Branch `agent/codex/demo-polish`, updated app and documentation, and a recording script in `docs/demo.md`.

## Verification
- `pytest -q`: 50 passed, using the existing curl checkout; no model or sandbox calls.
- Static build: 200 pages; all 3,130 links checked, no missing local files or citation targets.
- Browser: saved example sequence, citation expansion, search, live validation, saved-report redirect, and sample inputs.
- Desktop and 390 px mobile layouts inspected.
- All 197 saved verdicts, claims, and labels are unchanged.
