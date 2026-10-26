---
owner: codex
status: done
worktree: none
---

# 004 — Security and robustness review of the web app

## Goal
The web app will be public until 2026-12-15, unattended, with a Token Factory key behind live mode. Find what an
anonymous visitor could abuse: cost blow-ups, XSS, SSRF, crashes, information leaks.

## Context
- `src/proveit/web/app.py` (FastAPI routes, live mode SSE), `web/budget.py` (per-IP and daily dollar caps),
  `web/view.py` (view model), `web/templates/*.html` (Jinja2, autoescape on), `web/static/live.js`.
- Live mode runs `proveit.judge.pipeline.triage` on visitor-supplied text or a HackerOne URL. Report text and every
  model output must be treated as attacker-controlled (prompt injection can steer model output).
- Deployment will be a single container behind a reverse proxy (Hugging Face Spaces or similar).

## Acceptance criteria
- [ ] Each finding: file:line, a concrete request or input that triggers it, impact, severity.
- [ ] Cover at least: cost exhaustion (concurrency, spoofed client IPs, retries), injection into HTML or URLs,
      SSRF through the HackerOne fetch, error messages that leak secrets or paths, input size limits.
- [ ] No code changes. Report only.

## Output
`reviews/004-review-web-codex.md`

## Resolution (claude, 2026-10-26)
All six findings fixed; regression tests in `tests/test_web.py` (no API calls).
1. Admission reserves $0.10 per run atomically and caps concurrent runs at 2, so parallel requests cannot pass the cap.
2. Client identity is the last X-Forwarded-For entry (added by our proxy), never a client-chosen one; uvicorn no
   longer trusts forwarded headers from anywhere.
3. and 4. A run is settled in the worker's done-callback, so a disconnect cannot skip charging; failures are charged
   the full reservation.
5. Request bodies are capped at 64 KB while streaming; HackerOne responses at 1 MB; field types are validated.
6. Admission happens before the HackerOne fetch; cached reports redirect without using any budget.
Also fixed before the review: model-supplied URLs are only rendered as links when they are http(s).
