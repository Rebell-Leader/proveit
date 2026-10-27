# Review 005 — Codex on the Nebius sandbox reproduction stage

`codex exec -s read-only` over `src/proveit/repro/` (sandbox.py, images.py, stage.py) and the integrations in
`judge/pipeline.py`, `web/view.py`, `web/demo.py`. Codex reported findings only; fixes applied by Claude.

| # | Severity | Where | Finding | Resolution |
|---|---|---|---|---|
| 1 | high | stage.py `_SANITIZER` | A PoC that merely prints the word "AddressSanitizer" was read as a sanitizer report. | `_SANITIZER` now requires the structured form (`ERROR:`/`SUMMARY: …Sanitizer:` or `: runtime error:`), not the bare word. |
| 2 | high | stage.py `_CURL_FRAME` | A crash in a PoC helper named `Curl_report_helper` matched the curl-frame regex. | `_CURL_FRAME` now matches only the built-source path `/src/curl/(lib\|src)/*.c`; the PoC lives at `/tmp/poc.c`. (Fixed before the review, in the same pass.) |
| 3 | med | stage.py:classify | A syntax error or build-env failure became `fabricated_api`, so the UI claimed nonexistent libcurl functions. | `fabricated_api` now requires an actual missing-symbol diagnostic; otherwise `inconclusive`. |
| 4 | med | stage.py compile check | A compiler error containing the marker as a substring passed compile detection. | Compile and completion markers are matched line-exactly; a failed build prints `PROVEIT_BUILD_FAILED`. |
| 5 | med | stage.py harness | An unsanitized segfault still printed the completion marker and became `ran_clean`. | The harness prints `POC_EXIT=$?`; a non-zero/signal exit without a sanitizer report is `inconclusive`. |
| 6 | med | stage.py:classify | A PoC could push its sanitizer report past the output truncation limit and get `ran_clean`. | Truncated output without the completion marker is `inconclusive`. |
| 7 | med | images.py:target_release | "tested 8.0.0; fixed in 8.1.0" selected the fixed release 8.1.0. | Versions named in a fix context (`fixed/patched/resolved in <v>`) are excluded from the target. |
| 8 | med | sandbox.py:_wait | A transient poll error abandoned a running (billable) build without cancelling it. | The poll loop retries transient errors until the deadline, then cancels (best effort). |
| 9 | med | web/demo.py:_reproductions | A sandbox outage during export aborted the whole static demo build. | Each reproduction is wrapped; a failure is logged and skipped, the report just shows none. |

Covered by `tests/test_repro.py` (14 cases): sanitizer-form matching, curl-frame vs PoC-frame, fabricated-API vs
syntax error, segfault, truncation, and the build-script markers.
