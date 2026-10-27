# ProveIt — Devpost submission

**Tagline:** Checks AI-generated security reports against the real source code, so a maintainer can see which claims hold up before spending an hour on them.

**Try it:**
- Judge mode (197 curl reports, always instant): https://avaliev-proveit.static.hf.space
- Live mode (check any report now): https://proveit-live.onrender.com/live
- Source, method and results: https://github.com/Rebell-Leader/proveit

---

## Inspiration

In January 2026, curl — one of the most depended-on pieces of software on Earth — **shut down its public bug bounty**. Not because of a shortage of reports, but because of a flood of them: confident, well-formatted, AI-generated security reports that cite real functions and real line numbers and are completely wrong. Maintainers were spending hours disproving machine-generated fiction. curl's maintainer, Daniel Stenberg, started publicly labeling them "AI slop."

That is a brutal, specific, and growing problem for every open-source project, and it is squarely an AI problem. We didn't want to build another tool that *generates* more plausible text. We wanted one that **holds a report to the code** and shows its work.

## What it does

ProveIt reads a security report and, before any human spends time on it, checks every claim against the actual source at the version the report targets. It runs in six stages:

1. **Grounding** (deterministic, no model) — pins every file, line, symbol, commit, version and quoted snippet the report cites to the real repository. Catches outright fabrication.
2. **Claims** (NVIDIA Nemotron Nano, reasoning off) — turns the report into a short list of checkable claims.
3. **Evidence** (deterministic + Tavily) — fetches the exact curl functions and lines, and the dependency documentation the report leans on.
4. **Judgment** (NVIDIA Nemotron Ultra, reasoning on) — rules on each claim against the code it was shown: supported, contradicted, or not verifiable, with line citations and a draft reply.
5. **Receipts** (deterministic) — every citation must point at code the model was actually shown, on a central claim; external quotes must appear verbatim in the fetched page. A verdict without receipts is downgraded to "needs a human."
6. **Reproduction** (Nebius Sandboxes) — when the report ships a proof of concept that calls libcurl, ProveIt builds the targeted curl release under AddressSanitizer in an isolated sandbox VM and runs the PoC **offline**. A sanitizer crash inside curl's own code is a receipt a model cannot fake; a PoC that will not even compile against the real API is one too.

It never closes a report. It tells the maintainer what checks out, what doesn't, and exactly where to look.

## How we built it

- **Models:** NVIDIA Nemotron Nano (claim extraction) and Nemotron Ultra (judgment), both served on **Nebius Token Factory** (OpenAI-compatible). Thinking is toggled per stage; output is constrained to a strict JSON schema.
- **Reproduction:** **Nebius Sandboxes** (ConTree) over its REST API. We build curl once per release under AddressSanitizer + UBSan, cache it as an immutable sandbox checkpoint, then run each report's PoC with the guest network disabled.
- **Grounding:** a full local curl clone with history; deterministic checks over files, symbols, quotes, versions, commits and CVEs.
- **Web app:** FastAPI + Jinja (server-rendered, no build step). Judge mode is a pre-rendered static site; live mode streams each stage over SSE.
- **Dataset:** 49 reports curl's maintainer publicly labeled AI slop, plus 148 real reports behind published curl CVEs, all from HackerOne's public JSON. Models only ever see a report's title, body and date — labels never leak.

## Results (held-out test set, 77 reports, pipeline frozen)

- **Slop:** deprioritized 5 of 18 outright, flagged 4 more for a policy call, and called **0 of 18** valid.
- **Real CVEs:** found code supporting **22 of 59** (15 of 21 for 2026 reports), with **2 false alarms** that it shows honestly.
- **Reproduction:** rebuilt CVE-2026-92391 and caught a real stack overflow inside `curl_mime_free` under AddressSanitizer.
- **Cost:** about **$0.017 per report**.

The evaluation deliberately reports its own failures. ProveIt shows evidence and defers to the maintainer precisely because the models are sometimes wrong — including in the pipeline itself.

## Challenges we ran into

- **The slop lies about real code.** Our first grounding checker flagged 55% of *real* CVEs, because slop reports cite genuine curl functions and genuine line numbers. The fix was to treat only curl-namespaced APIs and explicit file:line as strong evidence, and to let the Ultra judge carry the semantic load.
- **A sandbox that breaks autotools.** curl's `./configure` fails inside the sandbox — its `cat confdefs.h - <<EOF` conftest writes hit "Bad file descriptor." We diagnosed it to the shell/heredoc layer and switched the build to CMake + Ninja.
- **Prompt injection in the reports themselves.** Reports try to close the prompt and dictate a verdict. The pipeline neutralizes section tags, and the receipts stage means a smuggled instruction still can't produce a verdict without real citations.
- **Honest reproduction.** Most real curl bugs need a live peer, so a clean offline run is only weak evidence — we classify it that way rather than overclaiming.

## What we're proud of

Two Nebius products working together to produce **evidence, not opinion**: the models reason over the code, and the sandbox produces a crash trace that settles the argument. And an evaluation that leads with its own mistakes.

## What's next

General repository integration beyond curl; live-mode reproduction for already-built releases; and a maintainer-facing triage queue.

## Built with

NVIDIA Nemotron (Nano + Ultra) · Nebius Token Factory · Nebius Sandboxes (ConTree) · Python · FastAPI · Jinja · AddressSanitizer/UBSan · CMake · Tavily · Hugging Face Spaces · Render
