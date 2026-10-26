# ProveIt

**Checks AI-generated bug reports against the real code before a maintainer spends an hour on them.**

In January 2026 curl ended its HackerOne bug bounty because AI-generated security reports were swamping its
maintainers. ProveIt reads a report, pins every file, line, function, commit, version and code quote it cites to the
repository at the revision the report targets, and tells the maintainer what checks out and what does not.
It is built on NVIDIA Nemotron models served by Nebius Token Factory.

> Status: day 3 of 5 (Nebius x NVIDIA Global AI Hackathon). The pipeline, held-out evaluation and web app work.
> Deployment and the demo video come next.

## How it works

| Stage | What runs | Why |
|---|---|---|
| 1. Grounding | deterministic code, no model | Pins every cited file, line, symbol, commit, quote and version to curl at the revision the report targets. Catches outright fabrication. |
| 2. Claims | **Nemotron 3 Nano** (30B-A3B), reasoning off, ~$0.0003 | Turns the report into checkable claims (flaw, trigger, impact...) and lists what it asserts about other projects' docs. |
| 3. Evidence | deterministic code + **Tavily** | Fetches the real curl functions and cited lines, line-numbered; Tavily fetches the dependencies' own documentation when the report quotes it. |
| 4. Judgment | **Nemotron 3 Ultra** (550B), reasoning on, ~$0.015 | Rules on each claim against the code it was shown: supported, contradicted or not verifiable, with line citations, a verdict and a draft reply. |
| 5. Receipts | deterministic code | Every citation must point at code or a source the judge was shown, on a central claim; external quotes must appear verbatim in the fetched page. A verdict without receipts becomes "needs human". |

Verdicts: `not_grounded` (fabricated references), `likely_invalid` (code contradicts the central claim),
`policy_question` (behavior is real, the project's own "not security issues" policy may exclude it),
`insufficient_info`, `needs_human`, `likely_valid`.
ProveIt never closes a report; it tells the maintainer where to look and drafts the reply.

Example (`uv run proveit triage 2887487`, an AI-slop report claiming a buffer overflow in `Curl_inet_ntop`):
Ultra marks the overflow claims contradicted, citing the length checks at `lib/inet_ntop.c:76` and `:173` that run
before every `strcpy`, while conceding the two true details (the `DEBUGASSERT` is debug-only; the wrapper itself does
not check size). 10 of 10 citations verified, $0.017, 13 seconds.

## Evaluation data

- **AI slop:** the 49 reports curl's maintainer lists as AI slop
  ([gist](https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd)).
- **Real:** the 148 HackerOne reports behind published curl CVEs ([curl.se/docs/vuln.json](https://curl.se/docs/vuln.json)).
- Report text comes from HackerOne's public JSON for disclosed reports. Only the title, body and submission date are
  ever shown to a checker or model; triage outcomes are kept apart so labels cannot leak.
- Reports are split into dev and test by a hash of their id. Rules were designed on dev failures only.

## Results on held-out reports

The pipeline was developed on the dev split (120 reports) and run once on the held-out test split (77 reports:
18 AI slop, 59 behind real curl CVEs). Test numbers, with 95% bootstrap intervals:

| Outcome | AI slop (18) | Real CVE reports (59) |
|---|---|---|
| Deprioritized: `not_grounded` or `likely_invalid`, with cited code | **5** (28%, 11–50%) | **2** (3%, 0–8%) |
| `policy_question`: behavior real, curl's own policy may exclude it | 4 | 3 |
| `needs_human` or `insufficient_info` | 9 | 32 |
| `likely_valid` with verified line citations | **0** | **22** (37%) |

- No slop report was called likely valid. Of the real CVE reports submitted in 2026, after Nemotron 3 Ultra was
  released and so not recallable from training, 15 of 21 were confirmed with code citations.
- Cost: $1.34 for the 77 reports ($0.017 each); Nano extraction is 1.4% of that.
- The judge made 490 citations; 440 point at code or sources it was shown. The 50 that do not are discarded, and a
  verdict that loses its receipts becomes `needs_human` (17 verdicts on test).
- The two false alarms (CVE-2023-38546, CVE-2022-27776) are subtle: the judge read the first as intended cookie
  behavior and misread a redirect condition in the second. Both are listed in `runs/triage/test-v1/summary.md`.

Grounding alone (no model) flags 2/18 slop and 0/59 real reports on test: most slop does not invent code, it
cites real functions and lies about them. That is why the Nemotron stage exists.

### What changed during development (dev split only)

| Version | Change | Slop flagged | Real flagged | Slop called valid |
|---|---|---|---|---|
| dev-v1 | first full pipeline | 16/31 | 5/89 | 0 |
| dev-v2 | receipts must be on central claims; evidence shows the latest release next to master | 12/31 | 0/89 | 3 |
| dev-v3 | judge applies curl's own "not security issues" policy, as of the report's revision | 18/31 | 2/89 | 0 |
| dev-v4 | a policy-only rejection with the flaw confirmed becomes `policy_question` | 11/31 (+7 policy questions) | 0/89 (+2) | 0 |

dev-v1's false alarms came from judging code that had changed after the release the reporter read; dev-v2 fixed that
by showing the release version of each changed function with the commits in between.

## Web app

- **Judge mode:** all 197 evaluated curl reports, each with ProveIt's verdict next to curl's actual outcome, the
  claims, the real code with the cited lines highlighted, and the draft reply. Precomputed, so it costs nothing to serve.
- **Live mode:** paste a public HackerOne URL or a report and watch the five stages stream in. Guarded for an unattended
  public demo: a worst-case cost is reserved per run, at most 2 runs at once, a daily dollar cap, a per-visitor limit,
  and size limits on everything read.

```bash
uv run uvicorn proveit.web.app:app --port 8000      # http://localhost:8000
docker build -t proveit . && docker run -p 7860:7860 -e NEBIUS_API_KEY=... -e TAVILY_API_KEY=... proveit
```

## Setup

```bash
uv sync
cp .env.example .env              # add your Nebius Token Factory key
uv run proveit smoke              # lists Nemotron models on your account and makes a test call
uv run proveit fetch-repo         # clones curl with full history into vendor/
uv run proveit dataset            # fetches and labels the 197 curl reports (about 3 minutes, 1 request/second)
uv run proveit eval               # grounding checker over the dataset
uv run proveit ground 2887487     # one report's grounding findings as JSON
uv run proveit triage 2887487     # full triage: grounding, Nano claims, evidence, Ultra judgment, receipts
uv run proveit triage-eval --split dev   # full triage over a split, scored (responses are cached on disk)
uv run proveit adversarial        # red-team reports (prompt injection, fake quotes...) through the real pipeline
uv run proveit export-demo        # rebuild the web app's judge-mode data from runs/triage/
uv run pytest
```

## License

Apache-2.0. See [LICENSE](LICENSE).
