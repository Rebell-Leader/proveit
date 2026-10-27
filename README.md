# ProveIt

**Does the code agree with the bug report?**

ProveIt helps open-source maintainers check security reports before investing time in an investigation. It reads the
report, finds the relevant source code, and shows what supports or contradicts each claim—with links to the exact lines.
The current implementation supports **curl**.

[Explore the demo](https://avaliev-proveit.static.hf.space) ·
[Check a report live](https://proveit-live.onrender.com/live) ·
[Recording guide](docs/demo.md)

## See the difference

A report claims `inet_ntop4` copies into a buffer without checking its size. The real code says:

```c
/* lib/inet_ntop.c:75–80, at the report's targeted revision */
len = strlen(tmp);
if(len == 0 || len >= size) {
  errno = ENOSPC;
  return (NULL);
}
strcpy(dst, tmp);
```

The check is right before the copy. ProveIt points the maintainer to it and drafts a reply.
[Inspect this saved analysis](https://avaliev-proveit.static.hf.space/r/2887487.html).

It can also find evidence for a real bug. In a second example, a proof of concept builds 5,000 nested MIME levels.
An offline run in a Nebius sandbox catches a stack overflow inside curl's cleanup code.
[Inspect the sandbox result](https://avaliev-proveit.static.hf.space/r/4024222.html).

## Why build this?

Security reports take time to investigate, even when they are wrong. curl
[ended its bug bounty in January 2026](https://daniel.haxx.se/blog/2026/01/26/the-end-of-the-curl-bug-bounty/)
after an influx of low-quality reports. A report can name real functions and still make false claims about them.

ProveIt checks those claims against the code. It provides evidence and a draft response; the maintainer decides what to do.

## How it works

1. **Find the code.** Deterministic checks verify references against the curl version the report targets.
2. **Check the claims.** NVIDIA Nemotron 3 Nano extracts claims; Nemotron 3 Ultra compares them with source code and relevant documentation.
3. **Check the answer.** Citation checks discard references outside the supplied evidence and verify quoted documentation. A judgment that loses required evidence becomes `needs_human`.
4. **Optionally reproduce.** Build the targeted curl release with sanitizers and run a proof of concept offline in a Nebius sandbox.

All model calls use **Nebius Token Factory**. Documentation search uses Tavily. Report code runs only in an isolated
sandbox with networking disabled. The web checker reads code; reproduction is available through the CLI and saved examples.
A verified citation shows where the model looked. It does not guarantee that the model understood the code correctly.

## What the test showed

We developed on 120 reports, then evaluated once on 77 held-out reports: 18 labeled AI slop by curl's maintainer and
59 linked to published vulnerabilities.

| Outcome | Labeled AI slop (18) | Known vulnerabilities (59) |
|---|---:|---:|
| Flagged for lower priority | 5 | **2 wrong** |
| Needs a policy decision | 4 | 3 |
| Needs human review or more information | 9 | 32 |
| Code supports the reported flaw | 0 | 22 |

Model calls cost $1.34 for the test, about $0.017 per report. Optional reproduction is excluded from these scores.
The two wrongly flagged real bugs were CVE-2023-38546 and CVE-2022-27776. ProveIt never closes reports automatically.
[Full method, uncertainty, and failures](docs/evaluation.md).

## Run locally

The saved demo needs no API key, curl clone, or model calls:

```bash
uv sync
uv run uvicorn proveit.web.app:app --port 8000
# Open http://localhost:8000
```

For new analyses:

```bash
cp .env.example .env                 # add your Nebius Token Factory and Tavily keys
uv run proveit smoke                # check the model connection
uv run proveit fetch-repo           # fetch curl's source and history
uv run proveit dataset              # fetch public report text
uv run proveit triage 2887487        # check a report
```

For sandbox reproduction, set `NEBIUS_PROJECT_ID` in [.env.example](.env.example)
(copied to `.env`) and ensure your Nebius account has sandbox access. Then run `uv run proveit reproduce 4024222`.
Never run report proof-of-concept code directly on the host.

```bash
uv run pytest
```

[Architecture, commands & hosting](docs/technical.md) · [Nebius & Nemotron feedback](FEEDBACK.md)

Built for the Nebius x NVIDIA Global AI Hackathon. Apache-2.0; see [LICENSE](LICENSE).
