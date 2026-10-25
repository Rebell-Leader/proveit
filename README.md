# ProveIt

**Checks AI-generated bug reports against the real code before a maintainer spends an hour on them.**

In January 2026 curl ended its HackerOne bug bounty because AI-generated security reports were swamping its
maintainers. ProveIt reads a report, pins every file, line, function, commit, version and code quote it cites to the
repository at the revision the report targets, and tells the maintainer what checks out and what does not.
It is built on NVIDIA Nemotron models served by Nebius Token Factory.

> Status: day 1 of 5 (Nebius x NVIDIA Global AI Hackathon). The deterministic grounding layer and the labeled
> evaluation set work. The Nemotron judgment stage, the sandbox reproduction and the web app come next.

## How it works

1. **Grounding (deterministic, no model):** extract everything the report cites, then check it against curl at the
   commit that was on master the day the report was submitted (or the commit in its GitHub permalink).
   Examples of what it catches: functions that never existed in any curl release, quoted code that appears nowhere in
   curl, `strcpy()` claimed in a file at a revision where curl's own source checker bans `strcpy`, versions that did
   not exist yet.
2. **Judgment (Nemotron on Token Factory, in progress):** Nemotron 3 Nano extracts claims; Nemotron 3 Ultra reads the
   real code the grounding step retrieved and judges whether each claimed flaw is real.
3. **Reproduction (in progress):** builds the target revision and runs the report's PoC in a sandbox with no network.

## Evaluation data

- **AI slop:** the 49 reports curl's maintainer lists as AI slop
  ([gist](https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd)).
- **Real:** the 148 HackerOne reports behind published curl CVEs ([curl.se/docs/vuln.json](https://curl.se/docs/vuln.json)).
- Report text comes from HackerOne's public JSON for disclosed reports. Only the title, body and submission date are
  ever shown to a checker or model; triage outcomes are kept apart so labels cannot leak.
- Reports are split into dev and test by a hash of their id. Rules were designed on dev failures only.

## Day 1 result: existence checks alone catch little slop

On the held-out test split (18 slop, 59 real), the decisive "fabrication" verdict flags **2/18 slop reports (11%)**
and **0/59 real CVE reports**. On dev it flags 2/31 slop and 0/89 real.

The finding behind that number: most curl slop does not invent code. It cites real files and real functions
(`Curl_inet_ntop`, `curl_mfprintf`, `lib/cookie.c`) and then makes false claims about them. So the grounding layer's
main job is to retrieve the exact real code each claim is about, for the Nemotron stage to judge. Full results,
including every false alarm and miss: `runs/grounding/summary.md` after running the eval.

## Setup

```bash
uv sync
cp .env.example .env              # add your Nebius Token Factory key
uv run proveit smoke              # lists Nemotron models on your account and makes a test call
uv run proveit fetch-repo         # clones curl with full history into vendor/
uv run proveit dataset            # fetches and labels the 197 curl reports (about 3 minutes, 1 request/second)
uv run proveit eval               # grounding checker over the dataset
uv run proveit ground 2887487     # one report's findings as JSON
uv run pytest
```

## License

Apache-2.0. See [LICENSE](LICENSE).
