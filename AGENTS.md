# ProveIt — agent guide

ProveIt checks AI-generated bug reports against the real code before a maintainer spends time on them.
It is built for the Nebius x NVIDIA Global AI Hackathon (deadline 2026-10-30 10:00 PT). All model calls go to
NVIDIA Nemotron on Nebius Token Factory.

## Layout

- `src/proveit/tf.py`: Token Factory client (OpenAI-compatible).
- `src/proveit/dataset.py`: builds the labeled curl dataset (AI-slop vs. real CVE reports from HackerOne).
- `src/proveit/grounding/`: deterministic checks. Do the files, lines, symbols and quoted code a report cites exist in the repo at the version it targets?
- `src/proveit/cli.py`: `uv run proveit <command>`.
- `data/curl_reports.jsonl`: labels and IDs only. Fetched report text lives in `data/cache/` (gitignored).
- `vendor/curl`: full curl clone with tags (gitignored). Create it with `uv run proveit fetch-repo`.

## Commands

```
uv sync
uv run proveit smoke            # Token Factory key + Nemotron model check
uv run proveit dataset          # fetch and label the curl reports
uv run proveit ground <h1-id>   # grounding report for one HackerOne report
uv run proveit eval             # grounding checker over the whole dataset
uv run pytest
```

## Rules

- Never commit secrets. Keys come from `.env` (see `.env.example`).
- **No label leakage.** Checkers and models see only a report's title, body, submission date and attachment names.
  Never pass the triage thread, team summaries, substate or CVE mapping into anything that produces a verdict.
- Never execute report PoC code on the host. Reproduction runs only in a sandbox with networking disabled.
- Deterministic checks decide what they can. Models handle what code cannot decide, and every verdict cites evidence
  (file@revision:line).
- Report misses honestly. Evaluation output includes the failure cases, not only the headline numbers.

## Working with several agents

Claude Code is the lead and integrator. Codex and agy are reviewers and testers that Claude calls headlessly.

- A task is one file in `tasks/NNN-short-name.md`, using the template in `tasks/README.md`.
- An agent that writes code works in its own git worktree on a branch named `agent/<agent>/<task>`, never in the main checkout.
- Reviews and findings go to `reviews/NNN-<agent>-<topic>.md`. Every finding has a file:line, a failure scenario and a severity.
- Reviewers report problems; they do not rewrite the code under review.
