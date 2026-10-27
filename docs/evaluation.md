# Evaluation

The saved collection contains 197 public curl reports: [49 labeled AI slop by curl's maintainer](https://gist.github.com/bagder/07f7581f6e3d78ef37dfbfc81fd1d1cd)
and [148 HackerOne reports linked to published curl CVEs](https://curl.se/docs/vuln.json).

Reports were split by a hash of their ID into development (120) and test (77). Rules were developed on the development
split. The figures below come from one run on the held-out test split. Checkers and models receive only the report's
title, body, submission date and attachment names. Triage discussion, team summaries, labels and CVE mappings are withheld.

## Held-out results

| Outcome | Labeled AI slop (18) | Known vulnerabilities (59) |
|---|---:|---:|
| `not_grounded` or `likely_invalid` | 5 (28%; 95% bootstrap interval 11–50%) | 2 (3%; interval 0–8%) |
| `policy_question` | 4 | 3 |
| `needs_human` or `insufficient_info` | 9 | 32 |
| `likely_valid` | 0 | 22 (37%) |

Policy questions are reported separately from reports flagged for lower priority. No slop report was marked likely
valid. Reference checks alone flagged 2/18 slop reports and 0/59 real reports; misleading reports often cite real code.

The test used $1.342 in model calls ($0.017 per report). This excludes external documentation search and optional
sandbox reproduction. The sandbox example was added separately and does not change these evaluation numbers.

## Failure cases

Two real vulnerability reports were wrongly flagged for lower priority:

- [CVE-2023-38546 / report 2148242](https://avaliev-proveit.static.hf.space/r/2148242.html): the model treated cookie injection through a file named “none” as intended behavior.
- [CVE-2022-27776 / report 1547048](https://avaliev-proveit.static.hf.space/r/1547048.html): the model misread a redirect condition and missed an authentication/cookie leak.

Of 490 citations, 440 pointed to supplied evidence. The 50 others were discarded. Seventeen judgments were changed to
`needs_human` after required evidence failed validation. Citation validity does not establish that the interpretation
is correct. [Report 3506159](https://avaliev-proveit.static.hf.space/r/3506159.html) shows a judgment withdrawn after a documentation quote could not be verified.

## Scope

This is a small evaluation on one project. It does not establish performance on other repositories. Many reports
remain unresolved, including 32 of the 59 real reports. ProveIt is an investigation aid; it does not close reports.

Machine-readable summaries and individual views are checked in under `data/demo/`. Full local run artifacts are kept
under the gitignored `runs/triage/test-v1/` directory. To inspect them in the app, open **Results & limitations**.
