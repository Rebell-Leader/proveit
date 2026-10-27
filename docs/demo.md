# Recording ProveIt

The pitch: **ProveIt checks security bug reports against the code, so maintainers can see which claims hold up.**

Show the evidence before explaining the pipeline. Use a calm, conversational delivery. Allow a beat for viewers to
read the highlighted line. Aim for about 2½ minutes.

## Before recording

- Start `uv run uvicorn proveit.web.app:app --port 8000` and open `http://localhost:8000`.
- Use a 1440×900 or 1440×810 browser window at 100% zoom. The app uses a consistent light theme.
- Open the three examples once: `/r/2887487`, `/r/4024222`, `/r/3506159`. These are saved real runs, so no API calls or waiting are needed.
- Keep the recorded-outcome comparison and technical details closed until you discuss them.
- If showing the hosted live checker, wake it before recording. A URL already in the collection opens a saved analysis; it does not rerun the models.
- Do not regenerate results or run report code locally for the recording. The sandbox output is already saved.

## Shot list and narration

| Time | Screen / action | Say |
|---|---|---|
| 0:00–0:20 | Landing page. Hold on the report/code card. | “A security report says there's a buffer overflow. It names the function. It includes code. Before you spend an hour investigating, there's one question: does the real code agree?” |
| 0:20–0:50 | Click **See a report checked**. Point at the highlighted size check. | “ProveIt checks the report against the version of curl it targets. This report says the copy has no size check. Here it is, right before the copy. If the buffer is too small, the function returns.” |
| 0:50–1:05 | Click **Inspect lib/inet_ntop.c:76**. Then open **Review a draft reply**. | “You can follow the finding to the exact source line, inspect every claim, and review a draft response. The maintainer still makes the call.” |
| 1:05–1:35 | Open `/r/4024222`. Show the finding, then **Sandbox output**. | “Now a real bug. Deeply nested MIME data sends curl's cleanup code into recursive calls until the stack runs out. We built the targeted release in a Nebius sandbox and ran the proof of concept offline. AddressSanitizer caught the stack overflow inside curl.” |
| 1:35–1:55 | Open `/r/3506159`. Hold on **Judgment withdrawn**. | “Our AI can be wrong too. Here it believed a made-up documentation quote. The citation check caught that and withdrew the judgment. This report needs a human.” |
| 1:55–2:20 | Open `/results`. Show the three numbers and the two failure cards. | “In 77 held-out reports, ProveIt flagged five of eighteen slop reports and found code supporting twenty-two real bugs. It also wrongly flagged two real bugs. That's why it shows evidence and never closes a report.” |
| 2:20–2:35 | Return to the landing page. | “Nemotron Nano extracts the claims. Ultra checks them against the code. Both run on Nebius Token Factory, with Nebius Sandboxes for reproduction. ProveIt gives maintainers a concrete place to start.” |

## Optional live segment

Use **Check a report → Paste report text → Invented function**. Explain that this is a synthetic sample, then click
**Check the report**. Show the five progress steps, then the finding. This needs a curl clone and configured API keys.
A new run usually takes 15–60 seconds. Keep it separate from the saved examples so viewers know what actually ran.

## Keep the claims precise

- The current implementation supports curl; it is not yet a general repository integration.
- “Code supports the claim” means source analysis. Only a completed sandbox run is a reproduction.
- The displayed cost is model-call cost. Sandbox and search costs are separate.
- The 197-report collection includes development data. Evaluation numbers refer only to the 77 held-out reports.
- “Labeled AI slop” is the maintainer's label. ProveIt checks technical claims; it does not detect who wrote a report.
- A citation check verifies the evidence exists, not that the model's interpretation is correct.
