# Feedback: Nebius Token Factory and NVIDIA Nemotron

Collected while building ProveIt (October 2026). Each item says what we did, what happened, and what would help.
Reproduction snippets assume the OpenAI Python SDK pointed at `https://api.tokenfactory.nebius.com/v1/`.

## What worked well

- **Strict JSON-schema output works on Nemotron 3 Nano and Ultra, with reasoning on.** Nested objects, arrays and
  enums came back parseable on every call we made. That made a multi-stage pipeline straightforward.
- **Price and latency fit triage work.** A full report triage (Nano extraction + Ultra judgment over ~8-10k tokens of
  real source code) costs about $0.015 and takes 5-20 seconds.
- **Ultra reads code well.** It found the exact bounds checks that disprove AI-slop reports and traced real
  connection-reuse bugs across three files, citing line numbers that our checker could verify.
- **Logprobs are available**, which closed APIs increasingly hide. Useful for calibration work.

## What needs work

1. **`reasoning_effort` is accepted but silently ignored on Nemotron.** `low`, `high` and unset produce identical
   token counts on both Nano and Ultra. What does work is `extra_body={"chat_template_kwargs": {"enable_thinking": False}}`
   (Ultra: 147 -> 2 output tokens on a yes/no question), but we found it by trial; the docs index has no page on
   reasoning control. Suggestion: document the switch per model, and either honor `reasoning_effort` or reject it.
   A reasoning budget (`reasoning_budget` in `chat_template_kwargs` or top level) also had no effect.
2. **Reasoning text comes back under different field names.** Nano returns `message.reasoning`, Ultra returns
   `message.reasoning_content`. Clients have to check both.
3. **Model IDs are inconsistent and differ from the pricing page names.** On one account:
   `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`, `nvidia/Nemotron-3-Ultra-550b-a55b`, `nvidia/nemotron-3-super-120b-a12b`,
   `nvidia/Nemotron-3_5-Lightning`, `nvidia/Nemotron-3.5-Super-VL`. Casing, the `NVIDIA-` prefix and `.` vs `_` vary,
   and the pricing page writes "Nemotron-3-Nano-30B-A3B". Our first call 404'd on the pricing-page name.
   Suggestion: one naming scheme, and accept the pricing-page names as aliases.
4. **A new account with no credits gets "You have exhausted your budget."** (HTTP 402, `credit_balance_exhausted`).
   For someone who has not spent anything yet, "no credits on this account; redeem a code or add funds at <link>"
   would save a support question. Promo credits from the hackathon form took a while to appear.
5. **Occasional empty or unparsable answers under strict JSON schema with long reasoning.** On an adversarial report
   (a prompt-injection attempt), Ultra once returned output that did not parse; the identical request succeeded on
   retry. We now retry once. A documented `finish_reason` when reasoning exhausts `max_tokens`, or a way to cap
   reasoning separately from the answer, would make this predictable.
6. **No reasoning budget.** Because thinking is all-or-nothing, cost per judgment varies 3x across reports
   (1.8k-9k output tokens). A `reasoning_budget` that works would let us price triage per report.
7. **Sandboxes are in beta behind an access request.** For a time-boxed hackathon, a self-serve tier (even small)
   would let more teams run generated code on Nebius instead of elsewhere.

## Would we build with it again?

Yes. Open Nemotron weights at these prices, with schema-constrained output and visible reasoning and logprobs, are a
good fit for verification tools that have to show their work. Fixing items 1 to 3 would remove most of the trial
and error we hit in the first hour.
