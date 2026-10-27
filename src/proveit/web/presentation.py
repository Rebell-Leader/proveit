"""Display copy for saved examples. Never used by the triage pipeline or evaluation."""

from __future__ import annotations

from proveit.web.view import VERDICTS

# Editorial summaries of three recorded runs, with links into their saved evidence.
# These describe the output; they are never passed to a model.
EXAMPLES = {
    2887487: {
        "kicker": "The false alarm",
        "headline": "The report missed a size check.",
        "claim": "The report claims an unchecked copy can overflow a buffer.",
        "finding": "The real function checks the size and returns before the copy if the buffer is too small.",
        "file": "lib/inet_ntop.c", "line": 76, "start": 75, "end": 81,
        "next": 4024222, "next_label": "Next: a bug that really crashes curl",
    },
    4024222: {
        "kicker": "The real bug",
        "headline": "This one really crashes curl.",
        "claim": "The report says deeply nested MIME data can crash curl during cleanup.",
        "finding": "ProveIt found the recursive cleanup path. A separate offline run in a Nebius sandbox caught a stack overflow inside curl.",
        "file": "lib/mime.c", "line": 1122, "start": 1113, "end": 1127,
        "next": 3506159, "next_label": "Next: when the AI gets it wrong",
    },
    3506159: {
        "kicker": "The AI's own mistake",
        "headline": "The AI believed a made-up quote.",
        "claim": "The report relies on a claim about how nghttp2 handles HTTP headers.",
        "finding": "The model accepted a documentation quote that the fetched source did not contain. The citation check withdrew its judgment and asked for human review.",
        "next": None, "next_label": "See the full evaluation",
    },
}


def present_report(view: dict) -> dict:
    """Refresh display labels without changing stored results or model output."""
    out = dict(view)
    label, tone, explain = VERDICTS.get(view.get("final"), VERDICTS["error"])
    out.update(final_label=label, tone=tone, explain=explain)
    example = EXAMPLES.get(view.get("id"))
    if example:
        spotlight = dict(example)
        spotlight["rows"] = [
            row for snippet in view.get("code", []) if snippet["name"] == example.get("file")
            for row in snippet["rows"]
            if example.get("start", 0) <= row["n"] <= example.get("end", 0)
        ]
        out["spotlight"] = spotlight
    reproduction = view.get("reproduction")
    if reproduction and reproduction.get("attempted"):
        out["reproduction"] = dict(reproduction)
        out["reproduction"]["signature"] = next(
            (line for line in reproduction.get("stderr", "").splitlines() if line.startswith("SUMMARY:")), ""
        )
    return out
