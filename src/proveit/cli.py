"""Command line entry point: `uv run proveit <command>`."""

from __future__ import annotations

import argparse
import json
import sys


def cmd_smoke(_: argparse.Namespace) -> int:
    from proveit import tf

    models = tf.list_models()
    nemotron = [m for m in models if "nemotron" in m.lower()]
    print(f"Token Factory reachable: {len(models)} models, {len(nemotron)} Nemotron:")
    for m in nemotron:
        print("  ", m)
    schema = {
        "type": "object",
        "properties": {"answer": {"type": "string"}, "confident": {"type": "boolean"}},
        "required": ["answer", "confident"],
        "additionalProperties": False,
    }
    for model in (tf.model_fast(), tf.model_deep()):
        try:
            c = tf.chat_json(
                [{"role": "user", "content": "Does curl's lib/ directory contain C or Rust? Answer in one word."}],
                schema,
                model=model,
                max_tokens=512,
            )
            print(f"{model}: {c.data} ({c.prompt_tokens}+{c.completion_tokens} tokens, {c.seconds:.1f}s)")
        except Exception as e:  # report every model, keep going
            print(f"{model}: FAILED {type(e).__name__}: {e}")
    return 0


def cmd_dataset(args: argparse.Namespace) -> int:
    from proveit import dataset

    print(json.dumps(dataset.build(limit=args.limit), indent=2))
    return 0


def cmd_fetch_repo(_: argparse.Namespace) -> int:
    from proveit.grounding import repo

    path = repo.ensure_curl()
    print(f"curl checkout ready at {path}")
    return 0


def cmd_ground(args: argparse.Namespace) -> int:
    from proveit import dataset
    from proveit.grounding import check

    rows = {r["h1_id"]: r for r in dataset.load()}
    row = rows.get(args.h1_id)
    if not row:
        print(f"report {args.h1_id} is not in the dataset (or not public)", file=sys.stderr)
        return 1
    result = check.ground_report(row["input"])
    print(json.dumps(result.to_dict(), indent=2))
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from proveit.grounding import evaluate

    evaluate.run(out_dir=args.out)
    return 0


def main() -> None:
    p = argparse.ArgumentParser(prog="proveit")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("smoke", help="check the Token Factory key and Nemotron models").set_defaults(fn=cmd_smoke)
    d = sub.add_parser("dataset", help="fetch and label the curl reports")
    d.add_argument("--limit", type=int, default=None)
    d.set_defaults(fn=cmd_dataset)
    sub.add_parser("fetch-repo", help="clone curl with full history into vendor/").set_defaults(fn=cmd_fetch_repo)
    g = sub.add_parser("ground", help="grounding report for one HackerOne report")
    g.add_argument("h1_id", type=int)
    g.set_defaults(fn=cmd_ground)
    e = sub.add_parser("eval", help="run the grounding checker over the dataset")
    e.add_argument("--out", default="runs/grounding")
    e.set_defaults(fn=cmd_eval)
    args = p.parse_args()
    sys.exit(args.fn(args))
