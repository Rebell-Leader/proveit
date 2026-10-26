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
                use_cache=False,
            )
            print(f"{model}: {c.data} ({c.prompt_tokens}+{c.completion_tokens} tokens, {c.seconds:.1f}s)")
        except Exception as e:  # report every model, keep going
            if getattr(e, "status_code", None) == 402:
                print(f"{model}: no credits on this account. Redeem a Token Factory promo code or add funds, then retry.")
            elif getattr(e, "status_code", None) == 404:
                print(f"{model}: not found. Set PROVEIT_MODEL_FAST / PROVEIT_MODEL_DEEP in .env to an ID listed above.")
            else:
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


def cmd_triage(args: argparse.Namespace) -> int:
    from proveit import dataset, tf
    from proveit.judge.pipeline import describe, triage

    rows = {r["h1_id"]: r for r in dataset.load()}
    row = rows.get(args.h1_id)
    if not row:
        print(f"report {args.h1_id} is not in the dataset (or not public)", file=sys.stderr)
        return 1
    result = triage(row["input"], thinking=not args.no_thinking)
    print(json.dumps(result, indent=2) if args.json else describe(result))
    print(f"\n[label, never shown to the models: {row['label']}]\nSpend this run: {tf.SPEND}", file=sys.stderr)
    return 0


def cmd_adversarial(args: argparse.Namespace) -> int:
    from proveit import ROOT, tf
    from proveit.judge.pipeline import triage

    cases = json.loads((ROOT / "tests" / "fixtures" / "adversarial.json").read_text())["cases"]
    passed = 0
    for case in cases:
        res = triage({k: case[k] for k in ("title", "body", "submitted_at")})
        ok = res["final"] in case["expect"]
        passed += ok
        why = res["receipts_override"] or "; ".join(res["judgment"].get("key_reasons", [])[:1])
        print(f"{'PASS' if ok else 'FAIL'} {case['name']:26} final={res['final']:17} expected {'/'.join(case['expect'])}")
        print(f"     {why[:200]}")
    print(f"\n{passed}/{len(cases)} adversarial cases handled as expected. Spend: {tf.SPEND}")
    return 0 if passed == len(cases) else 1


def cmd_triage_eval(args: argparse.Namespace) -> int:
    from proveit.judge import evaluate

    evaluate.run(split=args.split, per_label=args.per_label, thinking=not args.no_thinking, name=args.name, workers=args.workers)
    return 0


def cmd_export_demo(_: argparse.Namespace) -> int:
    from proveit.web.demo import export

    print(json.dumps(export(), indent=2))
    return 0


def cmd_build_site(args: argparse.Namespace) -> int:
    from pathlib import Path

    from proveit.web.static_site import build

    print(json.dumps(build(Path(args.out), args.live_url), indent=2))
    return 0


def cmd_export_history(_: argparse.Namespace) -> int:
    from proveit import DATA_DIR
    from proveit.grounding.repo import Repo

    path = DATA_DIR / "curl_identifier_history.txt"
    names = sorted(Repo().identifier_history())
    path.write_text("\n".join(names) + "\n")
    print(f"{len(names)} identifiers -> {path}")
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
    t = sub.add_parser("triage", help="full triage of one report: grounding, Nano claims, evidence, Ultra judgment")
    t.add_argument("h1_id", type=int)
    t.add_argument("--json", action="store_true")
    t.add_argument("--no-thinking", action="store_true", help="run the judge with reasoning off")
    t.set_defaults(fn=cmd_triage)
    sub.add_parser("adversarial", help="run the adversarial fixture reports through the full pipeline").set_defaults(fn=cmd_adversarial)
    te = sub.add_parser("triage-eval", help="run the full triage over a split and score it")
    te.add_argument("--split", choices=["dev", "test", "all"], default="dev")
    te.add_argument("--per-label", type=int, default=None, help="at most N slop and N valid reports (deterministic sample)")
    te.add_argument("--no-thinking", action="store_true")
    te.add_argument("--name", default=None, help="run name under runs/triage/")
    te.add_argument("--workers", type=int, default=6)
    te.set_defaults(fn=cmd_triage_eval)
    sub.add_parser("export-demo", help="write judge-mode data for the web app to data/demo/").set_defaults(fn=cmd_export_demo)
    bs = sub.add_parser("build-site", help="pre-render judge mode to static HTML")
    bs.add_argument("--out", default="site")
    bs.add_argument("--live-url", default=None, help="base URL of the live server, e.g. https://proveit.onrender.com")
    bs.set_defaults(fn=cmd_build_site)
    sub.add_parser("export-history", help="write curl's cross-release identifier index for deployments").set_defaults(fn=cmd_export_history)
    e = sub.add_parser("eval", help="run the grounding checker over the dataset")
    e.add_argument("--out", default="runs/grounding")
    e.set_defaults(fn=cmd_eval)
    args = p.parse_args()
    sys.exit(args.fn(args))
