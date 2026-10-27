# Architecture and operations

The web app is FastAPI with Jinja templates and plain JavaScript. Saved analyses need no model calls. The same templates
render live results and the static Hugging Face demo.

## Analysis stages

| Stage | Implementation | Output |
|---|---|---|
| Reference checks | `src/proveit/grounding/` | Files, lines, symbols, commits and quoted code checked at the report's targeted revision |
| Claim extraction | Nemotron 3 Nano, reasoning off | Checkable claims about the flaw, trigger and impact |
| Evidence gathering | git + Tavily | Line-numbered source, release/master differences, and relevant documentation |
| Judgment | Nemotron 3 Ultra, reasoning on | Per-claim assessments, citations, verdict and draft reply |
| Citation checks | Deterministic code | Discard unsupported citations; withdraw judgments that lose required evidence |
| Optional reproduction | Nebius Sandboxes | Compile against the targeted curl release with sanitizers and run offline |

Models run on Nebius Token Factory. Reproduction uses CMake; curl's autotools build does not work in this sandbox.
Cached build checkpoints reduce repeat build time. Report code never executes on the host. The web live endpoint
runs source analysis only; reproduction is a separate CLI operation.

Display summaries of selected saved examples live in `src/proveit/web/presentation.py`. They are not model inputs and
are not used to score reports. Original claims, reasoning, source, and sandbox output remain inspectable.

## Commands

```bash
uv run proveit ground 2887487             # reference checks only
uv run proveit triage 2887487             # reference checks + models + citation verification
uv run proveit reproduce 4024222          # offline sandbox reproduction
uv run proveit triage 4024222 --reproduce # analysis plus reproduction
uv run proveit eval                      # reference-check evaluation
uv run proveit triage-eval --split dev    # full pipeline on development data
uv run proveit adversarial               # adversarial reports through the pipeline
uv run proveit export-demo               # export saved views from local runs
uv run proveit build-site              # render the static site into site/
uv run pytest
```

See `uv run proveit --help` and `.env.example` for configuration. `export-demo` reads gitignored run artifacts and may
attempt featured sandbox reproduction when sandbox access is configured; it is not needed to serve the checked-in demo.

## Hosting

- Saved demo: a static Hugging Face Space. Rebuild and upload with `scripts/deploy_static.sh`.
- Live checker: the Dockerfile on Render (`render.yaml`). The free service may need about a minute to wake after inactivity.
- Neither web host needs a GPU; model inference runs on Token Factory.

The live endpoint limits request size, concurrent runs, daily spend and runs per visitor. A worst-case model-call cost
is reserved before a new run is admitted and settled when it finishes. Existing saved reports bypass model calls.
