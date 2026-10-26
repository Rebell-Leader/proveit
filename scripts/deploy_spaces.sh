#!/usr/bin/env bash
# Deploy both Hugging Face Spaces from this checkout (needs `hf auth login` with a write token).
#   live:   avaliev/proveit-live  Gradio SDK on ZeroGPU; runs the FastAPI app (judge + live mode)
#   static: avaliev/proveit       static judge mode, pre-rendered, always on
# API keys are never uploaded: add NEBIUS_API_KEY and TAVILY_API_KEY as secrets in the live Space's settings.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
live_space="${LIVE_SPACE:-avaliev/proveit-live}"
static_space="${STATIC_SPACE:-avaliev/proveit}"
live_url="${LIVE_URL:-https://avaliev-proveit-live.hf.space}"
rev="$(git -C "$root" rev-parse --short HEAD)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/live/data"
cp -r "$root/LICENSE" "$root/src" "$root/deploy/hf-live/." "$work/live/"
cp -r "$root/data/demo" "$work/live/data/" && cp "$root/data/curl_reports.jsonl" "$root/data/curl_identifier_history.txt" "$work/live/data/"
find "$work/live" -name __pycache__ -type d -prune -exec rm -rf {} +
hf upload "$live_space" "$work/live" . --repo-type space --commit-message "Deploy Rebell-Leader/proveit@$rev"

(cd "$root" && uv run proveit build-site --out "$work/static" --live-url "$live_url")
cp "$root/deploy/hf-static/README.md" "$work/static/"
hf upload "$static_space" "$work/static" . --repo-type space --commit-message "Static judge mode from Rebell-Leader/proveit@$rev"
