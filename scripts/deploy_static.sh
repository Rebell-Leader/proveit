#!/usr/bin/env bash
# Deploy the static judge mode to its Hugging Face Space (needs `hf auth login` with a write token).
# Live mode is the Docker image on Render (render.yaml); its "Open live mode" button points at LIVE_URL.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
space="${STATIC_SPACE:-avaliev/proveit}"
live_url="${LIVE_URL:-https://proveit-live.onrender.com}"
rev="$(git -C "$root" rev-parse --short HEAD)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(cd "$root" && uv run proveit build-site --out "$work/site" --live-url "$live_url")
cp "$root/deploy/hf-static/README.md" "$work/site/"
hf upload "$space" "$work/site" . --repo-type space --commit-message "Static judge mode from Rebell-Leader/proveit@$rev"
