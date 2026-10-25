#!/usr/bin/env bash
# Run a task file headlessly with Codex or agy and save the final answer under reviews/.
# Usage: scripts/agent.sh <codex|agy> tasks/NNN-name.md [extra instructions] [context file]
# A context file is pasted into the prompt. Use it for agy, whose headless mode cannot run shell commands.
set -euo pipefail

agent="${1:?agent: codex or agy}"
task="${2:?path to task file}"
extra="${3:-}"
root="$(git rev-parse --show-toplevel)"
name="$(basename "$task" .md)"
out="$root/reviews/${name}-${agent}.md"

context="${4:-}"
prompt="Read AGENTS.md, then do the task in $task. ${extra}
Write your final answer as Markdown. Every finding needs a file:line, a concrete failure scenario and a severity."
if [[ -n "$context" ]]; then
  prompt="$prompt

The data you need is below; you do not need to run any commands.

$(cat "$context")"
fi

case "$agent" in
  codex)
    codex exec -C "$root" -s read-only -o "$out" "$prompt" ;;
  agy)
    # --sandbox restricts the terminal; JSON output lets us keep only the final answer, not the process narration.
    (cd "$root" && agy -p "$prompt This is a headless run: nobody can approve a plan, so do the task now and do not edit files." \
      --sandbox --output-format json) | jq -r '.response' > "$out" ;;
  *)
    echo "unknown agent: $agent" >&2; exit 2 ;;
esac

echo "wrote $out"
