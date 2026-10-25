# Tasks

One file per task: `NNN-short-name.md`. Copy the template below.

```markdown
---
owner: codex | agy | claude
status: todo | doing | review | done
worktree: none | agent/<agent>/<task>
---

# NNN — Title

## Goal
What should be true when this is done, in one or two sentences.

## Context
Files to read first. What has been ruled out already.

## Acceptance criteria
- [ ] Checkable statements only.

## Output
Where results go (a file in `reviews/`, a branch, a JSON file).
```

Run a task headlessly with `scripts/agent.sh <codex|agy> tasks/NNN-short-name.md`.
