"""Retrieve the real curl code a report talks about, line-numbered, within a size budget.

The judge sees only these snippets, and its citations are checked against them afterwards, so it cannot
point at lines it was never shown.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from proveit.grounding.repo import SOURCE_DIRS, Repo

MAX_FUNCTION_LINES = 160
WINDOW = 25


@dataclass
class Snippet:
    path: str
    start: int  # 1-based, inclusive
    end: int  # inclusive
    reason: str
    lines: list[str]
    rev: str = ""  # revision the lines were read from
    label: str = ""  # how the judge must cite it, e.g. "lib/ws.c@curl-8_21_0"; defaults to path
    symbol: str = ""  # the function or macro this is the definition of, if any

    @property
    def name(self) -> str:
        return self.label or self.path

    def covers(self, path: str, line: int) -> bool:
        return path == self.name and self.start <= line <= self.end

    def render(self) -> str:
        body = "\n".join(f"{self.start + i:5d} | {text}" for i, text in enumerate(self.lines))
        return f"### {self.name} lines {self.start}-{self.end} ({self.reason})\n{body}"

    @property
    def size(self) -> int:
        return sum(len(l) + 8 for l in self.lines)


def find_definition(repo: Repo, rev: str, name: str) -> Snippet | None:
    """The body of a C function or macro named `name` at `rev`, if curl defines one."""
    pattern = rf"^([A-Za-z_][A-Za-z0-9_ \*]*[ \*])?{re.escape(name)}\s*\(|^#\s*define\s+{re.escape(name)}\b"
    out = repo._git("grep", "-n", "-E", pattern, rev, "--", *SOURCE_DIRS, check=False)
    candidates = []
    for line in out.split("\n"):
        parts = line.split(":", 3)
        if len(parts) != 4 or not parts[2].isdigit():
            continue
        path, num, text = parts[1], int(parts[2]), parts[3]
        if text.rstrip().endswith(";"):
            continue  # a prototype, not the definition
        # Prefer libcurl (lib/) over the curl tool (src/), then .c definitions over headers.
        candidates.append((not path.startswith("lib/"), not path.endswith(".c"), path, num, text))
    if not candidates:
        return None
    _, _, path, num, text = min(candidates)
    lines = (repo.read(rev, path) or "").splitlines()
    start = num
    if text.lstrip().startswith("#"):
        end = num
        while end < len(lines) and lines[end - 1].rstrip().endswith("\\"):
            end += 1
        return Snippet(path, start, end, f"definition of {name}", lines[start - 1 : end], rev=rev, symbol=name)
    # curl style may put the return type on the line above the name.
    prev = lines[num - 2].strip() if num >= 2 else ""
    if text.startswith(name) and prev and not prev.endswith((";", "}", "*/")) and not prev.startswith("#"):
        start = num - 1
    end = start
    opened = False
    while end < len(lines) and end - start < MAX_FUNCTION_LINES:
        cur = lines[end - 1]
        opened = opened or cur.startswith("{") or cur.rstrip().endswith("{")
        if opened and cur.startswith("}"):
            break
        end += 1
    reason = f"definition of {name}" + (" (truncated)" if end - start >= MAX_FUNCTION_LINES else "")
    return Snippet(path, start, end, reason, lines[start - 1 : end], rev=rev, symbol=name)


def window(repo: Repo, rev: str, path: str, start: int, end: int, reason: str) -> Snippet | None:
    lines = (repo.read(rev, path) or "").splitlines()
    if not lines or start > len(lines):
        return None
    lo, hi = max(1, start - WINDOW), min(len(lines), end + WINDOW)
    return Snippet(path, lo, hi, reason, lines[lo - 1 : hi], rev=rev)


def _merge(repo: Repo, rev: str, snippets: list[Snippet]) -> list[Snippet]:
    """Union overlapping or touching snippets of the same file, keeping the position of the first one."""
    kept: list[Snippet] = []
    for s in snippets:
        hit = next((k for k in kept if k.name == s.name and k.rev == s.rev and s.start <= k.end + 1 and k.start <= s.end + 1), None)
        if not hit:
            kept.append(s)
            continue
        if hit.start <= s.start and s.end <= hit.end:
            continue
        lines = (repo.read(s.rev or rev, s.path) or "").splitlines()
        hit.start, hit.end = min(hit.start, s.start), max(hit.end, s.end)
        hit.lines = lines[hit.start - 1 : hit.end]
        hit.reason = f"{hit.reason}; {s.reason}"
    return kept


def release_version(repo: Repo, rev: str, master_snippet: Snippet, release: tuple[str, str]) -> Snippet | None:
    """The same function as of the latest release, if it differs from master: reporters often read the release."""
    sha, tag = release
    alt = find_definition(repo, sha, master_snippet.symbol)
    if not alt or [l.strip() for l in alt.lines] == [l.strip() for l in master_snippet.lines]:
        return None
    # Commits that touched this function between the release and master (git log -L follows the function body).
    out = repo._git("log", "-s", "--format=%h %s", f"{sha}..{rev}", "-L", f":{master_snippet.symbol}:{master_snippet.path}", check=False)
    commits = [c for c in out.split("\n") if c.strip()][:3]
    alt.label = f"{alt.path}@{tag}"
    alt.reason = (f"definition of {alt.symbol} as in release {tag}; differs from master"
                  + (f"; commits that changed it since: " + " | ".join(commits) if commits else ""))
    return alt


def gather(repo: Repo, rev: str, grounding: dict, names: list[str], title: str, budget_chars: int = 90_000,
           release: tuple[str, str] | None = None) -> list[Snippet]:
    """Code for the report's claims, most relevant first: names in the title, names the claims depend on,
    lines the report cites, then any other curl symbol it mentions. With `release` (sha, tag), functions that
    changed since that release are also shown as they were in it."""
    known = set(grounding.get("symbols", []))
    ordered: list[str] = []
    for name in [n for n in known if n in title] + [n for n in names if n in known or n in repo.identifiers(rev)] + sorted(known):
        if name not in ordered:
            ordered.append(name)

    candidates: list[Snippet] = []
    for path, start, end in grounding.get("lines", []):
        s = window(repo, rev, path, start, end, f"lines {start}-{end} cited by the report")
        if s:
            candidates.append(s)
    for name in ordered:
        s = find_definition(repo, rev, name)
        if s:
            candidates.append(s)
    # Cited lines go first only if the title names nothing.
    if ordered and grounding.get("lines"):
        n_lines = len(grounding["lines"])
        defs = candidates[n_lines:]
        title_defs = [s for s in defs if any(s.reason == f"definition of {n}" for n in ordered if n in title)]
        candidates = title_defs + candidates[:n_lines] + [s for s in defs if s not in title_defs]

    if release and release[0] != rev:
        with_release = []
        for s in candidates:
            with_release.append(s)
            if s.symbol:
                alt = release_version(repo, rev, s, release)
                if alt:
                    with_release.append(alt)
        candidates = with_release

    picked, used = [], 0
    for s in _merge(repo, rev, candidates):
        if used + s.size > budget_chars:
            continue
        picked.append(s)
        used += s.size
    return picked


def render(snippets: list[Snippet]) -> str:
    return "\n\n".join(s.render() for s in snippets) if snippets else "(no curl code could be retrieved for this report)"
