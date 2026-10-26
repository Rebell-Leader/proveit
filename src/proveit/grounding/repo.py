"""Read-only questions about a git repository at a given revision."""

from __future__ import annotations

import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path

from proveit import CACHE_DIR, DATA_DIR, VENDOR_DIR

CURL_URL = "https://github.com/curl/curl.git"
CURL_DIR = VENDOR_DIR / "curl"
SOURCE_DIRS = ("lib", "src", "include")
_IDENT_RE = r"[A-Za-z_][A-Za-z0-9_]{2,}"
_BANFUNC = re.compile(r'^\s*"([A-Za-z_][\w]*)"\s*=>\s*1', re.M)


def ensure_curl() -> Path:
    if not (CURL_DIR / ".git").exists():
        CURL_DIR.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "-q", CURL_URL, str(CURL_DIR)], check=True)
    return CURL_DIR


class Repo:
    def __init__(self, path: Path = CURL_DIR, main_branch: str = "origin/master"):
        self.path = Path(path)
        self.main = main_branch

    def _git(self, *args: str, check: bool = True) -> str:
        res = subprocess.run(["git", "-C", str(self.path), *args], capture_output=True, text=True, errors="replace")
        if check and res.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)}: {res.stderr.strip()}")
        return res.stdout

    @lru_cache(maxsize=4096)
    def resolve(self, rev: str) -> str | None:
        """Full commit SHA for a SHA, tag or branch name; None if unknown."""
        for candidate in (rev, f"origin/{rev}"):
            out = self._git("rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}", check=False).strip()
            if out:
                return out
        return None

    @lru_cache(maxsize=4096)
    def rev_at(self, iso_date: str) -> str | None:
        """Last commit on the main branch at or before a date (what master looked like that day)."""
        out = self._git("rev-list", "-1", "--first-parent", f"--before={iso_date}", self.main).strip()
        return out or None

    @lru_cache(maxsize=1)
    def release_tags(self) -> list[tuple[str, str]]:
        """(tag, iso date) for curl release tags, oldest first."""
        out = self._git("for-each-ref", "--sort=creatordate", "--format=%(refname:short) %(creatordate:iso-strict)", "refs/tags")
        tags = []
        for line in out.splitlines():
            name, _, date = line.partition(" ")
            if re.fullmatch(r"curl-\d+_\d+(_\d+)?", name):
                tags.append((name, date))
        return tags

    def tag_for_version(self, version: str) -> str | None:
        parts = version.split(".")
        names = ["curl-" + "_".join(parts)]
        if len(parts) == 2:
            names.append("curl-" + "_".join(parts + ["0"]))
        known = {t for t, _ in self.release_tags()}
        return next((n for n in names if n in known), None)

    def latest_release_before(self, iso_date: str) -> str | None:
        prior = [t for t, d in self.release_tags() if d <= iso_date]
        return prior[-1] if prior else None

    @lru_cache(maxsize=64)
    def files(self, rev: str) -> frozenset[str]:
        return frozenset(self._git("ls-tree", "-r", "--name-only", rev).splitlines())

    @lru_cache(maxsize=512)
    def read(self, rev: str, path: str) -> str | None:
        res = subprocess.run(
            ["git", "-C", str(self.path), "show", f"{rev}:{path}"], capture_output=True, text=True, errors="replace"
        )
        return res.stdout if res.returncode == 0 else None

    def same_basename(self, rev: str, path: str) -> list[str]:
        base = path.rsplit("/", 1)[-1]
        return sorted(p for p in self.files(rev) if p.rsplit("/", 1)[-1] == base)

    @lru_cache(maxsize=1024)
    def path_ever_existed(self, path: str) -> bool:
        return bool(self._git("log", "--all", "-1", "--format=%H", "--", path, check=False).strip())

    @lru_cache(maxsize=24)  # each holds ~30k names; kept small for 512 MB hosts
    def identifiers(self, rev: str) -> frozenset[str]:
        """Every identifier-looking token in curl's source dirs at a revision (cached on disk)."""
        cache = CACHE_DIR / "idents" / f"{rev}.txt"
        if cache.exists():
            return frozenset(cache.read_text().split())
        out = self._git("grep", "-h", "-o", "-w", "-E", _IDENT_RE, rev, "--", *SOURCE_DIRS, check=False)
        idents = frozenset(out.split())
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text("\n".join(sorted(idents)))
        return idents

    @lru_cache(maxsize=1)
    def identifier_history(self) -> frozenset[str]:
        """Union of identifiers across all release tags since 7.50: has this name ever existed in curl?

        Deployments ship it as data/curl_identifier_history.txt (`proveit export-history`) so a cold start does not
        grep 150 release tags.
        """
        shipped = DATA_DIR / "curl_identifier_history.txt"
        if shipped.exists():
            return frozenset(shipped.read_text().split())
        tags = [t for t, _ in self.release_tags() if _version_tuple(t) >= (7, 50, 0)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            sets = list(pool.map(lambda t: self.identifiers(self.resolve(t)), tags))
        return frozenset().union(*sets)

    def grep_word(self, rev: str, word: str, paths: tuple[str, ...] = SOURCE_DIRS) -> list[tuple[str, int, str]]:
        out = self._git("grep", "-n", "-w", "-F", "-e", word, rev, "--", *paths, check=False)
        return _parse_grep(out)

    def grep_fixed(self, rev: str, needle: str, paths: tuple[str, ...] = SOURCE_DIRS) -> list[tuple[str, int, str]]:
        out = self._git("grep", "-n", "-F", "-e", needle, rev, "--", *paths, check=False)
        return _parse_grep(out)

    @lru_cache(maxsize=256)
    def _banned(self, rev: str) -> tuple[frozenset[str], re.Pattern | None]:
        src = self.read(rev, "scripts/checksrc.pl") or self.read(rev, "lib/checksrc.pl") or ""
        names = frozenset(_BANFUNC.findall(src.split("%banfunc", 1)[1].split(");", 1)[0])) if "%banfunc" in src else frozenset()
        # Before Dec 2025 the list was a Perl /x regex: if($l =~ /^(.*\W)(gets|strtok|v?sprintf|...)\s*\(/x)
        m = re.search(r"banned functions\s*\n\s*if\(\$l =~ /\^\(\.\*\\W\)(.*?)\\s\*\\\(", src, re.S)
        pattern = re.compile("".join(m.group(1).split())) if m else None
        return names, pattern

    @lru_cache(maxsize=256)
    def dev_version(self, rev: str) -> str | None:
        """LIBCURL_VERSION from curlver.h at a revision, e.g. "8.23.0-DEV" on master."""
        m = re.search(r'#define LIBCURL_VERSION "([\d.]+)', self.read(rev, "include/curl/curlver.h") or "")
        return m.group(1) if m else None

    @lru_cache(maxsize=256)
    def security_policy(self, rev: str) -> str | None:
        """The "Not security issues" section of curl's disclosure policy at a revision, if it has one."""
        text = self.read(rev, "docs/VULN-DISCLOSURE-POLICY.md") or ""
        start = text.find("\n# Not security issues")
        if start < 0:
            return None
        end = text.find("\n# ", start + 5)
        return text[start + 1 : end if end > 0 else None].strip()[:12_000]

    def is_banned(self, rev: str, func: str) -> bool:
        """Does curl's own source checker (checksrc.pl) refuse this function at this revision?"""
        names, pattern = self._banned(rev)
        return func in names or bool(pattern and pattern.fullmatch(func))


def _parse_grep(out: str) -> list[tuple[str, int, str]]:
    """Parse `git grep -n <rev>` output lines of the form <rev>:<path>:<line>:<text>."""
    hits = []
    for line in out.split("\n"):
        parts = line.split(":", 3)
        if len(parts) == 4 and parts[2].isdigit():
            hits.append((parts[1], int(parts[2]), parts[3]))
    return hits


def _version_tuple(tag: str) -> tuple[int, ...]:
    return tuple(int(x) for x in tag.removeprefix("curl-").split("_"))
