"""Grounding checks: does what a report cites exist in curl at the revision the report targets?

Each check emits a Finding with a status and evidence. The checks only decide existence questions
(is this file, line, symbol, commit, quote or version real?). Whether a flaw in real code is
exploitable is left to the model and sandbox stages.

Severity reflects how much a miss says about the report, not about the reporter's typing:
- strong: something presented as curl's (a curl-namespaced API, a curl source path, a quote of curl's
  code, an explicit file:line) does not exist.
- medium: a weaker reference does not check out (a non-namespaced call, a commit, a "line N" nearby).
- info: context only; never moves the verdict.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from functools import lru_cache

from proveit import CACHE_DIR
from proveit.grounding.extract import Extracted, extract
from proveit.grounding.repo import Repo

STRONG, MEDIUM, INFO = "strong", "medium", "info"

# C library, POSIX and Windows functions: real, but not curl's own code.
KNOWN_EXTERNAL = set(
    """
    strcpy strncpy strcat strncat strlen strnlen strcmp strncmp strcasecmp strncasecmp strchr strrchr strstr strtok
    strtok_r strdup strndup strerror strtol strtoul strtoll strtoull strtod atoi atol atoll sprintf snprintf vsprintf
    vsnprintf printf fprintf vprintf vfprintf sscanf scanf fscanf gets fgets puts fputs memcpy memmove memset memcmp
    memchr malloc calloc realloc free alloca fopen fclose fread fwrite fseek ftell fflush open close read write lseek
    stat fstat lstat unlink rename mkdir rmdir getenv setenv socket connect bind listen accept send recv sendto recvfrom
    select poll getaddrinfo freeaddrinfo gethostbyname inet_ntop inet_pton htons htonl ntohs ntohl exit abort assert
    time gettimeofday sleep usleep fork execve system popen pclose signal sigaction pthread_create pthread_mutex_lock
    pthread_mutex_unlock qsort bsearch rand srand isalpha isdigit isspace isalnum toupper tolower wcscpy wcslen
    """.split()
)
DANGEROUS_CALLS = {"strcpy", "strcat", "sprintf", "vsprintf", "gets", "strncpy", "strncat", "memcpy", "memmove", "sscanf", "alloca"}
# Public API names: if one of these does not exist, the report invented it.
CURL_API = re.compile(
    r"^(curl_|Curl_|curlx_|CURL(OPT|E|INFO|M|MOPT|SHOPT|SHE|U|UE|UPART|PROTO|AUTH|SSLOPT|PAUSE|WS|HE|H|FOLLOW|"
    r"SSLBACKEND|GSSAPI|USESSL|FTPSSL|KHSTAT|KHMATCH|KHTYPE|SOCKET|POLL|CSELECT|PX|HSTS|ALTSVC|MIMEOPT|OPTTYPE)_)"
)
THIRD_PARTY_PREFIX = re.compile(
    r"^(ngtcp2_|nghttp2_|nghttp3_|SSL_|OSSL_|EVP_|BIO_|X509_|ERR_|wolfSSL_|mbedtls_|gnutls_|libssh2_|ssh_|"
    r"inflate|deflate|BrotliDecoder|ZSTD_|idn2_|psl_|ares_|quiche_|gss_|krb5_|ldap_)"
)
CURL_SOURCE_DIRS = ("lib/", "src/", "include/")


@dataclass
class Finding:
    check: str  # file | line | symbol | commit | quote | version | permalink | cve
    status: str  # grounded | ungrounded | external | unverifiable
    severity: str  # strong | medium | info (only meaningful when ungrounded)
    claim: str
    evidence: str


@dataclass
class GroundingResult:
    rev: str | None
    rev_source: str
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    cited: list[str] = field(default_factory=list)  # curl source files the report cites, resolved
    symbols: list[str] = field(default_factory=list)  # curl symbols the report names that exist
    lines: list[tuple[str, int, int]] = field(default_factory=list)  # (path, start, end) line refs that exist

    @property
    def counts(self) -> dict[str, int]:
        c = {"grounded": 0, "ungrounded_strong": 0, "ungrounded_medium": 0}
        for f in self.findings:
            if f.status == "grounded" and f.check != "cve":
                c["grounded"] += 1
            elif f.status == "ungrounded" and f.severity in (STRONG, MEDIUM):
                c[f"ungrounded_{f.severity}"] += 1
        return c

    def to_dict(self) -> dict:
        return {"rev": self.rev, "rev_source": self.rev_source, "verdict": self.verdict, "counts": self.counts,
                "cited": self.cited, "symbols": self.symbols, "lines": self.lines,
                "findings": [asdict(f) for f in self.findings]}


@lru_cache(maxsize=1)
def curl_cves() -> frozenset[str]:
    path = CACHE_DIR / "vuln.json"
    if not path.exists():
        import httpx

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(httpx.get("https://curl.se/docs/vuln.json", timeout=30).text)
    return frozenset(a for v in json.loads(path.read_text()) for a in v.get("aliases", []))


def _norm(line: str) -> str:
    return " ".join(line.split())


def _substantive(line: str) -> bool:
    n = _norm(line)
    if len(n) < 12 or "..." in n or "…" in n or n.startswith(("//", "/*", "*", "#include")):
        return False
    return n not in {"{", "}", "};"}


def _ver_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def _pick_rev(repo: Repo, ex: Extracted, submitted_at: str) -> tuple[str | None, str]:
    for ref in ex.files:
        # Commit and release-tag permalinks pin a revision; branch names like "master" do not (they move).
        if ref.rev and (re.fullmatch(r"[0-9a-fA-F]{7,40}", ref.rev) or re.fullmatch(r"curl-\d+_\d+(_\d+)?", ref.rev)):
            sha = repo.resolve(ref.rev)
            if sha:
                return sha, f"permalink {ref.rev[:12]}"
    for h in ex.tested_commits:
        sha = repo.resolve(h)
        if sha:
            return sha, f"tested commit {h[:12]}"
    sha = repo.rev_at(submitted_at)
    return sha, f"master on {submitted_at[:10]}"


def _alt_revs(repo: Repo, ex: Extracted, rev: str, submitted_at: str) -> list[tuple[str, str]]:
    """Other revisions a report may legitimately describe: releases it names, and the latest release before it."""
    tags = [t for t in (repo.tag_for_version(v) for v in ex.versions) if t][:3]
    latest = repo.latest_release_before(submitted_at)
    if latest and latest not in tags:
        tags.append(latest)
    out = []
    for t in tags:
        sha = repo.resolve(t)
        if sha and sha != rev:
            out.append((sha, t))
    return out

def _check_files(repo: Repo, ex: Extracted, rev: str, alts: list[tuple[str, str]], findings: list[Finding],
                 idents_at_rev: frozenset[str]) -> list[str]:
    """File, permalink and line checks. Returns the curl paths the report cites (resolved)."""
    cited: list[str] = []
    for ref in ex.files:
        ref_rev, ref_label = rev, rev[:12]
        if ref.rev:
            sha = repo.resolve(ref.rev)
            if sha is None:
                hexlike = re.fullmatch(r"[0-9a-fA-F]{7,40}", ref.rev)
                findings.append(Finding("permalink", "ungrounded", STRONG if hexlike else MEDIUM,
                                        f"github.com/curl/curl/blob/{ref.rev}/{ref.path}",
                                        f"revision {ref.rev} does not exist in curl's history"))
                continue
            ref_rev, ref_label = sha, sha[:12]
        path = ref.path
        curl_path = (path.startswith(CURL_SOURCE_DIRS) or ref.source == "github") and not ref.reporter
        if path not in repo.files(ref_rev):
            matches = [m for m in repo.same_basename(ref_rev, path) if m.startswith(CURL_SOURCE_DIRS)]
            in_alt = next(((a, t) for a, t in alts if path in repo.files(a)), None) if not ref.rev else None
            if matches and "/" not in path and not ref.reporter:
                path = matches[0]  # a bare "http.c" means lib/http.c
            elif in_alt:
                ref_rev, ref_label = in_alt
                findings.append(Finding("file", "grounded", INFO, ref.path, f"{path} exists at {ref_label}, a release the report names or follows"))
            elif not curl_path:
                findings.append(Finding("file", "unverifiable", INFO, ref.path, f"{ref.path} is not a curl source file (the reporter's own, by the report's wording or name)"))
                continue
            elif ref.external:
                findings.append(Finding("file", "unverifiable", INFO, ref.path, f"{ref.path} is not in curl; the sentence is about a dependency"))
                continue
            elif matches:
                findings.append(Finding("file", "ungrounded", MEDIUM, ref.path,
                                        f"no {ref.path} at {ref_label}; a file with that name exists at {', '.join(matches[:3])}"))
                path = matches[0]
            elif repo.path_ever_existed(path):
                findings.append(Finding("file", "ungrounded", MEDIUM, ref.path,
                                        f"{ref.path} existed in curl's history but not at {ref_label}"))
                continue
            else:
                findings.append(Finding("file", "ungrounded", STRONG, ref.path, f"no file named {ref.path} has ever existed in curl"))
                continue
        else:
            findings.append(Finding("file", "grounded", INFO, ref.path, f"{path} exists at {ref_label}"))
        if path not in cited:
            cited.append(path)

        if ref.line_start:
            claim = f"{path}:{ref.line_start}" + (f"-{ref.line_end}" if ref.line_end else "")
            last_line = max(ref.line_start, ref.line_end or 0)
            lines = (repo.read(ref_rev, path) or "").splitlines()
            if last_line > len(lines) and not ref.rev:
                # The report may describe a release it names rather than master.
                for a, t in alts:
                    alt_lines = (repo.read(a, path) or "").splitlines()
                    if last_line <= len(alt_lines):
                        ref_rev, ref_label, lines = a, t, alt_lines
                        break
            precise = ref.source in ("github", "explicit")
            if last_line > len(lines):
                findings.append(Finding("line", "ungrounded", STRONG if precise else MEDIUM, claim,
                                        f"{path} has only {len(lines)} lines at {ref_label}"))
                continue
            lo, hi = max(0, ref.line_start - 6), min(len(lines), (ref.line_end or ref.line_start) + 5)
            window = "\n".join(lines[lo:hi])
            mentioned = [n for n in list(ex.identifiers) + sorted(ex.members) if n in idents_at_rev or n in KNOWN_EXTERNAL]
            hit = [n for n in mentioned if re.search(rf"\b{re.escape(n)}\b", window)]
            if not mentioned:
                findings.append(Finding("line", "unverifiable", INFO, claim, "the report names no symbol to look for at this line"))
            elif hit:
                findings.append(Finding("line", "grounded", INFO, claim, f"lines {lo + 1}-{hi} at {ref_label} contain {', '.join(hit[:4])}"))
            else:
                shown = _norm(lines[ref.line_start - 1])[:120]
                findings.append(Finding("line", "ungrounded", MEDIUM, claim,
                                        f"none of {', '.join(mentioned[:4])} appear near line {ref.line_start} at {ref_label}; it reads: {shown!r}"))
    return cited

def _resolve_cited(repo: Repo, rev: str, path: str) -> str | None:
    if path in repo.files(rev):
        return path
    matches = [m for m in repo.same_basename(rev, path) if m.startswith(CURL_SOURCE_DIRS)]
    return matches[0] if matches and "/" not in path else None


def _check_symbols(repo: Repo, ex: Extracted, rev: str, alts: list[tuple[str, str]], cited: list[str],
                   findings: list[Finding], idents_at_rev: frozenset[str]) -> None:
    attributed = {name for name, _ in ex.attributions}

    # "X is in lib/y.c": the symbol has to be in that file, not merely somewhere in curl.
    for name, raw_path in ex.attributions:
        path = _resolve_cited(repo, rev, raw_path)
        if not path:
            continue
        pattern = rf"\b{re.escape(name)}\s*\(" if name in KNOWN_EXTERNAL else rf"\b{re.escape(name)}\b"
        if any(re.search(pattern, repo.read(r, path) or "") for r in [rev] + [a for a, _ in alts]):
            findings.append(Finding("symbol", "grounded", INFO, f"{name} in {path}", f"{path} uses {name} at {rev[:12]}"))
            continue
        banned = name in KNOWN_EXTERNAL and repo.is_banned(rev, name)
        elsewhere = repo.grep_word(rev, name)[:1] if name not in KNOWN_EXTERNAL else []
        where = f"; it is in {elsewhere[0][0]}" if elsewhere else ""
        why = f"; curl's own source checker (checksrc.pl) bans {name}() at this revision" if banned else ""
        findings.append(Finding("symbol", "ungrounded", STRONG if banned else MEDIUM, f"{name} in {path}",
                                f"{path} does not contain {name} at {rev[:12]}{where}{why}"))

    history = None
    alt_idents = None
    for name, where in ex.identifiers.items():
        if name in attributed:
            continue
        if name in KNOWN_EXTERNAL:
            if name in DANGEROUS_CALLS and cited:
                in_cited = [p for p in cited if re.search(rf"\b{name}\s*\(", repo.read(rev, p) or "")]
                if not in_cited:
                    banned = repo.is_banned(rev, name)
                    why = f"; curl's own source checker (checksrc.pl) bans {name}() at this revision" if banned else ""
                    findings.append(Finding("symbol", "ungrounded", STRONG if banned else MEDIUM, f"{name}() call",
                                            f"{name}() is not called in {', '.join(cited[:3])} at {rev[:12]}{why}"))
                    continue
            findings.append(Finding("symbol", "external", INFO, name, f"{name} is a C library function"))
            continue
        if name in idents_at_rev:
            findings.append(Finding("symbol", "grounded", INFO, name, f"{name} exists in curl at {rev[:12]}"))
            continue
        if alt_idents is None:
            alt_idents = {t: repo.identifiers(a) for a, t in alts}
        alt_hit = next((t for t, ids in alt_idents.items() if name in ids), None)
        if alt_hit:
            findings.append(Finding("symbol", "grounded", INFO, name, f"{name} exists in curl at {alt_hit}"))
            continue
        if name in ex.poc_defined:
            if CURL_API.match(name):
                findings.append(Finding("symbol", "ungrounded", STRONG, name,
                                        f"{name} looks like a curl API but is defined by the report's own PoC code"))
            continue
        if name in ex.proposed:
            findings.append(Finding("symbol", "unverifiable", INFO, name, f"{name} appears only in a proposed fix"))
            continue
        history = history if history is not None else repo.identifier_history()
        if name in history:
            findings.append(Finding("symbol", "ungrounded", MEDIUM, name, f"{name} exists in other curl releases but not at {rev[:12]}"))
        elif CURL_API.match(name):
            # Naming slips are not inventions: Curl_multi_done for the static multi_done, CURLOPT_HTTPSIG for CURLOPT_HTTPSIG_*.
            family = next((i for i in sorted(idents_at_rev) if i.startswith(name + "_")), None)
            static = name.split("_", 1)[1] if name.startswith(("Curl_", "curl_", "curlx_")) else None
            if family:
                findings.append(Finding("symbol", "ungrounded", MEDIUM, name, f"no {name}, but the {family.rsplit('_', 1)[0]}_* family exists (e.g. {family})"))
            elif static and static in idents_at_rev:
                findings.append(Finding("symbol", "ungrounded", MEDIUM, name, f"no {name}, but curl has a function named {static}"))
            else:
                findings.append(Finding("symbol", "ungrounded", STRONG, name, f"{name} does not exist in any curl release since 7.50"))
        elif THIRD_PARTY_PREFIX.match(name):
            if name in ex.calls:
                findings.append(Finding("symbol", "ungrounded", MEDIUM, name, f"curl never calls {name} (it may be a real library function)"))
        elif name in ex.calls and (cited or where == "quote"):
            findings.append(Finding("symbol", "ungrounded", MEDIUM, name, f"{name}() does not exist in curl at {rev[:12]} or in any release since 7.50"))

def _quote_lines(block_text: str, lang: str) -> list[str]:
    """Lines a quote claims exist in curl: diff '+' lines dropped, markers and reporter '//' notes stripped."""
    raw = block_text.splitlines()
    is_diff = lang.lower() == "diff" or (raw and sum(l[:1] in "+-" for l in raw if l.strip()) / max(1, sum(bool(l.strip()) for l in raw)) >= 0.6)
    out = []
    for line in raw:
        if is_diff:
            if line.startswith("+"):
                continue  # proposed code, not a claim about curl
            line = line[1:] if line[:1] in "- " else line
        line = re.sub(r"\s//.*$", "", line)  # curl's style bans // comments, so these are the reporter's notes
        if _substantive(line):
            out.append(_norm(line))
    return out[:12]


def _check_quotes(repo: Repo, ex: Extracted, rev: str, alts: list[tuple[str, str]], cited: list[str],
                  submitted: str, findings: list[Finding]) -> None:
    # Reporters quote the release they tested as often as master, so search recent releases too.
    releases = [t for t, d in repo.release_tags() if d <= submitted][-3:]
    revs = [rev] + [a for a, _ in alts]
    revs += [r for r in (repo.resolve(t) for t in releases) if r and r not in revs]
    for block in ex.blocks:
        if block.kind != "quote":
            continue
        sub = _quote_lines(block.text, block.lang)
        paths = [block.path] if block.path else cited
        # A single quoted line counts if it is long enough to be specific and the report says where it is.
        if not sub or (len(sub) == 1 and (len(sub[0]) < 20 or not paths)):
            continue
        haystacks = [_norm(repo.read(r, p) or "") for r in revs for p in paths]
        found, missing = 0, []
        for line in sub:
            if any(line in h for h in haystacks):
                found += 1
                continue
            # Not in the cited file: look anywhere in curl's source before calling it invented.
            needle = max(re.split(r"\s{2,}", line), key=len)[:80]
            if any(repo.grep_fixed(r, needle) for r in revs):
                found += 1
            else:
                missing.append(line)
        frac = found / len(sub)
        preview = sub[0][:80]
        if frac >= 0.8:
            findings.append(Finding("quote", "grounded", INFO, preview, f"{found}/{len(sub)} quoted lines appear in curl at {rev[:12]}"))
        elif frac >= 0.5:
            findings.append(Finding("quote", "grounded", INFO, preview, f"{found}/{len(sub)} quoted lines appear in curl at {rev[:12]}"))
            findings.append(Finding("quote", "ungrounded", MEDIUM, missing[0][:80],
                                    f"{len(missing)} of {len(sub)} quoted lines appear nowhere in curl, e.g. {missing[0][:60]!r}"))
        else:
            # Medium, not strong: on dev this fired on 16% of slop but also 7% of real reports, which paraphrase too.
            findings.append(Finding("quote", "ungrounded", MEDIUM, preview, f"only {found}/{len(sub)} quoted lines appear anywhere in curl at {rev[:12]}"))

def _check_versions_commits_cves(repo: Repo, ex: Extracted, rev: str, findings: list[Finding]) -> None:
    dev = repo.dev_version(rev)
    ceiling = _ver_tuple(dev) if dev else None
    for v in ex.versions:
        if repo.tag_for_version(v):
            findings.append(Finding("version", "grounded", INFO, f"curl {v}", f"curl {v} is a real release"))
        elif ceiling and _ver_tuple(v) <= ceiling:
            note = "the development version on master at the time" if _ver_tuple(v) == ceiling else "not a release tag"
            findings.append(Finding("version", "unverifiable", INFO, f"curl {v}", f"curl {v}: {note}"))
        elif ceiling and _ver_tuple(v)[0] in (7, 8, 9):
            findings.append(Finding("version", "ungrounded", STRONG, f"curl {v}",
                                    f"curl {v} did not exist when the report was submitted (master was {dev}-DEV)"))
    for sha in ex.commits:
        if repo.resolve(sha):
            findings.append(Finding("commit", "grounded", INFO, sha[:12], f"commit {sha[:12]} exists in curl"))
        else:
            findings.append(Finding("commit", "ungrounded", MEDIUM, sha[:12], f"no commit {sha[:12]} in curl's history (may be a fork or PR branch)"))
    for cve in ex.cves:
        known = cve in curl_cves()
        findings.append(Finding("cve", "grounded" if known else "unverifiable", INFO, cve,
                                "a published curl CVE" if known else "not a curl CVE (may concern another project)"))


def _definition_files(repo: Repo, rev: str, names: list[str]) -> list[str]:
    """Files under lib/ and src/ that define any of these functions (name at the start of a line, followed by "(")."""
    files: list[str] = []
    for name in names[:8]:
        out = repo._git("grep", "-l", "-E", rf"^([A-Za-z_][A-Za-z0-9_ \*]*[ \*])?{re.escape(name)}\s*\(", rev, "--", "lib", "src", check=False)
        for line in out.split("\n"):
            path = line.split(":", 1)[-1]
            if path.endswith(".c") and path not in files:
                files.append(path)
    return files


def _fit(repo: Repo, ex: Extracted, rev: str) -> float:
    """How well a revision matches what the report shows: cited lines that contain the symbols it names,
    "line N" mentions whose sentence names code found near that line, and quoted lines found in cited files."""
    names = [n for n in list(ex.identifiers) + sorted(ex.members) if len(n) >= 4]
    score = 0.0
    if ex.line_mentions:
        candidates = [r.path for r in ex.files if not r.rev]
        candidates = [p for p in (_resolve_cited(repo, rev, c) for c in candidates) if p]
        candidates += [p for p in _definition_files(repo, rev, [n for _, ns in ex.line_mentions for n in ns]) if p not in candidates]
        texts = [(repo.read(rev, p) or "").splitlines() for p in candidates[:6]]
        for line_no, mentioned in ex.line_mentions[:20]:
            for lines in texts:
                window = "\n".join(lines[max(0, line_no - 4) : line_no + 3])
                if any(re.search(rf"\b{re.escape(n)}\b", window) for n in mentioned):
                    score += 1
                    break
    for ref in ex.files:
        if ref.rev or not ref.line_start:
            continue
        path = _resolve_cited(repo, rev, ref.path)
        lines = (repo.read(rev, path) or "").splitlines() if path else []
        if path and ref.line_start <= len(lines):
            window = "\n".join(lines[max(0, ref.line_start - 4) : (ref.line_end or ref.line_start) + 3])
            score += any(re.search(rf"\b{re.escape(n)}\b", window) for n in names)
    for block in ex.blocks:
        if block.kind != "quote":
            continue
        sub = _quote_lines(block.text, block.lang)
        paths = [block.path] if block.path else [r.path for r in ex.files if not r.rev]
        texts = [_norm(repo.read(rev, p) or "") for p in (_resolve_cited(repo, rev, q) for q in paths) if p]
        if sub and texts:
            score += sum(any(l in t for t in texts) for l in sub) / len(sub)
    return score


def ground_report(report: dict, repo: Repo | None = None) -> GroundingResult:
    """`report` is a dataset `input` dict: title, body, submitted_at, attachments."""
    repo = repo or Repo()
    ex = extract(report.get("title", ""), report.get("body", ""))
    submitted = report.get("submitted_at") or "2100-01-01"
    rev, rev_source = _pick_rev(repo, ex, submitted)
    if not rev:
        return GroundingResult(rev=None, rev_source=rev_source, verdict="nothing_to_check")
    if rev_source.startswith("master on"):
        # Reporters often read a release rather than master. Use the revision their line numbers and quotes fit best;
        # master wins ties.
        best = (_fit(repo, ex, rev), rev, rev_source)
        for alt, tag in _alt_revs(repo, ex, rev, submitted):
            score = _fit(repo, ex, alt)
            if score > best[0]:
                best = (score, alt, f"release {tag} (fits the report's line numbers and quotes better than master on {submitted[:10]})")
        _, rev, rev_source = best

    findings: list[Finding] = []
    idents_at_rev = repo.identifiers(rev)
    alts = _alt_revs(repo, ex, rev, submitted)
    cited = _check_files(repo, ex, rev, alts, findings, idents_at_rev)
    _check_symbols(repo, ex, rev, alts, cited, findings, idents_at_rev)
    _check_quotes(repo, ex, rev, alts, cited, submitted, findings)
    _check_versions_commits_cves(repo, ex, rev, findings)

    result = GroundingResult(rev=rev, rev_source=rev_source, verdict="", findings=findings, cited=cited)
    for f in findings:
        if f.check == "symbol" and f.status == "grounded":
            name = f.claim.split(" in ")[0]
            if name not in result.symbols:
                result.symbols.append(name)
        elif f.check == "line" and f.status != "ungrounded":
            m = re.fullmatch(r"(.+):(\d+)(?:-(\d+))?", f.claim)
            if m:
                result.lines.append((m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))))
    c = result.counts
    if c["ungrounded_strong"]:
        result.verdict = "not_grounded"
    elif c["ungrounded_medium"]:
        result.verdict = "partially_grounded"
    elif c["grounded"]:
        result.verdict = "grounded"
    else:
        result.verdict = "nothing_to_check"
    return result
