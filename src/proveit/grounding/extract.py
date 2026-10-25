"""Pull every checkable reference out of a report's text. No model calls; pure parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_FENCE = re.compile(r"```[ \t]*([\w+#-]*)[^\n]*\n(.*?)```", re.S)
_INLINE = re.compile(r"`([^`\n]{1,200})`")
_GH_BLOB = re.compile(
    r"github\.com/curl/curl/blob/([0-9a-fA-F]{7,40}|[\w.-]+)/([\w./-]+?)(?:#L(\d+)(?:-L(\d+))?)?(?=[\s)\]>\"'`,]|$)"
)
_PATH = re.compile(r"(?<![\w/.-])((?:[\w-]+/)*[\w-]+\.(?:c|h))(?::(\d+)(?:-(\d+))?)?(?!\w)(?!\.\w)")
_LINE_NEAR = re.compile(r"\blines?\s+(\d{1,6})(?:\s*(?:-|–|to)\s*(\d{1,6}))?", re.I)
_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")
_CONST = re.compile(r"\b(CURL[A-Z0-9]*_[A-Z0-9_]+)\b")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,}$")
_HEX = re.compile(r"\b([0-9a-f]{7,40})\b")
_VERSION = re.compile(r"\b(?:lib)?curl[\s/-]*(?:version\s*)?v?(\d+\.\d+(?:\.\d+)?)\b", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_C_DEF = re.compile(r"^[\w\s\*]+?\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{]*\)\s*\{", re.M)

_FIX_HINT = re.compile(r"\b(fix|patch|mitigat|remediat|recommend|suggest|solution|should be|replace|instead|corrected)", re.I)
_OUTPUT_HINT = re.compile(r"(==\d+==|AddressSanitizer|\(gdb\)|^#\d+\s+0x|Program received signal|Segmentation fault|valgrind)", re.M)
_POC_HINT = re.compile(r"(\bint\s+main\s*\(|#include\s*<|\bdef\s+\w+\(|\bimport\s+\w+)")
# Sentences that propose code rather than describe existing code.
_PROPOSAL_HINT = re.compile(r"\b(fix|patch|suggest|recommend|introduc|propos|could|should|would|replace|instead|mitigat|remediat|add(ing)? (a|an)\b)", re.I)
# Files the reporter says are theirs: "my test app is saved as lib/x.c", "poc.c", "repro_*.c".
_OWNER_HINT = re.compile(r"\b(my|our|saved as|reproducer|harness|attached|test (app|application|program|client))\b", re.I)
_OWNER_NAME = re.compile(r"(poc|repro|exploit|harness|crash|fuzz|test_?case)", re.I)
# "`X()` is implemented in lib/foo.c", "strcpy() is in lib/http.c"
_ATTRIB = re.compile(
    r"`?([A-Za-z_]\w{2,})(?:\(\))?`?(?:\s+(?:function|call|macro))?\s+(?:(?:is|are)\s+)?"
    r"(?:implemented|defined|located|found|called|used)?\s*in\s+`?((?:[\w-]+/)*[\w-]+\.[ch])\b"
)
# A sentence about another project: a missing path there is that project's file (libssh's src/knownhosts.c).
_DEP_HINT = re.compile(r"\b(libssh2?|openssl|boringssl|libressl|wolfssl|gnutls|mbedtls|nghttp2|nghttp3|ngtcp2|quiche|"
                       r"zlib|brotli|zstd|c-ares|libidn2|libpsl|rustls|krb5|openldap|nginx|apache|node|python)\b", re.I)
_TESTED_CTX = re.compile(r"\b(tested|testing|checkout|checked out|built|build|reproduced|HEAD|at commit|on commit)\b", re.I)
_MEMBER = re.compile(r"[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)+")
_COMMIT_CTX = re.compile(r"\b(commit|checkout|sha|revision|rev|git|HEAD|tree|tag|fixed in|introduced in)\b", re.I)
_C_LINE = re.compile(r"(;\s*$|\{\s*$|^\s*\}|->|\bif\s*\(|\breturn\b|\bwhile\s*\(|\bfor\s*\(|\bstruct\s+\w+|==|!=|\bNULL\b)")
_PUBLIC_API_CALL = re.compile(r"^curl_(easy|multi|share|url|global|mime|ws|slist|formadd|formfree)_?")
_SHELL_LANGS = {"bash", "sh", "shell", "console", "zsh", "cmd", "powershell", "text", "txt", "log", "output", "http"}
_C_LANGS = {"c", "h", "cpp", "c++", "diff"}

# English words that often appear before "(" in prose and are not code.
_PROSE_WORDS = {
    "and", "the", "for", "via", "see", "use", "using", "like", "such", "with", "from", "into", "this", "that",
    "line", "lines", "function", "functions", "method", "call", "calls", "called", "file", "code", "version",
    "example", "note", "e.g", "i.e", "etc", "low", "high", "medium", "critical", "cwe", "cvss", "impact",
}


@dataclass
class CodeBlock:
    lang: str
    text: str
    kind: str  # quote | poc | fix | output | shell
    start: int  # character offset in the report body
    path: str | None = None  # location the block says it comes from, e.g. "// lib/cookie.c:1184"


@dataclass
class FileRef:
    path: str
    line_start: int | None = None
    line_end: int | None = None
    rev: str | None = None  # commit or branch from a GitHub permalink
    source: str = "text"  # github | explicit (path:N) | near ("line N" close by) | text (no line)
    reporter: bool = False  # the report says this file is the reporter's own (PoC, test app)
    external: bool = False  # the sentence is about a dependency (libssh, OpenSSL...), not curl


@dataclass
class Extracted:
    files: list[FileRef] = field(default_factory=list)
    identifiers: dict[str, str] = field(default_factory=dict)  # name -> where seen (prose | inline | quote)
    calls: set[str] = field(default_factory=set)  # names written as name( outside PoC/fix blocks
    poc_defined: set[str] = field(default_factory=set)  # functions the reporter's own PoC defines
    proposed: set[str] = field(default_factory=set)  # names that appear only in proposal sentences ("introduce X()")
    attributions: list[tuple[str, str]] = field(default_factory=list)  # (symbol, path) from "X is in lib/y.c"
    commits: list[str] = field(default_factory=list)
    tested_commits: list[str] = field(default_factory=list)  # "Tested at commit X": the revision the report describes
    members: set[str] = field(default_factory=set)  # names from data->set.httpauth style expressions
    versions: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    blocks: list[CodeBlock] = field(default_factory=list)


def _c_like(text: str) -> bool:
    lines = [l for l in text.splitlines() if l.strip() and l.strip() not in ("...", "…")]
    return bool(lines) and sum(bool(_C_LINE.search(l)) for l in lines) / len(lines) >= 0.4


def _classify_block(lang: str, text: str, preceding: str) -> str:
    lang = lang.lower()
    if _OUTPUT_HINT.search(text):
        return "output"
    if lang in _SHELL_LANGS or text.lstrip().startswith(("$ ", "curl ", "./")):
        return "shell"
    if _POC_HINT.search(text):
        return "poc"
    if _FIX_HINT.search(preceding[-200:]):
        return "fix"
    calls = _CALL.findall(text)
    if calls and sum(bool(_PUBLIC_API_CALL.match(c)) for c in calls) / len(calls) >= 0.5 and not any(c.startswith("Curl_") for c in calls):
        return "poc"  # a usage snippet (curl_easy_setopt(easy, ...)) is the reporter's code, not curl's
    if lang in _C_LANGS or (not lang and _c_like(text)):
        return "quote"
    return "output"


def _add_ident(out: Extracted, name: str, where: str) -> None:
    if name.lower() in _PROSE_WORDS or not _IDENT.match(name) or _HEX.fullmatch(name):
        return
    # Keep the strongest provenance: quote > inline > prose.
    rank = {"prose": 0, "inline": 1, "quote": 2}
    if name not in out.identifiers or rank[where] > rank[out.identifiers[name]]:
        out.identifiers[name] = where


def _is_commitish(s: str) -> bool:
    return bool(re.search(r"\d", s)) and bool(re.search(r"[a-f]", s))


def extract(title: str, body: str) -> Extracted:
    out = Extracted()
    text = f"{title}\n\n{body}"
    seen_files: set[tuple] = set()

    def add_file(ref: FileRef) -> None:
        key = (ref.path, ref.line_start, ref.rev)
        if key not in seen_files:
            seen_files.add(key)
            out.files.append(ref)

    # Code blocks first, then work on the prose with blocks removed.
    prose_parts, last = [], 0
    for m in _FENCE.finditer(text):
        lang, code = m.group(1), m.group(2)
        kind = _classify_block(lang, code, text[max(0, m.start() - 300) : m.start()])
        block = CodeBlock(lang=lang, text=code, kind=kind, start=m.start())
        if kind == "quote":
            # A leading comment like "// lib/cookie.c:1184-1186" says where the quote comes from.
            for line in code.splitlines()[:2]:
                stripped = line.strip()
                pm = _PATH.search(line) if stripped.startswith(("//", "/*")) else None
                if pm:
                    block.path = pm.group(1)
                    add_file(FileRef(pm.group(1), int(pm.group(2)) if pm.group(2) else None,
                                     int(pm.group(3)) if pm.group(3) else None, source="explicit"))
                    break
        out.blocks.append(block)
        prose_parts.append(text[last : m.start()])
        last = m.end()
    prose_parts.append(text[last:])
    prose = "\n".join(prose_parts)

    for b in out.blocks:
        if b.kind == "poc":
            out.poc_defined.update(m.group(1) for m in _C_DEF.finditer(b.text))
        if b.kind == "quote":
            for m in _CALL.finditer(b.text):
                _add_ident(out, m.group(1), "quote")
                out.calls.add(m.group(1))

    for m in _GH_BLOB.finditer(text):
        add_file(
            FileRef(
                path=m.group(2),
                line_start=int(m.group(3)) if m.group(3) else None,
                line_end=int(m.group(4)) if m.group(4) else None,
                rev=m.group(1),
                source="github",
            )
        )

    described: set[str] = set()  # names used outside proposal sentences
    for line in prose.splitlines():
        if "github.com/" in line:
            line = _GH_BLOB.sub(" ", line)
        line = re.sub(r"https?://\S+", " ", line)  # paths inside other projects' URLs are not curl paths
        owner = bool(_OWNER_HINT.search(line))
        external = bool(_DEP_HINT.search(line))
        for m in _PATH.finditer(line):
            path = m.group(1)
            reporter = owner or bool(_OWNER_NAME.search(path.rsplit("/", 1)[-1]))
            if m.group(2):
                add_file(FileRef(path, int(m.group(2)), int(m.group(3)) if m.group(3) else None, source="explicit",
                                 reporter=reporter, external=external))
                continue
            near = _LINE_NEAR.search(line[m.end() : m.end() + 60]) or _LINE_NEAR.search(line[max(0, m.start() - 60) : m.start()])
            if near:
                add_file(FileRef(path, int(near.group(1)), int(near.group(2)) if near.group(2) else None, source="near",
                                 reporter=reporter, external=external))
            else:
                add_file(FileRef(path, reporter=reporter, external=external))

        proposal = bool(_PROPOSAL_HINT.search(line))
        names: list[tuple[str, str, bool]] = []  # (name, where, written as a call)
        for m in _INLINE.finditer(line):
            span = m.group(1).strip()
            for expr in _MEMBER.findall(span):
                out.members.update(n for n in re.split(r"->|\.", expr) if len(n) >= 3)
            if _IDENT.match(span.rstrip("()")):
                names.append((span.rstrip("()"), "inline", span.endswith("()")))
            for c in _CALL.finditer(span):
                names.append((c.group(1), "inline", True))
        for m in _CALL.finditer(line):
            name = m.group(1)
            # In running prose, "word (" is usually English. Count it only as name( or a code-shaped name.
            if line[m.end(1)] == "(" or "_" in name or re.search(r"[a-z][A-Z]", name):
                names.append((name, "prose", line[m.end(1)] == "("))
        for m in _CONST.finditer(line):
            names.append((m.group(1), "inline", False))
        for name, where, is_call in names:
            _add_ident(out, name, where)
            if is_call:
                out.calls.add(name)
            (out.proposed if proposal else described).add(name)
        if not proposal:
            for m in _ATTRIB.finditer(line):
                name = m.group(1)
                before, after = line[m.start(1) - 1 : m.start(1)], line[m.end(1) : m.end(1) + 2]
                # Only code-shaped names: "use-after-free in `lib/x.c`" is English, `free()` in lib/x.c is a claim.
                code_shaped = after.startswith(("(", "`")) or before == "`" or "_" in name or re.search(r"[a-z][A-Z]", name)
                if code_shaped and before != "-" and _IDENT.match(name) and name.lower() not in _PROSE_WORDS:
                    out.attributions.append((name, m.group(2)))
        for h in _HEX.findall(line):
            if _is_commitish(h) and (len(h) >= 12 or _COMMIT_CTX.search(line)):
                out.commits.append(h)
                if _TESTED_CTX.search(line):
                    out.tested_commits.append(h)
    out.proposed -= described

    out.commits = sorted(set(out.commits))
    out.versions = sorted({m.group(1) for m in _VERSION.finditer(text)})
    out.cves = sorted({m.group(0).upper() for m in _CVE.finditer(text)})
    return out
