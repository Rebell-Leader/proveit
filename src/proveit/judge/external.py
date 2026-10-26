"""Check what a report says about other projects' documentation, APIs and standards, using Tavily search.

Reports often lean on a claim about a dependency ("nghttp2 does not guarantee null-terminated names") that no
amount of reading curl's code can confirm. These are fetched from the real sources and given to the judge.

Leakage guard: searches never include the sites where a report's outcome is published (HackerOne, curl's
advisories and slop list), so the evaluation cannot read its own answer key.
"""

from __future__ import annotations

import hashlib
import json
import os

import httpx

from proveit import CACHE_DIR

TAVILY_URL = "https://api.tavily.com/search"
# Only the dependencies' own documentation and standards bodies: authoritative, and not where a curl report's
# outcome gets published.
DOC_DOMAINS = [
    "openssl.org", "docs.openssl.org", "nghttp2.org", "libssh.org", "api.libssh.org", "libssh2.org", "gnutls.org",
    "wolfssl.com", "mbed-tls.readthedocs.io", "rustls.dev", "docs.rs", "c-ares.org", "zlib.net", "libidn.gitlab.io",
    "rfc-editor.org", "datatracker.ietf.org", "ietf.org", "quicwg.org", "man7.org", "pubs.opengroup.org",
    "sourceware.org", "gnu.org", "en.cppreference.com", "open-std.org", "learn.microsoft.com", "developer.apple.com",
    "web.mit.edu", "openldap.org", "brotli.org", "facebook.github.io",
]
CACHE = CACHE_DIR / "tavily"
EXCLUDE_DOMAINS = [
    "hackerone.com", "curl.se", "daniel.haxx.se", "gist.github.com", "lwn.net", "theregister.com",
    "bleepingcomputer.com", "nvd.nist.gov", "cve.org", "cve.mitre.org", "osv.dev", "github.com/advisories",
]


def search(query: str, max_results: int = 4) -> list[dict]:
    """Tavily search with the leakage guard. Returns [{url, title, content}], cached on disk."""
    key = os.environ.get("TAVILY_API_KEY")
    if not key:
        return []
    payload = {"query": query, "search_depth": "advanced", "max_results": max_results, "chunks_per_source": 3,
               "include_answer": False, "include_domains": DOC_DOMAINS, "exclude_domains": EXCLUDE_DOMAINS}
    h = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    path = CACHE / f"{h}.json"
    if path.exists():
        return json.loads(path.read_text())
    resp = httpx.post(TAVILY_URL, json=payload, headers={"Authorization": f"Bearer {key}"}, timeout=60)
    resp.raise_for_status()
    # exclude_domains cannot express paths such as github.com/curl, so filter those out here as well.
    results = [{"url": r["url"], "title": r.get("title", ""), "content": r.get("content", "")[:2500]}
               for r in resp.json().get("results", [])
               if not any(bad in r["url"].lower() for bad in ("curl", "hackerone", "haxx"))]
    CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results))
    return results
