"""Receipts rules, from the Codex review of the judge stage (reviews/003-redteam-judge-codex.md). No API calls."""

from proveit.judge.evidence import Snippet
from proveit.judge.verdict import check_citations, check_external_quotes, enforce_receipts

CLAIMS = {"claims": [
    {"id": "C1", "kind": "flaw", "text": "SOCKS5 state lost across retries", "code_refs": []},
    {"id": "C2", "kind": "impact", "text": "curl_easy_escape accepts negative lengths", "code_refs": []},
]}
SNIPPETS = [Snippet("lib/escape.c", 80, 100, "definition", ["x"] * 21), Snippet("lib/socks.c", 548, 600, "lines", ["x"] * 53)]
NO_FINDINGS = {"findings": []}


def judgment(verdict, assessments, external_checks=()):
    return {"verdict": verdict, "claim_assessments": assessments, "external_checks": list(external_checks)}


def final(j, external=None, grounding=NO_FINDINGS):
    bad, verified = check_external_quotes(j, external)
    return enforce_receipts(j, check_citations(j, SNIPPETS, verified), grounding, CLAIMS, bad)[0]


def test_contradicting_an_incidental_claim_cannot_reject_the_report():
    j = judgment("likely_invalid", [
        {"id": "C1", "status": "not_verifiable", "evidence": [], "reasoning": ""},
        {"id": "C2", "status": "contradicted", "evidence": [{"file": "lib/escape.c", "line": 90, "note": ""}], "reasoning": ""},
    ])
    assert final(j) == "needs_human"


def test_contradicting_the_central_claim_with_shown_code_rejects():
    j = judgment("likely_invalid", [
        {"id": "C1", "status": "contradicted", "evidence": [{"file": "lib/socks.c", "line": 560, "note": ""}], "reasoning": ""},
    ])
    assert final(j) == "likely_invalid"


def test_supporting_an_incidental_claim_cannot_confirm_the_report():
    j = judgment("likely_valid", [
        {"id": "C2", "status": "supported", "evidence": [{"file": "lib/escape.c", "line": 90, "note": ""}], "reasoning": ""},
    ])
    assert final(j) == "needs_human"


def test_url_citation_without_a_verified_quote_does_not_count():
    external = [{"url": "https://docs.openssl.org/ssl_read", "content": "SSL_read() reads num bytes into buf."}]
    j = judgment("likely_valid", [
        {"id": "C1", "status": "supported", "evidence": [{"file": "https://docs.openssl.org/ssl_read", "line": 999, "note": ""}], "reasoning": ""},
    ])
    assert final(j, external) == "needs_human"


def test_url_citation_with_a_verbatim_quote_counts():
    external = [{"url": "https://docs.openssl.org/ssl_read", "content": "SSL_read() reads num bytes into buf."}]
    j = judgment("likely_valid", [
        {"id": "C1", "status": "supported", "evidence": [{"file": "https://docs.openssl.org/ssl_read", "line": 0, "note": ""}], "reasoning": ""},
    ], [{"statement": "reads num bytes", "status": "confirmed", "url": "https://docs.openssl.org/ssl_read", "quote": "SSL_read() reads num bytes into buf."}])
    assert final(j, external) == "likely_valid"


def test_fabricated_external_quote_demotes_the_verdict():
    external = [{"url": "https://nghttp2.org/documentation/types.html", "content": "Both name and value are guaranteed to be NULL-terminated."}]
    j = judgment("likely_valid", [
        {"id": "C1", "status": "supported", "evidence": [{"file": "lib/socks.c", "line": 560, "note": ""}], "reasoning": ""},
    ], [{"statement": "not null-terminated", "status": "confirmed", "url": "https://nghttp2.org/documentation/types.html",
         "quote": "The name and value pointers are NOT guaranteed to be null-terminated."}])
    assert final(j, external) == "needs_human"


def test_medium_grounding_findings_alone_cannot_authorize_rejection():
    grounding = {"findings": [{"status": "ungrounded", "severity": "medium", "check": "quote", "evidence": "x"}]}
    j = judgment("likely_invalid", [{"id": "C1", "status": "not_verifiable", "evidence": [], "reasoning": ""}])
    assert final(j, grounding=grounding) == "needs_human"


def test_tag_permalink_selects_the_release_revision():
    import pytest
    from proveit.grounding.repo import CURL_DIR, Repo

    if not (CURL_DIR / ".git").exists():
        pytest.skip("needs vendor/curl")
    from proveit.grounding.check import ground_report

    body = "Tested curl 8.3.0.\nhttps://github.com/curl/curl/blob/curl-8_3_0/lib/socks.c#L573-L592\nSOCKS5 state is lost."
    res = ground_report({"title": "t", "body": body, "submitted_at": "2023-10-12T12:00:00Z"})
    assert res.rev == Repo().resolve("curl-8_3_0")


def test_policy_rejection_needs_a_section_that_exists_in_the_shown_policy():
    policy = "# Not security issues\n\n## URL inconsistencies\n\nCurl parses URLs its own way.\n\n## Test code\n\n..."
    j = judgment("likely_invalid", [{"id": "C1", "status": "supported", "evidence": [], "reasoning": ""}])
    j["policy_section"] = "URL inconsistencies"
    assert enforce_receipts(j, check_citations(j, SNIPPETS), NO_FINDINGS, CLAIMS, [], policy)[0] == "policy_question"
    j["policy_section"] = "Harmless quirks"
    assert enforce_receipts(j, check_citations(j, SNIPPETS), NO_FINDINGS, CLAIMS, [], policy)[0] == "needs_human"
    j["policy_section"] = "URL inconsistencies"
    assert enforce_receipts(j, check_citations(j, SNIPPETS), NO_FINDINGS, CLAIMS, [], None)[0] == "needs_human"


def test_policy_alone_with_the_flaw_confirmed_is_a_question_not_a_rejection():
    policy = "# Not security issues\n\n## Busy-loops\n\n..."
    j = judgment("likely_invalid", [
        {"id": "C1", "status": "supported", "evidence": [{"file": "lib/socks.c", "line": 560, "note": ""}], "reasoning": ""},
    ])
    j["policy_section"] = "Busy-loops"
    assert enforce_receipts(j, check_citations(j, SNIPPETS), NO_FINDINGS, CLAIMS, [], policy)[0] == "policy_question"
