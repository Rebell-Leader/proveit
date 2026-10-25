"""Regression tests from the Codex review (reviews/001-review-grounding-codex.md). They run against vendor/curl."""

import pytest

from proveit.grounding.repo import CURL_DIR

pytestmark = pytest.mark.skipif(not (CURL_DIR / ".git").exists(), reason="needs vendor/curl (uv run proveit fetch-repo)")

SUBMITTED = "2026-10-01T00:00:00Z"


def verdict(body: str) -> str:
    from proveit.grounding.check import ground_report

    return ground_report({"title": "report", "body": body, "submitted_at": SUBMITTED}).verdict


# False-alarm risks: real-looking reports that must not be called fabricated.

def test_named_older_release_is_used_for_line_numbers():
    assert verdict("Tested curl 7.80.0. The affected code is lib/url.c:4000.") != "not_grounded"


def test_reporter_helper_function_is_not_a_fabrication():
    body = (
        "The issue is in lib/http.c. My reproducer calls trigger_probe().\n"
        "```c\n#include <curl/curl.h>\nvoid trigger_probe(void) {\n  return;\n}\n```\n"
    )
    assert verdict(body) != "not_grounded"


def test_proposed_api_in_prose_is_not_a_fabrication():
    assert verdict("The issue is in lib/http.c. Suggested fix: introduce curl_easy_proveit_guard().") != "not_grounded"


def test_reporter_file_under_lib_is_not_a_fabrication():
    assert verdict("The curl issue is in lib/http.c. My test application is saved as lib/proveit_client.c.") != "not_grounded"


def test_payload_hex_is_not_a_commit_claim():
    assert verdict("The issue is in lib/http.c. The request body is the literal ASCII string deadbee1.") == "grounded"


# Fabrications that used to pass as grounded.

def test_range_endpoint_beyond_file_is_caught():
    assert verdict("The affected code is lib/http.c:1-999999.") == "not_grounded"


def test_single_line_invented_quote_is_caught():
    body = "Vulnerable code in lib/http.c:\n```c\nlong invented_proveit_flag = 123456;\n```\n"
    assert verdict(body) != "grounded"


def test_include_does_not_hide_an_invented_curl_function():
    body = (
        "Vulnerable source in lib/http.c:\n"
        '```c\n#include "http.h"\nvoid Curl_proveit_fabricated(void) {\n  long invented_proveit_flag = 123456;\n}\n```\n'
    )
    assert verdict(body) == "not_grounded"


def test_symbol_must_be_in_the_file_it_is_attributed_to():
    assert verdict("The vulnerable function `curl_easy_init()` is implemented in lib/cookie.c.") != "grounded"


def test_banned_call_claimed_in_a_file_is_caught():
    # curl's checksrc.pl bans strcpy() since December 2025.
    assert verdict("The vulnerable call strcpy() is in lib/http.c.") == "not_grounded"


def test_half_real_quote_is_not_fully_grounded():
    body = (
        "Vulnerable code in lib/http.c:\n```c\n"
        "neg->accept_09 = data->set.http09_allowed;\n"
        "neg->wanted = neg->allowed = (CURL_HTTP_V1x);\n"
        "long invented_proveit_flag = 123456;\n"
        "long invented_proveit_size = 999999;\n```\n"
    )
    assert verdict(body) != "grounded"
