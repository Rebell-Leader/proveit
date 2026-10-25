from proveit.grounding.extract import extract


def test_github_permalink_with_line_range():
    ex = extract("t", "See https://github.com/curl/curl/blob/e251e858b941/lib/ws.c#L581-L590 for the bug.")
    assert len(ex.files) == 1
    ref = ex.files[0]
    assert (ref.path, ref.line_start, ref.line_end, ref.rev, ref.source) == ("lib/ws.c", 581, 590, "e251e858b941", "github")


def test_plain_path_with_line_number_nearby():
    ex = extract("t", "The overflow is in lib/http.c line 4521 when parsing headers.")
    assert [(f.path, f.line_start) for f in ex.files] == [("lib/http.c", 4521)]


def test_path_colon_line():
    ex = extract("t", "Crash at lib/vtls/openssl.c:1203.")
    assert [(f.path, f.line_start) for f in ex.files] == [("lib/vtls/openssl.c", 1203)]


def test_prose_english_words_are_not_symbols():
    ex = extract("t", "copy the number of characters (up to the buffer size) using Curl_dyn_add(buf).")
    assert "characters" not in ex.identifiers
    assert "Curl_dyn_add" in ex.identifiers


def test_constants_and_inline_code():
    ex = extract("t", "Setting `CURLOPT_MAXLIFETIME_CONN` together with `curl_easy_setopt` triggers it.")
    assert {"CURLOPT_MAXLIFETIME_CONN", "curl_easy_setopt"} <= set(ex.identifiers)


def test_block_kinds():
    body = (
        "Vulnerable code:\n```c\nif(len > max)\n  return CURLE_BAD;\n```\n"
        "PoC:\n```c\n#include <curl/curl.h>\nint main(void) { return 0; }\n```\n"
        "Suggested fix:\n```c\nstrncpy(a, b, sizeof(a) - 1);\n```\n"
        "```\n==123==ERROR: AddressSanitizer: heap-buffer-overflow\n```\n"
    )
    kinds = [b.kind for b in extract("t", body).blocks]
    assert kinds == ["quote", "poc", "fix", "output"]


def test_poc_defined_functions_are_recorded():
    body = "```c\n#include <string.h>\nvoid vulnerable_copy(char *s) {\n  char b[8]; strcpy(b, s);\n}\nint main(void) { vulnerable_copy(\"x\"); }\n```"
    assert "vulnerable_copy" in extract("t", body).poc_defined


def test_versions_and_cves():
    ex = extract("Bug in curl 8.4.0", "Affects libcurl/8.5.0 too, similar to cve-2023-38545.")
    assert ex.versions == ["8.4.0", "8.5.0"]
    assert ex.cves == ["CVE-2023-38545"]
