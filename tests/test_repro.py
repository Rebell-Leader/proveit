"""The reproduction stage's pure logic: classifying a sandbox run and assembling the script. No sandbox calls."""

from proveit.repro.stage import MARK_OK, build_script, classify
from proveit.repro.sandbox import RunResult


def run(stdout="", stderr="", exit_code=0, timed_out=False):
    return RunResult(operation="op", image="img", result_image=None, status="SUCCESS", exit_code=exit_code,
                     timed_out=timed_out, signal=None, stdout=stdout, stderr=stderr, truncated=False,
                     seconds=1.0, cost=0.0, networking=False)


ASAN_IN_CURL = ("AddressSanitizer: stack-overflow\n    #3 curl_mime_free /src/curl/lib/mime.c:1122\n"
                "SUMMARY: AddressSanitizer: stack-overflow")


def test_reproduced_needs_sanitizer_and_a_curl_frame():
    r = run(stdout=f"PROVEIT_COMPILED\n{MARK_OK}", stderr=ASAN_IN_CURL)
    assert classify(r, "c")["outcome"] == "reproduced"


def test_sanitizer_without_a_curl_frame_is_not_reproduced():
    r = run(stdout="PROVEIT_COMPILED", stderr="AddressSanitizer: heap-buffer-overflow\n    #0 main /tmp/poc.c:9")
    assert classify(r, "c")["outcome"] == "crash_outside_curl"


def test_poc_that_does_not_compile_is_fabricated_api():
    r = run(stderr="/tmp/poc.c:9: error: implicit declaration of function 'curl_easy_pwn'")
    out = classify(r, "c")
    assert out["outcome"] == "fabricated_api"
    assert "curl_easy_pwn" in out["missing_symbols"]


def test_clean_compiled_run_is_only_weak_evidence():
    r = run(stdout=f"PROVEIT_COMPILED\nall good\n{MARK_OK}")
    assert classify(r, "c")["outcome"] == "ran_clean"


def test_timeout_is_inconclusive():
    assert classify(run(timed_out=True), "c")["outcome"] == "inconclusive"


def test_shell_poc_never_reports_fabricated_api():
    # A shell PoC does not compile anything, so missing-symbol heuristics must not apply to it.
    assert classify(run(stdout=MARK_OK), "shell")["outcome"] == "ran_clean"


def test_build_script_delivers_c_without_a_heredoc_and_sets_the_stack():
    s = build_script({"language": "c", "c_source": "int main(void){return 0;}", "stack_kb": 512})
    assert "base64 -d > poc.c" in s and "<<" not in s
    assert "ulimit -s 512" in s and "cc-curl -o poc poc.c" in s


def test_build_script_uses_default_stack_when_zero():
    s = build_script({"language": "c", "c_source": "int main(void){return 0;}", "stack_kb": 0})
    assert "ulimit" not in s
