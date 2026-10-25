Could not save `reviews/001-review-grounding-codex.md`: this session’s filesystem is read-only. The review follows. No code was changed.

# Grounding checker review

Validated against local curl history using submission date `2026-10-01T00:00:00Z`, which selects revision `60cf74f438cf`. All eight existing tests pass. Reproduction probes used an in-memory identifier cache; no report PoC code was executed.

Severity below describes review priority, separately from the checker’s `strong` and `medium` findings.

## False-alarm risks

### 1. High — Explicit tested versions do not select the target revision

**Location:** [src/proveit/grounding/check.py:110](/home/obi/hackathons/nebius_hack/src/proveit/grounding/check.py:110)

**Input:**

> Tested curl 7.80.0. The affected code is lib/url.c:4000.

**Observed verdict:** `not_grounded`.

`_pick_rev()` considers hexadecimal permalinks and submission date, but ignores extracted versions. At `curl-7_80_0`, `lib/url.c` has 4,195 lines and line 4000 contains real code. Submission-date master has only 2,591 lines, so the checker emits a **strong** nonexistent-line finding.

A genuine report against an older release can therefore be flagged as fabricated despite explicitly naming the tested version.

### 2. High — Describing a reproducer’s own helper flags fabrication

**Location:** [src/proveit/grounding/check.py:199](/home/obi/hackathons/nebius_hack/src/proveit/grounding/check.py:199)

**Input:**

````markdown
The issue is in lib/http.c. My reproducer calls trigger_probe().
```c
#include <curl/curl.h>
void trigger_probe(void) {
  return;
}
```
````

**Observed verdict:** `not_grounded`.

The extractor correctly identifies `trigger_probe` as PoC-defined. However, mentioning its call in prose while citing any curl file produces a **strong** finding that the helper belongs to the PoC rather than curl.

The report explicitly attributes the function to its reproducer; it makes no false existence claim about curl.

### 3. High — Proposed APIs in prose are treated as existing APIs

**Location:** [src/proveit/grounding/extract.py:179](/home/obi/hackathons/nebius_hack/src/proveit/grounding/extract.py:179) and [check.py:207](/home/obi/hackathons/nebius_hack/src/proveit/grounding/check.py:207)

**Input:**

> The issue is in lib/http.c. Suggested fix: introduce curl_easy_proveit_guard().

**Observed verdict:** `not_grounded`.

Fix-context handling applies to fenced blocks, while prose calls enter ordinary symbol checking. The proposed API produces a **strong** nonexistent-symbol finding.

Adding a remediation suggestion can turn an otherwise grounded genuine report into a fabrication alarm.

### 4. High — Reporter-owned files under `lib/` are attributed to curl

**Location:** [src/proveit/grounding/check.py:135](/home/obi/hackathons/nebius_hack/src/proveit/grounding/check.py:135)

**Input:**

> The curl issue is in lib/http.c. My test application is saved as lib/proveit_client.c.

**Observed verdict:** `not_grounded`.

The directory prefix alone marks the application’s file as a curl source path. Its absence from curl history produces a **strong** finding, despite the explicit attribution to the reporter’s application.

A legitimate reproducer with its own conventional source layout can trigger a false fabrication alarm.

### 5. Medium — Payload strings are interpreted as commit claims

**Location:** [src/proveit/grounding/extract.py:189](/home/obi/hackathons/nebius_hack/src/proveit/grounding/extract.py:189)

**Input:**

> The issue is in lib/http.c. The request body is the literal ASCII string deadbee1.

**Observed verdict:** `partially_grounded`.

Every qualifying hexadecimal token in prose becomes a commit reference, without requiring commit-related context. The literal request body yields an ungrounded commit finding.

This incorrectly downgrades a report containing ordinary payload data. It does not trigger the current `fabrication` flagging rule.

## Fabrication patterns that receive `grounded`

### 6. Medium — Nonexistent range endpoints are never checked

**Location:** [src/proveit/grounding/check.py:163](/home/obi/hackathons/nebius_hack/src/proveit/grounding/check.py:163)

**Example body:**

> The affected code is lib/http.c:1-999999.

**Observed verdict:** `grounded`.

Only `line_start` is checked against file length. The nonexistent endpoint is silently clamped when constructing the search window. With no named symbol, the line finding is merely `unverifiable`; the existing file supplies the positive evidence needed for `grounded`.

The report fabricates a source range extending far beyond the file.

### 7. Medium — A fabricated single-line source quotation is skipped

**Location:** [src/proveit/grounding/check.py:240](/home/obi/hackathons/nebius_hack/src/proveit/grounding/check.py:240)

**Example body:**

````markdown
Vulnerable code in lib/http.c:
```c
long invented_proveit_flag = 123456;
```
````

**Observed verdict:** `grounded`.

The block is classified as a quotation, but quote checking skips blocks with fewer than two substantive lines. Its invented variable declaration also contains no function call for symbol extraction.

A report can quote nonexistent source verbatim and receive `grounded` based solely on its real filename.

### 8. Medium — An include directive suppresses an explicitly attributed source quotation

**Location:** [src/proveit/grounding/extract.py:80](/home/obi/hackathons/nebius_hack/src/proveit/grounding/extract.py:80)

**Example body:**

````markdown
Vulnerable source in lib/http.c:
```c
#include "http.h"
void Curl_proveit_fabricated(void) {
  long invented_proveit_flag = 123456;
}
```
````

**Observed verdict:** `grounded`.

Any matching `#include` classifies the entire block as PoC before source-quotation checking. Consequently, neither the fabricated curl-namespaced function nor the invented source is checked unless mentioned elsewhere.

An include directive lets a fabricated multi-line quotation bypass both symbol and quote validation.

### 9. Medium — Repository-wide token existence validates false file attribution

**Location:** [src/proveit/grounding/check.py:185](/home/obi/hackathons/nebius_hack/src/proveit/grounding/check.py:185)

**Example body:**

> The vulnerable function `curl_easy_init()` is implemented in lib/cookie.c.

**Observed verdict:** `grounded`.

`curl_easy_init` exists elsewhere in curl but has no occurrence in `lib/cookie.c` at the tested revision. Symbol checking accepts repository-wide identifier membership without checking the claimed file.

The same early return also bypasses the dangerous-call location check: this body receives `grounded` despite no `strcpy` occurrence in the cited file:

> The vulnerable call strcpy() is in lib/http.c.

Both examples fabricate code location, independently of whether any vulnerability is exploitable.

### 10. Medium — Half-real quotations are marked fully grounded

**Location:** [src/proveit/grounding/check.py:255](/home/obi/hackathons/nebius_hack/src/proveit/grounding/check.py:255)

**Example body:**

````markdown
Vulnerable code in lib/http.c:
```c
neg->accept_09 = data->set.http09_allowed;
neg->wanted = neg->allowed = (CURL_HTTP_V1x);
long invented_proveit_flag = 123456;
long invented_proveit_size = 999999;
```
````

**Observed verdict:** `grounded`, with quote evidence `2/4 quoted lines appear`.

The first two statements exist in the cited file; the final two are fabricated. The 50% threshold marks the entire quote grounded without recording its unmatched statements.

A report can surround invented source with an equal number of real lines and obtain a positive quotation finding.