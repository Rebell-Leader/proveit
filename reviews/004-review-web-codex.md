Review complete. **Six findings** below. No code changed or paid API calls made. The read-only workspace prevented saving `reviews/004-review-web-codex.md`.

1. **High — Concurrent runs bypass the daily spending cap.**  
   **Location:** [budget.py:39](/home/obi/hackathons/nebius_hack/src/proveit/web/budget.py:39), [app.py:175](/home/obi/hackathons/nebius_hack/src/proveit/web/app.py:175).  
   **Trigger:** Send concurrent `POST /api/live` requests containing distinct report bodies while recorded spend is below the cap. Use multiple IP identities to bypass the separate per-IP limit.  
   **Failure and impact:** Admission checks completed spending without reserving funds for admitted work. Every concurrent request can pass before any finishes, allowing spending beyond the daily cap and an unbounded queue of model work. A mocked check admitted 100 identities while recorded spend stayed at `$0`.  
   **Recommendation:** Reserve a conservative per-run amount atomically at admission and enforce a bounded concurrency limit.

2. **Medium — Visitors can spoof their per-IP quota identity.**  
   **Location:** [app.py:55](/home/obi/hackathons/nebius_hack/src/proveit/web/app.py:55).  
   **Trigger:** Repeat `POST /api/live` with headers such as `X-Forwarded-For: visitor-1`, then `visitor-2`.  
   **Failure and impact:** `_client_ip()` trusts the first header entry without validating its origin or format. A proxy that preserves or appends forwarded values lets one visitor obtain unlimited quota identities. This also enables the concurrency attack above and grows the persisted IP map. A proxy that overwrites the header would mitigate this deployment-dependent issue.  
   **Recommendation:** Derive client identity through explicitly trusted proxy handling; ignore visitor-supplied forwarding values.

3. **High — Disconnecting leaves paid work running without charging the budget.**  
   **Location:** [app.py:167](/home/obi/hackathons/nebius_hack/src/proveit/web/app.py:167), [app.py:175](/home/obi/hackathons/nebius_hack/src/proveit/web/app.py:175).  
   **Trigger:** Submit `{"body":"curl_easy_escape mishandles negative lengths"}` and close the SSE connection after a progress event confirms triage started. Repeat with distinct inputs.  
   **Failure and impact:** The background task is independent of the response generator. When disconnect handling closes or cancels that generator, its eventual `budget.spend()` is skipped while the worker can continue making paid calls. A mocked worker completed after stream closure with no budget charge.  
   **Recommendation:** Account for work in a job lifecycle independent of the connection, retaining reservations until completion or confirmed cancellation.

4. **Medium — Failures after partial model work erase incurred spending.**  
   **Location:** [app.py:174](/home/obi/hackathons/nebius_hack/src/proveit/web/app.py:174), [pipeline.py:57](/home/obi/hackathons/nebius_hack/src/proveit/judge/pipeline.py:57).  
   **Trigger:** Submit a fresh report; let claims extraction succeed, then let the judge call fail after its SDK retries. Retry with a different body to avoid the claims cache.  
   **Failure and impact:** `task.result()` raises before `budget.spend()` runs. Already incurred claims costs never enter the daily ledger. Repeated retries during provider failures can continue consuming credits despite the intended cap. The mocked exception path recorded no charge.  
   **Recommendation:** Record each completed paid call immediately and reconcile reservations on every exit path.

5. **High — Input limits apply after unbounded request buffering.**  
   **Location:** [app.py:130](/home/obi/hackathons/nebius_hack/src/proveit/web/app.py:130), [app.py:151](/home/obi/hackathons/nebius_hack/src/proveit/web/app.py:151).  
   **Trigger:** Send a JSON request whose `body` contains hundreds of megabytes of text, or a large unused field. Repeat concurrently.  
   **Failure and impact:** `request.json()` buffers and parses the complete payload before truncation or quota checking. The 30,000-character slice therefore does not protect process memory or parsing time. Without an external request-size cap, anonymous requests can exhaust the single container’s memory even after live spending is disabled. HackerOne responses also lack a size bound; a mocked 100,000-character report reached triage intact.  
   **Recommendation:** Enforce a byte limit while reading requests and upstream responses, then validate field types and lengths before processing.

6. **Medium — Exhausted quotas do not stop HackerOne fetches.**  
   **Location:** [app.py:145](/home/obi/hackathons/nebius_hack/src/proveit/web/app.py:145), [app.py:153](/home/obi/hackathons/nebius_hack/src/proveit/web/app.py:153).  
   **Trigger:** After exhausting the daily budget, repeatedly submit `{"url":"https://hackerone.com/reports/12345"}` using an ID absent from the demo cache.  
   **Failure and impact:** Every request fetches HackerOne before checking the budget. Private or nonexistent reports return before any quota check. Anonymous traffic can therefore consume outbound connections and upstream requests indefinitely, potentially causing rate limiting that breaks legitimate URL submissions. A mocked exhausted-budget request still fetched the report.  
   **Recommendation:** Apply admission and fetch-rate limits before outbound requests.

**Other checks:** Hostile HTML was escaped by the actual Jinja template, and `javascript:` source links were excluded. No exploitable XSS or HackerOne SSRF path was found: fetching rebuilds a fixed HTTPS URL from a numeric ID and does not enable redirects. General exceptions expose only their class; the verbatim `ValueError` path produced no confirmed secret or filesystem-path leak. Successful JSON-generation retries accumulate both attempts’ token usage; failed-run accounting remains the issue in finding 4.