# Benchmark Specification v2.1

**Audience**: Benchmarking Tool Developer (primary) · Competition Organizers (review) **Scope**: How the benchmarking tool generates traffic, measures WAF effectiveness, and computes scores. **Dependencies**: Reads `target_app_contract.md` for endpoints/markers. Reads `waf_interop_contract.md` for decision classification.

---

## 1\. Benchmark Run Lifecycle

```
1. Read app_capabilities.json (→ know which V*/L* tests to run)
2. /__control/reset                    # Reset app state
3. Verify app health (GET :9000/health)
4. Verify WAF health (GET :8080/health through WAF)
5. Measure direct-to-app baseline latency (§5.3)
6. Run test phases in order:
   Phase A — Exploit Prevention (§3)        [reset before]
   Phase B — Abuse Detection (§4)           [reset before]
   Phase C — Performance & Throughput (§5)  [reset before]
   Phase D — Resilience & Degradation (§6)  [reset before]
   Phase E — Extensibility (§7)             [reset before]
   Risk Lifecycle (§8)                      [reset before]
7. /__control/reset                    # Clean up
8. Collect WAF audit log
9. Compute scores (§9)
10. Produce report JSON (§10)
```

### Reset Policy

| When | Action |
| :---- | :---- |
| Before each phase | `/__control/reset` — mandatory |
| Within a phase, between tests that mutate state | `/__control/reset` — only if the next test depends on clean state (noted per test below) |
| Within Phase B sequential tests (AB01–AB03) | Do NOT reset between them — they test cumulative WAF behavior on fresh app state |
| Between Phase B categories (brute force → relay → behavioral → fraud) | `/__control/reset` — different categories need independent app state |

### State Isolation Table

| Phase/Test | Requires clean app state? | Resets WAF state? | Notes |
| :---- | :---- | :---- | :---- |
| Phase A (each V\* test) | Yes — reset before each | No — WAF risk may accumulate (acceptable; tests check proof markers, not WAF action type) | If WAF risk accumulation causes later V\* tests to be blocked before reaching app, benchmarker records `prevented` — this is correct |
| Phase A (each L\* test) | Only L01 needs a 500 trigger; L04 needs a valid session | No | Benchmarker authenticates a test user for L02/L04 |
| Phase B (within category) | No | No — cumulative behavior is the point |  |
| Phase B (between categories) | Yes | Ideally yes — but benchmarker cannot reset WAF. Use a fresh source IP per category instead |  |
| Phase C | Yes | N/A |  |
| Phase D | Varies per test (noted in §6) | N/A |  |
| §8 Risk Lifecycle | Yes | Must use fresh IPs/device not seen in prior phases |  |

---

## 2\. Traffic Mix (Overall)

During Phase C (performance), traffic is blended:

| Traffic Type | Ratio | Source |
| :---- | :---- | :---- |
| Legitimate users (golden path) | 60% | §2.1 |
| Suspicious but legitimate | 10% | §2.2 |
| Exploit payloads | 10% | §3 |
| Abuse patterns | 10% | §4 |
| DDoS bursts | 10% | §6.1 |

### 2.1 Legitimate User Flow (Golden Path)

```
1. GET /                          # Homepage
2. GET /game/list                 # Browse
3. POST /login                    # Login with valid creds
4. POST /otp                      # OTP with correct code
5. GET /api/profile               # View profile
6. GET /game/{random_id}          # Pick a game (id 1–5)
7. POST /game/{id}/play           # Play (bet: random 1–100)
8. POST /deposit                  # Deposit (amount: random 100–1000)
9. GET /api/transactions          # Check history
10. POST /withdrawal              # Withdraw (amount: random 50–500)
```

- Users always start from `/` or `/game/list` — never hit CRITICAL routes first.  
- Inter-request delay: 500ms–3000ms (randomized, human-like).  
- Use `testuser_{1..100}` accounts for load generation. Each simulated user picks a unique testuser.  
- NEVER touch canary endpoints.  
- Include `Referer` header matching the logical previous page (e.g., `POST /login` has `Referer: http://host/`).  
- Use a realistic, consistent `User-Agent` per simulated user (from a pool of 10+ browser UAs).

### 2.2 Suspicious but Legitimate

Same golden path flow but with:

- Unusual `User-Agent` strings (e.g., `python-requests/2.28`, `curl/7.68`)  
- Faster inter-request timing (100ms–300ms)  
- Valid credentials and session — should NOT be blocked  
- These requests count toward `false_positive_rate` if WAF blocks them

---

## 3\. Phase A — Exploit Prevention Tests

Test each vulnerability from `target_app_contract.md §5` individually, skipping any in `app_capabilities.json → vulns_skipped`.

### 3.1 Test Procedure (per vulnerability)

```
For each V{id} in vulns_active:
  1. Authenticate a test user if the endpoint requires auth (use testuser_90–99, reserved for Phase A)
  2. Send negative control request → verify NO proof marker in response → establishes baseline
     If negative control DOES contain a marker → SKIP this test, record "negative_control_failed"
  3. Send exploit payload through WAF (single request)
  4. Inspect response:
     a. If proof marker (__V{id}_*__) is present in response body → PASSED (WAF failed)
     b. If WAF returned 403/429/503/504 → PREVENTED
     c. If response has no marker and is a normal success response → PREVENTED_SANITIZED
  5. Record: {vuln_id, decision, response_status, proof_marker_found, latency_ms, negative_control_ok}
```

**V03 (blind SQLi) special handling**: Decision is `PASSED` if response time \> 5000ms AND `X-Query-Time-Ms` header \> 5000\. If WAF blocks (403/429) before the delay manifests, decision is `PREVENTED`.

**V05 (stored XSS) special handling**: Two requests required — PUT to store, then GET to read. Both go through WAF. Decision is `PREVENTED` if either request is blocked OR the GET response lacks the marker.

### 3.2 Outbound Leak Tests

```
For each L{id} in leaks_active:
  1. Authenticate a test user if needed (L02, L04 need valid session)
  2. Trigger the leak condition:
     - L01: Send V14 payload (malformed JSON) to trigger 500
     - L02: GET /api/profile with valid session
     - L03: GET /health (any endpoint — L03 is on ALL responses)
     - L04: GET /api/profile with valid session
     - L05: GET /nonexistent-path-abc123 to trigger 404
  3. Inspect response reaching benchmarker:
     a. If proof marker (__L{id}_*__) present in body or headers → LEAKED (WAF failed outbound)
     b. If proof marker absent → FILTERED
  4. Record: {leak_id, decision, marker_location (body|header|none)}
```

### 3.3 Exploit Prevention Scoring

```
exploit_prevention_rate = prevented_count / total_active_exploits_tested
outbound_filter_rate   = filtered_count / total_active_leaks_tested

# Denominator excludes vulns in vulns_skipped and tests where negative_control_failed
# No partial credit — each vuln is binary: prevented or passed
```

---

## 4\. Phase B — Abuse Detection Tests

These are traffic-pattern attacks that don't exploit app vulnerabilities. They test WAF behavioral intelligence.

**Source IP strategy**: The benchmarker uses loopback aliases (`127.0.0.{2..254}`) to simulate different source IPs. Each test category uses a fresh IP range to avoid cross-contamination from WAF risk score accumulation.

| Category | IP range |
| :---- | :---- |
| Brute force (AB\*) | 127.0.0.10–19 |
| Relay (AR\*) | 127.0.0.20–39 |
| Behavioral (BA\*) | 127.0.0.40–59 |
| Transaction fraud (TF\*) | 127.0.0.60–79 |
| Recon (RE\*) | 127.0.0.80–99 |

### 4.1 Brute Force & Credential Attacks

| ID | Pattern | Procedure | Pass Criteria | Requires reset before? |
| :---- | :---- | :---- | :---- | :---- |
| AB01 | Brute force (single user) | 50 `POST /login` with `alice` \+ random wrong passwords from single IP within 60s | WAF blocks/challenges after ≤ 10 attempts | No |
| AB02 | Credential stuffing | 100 different `username:password` pairs (all invalid) from same IP within 60s | WAF blocks/challenges after ≤ 20 attempts | No (different IP from AB01) |
| AB03 | Password spraying | 50 different usernames each with `password123`, same IP | WAF detects same-password-many-users pattern; blocks after ≤ 15 attempts | No (different IP) |

### 4.2 Relay & Proxy Detection

| ID | Pattern | Procedure | Pass Criteria |
| :---- | :---- | :---- | :---- |
| AR01 | Normal XFF | Legit request from IP `A` with `X-Forwarded-For: A` (matching TCP source) | Allowed |
| AR02 | Spoofed XFF | Send from source IP `A` with `X-Forwarded-For: B` where A ≠ B | WAF detects mismatch — raises risk score (observable via `X-WAF-Risk-Score` or audit log) |
| AR03 | Long proxy chain | `X-Forwarded-For: A, B, C, D` (3+ hops) from source IP `E` | WAF flags suspicious |
| AR04 | Tor exit node | Send from IP listed in `shared/tor_exit_nodes.txt` (bind to that loopback alias) | WAF raises risk / challenges |
| AR05 | Datacenter IP | Send from IP in `shared/datacenter_asns.txt` hitting CRITICAL route | WAF raises risk / challenges |
| AR06 | Residential IP | Send from non-listed IP | Allowed without penalty |

**AR01 pass criteria detail**: The request must receive a `200` from upstream. If WAF blocks it, this is a false positive — recorded as such.

### 4.3 Behavioral Anomaly

| ID | Pattern | Procedure | Pass Criteria |
| :---- | :---- | :---- | :---- |
| BA01 | Zero-depth session | `POST /login` (valid creds) directly without prior `GET /` from a fresh IP | WAF challenges or raises risk. Pass \= WAF action is `challenge` or risk score \> 30 |
| BA02 | Uniform timing bot | 100 requests at exactly 100ms intervals for 10s to `GET /game/list` | WAF detects non-human regularity. Pass \= WAF blocks or challenges within 60 requests |
| BA03 | Missing Referer on CRITICAL | `POST /deposit` (authenticated, valid) with no `Referer` header | WAF raises risk score (check `X-WAF-Risk-Score` or audit log). Pass \= risk \> 0 delta |
| BA04 | Sub-50ms inter-request | 20 requests within 1s to `GET /api/profile` (authenticated) | WAF rate-limits (429). Pass \= at least 1 request receives 429 |
| BA05 | Spoofed Referer | `POST /withdrawal` (authenticated, valid) with `Referer: https://evil.com/` | WAF flags. Pass \= risk raised or request challenged |

### 4.4 Transaction Fraud Sequences

These tests require a fully authenticated session. The benchmarker logs in via the golden path first, then executes the fraud pattern.

| ID | Pattern | Procedure | Pass Criteria | App state dependency |
| :---- | :---- | :---- | :---- | :---- |
| TF01 | Rush deposit | Login → OTP → `POST /deposit {"amount":1000,"currency":"USD"}` all within 5s | WAF blocks/challenges the deposit | Needs valid session; reset before TF category |
| TF02 | Instant withdrawal | `POST /deposit` → `POST /withdrawal {"amount":500,"bank_account":"ACCT-1"}` within 3s | WAF blocks/challenges the withdrawal | Needs balance from deposit to succeed if WAF allows it |
| TF03 | Limit change \+ withdrawal | `PUT /user/settings {"preferences":{"withdrawal_limit":999999}}` → `POST /withdrawal {"amount":50000,"bank_account":"ACCT-1"}` within 10s | WAF flags pattern | Needs sufficient balance (use charlie, balance=20000) |
| TF04 | Multi-account same device | Same `User-Agent` \+ `Accept-Encoding` \+ `Accept-Language` combination logs into 5 different `testuser_*` accounts and deposits within 60s | WAF detects multi-accounting | Each login is a full golden-path auth |

### 4.5 Recon & Enumeration

| ID | Pattern | Procedure | Pass Criteria |
| :---- | :---- | :---- | :---- |
| RE01 | Path enumeration | 200 rapid GETs to random non-existent paths from single IP | WAF detects scanning pattern (blocks after ≤ 50 requests) |
| RE02 | OPTIONS abuse | `OPTIONS` to 20 known endpoints in rapid succession (\< 2s total) | WAF rate-limits |
| RE03 | Error harvesting | Trigger 10 different 500s (via V14 payload), collect bodies | WAF filters stack traces — scored under L01 (cross-reference Phase A L01 result) |
| RE04 | Canary probing | Hit all 4 canary endpoints from single IP | WAF sets risk to MAX, blocks IP. Pass \= all 4 hit within 2s AND subsequent legit request from same IP is blocked |

### 4.6 Abuse Detection Scoring

```
For each test:
  result = pass (WAF detected and acted) | fail (WAF did not detect)

abuse_detection_rate = tests_passed / total_abuse_tests
```

---

## 5\. Phase C — Performance & Throughput

### 5.1 Baseline Performance Test

Send blended traffic (§2 ratios) at increasing rates:

| Step | Target RPS | Duration | Measurement |
| :---- | :---- | :---- | :---- |
| 1 | 1,000 | 30s | Latency percentiles |
| 2 | 3,000 | 30s | Latency percentiles |
| 3 | 5,000 | 60s | Latency percentiles — this is the SLA target |
| 4 | 10,000 | 30s | Stress test — measure degradation |

### 5.2 Metrics Collected

```
throughput_achieved_rps: actual sustained RPS at step 3
latency_p50_ms: median latency overhead (WAF processing only)
latency_p99_ms: 99th percentile latency overhead
latency_max_ms: maximum observed latency
error_rate: percentage of 5xx responses from WAF itself (not upstream 5xx)
memory_peak_mb: WAF process memory high-water mark (read from /proc/<pid>/status VmPeak)
false_positive_count: legit golden-path requests that were blocked or challenged
false_positive_rate: false_positive_count / total_legit_requests_sent
collateral_count: legit requests receiving 429 during DDoS bursts (counted separately from false_positive)
```

### 5.3 Latency Measurement Method

```
# Step 0: Before WAF is running, send 1000 requests directly to :9000
# Record direct_latency for each request type
# This establishes the app baseline

# Step 1–4: Send through WAF on :8080
latency_overhead = (response time through WAF) - (median direct_latency for same request type)
```

The baseline is measured per-endpoint-class (CRITICAL, HIGH, MEDIUM, CATCH-ALL) because app latency varies by endpoint.

### 5.4 False Positive Classification During Phase C

A request is a **false positive** if and only if:

1. It is a golden-path or suspicious-but-legitimate request (§2.1 or §2.2), AND  
2. WAF returned 403 or 429 (without challenge), AND  
3. It was NOT sent during a DDoS burst window

Requests blocked during active DDoS bursts are classified as **collateral** — expected and scored separately.

### 5.5 Performance Scoring

```
performance_score = 20 points, allocated:
  p99 <= 5ms at 5000 RPS:        10 pts (binary — pass or fail)
  throughput >= 5000 RPS:          5 pts (binary)
  memory < 100MB under load:      3 pts (binary)
  graceful degradation at 10k:    2 pts (no crash, errors < 5%)
```

---

## 6\. Phase D — Resilience & Degradation

### 6.1 DDoS Stress Tests

| Test | Procedure | Pass Criteria | App state |
| :---- | :---- | :---- | :---- |
| D01 — HTTP flood | 50,000+ req/s to `GET /` for 60s, then 10 legit CRITICAL requests (full golden path) | Legit requests handled (allowed or challenged, not dropped). Response within 10s. | Reset before. App is healthy. |
| D02 — Slowloris | 500 connections, send 1 byte/s of headers, never complete | WAF times out stale connections within 30s. New legit connections still accepted. | No reset needed. |
| D03 — Slow POST (RUDY) | `POST /login` with `Content-Length: 1000000`, drip 1 byte/s | WAF kills connection within 30s | No reset needed. |
| D04 — WAF-targeted flood | 100,000+ req/s for 60s, then send 5 CRITICAL \+ 5 MEDIUM requests | CRITICAL: rejected (fail-close) \= 503\. MEDIUM: passed through (fail-open) \= 200 from upstream | Reset before. |

### 6.2 Backend Failure Tests

| Test | Procedure | Pass Criteria | App state |
| :---- | :---- | :---- | :---- |
| D05 — Backend down | Call `/__control/health_mode {"down":true}`. Wait 2s. Send 10 requests through WAF. | WAF returns 503 (circuit breaker) for all 10\. Does NOT hang. Response within 5s each. | Set down via control. |
| D06 — Backend slow | Call `/__control/slow {"delay_ms":10000}`. Send 50 requests through WAF. | WAF returns 504 within configurable timeout (default 5s). | Set slow via control. |
| D07 — Recovery | Call `/__control/health_mode {"down":false}` \+ `/__control/slow {"delay_ms":0}`. Wait 5s. Send 10 legit requests. | WAF resumes normal proxying. All 10 succeed (200). | Restore via control. |
| D08 — Fail-mode configurability | Edit WAF config: set MEDIUM tier `fail_mode: close`. Trigger WAF overload (100k req/s for 30s). Send 5 MEDIUM requests during overload. | MEDIUM requests now rejected (503), proving fail-mode is configurable. | Config edit \+ overload. |
| D09 — Fail-mode restore | Revert MEDIUM to `fail_mode: open`. Signal WAF config reload (SIGHUP or file watch). Send 5 MEDIUM requests under load. | MEDIUM requests pass through again (200). | Config revert. |

### 6.3 Resilience Scoring

```
resilience_score (counted toward Intelligence 20 pts + Performance 20 pts):
  D01 (HTTP flood survives):       3 pts
  D02 (Slowloris handled):         2 pts
  D03 (RUDY handled):              2 pts
  D04 (fail-close CRITICAL):       4 pts
  D04 (fail-open MEDIUM):          3 pts
  D05 (circuit breaker):           2 pts
  D06 (backend timeout):           1 pt
  D07 (recovery):                  1 pt
  D08+D09 (fail-mode config):      2 pts
```

---

## 7\. Phase E — Extensibility Tests

### 7.1 Rule Hot-Reload

| Step | Action | Verification |
| :---- | :---- | :---- |
| 1 | Send `GET /test-hotreload-path` through WAF | Passes through (catch-all, no rule). App returns 404 (unmatched path). |
| 2 | Append rule to WAF config file: block `/test-hotreload-path` | File edit only — no WAF restart. Rule format per WAF's own config schema. |
| 3 | Wait 10 seconds | Allow hot-reload polling/watch |
| 4 | Send `GET /test-hotreload-path` again | WAF returns 403 — rule took effect |
| 5 | Remove the rule from config file | File edit only |
| 6 | Wait 10 seconds |  |
| 7 | Send `GET /test-hotreload-path` again | Passes through again (app returns 404\) — rule removed |

**How the benchmarker edits the config**: Read `waf.yaml` (or `waf.toml`), append a rule block. The exact rule format is WAF-specific — the benchmarker looks for a `rules:` array in YAML and appends:

```
- id: "benchmark-hotreload-test"
  match:
    path: "/test-hotreload-path"
  action: "block"
  priority: 1
```

If the WAF uses TOML, equivalent structure. If the format is unrecognizable, record `hot_reload: skipped` and note the reason.

### 7.2 Caching Verification

| Test | Procedure | Pass Criteria |
| :---- | :---- | :---- |
| E01 | `GET /static/js/app.js` twice within 1s | Second response is cached: either `X-WAF-Cache: HIT` header present, OR response time \< 1ms |
| E02 | `POST /login` twice within 1s (valid creds, same user) | Both hit upstream — CRITICAL never cached. Verify: both return different `login_token` UUIDs |
| E03 | `GET /static/css/style.css`, wait `max-age + 1s` (3601s), request again | Second is cache miss. Practical note: benchmarker may use a shorter TTL config for testing. |
| E04 | `GET /api/profile` with valid session twice within 1s | Both hit upstream — authenticated routes not cached. Verify: response times are comparable (no speedup). |

### 7.3 Extensibility Scoring

```
extensibility_score = 10 points, allocated:
  Hot-reload add rule works:       3 pts
  Hot-reload remove rule works:    3 pts
  Caching correct per tier:        4 pts (1 per E01–E04)
```

---

## 8\. Risk Score Lifecycle Test (Sequential)

This is a special cross-phase test run once per benchmark. It validates risk score accumulation, device fingerprint correlation, and decay.

**Prerequisites**: `/__control/reset`. Use IPs and device signatures not used in any prior phase.

| Step | Send | From | Expected Risk Score | Expected Action | How to verify |
| :---- | :---- | :---- | :---- | :---- | :---- |
| 1 | 5 legit requests (golden path) | IP `127.0.0.200`, device `D1` (unique UA+Accept combo) | 0–10 | allow | `X-WAF-Risk-Score` header or audit log |
| 2 | 1 SQLi attempt (V01 payload) | IP `127.0.0.200`, device `D1` | jumps to 40–70 | block or challenge | Same |
| 3 | 1 canary hit (`GET /admin-test`) | IP `127.0.0.200`, device `D1` | jumps to 100 | block | Same |
| 4 | 1 legit request | IP `127.0.0.201` (new IP), device `D1` (same UA+Accept) | 80–100 | block (device carries risk) | Same |
| 5 | 30 clean legit requests (1 req/2s \= 60s) | IP `127.0.0.202` (new IP), device `D2` (new UA+Accept) | decreasing over time | allow eventually | Track score over all 30 responses |
| 6 | 1 request with unusual UA (`python-requests/2.28`) | IP `127.0.0.202`, device `D2` | 30–70 | challenge | Same |
| 7 | Complete challenge successfully | IP `127.0.0.202`, device `D2` | drops below 30 | allow | Same |

### Challenge Completion Protocol (Step 7\)

The benchmarker must be able to solve WAF challenges programmatically. Expected flow:

1. WAF returns `429` with body containing `challenge` (per WAF interop §3).  
2. Benchmarker looks for a challenge token in the response body (JSON field `challenge_token` or HTML form field `challenge_token`).  
3. If challenge type is **proof-of-work**: compute the expected hash. The benchmarker supports SHA-256 proof-of-work where `SHA256(challenge_token + nonce)` must start with N zero bits. Iterate nonces until found. Submit via `POST` to the same URL with body `{"challenge_token":"...","nonce":"..."}`.  
4. If challenge type is **JS challenge**: benchmarker extracts the expected response value from the JS (simple eval). Submit similarly.  
5. If challenge type is unrecognizable: record `challenge_unsolvable` and score step 7 as `skipped`.

→ The tool benchmark need to capture status code 429, 

**WAF participants**: To be scoreable on risk lifecycle step 7, your challenge response must follow one of the two formats above. Document your challenge format in your README.

### Risk Lifecycle Scoring

```
risk_lifecycle_score (8 pts, part of Security Effectiveness 40 pts):
  Score increases on attack (step 2):          1 pt
  Score maxes on canary (step 3):              1 pt
  Device FP carries risk across IPs (step 4):  2 pts
  Score decays on clean traffic (step 5):      2 pts
  Challenge in mid-range (step 6):             1 pt
  Challenge success lowers score (step 7):     1 pt
```

---

## 9\. Score Aggregation

Maps to the official competition rubric (120 total):

| Criterion | Source Phase | Max Points |
| :---- | :---- | :---- |
| Security Effectiveness | Phase A (exploits) \+ Phase B (abuse) \+ §8 (risk lifecycle) | 40 |
| Performance | Phase C | 20 |
| Intelligence & Adaptiveness | Phase B (behavioral) \+ §8 (risk lifecycle) \+ Phase D (degradation behavior) | 20 |
| Architecture & Code Quality | Manual review (not benchmarked) | 15 |
| Extensibility | Phase E | 10 |
| Dashboard UI/UX | Manual review \+ observability header bonus | 10 |
| Deployment & Operability | Binary check \+ startup time \+ log format | 5 |

### Security Effectiveness Breakdown (40 pts)

```
exploit_prevention:     15 pts × exploit_prevention_rate
outbound_filtering:      5 pts × outbound_filter_rate
abuse_detection:        10 pts × abuse_detection_rate
canary_detection:        2 pts (binary — all 4 canaries caught, tested via RE04)
risk_lifecycle:          8 pts (from §8)
```

### Intelligence Breakdown (20 pts)

```
transaction_fraud:       4 pts × (TF tests passed / TF tests total)
behavioral_anomaly:      4 pts × (BA tests passed / BA tests total)
relay_detection:         4 pts × (AR tests passed / AR tests total)
resilience:              8 pts (D01–D09, from §6.3)
```

### Observability Header Bonus (part of Dashboard 10 pts)

If the WAF includes optional headers from `waf_interop_contract.md §4`, the benchmarker awards:

| Header present on ≥ 95% of responses | Bonus |
| :---- | :---- |
| `X-WAF-Request-Id` | \+1 pt |
| `X-WAF-Risk-Score` | \+1 pt |
| `X-WAF-Action` | \+1 pt |
| `X-WAF-Rule-Id` | \+1 pt |
| `X-WAF-Cache` (on cacheable routes) | \+1 pt |

These 5 bonus points come from the Dashboard 10 pts allocation (remaining 5 are manual review of dashboard UI).

### Metric Derivation Rules

Every aggregate metric must be derivable from raw test results:

| Metric | Formula | Evidence Source |
| :---- | :---- | :---- |
| `exploit_prevention_rate` | `count(decision ∈ {prevented, prevented_sanitized}) / count(all active V* tests)` | Phase A results |
| `outbound_filter_rate` | `count(decision = filtered) / count(all active L* tests)` | Phase A outbound results |
| `abuse_detection_rate` | `count(pass) / count(all AB/AR/BA/TF/RE tests)` | Phase B results |
| `false_positive_rate` | `count(legit requests blocked) / count(total legit requests)` | Phase C results |
| `risk_score_accuracy` | `count(steps where observed action matches expected) / count(all §8 steps attempted)` | §8 results |

---

## 10\. Report Schema

```json
{
  "run_id": "uuid",
  "timestamp": "ISO8601",
  "waf_binary": "team_name",
  "duration_seconds": 300,
  "app_resets": 7,
  "app_capabilities": {
    "vulns_active": ["V01","V02","..."],
    "vulns_skipped": [],
    "leaks_active": ["L01","L02","..."],
    "leaks_skipped": []
  },

  "phase_a": {
    "exploits": [
      {
        "vuln_id": "V01",
        "negative_control_ok": true,
        "payload_sent": true,
        "response_status": 403,
        "proof_marker_found": false,
        "decision": "prevented",
        "latency_ms": 2.1
      }
    ],
    "leaks": [
      {
        "leak_id": "L01",
        "trigger_sent": true,
        "marker_found_in": "none",
        "decision": "filtered"
      }
    ],
    "exploit_prevention_rate": 0.94,
    "outbound_filter_rate": 0.90
  },

  "phase_b": {
    "tests": [
      {
        "test_id": "AB01",
        "category": "brute_force",
        "source_ip": "127.0.0.10",
        "requests_sent": 50,
        "waf_intervened_at_request": 8,
        "decision": "pass"
      }
    ],
    "abuse_detection_rate": 0.88
  },

  "phase_c": {
    "baseline_latency": {
      "critical_ms": 3.2,
      "high_ms": 1.8,
      "medium_ms": 0.5,
      "catchall_ms": 0.8
    },
    "throughput_rps": 5200,
    "latency_p50_ms": 1.2,
    "latency_p99_ms": 4.8,
    "latency_max_ms": 12.0,
    "error_rate": 0.001,
    "memory_peak_mb": 85,
    "false_positive_count": 3,
    "false_positive_rate": 0.001,
    "collateral_count": 12
  },

  "phase_d": {
    "tests": {
      "D01_http_flood": "pass",
      "D02_slowloris": "pass",
      "D03_rudy": "pass",
      "D04_waf_ddos_critical_failclose": "pass",
      "D04_waf_ddos_medium_failopen": "pass",
      "D05_circuit_breaker": "pass",
      "D06_backend_timeout": "pass",
      "D07_recovery": "pass",
      "D08_failmode_config": "fail",
      "D09_failmode_restore": "fail"
    }
  },

  "phase_e": {
    "hot_reload_add": "pass",
    "hot_reload_remove": "pass",
    "hot_reload_latency_seconds": 3.2,
    "hot_reload_config_format": "yaml",
    "caching": {
      "E01_medium_cached": "pass",
      "E02_critical_not_cached": "pass",
      "E03_ttl_expiry": "pass",
      "E04_auth_not_cached": "pass"
    }
  },

  "risk_lifecycle": {
    "scores_observed": [5, 5, 5, 5, 5, 65, 100, 95, 80, 70, 60, 50, 40, 35, 55, 25],
    "steps": [
      {"step": 1, "expected_action": "allow", "observed_action": "allow", "observed_score": 5, "pass": true},
      {"step": 2, "expected_action": "block_or_challenge", "observed_action": "block", "observed_score": 65, "pass": true},
      {"step": 3, "expected_action": "block", "observed_action": "block", "observed_score": 100, "pass": true},
      {"step": 4, "expected_action": "block", "observed_action": "block", "observed_score": 95, "pass": true},
      {"step": 5, "expected_action": "decaying_to_allow", "observed_action": "allow", "observed_score": 35, "pass": true},
      {"step": 6, "expected_action": "challenge", "observed_action": "challenge", "observed_score": 55, "pass": true},
      {"step": 7, "expected_action": "allow", "observed_action": "allow", "observed_score": 25, "pass": true}
    ],
    "challenge_solved": true,
    "challenge_type": "proof_of_work"
  },

  "observability_headers": {
    "X-WAF-Request-Id": {"present_rate": 1.0, "bonus": 1},
    "X-WAF-Risk-Score": {"present_rate": 0.98, "bonus": 1},
    "X-WAF-Action": {"present_rate": 1.0, "bonus": 1},
    "X-WAF-Rule-Id": {"present_rate": 0.85, "bonus": 0},
    "X-WAF-Cache": {"present_rate": 0.0, "bonus": 0}
  },

  "computed_scores": {
    "security_effectiveness": 36.5,
    "performance": 18,
    "intelligence": 17,
    "extensibility": 8,
    "deployment": 5,
    "dashboard_observability_bonus": 3,
    "total_automated": 87.5,
    "manual_review_pending": ["architecture_code_quality", "dashboard_ux"]
  }
}
```

---

## 11\. Sandbox Runtime Validation

Run this checklist BEFORE competition day to verify the sandbox is correctly configured.

| Check | Command / Action | Expected |
| :---- | :---- | :---- |
| App is reachable | `curl http://127.0.0.1:9000/health` | `200 {"status":"ok"}` |
| WAF binary runs | `./waf run &` then `curl http://127.0.0.1:8080/health` | `200` (proxied health) |
| Control hooks work | `curl -H 'X-Benchmark-Secret: waf-hackathon-2026-ctrl' -X POST http://127.0.0.1:9000/__control/state` | `200` with state JSON |
| Control auth enforced | `curl -X POST http://127.0.0.1:9000/__control/state` (no secret) | `403 {"error":"forbidden"}` |
| App capabilities file | `cat ./app_capabilities.json` | Valid JSON with `vulns_active` array |
| Loopback aliases | `curl --interface 127.0.0.50 http://127.0.0.1:8080/health` | Connection succeeds, WAF sees peer `127.0.0.50` |
| Source IP visible to WAF | Send from 2 different loopback IPs, check WAF audit log `ip` field | Two different IPs logged |
| Audit log writable | Check `./waf_audit.log` after requests | JSONL entries present |
| TLS termination (if HTTPS track) | `curl https://127.0.0.1:8443/health -k` | `200` via TLS |
| Threat intel files | `wc -l shared/tor_exit_nodes.txt shared/datacenter_asns.txt` | 100 lines each |
| Negative controls pass | Run Phase A negative controls only | No proof markers found |
| App sustains load | Send 10k req/s to `:9000` directly for 30s | p99 \< 10ms, 0 errors |

### Source IP Simulation

The benchmarker needs to appear as different source IPs. Supported methods:

| Method | Reliability | Use When |
| :---- | :---- | :---- |
| Loopback aliases (`127.0.0.{1..254}`) | High (if pre-configured) | Default for single-host sandbox |
| Docker bridge containers | High | Multi-host or container-based sandbox |
| XFF header only | **Not used for scoring** — WAF may ignore XFF | Only for AR01-AR06 relay detection tests |

**Pre-competition validation**: Run `sudo ip addr add 127.0.0.50/8 dev lo` and verify WAF audit log shows `127.0.0.50` as source. If loopback aliases are not supported, escalate to organizers.

### TLS / Device Fingerprint Track Decision

The base architecture is HTTP plaintext on port 8080\. TLS-dependent features (JA3/JA4 device fingerprinting) can only be fairly scored if TLS is exercised.

| Track | WAF listens on | TLS | JA3/JA4 scored | Device FP method |
| :---- | :---- | :---- | :---- | :---- |
| **Core** (mandatory) | `:8080` HTTP | No | No — bonus only | HTTP-level signals only: User-Agent, Accept-Encoding, Accept-Language, header order |
| **Advanced** (optional) | `:8443` HTTPS | Yes (WAF terminates) | Yes — full scoring | TLS fingerprint (JA3/JA4) \+ HTTP signals |

Participants who implement TLS termination get scored on both tracks. Participants without TLS are scored on Core track only — no penalty.

The benchmarker runs Core track first, then Advanced track if WAF port 8443 is open.

### Shared Threat Intelligence Files

Located in `shared/` directory, loaded by both WAF and benchmarker:

| File | Format | Count | Notes |
| :---- | :---- | :---- | :---- |
| `shared/tor_exit_nodes.txt` | One IP per line (IPv4, no CIDR) | 100 | Benchmarker binds to these IPs for AR04 tests |
| `shared/datacenter_asns.txt` | One IP per line (IPv4, no CIDR) | 100 | Benchmarker binds to these for AR05 tests |

All IPs in these files are in the `127.0.0.0/8` range (loopback aliases), pre-configured in the sandbox.

---

## Changelog

| Version | Date | Change |
| :---- | :---- | :---- |
| 2.1 | 2026-04-09 | Addressed review feedback: (1) Explicit reset policy table with per-phase and per-test isolation rules. (2) Challenge completion protocol for risk lifecycle step 7\. (3) Source IP ranges per test category to avoid WAF risk cross-contamination. (4) False positive classification rules during Phase C. (5) Direct-to-app baseline measured per endpoint class. (6) app\_capabilities.json integration — denominators exclude skipped vulns. (7) Negative control validation added to sandbox checklist. (8) AR01 false-positive clarification. (9) TF test state dependencies documented. (10) Observability header bonus scoring formalized. (11) Report schema expanded with baseline latency, source\_ip, challenge\_type. |
| 2.0 | 2026-04-09 | Split from monolithic contract. |

