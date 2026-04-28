# Target App Contract v2.1

**Audience**: Vuln App Developer · Benchmarking Tool Developer **Scope**: ONLY what the target application exposes. Nothing about WAF behavior, scoring, or sandbox ops. **Note**: This app is benchmark-instrumented and intentionally vulnerable. It is not intended to represent a WAF-unaware production backend.

---

## 1\. Architecture

```
[Benchmarking Tool] --HTTP/HTTPS--> [WAF Binary] --HTTP--> :9000 [Vuln App]
```

- **App listens on**: `0.0.0.0:9000` (plaintext HTTP only — TLS terminates at the WAF)  
- **All API responses**: `Content-Type: application/json; charset=utf-8` unless noted  
- **Character encoding**: UTF-8 everywhere  
- **The app trusts ALL incoming headers unconditionally.** It does NOT inspect `X-Forwarded-For`, `Host`, or any proxy headers for security purposes. Header trust is the WAF's responsibility.

---

## 2\. Authentication Model

Single linear flow, one auth mechanism post-OTP:

```
POST /login  →  login_token (short-lived, opaque)
POST /otp    →  Sets cookie: sid=<session_id>
All subsequent routes  →  Cookie: sid=<session_id>
```

| Token | Format | Lifetime | Transport | Purpose |
| :---- | :---- | :---- | :---- | :---- |
| `login_token` | UUID v4 | 5 min | JSON response body only | Passed to `/otp` to prove login succeeded |
| `session_id` (aka `sid`) | UUID v4 | 30 min sliding (reset on each authenticated request) | `Set-Cookie: sid=<val>; Path=/; HttpOnly; SameSite=Strict` | All authenticated routes after OTP |

**Rules:**

- `login_token` is NOT valid for any route other than `POST /otp`.  
- After OTP, `login_token` is consumed and invalidated.  
- All authenticated routes require `Cookie: sid=<session_id>`. No JWT, no body-embedded session IDs.  
- Missing or invalid `sid` → `401 {"error":"unauthorized"}`.  
- Concurrent logins for the same user are allowed — each produces an independent session.

---

## 3\. Seeded Users

Pre-loaded on every app start and on `/__control/reset`.

| username | password | otp\_code | user\_id | initial\_balance |
| :---- | :---- | :---- | :---- | :---- |
| `alice` | `P@ssw0rd1` | `123456` | 1 | 10000 |
| `bob` | `S3cureP@ss` | `654321` | 2 | 5000 |
| `charlie` | `Ch@rlie99` | `111222` | 3 | 20000 |
| `testuser_{1..100}` | `Test#{n}Pass` | `{n:06d}` | 100+n | 1000 |

Each user also has seeded PII fields:

- `card_number`: `"__L04_PII__4111-XXXX-XXXX-{user_id:04d}"`  
- `bank_account`: `"__L04_PII__ACCT-{user_id:06d}"`  
- `ssn`: `"__L04_PII__000-00-{user_id:04d}"`

---

## 4\. Endpoint Catalog

### 4.1 CRITICAL Tier

**POST /login**

```
Request:  {"username": "str", "password": "str"}
Success:  200 {"login_token": "uuid", "user_id": int}
Failure:  401 {"error": "invalid_credentials"}
Auth:     None
Side-effects: Creates login_token valid for 5 min
Rate behavior: App NEVER rate-limits. Responds identically on 1st and 10000th attempt.
```

**POST /otp**

```
Request:  {"login_token": "uuid", "otp_code": "str (6 digits)"}
Success:  200 {"verified": true, "session_id": "uuid"}
          + Set-Cookie: sid=<session_id>; Path=/; HttpOnly; SameSite=Strict
Failure:  401 {"error": "invalid_otp"}
Auth:     Valid login_token
Side-effects: Consumes login_token, creates session
```

**POST /deposit**

```
Request:  {"amount": number, "currency": "USD"}
Success:  200 {"tx_id": "uuid", "balance": number}
Failure:  400 {"error": "invalid_amount"} | 401 {"error": "unauthorized"}
Auth:     Cookie sid
Constraints: amount must be > 0 and <= 1000000. Non-numeric or missing → 400.
Side-effects: Increases balance, creates transaction record
```

**POST /withdrawal**

```
Request:  {"amount": number, "bank_account": "str"}
Success:  200 {"tx_id": "uuid", "status": "pending", "balance": number}
Failure:  400 {"error": "insufficient_balance"} | 401 {"error": "unauthorized"}
Auth:     Cookie sid
Constraints: amount must be > 0 and <= user's withdrawal_limit (default 10000). Over limit → 400 {"error":"exceeds_limit"}.
Side-effects: Decreases balance, creates transaction record
```

### 4.2 HIGH Tier

**GET /game/list**

```
Success:  200 [{"id": int, "name": "str", "status": "str"}]
Auth:     None
Seeded data: 5 games with ids 1–5, status "active"
```

**GET /game/:id**

```
Success:  200 {"id": int, "name": "str", "status": "str", "description": "str"}
Failure:  404 {"error": "not_found"}
Auth:     None
```

**POST /game/:id/play**

```
Request:  {"bet": number}
Success:  200 {"result": "win|lose", "payout": number, "balance": number}
Failure:  400 | 401 | 404
Auth:     Cookie sid
Determinism: result is random (no seeded RNG). Benchmarker must not depend on win/lose outcome.
Side-effects: Adjusts balance, creates transaction record
```

**GET /api/profile**

```
Success:  200 {
  "user_id": int,
  "username": "str",
  "email": "str",
  "display_name": "str",
  "balance": number,
  "card_number": "str",       ← PII: always present, WAF should redact
  "bank_account": "str",      ← PII: always present, WAF should redact
  "ssn": "str"                ← PII: always present, WAF should redact
}
Auth:     Cookie sid
```

**PUT /api/profile**

```
Request:  {"email": "str", "display_name": "str"}
Success:  200 {"updated": true}
Auth:     Cookie sid
Side-effects: Updates profile fields. App does NOT sanitize input — stores raw values (enables stored XSS).
```

**GET /api/transactions**

```
Query:    ?page=int&limit=int (default page=1, limit=20, max limit=100)
Success:  200 {"items": [{"tx_id":"uuid","type":"deposit|withdrawal|bet","amount":number,"ts":"ISO8601"}], "total": int, "page": int}
Auth:     Cookie sid
```

**GET /user/settings**

```
Success:  200 {"preferences": {"withdrawal_limit": number, "notifications": bool}}
Auth:     Cookie sid
```

**PUT /user/settings**

```
Request:  {"preferences": {"withdrawal_limit": number}}
Success:  200 {"updated": true}
Auth:     Cookie sid
Side-effects: Updates settings. No server-side validation on withdrawal_limit (accepts any positive number).
```

### 4.3 MEDIUM Tier

| Method | Path | Content-Type | Size | Cache header |
| :---- | :---- | :---- | :---- | :---- |
| GET | `/static/js/app.js` | `application/javascript` | \~50KB | `Cache-Control: public, max-age=3600` \+ `ETag` |
| GET | `/static/css/style.css` | `text/css` | \~10KB | same |
| GET | `/assets/logo.png` | `image/png` | \~5KB | same |
| GET | `/public/terms.html` | `text/html` | \~2KB | same |
| GET | `/public/faq.html` | `text/html` | \~2KB | same |

Static file responses are **byte-identical** across requests (deterministic content, deterministic ETag). No proof markers ever appear in static file content.

### 4.4 CATCH-ALL Tier

| Method | Path | Response | Notes |
| :---- | :---- | :---- | :---- |
| GET | `/` | `200` HTML homepage | Links to `/game/list`, `/about`, `/public/*` ONLY. No links to canaries, no links to API routes. |
| GET | `/about` | `200` HTML page |  |
| GET | `/health` | `200 {"status":"ok"}` | Infra-only, not linked anywhere |
| GET | `/sitemap.xml` | `200` XML | Lists ONLY: `/`, `/about`, `/game/list`, `/public/terms.html`, `/public/faq.html`. No canaries, no API routes, no debug paths. |
| ANY | `/*` (unmatched) | `404 {"error":"not_found"}` | Normal mode: no path disclosure. Leak mode (L05): see §6. |

### 4.5 Canary Endpoints

These exist in the app but are NEVER linked from any page, sitemap, response body, or error message. Legitimate benchmark traffic never touches them.

| Method | Path | Response |
| :---- | :---- | :---- |
| GET | `/admin-test` | `200 {"admin":true,"marker":"__CANARY_HIT__"}` |
| GET | `/api-debug` | `200 {"debug_info":{"db":"postgres://internal:5432"},"marker":"__CANARY_HIT__"}` |
| GET | `/.env` | `200` text: `DB_PASSWORD=secret123\n__CANARY_HIT__` |
| GET | `/wp-admin` | `200` HTML containing `__CANARY_HIT__` |

Canary responses have **no special headers**. Status is always `200`. The app does NOT set any header signaling these are canaries.

### 4.6 Global Error Schema

```json
{"error": "string_error_code", "message": "Optional human-readable detail"}
```

Status codes: `400` bad request, `401` unauthorized, `404` not found, `500` internal error.

The full set of `error` string codes used by the app:

| Code | Used by |
| :---- | :---- |
| `invalid_credentials` | POST /login |
| `invalid_otp` | POST /otp |
| `unauthorized` | Any authenticated route with bad/missing sid |
| `invalid_amount` | POST /deposit, POST /game/:id/play |
| `insufficient_balance` | POST /withdrawal |
| `exceeds_limit` | POST /withdrawal |
| `not_found` | GET /game/:id (invalid id), ANY unmatched route |
| `internal_error` | Any 500 |

Unknown JSON fields in request bodies are silently ignored. Header names are case-insensitive per HTTP spec.

---

## 5\. Vulnerability Catalog (Inbound Exploits)

Each vulnerability is intentionally embedded in the app. Proof markers are synthetic strings that ONLY appear when exploitation succeeds. No marker ever appears in legitimate responses.

### Proof Marker Invariant

**The app guarantees**: No proof marker matching the regex `__[VL]\d+[a-b]?_\w+__` will ever appear in any response to a legitimate request (valid credentials, well-formed input, no attack payload). This is the single source of truth for distinguishing exploit success from normal behavior.

### 5.1 Injection Vulnerabilities

| ID | Vector | Endpoint | Method | Example Payload | Proof Marker | Negative Control |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| V01 | SQLi (classic) | `/login` | POST | `{"username":"' OR 1=1--","password":"x"}` | `__V01_LOGIN_BYPASS__` in body alongside a valid `login_token` | Normal login with valid creds: `login_token` present, no marker. Normal login with wrong creds: `401`, no marker. |
| V02 | SQLi (UNION) | `/api/transactions?page=0 UNION SELECT 1,username,password,0 FROM users--` | GET | UNION in page param | `__V02_USER_DUMP__` prepended to each leaked row | Normal `?page=1` with valid session returns clean transaction list, no marker |
| V03 | SQLi (blind/time) | `/login` | POST | `{"username":"' AND SLEEP(5)--","password":"x"}` | Response time \> 5000ms AND app sets header `X-Query-Time-Ms: <value>` where value \> 5000 | Normal login responds in \< 100ms, no `X-Query-Time-Ms` header |
| V04 | XSS (reflected) | `/game/1?name=<script>__V04_XSS__</script>` | GET | Script in query param | `__V04_XSS__` unescaped in response body | Normal `GET /game/1` (no `name` param) has no marker |
| V05 | XSS (stored) | `/api/profile` | PUT | `{"display_name":"<img onerror=__V05_STORED_XSS__>"}` | Subsequent `GET /api/profile` contains `__V05_STORED_XSS__` unescaped | Clean profile (after reset) has no marker |
| V06 | Path Traversal | `/static/../../../etc/passwd` | GET | `../` sequences | `__V06_TRAVERSAL__` in body (app serves fake `/etc/passwd` containing this) | Normal `GET /static/js/app.js` has no marker |
| V07 | Path Traversal (encoded) | `/static/%2e%2e/%2e%2e/%2e%2e/etc/passwd` | GET | URL-encoded `../` | `__V07_TRAVERSAL_ENC__` in body (same fake file, different marker) | Normal `GET /static/js/app.js` has no marker |
| V08 | SSRF (metadata) | `/api/profile` | PUT | `{"email":"http://169.254.169.254/latest/meta-data/"}` | `__V08_SSRF_META__` in response body | Normal `PUT /api/profile {"email":"user@example.com","display_name":"Alice"}` returns `{"updated":true}`, no marker |
| V09 | SSRF (internal) | `/game/1/play` | POST | `{"bet":1,"callback_url":"http://127.0.0.1:9000/health"}` | `__V09_SSRF_INTERNAL__` in response body | Normal `POST /game/1/play {"bet":1}` (no `callback_url`) returns game result, no marker |
| V10 | CRLF / Header Injection | Any endpoint | ANY | Header `X-Custom: val\r\nX-Injected: __V10_CRLF__` | Response contains header `X-Injected` with value `__V10_CRLF__` | Normal request (no `X-Custom` header) has no `X-Injected` header |
| V11 | Host Header Injection | `/` | GET | `Host: evil.com` | Response body contains `__V11_HOST_INJECT__` in a link href | Normal request with legitimate `Host` produces no marker |
| V16 | Content-Type Mismatch | `/login` | POST | `Content-Type: text/plain` but JSON body `{"username":"' OR 1=1--","password":"x"}` | `__V16_CTYPE_BYPASS__` in body alongside login\_token | Normal login with correct `Content-Type: application/json` and valid creds: `login_token` present, no marker |

### 5.2 Parser Abuse Vulnerabilities

| ID | Vector | Endpoint | Method | Example Payload | Proof Marker | Negative Control |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| V14 | Malformed JSON | `/deposit` | POST | `{"amount":1e999999}` | `__V14_MALFORMED__` in 500 body | Normal deposit `{"amount":100,"currency":"USD"}` returns 200, no marker |
| V15 | Oversized Payload | `/deposit` | POST | 10MB body (any content) | `__V15_OVERSIZE__` in 500 body | Normal deposit under 1MB returns 200, no marker |
| V19 | Deeply Nested JSON | `/deposit` | POST | `{"a":{"a":{...}}}` 100+ levels deep | `__V19_NESTED__` in 500 body | Normal deposit with flat JSON returns 200, no marker |

### 5.3 Framework Behavior Notes

Some vulnerabilities depend on the app's framework/runtime NOT sanitizing certain inputs:

| ID | Dependency | App developer must ensure |
| :---- | :---- | :---- |
| V06/V07 | Path normalization | App router must NOT normalize `../` before handler — use a raw path handler for `/static/*` |
| V10 | CRLF handling | App must copy custom request headers to response without sanitizing `\r\n` |
| V11 | Host header | App must use raw `Host` header in response body generation |
| V16 | Content-Type parsing | App must parse JSON from body regardless of Content-Type header |

If the chosen framework prevents any of these, the vuln app developer must work around it or document that the vulnerability cannot be reliably produced, and the benchmarker will skip that test.

### 5.4 Vulnerability Availability Declaration

On startup, the app writes a file `./app_capabilities.json`:

```json
{
  "vulns_active": ["V01","V02","V03","V04","V05","V06","V07","V08","V09","V10","V11","V14","V15","V16","V19"],
  "vulns_skipped": [],
  "leaks_active": ["L01","L02","L03","L04","L05"],
  "leaks_skipped": [],
  "skip_reasons": {}
}
```

If the framework prevents a vulnerability, move it to `vulns_skipped` and add a reason. The benchmarker reads this file and adjusts denominators accordingly.

---

## 6\. Response Leak Catalog (Outbound)

These leaks are always active in normal mode. The WAF should filter them.

| ID | Leak Type | Trigger | What Leaks | Proof Marker | Negative Control |
| :---- | :---- | :---- | :---- | :---- | :---- |
| L01 | Stack trace | Any `500` error (e.g., V14/V15/V19 triggers) | Full stack trace with file paths | `__L01_STACKTRACE__` embedded in trace text | Non-500 responses never contain `__L01_STACKTRACE__` |
| L02 | Internal IP header | Every response from `GET /api/profile` (success or error) | Response header `X-Internal-Host: __L02_INTERNAL_IP__10.0.1.45` | Header present with `__L02_INTERNAL_IP__` | Other endpoints do NOT emit `X-Internal-Host` |
| L03 | Debug SQL header | Every response from ALL endpoints | Response header `X-Debug-Query: SELECT ... __L03_DEBUG_SQL__` | Header present with `__L03_DEBUG_SQL__` | (Always present — no negative control needed; WAF must strip it) |
| L04 | PII fields | `GET /api/profile` success | `card_number`, `bank_account`, `ssn` fields containing `__L04_PII__` prefix | Any of these fields present with `__L04_PII__` in value | Unauthenticated request returns `401` with no PII fields |
| L05 | Verbose 404 | Any `404` response | `"tried_paths":["/var/www/app/__L05_VERBOSE_404__/..."]` in body | `__L05_VERBOSE_404__` in body | `200` responses never contain `__L05_VERBOSE_404__` |

---

## 7\. Backend Control Hooks

Internal-only endpoints for deterministic benchmark testing. Accessible ONLY via direct call to `:9000` (bypassing WAF). Restricted to requests containing header `X-Benchmark-Secret: waf-hackathon-2026-ctrl`.

Missing or wrong `X-Benchmark-Secret` → `403 {"error":"forbidden"}`.

| Method | Path | Request Body | Effect | Response |
| :---- | :---- | :---- | :---- | :---- |
| POST | `/__control/reset` | None | Reset ALL data to initial seeded state (users, balances, transactions, stored XSS, settings, sessions). Runs synchronously — returns only after reset is complete. | `200 {"reset":true,"ts":"ISO8601"}` |
| POST | `/__control/slow` | `{"delay_ms": int}` | Add artificial delay to all subsequent responses. `0` \= disable. Delay is added AFTER processing (response body is computed, then delayed). | `200 {"delay_ms":int}` |
| POST | `/__control/error_mode` | \`{"mode": "normal | crash | timeout"}\` |
| POST | `/__control/health_mode` | `{"down": bool}` | `true` \= stop accepting NEW connections on port 9000 (simulate backend down). The control response itself is sent first, then the listener stops. `false` \= resume accepting connections. | `200 {"down":bool}` |
| GET | `/__control/state` | None | Inspect app state | `200 {"users_count":int,"active_sessions":int,"transactions_count":int,"stored_xss_active":bool,"delay_ms":int,"error_mode":"str","down":bool}` |

These endpoints are NOT proxied through the WAF. Benchmarker calls them directly on port 9000\. Control hooks are NOT affected by `error_mode` or `slow` — they always respond normally and immediately.

---

## 8\. State & Concurrency Model

### Reset semantics

- `POST /__control/reset` restores ALL data to §3 initial values.  
- Reset is **synchronous and atomic**: no requests are partially served during reset. In-flight requests to other endpoints receive `503 {"error":"resetting"}` during reset.  
- Benchmarker MUST call reset before every scored run.  
- Stored XSS (V05), modified profiles, changed settings, transaction history, and all sessions are cleared.

### Concurrency rules

- `tx_id` is always a unique UUID v4 — never duplicated.  
- Deposits are non-idempotent: two identical POSTs \= two transactions.  
- Withdrawals succeed if `balance >= amount` at execution time. No optimistic locking — under high concurrency, balance may go negative by a small margin (race condition is acceptable).  
- The app has NO rate limiting, NO anti-fraud, NO bot detection. That is the WAF's job.

### State drift

- Balances change as deposits/withdrawals execute during a run.  
- Transaction history grows.  
- Profile data may be modified by V05/V08 payloads.  
- This is expected. Benchmarker should call `/__control/reset` between test phases if deterministic state is needed.

### Performance guarantees under load

- The app MUST sustain **10,000 req/s** with \< 10ms p99 latency for non-exploit, non-control endpoints.  
- Under load, the app's behavior is **deterministic**: same input → same output (except `tx_id` UUIDs and `game/play` randomness). No requests are silently dropped.  
- If the app cannot sustain the target RPS, the benchmarker's latency overhead measurement (§5.3 of benchmark spec) becomes inaccurate. The app developer must load-test independently.

---

## 9\. Shared Constants

```
app_host: "0.0.0.0"
app_port: 9000
session_cookie_name: "sid"
content_type: "application/json; charset=utf-8"
max_request_body_bytes: 1048576          # 1MB — anything over triggers V15
static_cache_control: "public, max-age=3600"
control_secret: "waf-hackathon-2026-ctrl"
control_prefix: "/__control"

canary_paths:
  - "/admin-test"
  - "/api-debug"
  - "/.env"
  - "/wp-admin"

pii_fields:
  - "card_number"
  - "bank_account"
  - "ssn"

leak_headers_emitted_by_app:
  - "X-Internal-Host"
  - "X-Debug-Query"

proof_marker_regex: "__[VL]\\d+[a-b]?_\\w+__"   # Matches all synthetic markers

capabilities_file: "./app_capabilities.json"      # Written on startup
```

---

## 10\. Network & Header Behavior

The app is header-naive by design:

| Header | App behavior | Implication for WAF |
| :---- | :---- | :---- |
| `Host` | Used raw in HTML output (enables V11) | WAF must validate/rewrite before proxying |
| `X-Forwarded-For` | Ignored entirely | WAF decides trust policy; app never sees real client IP |
| `X-Real-IP` | Ignored | Same |
| `X-Custom` / arbitrary headers | Echoed in response if present (enables V10) | WAF must sanitize before proxying |
| `Content-Type` | Ignored for parsing — always attempts JSON parse (enables V16) | WAF may enforce Content-Type match |
| `Cookie: sid=...` | Used for auth | WAF must forward `Cookie` header intact for authenticated routes |

The app logs the TCP peer address (always `127.0.0.1` since the WAF is on the same host). It does NOT log any proxy headers. Source IP attribution is the WAF's responsibility.

---

## Changelog

| Version | Date | Change |
| :---- | :---- | :---- |
| 2.1 | 2026-04-09 | Addressed review feedback: (1) Added §10 header/network trust boundary section. (2) Reset is now specified as synchronous/atomic with in-flight behavior. (3) Added performance guarantees under load (§8). (4) Added `app_capabilities.json` for skipped vulns (§5.4). (5) Added negative controls for all leaks (§6). (6) Explicit error codes enumerated (§4.6). (7) Session sliding lifetime clarified. (8) Withdrawal limit interaction documented. (9) Control hooks unaffected by error\_mode. (10) Concurrent login behavior specified. |
| 2.0 | 2026-04-09 | Full rewrite from v1.2 monolithic contract. |

