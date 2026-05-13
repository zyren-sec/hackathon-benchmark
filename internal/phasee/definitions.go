package phasee

import "strings"

// GetETests returns Phase E test definitions (EXT-03 only — v2.5).
// EXT-01 and EXT-02 are evaluated manually by BTC; not part of automated benchmark.
// Source: phase_E.md v2.5 §4–§5
func GetETests(wafBaseURL, wafAdminURL string) []ETest {
	return []ETest{
		// ── CAT 1: Caching Correctness Tests ──

		// EXT-03 — Caching Correctness (composite)
		{
			ID:         "EXT-03",
			Name:       "Caching Correctness",
			Category:   "caching",
			Criterion:  "EXT",
			MaxScore:   4.0,
			Description: "Kiểm tra cache behavior của WAF theo route tier: STATIC routes phải được cache (X-WAF-Cache: HIT), CRITICAL và authenticated routes KHÔNG được cache, TTL phải được tôn trọng.",
			PassCriterion: "E01: STATIC route cached (HIT); E02: CRITICAL route NOT cached; E03: TTL expiry works; E04: Authenticated route NOT cached. Mỗi sub-test 1 điểm (binary).",
			FailReasons: map[string]string{
				"e01_fail": "E01: STATIC /static/js/app.js not cached (no HIT on second request)",
				"e02_fail": "E02: CRITICAL /login was cached (got HIT) — critical routes should never cache",
				"e03_fail": "E03: STATIC TTL not respected — stale cache served after TTL expiry",
				"e04_fail": "E04: Authenticated /api/profile was cached — auth routes should never cache",
				"cache_header_missing": "X-WAF-Cache header missing — cannot verify HIT/MISS",
			},
			SourceIP:  "127.0.0.90",
			CacheTest: true,
			VerifyRoutes: []EVerifyRoute{
				{Method: "GET", Endpoint: "/static/js/app.js", ExpectedCode: 200, ExpectedCache: "HIT", Tier: "STATIC", Description: "E01: Static JS"},
				{Method: "POST", Endpoint: "/login", ExpectedCode: 200, ExpectedCache: "", Tier: "CRITICAL", Description: "E02: Login"},
				{Method: "GET", Endpoint: "/static/css/style.css", ExpectedCode: 200, ExpectedCache: "HIT", Tier: "STATIC", Description: "E03: Static CSS"},
				{Method: "GET", Endpoint: "/api/profile", ExpectedCode: 200, ExpectedCache: "", Tier: "MEDIUM", Description: "E04: Profile (auth)", WithAuth: true},
			},
			ReproduceScript: reproduceEXT03(wafBaseURL, wafAdminURL),
		},
	}
}

// ── Reproduce Scripts ──

func reproduceEXT01(wafBaseURL, wafAdminURL string) string {
	return applyURLs(`#!/bin/bash
# Phase E — EXT-01 Hot-Reload Add Rule Reproduction

echo "=== EXT-01: Hot-Reload Add Rule ==="

WAF_CONFIG="/var/www/waf.yaml"
WAF_URL="http://127.0.0.1:8080"
WAF_ADMIN="http://127.0.0.1:8081"

# Step 1: Verify baseline — /test-hotreload-path should be allowed (no rule yet)
echo "--- Baseline: /test-hotreload-path before adding rule ---"
BASELINE=$(curl -s -o /dev/null -w "%{http_code}" ${WAF_URL}/test-hotreload-path)
echo "HTTP Status: ${BASELINE}"
if [ "${BASELINE}" = "403" ]; then
  echo "WARNING: /test-hotreload-path already blocked — may have leftover rule from previous run"
fi

# Step 2: Add rule to WAF config
echo ""
echo "--- Adding benchmark-hotreload-test rule ---"
if [ -f "${WAF_CONFIG}" ]; then
  # YAML format
  echo '- id: "benchmark-hotreload-test"' >> ${WAF_CONFIG}
  echo '  match:' >> ${WAF_CONFIG}
  echo '    path: "/test-hotreload-path"' >> ${WAF_CONFIG}
  echo '  action: "block"' >> ${WAF_CONFIG}
  echo '  priority: 1' >> ${WAF_CONFIG}
  echo "Rule appended to ${WAF_CONFIG}"
else
  WAF_CONFIG="/var/www/waf.toml"
  if [ -f "${WAF_CONFIG}" ]; then
    echo '[[rules]]' >> ${WAF_CONFIG}
    echo 'id = "benchmark-hotreload-test"' >> ${WAF_CONFIG}
    echo 'action = "block"' >> ${WAF_CONFIG}
    echo 'priority = 1' >> ${WAF_CONFIG}
    echo '' >> ${WAF_CONFIG}
    echo '[rules.match]' >> ${WAF_CONFIG}
    echo 'path = "/test-hotreload-path"' >> ${WAF_CONFIG}
    echo "Rule appended to ${WAF_CONFIG}"
  else
    echo "ERROR: WAF config not found"
    exit 1
  fi
fi

# Step 3: Hot-reload WAF
echo ""
echo "--- Hot-reloading WAF ---"
curl -s -X POST ${WAF_ADMIN}/__waf_control/reload

# Step 4: Wait for SLA (max 10s) then verify
echo ""
echo "--- Waiting 5s for rule to take effect ---"
sleep 5

echo "--- Verification: /test-hotreload-path (expect 403 BLOCK) ---"
for i in 1 2 3; do
  RESULT=$(curl -s -w "\nHTTP:%{http_code} | X-WAF-Action:%header{X-WAF-Action}" ${WAF_URL}/test-hotreload-path)
  echo "Request $i: $RESULT"
done

echo ""
echo "=== EXT-01 Complete ==="
echo "Pass criterion: Rule takes effect within 10s → /test-hotreload-path returns 403"
echo "Binary: pass = +3 pts, fail = 0 pts"`, wafBaseURL, wafAdminURL)
}

func reproduceEXT02(wafBaseURL, wafAdminURL string) string {
	return applyURLs(`#!/bin/bash
# Phase E — EXT-02 Hot-Reload Remove Rule Reproduction

echo "=== EXT-02: Hot-Reload Remove Rule ==="

WAF_CONFIG="/var/www/waf.yaml"
WAF_URL="http://127.0.0.1:8080"
WAF_ADMIN="http://127.0.0.1:8081"

# Step 1: Verify current state — /test-hotreload-path should be blocked (from EXT-01)
echo "--- Current state: /test-hotreload-path (should be blocked from EXT-01) ---"
CURRENT=$(curl -s -o /dev/null -w "%{http_code}" ${WAF_URL}/test-hotreload-path)
echo "HTTP Status: ${CURRENT}"
if [ "${CURRENT}" != "403" ]; then
  echo "WARNING: /test-hotreload-path not blocked — EXT-01 may not have passed"
fi

# Step 2: Remove the benchmark-hotreload-test rule
echo ""
echo "--- Removing benchmark-hotreload-test rule ---"
if [ -f "${WAF_CONFIG}" ]; then
  # Remove the rule block (id: "benchmark-hotreload-test" through next rule or EOF)
  if command -v yq &> /dev/null; then
    yq eval 'del(.[] | select(.id == "benchmark-hotreload-test"))' -i ${WAF_CONFIG}
  else
    # sed-based removal for YAML
    sed -i '/id: "benchmark-hotreload-test"/,/^-\|^\[\[/d' ${WAF_CONFIG}
    # Clean up trailing blank lines
    sed -i '/^$/N;/^\n$/d' ${WAF_CONFIG}
  fi
  echo "Rule removed from ${WAF_CONFIG}"
else
  WAF_CONFIG="/var/www/waf.toml"
  if [ -f "${WAF_CONFIG}" ]; then
    sed -i '/id = "benchmark-hotreload-test"/,/^\[\[/d' ${WAF_CONFIG}
    echo "Rule removed from ${WAF_CONFIG}"
  else
    echo "ERROR: WAF config not found"
    exit 1
  fi
fi

# Step 3: Hot-reload WAF
echo ""
echo "--- Hot-reloading WAF ---"
curl -s -X POST ${WAF_ADMIN}/__waf_control/reload

# Step 4: Wait for SLA then verify
echo ""
echo "--- Waiting 5s for rule removal to take effect ---"
sleep 5

echo "--- Verification: /test-hotreload-path (expect 200 ALLOW from upstream) ---"
for i in 1 2 3; do
  RESULT=$(curl -s -w "\nHTTP:%{http_code} | X-WAF-Action:%header{X-WAF-Action}" ${WAF_URL}/test-hotreload-path)
  echo "Request $i: $RESULT"
done

echo ""
echo "=== EXT-02 Complete ==="
echo "Pass criterion: Rule removed within 10s → /test-hotreload-path returns 200"
echo "Binary: pass = +3 pts, fail = 0 pts"`, wafBaseURL, wafAdminURL)
}

func reproduceEXT03(wafBaseURL, wafAdminURL string) string {
	return applyURLs(`#!/bin/bash
# Phase E — EXT-03 Caching Correctness Reproduction

WAF_URL="http://127.0.0.1:8080"
WAF_ADMIN="http://127.0.0.1:8081"
SID=""  # will be populated for E04

echo "=== EXT-03: Caching Correctness ==="

# ── E01: STATIC route cached ──
echo ""
echo "--- E01: STATIC /static/js/app.js (expect HIT on 2nd request) ---"
echo "Request 1 (expect MISS):"
curl -s --interface 127.0.0.90 -w "\nHTTP:%{http_code} | Cache:%header{X-WAF-Cache}\n" \
  ${WAF_URL}/static/js/app.js | tail -5
sleep 0.2
echo "Request 2 (expect HIT):"
curl -s --interface 127.0.0.90 -w "\nHTTP:%{http_code} | Cache:%header{X-WAF-Cache}\n" \
  ${WAF_URL}/static/js/app.js | tail -5

# ── E02: CRITICAL route NOT cached ──
echo ""
echo "--- E02: CRITICAL /login (expect MISS on all requests) ---"
echo "Request 1:"
curl -s --interface 127.0.0.91 -w "\nHTTP:%{http_code} | Cache:%header{X-WAF-Cache}\n" \
  -X POST ${WAF_URL}/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"P@ssw0rd1"}' | tail -5
sleep 0.2
echo "Request 2:"
curl -s --interface 127.0.0.91 -w "\nHTTP:%{http_code} | Cache:%header{X-WAF-Cache}\n" \
  -X POST ${WAF_URL}/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"P@ssw0rd1"}' | tail -5

# ── E03: STATIC TTL expiry ──
echo ""
echo "--- E03: STATIC /static/css/style.css (TTL expiry test) ---"
echo "Request 1 (expect MISS):"
curl -s --interface 127.0.0.92 -w "\nHTTP:%{http_code} | Cache:%header{X-WAF-Cache}\n" \
  ${WAF_URL}/static/css/style.css | tail -5
echo "First cache-WAF to set short TTL if possible, or wait for natural expiry"
echo "Request 2 (after TTL wait, expect MISS if TTL respected):"
sleep 2
curl -s --interface 127.0.0.92 -w "\nHTTP:%{http_code} | Cache:%header{X-WAF-Cache}\n" \
  ${WAF_URL}/static/css/style.css | tail -5

# ── E04: Authenticated route NOT cached ──
echo ""
echo "--- E04: Authenticated /api/profile (expect MISS) ---"
# Get session for alice
echo "Getting auth session..."
LT=$(curl -s --interface 127.0.0.93 -X POST ${WAF_URL}/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"P@ssw0rd1"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['login_token'])" 2>/dev/null || echo "")
if [ -n "${LT}" ]; then
  SID=$(curl -s --interface 127.0.0.93 -X POST ${WAF_URL}/otp \
    -H 'Content-Type: application/json' \
    -d "{\"login_token\":\"${LT}\",\"otp_code\":\"123456\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])" 2>/dev/null || echo "")
  echo "Session: ${SID}"
fi

if [ -n "${SID}" ]; then
  echo "Request 1 (expect MISS):"
  curl -s --interface 127.0.0.93 -w "\nHTTP:%{http_code} | Cache:%header{X-WAF-Cache}\n" \
    -H "Cookie: sid=${SID}" ${WAF_URL}/api/profile | tail -5
  sleep 0.2
  echo "Request 2 (expect MISS — auth routes should never cache):"
  curl -s --interface 127.0.0.93 -w "\nHTTP:%{http_code} | Cache:%header{X-WAF-Cache}\n" \
    -H "Cookie: sid=${SID}" ${WAF_URL}/api/profile | tail -5
else
  echo "WARNING: Could not obtain auth session — E04 verification incomplete"
fi

echo ""
echo "=== EXT-03 Complete ==="
echo "Pass criteria:"
echo "  E01: STATIC → HIT on 2nd request (+1 pt)"
echo "  E02: CRITICAL → MISS on all requests (+1 pt)"
echo "  E03: TTL respected → MISS after expiry (+1 pt)"
echo "  E04: Auth route → MISS on all requests (+1 pt)"
echo "  Total: up to 4 pts (1 pt per sub-test)"`, wafBaseURL, wafAdminURL)
}

// ── URL Replacement Helper ──

// applyURLs replaces hardcoded localhost URLs with the configured URLs.
func applyURLs(script, wafBaseURL, wafAdminURL string) string {
	return strings.NewReplacer(
		"http://127.0.0.1:8080", wafBaseURL,
		"http://127.0.0.1:8081", wafAdminURL,
	).Replace(script)
}
