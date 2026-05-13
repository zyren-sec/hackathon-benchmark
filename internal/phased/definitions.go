package phased

import (
	"strings"

	"github.com/waf-hackathon/benchmark-new/internal/phasec"
)

// GetDTests returns all 9 D* test definitions (D01–D09) with tier-adjusted parameters.
// Source: phase_D.md v2.5 §4
func GetDTests(targetBaseURL, wafBaseURL, wafAdminURL string, tier phasec.ResourceTier) []DTest {
	fp := GetDTierFloodParams(tier)
	return []DTest{
		// ── CAT 1: DDoS Stress Tests (D01–D04) ──

		// D01 — HTTP Flood Survival
		{
			ID: "D01", Name: "HTTP Flood Survival",
			Category: "ddos",
			MaxScore:    3.0,
			Description: "WAF sống sót qua HTTP flood trong và vẫn xử lý legitimate requests.",
			PassCriterion: "≥7/10 legitimate requests trong flood và ≥9/10 legitimate requests sau flood được xử lý; WAF không crash; không có circuit_breaker action.",
			FailReasons: map[string]string{
				"waf_crashed":           "WAF process died during or after flood",
				"during_verify_fail":    "<7/10 legitimate requests passed during flood",
				"insufficient_flood_load": "Flood tool achieved <10% of target RPS — WAF rate-limiting prevented valid stress test",
				"after_verify_fail":     "<9/10 legitimate requests passed after flood",
				"circuit_breaker":       "Legitimate requests received circuit_breaker (503) — unacceptable per contract §3.1 for volumetric abuse",
				"tool_error":            "Flood tool (wrk2) failed to execute or returned unexpected output",
			},
			SourceIP:    "127.0.0.210",
			Tool:        "wrk2",
			DurationSec: fp.Wrk2Duration,
			Connections: fp.Wrk2Connections,
			TargetRPS:   50000,
			VerifyDuring: true,
			VerifyAfter:  true,
			VerifyRoutes: LegitimateRoutes,
			ReproduceScript: reproduceD01(targetBaseURL, wafBaseURL, wafAdminURL, fp),
		},

		// D02 — Slowloris Defense
		{
			ID: "D02", Name: "Slowloris Defense",
			Category: "ddos",
			MaxScore:    2.0,
			Description: "WAF phát hiện và timeout 500 slow connections (1 byte/s headers, không bao giờ hoàn thành) trong 30 giây, đồng thời vẫn chấp nhận kết nối mới hợp lệ.",
			PassCriterion: "≥90% slow connections bị timeout/closed (<120s); Service Available = YES; legitimate traffic vẫn accepted.",
			FailReasons: map[string]string{
				"service_unavailable":  "Service Available = NO — WAF không chấp nhận kết nối mới",
				"high_pending":         "≥50 connections still pending sau 120s — WAF không timeout connections",
				"no_connections_established": "slowhttptest could not establish any connections — WAF may be blocking at connection level",
				"post_verify_fail":     "Legitimate requests bị từ chối sau slowloris test",
				"tool_error":           "slowhttptest failed to execute",
			},
			SourceIP:    "127.0.0.211",
			Tool:        "slowhttptest",
			DurationSec: fp.SlowlorisDuration,
			Connections: fp.SlowhttptestConns,
			VerifyAfter: true,
			VerifyRoutes: LegitimateRoutes,
			ReproduceScript: reproduceD02(targetBaseURL, wafBaseURL, wafAdminURL, fp),
		},

		// D03 — RUDY / Slow POST Defense
		{
			ID: "D03", Name: "RUDY Defense",
			Category: "ddos",
			MaxScore:    2.0,
			Description: "WAF phát hiện và kill 500 slow POST connections (Content-Length: 1000000, nhỏ giọt 1 byte/s body) trong 30 giây.",
			PassCriterion: "≥90% slow POST connections bị timeout/closed; Service Available = YES; legitimate traffic vẫn accepted.",
			FailReasons: map[string]string{
				"service_unavailable":  "Service Available = NO — WAF không chấp nhận kết nối mới",
				"high_pending":         "≥50 connections still pending sau 120s",
				"no_connections_established": "slowhttptest could not establish any connections — WAF may be blocking at connection level",
				"post_verify_fail":     "Legitimate requests bị từ chối sau RUDY test",
				"tool_error":           "slowhttptest failed to execute",
			},
			SourceIP:    "127.0.0.212",
			Tool:        "slowhttptest",
			DurationSec: fp.RudyDuration,
			Connections: fp.SlowhttptestConns,
			VerifyAfter: true,
			VerifyRoutes: LegitimateRoutes,
			ReproduceScript: reproduceD03(targetBaseURL, wafBaseURL, wafAdminURL, fp),
		},

		// D04 — WAF-Targeted Flood (Fail-Close + Fail-Open)
		{
			ID: "D04", Name: "WAF-Targeted Flood (Fail-Close + Fail-Open)",
			Category: "ddos",
			MaxScore:    7.0, // 4 (CRITICAL fail-close) + 3 (MEDIUM fail-open)
			Description: "Khi WAF bị overload ở 100,000+ RPS, CRITICAL routes phải fail-close (503) và MEDIUM/CATCH_ALL/STATIC routes phải fail-open (200 từ upstream).",
			PassCriterion: "CRITICAL: 4/4 routes fail-close (503) → +4 pts; MEDIUM+CATCH_ALL+STATIC: ≥8/10 routes fail-open (200) → +3 pts.",
			FailReasons: map[string]string{
				"waf_crashed":          "WAF process died during flood",
				"critical_fail_close":  "CRITICAL routes not all fail-close (503)",
				"medium_fail_open":     "MEDIUM/CATCH_ALL/STATIC routes not all fail-open (200)",
				"tool_error":           "Flood tool (wrk2) failed to execute",
			},
			SourceIP:    "127.0.0.213",
			Tool:        "wrk2+curl",
			DurationSec: 60,
			TargetRPS:   100000,
			VerifyAfter: true,
			VerifyRoutes: nil, // Uses per-tier routes dynamically
			ReproduceScript: reproduceD04(targetBaseURL, wafBaseURL, wafAdminURL, fp),
		},

		// ── CAT 2: Backend Failure Tests (D05–D07) ──

		// D05 — Backend Down / Circuit Breaker
		{
			ID: "D05", Name: "Backend Down / Circuit Breaker",
			Category: "backend_failure",
			MaxScore:    2.0,
			Description: "Khi UPSTREAM bị DOWN, WAF phát hiện và circuit-break (trả 503 circuit_breaker), không treo.",
			PassCriterion: "Tất cả verification requests qua WAF trả về 503 với X-WAF-Action: circuit_breaker.",
			FailReasons: map[string]string{
				"no_circuit_breaker":   "WAF không trả circuit_breaker — có thể treo, timeout, hoặc trả action khác",
				"wrong_status":         "WAF trả status khác 503",
				"upstream_control_fail":"Không thể set UPSTREAM về chế độ DOWN",
			},
			SourceIP:    "127.0.0.215",
			Tool:        "curl",
			BackendDown: true,
			VerifyAfter: true,
			VerifyRoutes: []DVerifyRoute{
				{Method: "GET", Endpoint: "/", ExpectedCode: 503, ExpectedAction: "circuit_breaker", Tier: "CATCH_ALL", Description: "Circuit breaker check"},
				{Method: "GET", Endpoint: "/health", ExpectedCode: 503, ExpectedAction: "circuit_breaker", Tier: "CATCH_ALL", Description: "Health check via WAF"},
				{Method: "POST", Endpoint: "/login", ExpectedCode: 503, ExpectedAction: "circuit_breaker", Tier: "CRITICAL", Description: "Login via WAF"},
			},
			ReproduceScript: reproduceD05(targetBaseURL, wafBaseURL, wafAdminURL),
		},

		// D06 — Backend Slow / Timeout
		{
			ID: "D06", Name: "Backend Slow / Timeout",
			Category: "backend_failure",
			MaxScore:    1.0,
			Description: "Khi UPSTREAM chậm (delay 10s), WAF timeout và trả 504 thay vì treo.",
			PassCriterion: "Tất cả verification requests qua WAF trả về 504 Gateway Timeout.",
			FailReasons: map[string]string{
				"no_timeout":           "WAF không timeout — treo hoặc trả status khác",
				"wrong_status":         "WAF trả status khác 504",
				"upstream_control_fail":"Không thể set UPSTREAM về chế độ SLOW",
			},
			SourceIP:    "127.0.0.216",
			Tool:        "curl",
			BackendSlow: true,
			DelayMs:     10000,
			VerifyAfter: true,
			VerifyRoutes: []DVerifyRoute{
				{Method: "GET", Endpoint: "/", ExpectedCode: 504, Tier: "CATCH_ALL", Description: "Timeout check"},
				{Method: "GET", Endpoint: "/game/list", ExpectedCode: 504, Tier: "MEDIUM", Description: "Game list via WAF"},
			},
			ReproduceScript: reproduceD06(targetBaseURL, wafBaseURL, wafAdminURL),
		},

		// D07 — Recovery
		{
			ID: "D07", Name: "Recovery",
			Category: "backend_failure",
			MaxScore:    1.0,
			Description: "Sau khi UPSTREAM được khôi phục (từ DOWN và SLOW), WAF tiếp tục proxy bình thường.",
			PassCriterion: "Tất cả legitimate requests trả về 200 OK.",
			FailReasons: map[string]string{
				"recovery_fail":        "WAF không phục hồi sau khi UPSTREAM restored",
				"still_circuit_broken": "WAF vẫn circuit-break sau khi UPSTREAM healthy",
				"still_timeout":        "WAF vẫn timeout sau khi UPSTREAM fast",
			},
			SourceIP:    "127.0.0.217",
			Tool:        "curl",
			VerifyAfter: true,
			VerifyRoutes: LegitimateRoutes,
			ReproduceScript: reproduceD07(targetBaseURL, wafBaseURL, wafAdminURL),
		},

		// ── CAT 3: Fail-Mode Configurability (D08–D09) ──

		// D08 — Fail-Mode Configurable
		{
			ID: "D08", Name: "Fail-Mode Configurable",
			Category: "fail_mode_config",
			MaxScore:    1.0,
			Description: "Chứng minh fail-mode có thể cấu hình được — đổi MEDIUM tier fail_mode: close trong WAF config và hot-reload, MEDIUM routes chuyển từ fail-open sang fail-close dưới tải.",
			PassCriterion: "Sau khi config MEDIUM tier fail_mode=close, ≥4/5 MEDIUM routes fail-close (503) dưới tải.",
			FailReasons: map[string]string{
				"config_not_found":     "Không tìm thấy WAF config file",
				"config_format_error":  "WAF config format không nhận diện được",
				"config_not_applied":   "Config change không có hiệu lực sau hot-reload",
				"medium_not_fail_close":"MEDIUM routes vẫn fail-open sau khi đổi config",
			},
			SourceIP:     "127.0.0.218",
			Tool:         "wrk2+curl",
			DurationSec:  30,
			TargetRPS:    100000,
			ConfigChange: true,
			ConfigKey:    "medium_tier_fail_mode",
			ConfigValue:  "close",
			VerifyAfter:  true,
			VerifyRoutes: MEDIUMRoutes,
			ReproduceScript: reproduceD08(targetBaseURL, wafBaseURL, wafAdminURL, fp),
		},

		// D09 — Fail-Mode Restore
		{
			ID: "D09", Name: "Fail-Mode Restore",
			Category: "fail_mode_config",
			MaxScore:    1.0,
			Description: "Revert fail-mode về open cho MEDIUM, hot-reload, và verify MEDIUM routes trở lại fail-open dưới tải.",
			PassCriterion: "Sau khi revert MEDIUM tier fail_mode=open, ≥4/5 MEDIUM routes fail-open (200) dưới tải.",
			FailReasons: map[string]string{
				"config_not_applied":   "Config revert không có hiệu lực sau hot-reload",
				"medium_not_fail_open": "MEDIUM routes vẫn fail-close sau khi revert",
				"prereq_d08_failed":    "Prerequisite D08 not met — cannot test restore",
			},
			SourceIP:     "127.0.0.219",
			Tool:         "wrk2+curl",
			DurationSec:  30,
			TargetRPS:    100000,
			ConfigChange: true,
			ConfigKey:    "medium_tier_fail_mode",
			ConfigValue:  "open",
			VerifyAfter:  true,
			VerifyRoutes: MEDIUMRoutes,
			ReproduceScript: reproduceD09(targetBaseURL, wafBaseURL, wafAdminURL, fp),
		},
	}
}

// ── Reproduce Scripts (self-contained, copy-paste for teams) ──

func reproduceD01(targetBaseURL, wafBaseURL, wafAdminURL string, fp DFloodParams) string {
	_ = fp // tier params used by engine; reproduce script uses TIER-MID defaults
	return applyURLs(`#!/bin/bash
# Phase D — D01 HTTP Flood Survival Reproduction
# Prerequisites: WAF-PROXY on :8080, UPSTREAM on :9000, wrk2 installed

WAF_URL="http://127.0.0.1:8080"
DURATION=60
RPS=50000

echo "=== D01: HTTP Flood Survival ==="
echo "Starting wrk2 flood: ${RPS} RPS for ${DURATION}s against WAF..."

# Run wrk2 with constant-rate mode
wrk2 -t4 -c500 -d${DURATION}s -R${RPS} --latency \
  --script <(cat <<'WRKEOF'
request = function()
  local paths = {"/", "/health", "/game/list", "/about", "/sitemap.xml"}
  local path = paths[math.random(#paths)]
  return wrk.format("GET", path, {["User-Agent"]="D01-Benchmark/2.7"})
end
WRKEOF
) ${WAF_URL}

echo ""
echo "=== Post-flood Verification ==="
for ep in /health / /game/list /about /sitemap.xml; do
  CODE=$(curl -s --interface 127.0.0.210 -o /dev/null -w "%{http_code}" ${WAF_URL}${ep})
  echo "GET ${ep}: HTTP ${CODE}"
done`, targetBaseURL, wafBaseURL, wafAdminURL)
}

func reproduceD02(targetBaseURL, wafBaseURL, wafAdminURL string, fp DFloodParams) string {
	_ = fp // tier params used by engine; reproduce script uses TIER-MID defaults
	return applyURLs(`#!/bin/bash
# Phase D — D02 Slowloris Defense (500 connections, 30s) Reproduction
# Prerequisites: slowhttptest installed

WAF_URL="http://127.0.0.1:8080"
DURATION=30
CONNS=500

echo "=== D02: Slowloris Defense ==="
echo "Starting slowhttptest: ${CONNS} connections for ${DURATION}s..."

slowhttptest -c ${CONNS} -H -g -o d02_slowloris \
  -i 10 -r 200 -t GET -u ${WAF_URL} -x 24 -p 3 \
  -l ${DURATION}

echo ""
echo "=== Post-test Verification ==="
for ep in /health / /game/list /about /sitemap.xml; do
  CODE=$(curl -s --interface 127.0.0.211 -o /dev/null -w "%{http_code}" ${WAF_URL}${ep})
  echo "GET ${ep}: HTTP ${CODE}"
done`, targetBaseURL, wafBaseURL, wafAdminURL)
}

func reproduceD03(targetBaseURL, wafBaseURL, wafAdminURL string, fp DFloodParams) string {
	_ = fp // tier params used by engine; reproduce script uses TIER-MID defaults
	return applyURLs(`#!/bin/bash
# Phase D — D03 RUDY Defense (500 slow POST, 30s) Reproduction
# Prerequisites: slowhttptest installed

WAF_URL="http://127.0.0.1:8080"
DURATION=30
CONNS=500

echo "=== D03: RUDY Defense ==="
echo "Starting slowhttptest (RUDY mode): ${CONNS} connections for ${DURATION}s..."

slowhttptest -c ${CONNS} -B -g -o d03_rudy \
  -i 10 -r 200 -t POST -u ${WAF_URL}/login \
  -x 24 -p 3 -l ${DURATION}

echo ""
echo "=== Post-test Verification ==="
for ep in /health / /game/list /about /sitemap.xml; do
  CODE=$(curl -s --interface 127.0.0.212 -o /dev/null -w "%{http_code}" ${WAF_URL}${ep})
  echo "GET ${ep}: HTTP ${CODE}"
done`, targetBaseURL, wafBaseURL, wafAdminURL)
}

func reproduceD04(targetBaseURL, wafBaseURL, wafAdminURL string, fp DFloodParams) string {
	_ = fp // tier params used by engine; reproduce script uses TIER-MID defaults
	return applyURLs(`#!/bin/bash
# Phase D — D04 WAF-Targeted Flood Fail-Close/Open Verification
# Prerequisites: WAF-PROXY on :8080, UPSTREAM on :9000, wrk2 installed

WAF_URL="http://127.0.0.1:8080"
DURATION=60
RPS=100000

echo "=== D04: WAF-Targeted Flood ==="
echo "Starting wrk2 flood: ${RPS} RPS for ${DURATION}s..."

wrk2 -t4 -c500 -d${DURATION}s -R${RPS} --latency ${WAF_URL}/ &

sleep 30  # Wait for WAF to enter degraded mode

echo ""
echo "=== CRITICAL Route Verification (expect 503 fail-close) ==="
for ep in /login /otp /deposit /withdrawal; do
  CODE=$(curl -s --interface 127.0.0.213 -o /dev/null -w "%{http_code}" ${WAF_URL}${ep})
  echo "${ep}: HTTP ${CODE}"
done

echo ""
echo "=== MEDIUM Route Verification (expect 200 fail-open) ==="
for ep in /game/list /game/1 /api/profile /api/transactions /user/settings; do
  CODE=$(curl -s --interface 127.0.0.213 -o /dev/null -w "%{http_code}" ${WAF_URL}${ep})
  echo "${ep}: HTTP ${CODE}"
done

echo ""
echo "=== CATCH_ALL Route Verification (expect 200 fail-open) ==="
for ep in / /about /sitemap.xml; do
  CODE=$(curl -s --interface 127.0.0.213 -o /dev/null -w "%{http_code}" ${WAF_URL}${ep})
  echo "${ep}: HTTP ${CODE}"
done

wait`, targetBaseURL, wafBaseURL, wafAdminURL)
}

func reproduceD05(targetBaseURL, wafBaseURL, wafAdminURL string) string {
	return applyURLs(`#!/bin/bash
# Phase D — D05 Backend Down / Circuit Breaker Reproduction

echo "=== D05: Circuit Breaker ==="

# Set UPSTREAM to DOWN mode
echo "Setting UPSTREAM to DOWN..."
curl -s -X POST http://127.0.0.1:9000/__control/health_mode \
  -H 'X-Benchmark-Secret: waf-hackathon-2026-ctrl' \
  -d '{"down":true}'

echo ""
echo "=== Verification via WAF (expect 503 circuit_breaker) ==="
for ep in / /health /login; do
  echo -n "GET ${ep}: "
  curl -s --interface 127.0.0.215 -o /tmp/d05_resp.txt -w "HTTP %{http_code}" \
    -D /tmp/d05_headers.txt http://127.0.0.1:8080${ep}
  echo -n " | WAF-Action: "
  grep -i x-waf-action /tmp/d05_headers.txt | cut -d: -f2- | tr -d '\r'
  echo ""
done

# RESTORE UPSTREAM
echo ""
echo "Restoring UPSTREAM..."
curl -s -X POST http://127.0.0.1:9000/__control/health_mode \
  -H 'X-Benchmark-Secret: waf-hackathon-2026-ctrl' \
  -d '{"down":false}'`, targetBaseURL, wafBaseURL, wafAdminURL)
}

func reproduceD06(targetBaseURL, wafBaseURL, wafAdminURL string) string {
	return applyURLs(`#!/bin/bash
# Phase D — D06 Backend Slow / Timeout Reproduction

echo "=== D06: Backend Slow ==="

# Set UPSTREAM to SLOW mode (10s delay)
echo "Setting UPSTREAM to SLOW (10s delay)..."
curl -s -X POST http://127.0.0.1:9000/__control/slow \
  -H 'X-Benchmark-Secret: waf-hackathon-2026-ctrl' \
  -d '{"delay_ms":10000}'

echo ""
echo "=== Verification via WAF (expect 504 Gateway Timeout) ==="
for ep in / /game/list; do
  echo -n "GET ${ep}: "
  curl -s --interface 127.0.0.216 -o /dev/null -w "HTTP %{http_code} | Time: %{time_total}s\n" \
    --max-time 15 http://127.0.0.1:8080${ep}
done

# RESTORE UPSTREAM
echo ""
echo "Restoring UPSTREAM (delay_ms=0)..."
curl -s -X POST http://127.0.0.1:9000/__control/slow \
  -H 'X-Benchmark-Secret: waf-hackathon-2026-ctrl' \
  -d '{"delay_ms":0}'`, targetBaseURL, wafBaseURL, wafAdminURL)
}

func reproduceD07(targetBaseURL, wafBaseURL, wafAdminURL string) string {
	return applyURLs(`#!/bin/bash
# Phase D — D07 Recovery Reproduction

echo "=== D07: Recovery ==="

# Ensure UPSTREAM is healthy
echo "Ensuring UPSTREAM is healthy..."
curl -s -X POST http://127.0.0.1:9000/__control/health_mode \
  -H 'X-Benchmark-Secret: waf-hackathon-2026-ctrl' \
  -d '{"down":false}'
curl -s -X POST http://127.0.0.1:9000/__control/slow \
  -H 'X-Benchmark-Secret: waf-hackathon-2026-ctrl' \
  -d '{"delay_ms":0}'

# Reset WAF state
curl -s -X POST http://127.0.0.1:8081/__waf_control/reset_state

echo ""
echo "=== Verification (expect 200 OK) ==="
for ep in /health / /game/list /about /sitemap.xml; do
  CODE=$(curl -s --interface 127.0.0.217 -o /dev/null -w "%{http_code}" http://127.0.0.1:8080${ep})
  echo "GET ${ep}: HTTP ${CODE}"
done`, targetBaseURL, wafBaseURL, wafAdminURL)
}

func reproduceD08(targetBaseURL, wafBaseURL, wafAdminURL string, fp DFloodParams) string {
	_ = fp // tier params used by engine; reproduce script uses TIER-MID defaults
	return applyURLs(`#!/bin/bash
# Phase D — D08 Fail-Mode Configurable Reproduction

echo "=== D08: Fail-Mode Configurable ==="

WAF_CONFIG="/var/www/waf.yaml"

# Edit WAF config: set MEDIUM tier fail_mode to close
echo "Setting MEDIUM tier fail_mode=close in WAF config..."
if [ -f "${WAF_CONFIG}" ]; then
  # Use yq or sed to modify the config
  # This is WAF-specific; adjust for your WAF implementation
  echo "  Using config: ${WAF_CONFIG}"
  # yq eval '.tiers.medium.fail_mode = "close"' -i ${WAF_CONFIG}
  echo "  (Adjust config path and format for your WAF)"
else
  echo "  WARNING: WAF config not found at ${WAF_CONFIG}"
fi

# Hot-reload WAF
echo "Hot-reloading WAF..."
curl -s -X POST http://127.0.0.1:8081/__waf_control/reload

# Run flood
WAF_URL="http://127.0.0.1:8080"
echo "Starting flood: 100k RPS for 30s..."
wrk2 -t4 -c500 -d30s -R100000 ${WAF_URL}/ &

sleep 15

# Verify MEDIUM routes fail-close
echo ""
echo "=== MEDIUM Route Verification (expect 503 fail-close) ==="
for ep in /game/list /game/1 /api/profile /api/transactions /user/settings; do
  CODE=$(curl -s --interface 127.0.0.218 -o /dev/null -w "%{http_code}" ${WAF_URL}${ep})
  echo "${ep}: HTTP ${CODE}"
done

wait`, targetBaseURL, wafBaseURL, wafAdminURL)
}

func reproduceD09(targetBaseURL, wafBaseURL, wafAdminURL string, fp DFloodParams) string {
	_ = fp // tier params used by engine; reproduce script uses TIER-MID defaults
	return applyURLs(`#!/bin/bash
# Phase D — D09 Fail-Mode Restore Reproduction

echo "=== D09: Fail-Mode Restore ==="

WAF_CONFIG="/var/www/waf.yaml"

# Revert WAF config: set MEDIUM tier fail_mode back to open
echo "Reverting MEDIUM tier fail_mode=open in WAF config..."
if [ -f "${WAF_CONFIG}" ]; then
  # yq eval '.tiers.medium.fail_mode = "open"' -i ${WAF_CONFIG}
  echo "  (Adjust config path and format for your WAF)"
else
  echo "  WARNING: WAF config not found at ${WAF_CONFIG}"
fi

# Hot-reload WAF
echo "Hot-reloading WAF..."
curl -s -X POST http://127.0.0.1:8081/__waf_control/reload

# Run flood
WAF_URL="http://127.0.0.1:8080"
echo "Starting flood: 100k RPS for 30s..."
wrk2 -t4 -c500 -d30s -R100000 ${WAF_URL}/ &

sleep 15

# Verify MEDIUM routes fail-open
echo ""
echo "=== MEDIUM Route Verification (expect 200 fail-open) ==="
for ep in /game/list /game/1 /api/profile /api/transactions /user/settings; do
  CODE=$(curl -s --interface 127.0.0.219 -o /dev/null -w "%{http_code}" ${WAF_URL}${ep})
  echo "${ep}: HTTP ${CODE}"
done

wait`, targetBaseURL, wafBaseURL, wafAdminURL)
}

// ── URL Replacement Helper ──

// applyURLs replaces hardcoded localhost URLs with the configured URLs.
func applyURLs(script, targetBaseURL, wafBaseURL, wafAdminURL string) string {
	return strings.NewReplacer(
		"http://127.0.0.1:9000", targetBaseURL,
		"http://127.0.0.1:8080", wafBaseURL,
		"http://127.0.0.1:8081", wafAdminURL,
	).Replace(script)
}