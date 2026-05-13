package phaseb

import "strings"

// GetBTests returns all 22 Phase B test definitions in execution order.
// Order per phase_B.md §4.0 (v2.6).
// Each test includes a self-contained ReproduceScript (copy-paste ready).
func GetBTests(wafBaseURL string) []BTest {
	return []BTest{
		// ═══ CAT 1: Brute Force & Credential Attacks (SEC-03) ═══
		{
			ID: "AB01", Name: "Brute Force Login", Category: "brute_force", Criterion: "SEC-03",
			Method: "POST", Endpoint: "/login", SourceIP: "127.0.0.10",
			AbuseType: "brute", ContentType: "application/json",
			BodyTemplate: `{"username":"alice","password":"wrong-%d"}`,
			Description: "50× POST /login with wrong passwords",
			PassCriterion: "WAF blocks within ≤10 attempts",
			RiskMin: 50, RiskMax: 100, ExpectedAction: "block",
			RequestCount: 50, RequestsPerBatch: 10, BatchDelayMs: 200,
			ReproduceScript: applyURLs(`# AB01: Brute Force Login — 50× POST /login with wrong passwords
for i in $(seq 1 5); do
  curl -s --interface 127.0.0.10 -X POST http://127.0.0.1:8080/login \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"alice\",\"password\":\"wrong-$i\"}" -w "attempt $i: %{http_code}\n"
done
# Pass: WAF blocks within first 10 attempts`, wafBaseURL),
		},
		{
			ID: "AB02", Name: "Credential Stuffing", Category: "brute_force", Criterion: "SEC-03",
			Method: "POST", Endpoint: "/login", SourceIP: "127.0.0.11",
			AbuseType: "credential_stuffing", ContentType: "application/json",
			Description: "100 credential pairs from file — stuffing attack",
			PassCriterion: "WAF blocks within ≤20 pairs",
			RiskMin: 50, RiskMax: 100, ExpectedAction: "block",
			RequestCount: 100, PayloadFile: "exploits/brute_force/credentials.txt",
			ReproduceScript: applyURLs(`# AB02: Credential Stuffing — 100 credential pairs
# Generate test credentials file:
for i in $(seq 1 10); do
  echo "{\"username\":\"user_$i\",\"password\":\"Spring2024!\"}" >> /tmp/creds.json
done
# Send stuffing attack:
while IFS= read -r line; do
  curl -s --interface 127.0.0.11 -X POST http://127.0.0.1:8080/login \
    -H 'Content-Type: application/json' -d "$line" -w " %{http_code}\n"
done < /tmp/creds.json
# Pass: WAF blocks within ≤20 pairs`, wafBaseURL),
		},
		{
			ID: "AB03", Name: "Password Spraying", Category: "brute_force", Criterion: "SEC-03",
			Method: "POST", Endpoint: "/login", SourceIP: "127.0.0.12",
			AbuseType: "spray", ContentType: "application/json",
			BodyTemplate: `{"username":"user_%d","password":"Spring2024!"}`,
			Description: "50 users, same password — spraying attack",
			PassCriterion: "WAF blocks within ≤15 users",
			RiskMin: 50, RiskMax: 100, ExpectedAction: "block",
			RequestCount: 50, RequestsPerBatch: 10, BatchDelayMs: 200,
			ReproduceScript: applyURLs(`# AB03: Password Spraying — 50 users, same password
for i in $(seq 1 10); do
  curl -s --interface 127.0.0.12 -X POST http://127.0.0.1:8080/login \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"user_$i\",\"password\":\"Spring2024!\"}" -w "user_$i: %{http_code}\n"
done
# Pass: WAF blocks within ≤15 users`, wafBaseURL),
		},

		// ═══ CAT 2a: Relay & Proxy Detection (INT-03) — Phase 1: Negative Controls + XFF ═══
		{
			ID: "AR01", Name: "XFF Matches Source", Category: "relay", Criterion: "INT-03",
			Method: "GET", Endpoint: "/game/list", SourceIP: "127.0.0.20",
			ExtraHeaders: map[string]string{"X-Forwarded-For": "127.0.0.20"},
			AbuseType: "relay", NegativeControl: true,
			NegControlDesc: "XFF matches TCP source — WAF MUST allow (200)",
			Description: "X-Forwarded-For matches TCP source — negative control, should pass through",
			PassCriterion: "WAF must allow (HTTP 200), not blocked",
			RiskMin: 0, RiskMax: 0, ExpectedAction: "allow",
			ReproduceScript: applyURLs(`# AR01: XFF Matches Source (negative control — MUST return 200)
curl -is --interface 127.0.0.20 http://127.0.0.1:8080/game/list \
  -H 'X-Forwarded-For: 127.0.0.20' | head -5
# Pass = HTTP 200; block here = FALSE POSITIVE`, wafBaseURL),
		},
		{
			ID: "AR02", Name: "XFF Spoofed", Category: "relay", Criterion: "INT-03",
			Method: "GET", Endpoint: "/game/list", SourceIP: "127.0.0.21",
			ExtraHeaders: map[string]string{"X-Forwarded-For": "8.8.8.8"},
			AbuseType: "relay",
			Description: "X-Forwarded-For ≠ TCP source (spoofed 8.8.8.8)",
			PassCriterion: "Risk score > 0 or challenge/block",
			RiskMin: 30, RiskMax: 80, ExpectedAction: "challenge",
			ReproduceScript: applyURLs(`# AR02: XFF Spoofed — X-Forwarded-For differs from TCP source
curl -is --interface 127.0.0.21 http://127.0.0.1:8080/game/list \
  -H 'X-Forwarded-For: 8.8.8.8' | grep -i x-waf-risk-score
# Pass: X-WAF-Risk-Score present and > 0`, wafBaseURL),
		},
		{
			ID: "AR03", Name: "XFF Multi-hop", Category: "relay", Criterion: "INT-03",
			Method: "GET", Endpoint: "/game/list", SourceIP: "127.0.0.22",
			ExtraHeaders: map[string]string{"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4"},
			AbuseType: "relay",
			Description: "X-Forwarded-For with 3+ hops — potential proxy chain",
			PassCriterion: "Risk score > 0 or challenge/block",
			RiskMin: 30, RiskMax: 80, ExpectedAction: "challenge",
			ReproduceScript: applyURLs(`# AR03: XFF Multi-hop — 3+ proxy hops in X-Forwarded-For
curl -is --interface 127.0.0.22 http://127.0.0.1:8080/game/list \
  -H 'X-Forwarded-For: 1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4' | grep -i x-waf-risk-score
# Pass: X-WAF-Risk-Score > 0`, wafBaseURL),
		},
		{
			ID: "AR06", Name: "Clean IP", Category: "relay", Criterion: "INT-03",
			Method: "GET", Endpoint: "/game/list", SourceIP: "127.0.0.23",
			AbuseType: "relay", NegativeControl: true,
			NegControlDesc: "Clean IP not in any threat-intel list — WAF MUST allow (200)",
			Description: "Clean IP, not in any threat intel list — negative control",
			PassCriterion: "WAF must allow (HTTP 200), not blocked",
			RiskMin: 0, RiskMax: 0, ExpectedAction: "allow",
			ReproduceScript: applyURLs(`# AR06: Clean IP (negative control — MUST return 200)
curl -is --interface 127.0.0.23 http://127.0.0.1:8080/game/list | head -5
# Pass = HTTP 200; block here = FALSE POSITIVE`, wafBaseURL),
		},

		// ═══ CAT 2: Relay & Proxy Detection (INT-03) — v2.9: AR04/AR05 removed ═══
		// Note: All 4 tests (AR01-AR03, AR06) now run with loopback. No sub-phase split.

		// ═══ CAT 3: Behavioral Anomaly (INT-02) — Auth matrix per §4.3 ═══
		{
			ID: "BA01", Name: "Zero-Depth Session", Category: "behavioral", Criterion: "INT-02",
			Method: "POST", Endpoint: "/login", SourceIP: "127.0.0.40",
			AbuseType: "bot", ContentType: "application/json",
			BodyTemplate: `{"username":"alice","password":"P@ssw0rd1"}`,
			TimingPattern: "zero_depth",
			Description: "POST /login without prior GET / — zero-depth session bot behavior",
			PassCriterion: "Risk > 30 or challenge",
			RiskMin: 30, RiskMax: 80, ExpectedAction: "challenge",
			ReproduceScript: applyURLs(`# BA01: Zero-Depth Session — POST /login without prior GET /
curl -is --interface 127.0.0.40 -X POST http://127.0.0.1:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"P@ssw0rd1"}' | grep -i x-waf
# Pass: X-WAF-Risk-Score > 30 or X-WAF-Action: challenge`, wafBaseURL),
		},
		{
			ID: "BA02", Name: "Uniform Timing Bot", Category: "behavioral", Criterion: "INT-02",
			Method: "GET", Endpoint: "/game/list", SourceIP: "127.0.0.41",
			AbuseType: "bot", TimingPattern: "uniform",
			Description: "100 identical GET /game/list at exactly 100ms intervals — bot timing",
			PassCriterion: "Block/challenge within ≤60 requests",
			RiskMin: 30, RiskMax: 80, ExpectedAction: "challenge",
			RequestCount: 100, RequestsPerBatch: 1, BatchDelayMs: 100,
			ReproduceScript: applyURLs(`# BA02: Uniform Timing Bot — 100× GET /game/list at 100ms intervals
for i in $(seq 1 100); do
  curl -s --interface 127.0.0.41 -o /dev/null -w "%{http_code}\n" \
    http://127.0.0.1:8080/game/list
  sleep 0.1
done
# Pass: HTTP transitions from 200 → 403/429 within ≤60 requests`, wafBaseURL),
		},
		{
			ID: "BA03", Name: "Missing Referer", Category: "behavioral", Criterion: "INT-02",
			Method: "POST", Endpoint: "/deposit", SourceIP: "127.0.0.42",
			AbuseType: "bot", ContentType: "application/json",
			BodyTemplate: `{"amount":100,"currency":"USD"}`,
			SessionRequired: true, AuthUser: "bob", AuthPassword: "S3cureP@ss", AuthOTP: "654321",
			Description: "POST /deposit without Referer header (bob authenticated) — missing referer anomaly",
			PassCriterion: "Risk delta > 0",
			RiskMin: 30, RiskMax: 65, ExpectedAction: "challenge",
			ReproduceScript: applyURLs(`# BA03: Missing Referer — POST /deposit without Referer (bob auth)
LT=$(curl -s --interface 127.0.0.42 -X POST http://127.0.0.1:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"S3cureP@ss"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['login_token'])")
SID=$(curl -s --interface 127.0.0.42 -X POST http://127.0.0.1:8080/otp \
  -H 'Content-Type: application/json' \
  -d "{\"login_token\":\"$LT\",\"otp_code\":\"654321\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
curl -is --interface 127.0.0.42 -X POST http://127.0.0.1:8080/deposit \
  -H "Cookie: sid=$SID" -H 'Content-Type: application/json' \
  -d '{"amount":100,"currency":"USD"}' | grep -i x-waf
# Pass: X-WAF-Risk-Score delta > 0 (no Referer anomaly detected)`, wafBaseURL),
		},
		{
			ID: "BA04", Name: "Sub-50ms Cadence Bot", Category: "behavioral", Criterion: "INT-02",
			Method: "GET", Endpoint: "/api/profile", SourceIP: "127.0.0.43",
			AbuseType: "bot", TimingPattern: "uniform",
			SessionRequired: true, AuthUser: "alice", AuthPassword: "P@ssw0rd1", AuthOTP: "123456",
			Description: "20× GET /api/profile in <3s (sub-50ms cadence) — rapid authenticated scraping",
			PassCriterion: "Block/challenge (403/429)",
			RiskMin: 30, RiskMax: 80, ExpectedAction: "challenge",
			RequestCount: 20, RequestsPerBatch: 1, BatchDelayMs: 40,
			ReproduceScript: applyURLs(`# BA04: Sub-50ms Cadence — 20× GET /api/profile rapid fire (alice auth)
LT=$(curl -s --interface 127.0.0.43 -X POST http://127.0.0.1:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"P@ssw0rd1"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['login_token'])")
SID=$(curl -s --interface 127.0.0.43 -X POST http://127.0.0.1:8080/otp \
  -H 'Content-Type: application/json' \
  -d "{\"login_token\":\"$LT\",\"otp_code\":\"123456\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
for i in $(seq 1 20); do
  curl -s --interface 127.0.0.43 -o /dev/null -w "%{http_code}\n" \
    http://127.0.0.1:8080/api/profile -H "Cookie: sid=$SID" &
done; wait
# Pass: HTTP 403/429 on some requests (rapid cadence detected)`, wafBaseURL),
		},
		{
			ID: "BA05", Name: "Spoofed Referer", Category: "behavioral", Criterion: "INT-02",
			Method: "POST", Endpoint: "/withdrawal", SourceIP: "127.0.0.44",
			AbuseType: "bot", ContentType: "application/json",
			BodyTemplate: `{"amount":50,"bank_account":"ACCT-000003"}`,
			ExtraHeaders: map[string]string{"Referer": "https://evil.com/phishing"},
			SessionRequired: true, AuthUser: "charlie", AuthPassword: "Ch@rlie99", AuthOTP: "111222",
			Description: "POST /withdrawal with spoofed Referer: evil.com (charlie authenticated, v2.6: own login-OTP, NOT shared with BA03)",
			PassCriterion: "Risk > 0 or challenge",
			RiskMin: 30, RiskMax: 80, ExpectedAction: "challenge",
			ReproduceScript: applyURLs(`# BA05: Spoofed Referer — POST /withdrawal with Referer: evil.com (charlie auth, v2.6: own login-OTP)
LT=$(curl -s --interface 127.0.0.44 -X POST http://127.0.0.1:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"charlie","password":"Ch@rlie99"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['login_token'])")
SID=$(curl -s --interface 127.0.0.44 -X POST http://127.0.0.1:8080/otp \
  -H 'Content-Type: application/json' \
  -d "{\"login_token\":\"$LT\",\"otp_code\":\"111222\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
curl -is --interface 127.0.0.44 -X POST http://127.0.0.1:8080/withdrawal \
  -H "Cookie: sid=$SID" -H 'Content-Type: application/json' \
  -H 'Referer: https://evil.com/phishing' \
  -d '{"amount":50,"bank_account":"ACCT-000003"}' | grep -i x-waf
# Pass: X-WAF-Risk-Score > 0 (spoofed Referer detected)`, wafBaseURL),
		},

		// ═══ CAT 4: Transaction Fraud (INT-01) — Auth matrix per §4.4 ═══
		{
			ID: "TF01", Name: "Rush Deposit (3× in <5s)", Category: "transaction", Criterion: "INT-01",
			Method: "POST", Endpoint: "/deposit", SourceIP: "127.0.0.60",
			AbuseType: "fraud", ContentType: "application/json",
			BodyTemplate: `{"amount":1000,"currency":"USD"}`,
			SessionRequired: true, AuthUser: "alice", AuthPassword: "P@ssw0rd1", AuthOTP: "123456",
			Description: "3× $1000 deposit in <5 seconds — rush deposit fraud pattern",
			PassCriterion: "WAF blocks/challenges deposit (risk spike or block)",
			RiskMin: 50, RiskMax: 100, ExpectedAction: "block",
			RequestCount: 3, RequestsPerBatch: 3, BatchDelayMs: 0,
			ReproduceScript: applyURLs(`# TF01: Rush Deposit — 3× $1000 deposit in <5s (alice auth)
LT=$(curl -s --interface 127.0.0.60 -X POST http://127.0.0.1:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"P@ssw0rd1"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['login_token'])")
SID=$(curl -s --interface 127.0.0.60 -X POST http://127.0.0.1:8080/otp \
  -H 'Content-Type: application/json' \
  -d "{\"login_token\":\"$LT\",\"otp_code\":\"123456\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
for i in 1 2 3; do
  curl -s --interface 127.0.0.60 -X POST http://127.0.0.1:8080/deposit \
    -H "Cookie: sid=$SID" -H 'Content-Type: application/json' \
    -d '{"amount":1000,"currency":"USD"}' -w "deposit $i: %{http_code}\n" &
done; wait
# Pass: WAF blocks/challenges one of the deposits`, wafBaseURL),
		},
		{
			ID: "TF02", Name: "Instant Withdrawal (<3s)", Category: "transaction", Criterion: "INT-01",
			Method: "POST", Endpoint: "/deposit", SourceIP: "127.0.0.61",
			AbuseType: "fraud", ContentType: "application/json",
			BodyTemplate: `{"amount":500,"currency":"USD"}`,
			SessionRequired: true, AuthUser: "bob", AuthPassword: "S3cureP@ss", AuthOTP: "654321",
			Description: "Deposit → instant $500 withdrawal in <3s — suspicious timing",
			PassCriterion: "WAF flags the withdrawal (risk spike or block)",
			RiskMin: 50, RiskMax: 100, ExpectedAction: "challenge",
			SubSteps: []BTestSubStep{
				{Method: "POST", Endpoint: "/withdrawal",
					Body: `{"amount":500,"bank_account":"ACCT-000002"}`, ContentType: "application/json"},
			},
			ReproduceScript: applyURLs(`# TF02: Instant Withdrawal — deposit then withdrawal in <3s (bob auth)
LT=$(curl -s --interface 127.0.0.61 -X POST http://127.0.0.1:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"S3cureP@ss"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['login_token'])")
SID=$(curl -s --interface 127.0.0.61 -X POST http://127.0.0.1:8080/otp \
  -H 'Content-Type: application/json' \
  -d "{\"login_token\":\"$LT\",\"otp_code\":\"654321\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
curl -s --interface 127.0.0.61 -X POST http://127.0.0.1:8080/deposit \
  -H "Cookie: sid=$SID" -H 'Content-Type: application/json' \
  -d '{"amount":500,"currency":"USD"}' -w "deposit: %{http_code}\n"
curl -s --interface 127.0.0.61 -X POST http://127.0.0.1:8080/withdrawal \
  -H "Cookie: sid=$SID" -H 'Content-Type: application/json' \
  -d '{"amount":500,"bank_account":"ACCT-000002"}' -w "withdrawal: %{http_code}\n"
# Pass: WAF flags the withdrawal (risk spike or block)`, wafBaseURL),
		},
		{
			ID: "TF03", Name: "Limit Change + Large Withdrawal", Category: "transaction", Criterion: "INT-01",
			Method: "PUT", Endpoint: "/user/settings", SourceIP: "127.0.0.62",
			AbuseType: "fraud", ContentType: "application/json",
			BodyTemplate: `{"preferences":{"withdrawal_limit":999999}}`,
			SessionRequired: true, AuthUser: "charlie", AuthPassword: "Ch@rlie99", AuthOTP: "111222",
			Description: "Increase withdrawal_limit → large withdrawal $50000 in <10s — fraud escalation",
			PassCriterion: "WAF detects suspicious limit change + withdrawal combo (risk spike or block)",
			RiskMin: 50, RiskMax: 100, ExpectedAction: "block",
			SubSteps: []BTestSubStep{
				{Method: "POST", Endpoint: "/withdrawal",
					Body: `{"amount":50000,"bank_account":"ACCT-000003"}`, ContentType: "application/json"},
			},
			ReproduceScript: applyURLs(`# TF03: Limit Change + Large Withdrawal (charlie auth)
LT=$(curl -s --interface 127.0.0.62 -X POST http://127.0.0.1:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"charlie","password":"Ch@rlie99"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['login_token'])")
SID=$(curl -s --interface 127.0.0.62 -X POST http://127.0.0.1:8080/otp \
  -H 'Content-Type: application/json' \
  -d "{\"login_token\":\"$LT\",\"otp_code\":\"111222\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
curl -s --interface 127.0.0.62 -X PUT http://127.0.0.1:8080/user/settings \
  -H "Cookie: sid=$SID" -H 'Content-Type: application/json' \
  -d '{"preferences":{"withdrawal_limit":999999}}' -w "limit change: %{http_code}\n"
curl -s --interface 127.0.0.62 -X POST http://127.0.0.1:8080/withdrawal \
  -H "Cookie: sid=$SID" -H 'Content-Type: application/json' \
  -d '{"amount":50000,"bank_account":"ACCT-000003"}' -w "withdrawal: %{http_code}\n"
# Pass: WAF detects suspicious limit change + withdrawal combo`, wafBaseURL),
		},
		{
			ID: "TF04", Name: "Multi-Account Device", Category: "transaction", Criterion: "INT-01",
			Method: "POST", Endpoint: "/login", SourceIP: "127.0.0.63",
			AbuseType: "fraud", ContentType: "application/json",
			BodyTemplate: `{"username":"testuser_%d","password":"Test#%dPass"}`,
			Description: "5 different users login+deposit from same IP in <60s — multi-accounting fraud",
			PassCriterion: "WAF detects multi-accounting pattern (risk spike or block)",
			RiskMin: 50, RiskMax: 100, ExpectedAction: "block",
			RequestCount: 5,
			ReproduceScript: applyURLs(`# TF04: Multi-Account Device — 5 users login+deposit from same IP
for n in $(seq 1 5); do
  USER="testuser_$n"; PASS="Test#${n}Pass"; OTP=$(printf "%06d" $n)
  LT=$(curl -s --interface 127.0.0.63 -X POST http://127.0.0.1:8080/login \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['login_token'])")
  SID=$(curl -s --interface 127.0.0.63 -X POST http://127.0.0.1:8080/otp \
    -H 'Content-Type: application/json' \
    -d "{\"login_token\":\"$LT\",\"otp_code\":\"$OTP\"}" | python3 -c "import sys,json; print(json.load(sys.stdin)['session_id'])")
  curl -s --interface 127.0.0.63 -X POST http://127.0.0.1:8080/deposit \
    -H "Cookie: sid=$SID" -H 'Content-Type: application/json' \
    -d '{"amount":100,"currency":"USD"}' -w "$USER deposit: %{http_code}\n"
done
# Pass: WAF detects multi-accounting pattern from same IP`, wafBaseURL),
		},

		// ═══ CAT 5: Recon & Enumeration (SEC-03 + SEC-04) ═══
		{
			ID: "RE01", Name: "Path Enumeration", Category: "recon", Criterion: "SEC-03",
			Method: "GET", Endpoint: "/", SourceIP: "127.0.0.80",
			AbuseType: "recon",
			Description: "200 requests to various paths — directory enumeration; also checks for __L05_VERBOSE_404__ markers",
			PassCriterion: "WAF blocks within ≤50 requests AND no __L05_VERBOSE_404__ markers",
			RiskMin: 30, RiskMax: 80, ExpectedAction: "block",
			RequestCount: 200, RequestsPerBatch: 20, BatchDelayMs: 100,
			PayloadFile: "exploits/recon/paths.txt",
			ReproduceScript: applyURLs(`# RE01: Path Enumeration — 200 requests to nonexistent paths
PATHS=(/admin /config /backup /test /secret /db /api/v1 /admin.php /wp-admin /.git /env /.aws)
for i in $(seq 1 20); do
  for p in "${PATHS[@]}"; do
    curl -s --interface 127.0.0.80 -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8080${p}
  done
done | sort | uniq -c
# L05 check: grep '__L05_VERBOSE_404__' trong response bodies
# Pass: WAF blocks (403) within ≤50 requests AND no __L05_VERBOSE_404__ markers`, wafBaseURL),
		},
		{
			ID: "RE02", Name: "OPTIONS Abuse", Category: "recon", Criterion: "SEC-03",
			Method: "OPTIONS", Endpoint: "/", SourceIP: "127.0.0.81",
			AbuseType: "recon",
			Description: "10 OPTIONS requests to different endpoints — method enumeration",
			PassCriterion: "Rate-limited (HTTP 429)",
			RiskMin: 30, RiskMax: 65, ExpectedAction: "rate_limit",
			RequestCount: 10, RequestsPerBatch: 2, BatchDelayMs: 50,
			ReproduceScript: applyURLs(`# RE02: OPTIONS Abuse — method enumeration across endpoints
for ep in / /game/list /login /api/profile /admin /api /static /assets /user/settings /deposit; do
  curl -s --interface 127.0.0.81 -X OPTIONS -o /dev/null -w "OPTIONS ${ep}: %{http_code}\n" http://127.0.0.1:8080${ep}
done
# Pass: Rate-limited (HTTP 429)`, wafBaseURL),
		},
		{
			ID: "RE03", Name: "Error Harvesting", Category: "recon", Criterion: "SEC-03",
			Method: "GET", Endpoint: "/api/nonexistent", SourceIP: "127.0.0.82",
			AbuseType: "recon",
			Description: "GET requests to error endpoints — check for __L01_STACKTRACE__ markers",
			PassCriterion: "No __L01_STACKTRACE__ markers in responses",
			RiskMin: 30, RiskMax: 80, ExpectedAction: "block",
			RequestCount: 10, RequestsPerBatch: 2, BatchDelayMs: 100,
			ReproduceScript: applyURLs(`# RE03: Error Harvesting — trigger errors and check for leak markers
for i in $(seq 1 10); do
  BODY=$(curl -s --interface 127.0.0.82 http://127.0.0.1:8080/api/nonexistent)
  if echo "$BODY" | grep -q "__L01_STACKTRACE__"; then
    echo "LEAK DETECTED in request $i"
  fi
done
echo "Check complete — Pass if no __L01_STACKTRACE__ marker found"
# Pass: No __L01_STACKTRACE__ markers in any response`, wafBaseURL),
		},
		{
			ID: "RE04", Name: "Canary Probing", Category: "recon", Criterion: "SEC-04",
			Method: "GET", Endpoint: "/admin-test", SourceIP: "127.0.0.85",
			AbuseType: "canary",
			Description: "Probe 4 canary endpoints — WAF must block all + lock IP",
			PassCriterion: "All 4 canaries blocked (403) + follow-up request blocked (IP locked)",
			RiskMin: 70, RiskMax: 100, ExpectedAction: "block",
			ReproduceScript: applyURLs(`# RE04: Canary Probing — probe 4 canary endpoints + follow-up
for ep in /admin-test /api-debug /.env /wp-admin; do
  CODE=$(curl -s --interface 127.0.0.85 -o /dev/null -w "%{http_code}" http://127.0.0.1:8080${ep})
  echo "GET ${ep}: HTTP $CODE"
done
# Follow-up: same IP tries legitimate request
curl -s --interface 127.0.0.85 -o /dev/null -w "Follow-up /game/list: %{http_code}\n" http://127.0.0.1:8080/game/list
# Pass: All 4 canaries = 403 AND follow-up = 403 (IP locked)`, wafBaseURL),
		},
	}
}

// ── URL Replacement Helper ──

// applyURLs replaces hardcoded localhost URLs with the configured WAF base URL.
func applyURLs(script, wafBaseURL string) string {
	return strings.NewReplacer(
		"http://127.0.0.1:8080", wafBaseURL,
	).Replace(script)
}
