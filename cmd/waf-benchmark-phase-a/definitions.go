// Test Definitions from exploit_catalogue.md
// Based on WAF Hackathon 2026 specifications

package main

// GetTestDefinitions returns all test cases from exploit_catalogue.md
func GetTestDefinitions() []TestDefinition {
	return []TestDefinition{
		// V01 - SQL Injection (classic OR)
		{
			ID:       "V01",
			Category: "SQLi",
			Method:   "POST",
			Path:     "/login",
			Auth:     false,
			Marker:   "__V01_LOGIN_BYPASS__",
			Severity: "Critical",
			Description: "SQL Injection classic OR - username parameter",
			Payloads: GetSQLiAdvancedPayloads(),
		},
		// V02 - SQL Injection (UNION dump)
		{
			ID:       "V02",
			Category: "SQLi",
			Method:   "GET",
			Path:     "/api/transactions",
			Auth:     true,
			Marker:   "__V02_USER_DUMP__",
			Severity: "Critical",
			Description: "SQL Injection UNION - page parameter",
			Payloads: []AdvancedPayload{
				{
					Name:       "UNION_BASIC",
					RawPayload: "1 UNION SELECT username,password_hash FROM users",
					Variants: []string{
						"1%20UNION%20SELECT%20username,password_hash%20FROM%20users",
						"1+UNION+SELECT+username,password_hash+FROM+users",
						"1/*!50000UNION*/SELECT/*!50000username*/,password_hash/*!50000FROM*/users",
					},
					Technique:   "union_injection",
					ContentType: "",
				},
			},
		},
		// V03 - Blind SQLi (time-based)
		{
			ID:       "V03",
			Category: "SQLi",
			Method:   "POST",
			Path:     "/login",
			Auth:     false,
			Marker:   "X-Query-Time-Ms",
			Severity: "High",
			Description: "Blind SQL Injection time-based - SLEEP detection via header",
			Payloads: []AdvancedPayload{
				{
					Name:       "SLEEP_BASIC",
					RawPayload: `{"username":"x\" SLEEP(3) --","password":"x"}`,
					Variants: []string{
						`{"username":"x\" SLEEP(3) --","password":"x"}`,
						`{"username":"x\"%20SLEEP(3)%20--","password":"x"}`,
						`{"username":"x\"/**/SLEEP(3)/**/--","password":"x"}`,
						`{"username":"x\"%20OR%20SLEEP(3)%20--","password":"x"}`,
					},
					Technique:   "time_based_blind",
					ContentType: "application/json",
				},
			},
		},
		// V04 - Reflected XSS
		{
			ID:       "V04",
			Category: "XSS",
			Method:   "GET",
			Path:     "/game/1",
			Auth:     false,
			Marker:   "__V04_XSS__",
			Severity: "Critical",
			Description: "Reflected XSS - name parameter echoed unescaped",
			Payloads: GetXSSAdvancedPayloads(),
		},
		// V05 - Stored XSS
		{
			ID:       "V05",
			Category: "XSS",
			Method:   "PUT",
			Path:     "/api/profile",
			Auth:     true,
			Marker:   "<img src=x onerror=alert(1)>",
			Severity: "Critical",
			Description: "Stored XSS - display_name parameter stored and returned",
			Payloads: GetStoredXSSPayloads(),
		},
		// V06 - Path Traversal (raw)
		{
			ID:       "V06",
			Category: "PathTraversal",
			Method:   "GET",
			Path:     "/static/../../etc/passwd",
			Auth:     false,
			Marker:   "__V06_TRAVERSAL__",
			Severity: "Critical",
			Description: "Path Traversal raw - double dot slash",
			Payloads: GetPathTraversalPayloads(),
		},
		// V07 - Path Traversal (URL-encoded)
		{
			ID:       "V07",
			Category: "PathTraversal",
			Method:   "GET",
			Path:     "/static/%2e%2e/%2e%2e/etc/passwd",
			Auth:     false,
			Marker:   "__V07_TRAVERSAL_ENC__",
			Severity: "Critical",
			Description: "Path Traversal URL-encoded - %2e%2e",
			Payloads: []AdvancedPayload{
				{
					Name:       "ENCODED_BASIC",
					RawPayload: "/static/%2e%2e/%2e%2e/etc/passwd",
					Variants: []string{
						"/static/%2e%2e/%2e%2e/etc/passwd",
						"/static/%252e%252e/%252e%252e/etc/passwd",
						"/static/..%2f..%2fetc/passwd",
						"/static/....//....//....//etc/passwd",
						"/static/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
					},
					Technique:   "url_encoding",
					ContentType: "",
				},
			},
		},
		// V08 - SSRF (cloud metadata)
		{
			ID:       "V08",
			Category: "SSRF",
			Method:   "PUT",
			Path:     "/api/profile",
			Auth:     true,
			Marker:   "__V08_SSRF_META__",
			Severity: "High",
			Description: "SSRF cloud metadata - 169.254.169.254",
			Payloads: GetSSRFPayloads(),
		},
		// V09 - SSRF (internal callback)
		{
			ID:       "V09",
			Category: "SSRF",
			Method:   "POST",
			Path:     "/game/1/play",
			Auth:     true,
			Marker:   "__V09_SSRF_INTERNAL__",
			Severity: "High",
			Description: "SSRF internal callback - localhost/127.0.0.1",
			Payloads: []AdvancedPayload{
				{
					Name:       "INTERNAL_LOCALHOST",
					RawPayload: `{"bet":5,"callback_url":"http://127.0.0.1/admin/dashboard"}`,
					Variants: []string{
						`{"bet":5,"callback_url":"http://127.0.0.1/admin/dashboard"}`,
						`{"bet":5,"callback_url":"http://localhost/admin/dashboard"}`,
						`{"bet":5,"callback_url":"http://0.0.0.0/admin/dashboard"}`,
						`{"bet":5,"callback_url":"http://[::1]/admin/dashboard"}`,
						`{"bet":5,"callback_url":"http://0177.0.0.1/admin/dashboard"}`,
						`{"bet":5,"callback_url":"http://2130706433/admin/dashboard"}`,
					},
					Technique:   "internal_ip",
					ContentType: "application/json",
				},
			},
		},
		// V10 - CRLF injection
		{
			ID:       "V10",
			Category: "CRLF",
			Method:   "GET",
			Path:     "/game/list",
			Auth:     false,
			Marker:   "__V10_CRLF__",
			Severity: "High",
			Description: "CRLF injection - header injection via \r\n",
			Payloads: GetCRLFPayloads(),
		},
		// V11 - Host header injection
		{
			ID:       "V11",
			Category: "HostInjection",
			Method:   "GET",
			Path:     "/",
			Auth:     false,
			Marker:   "__V11_HOST_INJECT__",
			Severity: "Medium",
			Description: "Host header injection - evil.com in Host header",
			Payloads: []AdvancedPayload{
				{
					Name:       "HOST_INJECT",
					RawPayload: "Host: evil.com",
					Variants: []string{
						"evil.com",
						"evil.com:80",
						"evil.com:443",
						"evil.com\r\nX-Injected: test",
					},
					Technique:   "header_injection",
					ContentType: "",
				},
			},
		},
		// V16 - Content-Type bypass
		{
			ID:       "V16",
			Category: "SQLi",
			Method:   "POST",
			Path:     "/login",
			Auth:     false,
			Marker:   "__V16_CTYPE_BYPASS__",
			Severity: "High",
			Description: "Content-Type bypass - SQLi with text/plain",
			Payloads: []AdvancedPayload{
				{
					Name:       "CTYPE_BYPASS",
					RawPayload: `{"username":"alice" OR "1"="1","password":"x"}`,
					Variants: []string{
						`{"username":"alice" OR "1"="1","password":"x"}`,
					},
					Technique:   "content_type_bypass",
					ContentType: "text/plain",
				},
			},
		},
		// V20 - Supply Chain (Log4Shell)
		{
			ID:       "V20",
			Category: "SupplyChain",
			Method:   "POST",
			Path:     "/api/feedback",
			Auth:     false,
			Marker:   "__V20_SUPPLY_CHAIN__",
			Severity: "Critical",
			Description: "Supply chain - Log4Shell JNDI injection",
			Payloads: GetSupplyChainPayloads(),
		},
		// V22 - Admin ACL bypass
		{
			ID:       "V22",
			Category: "ACL",
			Method:   "GET",
			Path:     "/admin/dashboard",
			Auth:     false,
			Marker:   "__V22_ADMIN_ACL__",
			Severity: "Critical",
			Description: "Admin ACL bypass - unauthenticated admin access",
			Payloads: []AdvancedPayload{
				{
					Name:       "ADMIN_DIRECT",
					RawPayload: "GET /admin/dashboard",
					Variants: []string{
						"/admin/dashboard",
						"/admin/users",
					},
					Technique:   "direct_access",
					ContentType: "",
				},
			},
		},
		// V23 - Config file exposure
		{
			ID:       "V23",
			Category: "ConfigExposure",
			Method:   "GET",
			Path:     "/.git/config",
			Auth:     false,
			Marker:   "__V23_CONFIG_LEAK__",
			Severity: "Critical",
			Description: "Config file exposure - .git/config, .env, etc.",
			Payloads: []AdvancedPayload{
				{
					Name:       "GIT_CONFIG",
					RawPayload: "GET /.git/config",
					Variants: []string{
						"/.git/config",
						"/.htaccess",
						"/config.yaml",
						"/config.json",
						"/.env",
						"/.env.bak",
						"/backup.sql",
					},
					Technique:   "sensitive_files",
					ContentType: "",
				},
			},
		},
		// V14 - Malformed JSON (Infinity / NaN / overflow)
		{
			ID:       "V14",
			Category: "MalformedInput",
			Method:   "POST",
			Path:     "/deposit",
			Auth:     true,
			Marker:   "__V14_MALFORMED__",
			Severity: "Medium",
			Description: "Malformed JSON - Infinity/NaN/overflow in amount field",
			Payloads: []AdvancedPayload{
				{
					Name:       "OVERFLOW",
					RawPayload: `{"amount":1e308,"currency":"USD"}`,
					Variants: []string{
						`{"amount":1e308,"currency":"USD"}`,
						`{"amount":Infinity,"currency":"USD"}`,
						`{"amount":NaN,"currency":"USD"}`,
						`{"amount":9999999999999999999999999999999,"currency":"USD"}`,
					},
					Technique:   "numeric_overflow",
					ContentType: "application/json",
				},
			},
		},
		// V15 - Oversized payload (>1 MB)
		{
			ID:       "V15",
			Category: "MalformedInput",
			Method:   "POST",
			Path:     "/login",
			Auth:     false,
			Marker:   "__V15_OVERSIZE__",
			Severity: "Medium",
			Description: "Oversized payload >1 MB to exhaust server resources",
			Payloads: GetOversizedPayloads(),
		},
		// V19 - Deeply nested JSON (>100 levels)
		{
			ID:       "V19",
			Category: "MalformedInput",
			Method:   "POST",
			Path:     "/deposit",
			Auth:     true,
			Marker:   "__V19_NESTED__",
			Severity: "Medium",
			Description: "Deeply nested JSON >100 levels to crash parser",
			Payloads: GetDeeplyNestedPayloads(),
		},
		// V21 - Asymmetric DoS (expensive export)
		{
			ID:       "V21",
			Category: "DoS",
			Method:   "POST",
			Path:     "/api/bet-reports/export",
			Auth:     true,
			Marker:   "__V21_ASYMMETRIC_DOS__",
			Severity: "Medium",
			Description: "Asymmetric DoS - expensive export consuming ~3s CPU per request",
			Payloads: []AdvancedPayload{
				{
					Name:       "EXPORT_PDF",
					RawPayload: `{"format":"pdf"}`,
					Variants: []string{
						`{"format":"pdf"}`,
						`{"format":"csv"}`,
					},
					Technique:   "expensive_operation",
					ContentType: "application/json",
				},
			},
		},
		// V24 - Race condition (TOCTOU on reward claim)
		{
			ID:       "V24",
			Category: "RaceCondition",
			Method:   "POST",
			Path:     "/api/rewards/claim",
			Auth:     true,
			Marker:   "__V24_RACE_CONDITION__",
			Severity: "High",
			Description: "Race condition TOCTOU - concurrent reward claims",
			Payloads: []AdvancedPayload{
				{
					Name:       "RACE_CLAIM",
					RawPayload: `POST /api/rewards/claim`,
					Variants: []string{
						`{}`,
						`{"claim":"reward"}`,
					},
					Technique:   "toctou",
					ContentType: "application/json",
				},
			},
		},
		// L01 - Stack trace leak
		{
			ID:       "L01",
			Category: "Leak",
			Method:   "GET",
			Path:     "/game/list",
			Auth:     false,
			Marker:   "__L01_STACKTRACE__",
			Severity: "Medium",
			Description: "Stack trace leak in error responses",
			Payloads: []AdvancedPayload{
				{
					Name:       "TRIGGER_ERROR",
					RawPayload: "Trigger 500 error",
					Variants: []string{
						"invalid",
					},
					Technique:   "error_trigger",
					ContentType: "",
				},
			},
		},
		// L03 - Debug SQL header
		{
			ID:       "L03",
			Category: "Leak",
			Method:   "GET",
			Path:     "/game/list",
			Auth:     false,
			Marker:   "__L03_DEBUG_SQL__",
			Severity: "Medium",
			Description: "Debug SQL header in every response",
			Payloads: []AdvancedPayload{
				{
					Name:       "CHECK_HEADER",
					RawPayload: "GET /game/list",
					Variants: []string{
						"/game/list",
					},
					Technique:   "header_check",
					ContentType: "",
				},
			},
		},
		// L02 - Internal IP in X-Internal-Host header
		{
			ID:       "L02",
			Category: "Leak",
			Method:   "GET",
			Path:     "/api/profile",
			Auth:     true,
			Marker:   "__L02_INTERNAL_IP__",
			Severity: "Medium",
			Description: "Internal IP leaked in X-Internal-Host response header",
			Payloads: []AdvancedPayload{
				{
					Name:       "CHECK_INTERNAL_IP",
					RawPayload: "GET /api/profile",
					Variants: []string{
						"/api/profile",
					},
					Technique:   "header_check",
					ContentType: "",
				},
			},
		},
		// L04 - PII fields in profile / admin responses
		{
			ID:       "L04",
			Category: "Leak",
			Method:   "GET",
			Path:     "/api/profile",
			Auth:     true,
			Marker:   "__L04_PII__",
			Severity: "Critical",
			Description: "PII data (credit card, SSN, bank account) leaked in profile/admin responses",
			Payloads: []AdvancedPayload{
				{
					Name:       "PII_PROFILE",
					RawPayload: "GET /api/profile",
					Variants: []string{
						"/api/profile",
					},
					Technique:   "pii_check",
					ContentType: "",
				},
				{
					Name:       "PII_ADMIN",
					RawPayload: "GET /admin/users",
					Variants: []string{
						"/admin/users",
					},
					Technique:   "pii_check",
					ContentType: "",
				},
			},
		},
		// L05 - Verbose 404 paths
		{
			ID:       "L05",
			Category: "Leak",
			Method:   "GET",
			Path:     "/nonexistent",
			Auth:     false,
			Marker:   "__L05_VERBOSE_404__",
			Severity: "Low",
			Description: "Verbose 404 leaks internal paths in response body",
			Payloads: []AdvancedPayload{
				{
					Name:       "VERBOSE_404",
					RawPayload: "GET /nonexistent",
					Variants: []string{
						"/nonexistent",
					},
					Technique:   "path_leak",
					ContentType: "",
				},
			},
		},
		// CANARY endpoints
		{
			ID:       "CANARY-1",
			Category: "Canary",
			Method:   "GET",
			Path:     "/admin-test",
			Auth:     false,
			Marker:   "__CANARY_HIT__",
			Severity: "High",
			Description: "Canary honeypot - /admin-test",
			Payloads: []AdvancedPayload{
				{
					Name:       "ADMIN_TEST",
					RawPayload: "GET /admin-test",
					Variants:   []string{"/admin-test"},
					Technique:  "honeypot",
				},
			},
		},
		{
			ID:       "CANARY-2",
			Category: "Canary",
			Method:   "GET",
			Path:     "/api-debug",
			Auth:     false,
			Marker:   "__CANARY_HIT__",
			Severity: "High",
			Description: "Canary honeypot - /api-debug",
			Payloads: []AdvancedPayload{
				{
					Name:       "API_DEBUG",
					RawPayload: "GET /api-debug",
					Variants:   []string{"/api-debug"},
					Technique:  "honeypot",
				},
			},
		},
		{
			ID:       "CANARY-3",
			Category: "Canary",
			Method:   "GET",
			Path:     "/.env",
			Auth:     false,
			Marker:   "__CANARY_HIT__",
			Severity: "High",
			Description: "Canary honeypot - /.env",
			Payloads: []AdvancedPayload{
				{
					Name:       "ENV_FILE",
					RawPayload: "GET /.env",
					Variants:   []string{"/.env"},
					Technique:  "honeypot",
				},
			},
		},
		{
			ID:       "CANARY-4",
			Category: "Canary",
			Method:   "GET",
			Path:     "/wp-admin",
			Auth:     false,
			Marker:   "__CANARY_HIT__",
			Severity: "High",
			Description: "Canary honeypot - /wp-admin",
			Payloads: []AdvancedPayload{
				{
					Name:       "WP_ADMIN",
					RawPayload: "GET /wp-admin",
					Variants:   []string{"/wp-admin"},
					Technique:  "honeypot",
				},
			},
		},
	}
}
