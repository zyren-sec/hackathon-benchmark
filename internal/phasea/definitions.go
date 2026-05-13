package phasea

// GetVulnTests returns all 20 V* test definitions (V01–V24, excluding V12/V13/V17/V18).
// Source: phase_A.md §6.5 Vulnerability Catalog + §5.4 Decision Matrix
func GetVulnTests() []VulnTest {
	return []VulnTest{
		// ── CAT 1: SQL Injection (V01–V03) ──
		{
			ID: "V01", Name: "SQLi Classic",
			Category: "SQLi", ThreatGroup: "High-confidence injection",
			Method: "POST", Endpoint: "/login",
			AuthRequired: false,
			ProofMarker: "__V01_LOGIN_BYPASS__",
			Tier: "CRITICAL", RiskMin: 70, RiskMax: 100,
			ContentType:  "application/json",
			BodyTemplate: `{"username":"%s","password":"x"}`,
			PayloadCat:   "sqli",
			Description:  "SQL Injection classic OR - username parameter",
		},
		{
			ID: "V02", Name: "SQLi UNION",
			Category: "SQLi", ThreatGroup: "High-confidence injection",
			Method: "GET", Endpoint: "/api/transactions",
			AuthRequired: true,
			ProofMarker: "__V02_USER_DUMP__",
			Tier: "CRITICAL", RiskMin: 70, RiskMax: 100,
			QueryParam:  "page",
			PayloadCat:  "sqli",
			Description: "SQL Injection UNION - page parameter",
		},
		{
			ID: "V03", Name: "Blind SQLi (timing)",
			Category: "SQLi", ThreatGroup: "Blind / Timing-based injection",
			Method: "POST", Endpoint: "/login",
			AuthRequired: false,
			ProofMarker: "",
			Tier: "HIGH", RiskMin: 50, RiskMax: 85,
			Special:      "v03_timing",
			ContentType:  "application/json",
			BodyTemplate: `{"username":"%s","password":"x"}`,
			PayloadCat:   "sqli",
			Description:  "Blind SQL Injection time-based - SLEEP detection",
		},

		// ── CAT 2: XSS (V04–V05) ──
		{
			ID: "V04", Name: "Reflected XSS",
			Category: "XSS", ThreatGroup: "High-confidence injection",
			Method: "GET", Endpoint: "/game/1",
			AuthRequired: false,
			ProofMarker: "__V04_XSS__",
			Tier: "CRITICAL", RiskMin: 70, RiskMax: 100,
			QueryParam:  "name",
			PayloadCat:  "xss",
			Description: "Reflected XSS - name parameter echoed unescaped",
		},
		{
			ID: "V05", Name: "Stored XSS",
			Category: "XSS", ThreatGroup: "Stored XSS",
			Method: "PUT", Endpoint: "/api/profile",
			AuthRequired: true,
			ProofMarker: "__V05_STORED__",
			Tier: "CRITICAL", RiskMin: 70, RiskMax: 100,
			Special:      "v05_stored",
			ContentType:  "application/json",
			BodyTemplate: `{"display_name":"%s"}`,
			PayloadCat:   "xss",
			Description:  "Stored XSS - display_name parameter stored and returned",
		},

		// ── CAT 3: Path Traversal (V06–V07) ──
		{
			ID: "V06", Name: "Path Traversal",
			Category: "PathTraversal", ThreatGroup: "Path traversal",
			Method: "GET", Endpoint: "/static/",
			AuthRequired: false,
			ProofMarker: "__V06_TRAVERSAL__",
			Tier: "CRITICAL", RiskMin: 70, RiskMax: 100,
			PayloadCat:  "path_traversal",
			Description: "Path Traversal raw - double dot slash",
			// Payload is appended to the URL path directly
		},
		{
			ID: "V07", Name: "Path Traversal Enc",
			Category: "PathTraversal", ThreatGroup: "Path traversal",
			Method: "GET", Endpoint: "/static/",
			AuthRequired: false,
			ProofMarker: "__V07_TRAVERSAL_ENC__",
			Tier: "CRITICAL", RiskMin: 70, RiskMax: 100,
			PayloadCat:  "path_traversal",
			Description: "Path Traversal URL-encoded - %2e%2e",
			// Payload is appended to the URL path directly
		},

		// ── CAT 4: SSRF (V08–V09) ──
		{
			ID: "V08", Name: "SSRF Metadata",
			Category: "SSRF", ThreatGroup: "High-confidence injection",
			Method: "PUT", Endpoint: "/api/profile",
			AuthRequired: true,
			ProofMarker: "__V08_SSRF_META__",
			Tier: "HIGH", RiskMin: 50, RiskMax: 85,
			ContentType:  "application/json",
			BodyTemplate: `{"imageUrl":"%s"}`,
			PayloadCat:   "ssrf",
			Description:  "SSRF cloud metadata - imageUrl parameter",
		},
		{
			ID: "V09", Name: "SSRF Internal",
			Category: "SSRF", ThreatGroup: "High-confidence injection",
			Method: "POST", Endpoint: "/game/1/play",
			AuthRequired: true,
			ProofMarker: "__V09_SSRF_INTERNAL__",
			Tier: "HIGH", RiskMin: 50, RiskMax: 85,
			ContentType:  "application/json",
			BodyTemplate: `{"action":"%s"}`,
			PayloadCat:   "ssrf",
			Description:  "SSRF internal services - play action parameter",
		},

		// ── CAT 5: Protocol/Header Injection (V10–V11) ──
		{
			ID: "V10", Name: "CRLF Injection",
			Category: "HeaderInjection", ThreatGroup: "Protocol/Header injection",
			Method: "GET", Endpoint: "/",
			AuthRequired: false,
			ProofMarker: "__V10_CRLF__",
			Tier: "HIGH", RiskMin: 50, RiskMax: 85,
			QueryParam:  "q", // payload sent as query param value
			PayloadCat:  "header_injection",
			Description: "CRLF injection - response splitting",
		},
		{
			ID: "V11", Name: "Host Header Inject",
			Category: "HeaderInjection", ThreatGroup: "Protocol/Header injection",
			Method: "GET", Endpoint: "/",
			AuthRequired: false,
			ProofMarker: "__V11_HOST_INJECT__",
			Tier: "MEDIUM", RiskMin: 30, RiskMax: 65,
			ExtraHeaders: map[string]string{}, // Host header set dynamically
			PayloadCat:   "header_injection",
			Description:  "Host header injection - cache poisoning",
		},

		// ── CAT 6: Input Validation (V14–V16, V19) ──
		{
			ID: "V14", Name: "Malformed JSON",
			Category: "InputValidation", ThreatGroup: "Input validation",
			Method: "POST", Endpoint: "/deposit",
			AuthRequired: true,
			ProofMarker: "__V14_MALFORMED__",
			Tier: "MEDIUM", RiskMin: 30, RiskMax: 65,
			ContentType:  "application/json",
			BodyTemplate: `%s`, // raw — payloads are already complete JSON
			PayloadCat:   "input_validation",
			Description:  "Malformed JSON - NaN/Infinity values",
		},
		{
			ID: "V15", Name: "Oversized Payload",
			Category: "InputValidation", ThreatGroup: "Input validation",
			Method: "POST", Endpoint: "/login",
			AuthRequired: false,
			ProofMarker: "__V15_OVERSIZE__",
			Tier: "MEDIUM", RiskMin: 30, RiskMax: 65,
			ContentType:  "application/json",
			BodyTemplate: `{"username":"%s","password":"x"}`,
			PayloadCat:   "input_validation",
			Description:  "Oversized payload - >1MB request body",
		},
		{
			ID: "V16", Name: "Content-Type Bypass",
			Category: "InputValidation", ThreatGroup: "Input validation ─ CT bypass",
			Method: "POST", Endpoint: "/login",
			AuthRequired: false,
			ProofMarker: "__V16_CTYPE_BYPASS__",
			Tier: "HIGH", RiskMin: 50, RiskMax: 85,
			ContentType:  "text/plain",
			BodyTemplate: `%s`, // raw SQLi — sent as text/plain
			PayloadCat:   "sqli",
			Description:  "Content-Type bypass - SQLi in text/plain body",
		},
		{
			ID: "V19", Name: "Deeply Nested JSON",
			Category: "InputValidation", ThreatGroup: "Input validation",
			Method: "POST", Endpoint: "/deposit",
			AuthRequired: true,
			ProofMarker: "__V19_NESTED__",
			Tier: "MEDIUM", RiskMin: 30, RiskMax: 65,
			ContentType:  "application/json",
			BodyTemplate: `%s`, // raw — payloads are already nested JSON
			PayloadCat:   "input_validation",
			Description:  "Deeply nested JSON - >100 nesting levels",
		},

		// ── CAT 7: Business Logic & Misc (V20–V24) ──
		{
			ID: "V20", Name: "Supply Chain (JNDI)",
			Category: "SupplyChain", ThreatGroup: "Supply chain / JNDI",
			Method: "POST", Endpoint: "/api/feedback",
			AuthRequired: false,
			ProofMarker: "__V20_SUPPLY_CHAIN__",
			Tier: "CRITICAL", RiskMin: 70, RiskMax: 100,
			ContentType:  "application/json",
			BodyTemplate: `{"feedback":"%s"}`,
			PayloadCat:   "template_injection",
			Description:  "Supply-chain attack - JNDI/Log4Shell injection",
		},
		{
			ID: "V21", Name: "Asymmetric DoS",
			Category: "BusinessLogic", ThreatGroup: "Asymmetric DoS",
			Method: "POST", Endpoint: "/api/bet-reports/export",
			AuthRequired: true,
			ProofMarker: "__V21_ASYMMETRIC_DOS__",
			Tier: "MEDIUM", RiskMin: 30, RiskMax: 65,
			ContentType:  "application/json",
			BodyTemplate: `{"format":"%s"}`,
			PayloadCat:   "command_injection",
			Description:  "Asymmetric DoS - resource-intensive export",
		},
		{
			ID: "V22", Name: "Admin ACL Bypass",
			Category: "AccessControl", ThreatGroup: "Access control bypass",
			Method: "GET", Endpoint: "/admin/dashboard",
			AuthRequired: false,
			ProofMarker: "__V22_ADMIN_ACL__",
			Tier: "CRITICAL", RiskMin: 70, RiskMax: 100,
			PayloadCat:  "path_traversal",
			Description: "Admin ACL bypass - unauthorized dashboard access",
			// Additional endpoints tested via payload substitution
		},
		{
			ID: "V23", Name: "Config File Leak",
			Category: "AccessControl", ThreatGroup: "Access control bypass",
			Method: "GET", Endpoint: "/.git/config",
			AuthRequired: false,
			ProofMarker: "__V23_CONFIG_LEAK__",
			Tier: "CRITICAL", RiskMin: 70, RiskMax: 100,
			PayloadCat:  "path_traversal",
			Description: "Config file exposure - /.git/config and /config.yaml",
			// Additional endpoints tested via payload substitution
		},
		{
			ID: "V24", Name: "Race Condition",
			Category: "BusinessLogic", ThreatGroup: "Race condition",
			Method: "POST", Endpoint: "/api/rewards/claim",
			AuthRequired: true,
			ProofMarker: "__V24_RACE_CONDITION__",
			Tier: "HIGH", RiskMin: 50, RiskMax: 85,
			Special:      "v24_race",
			ContentType:  "application/json",
			BodyTemplate: `%s`, // raw JSON payload
			PayloadCat:   "input_validation",
			Description:  "Race condition - TOCTOU reward claiming",
		},
	}
}

// GetCategories returns the 7 category groups in display order.
func GetCategories() []struct {
	Num     int
	Title   string
	IDRange string
	IDs     []string
} {
	return []struct {
		Num     int
		Title   string
		IDRange string
		IDs     []string
	}{
		{Num: 1, Title: "SQL Injection", IDRange: "V01–V03", IDs: []string{"V01", "V02", "V03"}},
		{Num: 2, Title: "XSS", IDRange: "V04–V05", IDs: []string{"V04", "V05"}},
		{Num: 3, Title: "Path Traversal", IDRange: "V06–V07", IDs: []string{"V06", "V07"}},
		{Num: 4, Title: "SSRF", IDRange: "V08–V09", IDs: []string{"V08", "V09"}},
		{Num: 5, Title: "Protocol/Header Injection", IDRange: "V10–V11", IDs: []string{"V10", "V11"}},
		{Num: 6, Title: "Input Validation", IDRange: "V14–V16, V19", IDs: []string{"V14", "V15", "V16", "V19"}},
		{Num: 7, Title: "Business Logic & Misc", IDRange: "V20–V24", IDs: []string{"V20", "V21", "V22", "V23", "V24"}},
	}
}

// TierToRiskRange maps tier to expected risk range.
func TierToRiskRange(tier string) (int, int) {
	switch tier {
	case "CRITICAL":
		return 70, 100
	case "HIGH":
		return 50, 85
	case "MEDIUM":
		return 30, 65
	default:
		return 0, 100
	}
}
