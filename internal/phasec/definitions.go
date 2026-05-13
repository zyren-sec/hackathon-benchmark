package phasec

import "fmt"

// ── Endpoint Classes for Baseline & WAF Latency ──

// GetEndpointClasses returns the 4 endpoint classes used for latency measurement.
func GetEndpointClasses() []struct {
	Name      string
	Endpoints []string
	Samples   int
} {
	return []struct {
		Name      string
		Endpoints []string
		Samples   int
	}{
		{
			Name:      "critical",
			Endpoints: []string{"/login", "/deposit", "/withdraw"},
			Samples:   250,
		},
		{
			Name:      "high",
			Endpoints: []string{"/api/profile", "/game/list"},
			Samples:   250,
		},
		{
			Name:      "medium",
			Endpoints: []string{"/static/js/app.js", "/static/css/style.css", "/api/transactions"},
			Samples:   250,
		},
		{
			Name:      "catch_all",
			Endpoints: []string{"/health", "/"},
			Samples:   250,
		},
	}
}

// ── Load Test Steps Configuration ──

// GetLoadTestSteps returns the 4 sequential load test steps per §5.
func GetLoadTestSteps() []LoadTestConfig {
	return []LoadTestConfig{
		{StepNum: 1, TargetRPS: 1000, DurationSec: 30, Marker: "", Purpose: "Baseline load"},
		{StepNum: 2, TargetRPS: 3000, DurationSec: 30, Marker: "", Purpose: "Intermediate"},
		{StepNum: 3, TargetRPS: 5000, DurationSec: 60, Marker: "⬤ SLA TARGET", Purpose: "Evaluates PERF-01 & PERF-02"},
		{StepNum: 4, TargetRPS: 10000, DurationSec: 60, Marker: "⚡ STRESS TEST", Purpose: "Evaluates PERF-04 (graceful degradation)"},
	}
}

// ── Golden Path (Legitimate Traffic — 10-step flow) ──

// GetGoldenPath returns the 10-step legitimate user flow for 60% traffic.
func GetGoldenPath() []GoldenPathStep {
	return []GoldenPathStep{
		{StepNum: 1, Name: "GET /", Method: "GET", Endpoint: "/", ContentType: "", ExpectedStatus: 200},
		{StepNum: 2, Name: "GET /health", Method: "GET", Endpoint: "/health", ContentType: "", ExpectedStatus: 200},
		{StepNum: 3, Name: "POST /login", Method: "POST", Endpoint: "/login",
			Body: `{"username":"testuser_90","password":"Test#90Pass"}`,
			ContentType: "application/json", ExpectedStatus: 200},
		{StepNum: 4, Name: "POST /otp", Method: "POST", Endpoint: "/otp",
			Body:        `{"login_token":"${TOKEN}","otp_code":"000090"}`,
			ContentType: "application/json", ExpectedStatus: 200},
		{StepNum: 5, Name: "GET /game/list", Method: "GET", Endpoint: "/game/list",
			ContentType: "", ExpectedStatus: 200},
		{StepNum: 6, Name: "GET /api/profile", Method: "GET", Endpoint: "/api/profile",
			ContentType: "", ExpectedStatus: 200},
		{StepNum: 7, Name: "GET /api/transactions", Method: "GET", Endpoint: "/api/transactions",
			ContentType: "", ExpectedStatus: 200},
		{StepNum: 8, Name: "POST /deposit", Method: "POST", Endpoint: "/deposit",
			Body:        `{"amount":100,"currency":"USD"}`,
			ContentType: "application/json", ExpectedStatus: 200},
		{StepNum: 9, Name: "POST /withdraw", Method: "POST", Endpoint: "/withdraw",
			Body:        `{"amount":50,"currency":"USD"}`,
			ContentType: "application/json", ExpectedStatus: 200},
		{StepNum: 10, Name: "GET /logout", Method: "GET", Endpoint: "/logout",
			ContentType: "", ExpectedStatus: 200},
	}
}

// ── Suspicious but Legitimate Endpoints (10% traffic) ──

// GetSuspiciousEndpoints returns endpoints that look suspicious but are legitimate.
func GetSuspiciousEndpoints() []struct {
	Method      string
	Endpoint    string
	Body        string
	ContentType string
} {
	return []struct {
		Method      string
		Endpoint    string
		Body        string
		ContentType string
	}{
		{Method: "POST", Endpoint: "/login",
			Body:        `{"username":"does_not_exist_99","password":"wrong_pass"}`,
			ContentType: "application/json"},
		{Method: "GET", Endpoint: "/static/js/nonexistent.js",
			ContentType: ""},
		{Method: "GET", Endpoint: "/api/admin/users",
			ContentType: ""},
		{Method: "PUT", Endpoint: "/api/profile",
			Body:        `{"display_name":"<b>Normal User</b>","imageUrl":"https://example.com/avatar.png"}`,
			ContentType: "application/json"},
		{Method: "GET", Endpoint: "/game/99999",
			ContentType: ""},
		{Method: "POST", Endpoint: "/api/feedback",
			Body:        `{"feedback":"Great game but needs more levels!"}`,
			ContentType: "application/json"},
		{Method: "GET", Endpoint: "/api/transactions?page=100",
			ContentType: ""},
	}
}

// ── Exploit Payloads (10% traffic — V01, V04, V06, V09) ──

// GetExploitPayloads returns exploit payloads for Phase C blended traffic.
func GetExploitPayloads() []ExploitPayloadConfig {
	return []ExploitPayloadConfig{
		{
			VulnID: "V01", Name: "SQLi Classic",
			Category: "SQLi", Method: "POST", Endpoint: "/login",
			Payload:     `{"username":"admin' OR '1'='1' --","password":"x"}`,
			ContentType: "application/json",
			ProofMarker: "__V01_LOGIN_BYPASS__",
		},
		{
			VulnID: "V04", Name: "Reflected XSS",
			Category: "XSS", Method: "GET", Endpoint: "/game/1",
			Payload:     `name=<script>alert('XSS')</script>`,
			ContentType: "",
			ProofMarker: "__V04_XSS__",
		},
		{
			VulnID: "V06", Name: "Path Traversal",
			Category: "PathTraversal", Method: "GET", Endpoint: "/static/",
			Payload:     `../../etc/passwd`,
			ContentType: "",
			ProofMarker: "__V06_TRAVERSAL__",
		},
		{
			VulnID: "V09", Name: "SSRF Internal",
			Category: "SSRF", Method: "POST", Endpoint: "/game/1/play",
			Payload:     `{"action":"http://169.254.169.254/latest/meta-data/"}`,
			ContentType: "application/json",
			ProofMarker: "__V09_SSRF_INTERNAL__",
		},
	}
}

// ── Abuse Patterns (10% traffic) ──

// GetAbusePatterns returns abuse pattern endpoints for blended traffic.
func GetAbusePatterns() []struct {
	Method      string
	Endpoint    string
	Body        string
	ContentType string
	Description string
} {
	return []struct {
		Method      string
		Endpoint    string
		Body        string
		ContentType string
		Description string
	}{
		{
			Method: "POST", Endpoint: "/login",
			Body:        `{"username":"admin","password":"password123"}`,
			ContentType: "application/json",
			Description: "Failed login attempt — common password",
		},
		{
			Method: "POST", Endpoint: "/login",
			Body:        `{"username":"root","password":"root"}`,
			ContentType: "application/json",
			Description: "Failed login attempt — default credentials",
		},
		{
			Method: "GET", Endpoint: "/admin/config",
			ContentType: "",
			Description: "Path scanning — /admin/config",
		},
		{
			Method: "GET", Endpoint: "/.env",
			ContentType: "",
			Description: "Path scanning — dotfile access",
		},
		{
			Method: "GET", Endpoint: "/wp-admin",
			ContentType: "",
			Description: "Path scanning — known admin path",
		},
		{
			Method: "OPTIONS", Endpoint: "/",
			ContentType: "",
			Description: "OPTIONS abuse — enumeration",
		},
		{
			Method: "GET", Endpoint: "/robots.txt",
			ContentType: "",
			Description: "Recon — robots.txt",
		},
		{
			Method: "GET", Endpoint: "/sitemap.xml",
			ContentType: "",
			Description: "Recon — sitemap.xml",
		},
	}
}

// ── DDoS Burst Endpoints ──

// GetDDoSBurstEndpoints returns endpoints used during DDoS bursts.
func GetDDoSBurstEndpoints() []string {
	return []string{
		"/",
		"/health",
		"/login",
		"/game/list",
		"/api/transactions",
	}
}

// ── Source IP Pool ──

// GetSourceIPPool returns loopback aliases for Phase C (127.0.0.200–220).
func GetSourceIPPool() []string {
	ips := make([]string, 21)
	for i := 0; i < 21; i++ {
		ips[i] = fmt.Sprintf("127.0.0.%d", 200+i)
	}
	return ips
}

// ── Browser Profile Rotation ──

// GetUserAgents returns a pool of User-Agent strings for rotation.
func GetUserAgents() []string {
	return []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
	}
}

// GetAcceptLanguages returns a pool of Accept-Language headers.
func GetAcceptLanguages() []string {
	return []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.8",
		"vi-VN,vi;q=0.9,en;q=0.7",
		"fr-FR,fr;q=0.9,en;q=0.6",
		"ja-JP,ja;q=0.9,en;q=0.5",
	}
}


