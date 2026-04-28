package waf

import (
	"strings"
	"testing"

	"github.com/valyala/fasthttp"
)

func TestDecisionString(t *testing.T) {
	tests := []struct {
		decision Decision
		expected string
	}{
		{Allow, "Allow"},
		{Block, "Block"},
		{Challenge, "Challenge"},
		{RateLimit, "RateLimit"},
		{CircuitBreaker, "CircuitBreaker"},
		{Timeout, "Timeout"},
		{UpstreamError, "UpstreamError"},
		{PreventedSanitized, "PreventedSanitized"},
		{ExploitPassed, "ExploitPassed"},
		{Unknown, "Unknown"},
		{Decision(999), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.decision.String(); got != tt.expected {
			t.Errorf("Decision(%d).String() = %s, want %s", tt.decision, got, tt.expected)
		}
	}
}

func TestDecisionIsPrevented(t *testing.T) {
	preventedDecisions := []Decision{Block, Challenge, RateLimit, CircuitBreaker, PreventedSanitized}
	nonPreventedDecisions := []Decision{Allow, ExploitPassed, Timeout, UpstreamError, Unknown}

	for _, d := range preventedDecisions {
		if !d.IsPrevented() {
			t.Errorf("Decision(%s).IsPrevented() = false, want true", d.String())
		}
	}

	for _, d := range nonPreventedDecisions {
		if d.IsPrevented() {
			t.Errorf("Decision(%s).IsPrevented() = true, want false", d.String())
		}
	}
}

func TestDecisionIsBypassed(t *testing.T) {
	if !ExploitPassed.IsBypassed() {
		t.Error("ExploitPassed.IsBypassed() should be true")
	}

	if Block.IsBypassed() {
		t.Error("Block.IsBypassed() should be false")
	}
}

func TestDecisionIsError(t *testing.T) {
	if !Timeout.IsError() {
		t.Error("Timeout.IsError() should be true")
	}
	if !UpstreamError.IsError() {
		t.Error("UpstreamError.IsError() should be true")
	}

	if Block.IsError() {
		t.Error("Block.IsError() should be false")
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       []byte
		headers    map[string]string
		expected   Decision
	}{
		{
			name:       "403 Forbidden",
			statusCode: 403,
			body:       []byte("blocked"),
			headers:    map[string]string{},
			expected:   Block,
		},
		{
			name:       "429 Rate Limit without challenge",
			statusCode: 429,
			body:       []byte("rate limited"),
			headers:    map[string]string{},
			expected:   RateLimit,
		},
		{
			name:       "429 Challenge with challenge body",
			statusCode: 429,
			body:       []byte("challenge required"),
			headers:    map[string]string{},
			expected:   Challenge,
		},
		{
			name:       "503 Circuit Breaker",
			statusCode: 503,
			body:       []byte("service unavailable"),
			headers:    map[string]string{},
			expected:   CircuitBreaker,
		},
		{
			name:       "504 Timeout",
			statusCode: 504,
			body:       []byte("gateway timeout"),
			headers:    map[string]string{},
			expected:   Timeout,
		},
		{
			name:       "502 Upstream Error",
			statusCode: 502,
			body:       []byte("bad gateway"),
			headers:    map[string]string{},
			expected:   UpstreamError,
		},
		{
			name:       "200 with markers - Exploit Passed",
			statusCode: 200,
			body:       []byte("response __V01_SQLI__ marker"),
			headers:    map[string]string{},
			expected:   ExploitPassed,
		},
		{
			name:       "200 no markers - Prevented/Sanitized",
			statusCode: 200,
			body:       []byte("safe response"),
			headers:    map[string]string{},
			expected:   PreventedSanitized,
		},
		{
			name:       "400 with markers",
			statusCode: 400,
			body:       []byte("__L01_STACKTRACE__"),
			headers:    map[string]string{},
			expected:   ExploitPassed,
		},
		{
			name:       "500 with markers",
			statusCode: 500,
			body:       []byte("error __V01_SQLI__"),
			headers:    map[string]string{},
			expected:   ExploitPassed,
		},
		{
			name:       "Unknown status without markers",
			statusCode: 418, // I'm a teapot
			body:       []byte("teapot"),
			headers:    map[string]string{},
			expected:   Unknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.statusCode, tt.body, tt.headers)
			if got != tt.expected {
				t.Errorf("Classify(%d, ...) = %v, want %v", tt.statusCode, got, tt.expected)
			}
		})
	}
}

func TestClassifyWithChallengeHeaders(t *testing.T) {
	// Test challenge detection via headers
	headers := map[string]string{
		"X-Challenge-Token": "abc123",
	}

	decision := Classify(429, []byte("rate limited"), headers)
	if decision != Challenge {
		t.Errorf("Expected Challenge, got %s", decision.String())
	}
}

func TestClassifyWithPoWHeaders(t *testing.T) {
	headers := map[string]string{
		"X-PoW-Challenge": "some-challenge",
	}

	decision := Classify(429, []byte("verify"), headers)
	if decision != Challenge {
		t.Errorf("Expected Challenge for PoW header, got %s", decision.String())
	}
}

func TestContainsChallenge(t *testing.T) {
	tests := []struct {
		body     string
		expected bool
	}{
		{"challenge required", true},
		{"CAPTCHA needed", true},
		{"proof-of-work token", true},
		{"please wait while we verify", true},
		{"javascript challenge", true},
		{"JS challenge required", true},
		{"normal response", false},
		{"just some text", false},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			got := containsChallenge([]byte(tt.body), map[string]string{})
			if got != tt.expected {
				t.Errorf("containsChallenge(%q) = %v, want %v", tt.body, got, tt.expected)
			}
		})
	}
}

func TestHasMarkers(t *testing.T) {
	tests := []struct {
		body     string
		headers  map[string]string
		expected bool
	}{
		{"response __V01_SQLI__", map[string]string{}, true},
		{"__L01_STACKTRACE__ found", map[string]string{}, true},
		{"__V14a_ERROR__ marker", map[string]string{}, true},
		{"normal response", map[string]string{}, false},
		{"", map[string]string{"X-Header": "__V01_TEST__"}, true},
		{"no marker", map[string]string{"X-Header": "value"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			got := hasMarkers([]byte(tt.body), tt.headers)
			if got != tt.expected {
				t.Errorf("hasMarkers(%q, headers) = %v, want %v", tt.body, got, tt.expected)
			}
		})
	}
}

func TestClassifyWithDetails(t *testing.T) {
	body := []byte("response __V01_SQLI__")
	headers := map[string]string{}

	decision, details := ClassifyWithDetails(200, body, headers)

	if decision != ExploitPassed {
		t.Errorf("Expected ExploitPassed, got %s", decision.String())
	}

	if details["status_code"] != 200 {
		t.Errorf("Expected status_code 200, got %v", details["status_code"])
	}

	if details["decision"] != "ExploitPassed" {
		t.Errorf("Expected decision ExploitPassed, got %v", details["decision"])
	}

	if details["has_markers"] != true {
		t.Errorf("Expected has_markers true, got %v", details["has_markers"])
	}
}

func TestNewWAFClient(t *testing.T) {
	client := NewWAFClient("127.0.0.1", 8080, 30)

	if client.host != "127.0.0.1" {
		t.Errorf("Expected host 127.0.0.1, got %s", client.host)
	}

	if client.port != 8080 {
		t.Errorf("Expected port 8080, got %d", client.port)
	}

	if client.timeout != 30 {
		t.Errorf("Expected timeout 30, got %v", client.timeout)
	}

	if client.clientPool == nil {
		t.Error("Expected client pool to be initialized")
	}
}

func TestWAFClientGetBaseURL(t *testing.T) {
	client := NewWAFClient("127.0.0.1", 8080, 30)

	expected := "http://127.0.0.1:8080"
	if got := client.GetBaseURL(); got != expected {
		t.Errorf("GetBaseURL() = %s, want %s", got, expected)
	}
}

func TestDetectMarkers(t *testing.T) {
	body := []byte("response __V01_SQLI__ and __L01_STACKTRACE__ here")
	headers := map[string]string{
		"X-Custom": "__V02_XSS__",
	}

	markers := DetectMarkers(body, headers)

	if len(markers) != 3 {
		t.Errorf("Expected 3 markers, got %d: %v", len(markers), markers)
	}

	// Check for specific markers
	found := make(map[string]bool)
	for _, m := range markers {
		found[m] = true
	}

	if !found["__V01_SQLI__"] {
		t.Error("Expected to find __V01_SQLI__")
	}

	if !found["__L01_STACKTRACE__"] {
		t.Error("Expected to find __L01_STACKTRACE__")
	}

	if !found["__V02_XSS__"] {
		t.Error("Expected to find __V02_XSS__")
	}
}

func TestDetectMarkersDuplicates(t *testing.T) {
	// Test that duplicates are removed
	body := []byte("__V01_SQLI__ and __V01_SQLI__ again")
	markers := DetectMarkers(body, map[string]string{})

	if len(markers) != 1 {
		t.Errorf("Expected 1 unique marker, got %d: %v", len(markers), markers)
	}
}

func TestDetectSpecificMarker(t *testing.T) {
	body := []byte("response __V01_SQLI__ here")
	headers := map[string]string{}

	if !DetectSpecificMarker(body, headers, "__V01_SQLI__") {
		t.Error("Expected to detect specific marker __V01_SQLI__")
	}

	if DetectSpecificMarker(body, headers, "__L01_STACKTRACE__") {
		t.Error("Should not detect marker __L01_STACKTRACE__")
	}
}

func TestIsVulnerabilityMarker(t *testing.T) {
	if !IsVulnerabilityMarker("__V01_SQLI__") {
		t.Error("Expected __V01_SQLI__ to be vulnerability marker")
	}

	if IsVulnerabilityMarker("__L01_STACKTRACE__") {
		t.Error("Expected __L01_STACKTRACE__ NOT to be vulnerability marker")
	}
}

func TestIsLeakMarker(t *testing.T) {
	if !IsLeakMarker("__L01_STACKTRACE__") {
		t.Error("Expected __L01_STACKTRACE__ to be leak marker")
	}

	if IsLeakMarker("__V01_SQLI__") {
		t.Error("Expected __V01_SQLI__ NOT to be leak marker")
	}
}

func TestExtractVulnerabilityID(t *testing.T) {
	tests := []struct {
		marker   string
		expected string
	}{
		{"__V01_SQLI__", "V01"},
		{"__V14a_ERROR__", "V14a"},
		{"__L01_STACKTRACE__", ""},
		{"__CANARY_TEST__", ""},
	}

	for _, tt := range tests {
		got := ExtractVulnerabilityID(tt.marker)
		if got != tt.expected {
			t.Errorf("ExtractVulnerabilityID(%q) = %s, want %s", tt.marker, got, tt.expected)
		}
	}
}

func TestExtractLeakID(t *testing.T) {
	tests := []struct {
		marker   string
		expected string
	}{
		{"__L01_STACKTRACE__", "L01"},
		{"__L05_VERBOSE_404__", "L05"},
		{"__V01_SQLI__", ""},
	}

	for _, tt := range tests {
		got := ExtractLeakID(tt.marker)
		if got != tt.expected {
			t.Errorf("ExtractLeakID(%q) = %s, want %s", tt.marker, got, tt.expected)
		}
	}
}

func TestCountVulnerabilityMarkers(t *testing.T) {
	markers := []string{"__V01_SQLI__", "__V02_XSS__", "__L01_STACKTRACE__", "__V03_CMD__"}

	count := CountVulnerabilityMarkers(markers)
	if count != 3 {
		t.Errorf("Expected 3 vulnerability markers, got %d", count)
	}
}

func TestCountLeakMarkers(t *testing.T) {
	markers := []string{"__V01_SQLI__", "__L01_STACKTRACE__", "__L02_IP__", "__V03_CMD__"}

	count := CountLeakMarkers(markers)
	if count != 2 {
		t.Errorf("Expected 2 leak markers, got %d", count)
	}
}

func TestFilterMarkersByPrefix(t *testing.T) {
	markers := []string{"__V01_SQLI__", "__V02_XSS__", "__L01_STACKTRACE__", "__L02_IP__"}

	vuln := FilterMarkersByPrefix(markers, "__V")
	if len(vuln) != 2 {
		t.Errorf("Expected 2 vulnerability markers, got %d", len(vuln))
	}

	leaks := FilterMarkersByPrefix(markers, "__L")
	if len(leaks) != 2 {
		t.Errorf("Expected 2 leak markers, got %d", len(leaks))
	}
}

func TestFilterMarkersByType(t *testing.T) {
	markers := []string{"__V01_SQLI__", "__V02_XSS__", "__L01_STACKTRACE__", "__L02_IP__"}

	vuln := FilterMarkersByType(markers, "vulnerability")
	if len(vuln) != 2 {
		t.Errorf("Expected 2 vulnerability markers, got %d", len(vuln))
	}

	leaks := FilterMarkersByType(markers, "leak")
	if len(leaks) != 2 {
		t.Errorf("Expected 2 leak markers, got %d", len(leaks))
	}

	all := FilterMarkersByType(markers, "all")
	if len(all) != 4 {
		t.Errorf("Expected 4 markers, got %d", len(all))
	}
}

func TestValidateMarker(t *testing.T) {
	validMarkers := []string{
		"__V01_SQLI__",
		"__L01_STACKTRACE__",
		"__V14a_ERROR__",
	}

	invalidMarkers := []string{
		"__X01_TEST__",   // X is not V or L
		"V01_SQLI__",     // Missing prefix __
		"__V01_SQLI",     // Missing suffix __
		"just text",
	}

	for _, m := range validMarkers {
		if !ValidateMarker(m) {
			t.Errorf("Expected %s to be valid", m)
		}
	}

	for _, m := range invalidMarkers {
		if ValidateMarker(m) {
			t.Errorf("Expected %s to be invalid", m)
		}
	}
}

func TestParseMarkerInfo(t *testing.T) {
	info := ParseMarkerInfo("__V01_SQLI__")

	if info.Marker != "__V01_SQLI__" {
		t.Errorf("Expected Marker __V01_SQLI__, got %s", info.Marker)
	}

	if info.Type != "vulnerability" {
		t.Errorf("Expected Type vulnerability, got %s", info.Type)
	}

	if info.ID != "V01" {
		t.Errorf("Expected ID V01, got %s", info.ID)
	}

	if info.Description != "SQLI" {
		t.Errorf("Expected Description SQLI, got %s", info.Description)
	}
}

func TestGroupMarkersByVulnerability(t *testing.T) {
	markers := []string{"__V01_SQLI__", "__V01_UNION__", "__V02_XSS__"}

	groups := GroupMarkersByVulnerability(markers)

	if len(groups["V01"]) != 2 {
		t.Errorf("Expected 2 markers for V01, got %d", len(groups["V01"]))
	}

	if len(groups["V02"]) != 1 {
		t.Errorf("Expected 1 marker for V02, got %d", len(groups["V02"]))
	}
}

func TestExtractRiskScore(t *testing.T) {
	tests := []struct {
		headers  map[string]string
		expected int
		found    bool
	}{
		{map[string]string{"X-WAF-Risk-Score": "50"}, 50, true},
		{map[string]string{"x-waf-risk-score": "75"}, 75, true}, // case-insensitive
		{map[string]string{"X-WAF-Risk-Score": "invalid"}, 0, false},
		{map[string]string{}, 0, false},
	}

	for _, tt := range tests {
		got, found := ExtractRiskScore(tt.headers)
		if got != tt.expected || found != tt.found {
			t.Errorf("ExtractRiskScore(%v) = (%d, %v), want (%d, %v)",
				tt.headers, got, found, tt.expected, tt.found)
		}
	}
}

func TestExtractAction(t *testing.T) {
	tests := []struct {
		headers  map[string]string
		expected string
		found    bool
	}{
		{map[string]string{"X-WAF-Action": "block"}, "block", true},
		{map[string]string{"x-waf-action": "ALLOW"}, "allow", true},
		{map[string]string{}, "", false},
	}

	for _, tt := range tests {
		got, found := ExtractAction(tt.headers)
		if got != tt.expected || found != tt.found {
			t.Errorf("ExtractAction(%v) = (%s, %v), want (%s, %v)",
				tt.headers, got, found, tt.expected, tt.found)
		}
	}
}

func TestExtractRequestID(t *testing.T) {
	headers := map[string]string{"X-WAF-Request-Id": "req-abc-123"}

	got, found := ExtractRequestID(headers)
	if !found || got != "req-abc-123" {
		t.Errorf("ExtractRequestID() = (%s, %v), want (req-abc-123, true)", got, found)
	}
}

func TestExtractRuleID(t *testing.T) {
	headers := map[string]string{"X-WAF-Rule-Id": "SQLI-001"}

	got, found := ExtractRuleID(headers)
	if !found || got != "SQLI-001" {
		t.Errorf("ExtractRuleID() = (%s, %v), want (SQLI-001, true)", got, found)
	}
}

func TestExtractCacheStatus(t *testing.T) {
	tests := []struct {
		headers  map[string]string
		expected string
		found    bool
	}{
		{map[string]string{"X-WAF-Cache": "HIT"}, "HIT", true},
		{map[string]string{"x-waf-cache": "miss"}, "MISS", true},
		{map[string]string{}, "", false},
	}

	for _, tt := range tests {
		got, found := ExtractCacheStatus(tt.headers)
		if got != tt.expected || found != tt.found {
			t.Errorf("ExtractCacheStatus(%v) = (%s, %v), want (%s, %v)",
				tt.headers, got, found, tt.expected, tt.found)
		}
	}
}

func TestIsCacheHit(t *testing.T) {
	tests := []struct {
		headers  map[string]string
		expected bool
	}{
		{map[string]string{"X-WAF-Cache": "HIT"}, true},
		{map[string]string{"X-WAF-Cache": "hit"}, true},
		{map[string]string{"X-WAF-Cache": "MISS"}, false},
		{map[string]string{}, false},
	}

	for _, tt := range tests {
		if got := IsCacheHit(tt.headers); got != tt.expected {
			t.Errorf("IsCacheHit(%v) = %v, want %v", tt.headers, got, tt.expected)
		}
	}
}

func TestIsCacheMiss(t *testing.T) {
	tests := []struct {
		headers  map[string]string
		expected bool
	}{
		{map[string]string{"X-WAF-Cache": "MISS"}, true},
		{map[string]string{"X-WAF-Cache": "miss"}, true},
		{map[string]string{"X-WAF-Cache": "HIT"}, false},
		{map[string]string{}, false},
	}

	for _, tt := range tests {
		if got := IsCacheMiss(tt.headers); got != tt.expected {
			t.Errorf("IsCacheMiss(%v) = %v, want %v", tt.headers, got, tt.expected)
		}
	}
}

func TestGetAllWAFHeaders(t *testing.T) {
	headers := map[string]string{
		"X-WAF-Risk-Score": "50",
		"X-WAF-Action":     "block",
		"Content-Type":     "application/json",
	}

	wafHeaders := GetAllWAFHeaders(headers)

	if _, exists := wafHeaders["X-WAF-Risk-Score"]; !exists {
		t.Error("Expected to find X-WAF-Risk-Score")
	}

	if _, exists := wafHeaders["Content-Type"]; exists {
		t.Error("Content-Type should not be in WAF headers")
	}
}

func TestExtractObservabilitySummary(t *testing.T) {
	headers := map[string]string{
		"X-WAF-Risk-Score": "75",
		"X-WAF-Action":     "challenge",
		"X-WAF-Request-Id": "req-123",
		"X-WAF-Rule-Id":    "SQLI-002",
		"X-WAF-Cache":      "MISS",
	}

	summary := ExtractObservabilitySummary(headers)

	if summary.RiskScore != 75 {
		t.Errorf("Expected RiskScore 75, got %d", summary.RiskScore)
	}

	if summary.Action != "challenge" {
		t.Errorf("Expected Action challenge, got %s", summary.Action)
	}

	if summary.RequestID != "req-123" {
		t.Errorf("Expected RequestID req-123, got %s", summary.RequestID)
	}

	if summary.RuleID != "SQLI-002" {
		t.Errorf("Expected RuleID SQLI-002, got %s", summary.RuleID)
	}

	if summary.CacheStatus != "MISS" {
		t.Errorf("Expected CacheStatus MISS, got %s", summary.CacheStatus)
	}
}

func TestWAFResponseMethods(t *testing.T) {
	resp := &WAFResponse{
		StatusCode: 403,
		Decision:   Block,
		Markers:    []string{},
		RiskScore:  80,
		LatencyMs:  100,
	}

	if !resp.IsBlocked() {
		t.Error("Expected IsBlocked() to be true for 403 response")
	}

	if resp.IsChallenged() {
		t.Error("Expected IsChallenged() to be false")
	}

	if resp.IsAllowed() {
		t.Error("Expected IsAllowed() to be false for blocked response")
	}

	// Create a response with markers and 200 status for ExploitSucceeded test
	respWithMarkers := &WAFResponse{
		StatusCode: 200,
		Decision:   ExploitPassed,
		Markers:    []string{"__V01_SQLI__"},
		RiskScore:  80,
		LatencyMs:  100,
	}

	if !respWithMarkers.HasMarker("__V01_SQLI__") {
		t.Error("Expected HasMarker(__V01_SQLI__) to be true")
	}

	if respWithMarkers.HasMarker("__L01__") {
		t.Error("Expected HasMarker(__L01__) to be false")
	}

	if !respWithMarkers.ExploitSucceeded() {
		t.Error("Expected ExploitSucceeded() to be true when markers present and status 200")
	}

	// Test String()
	str := resp.String()
	if !strings.Contains(str, "403") || !strings.Contains(str, "Block") {
		t.Error("Expected String() to contain status code and decision")
	}
}

func TestWAFResponseExploitSucceeded(t *testing.T) {
	// Exploit succeeded: 200 with markers
	respSuccess := &WAFResponse{
		StatusCode: 200,
		Decision:   ExploitPassed,
		Markers:    []string{"__V01_SQLI__"},
	}
	if !respSuccess.ExploitSucceeded() {
		t.Error("Expected ExploitSucceeded() true for 200 with markers")
	}

	// Exploit failed: 200 no markers (sanitized)
	respSanitized := &WAFResponse{
		StatusCode: 200,
		Decision:   PreventedSanitized,
		Markers:    []string{},
	}
	if respSanitized.ExploitSucceeded() {
		t.Error("Expected ExploitSucceeded() false for sanitized response")
	}

	// Exploit failed: blocked
	respBlocked := &WAFResponse{
		StatusCode: 403,
		Decision:   Block,
		Markers:    []string{},
	}
	if respBlocked.ExploitSucceeded() {
		t.Error("Expected ExploitSucceeded() false for blocked response")
	}
}

func TestIsCanaryMarker(t *testing.T) {
	if !IsCanaryMarker("__CANARY_TEST__") {
		t.Error("Expected __CANARY_TEST__ to be canary marker")
	}

	if IsCanaryMarker("__V01_SQLI__") {
		t.Error("Expected __V01_SQLI__ NOT to be canary marker")
	}
}

func TestExtractQueryTimeMs(t *testing.T) {
	headers := map[string]string{"X-Query-Time-Ms": "150"}

	time, found := ExtractQueryTimeMs(headers)
	if !found || time != 150 {
		t.Errorf("ExtractQueryTimeMs() = (%d, %v), want (150, true)", time, found)
	}
}

func TestExtractInternalHost(t *testing.T) {
	headers := map[string]string{"X-Internal-Host": "10.0.0.5:8080"}

	host, found := ExtractInternalHost(headers)
	if !found || host != "10.0.0.5:8080" {
		t.Errorf("ExtractInternalHost() = (%s, %v), want (10.0.0.5:8080, true)", host, found)
	}
}

func TestExtractDebugQuery(t *testing.T) {
	headers := map[string]string{"X-Debug-Query": "SELECT * FROM users"}

	query, found := ExtractDebugQuery(headers)
	if !found || query != "SELECT * FROM users" {
		t.Errorf("ExtractDebugQuery() = (%s, %v), want (SELECT * FROM users, true)", query, found)
	}
}

func TestGroupMarkersByLeak(t *testing.T) {
	markers := []string{"__L01_STACKTRACE__", "__L01_IP__", "__L02_DEBUG__"}

	groups := GroupMarkersByLeak(markers)

	if len(groups["L01"]) != 2 {
		t.Errorf("Expected 2 markers for L01, got %d", len(groups["L01"]))
	}

	if len(groups["L02"]) != 1 {
		t.Errorf("Expected 1 marker for L02, got %d", len(groups["L02"]))
	}
}

func TestHasRiskScore(t *testing.T) {
	headers := map[string]string{"X-WAF-Risk-Score": "50"}
	if !HasRiskScore(headers) {
		t.Error("Expected HasRiskScore to be true")
	}

	headers = map[string]string{}
	if HasRiskScore(headers) {
		t.Error("Expected HasRiskScore to be false")
	}
}

func TestHasCacheStatus(t *testing.T) {
	headers := map[string]string{"X-WAF-Cache": "HIT"}
	if !HasCacheStatus(headers) {
		t.Error("Expected HasCacheStatus to be true")
	}

	headers = map[string]string{}
	if HasCacheStatus(headers) {
		t.Error("Expected HasCacheStatus to be false")
	}
}

func TestGetHeaderByName(t *testing.T) {
	headers := map[string]string{
		"Content-Type": "application/json",
		"X-Custom":     "value",
	}

	val, found := GetHeaderByName(headers, "content-type")
	if !found || val != "application/json" {
		t.Error("Expected to find Content-Type header")
	}

	_, found = GetHeaderByName(headers, "X-Not-Exists")
	if found {
		t.Error("Should not find non-existent header")
	}
}

func TestHasHeader(t *testing.T) {
	headers := map[string]string{"X-WAF-Action": "block"}

	if !HasHeader(headers, "x-waf-action") {
		t.Error("Expected HasHeader to be true for x-waf-action")
	}

	if HasHeader(headers, "X-Not-Exists") {
		t.Error("Expected HasHeader to be false for non-existent header")
	}
}

func TestHeaderNames(t *testing.T) {
	headers := map[string]string{
		"X-Header-1": "v1",
		"X-Header-2": "v2",
	}

	names := HeaderNames(headers)
	if len(names) != 2 {
		t.Errorf("Expected 2 header names, got %d", len(names))
	}
}

func TestWAFClientClose(t *testing.T) {
	client := NewWAFClient("127.0.0.1", 8080, 30)

	// Close should not panic even with empty pool
	if err := client.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Client pool should be reset
	if len(client.clientPool) != 0 {
		t.Errorf("Expected empty pool after Close(), got %d clients", len(client.clientPool))
	}
}

func TestWAFClientGetClientStats(t *testing.T) {
	client := NewWAFClient("127.0.0.1", 8080, 30)

	// Empty pool should return empty stats
	stats := client.GetClientStats()
	if len(stats) != 0 {
		t.Errorf("Expected empty stats, got %d entries", len(stats))
	}
}

// Integration-style test: ParseResponse helper
func TestParseResponseHelper(t *testing.T) {
	// Create a fasthttp response
	resp := fasthttp.AcquireResponse()
	resp.SetStatusCode(200)
	resp.SetBody([]byte("response __V01_SQLI__"))
	resp.Header.Set("X-WAF-Risk-Score", "50")
	resp.Header.Set("X-WAF-Action", "block")

	// We can't directly test parseResponse, but we can verify the detection logic
	markers := DetectMarkers(resp.Body(), map[string]string{
		"X-WAF-Risk-Score": "50",
		"X-WAF-Action":     "block",
	})

	if len(markers) != 1 || markers[0] != "__V01_SQLI__" {
		t.Errorf("Expected __V01_SQLI__ marker, got %v", markers)
	}

	fasthttp.ReleaseResponse(resp)
}
