package phases

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/waf-hackathon/benchmark/internal/target"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

// ExploitTest represents a single exploit test case
type ExploitTest struct {
	ID           string                 // V01, V02, etc.
	Category     string                 // SQLi, XSS, PathTraversal, etc.
	Method       string                 // GET, POST, PUT, DELETE
	Path         string                 // Request path
	AuthRequired bool                   // Does this test need authentication?
	Payload      map[string]interface{} // Request body/query params
	Headers      map[string]string      // Additional headers
	ProofMarker  string                 // Expected marker (e.g., __V01_SQLI__)
	Description  string                 // Human-readable description
}

// ExploitResult contains the result of running an exploit test
type ExploitResult struct {
	TestID          string
	Category        string
	Decision        waf.Decision
	Passed          bool           // true if exploit was blocked/prevented
	Bypassed        bool           // true if exploit succeeded (marker found)
	Markers         []string       // Markers found in response
	RiskScore       int            // Risk score from WAF
	ResponseTimeMs  int64          // Response latency
	Error           string         // Error message if any
	NegativeControl bool           // Was this the negative control test?
	Description     string         // Human-readable description
}

// LeakTest represents an outbound leak detection test
type LeakTest struct {
	ID              string            // L01, L02, etc.
	TriggerEndpoint string            // Where to trigger the leak
	TriggerMethod   string            // HTTP method
	TriggerPayload  interface{}       // Payload to trigger leak
	ProofMarker     string            // Expected marker in response
	HeaderCheck     string            // Header to check (e.g., X-Internal-Host)
	Description     string            // Human-readable description
}

// LeakResult contains the result of a leak test
type LeakResult struct {
	TestID         string
	Passed         bool      // true if leak was prevented/filtered
	LeakDetected   bool      // true if leak marker found
	Markers        []string
	HeaderValue    string    // Value of checked header if applicable
	ResponseTimeMs int64
	Error          string
}

// PhaseAResult contains all results from Phase A testing
type PhaseAResult struct {
	ExploitTests       []ExploitResult
	LeakTests          []LeakResult
	ExploitPreventionRate float64
	OutboundFilterRate    float64
	TotalExploits      int
	BlockedExploits    int
	TotalLeaks         int
	FilteredLeaks      int
	DurationMs         int64
}

// IsPassed returns true if the exploit was prevented (WAF worked)
func (r *ExploitResult) IsPassed() bool {
	// Passed if: blocked, challenged, rate limited, or no markers when markers expected
	if r.NegativeControl {
		// Negative control should NOT have markers
		return !r.Bypassed && len(r.Markers) == 0
	}
	return r.Decision.IsPrevented()
}

// String returns human-readable result
func (r *ExploitResult) String() string {
	status := "PASS"
	if !r.IsPassed() {
		status = "FAIL"
	}
	return fmt.Sprintf("[%s] %s (%s): Decision: %s, Markers: %v",
		status, r.TestID, r.Category, r.Decision.String(), r.Markers)
}

// GetExploitTestCatalog returns all exploit tests V01-V24
func GetExploitTestCatalog() []ExploitTest {
	return []ExploitTest{
		// V01: SQL Injection Classic
		{
			ID:           "V01",
			Category:     "SQLi",
			Method:       "POST",
			Path:         "/login",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"username": "' OR 1=1--",
				"password": "password",
			},
			ProofMarker: "__V01_SQLI__",
			Description: "Classic SQL Injection in login form",
		},
		// V02: SQL Injection UNION-based
		{
			ID:           "V02",
			Category:     "SQLi",
			Method:       "GET",
			Path:         "/api/transactions",
			AuthRequired: true,
			Payload: map[string]interface{}{
				"page": "1 UNION SELECT username, password FROM users--",
			},
			ProofMarker: "__V02_SQLI__",
			Description: "UNION-based SQL Injection in query parameter",
		},
		// V03: Blind SQL Injection (Timing-based)
		{
			ID:           "V03",
			Category:     "SQLi",
			Method:       "POST",
			Path:         "/login",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"username": "admin' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
				"password": "password",
			},
			ProofMarker: "__V03_BLIND__",
			Description: "Blind SQL Injection with SLEEP()",
		},
		// V04: Reflected XSS
		{
			ID:           "V04",
			Category:     "XSS",
			Method:       "GET",
			Path:         "/game/1",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"name": "<script>alert('XSS')</script>",
			},
			ProofMarker: "__V04_XSS__",
			Description: "Reflected Cross-Site Scripting",
		},
		// V05: Stored XSS
		{
			ID:           "V05",
			Category:     "XSS",
			Method:       "PUT",
			Path:         "/api/profile",
			AuthRequired: true,
			Payload: map[string]interface{}{
				"bio": "<img src=x onerror=alert('stored')>",
			},
			ProofMarker: "__V05_STORED__",
			Description: "Stored Cross-Site Scripting in profile",
		},
		// V06: Path Traversal
		{
			ID:           "V06",
			Category:     "PathTraversal",
			Method:       "GET",
			Path:         "/static/../../../../etc/passwd",
			AuthRequired: false,
			Payload:      map[string]interface{}{},
			ProofMarker:  "__V06_TRAVERSAL__",
			Description:  "Path Traversal attack",
		},
		// V07: Encoded Path Traversal
		{
			ID:           "V07",
			Category:     "PathTraversal",
			Method:       "GET",
			Path:         "/static/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			AuthRequired: false,
			Payload:      map[string]interface{}{},
			ProofMarker:  "__V07_ENCODED__",
			Description:  "URL-encoded Path Traversal",
		},
		// V08: SSRF - Metadata Endpoint
		{
			ID:           "V08",
			Category:     "SSRF",
			Method:       "PUT",
			Path:         "/api/profile",
			AuthRequired: true,
			Payload: map[string]interface{}{
				"avatar_url": "http://169.254.169.254/latest/meta-data/",
			},
			ProofMarker: "__V08_SSRF__",
			Description: "Server-Side Request Forgery to metadata endpoint",
		},
		// V09: SSRF - Internal Network
		{
			ID:           "V09",
			Category:     "SSRF",
			Method:       "POST",
			Path:         "/game/1/play",
			AuthRequired: true,
			Payload: map[string]interface{}{
				"callback_url": "http://127.0.0.1:9000/__control/health",
			},
			ProofMarker: "__V09_SSRF__",
			Description: "SSRF to internal control endpoint",
		},
		// V10: CRLF Injection
		{
			ID:           "V10",
			Category:     "CRLF",
			Method:       "GET",
			Path:         "/api/search",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"q": "test\r\nSet-Cookie: malicious=value",
			},
			Headers: map[string]string{
				"X-Inject": "test\r\nX-Custom: injected",
			},
			ProofMarker: "__V10_CRLF__",
			Description: "CRLF Injection in headers",
		},
		// V11: Host Header Injection
		{
			ID:           "V11",
			Category:     "HostHeader",
			Method:       "GET",
			Path:         "/",
			AuthRequired: false,
			Payload:      map[string]interface{}{},
			Headers: map[string]string{
				"Host": "evil.com",
			},
			ProofMarker: "__V11_HOST__",
			Description: "Host Header Injection",
		},
		// V14: Malformed JSON
		{
			ID:           "V14",
			Category:     "Malformed",
			Method:       "POST",
			Path:         "/api/data",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"_raw": "{\"num\": 1e999999}",
			},
			ProofMarker: "__V14_MALFORMED__",
			Description: "Malformed JSON with extreme number",
		},
		// V15: Oversized Payload
		{
			ID:           "V15",
			Category:     "Oversized",
			Method:       "POST",
			Path:         "/api/data",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"_raw": fmt.Sprintf("{\"data\": \"%s\"}", strings.Repeat("A", 2*1024*1024)), // 2MB
			},
			ProofMarker: "__V15_OVERSIZED__",
			Description: "Oversized payload > 1MB",
		},
		// V16: Content-Type Bypass
		{
			ID:           "V16",
			Category:     "Bypass",
			Method:       "POST",
			Path:         "/api/data",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"_raw": "' OR 1=1--",
			},
			Headers: map[string]string{
				"Content-Type": "text/plain",
			},
			ProofMarker: "__V16_BYPASS__",
			Description: "Content-Type Bypass with SQLi in text/plain",
		},
		// V19: Deeply Nested JSON
		{
			ID:           "V19",
			Category:     "Nested",
			Method:       "POST",
			Path:         "/api/data",
			AuthRequired: false,
			Payload:      generateNestedPayload(120), // 120 levels deep
			ProofMarker:  "__V19_NESTED__",
			Description:  "Deeply nested JSON (>100 levels)",
		},
		// V20: Command Injection
		{
			ID:           "V20",
			Category:     "CommandInjection",
			Method:       "GET",
			Path:         "/api/ping",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"host": "127.0.0.1; cat /etc/passwd",
			},
			ProofMarker: "__V20_CMDI__",
			Description: "Command Injection in ping parameter",
		},
		// V21: LDAP Injection
		{
			ID:           "V21",
			Category:     "LDAPInjection",
			Method:       "GET",
			Path:         "/api/search",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"user": "*)(uid=*))(&(uid=*",
			},
			ProofMarker: "__V21_LDAP__",
			Description: "LDAP Injection",
		},
		// V22: XML External Entity (XXE)
		{
			ID:           "V22",
			Category:     "XXE",
			Method:       "POST",
			Path:         "/api/xml",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"_raw": `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
			},
			Headers: map[string]string{
				"Content-Type": "application/xml",
			},
			ProofMarker: "__V22_XXE__",
			Description: "XML External Entity attack",
		},
		// V23: Insecure Deserialization
		{
			ID:           "V23",
			Category:     "Deserialization",
			Method:       "POST",
			Path:         "/api/process",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"_raw": `rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvcnNIAAF0aHJlc2hvbGR4cD9AAAAAAAABdw`, // base64 encoded serialized object
			},
			Headers: map[string]string{
				"Content-Type": "application/octet-stream",
			},
			ProofMarker: "__V23_DESER__",
			Description: "Insecure Deserialization",
		},
		// V24: HTTP Request Smuggling
		{
			ID:           "V24",
			Category:     "RequestSmuggling",
			Method:       "POST",
			Path:         "/",
			AuthRequired: false,
			Payload: map[string]interface{}{
				"_raw": "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n",
			},
			Headers: map[string]string{
				"Content-Length": "5",
				"Transfer-Encoding": "chunked",
			},
			ProofMarker: "__V24_SMUGGLE__",
			Description: "HTTP Request Smuggling",
		},
	}
}

// GetLeakTestCatalog returns all leak detection tests L01-L05
func GetLeakTestCatalog() []LeakTest {
	return []LeakTest{
		// L01: Stack Trace Leak
		{
			ID:              "L01",
			TriggerEndpoint: "/api/error",
			TriggerMethod:   "GET",
			TriggerPayload:  map[string]interface{}{"trigger": "error"},
			ProofMarker:     "__L01_STACKTRACE__",
			Description:     "Stack trace leaked in error response",
		},
		// L02: Internal IP Leak
		{
			ID:              "L02",
			TriggerEndpoint: "/api/profile",
			TriggerMethod:   "GET",
			TriggerPayload:  nil,
			ProofMarker:     "__L02_IPLEAK__",
			HeaderCheck:     "X-Internal-Host",
			Description:     "Internal IP address leaked in header",
		},
		// L03: Debug SQL Query Leak
		{
			ID:              "L03",
			TriggerEndpoint: "/api/data",
			TriggerMethod:   "GET",
			TriggerPayload:  map[string]interface{}{"debug": "true"},
			ProofMarker:     "__L03_DEBUGSQL__",
			HeaderCheck:     "X-Debug-Query",
			Description:     "SQL query leaked in debug header",
		},
		// L04: PII Leak
		{
			ID:              "L04",
			TriggerEndpoint: "/api/profile",
			TriggerMethod:   "GET",
			TriggerPayload:  nil,
			ProofMarker:     "__L04_PII__",
			Description:     "PII data leaked in response body",
		},
		// L05: Verbose 404 Error
		{
			ID:              "L05",
			TriggerEndpoint: "/nonexistent-path-xyz",
			TriggerMethod:   "GET",
			TriggerPayload:  nil,
			ProofMarker:     "__L05_VERBOSE_404__",
			Description:     "Verbose 404 error message",
		},
	}
}

// generateNestedPayload creates a deeply nested JSON structure
func generateNestedPayload(depth int) map[string]interface{} {
	if depth <= 1 {
		return map[string]interface{}{"value": "leaf"}
	}
	return map[string]interface{}{
		"nested": generateNestedPayload(depth - 1),
	}
}

// RunExploitTest executes a single exploit test
func RunExploitTest(test ExploitTest, wafClient *waf.WAFClient, sourceIP string, auth *target.Auth, session *target.Session) (*ExploitResult, error) {
	start := time.Now()

	// Build request
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethod(test.Method)

	// Build URL with query params for GET requests
	url := test.Path
	if test.Method == "GET" && len(test.Payload) > 0 {
		url = buildURLWithParams(url, test.Payload)
	}
	req.SetRequestURI(url)

	// Set headers
	for k, v := range test.Headers {
		req.Header.Set(k, v)
	}

	// Set body for POST/PUT requests
	if test.Method == "POST" || test.Method == "PUT" {
		if raw, ok := test.Payload["_raw"]; ok {
			// Raw payload provided
			req.SetBody([]byte(raw.(string)))
			if ct, hasCT := test.Headers["Content-Type"]; hasCT {
				req.Header.SetContentType(ct)
			}
		} else if len(test.Payload) > 0 {
			// JSON payload
			body, _ := json.Marshal(test.Payload)
			req.SetBody(body)
			req.Header.SetContentType("application/json")
		}
	}

	// Add auth cookie if required
	if test.AuthRequired && session != nil {
		for _, cookie := range session.Cookies {
			req.Header.SetCookie(cookie.Name, cookie.Value)
		}
	}

	// Send request through WAF
	wafResp, err := wafClient.SendRequest(req, sourceIP)
	if err != nil {
		return &ExploitResult{
			TestID:         test.ID,
			Category:       test.Category,
			Decision:       waf.Unknown,
			Passed:         false,
			ResponseTimeMs: time.Since(start).Milliseconds(),
			Error:          err.Error(),
		}, nil
	}

	latency := time.Since(start).Milliseconds()

	// Check for proof markers
	markers := wafResp.Markers
	hasMarker := wafResp.HasMarker(test.ProofMarker)

	// Determine if exploit was prevented or bypassed
	bypassed := wafResp.ExploitSucceeded() || hasMarker
	passed := !bypassed

	return &ExploitResult{
		TestID:         test.ID,
		Category:       test.Category,
		Decision:       wafResp.Decision,
		Passed:         passed,
		Bypassed:       bypassed,
		Markers:        markers,
		RiskScore:      wafResp.RiskScore,
		ResponseTimeMs: latency,
	}, nil
}

// RunLeakTest executes a single leak detection test
func RunLeakTest(test LeakTest, wafClient *waf.WAFClient, sourceIP string) (*LeakResult, error) {
	start := time.Now()

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethod(test.TriggerMethod)
	req.SetRequestURI(test.TriggerEndpoint)

	// Set body if payload exists
	if test.TriggerPayload != nil {
		if raw, ok := test.TriggerPayload.(map[string]interface{})["_raw"]; ok {
			req.SetBody([]byte(raw.(string)))
		} else {
			body, _ := json.Marshal(test.TriggerPayload)
			req.SetBody(body)
			req.Header.SetContentType("application/json")
		}
	}

	wafResp, err := wafClient.SendRequest(req, sourceIP)
	if err != nil {
		return &LeakResult{
			TestID:         test.ID,
			Passed:         false,
			ResponseTimeMs: time.Since(start).Milliseconds(),
			Error:          err.Error(),
		}, nil
	}

	latency := time.Since(start).Milliseconds()

	// Check for leak markers
	markers := wafResp.Markers
	leakDetected := wafResp.HasMarker(test.ProofMarker)

	// Check header if specified
	headerValue := ""
	if test.HeaderCheck != "" {
		if val, ok := wafResp.Headers[test.HeaderCheck]; ok {
			headerValue = val
			// If header exists, consider it a leak
			if headerValue != "" {
				leakDetected = true
			}
		}
	}

	// Leak is filtered if no marker found and no sensitive header
	passed := !leakDetected

	return &LeakResult{
		TestID:         test.ID,
		Passed:         passed,
		LeakDetected:   leakDetected,
		Markers:        markers,
		HeaderValue:    headerValue,
		ResponseTimeMs: latency,
	}, nil
}

// RunNegativeControl runs a legitimate request to ensure no false positives
func RunNegativeControl(wafClient *waf.WAFClient, sourceIP string) (*ExploitResult, error) {
	start := time.Now()

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethod("GET")
	req.SetRequestURI("/")

	wafResp, err := wafClient.SendRequest(req, sourceIP)
	if err != nil {
		return &ExploitResult{
			TestID:          "NEGATIVE_CONTROL",
			Category:        "Control",
			Decision:        waf.Unknown,
			Passed:          false,
			NegativeControl: true,
			ResponseTimeMs:  time.Since(start).Milliseconds(),
			Error:           err.Error(),
		}, nil
	}

	latency := time.Since(start).Milliseconds()

	// Negative control passes if no markers found and request allowed
	bypassed := len(wafResp.Markers) > 0
	passed := !bypassed && (wafResp.Decision == waf.Allow || wafResp.Decision == waf.PreventedSanitized)

	return &ExploitResult{
		TestID:          "NEGATIVE_CONTROL",
		Category:        "Control",
		Decision:        wafResp.Decision,
		Passed:          passed,
		Bypassed:        bypassed,
		Markers:         wafResp.Markers,
		RiskScore:       wafResp.RiskScore,
		ResponseTimeMs:  latency,
		NegativeControl: true,
	}, nil
}

// RunPhaseA executes all Phase A tests
func RunPhaseA(capabilities *target.AppCapabilities, wafClient *waf.WAFClient, control *target.Control, auth *target.Auth, sourceIP string) (*PhaseAResult, error) {
	start := time.Now()

	result := &PhaseAResult{
		ExploitTests: make([]ExploitResult, 0),
		LeakTests:    make([]LeakResult, 0),
	}

	// Run negative control first
	control.Reset()
	time.Sleep(100 * time.Millisecond)

	negControl, err := RunNegativeControl(wafClient, sourceIP)
	if err != nil {
		return nil, fmt.Errorf("negative control failed: %w", err)
	}
	result.ExploitTests = append(result.ExploitTests, *negControl)

	// Run exploit tests
	exploitCatalog := GetExploitTestCatalog()
	for _, test := range exploitCatalog {
		// Check if vulnerability is active
		if !capabilities.IsVulnActive(test.ID) {
			continue
		}

		// Reset target before each test
		control.Reset()
		time.Sleep(100 * time.Millisecond)

		// Get authenticated session if needed
		var session *target.Session
		if test.AuthRequired {
			session, err = auth.LoginWithCredentials(target.UserAlice)
			if err != nil {
				result.ExploitTests = append(result.ExploitTests, ExploitResult{
					TestID: test.ID,
					Error:  fmt.Sprintf("auth failed: %v", err),
				})
				continue
			}
		}

		testResult, err := RunExploitTest(test, wafClient, sourceIP, auth, session)
		if err != nil {
			testResult = &ExploitResult{
				TestID: test.ID,
				Error:  err.Error(),
			}
		}
		result.ExploitTests = append(result.ExploitTests, *testResult)

		result.TotalExploits++
		if testResult.IsPassed() {
			result.BlockedExploits++
		}
	}

	// Run leak tests
	leakCatalog := GetLeakTestCatalog()
	for _, test := range leakCatalog {
		if !capabilities.IsLeakActive(test.ID) {
			continue
		}

		control.Reset()
		time.Sleep(100 * time.Millisecond)

		leakResult, err := RunLeakTest(test, wafClient, sourceIP)
		if err != nil {
			leakResult = &LeakResult{
				TestID: test.ID,
				Error:  err.Error(),
			}
		}
		result.LeakTests = append(result.LeakTests, *leakResult)

		result.TotalLeaks++
		if leakResult.Passed {
			result.FilteredLeaks++
		}
	}

	// Calculate rates
	if result.TotalExploits > 0 {
		result.ExploitPreventionRate = float64(result.BlockedExploits) / float64(result.TotalExploits) * 100
	}
	if result.TotalLeaks > 0 {
		result.OutboundFilterRate = float64(result.FilteredLeaks) / float64(result.TotalLeaks) * 100
	}

	result.DurationMs = time.Since(start).Milliseconds()

	return result, nil
}

// buildURLWithParams builds URL with query parameters
func buildURLWithParams(path string, params map[string]interface{}) string {
	if len(params) == 0 {
		return path
	}

	var sb strings.Builder
	sb.WriteString(path)
	sb.WriteString("?")

	first := true
	for k, v := range params {
		if !first {
			sb.WriteString("&")
		}
		first = false
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(fmt.Sprintf("%v", v))
	}

	return sb.String()
}

// Summary returns a human-readable summary of Phase A results
func (r *PhaseAResult) Summary() string {
	return fmt.Sprintf(
		"Phase A - Exploit Prevention\n"+
		"  Exploit Tests: %d/%d passed (%.1f%%)\n"+
		"  Leak Tests: %d/%d passed (%.1f%%)\n"+
		"  Duration: %dms",
		r.BlockedExploits, r.TotalExploits, r.ExploitPreventionRate,
		r.FilteredLeaks, r.TotalLeaks, r.OutboundFilterRate,
		r.DurationMs,
	)
}
