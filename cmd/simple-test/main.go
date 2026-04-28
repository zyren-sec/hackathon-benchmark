package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// SimplePhaseATest runs a simplified Phase A test against a remote site
// without requiring WAF control endpoints
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: simple-test <target-url>")
		fmt.Println("Example: simple-test http://sec-team.waf-exams.info")
		os.Exit(1)
	}

	targetURL := os.Args[1]
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}

	fmt.Printf("Running simple Phase A test against: %s\n\n", targetURL)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	results := &TestResults{
		Target:    targetURL,
		Timestamp: time.Now().Format(time.RFC3339),
		Tests:     []TestResult{},
	}

	// Test 1: Basic connectivity
	fmt.Println("[TEST 1] Basic connectivity...")
	testBasicConnectivity(client, targetURL, results)

	// Test 2: SQL Injection attempt
	fmt.Println("[TEST 2] SQL Injection test...")
	testSQLInjection(client, targetURL, results)

	// Test 3: XSS attempt
	fmt.Println("[TEST 3] XSS test...")
	testXSS(client, targetURL, results)

	// Test 4: Path Traversal
	fmt.Println("[TEST 4] Path Traversal test...")
	testPathTraversal(client, targetURL, results)

	// Generate report
	generateHTMLReport(results)
	generateJSONReport(results)

	fmt.Printf("\n✓ Reports generated in ./reports/\n")
	fmt.Printf("  - benchmark_report.html\n")
	fmt.Printf("  - benchmark_report.json\n")
}

type TestResults struct {
	Target    string       `json:"target"`
	Timestamp string       `json:"timestamp"`
	Tests     []TestResult `json:"tests"`
	Passed    int          `json:"passed"`
	Failed    int          `json:"failed"`
}

type TestResult struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Passed      bool   `json:"passed"`
	StatusCode  int    `json:"status_code"`
	ResponseSize int   `json:"response_size"`
	Error       string `json:"error,omitempty"`
}

func testBasicConnectivity(client *http.Client, targetURL string, results *TestResults) {
	resp, err := client.Get(targetURL + "/")
	if err != nil {
		results.Tests = append(results.Tests, TestResult{
			ID:       "CONN",
			Name:     "Basic Connectivity",
			Category: "Connectivity",
			Passed:   false,
			Error:    err.Error(),
		})
		fmt.Printf("  FAIL: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	passed := resp.StatusCode == 200

	results.Tests = append(results.Tests, TestResult{
		ID:           "CONN",
		Name:         "Basic Connectivity",
		Category:     "Connectivity",
		Passed:       passed,
		StatusCode:   resp.StatusCode,
		ResponseSize: len(body),
	})

	if passed {
		results.Passed++
		fmt.Printf("  PASS: Status %d, Response size: %d bytes\n", resp.StatusCode, len(body))
	} else {
		results.Failed++
		fmt.Printf("  FAIL: Status %d\n", resp.StatusCode)
	}
}

func testSQLInjection(client *http.Client, targetURL string, results *TestResults) {
	// Try SQL injection in query parameter
	testURL := targetURL + "/?id=' OR '1'='1"
	resp, err := client.Get(testURL)
	if err != nil {
		results.Tests = append(results.Tests, TestResult{
			ID:       "SQLI",
			Name:     "SQL Injection",
			Category: "Exploit",
			Passed:   false,
			Error:    err.Error(),
		})
		results.Failed++
		fmt.Printf("  FAIL: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Check if SQL error messages leaked (would be a FAIL for security)
	sqlErrors := []string{"sql", "mysql", "sqlite", "postgres", "ora-", "syntax error"}
	foundError := false
	bodyLower := strings.ToLower(bodyStr)
	for _, errPattern := range sqlErrors {
		if strings.Contains(bodyLower, errPattern) {
			foundError = true
			break
		}
	}

	// If we get 200 with SQL errors showing, that's bad
	// If we get blocked (403/429/503), that's good (WAF working)
	passed := resp.StatusCode == 200 && !foundError

	results.Tests = append(results.Tests, TestResult{
		ID:           "SQLI",
		Name:         "SQL Injection",
		Category:     "Exploit",
		Passed:       passed,
		StatusCode:   resp.StatusCode,
		ResponseSize: len(body),
	})

	if passed {
		results.Passed++
		fmt.Printf("  PASS: Status %d (no SQL errors)\n", resp.StatusCode)
	} else {
		results.Failed++
		if foundError {
			fmt.Printf("  FAIL: SQL error messages in response!\n")
		} else {
			fmt.Printf("  BLOCKED: Status %d (WAF may be active)\n", resp.StatusCode)
		}
	}
}

func testXSS(client *http.Client, targetURL string, results *TestResults) {
	// Try XSS in query parameter
	testURL := targetURL + "/?q=<script>alert('xss')</script>"
	resp, err := client.Get(testURL)
	if err != nil {
		results.Tests = append(results.Tests, TestResult{
			ID:       "XSS",
			Name:     "Cross-Site Scripting",
			Category: "Exploit",
			Passed:   false,
			Error:    err.Error(),
		})
		results.Failed++
		fmt.Printf("  FAIL: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Check if script tag appears unescaped in response
	passed := !strings.Contains(bodyStr, "<script>alert('xss')</script>")

	results.Tests = append(results.Tests, TestResult{
		ID:           "XSS",
		Name:         "Cross-Site Scripting",
		Category:     "Exploit",
		Passed:       passed,
		StatusCode:   resp.StatusCode,
		ResponseSize: len(body),
	})

	if passed {
		results.Passed++
		fmt.Printf("  PASS: XSS payload not reflected\n")
	} else {
		results.Failed++
		fmt.Printf("  FAIL: XSS payload reflected in response!\n")
	}
}

func testPathTraversal(client *http.Client, targetURL string, results *TestResults) {
	// Try path traversal
	testURL := targetURL + "/static/../../../etc/passwd"
	resp, err := client.Get(testURL)
	if err != nil {
		results.Tests = append(results.Tests, TestResult{
			ID:       "PATH",
			Name:     "Path Traversal",
			Category: "Exploit",
			Passed:   false,
			Error:    err.Error(),
		})
		results.Failed++
		fmt.Printf("  FAIL: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// Check for passwd content
	passed := !strings.Contains(bodyStr, "root:")

	results.Tests = append(results.Tests, TestResult{
		ID:           "PATH",
		Name:         "Path Traversal",
		Category:     "Exploit",
		Passed:       passed,
		StatusCode:   resp.StatusCode,
		ResponseSize: len(body),
	})

	if passed {
		results.Passed++
		fmt.Printf("  PASS: No /etc/passwd content leaked\n")
	} else {
		results.Failed++
		fmt.Printf("  FAIL: /etc/passwd content in response!\n")
	}
}

func generateJSONReport(results *TestResults) {
	os.MkdirAll("./reports", 0755)
	data, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile("./reports/benchmark_report.json", data, 0644)
}

func generateHTMLReport(results *TestResults) {
	os.MkdirAll("./reports", 0755)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>WAF Benchmark Report - %s</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
		.container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
		h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
		.summary { display: flex; gap: 20px; margin: 20px 0; }
		.card { background: #f8f9fa; padding: 20px; border-radius: 8px; flex: 1; text-align: center; }
		.card h3 { margin: 0 0 10px 0; color: #666; }
		.card .value { font-size: 2em; font-weight: bold; }
		.pass { color: #28a745; }
		.fail { color: #dc3545; }
		table { width: %%100; border-collapse: collapse; margin-top: 20px; }
		th { background: #007bff; color: white; padding: 12px; text-align: left; }
		td { padding: 12px; border-bottom: 1px solid #dee2e6; }
		tr:hover { background: #f8f9fa; }
		.status-pass { color: #28a745; font-weight: bold; }
		.status-fail { color: #dc3545; font-weight: bold; }
		.timestamp { color: #666; font-size: 0.9em; }
	</style>
</head>
<body>
	<div class="container">
		<h1>WAF Benchmark Report</h1>
		<p class="timestamp">Target: %s<br>Generated: %s</p>

		<div class="summary">
			<div class="card">
				<h3>Total Tests</h3>
				<div class="value">%d</div>
			</div>
			<div class="card">
				<h3>Passed</h3>
				<div class="value pass">%d</div>
			</div>
			<div class="card">
				<h3>Failed</h3>
				<div class="value fail">%d</div>
			</div>
			<div class="card">
				<h3>Pass Rate</h3>
				<div class="value">%.1f%%</div>
			</div>
		</div>

		<h2>Test Results</h2>
		<table>
			<tr>
				<th>ID</th>
				<th>Name</th>
				<th>Category</th>
				<th>Status</th>
				<th>HTTP Status</th>
				<th>Response Size</th>
			</tr>
`, results.Target, results.Target, results.Timestamp, len(results.Tests), results.Passed, results.Failed,
		float64(results.Passed)/float64(len(results.Tests))*100)

	for _, test := range results.Tests {
		statusClass := "status-fail"
		statusText := "FAIL"
		if test.Passed {
			statusClass = "status-pass"
			statusText = "PASS"
		}
		html += fmt.Sprintf(`			<tr>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td class="%s">%s</td>
				<td>%d</td>
				<td>%d bytes</td>
			</tr>
`, test.ID, test.Name, test.Category, statusClass, statusText, test.StatusCode, test.ResponseSize)
	}

	html += `
		</table>

		<h2>Notes</h2>
		<ul>
			<li>This is a simplified Phase A test against a remote target without WAF control endpoints.</li>
			<li>Tests check for basic exploit prevention patterns.</li>
			<li>A "PASS" means the vulnerability was not detected or was properly blocked.</li>
			<li>A "FAIL" means the vulnerability was exploitable or information was leaked.</li>
		</ul>
	</div>
</body>
</html>`

	os.WriteFile("./reports/benchmark_report.html", []byte(html), 0644)
}
