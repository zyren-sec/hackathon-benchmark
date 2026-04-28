package phases

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/waf-hackathon/benchmark/internal/target"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

// Phase D - Resilience Tests
// Tests WAF resilience against DDoS attacks and backend failures

// ResilienceResult represents the result of a single resilience test
type ResilienceResult struct {
	TestID      string
	Name        string
	Category    string // DDoS, SlowAttack, BackendFailure, FailMode
	Passed      bool
	Description string
	Details     map[string]interface{}
}

// PhaseDResult contains all results from Phase D testing
type PhaseDResult struct {
	DDoSTests           []ResilienceResult // D01-D04
	SlowAttackTests     []ResilienceResult // D02-D03
	BackendFailureTests []ResilienceResult // D05-D07
	FailModeTests       []ResilienceResult // D08-D09
	DDoSScore           float64            // 4 points max
	BackendScore        float64            // 3 points max
	FailModeScore       float64            // 2 points max
	TotalScore          float64
	DurationMs          int64
}

// DDoSTester handles DDoS resilience tests
type DDoSTester struct {
	wafClient    *waf.WAFClient
	targetClient *target.Client
}

// NewDDoSTester creates a new DDoS tester
func NewDDoSTester(wafClient *waf.WAFClient, targetClient *target.Client) *DDoSTester {
	return &DDoSTester{
		wafClient:    wafClient,
		targetClient: targetClient,
	}
}

// RunD01HTTPFlood runs D01 HTTP flood test
// Send 50,000 req/s to GET / for 60 seconds
// After flood, wait 10 seconds, send 10 legitimate requests
// Pass if all 10 succeed
func (d *DDoSTester) RunD01HTTPFlood() ResilienceResult {
	result := ResilienceResult{
		TestID:      "D01",
		Name:        "HTTP Flood",
		Category:    "DDoS",
		Description: "50k req/s flood for 60s, then verify legitimate requests still succeed",
		Details:     make(map[string]interface{}),
		Passed:      false,
	}

	floodDuration := 60 * time.Second

	// Start flood
	ctx, cancel := context.WithTimeout(context.Background(), floodDuration)
	defer cancel()

	var requestCount int64

	g, ctx := errgroup.WithContext(ctx)

	// Launch workers
	for i := 0; i < 100; i++ {
		g.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return nil
				default:
					// Send request through WAF
					d.wafClient.SendRequestWithIP("GET", "/", nil, nil, "127.0.0.200")
					atomic.AddInt64(&requestCount, 1)
				}
			}
		})
	}

	// Wait for flood to complete
	start := time.Now()
	g.Wait()
	actualDuration := time.Since(start)

	result.Details["flood_duration_ms"] = actualDuration.Milliseconds()
	result.Details["total_requests"] = requestCount

	// Wait 10 seconds after flood
	time.Sleep(10 * time.Second)

	// Send 10 legitimate requests
	legitimatePassed := 0
	for i := 0; i < 10; i++ {
		resp, err := d.wafClient.SendRequestWithIP("GET", "/", nil, nil, "127.0.0.201")
		if err == nil && (resp.StatusCode == 200 || resp.StatusCode == 429) {
			legitimatePassed++
		}
		time.Sleep(100 * time.Millisecond)
	}

	result.Details["legitimate_passed"] = legitimatePassed
	result.Details["legitimate_total"] = 10

	// Pass if all 10 legitimate requests succeeded
	if legitimatePassed == 10 {
		result.Passed = true
	}

	return result
}

func dialWAF(baseURL string) (net.Conn, string, string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid WAF base URL %q: %w", baseURL, err)
	}

	host := u.Hostname()
	if host == "" {
		return nil, "", "", fmt.Errorf("invalid WAF host in URL %q", baseURL)
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	addr := net.JoinHostPort(host, port)
	if u.Scheme == "https" {
		conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: host})
		if err != nil {
			return nil, "", "", err
		}
		return conn, host, addr, nil
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, "", "", err
	}
	return conn, host, addr, nil
}

// RunD02Slowloris runs D02 Slowloris test
// Open 500 TCP connections, send partial HTTP request
// Drip 1 byte per second for 30 seconds
// Verify WAF kills stale connections
func (d *DDoSTester) RunD02Slowloris() ResilienceResult {
	result := ResilienceResult{
		TestID:      "D02",
		Name:        "Slowloris",
		Category:    "SlowAttack",
		Description: "500 slow connections, verify WAF kills them but accepts new legitimate",
		Details:     make(map[string]interface{}),
		Passed:      false,
	}

	wafBaseURL := d.wafClient.GetBaseURL()

	numConnections := 500
	dripDuration := 30 * time.Second

	var connectionsOpened int64
	var connectionsKilled int64
	var wg sync.WaitGroup

	// Launch slow connections
	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Open TCP connection to WAF
			conn, wafHost, _, err := dialWAF(wafBaseURL)
			if err != nil {
				return
			}
			defer conn.Close()

			atomic.AddInt64(&connectionsOpened, 1)

			// Send partial HTTP request (incomplete headers)
			partialRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n", wafHost)
			conn.Write([]byte(partialRequest))

			// Drip 1 byte per second
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()

			dripCount := 0
			deadline := time.After(dripDuration)

			for {
				select {
				case <-ticker.C:
					_, err := conn.Write([]byte("X"))
					if err != nil {
						// Connection was killed
						atomic.AddInt64(&connectionsKilled, 1)
						return
					}
					dripCount++
				case <-deadline:
					// Timeout reached
					return
				}
			}
		}(i)
	}

	// Wait for all connections
	wg.Wait()

	result.Details["connections_opened"] = connectionsOpened
	result.Details["connections_killed"] = connectionsKilled

	// Verify new legitimate connection still accepted
	conn, _, dialAddr, err := dialWAF(wafBaseURL)
	if err == nil {
		conn.Close()
		result.Details["new_connection_accepted"] = true
		result.Details["waf_dial_addr"] = dialAddr
	} else {
		result.Details["new_connection_accepted"] = false
	}

	// Pass if most connections were killed AND new connections accepted
	if float64(connectionsKilled) > float64(numConnections)*0.8 {
		result.Details["killed_threshold_met"] = true
		if err == nil {
			result.Passed = true
		}
	}

	return result
}

// RunD03RUDY runs D03 RUDY (Slow POST) test
// POST /login with Content-Length: 1000000
// Send 1 byte per second
// Verify WAF kills connection within 30 seconds
func (d *DDoSTester) RunD03RUDY() ResilienceResult {
	result := ResilienceResult{
		TestID:      "D03",
		Name:        "RUDY (Slow POST)",
		Category:    "SlowAttack",
		Description: "Slow POST with large Content-Length, verify WAF kills within 30s",
		Details:     make(map[string]interface{}),
		Passed:      false,
	}

	wafBaseURL := d.wafClient.GetBaseURL()

	conn, wafHost, dialAddr, err := dialWAF(wafBaseURL)
	if err != nil {
		result.Details["connection_error"] = err.Error()
		return result
	}
	defer conn.Close()

	// Send POST request with large Content-Length
	headers := "POST /login HTTP/1.1\r\n" +
		fmt.Sprintf("Host: %s\r\n", wafHost) +
		"Content-Type: application/json\r\n" +
		"Content-Length: 1000000\r\n" +
		"\r\n"

	conn.Write([]byte(headers))

	// Send 1 byte per second
	start := time.Now()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	bytesSent := 0
	connectionKilled := false

	for i := 0; i < 30; i++ {
		select {
		case <-ticker.C:
			_, err := conn.Write([]byte("{"))
			if err != nil {
				// Connection was killed
				connectionKilled = true
				result.Details["connection_killed_at_seconds"] = i
				break
			}
			bytesSent++
		}
		if connectionKilled {
			break
		}
	}

	duration := time.Since(start)
	result.Details["bytes_sent"] = bytesSent
	result.Details["duration_ms"] = duration.Milliseconds()
	result.Details["connection_killed"] = connectionKilled
	result.Details["waf_dial_addr"] = dialAddr

	// Pass if connection was killed within 30 seconds
	if connectionKilled && duration < 30*time.Second {
		result.Passed = true
	}

	return result
}

// RunD04WAFFlood runs D04 WAF-targeted flood test
// Send 100,000 req/s for 60 seconds
// During flood: send 5 CRITICAL + 5 MEDIUM requests
// CRITICAL should return 503 (fail-close)
// MEDIUM should return 200 (fail-open)
func (d *DDoSTester) RunD04WAFFlood() ResilienceResult {
	result := ResilienceResult{
		TestID:      "D04",
		Name:        "WAF-Targeted Flood",
		Category:    "DDoS",
		Description: "100k req/s flood, verify fail-close for CRITICAL, fail-open for MEDIUM",
		Details:     make(map[string]interface{}),
		Passed:      false,
	}

	floodDuration := 60 * time.Second

	// Start flood in background
	ctx, cancel := context.WithTimeout(context.Background(), floodDuration)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	// Launch flood workers
	for i := 0; i < 200; i++ {
		g.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return nil
				default:
					d.wafClient.SendRequestWithIP("GET", "/", nil, nil, "127.0.0.210")
				}
			}
		})
	}

	// During flood, send tiered requests
	start := time.Now()
	criticalResults := []int{}
	mediumResults := []int{}

	// Send requests every 6 seconds for 60 seconds = 10 rounds
	ticker := time.NewTicker(6 * time.Second)
	defer ticker.Stop()

	for i := 0; i < 10; i++ {
		<-ticker.C

		// Send 5 CRITICAL requests
		for j := 0; j < 5; j++ {
			resp, err := d.wafClient.SendRequestWithIP("POST", "/login", nil, nil, "127.0.0.220")
			if err == nil {
				criticalResults = append(criticalResults, resp.StatusCode)
			}
		}

		// Send 5 MEDIUM requests
		for j := 0; j < 5; j++ {
			resp, err := d.wafClient.SendRequestWithIP("GET", "/static/js/app.js", nil, nil, "127.0.0.221")
			if err == nil {
				mediumResults = append(mediumResults, resp.StatusCode)
			}
		}
	}

	g.Wait()
	result.Details["flood_duration_ms"] = time.Since(start).Milliseconds()

	// Analyze results
	critical503s := 0
	critical200s := 0
	for _, code := range criticalResults {
		if code == 503 {
			critical503s++
		}
		if code == 200 {
			critical200s++
		}
	}

	medium200s := 0
	for _, code := range mediumResults {
		if code == 200 {
			medium200s++
		}
	}

	result.Details["critical_503_count"] = critical503s
	result.Details["critical_200_count"] = critical200s
	result.Details["medium_200_count"] = medium200s
	result.Details["critical_total"] = len(criticalResults)
	result.Details["medium_total"] = len(mediumResults)

	// Pass if: most CRITICAL returned 503 (fail-close) AND most MEDIUM returned 200 (fail-open)
	criticalFailCloseRate := float64(critical503s) / float64(len(criticalResults))
	mediumFailOpenRate := float64(medium200s) / float64(len(mediumResults))

	result.Details["fail_close_rate"] = criticalFailCloseRate
	result.Details["fail_open_rate"] = mediumFailOpenRate

	if criticalFailCloseRate >= 0.7 && mediumFailOpenRate >= 0.7 {
		result.Passed = true
	}

	return result
}

// BackendTester handles backend failure tests
type BackendTester struct {
	wafClient    *waf.WAFClient
	targetClient *target.Client
	control      *target.Control
}

// NewBackendTester creates a new backend tester
func NewBackendTester(wafClient *waf.WAFClient, targetClient *target.Client, control *target.Control) *BackendTester {
	return &BackendTester{
		wafClient:    wafClient,
		targetClient: targetClient,
		control:      control,
	}
}

// FailModeTester handles D08-D09 fail-mode configurability tests
type FailModeTester struct {
	wafClient *waf.WAFClient
	control   *target.Control
}

// NewFailModeTester creates a new fail-mode tester
func NewFailModeTester(wafClient *waf.WAFClient, control *target.Control) *FailModeTester {
	return &FailModeTester{
		wafClient: wafClient,
		control:   control,
	}
}

// RunD08FailModeConfigChange runs D08 fail-mode configurability test
// Simulates fail-close config for MEDIUM tier and verifies 503 behavior
func (f *FailModeTester) RunD08FailModeConfigChange() ResilienceResult {
	result := ResilienceResult{
		TestID:      "D08",
		Name:        "Fail-Mode Config Change",
		Category:    "FailMode",
		Description: "Apply fail-close mode and verify MEDIUM tier returns 503",
		Details:     make(map[string]interface{}),
		Passed:      false,
	}

	result.Details["mutation_strategy"] = "control_hook_health_mode"
	result.Details["target_tier"] = "MEDIUM"

	if f.control == nil {
		result.Details["config_apply_error"] = "control interface is nil"
		return result
	}

	if err := f.control.SetHealthMode(true); err != nil {
		result.Details["config_apply_error"] = err.Error()
		return result
	}

	time.Sleep(300 * time.Millisecond)

	statusCodes := make([]int, 0, 5)
	failedRequests := 0
	for i := 0; i < 5; i++ {
		resp, err := f.wafClient.SendRequestWithIP("GET", "/static/js/app.js", nil, nil, "127.0.0.230")
		if err != nil {
			failedRequests++
			continue
		}
		statusCodes = append(statusCodes, resp.StatusCode)
	}

	returned503 := 0
	for _, code := range statusCodes {
		if code == 503 {
			returned503++
		}
	}

	result.Details["status_codes"] = statusCodes
	result.Details["request_errors"] = failedRequests
	result.Details["returned_503"] = returned503
	result.Details["total_attempted"] = 5

	// Deterministic pass criteria: all successful responses should be 503 and no request errors
	if failedRequests == 0 && len(statusCodes) == 5 && returned503 == 5 {
		result.Passed = true
	}

	return result
}

// RunD09FailModeRestore runs D09 fail-mode restore test
// Restores default fail-open behavior and verifies MEDIUM tier returns 200
func (f *FailModeTester) RunD09FailModeRestore() ResilienceResult {
	result := ResilienceResult{
		TestID:      "D09",
		Name:        "Fail-Mode Restore",
		Category:    "FailMode",
		Description: "Revert fail-mode and verify MEDIUM tier returns 200",
		Details:     make(map[string]interface{}),
		Passed:      false,
	}

	result.Details["mutation_strategy"] = "control_hook_health_mode"
	result.Details["target_tier"] = "MEDIUM"

	if f.control == nil {
		result.Details["config_revert_error"] = "control interface is nil"
		return result
	}

	if err := f.control.SetHealthMode(false); err != nil {
		result.Details["config_revert_error"] = err.Error()
		return result
	}

	if err := f.control.SetErrorMode("normal"); err != nil {
		result.Details["error_mode_reset_error"] = err.Error()
		return result
	}

	if err := f.control.SetSlow(0); err != nil {
		result.Details["slow_mode_reset_error"] = err.Error()
		return result
	}

	time.Sleep(300 * time.Millisecond)

	statusCodes := make([]int, 0, 5)
	failedRequests := 0
	for i := 0; i < 5; i++ {
		resp, err := f.wafClient.SendRequestWithIP("GET", "/static/js/app.js", nil, nil, "127.0.0.231")
		if err != nil {
			failedRequests++
			continue
		}
		statusCodes = append(statusCodes, resp.StatusCode)
	}

	returned200 := 0
	for _, code := range statusCodes {
		if code == 200 {
			returned200++
		}
	}

	result.Details["status_codes"] = statusCodes
	result.Details["request_errors"] = failedRequests
	result.Details["returned_200"] = returned200
	result.Details["total_attempted"] = 5

	// Deterministic pass criteria: all successful responses should be 200 and no request errors
	if failedRequests == 0 && len(statusCodes) == 5 && returned200 == 5 {
		result.Passed = true
	}

	return result
}

// RunD05BackendDown runs D05 backend down test.
// Spec: set down=true, wait 2s, send 10 requests, all must be 503 and each <= 5s.
func (b *BackendTester) RunD05BackendDown() ResilienceResult {
	result := ResilienceResult{
		TestID:      "D05",
		Name:        "Backend Down - Circuit Breaker",
		Category:    "BackendFailure",
		Description: "Set backend down and verify 10/10 requests return 503 within timeout",
		Details:     make(map[string]interface{}),
		Passed:      false,
	}

	if b.control == nil {
		result.Details["control_error"] = "control interface is nil"
		return result
	}

	if err := b.control.SetHealthMode(true); err != nil {
		result.Details["set_health_mode_error"] = err.Error()
		return result
	}
	result.Details["health_mode_set"] = "down=true"

	// Allow propagation to WAF circuit breaker.
	time.Sleep(2 * time.Second)

	const attempts = 10
	statusCodes := make([]int, 0, attempts)
	latencyMs := make([]int64, 0, attempts)
	requestErrors := 0
	fastEnough := 0
	returned503 := 0

	for i := 0; i < attempts; i++ {
		start := time.Now()
		resp, err := b.wafClient.SendRequestWithIP("GET", "/", nil, nil, "127.0.0.240")
		durMs := time.Since(start).Milliseconds()
		latencyMs = append(latencyMs, durMs)

		if err != nil {
			requestErrors++
			continue
		}

		statusCodes = append(statusCodes, resp.StatusCode)
		if resp.StatusCode == 503 {
			returned503++
		}
		if durMs <= 5000 {
			fastEnough++
		}
	}

	result.Details["attempted_requests"] = attempts
	result.Details["request_errors"] = requestErrors
	result.Details["status_codes"] = statusCodes
	result.Details["latency_ms"] = latencyMs
	result.Details["returned_503"] = returned503
	result.Details["within_5s"] = fastEnough

	if requestErrors == 0 && len(statusCodes) == attempts && returned503 == attempts && fastEnough == attempts {
		result.Passed = true
	}

	return result
}

// RunD06BackendSlow runs D06 backend slow test.
// Spec: set slow delay to 10s, send 50 requests, expect 504 and each <= 5s.
func (b *BackendTester) RunD06BackendSlow() ResilienceResult {
	result := ResilienceResult{
		TestID:      "D06",
		Name:        "Backend Slow - Timeout",
		Category:    "BackendFailure",
		Description: "Set backend slow (10s) and verify 50/50 requests return 504 within timeout",
		Details:     make(map[string]interface{}),
		Passed:      false,
	}

	if b.control == nil {
		result.Details["control_error"] = "control interface is nil"
		return result
	}

	if err := b.control.SetHealthMode(false); err != nil {
		result.Details["set_health_mode_error"] = err.Error()
		return result
	}
	if err := b.control.SetSlow(10000); err != nil {
		result.Details["set_slow_error"] = err.Error()
		return result
	}
	result.Details["slow_mode_set"] = "delay_ms=10000"

	const attempts = 50
	statusCodes := make([]int, 0, attempts)
	latencyMs := make([]int64, 0, attempts)
	requestErrors := 0
	returned504 := 0
	withinTimeout := 0

	for i := 0; i < attempts; i++ {
		start := time.Now()
		resp, err := b.wafClient.SendRequestWithIP("GET", "/", nil, nil, "127.0.0.241")
		durMs := time.Since(start).Milliseconds()
		latencyMs = append(latencyMs, durMs)

		if err != nil {
			requestErrors++
			continue
		}

		statusCodes = append(statusCodes, resp.StatusCode)
		if resp.StatusCode == 504 {
			returned504++
		}
		if durMs <= 5000 {
			withinTimeout++
		}
	}

	result.Details["attempted_requests"] = attempts
	result.Details["request_errors"] = requestErrors
	result.Details["status_codes"] = statusCodes
	result.Details["latency_ms"] = latencyMs
	result.Details["returned_504"] = returned504
	result.Details["within_5s"] = withinTimeout

	if requestErrors == 0 && len(statusCodes) == attempts && returned504 == attempts && withinTimeout == attempts {
		result.Passed = true
	}

	return result
}

// RunD07BackendRecovery runs D07 backend recovery test
// Restore backend, verify recovery within 5 seconds
func (b *BackendTester) RunD07BackendRecovery() ResilienceResult {
	result := ResilienceResult{
		TestID:      "D07",
		Name:        "Backend Recovery",
		Category:    "BackendFailure",
		Description: "After backend recovery, WAF should pass traffic within 5s",
		Details:     make(map[string]interface{}),
		Passed:      false,
	}

	if b.control == nil {
		result.Details["control_error"] = "control interface is nil"
		return result
	}

	// Restore backend to normal before polling recovery.
	if err := b.control.SetHealthMode(false); err != nil {
		result.Details["set_health_mode_error"] = err.Error()
		return result
	}
	if err := b.control.SetSlow(0); err != nil {
		result.Details["set_slow_error"] = err.Error()
		return result
	}
	if err := b.control.SetErrorMode("normal"); err != nil {
		result.Details["set_error_mode_error"] = err.Error()
		return result
	}

	// Poll WAF for recovery
	start := time.Now()
	recovered := false

	for i := 0; i < 10; i++ {
		resp, err := b.wafClient.SendRequestWithIP("GET", "/", nil, nil, "127.0.0.242")
		if err == nil && resp.StatusCode == 200 {
			recovered = true
			result.Details["recovery_time_ms"] = time.Since(start).Milliseconds()
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	result.Details["total_wait_ms"] = time.Since(start).Milliseconds()
	result.Details["recovered"] = recovered

	if recovered && time.Since(start) < 5*time.Second {
		result.Passed = true
	}

	return result
}

// RunPhaseD executes all Phase D tests
func RunPhaseD(wafClient *waf.WAFClient, targetClient *target.Client, control *target.Control) (*PhaseDResult, error) {
	start := time.Now()
	result := &PhaseDResult{
		DDoSTests:           make([]ResilienceResult, 0),
		SlowAttackTests:     make([]ResilienceResult, 0),
		BackendFailureTests: make([]ResilienceResult, 0),
		FailModeTests:       make([]ResilienceResult, 0),
	}

	ddosTester := NewDDoSTester(wafClient, targetClient)
	backendTester := NewBackendTester(wafClient, targetClient, control)
	failModeTester := NewFailModeTester(wafClient, control)

	// D01: HTTP Flood
	fmt.Println("Phase D: Running D01 HTTP flood test...")
	d01 := ddosTester.RunD01HTTPFlood()
	result.DDoSTests = append(result.DDoSTests, d01)

	// D02: Slowloris
	fmt.Println("Phase D: Running D02 Slowloris test...")
	d02 := ddosTester.RunD02Slowloris()
	result.SlowAttackTests = append(result.SlowAttackTests, d02)

	// D03: RUDY
	fmt.Println("Phase D: Running D03 RUDY test...")
	d03 := ddosTester.RunD03RUDY()
	result.SlowAttackTests = append(result.SlowAttackTests, d03)

	// D04: WAF-targeted flood
	fmt.Println("Phase D: Running D04 WAF-targeted flood test...")
	d04 := ddosTester.RunD04WAFFlood()
	result.DDoSTests = append(result.DDoSTests, d04)

	// D05-D07: Backend failure tests
	fmt.Println("Phase D: Running D05 backend down test...")
	d05 := backendTester.RunD05BackendDown()
	result.BackendFailureTests = append(result.BackendFailureTests, d05)

	fmt.Println("Phase D: Running D06 backend slow test...")
	d06 := backendTester.RunD06BackendSlow()
	result.BackendFailureTests = append(result.BackendFailureTests, d06)

	fmt.Println("Phase D: Running D07 backend recovery test...")
	d07 := backendTester.RunD07BackendRecovery()
	result.BackendFailureTests = append(result.BackendFailureTests, d07)

	// D08-D09: fail-mode configurability tests
	fmt.Println("Phase D: Running D08 fail-mode config change test...")
	d08 := failModeTester.RunD08FailModeConfigChange()
	result.FailModeTests = append(result.FailModeTests, d08)

	fmt.Println("Phase D: Running D09 fail-mode restore test...")
	d09 := failModeTester.RunD09FailModeRestore()
	result.FailModeTests = append(result.FailModeTests, d09)

	// Calculate scores for D01-D09
	applyPhaseDScores(result)
	result.DurationMs = time.Since(start).Milliseconds()

	return result, nil
}

// Summary returns a human-readable summary of Phase D results
func (r *PhaseDResult) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(
		"Phase D (Resilience) - Duration: %dms\n"+
		"  DDoS Tests: %d/%d passed (%.0f/4 pts)\n"+
		"  Slow Attack Tests: %d/%d passed\n"+
		"  Backend Tests: %d/%d passed (%.0f/3 pts)\n"+
		"  Fail Mode Tests: %d/%d passed (%.0f/2 pts)\n"+
		"  Total Score: %.0f/9",
		r.DurationMs,
		countPassedResilience(r.DDoSTests), len(r.DDoSTests), r.DDoSScore,
		countPassedResilience(r.SlowAttackTests), len(r.SlowAttackTests),
		countPassedResilience(r.BackendFailureTests), len(r.BackendFailureTests), r.BackendScore,
		countPassedResilience(r.FailModeTests), len(r.FailModeTests), r.FailModeScore,
		r.TotalScore,
	))

	// Add details for failed tests
	for _, test := range r.DDoSTests {
		if !test.Passed {
			sb.WriteString(fmt.Sprintf("\n    [!] %s: %s", test.TestID, test.Name))
		}
	}
	for _, test := range r.SlowAttackTests {
		if !test.Passed {
			sb.WriteString(fmt.Sprintf("\n    [!] %s: %s", test.TestID, test.Name))
		}
	}
	for _, test := range r.BackendFailureTests {
		if !test.Passed {
			sb.WriteString(fmt.Sprintf("\n    [!] %s: %s", test.TestID, test.Name))
		}
	}
	for _, test := range r.FailModeTests {
		if !test.Passed {
			sb.WriteString(fmt.Sprintf("\n    [!] %s: %s", test.TestID, test.Name))
		}
	}

	return sb.String()
}

// applyPhaseDScores calculates DDoS, backend, fail-mode, and total scores for Phase D.
func applyPhaseDScores(result *PhaseDResult) {
	if result == nil {
		return
	}

	result.DDoSScore = float64(countPassedResilience(result.DDoSTests))
	result.BackendScore = float64(countPassedResilience(result.BackendFailureTests))
	result.FailModeScore = float64(countPassedResilience(result.FailModeTests))
	result.TotalScore = result.DDoSScore + result.BackendScore + result.FailModeScore
}

// countPassedResilience counts passed resilience tests
func countPassedResilience(tests []ResilienceResult) int {
	count := 0
	for _, test := range tests {
		if test.Passed {
			count++
		}
	}
	return count
}

// countPassed counts passed resilience tests
func countResiliencePassed(tests []ResilienceResult) int {
	count := 0
	for _, test := range tests {
		if test.Passed {
			count++
		}
	}
	return count
}
