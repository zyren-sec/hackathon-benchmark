package phaseb

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/waf-hackathon/benchmark-new/internal/challenge"
	"github.com/waf-hackathon/benchmark-new/internal/crossphase"
)

// ── Engine ──

type BEngine struct {
	cfg             *BConfigWrapper
	pool            *crossphase.GlobalResponsePool // SEC-02 response collector
	challengeSolver *challenge.Solver              // 429 challenge lifecycle handler
	targetURL       string
	wafURL          string
	wafAdminURL     string
	controlSecret   string
	client          *http.Client
	dryRun          bool
}

type BConfigWrapper struct {
	TargetBaseURL string
	WAFBaseURL    string
	WAFAdminURL   string
	ControlSecret string
	TimeoutSec    int
	Verbose       bool
	DryRun        bool
}

func NewBEngine(cfg *BConfigWrapper, pool *crossphase.GlobalResponsePool, chSolver *challenge.Solver) *BEngine {
	return &BEngine{
		cfg:             cfg,
		pool:            pool,
		challengeSolver: chSolver,
		targetURL:       cfg.TargetBaseURL,
		wafURL:          cfg.WAFBaseURL,
		wafAdminURL:     cfg.WAFAdminURL,
		controlSecret:   cfg.ControlSecret,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSec) * time.Second,
		},
		dryRun: cfg.DryRun,
	}
}

// Run executes the full Phase B workflow.
func (e *BEngine) Run() (*PhaseBResult, error) {
	if e.dryRun {
		return e.simulateRun(), nil
	}
	return e.realRun()
}

// ── Real HTTP Execution ──

func (e *BEngine) realRun() (*PhaseBResult, error) {
	now := time.Now()
	result := &PhaseBResult{
		StartTime: now,
		WAFTarget: e.cfg.WAFBaseURL,
		WAFMode:   "enforce",
		Scores:    make(map[string]float64),
	}

	// 1. Pre-check: proxy health gate
	alive, total := e.preCheckProxies()
	result.PreCheckAlive = alive
	result.PreCheckTotal = total
	result.PreCheckPassed = alive >= 3
	if !result.PreCheckPassed {
		result.PreCheckWarning = true
		if e.cfg.Verbose {
			fmt.Printf("⚠️  Proxy health gate: %d/%d alive — continuing with loopback fallback\n", alive, total)
		}
	}

	// 2. Full Reset Sequence (§3.1)
	result.ResetSteps = e.fullResetSequenceReal()
	result.ResetAllPassed = true
	for _, s := range result.ResetSteps {
		// Step 4 (flush_cache) is non-fatal — skip if 501
		if !s.Success && s.StepNum != 4 {
			result.ResetAllPassed = false
			break
		}
	}
	if !result.ResetAllPassed {
		result.EndTime = time.Now()
		return result, fmt.Errorf("reset sequence failed")
	}

	// 2b. AB Negative Control Pre-test (§4.1): 3 legitimate logins from 127.0.0.9
	// If WAF blocks these, it's a false positive affecting SEC-03
	if e.cfg.Verbose {
		fmt.Println("  [PRE-TEST] AB Negative Control: 3 legitimate logins (127.0.0.9)")
	}
	abNegControlPassed := true
	for i := 1; i <= 3; i++ {
		r := e.doRequest("POST", "/login",
			`{"username":"alice","password":"P@ssw0rd1"}`,
			map[string]string{"Content-Type": "application/json"},
			"AB-NEG-CTRL", "127.0.0.9")
		if r.Blocked {
			abNegControlPassed = false
			if e.cfg.Verbose {
				fmt.Printf("  ⚠️  AB Negative Control FAIL: login %d blocked (HTTP %d)\n", i, r.StatusCode)
			}
		}
	}
	if !abNegControlPassed {
		result.ABNegControlPassed = false
		if e.cfg.Verbose {
			fmt.Println("  ⚠️  AB Negative Control: FAIL — legitimate logins blocked (false positive)")
		}
	} else if e.cfg.Verbose {
		fmt.Println("  ✓ AB Negative Control: all 3 logins allowed (200)")
	}

	// 3. Run all tests in execution order
	// v2.9: Relay no longer split into sub-phases (AR04/AR05 removed)
	allTests := GetBTests(e.wafURL)
	categoryOrder := []string{"brute_force", "relay", "behavioral", "transaction", "recon"}

	var previousCat string
	var currentCatTests []BTestResult
	needsReset := true     // First test always shows "Reset before: Yes" (after Full Reset Sequence)
	resetType := "UPSTREAM+WAF (Full Reset Sequence)"

	for i, bt := range allTests {
		if i > 0 && bt.Category != previousCat {
			e.resetBoth()
			needsReset = true
			resetType = "UPSTREAM+WAF"
			if e.cfg.Verbose {
				fmt.Printf("  [RESET] UPSTREAM + WAF: %s → %s\n", previousCat, bt.Category)
			}
			result = e.buildCategoryResult(result, previousCat, currentCatTests, 0)
			currentCatTests = nil
		}

		tr := e.runTestReal(&bt)
		// Tag reset info on first test of each category
		if needsReset {
			tr.ResetBefore = true
			tr.ResetType = resetType
			needsReset = false
		}
		currentCatTests = append(currentCatTests, tr)
		result.TestResults = append(result.TestResults, tr)
		previousCat = bt.Category
	}
	result = e.buildCategoryResult(result, previousCat, currentCatTests, 0)
	result = e.reorderCategories(result, categoryOrder)

	computeScores(result)
	result.EndTime = time.Now()
	return result, nil
}

// ── HTTP Helpers ──

// doRequest sends an HTTP request through WAF and captures the result.
func (e *BEngine) doRequest(method, path, body string, headers map[string]string, testID, sourceIP string) BRequestResult {
	req := BRequestResult{
		Method: method,
		URL:    e.wafURL + path,
	}

	fullURL := e.wafURL + path
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
		req.RequestBody = body
	}

	httpReq, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		req.StatusCode = 0
		req.FailReason = "MISSING HDR"
		return req
	}

	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}

	req.RequestHeaders = make(map[string]string)
	for k, vv := range httpReq.Header {
		req.RequestHeaders[k] = strings.Join(vv, ", ")
	}

	// Build curl command
	req.CurlCommand = buildCurlB(fullURL, method, headers, body)

	start := time.Now()
	resp, err := e.client.Do(httpReq)
	req.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		req.StatusCode = 0
		return req
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	req.StatusCode = resp.StatusCode
	req.ResponseBody = string(bodyBytes)

	req.ResponseHeaders = make(map[string]string)
	for k, vv := range resp.Header {
		req.ResponseHeaders[k] = strings.Join(vv, ", ")
	}

	// Append to global response pool for SEC-02 (cross_phase.md §3)
	if e.pool != nil {
		e.pool.Append("B", testID, sourceIP, path, method,
			req.StatusCode, req.ResponseBody, req.ResponseHeaders)
	}

	// 429 Challenge detection and lifecycle evaluation (429_challenge.md)
	if e.challengeSolver != nil && challenge.IsChallenge(req.StatusCode, req.ResponseHeaders) {
		ctx := challenge.PhaseHookContext{
			Phase:           "B",
			TestID:          testID,
			Method:          method,
			Endpoint:        path,
			RequestBody:     body,
			RequestHeaders:  req.RequestHeaders,
			StatusCode:      req.StatusCode,
			ResponseBody:    req.ResponseBody,
			ResponseHeaders: req.ResponseHeaders,
		}
		lr := e.challengeSolver.HandleChallenge(ctx)
		if e.cfg.Verbose {
			challenge.DisplayChallengeResult(lr)
		}
	}

	req.WAFAction = strings.TrimSpace(resp.Header.Get("X-WAF-Action"))
	if rs := resp.Header.Get("X-WAF-Risk-Score"); rs != "" {
		req.RiskScore, _ = strconv.Atoi(strings.TrimSpace(rs))
	}

	req.Blocked = req.StatusCode == 403 || req.StatusCode == 429 ||
		strings.EqualFold(req.WAFAction, "block") ||
		strings.EqualFold(req.WAFAction, "challenge")

	return req
}

// buildCurlB builds a curl command for reproducibility.
func buildCurlB(fullURL, method string, headers map[string]string, body string) string {
	var sb strings.Builder
	sb.WriteString("curl")
	if method != "GET" {
		sb.WriteString(fmt.Sprintf(" -X %s", method))
	}
	sb.WriteString(fmt.Sprintf(" '%s'", strings.ReplaceAll(fullURL, "'", "'\\''")))
	for k, v := range headers {
		if strings.EqualFold(k, "content-length") {
			continue
		}
		sb.WriteString(fmt.Sprintf(" -H '%s: %s'",
			strings.ReplaceAll(k, "'", "'\\''"),
			strings.ReplaceAll(v, "'", "'\\''")))
	}
	if body != "" {
		sb.WriteString(fmt.Sprintf(" -d '%s'", strings.ReplaceAll(body, "'", "'\\''")))
	}
	sb.WriteString(" -s -o - -w '\\nHTTP_STATUS:%%{http_code}' --max-time 30")
	return sb.String()
}

// ── Reset Helpers ──

func (e *BEngine) fullResetSequenceReal() []BResetStep {
	var steps []BResetStep

	// v2.6 order per §3.1: UPSTREAM first, then WAF
	// [1] UPSTREAM reset → [2] UPSTREAM health → [3] WAF set_profile → [4] WAF flush_cache → [5] WAF reset_state
	// Rationale: reset UPSTREAM first so WAF initialises against a known-clean upstream.
	doStep := func(num int, name, method, urlStr string, body string, fatal bool) BResetStep {
		rs := BResetStep{StepNum: num, Name: name, Method: method, URL: urlStr}
		start := time.Now()

		var req *http.Request
		var err error
		if body != "" {
			req, err = http.NewRequest(method, urlStr, bytes.NewReader([]byte(body)))
		} else {
			req, err = http.NewRequest(method, urlStr, nil)
		}
		if err != nil {
			rs.Error = err.Error()
			rs.LatencyMs = time.Since(start).Seconds() * 1000
			return rs
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Benchmark-Secret", e.controlSecret)

		var resp *http.Response
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(2 * time.Second)
			}
			resp, err = e.client.Do(req)
			if err == nil {
				break
			}
		}
		rs.LatencyMs = time.Since(start).Seconds() * 1000
		if err != nil {
			rs.Error = err.Error()
			return rs
		}
		defer resp.Body.Close()
		rs.StatusCode = resp.StatusCode

		// Step 4 (flush_cache): accept 200 or 501 (cache not supported) — NOT fatal
		if num == 4 && (resp.StatusCode == 200 || resp.StatusCode == 501) {
			rs.Success = true
		} else if resp.StatusCode == 200 {
			rs.Success = true
		}
		return rs
	}

	// v2.6 order per §3.1:
	// Step 1: Reset UPSTREAM state
	steps = append(steps, doStep(1, "Reset UPSTREAM", "POST",
		e.targetURL+"/__control/reset", "", true))
	// Step 2: UPSTREAM health check
	// v2.6 spec says /__control/health, but UPSTREAM may only expose /health.
	steps = append(steps, e.doHealthStep(2, "UPSTREAM health check"))
	// Step 3: Set WAF to enforce mode
	steps = append(steps, doStep(3, "Set WAF profile (enforce)", "POST",
		e.wafAdminURL+"/__waf_control/set_profile",
		`{"scope":"all","mode":"enforce"}`, true))
	// Step 4: Flush WAF cache (not fatal — 200 or 501 OK)
	steps = append(steps, doStep(4, "Flush WAF cache", "POST",
		e.wafAdminURL+"/__waf_control/flush_cache", "", false))
	// Step 5: Reset WAF state (final — clean residual risk scores)
	steps = append(steps, doStep(5, "Reset WAF state", "POST",
		e.wafAdminURL+"/__waf_control/reset_state", "", true))

	return steps
}

// doHealthStep tries /__control/health first (spec), falls back to /health.
// Both return {"status":"ok"} on success.
func (e *BEngine) doHealthStep(num int, name string) BResetStep {
	rs := BResetStep{StepNum: num, Name: name, Method: "GET"}
	start := time.Now()

	// Try spec endpoint first: /__control/health
	tryHealth := func(urlStr string) (int, bool) {
		req, _ := http.NewRequest("GET", urlStr, nil)
		req.Header.Set("X-Benchmark-Secret", e.controlSecret)
		resp, err := e.client.Do(req)
		if err != nil {
			return 0, false
		}
		defer resp.Body.Close()
		return resp.StatusCode, resp.StatusCode == 200
	}

	specURL := e.targetURL + "/__control/health"
	code, ok := tryHealth(specURL)
	if ok {
		rs.StatusCode = code
		rs.Success = true
		rs.LatencyMs = time.Since(start).Seconds() * 1000
		rs.URL = specURL
		return rs
	}

	// Fallback: /health (no X-Benchmark-Secret needed)
	fallbackURL := e.targetURL + "/health"
	req2, _ := http.NewRequest("GET", fallbackURL, nil)
	resp2, err := e.client.Do(req2)
	rs.LatencyMs = time.Since(start).Seconds() * 1000
	if err != nil {
		rs.Error = err.Error()
		return rs
	}
	defer resp2.Body.Close()
	rs.StatusCode = resp2.StatusCode
	rs.Success = resp2.StatusCode == 200
	rs.URL = fallbackURL
	return rs
}

// resetBoth resets both UPSTREAM and WAF state (between categories).
func (e *BEngine) resetBoth() {
	// Reset UPSTREAM
	req, _ := http.NewRequest("POST", e.targetURL+"/__control/reset", nil)
	req.Header.Set("X-Benchmark-Secret", e.controlSecret)
	resp, err := e.client.Do(req)
	if err == nil {
		resp.Body.Close()
	}

	// Reset WAF state
	req2, _ := http.NewRequest("POST", e.wafAdminURL+"/__waf_control/reset_state", nil)
	req2.Header.Set("X-Benchmark-Secret", e.controlSecret)
	resp2, err2 := e.client.Do(req2)
	if err2 == nil {
		resp2.Body.Close()
	}
}

// preCheckProxies tests SOCKS5 proxy health. Returns alive, total.
// v2.6: Reads actual proxy list from docs/hackathon/proxy_ip.md.
// Falls back to 5/5 if file not found (proxy health is advisory, not blocking).
func (e *BEngine) preCheckProxies() (int, int) {
	proxyFile := "/var/www/docs/hackathon/proxy_ip.md"
	data, err := os.ReadFile(proxyFile)
	if err != nil {
		// File not found — skip proxy health gate gracefully
		return 5, 5
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	total := 0
	alive := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		total++
		// Quick TCP dial test on proxy IP:PORT
		parts := strings.SplitN(line, ":", 4)
		if len(parts) >= 2 {
			conn, err := net.DialTimeout("tcp", parts[0]+":"+parts[1], 3*time.Second)
			if err == nil {
				conn.Close()
				alive++
			}
		}
	}
	if total == 0 {
		return 5, 5 // No proxies configured — use loopback only
	}
	return alive, total
}

// ── Login/OTP Session Helper (§4.3 BA05 + TF auth) ──

// loginOTP performs login+OTP exchange and returns a session cookie (sid).
// v2.6: Each BA test and each TF test gets its own isolated session.
func (e *BEngine) loginOTP(username, password, otpCode string) string {
	// Step 1: Login
	loginBody := fmt.Sprintf(`{"username":"%s","password":"%s"}`, username, password)
	req1, _ := http.NewRequest("POST", e.wafURL+"/login",
		bytes.NewReader([]byte(loginBody)))
	req1.Header.Set("Content-Type", "application/json")
	resp1, err := e.client.Do(req1)
	if err != nil {
		return ""
	}
	defer resp1.Body.Close()
	body1, _ := io.ReadAll(io.LimitReader(resp1.Body, 64*1024))
	// Extract login_token from JSON response (simple string search)
	lt := extractJSONString(string(body1), "login_token")
	if lt == "" {
		return ""
	}

	// Step 2: OTP exchange
	otpBody := fmt.Sprintf(`{"login_token":"%s","otp_code":"%s"}`, lt, otpCode)
	req2, _ := http.NewRequest("POST", e.wafURL+"/otp",
		bytes.NewReader([]byte(otpBody)))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := e.client.Do(req2)
	if err != nil {
		return ""
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 64*1024))
	sid := extractJSONString(string(body2), "session_id")
	if sid == "" {
		// Fallback: check Set-Cookie header
		for _, c := range resp2.Header["Set-Cookie"] {
			if strings.HasPrefix(c, "sid=") {
				parts := strings.SplitN(c, ";", 2)
				sid = strings.TrimPrefix(parts[0], "sid=")
				break
			}
		}
	}
	return sid
}

// extractJSONString extracts a string value for a given key from a JSON body.
// Lightweight — avoids full JSON parsing.
func extractJSONString(body, key string) string {
	search := fmt.Sprintf(`"%s":"`, key)
	idx := strings.Index(body, search)
	if idx < 0 {
		return ""
	}
	start := idx + len(search)
	end := strings.IndexByte(body[start:], '"')
	if end < 0 {
		return ""
	}
	return body[start : start+end]
}

// ── Real Test Runners ──

func (e *BEngine) runTestReal(bt *BTest) BTestResult {
	tr := BTestResult{
		TestID:          bt.ID,
		Name:            bt.Name,
		Category:        bt.Category,
		Criterion:       bt.Criterion,
		SourceIP:        bt.SourceIP,
		Method:          bt.Method,
		Endpoint:        bt.Endpoint,
		Description:     bt.Description,
		PassCriterion:   bt.PassCriterion,
		NegativeControl: bt.NegativeControl,
		AbuseType:       bt.AbuseType,
		ReproduceScript: bt.ReproduceScript,
	}

	totalReqs := bt.RequestCount
	if totalReqs == 0 {
		totalReqs = 1
	}
	tr.TotalRequests = totalReqs
	tr.BlockedAt = -1
	tr.MinLatencyMs = 999.0

	headers := make(map[string]string)
	if bt.ContentType != "" {
		headers["Content-Type"] = bt.ContentType
	}
	for k, v := range bt.ExtraHeaders {
		headers[k] = v
	}

	// v2.6 Session Isolation: Each test with AuthUser gets its OWN login-OTP.
	// BA03 (bob), BA04 (alice), BA05 (charlie) all have separate sessions.
	// TF tests also get dedicated auth per test.
	var sessionCookie string
	if bt.SessionRequired || bt.AuthUser != "" {
		if bt.AuthUser != "" && bt.AuthPassword != "" && bt.AuthOTP != "" {
			sessionCookie = e.loginOTP(bt.AuthUser, bt.AuthPassword, bt.AuthOTP)
		} else if bt.Category == "transaction" {
			// Legacy fallback for TF tests without explicit AuthUser
			sessionCookie = e.loginOTP("alice", "P@ssw0rd1", "123456")
		} else {
			sessionCookie = e.loginOTP("alice", "P@ssw0rd1", "123456")
		}
		if sessionCookie != "" {
			headers["Cookie"] = "sid=" + sessionCookie
			tr.AuthUsed = true
			// Truncate SID for display (first 8 chars)
			if len(sessionCookie) > 8 {
				tr.SessionID = sessionCookie[:8] + "..."
			} else {
				tr.SessionID = sessionCookie
			}
		}
	}

	// TF04: Multi-Account Device — 5 users, each does login→OTP→deposit
	if bt.ID == "TF04" {
		tr.TotalRequests = bt.RequestCount * 3 // login + otp + deposit per user
		tr.AuthUsed = true // Multi-account does per-user auth
		tr.SessionID = "multi (5 users)"
		for u := 1; u <= bt.RequestCount; u++ {
			username := fmt.Sprintf("testuser_%d", u)
			password := fmt.Sprintf("Test#%dPass", u)
			otp := fmt.Sprintf("%06d", u)

			// Login
			loginBody := fmt.Sprintf(`{"username":"%s","password":"%s"}`, username, password)
			r1 := e.doRequest("POST", "/login", loginBody, headers, bt.ID, bt.SourceIP)
			r1.Index = (u-1)*3 + 1
			tr.Requests = append(tr.Requests, r1)

			// OTP
			lt := extractJSONString(r1.ResponseBody, "login_token")
			otpBody := fmt.Sprintf(`{"login_token":"%s","otp_code":"%s"}`, lt, otp)
			r2 := e.doRequest("POST", "/otp", otpBody, headers, bt.ID, bt.SourceIP)
			r2.Index = (u-1)*3 + 2
			tr.Requests = append(tr.Requests, r2)

			// Deposit
			sid := extractJSONString(r2.ResponseBody, "session_id")
			if sid == "" {
				for _, c := range r2.ResponseHeaders {
					if strings.HasPrefix(c, "sid=") {
						sid = strings.TrimPrefix(strings.SplitN(c, ";", 2)[0], "sid=")
						break
					}
				}
			}
			depHeaders := make(map[string]string)
			for k, v := range headers {
				depHeaders[k] = v
			}
			if sid != "" {
				depHeaders["Cookie"] = "sid=" + sid
			}
			depHeaders["Content-Type"] = "application/json"
			r3 := e.doRequest("POST", "/deposit", `{"amount":100,"currency":"USD"}`, depHeaders, bt.ID, bt.SourceIP)
			r3.Index = (u-1)*3 + 3
			tr.Requests = append(tr.Requests, r3)

			if r1.Blocked || r2.Blocked || r3.Blocked {
				if tr.BlockedAt < 0 {
					tr.BlockedAt = r3.Index
				}
			}
		}
		// Skip normal loop for TF04
		goto computeResults
	}

	for i := 0; i < totalReqs && i < 200; i++ {
		body := ""
		if bt.BodyTemplate != "" {
			body = fmt.Sprintf(bt.BodyTemplate, i+1)
		}

		req := e.doRequest(bt.Method, bt.Endpoint, body, headers, bt.ID, bt.SourceIP)
		req.Index = i + 1

		if req.Blocked && tr.BlockedAt < 0 {
			tr.BlockedAt = i + 1
		}

		tr.Requests = append(tr.Requests, req)

		if req.LatencyMs < tr.MinLatencyMs {
			tr.MinLatencyMs = req.LatencyMs
		}
		if req.LatencyMs > tr.MaxLatencyMs {
			tr.MaxLatencyMs = req.LatencyMs
		}
		if req.RiskScore > tr.MaxRiskScore {
			tr.MaxRiskScore = req.RiskScore
		}
		if req.RiskScore < tr.MinRiskScore {
			tr.MinRiskScore = req.RiskScore
		}

		// Small delay between requests to avoid overwhelming
		time.Sleep(10 * time.Millisecond)
	}

	// Execute SubSteps (TF02: withdrawal, TF03: withdrawal)
	for _, ss := range bt.SubSteps {
		subHeaders := make(map[string]string)
		for k, v := range headers {
			subHeaders[k] = v
		}
		if ss.ContentType != "" {
			subHeaders["Content-Type"] = ss.ContentType
		}
		req := e.doRequest(ss.Method, ss.Endpoint, ss.Body, subHeaders, bt.ID, bt.SourceIP)
		req.Index = len(tr.Requests) + 1
		tr.Requests = append(tr.Requests, req)

		if req.Blocked && tr.BlockedAt < 0 {
			tr.BlockedAt = req.Index
		}
		if req.RiskScore > tr.MaxRiskScore {
			tr.MaxRiskScore = req.RiskScore
		}
		if req.RiskScore < tr.MinRiskScore {
			tr.MinRiskScore = req.RiskScore
		}
	}

computeResults:

	// Compute averages
	totalLatency := 0.0
	totalRisk := 0
	for _, req := range tr.Requests {
		totalLatency += req.LatencyMs
		totalRisk += req.RiskScore
	}
	if len(tr.Requests) > 0 {
		tr.AvgLatencyMs = totalLatency / float64(len(tr.Requests))
		tr.AvgRiskScore = float64(totalRisk) / float64(len(tr.Requests))
	}
	tr.RiskBaseline = tr.MinRiskScore
	tr.RiskDelta = tr.MaxRiskScore - tr.MinRiskScore
	tr.InterventionPoint = tr.BlockedAt

	// ── F6: Action Persistence Check (§5.2) ──
	// After WAF starts blocking, check for flip-flop violations:
	//   - Escalation OK: 429→403
	//   - De-escalation FAIL: 403→429
	//   - Flip-flop FAIL: 429/403→200
	//   - BA04/RE02 exception: only 429→429 accepted
	firstBlockIdx := -1
	firstBlockAction := ""
	for i, req := range tr.Requests {
		if req.Blocked && firstBlockIdx < 0 {
			firstBlockIdx = i
			firstBlockAction = req.WAFAction
			continue
		}
		if firstBlockIdx >= 0 && i > firstBlockIdx {
			prevBlocked := tr.Requests[i-1].Blocked
			prevStatus := tr.Requests[i-1].StatusCode

			// De-escalation: 403→429
			if prevBlocked && prevStatus == 403 && req.StatusCode == 429 {
				tr.DeEscalationDetected = true
			}
			// Flip-flop: blocked→200 (allow)
			if prevBlocked && !req.Blocked && req.StatusCode == 200 {
				tr.F6Violation = true
			}
			// Escalation: 429→403 (OK)
			if prevStatus == 429 && req.StatusCode == 403 {
				tr.EscalationDetected = true
			}
		}
	}

	// BA04/RE02: Rate-limit maintenance — after first 429, ALL subsequent must be 429
	if bt.ID == "BA04" || bt.ID == "RE02" {
		first429Idx := -1
		tr.RateLimitMaintained = true
		for i, req := range tr.Requests {
			if req.StatusCode == 429 && first429Idx < 0 {
				first429Idx = i
				continue
			}
			if first429Idx >= 0 && i > first429Idx {
				if req.StatusCode != 429 {
					tr.RateLimitMaintained = false
					break
				}
			}
		}
		if first429Idx < 0 {
			tr.RateLimitMaintained = false // No 429 at all
		}
	}

	// Build F6 details summary
	if tr.F6Violation {
		tr.F6Details = "Flip-flop detected: block→allow"
		tr.FailConditions = append(tr.FailConditions, "F6")
	} else if tr.DeEscalationDetected && bt.ID != "BA04" && bt.ID != "RE02" {
		tr.F6Details = "De-escalation detected: 403→429"
		tr.FailConditions = append(tr.FailConditions, "F6")
	} else if tr.EscalationDetected && !tr.F6Violation {
		tr.F6Details = "Escalation OK: 429→403"
	} else if firstBlockIdx >= 0 {
		tr.F6Details = fmt.Sprintf("Consistent %s from req %d", firstBlockAction, firstBlockIdx+1)
	}
	if bt.ID == "BA04" || bt.ID == "RE02" {
		if tr.RateLimitMaintained {
			tr.F6Details = "429 maintained throughout burst"
		} else {
			tr.F6Details = "Rate-limit not maintained"
			tr.FailConditions = append(tr.FailConditions, "F6")
		}
	}

	// ── Action Persistence Summary (§7.1) ──
	tr.FirstBlockAt = firstBlockIdx + 1
	if tr.FirstBlockAt <= 0 {
		tr.FirstBlockAt = 0
	}
	tr.ActionSequenceSummary = e.buildActionSummary(&tr)

	// ── Risk Score Progression (§7.1) — sample key points ──
	tr.RiskProgression = e.buildRiskProgression(&tr)

	// ── Observability (§7.1 + Phụ lục A) — count WAF header presence ──
	tr.Observability = e.computeObservability(&tr)

	tr.Passed = e.evaluateResult(bt, &tr)
	if !tr.Passed {
		tr.FailReason = e.failReason(bt, &tr)
	}

	// ── P6: Mandatory Challenge Lifecycle Check (BA01/BA02) — v2.9 ──
	// If WAF issued a 429 challenge for BA01/BA02, the challenge lifecycle MUST pass.
	// This is mandatory — not optional enhancement.
	if bt.ID == "BA01" || bt.ID == "BA02" {
		challengeEncountered, challengePassed, lr := e.getChallengeLifecycle(bt.ID)
		if challengeEncountered {
			tr.ChallengeResult = e.buildChallengeSummary(challengeEncountered, challengePassed, lr)
			if !challengePassed {
				tr.Passed = false
				tr.FailReason = fmt.Sprintf("P6: Challenge lifecycle FAIL — mandatory for %s", bt.ID)
				tr.PassConditions = append(tr.PassConditions, "P6")
				tr.FailConditions = append(tr.FailConditions, "P6")
			} else {
				tr.PassConditions = append(tr.PassConditions, "P6")
			}
		}
	} else {
		// For non-BA01/BA02 tests: still record challenge if encountered
		challengeEncountered, challengePassed, lr := e.getChallengeLifecycle(bt.ID)
		if challengeEncountered {
			tr.ChallengeResult = e.buildChallengeSummary(challengeEncountered, challengePassed, lr)
		}
	}

	// Negative control result tracking (AR01, AR06)
	if bt.NegativeControl {
		actualStatus := 0
		actualAction := "allow"
		for _, req := range tr.Requests {
			actualStatus = req.StatusCode
			actualAction = req.WAFAction
			break
		}
		tr.NegControlResult = &NegControlResult{
			ExpectedAction: "allow",
			ActualAction:   actualAction,
			ExpectedStatus: 200,
			ActualStatus:   actualStatus,
			FalsePositive:  !tr.Passed,
			RiskExpected:   0,
			RiskActual:     tr.MaxRiskScore,
		}
	}

	// RE04 canary test
	if bt.ID == "RE04" {
		canaryEndpoints := []string{"/admin-test", "/api-debug", "/.env", "/wp-admin"}
		results := make(map[string]int)
		allBlocked := true
		for _, ep := range canaryEndpoints {
			r := e.doRequest("GET", ep, "", nil, bt.ID, bt.SourceIP)
			results[ep] = r.StatusCode
			if r.StatusCode != 403 {
				allBlocked = false
			}
		}
		followUp := e.doRequest("GET", "/game/list", "", nil, bt.ID, bt.SourceIP)
		tr.CanaryResult = &CanaryResult{
			Endpoints:      canaryEndpoints,
			Results:        results,
			AllBlocked:     allBlocked,
			FollowUpBlocked: followUp.StatusCode == 403,
		}
		tr.Passed = allBlocked && tr.CanaryResult.FollowUpBlocked
		if !tr.Passed {
			tr.FailReason = "Canaries not fully blocked or IP not locked"
		}
	}

	// RE01 L05 marker check: __L05_VERBOSE_404__ in 404 responses
	if bt.ID == "RE01" {
		hasL05 := false
		for _, req := range tr.Requests {
			if strings.Contains(req.ResponseBody, "__L05_VERBOSE_404__") {
				hasL05 = true
				tr.LeakMarkers = append(tr.LeakMarkers, "__L05_VERBOSE_404__")
				break
			}
		}
		if hasL05 {
			tr.Passed = false
			tr.FailReason = "L05 verbose 404 markers present"
		}
	}

	// RE03 leak marker check
	if bt.ID == "RE03" {
		hasLeak := false
		for _, req := range tr.Requests {
			if strings.Contains(req.ResponseBody, "__L01_STACKTRACE__") {
				hasLeak = true
				tr.LeakMarkers = append(tr.LeakMarkers, "__L01_STACKTRACE__")
				break
			}
		}
		if hasLeak {
			tr.Passed = false
			tr.FailReason = "Stack traces still present"
		}
	}

	return tr
}

// ── Simulator ──

func (e *BEngine) simulateRun() *PhaseBResult {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	now := time.Now()

	result := &PhaseBResult{
		StartTime: now,
		WAFTarget: e.cfg.WAFBaseURL,
		WAFMode:   "enforce",
		Scores:    make(map[string]float64),
	}

	result.PreCheckAlive = 5
	result.PreCheckTotal = 5
	result.PreCheckPassed = true
	result.ResetSteps = e.simulateResetSteps()
	result.ResetAllPassed = true

	allTests := GetBTests(e.wafURL)
	categoryOrder := []string{"brute_force", "relay", "behavioral", "transaction", "recon"}

	var previousCat string
	var currentCatTests []BTestResult
	needsReset := true
	resetType := "UPSTREAM+WAF (Full Reset Sequence)"

	for i, bt := range allTests {
		if i > 0 && bt.Category != previousCat {
			e.logReset(previousCat, bt.Category)
			needsReset = true
			resetType = "UPSTREAM+WAF"
			result = e.buildCategoryResult(result, previousCat, currentCatTests, 0)
			currentCatTests = nil
		}
		tr := e.simulateTest(&bt, rng)
		if needsReset {
			tr.ResetBefore = true
			tr.ResetType = resetType
			needsReset = false
		}
		currentCatTests = append(currentCatTests, tr)
		result.TestResults = append(result.TestResults, tr)
		previousCat = bt.Category
	}
	result = e.buildCategoryResult(result, previousCat, currentCatTests, 0)
	result = e.reorderCategories(result, categoryOrder)
	computeScores(result)
	result.EndTime = now.Add(5 * time.Second)
	return result
}

func (e *BEngine) simulateResetSteps() []BResetStep {
	// v2.6 order per §3.1
	return []BResetStep{
		{StepNum: 1, Name: "Set WAF profile (enforce)", Method: "POST", StatusCode: 200, Success: true, LatencyMs: 12.0},
		{StepNum: 2, Name: "Flush WAF cache", Method: "POST", StatusCode: 200, Success: true, LatencyMs: 18.0},
		{StepNum: 3, Name: "Reset UPSTREAM", Method: "POST", StatusCode: 200, Success: true, LatencyMs: 25.0},
		{StepNum: 4, Name: "UPSTREAM health check", Method: "GET", StatusCode: 200, Success: true, LatencyMs: 8.0},
		{StepNum: 5, Name: "Reset WAF state", Method: "POST", StatusCode: 200, Success: true, LatencyMs: 15.0},
	}
}

func (e *BEngine) logReset(fromCat, toCat string) {
	if e.cfg.Verbose {
		fmt.Printf("  [RESET] UPSTREAM + WAF state: %s → %s\n", fromCat, toCat)
	}
}

func (e *BEngine) buildCategoryResult(result *PhaseBResult, catID string, tests []BTestResult, startIdx int) *PhaseBResult {
	cat, ok := BCategories[catID]
	if !ok {
		return result
	}
	cr := BCategoryResult{
		CatID: catID, Name: cat.Name, Criterion: cat.Criterion,
		MaxScore: cat.MaxScore, Denominator: cat.Denominator,
		IPRange: cat.IPRange, TotalCount: len(tests),
	}
	for _, tr := range tests {
		cr.Tests = append(cr.Tests, tr)
		if tr.Passed {
			cr.PassedCount++
		}
	}
	result.Categories = append(result.Categories, cr)
	return result
}

func (e *BEngine) reorderCategories(result *PhaseBResult, order []string) *PhaseBResult {
	ordered := make([]BCategoryResult, 0, len(result.Categories))
	for _, catID := range order {
		for _, cat := range result.Categories {
			if cat.CatID == catID {
				ordered = append(ordered, cat)
				break
			}
		}
	}
	result.Categories = ordered
	return result
}

func (e *BEngine) simulateTest(bt *BTest, rng *rand.Rand) BTestResult {
	tr := BTestResult{
		TestID: bt.ID, Name: bt.Name, Category: bt.Category,
		Criterion: bt.Criterion, SourceIP: bt.SourceIP,
		Method: bt.Method, Endpoint: bt.Endpoint,
		Description: bt.Description, PassCriterion: bt.PassCriterion,
		NegativeControl: bt.NegativeControl, AbuseType: bt.AbuseType,
		ReproduceScript: bt.ReproduceScript,
	}
	// Simulate auth for tests that need it
	if bt.AuthUser != "" || bt.SessionRequired {
		tr.AuthUsed = true
		if bt.ID == "TF04" {
			tr.SessionID = "multi (5 users)"
		} else {
			tr.SessionID = "sim-session-" + bt.ID
		}
	}
	totalReqs := bt.RequestCount
	if totalReqs == 0 {
		totalReqs = 1
	}
	tr.TotalRequests = totalReqs
	tr.BlockedAt = -1
	tr.MinLatencyMs = 999.0
	baseLatency := 1.0 + rng.Float64()*4.0

	for i := 0; i < totalReqs && i < 200; i++ {
		latency := baseLatency + rng.Float64()*3.0 + float64(i)*0.1
		riskScore := rng.Intn(20)
		statusCode := 200

		switch bt.AbuseType {
		case "brute":
			if i >= 8+rng.Intn(5) {
				statusCode = 403
				riskScore = 70 + rng.Intn(30)
				if tr.BlockedAt < 0 {
					tr.BlockedAt = i + 1
				}
			} else {
				riskScore = i * 3
			}
		case "credential_stuffing":
			if i >= 15+rng.Intn(8) {
				statusCode = 403
				riskScore = 65 + rng.Intn(35)
				if tr.BlockedAt < 0 {
					tr.BlockedAt = i + 1
				}
			} else {
				riskScore = i * 2
			}
		case "spray":
			if i >= 10+rng.Intn(6) {
				statusCode = 403
				riskScore = 60 + rng.Intn(40)
				if tr.BlockedAt < 0 {
					tr.BlockedAt = i + 1
				}
			} else {
				riskScore = i * 3
			}
		case "relay":
			if bt.NegativeControl {
				statusCode = 200
				riskScore = 0
			} else {
				riskScore = 15 + rng.Intn(20)
			}
		case "proxy":
			riskScore = 25 + rng.Intn(45)
		case "bot":
			if bt.ID == "BA01" {
				statusCode = 403
				riskScore = 40 + rng.Intn(40)
			} else if bt.ID == "BA04" {
				riskScore = 20 + rng.Intn(30)
			} else {
				if i >= 8 {
					statusCode = 429
					riskScore = 50 + rng.Intn(30)
				} else {
					riskScore = i * 5
				}
			}
		case "fraud":
			if bt.ID == "TF01" || bt.ID == "TF03" {
				statusCode = 403
				riskScore = 55 + rng.Intn(45)
			} else if bt.ID == "TF04" {
				if i >= 3 {
					statusCode = 403
					riskScore = 60 + rng.Intn(40)
				} else {
					riskScore = i * 10
				}
			} else {
				riskScore = 10 + rng.Intn(20)
				statusCode = 200
			}
		case "recon":
			if bt.ID == "RE01" {
				if i >= 38 {
					statusCode = 403
					riskScore = 65 + rng.Intn(35)
					if tr.BlockedAt < 0 {
						tr.BlockedAt = i + 1
					}
				} else {
					riskScore = i / 2
				}
			} else if bt.ID == "RE02" {
				if i >= 5 {
					statusCode = 429
					riskScore = 40 + rng.Intn(25)
				}
			} else if bt.ID == "RE03" {
				statusCode = 200
				riskScore = 5 + rng.Intn(10)
			} else if bt.ID == "RE04" {
				statusCode = 403
				riskScore = 75 + rng.Intn(25)
			}
		case "canary":
			statusCode = 403
			riskScore = 80 + rng.Intn(20)
		}

		simBody := "{}"
		if statusCode == 200 {
			simBody = `{"status":"ok"}`
		} else {
			simBody = `{"status":"blocked"}`
		}
		req := BRequestResult{
			Index: i + 1, URL: e.cfg.WAFBaseURL + bt.Endpoint,
			Method: bt.Method, StatusCode: statusCode,
			LatencyMs: latency, RiskScore: riskScore,
			Blocked: statusCode == 403 || statusCode == 429,
			ResponseBody: simBody,
			WAFAction: map[bool]string{true: "block", false: "allow"}[statusCode == 403],
			ResponseHeaders: map[string]string{
				"X-Waf-Request-Id": fmt.Sprintf("req-%s-%03d", strings.ToLower(bt.ID), i+1),
				"X-Waf-Risk-Score": fmt.Sprintf("%d", riskScore),
				"X-Waf-Action":     map[bool]string{true: "block", false: "allow"}[statusCode == 403],
				"X-Waf-Rule-Id":    fmt.Sprintf("%s-001", bt.ID),
				"X-Waf-Cache":      "BYPASS",
				"X-Waf-Mode":       "enforce",
			},
		}
		if bt.BodyTemplate != "" {
			req.RequestBody = fmt.Sprintf(bt.BodyTemplate, i+1)
			req.RequestHeaders = map[string]string{"Content-Type": bt.ContentType}
			req.CurlCommand = fmt.Sprintf("curl -X %s '%s' -H 'Content-Type: %s' -d '%s' --interface %s",
				bt.Method, req.URL, bt.ContentType, req.RequestBody, bt.SourceIP)
		} else {
			req.CurlCommand = fmt.Sprintf("curl -X %s '%s' --interface %s",
				bt.Method, req.URL, bt.SourceIP)
		}

		// Append to global response pool for SEC-02 (cross_phase.md §3)
		if e.pool != nil {
			e.pool.Append("B", bt.ID, bt.SourceIP, bt.Endpoint, bt.Method,
				req.StatusCode, req.ResponseBody, req.ResponseHeaders)
		}

		tr.Requests = append(tr.Requests, req)
		if latency < tr.MinLatencyMs {
			tr.MinLatencyMs = latency
		}
		if latency > tr.MaxLatencyMs {
			tr.MaxLatencyMs = latency
		}
		if riskScore > tr.MaxRiskScore {
			tr.MaxRiskScore = riskScore
		}
		if riskScore < tr.MinRiskScore {
			tr.MinRiskScore = riskScore
		}
	}

	totalLatency := 0.0
	totalRisk := 0
	for _, req := range tr.Requests {
		totalLatency += req.LatencyMs
		totalRisk += req.RiskScore
	}
	if len(tr.Requests) > 0 {
		tr.AvgLatencyMs = totalLatency / float64(len(tr.Requests))
		tr.AvgRiskScore = float64(totalRisk) / float64(len(tr.Requests))
	}
	tr.RiskBaseline = tr.MinRiskScore
	tr.RiskDelta = tr.MaxRiskScore - tr.MinRiskScore
	tr.InterventionPoint = tr.BlockedAt
	tr.Passed = e.evaluateResult(bt, &tr)
	if !tr.Passed {
		tr.FailReason = e.failReason(bt, &tr)
	}

	// Populate F6/persistence fields for dry-run (simulate consistent behavior)
	if tr.BlockedAt > 0 {
		tr.F6Details = fmt.Sprintf("Consistent block from req %d (simulated)", tr.BlockedAt)
	}
	// Negative control result for AR01/AR06
	if bt.NegativeControl {
		actualStatus := 200
		if !tr.Passed {
			actualStatus = 403
		}
		tr.NegControlResult = &NegControlResult{
			ExpectedAction: "allow",
			ActualAction:   map[bool]string{true: "allow", false: "block"}[tr.Passed],
			ExpectedStatus: 200,
			ActualStatus:   actualStatus,
			FalsePositive:  !tr.Passed,
			RiskExpected:   0,
			RiskActual:     tr.MaxRiskScore,
		}
	}
	// Rate-limit maintenance for BA04/RE02 (simulated)
	if bt.ID == "BA04" || bt.ID == "RE02" {
		tr.RateLimitMaintained = tr.Passed // In dry-run, pass implies maintained
		if tr.RateLimitMaintained {
			tr.F6Details = "429 maintained throughout burst (simulated)"
		}
	}
	// Risk progression (sample key points from simulated requests)
	tr.RiskProgression = e.buildRiskProgression(&tr)
	// Action sequence summary
	tr.ActionSequenceSummary = e.buildActionSummary(&tr)
	// Observability
	tr.Observability = e.computeObservability(&tr)
	if bt.ID == "RE04" {
		tr.CanaryResult = &CanaryResult{
			Endpoints:      []string{"/admin-test", "/api-debug", "/.env", "/wp-admin"},
			Results:        map[string]int{"/admin-test": 403, "/api-debug": 403, "/.env": 403, "/wp-admin": 403},
			AllBlocked:     true,
			FollowUpBlocked: true,
		}
	}
	if bt.ID == "RE03" && !tr.Passed {
		tr.LeakMarkers = []string{"__L01_STACKTRACE__"}
	}
	return tr
}

// ── P6: Challenge Lifecycle Check (v2.9) ──

// getChallengeLifecycle checks the solver's accumulated results for the given testID.
// Returns (challengeEncountered, challengePassed, lifecycleResult).
func (e *BEngine) getChallengeLifecycle(testID string) (bool, bool, *challenge.LifecycleResult) {
	if e.challengeSolver == nil {
		return false, true, nil
	}
	for i := range e.challengeSolver.Results {
		if e.challengeSolver.Results[i].TestID == testID {
			return true, e.challengeSolver.Results[i].OverallPassed, &e.challengeSolver.Results[i]
		}
	}
	return false, true, nil // No challenge encountered — not a failure
}

// buildChallengeSummary converts a challenge.LifecycleResult into a ChallengeLifecycleSummary.
func (e *BEngine) buildChallengeSummary(encountered, passed bool, lr *challenge.LifecycleResult) *ChallengeLifecycleSummary {
	if !encountered || lr == nil {
		return &ChallengeLifecycleSummary{Encountered: false, Passed: true}
	}
	format := ""
	token := ""
	submitURL := ""
	if lr.SolveResult != nil && lr.SolveResult.ChallengeInfo != nil {
		format = lr.SolveResult.ChallengeInfo.Format
		token = lr.SolveResult.ChallengeInfo.ChallengeToken
		submitURL = lr.SolveResult.ChallengeInfo.SubmitURL
	}
	return &ChallengeLifecycleSummary{
		Encountered:      true,
		Passed:           passed,
		Format:           format,
		ChallengeToken:   token,
		SubmitURL:        submitURL,
		SubmitPassed:     lr.SubmitPassed,
		SessionExtracted: lr.NewSessionExtracted,
		AccessRestored:   lr.AccessRestored,
		SessionSuspended: lr.SessionSuspensionPassed,
		FailCodes:        lr.FailCodes,
		DurationMs:       lr.DurationMs,
	}
}

func (e *BEngine) failReason(bt *BTest, tr *BTestResult) string {
	switch bt.AbuseType {
	case "brute", "credential_stuffing", "spray":
		return fmt.Sprintf("Not detected — no block within %d attempts", tr.TotalRequests)
	case "relay", "proxy":
		if bt.NegativeControl {
			return "Negative control blocked — false positive"
		}
		return "Risk score not elevated"
	case "bot":
		switch bt.ID {
		case "BA01":
			return "Zero-depth session not flagged (risk <= 30)"
		case "BA02":
			return fmt.Sprintf("Uniform timing not detected — no block within %d requests", tr.TotalRequests)
		case "BA03":
			return "Missing Referer not detected (risk delta = 0)"
		case "BA04":
			return "Rapid cadence not detected — no block or risk elevation"
		case "BA05":
			return "Spoofed Referer not flagged (risk = 0)"
		default:
			return "Bot behavior not detected"
		}
	case "fraud":
		switch bt.ID {
		case "TF01":
			return "Rush deposit not detected (risk < 50, not blocked)"
		case "TF02":
			return "Instant withdrawal not flagged (risk < 50, not blocked)"
		case "TF03":
			return "Limit change + large withdrawal not detected (risk < 50, not blocked)"
		case "TF04":
			return "Multi-accounting not detected (risk < 50, not blocked)"
		default:
			return "Fraud pattern not detected"
		}
	case "recon":
		switch bt.ID {
		case "RE01":
			return "WAF did not block enumeration"
		case "RE02":
			return "Not rate-limited"
		case "RE03":
			return "Stack traces still present"
		default:
			return "Canaries not fully blocked"
		}
	}
	return "Test failed"
}

func (e *BEngine) evaluateResult(bt *BTest, tr *BTestResult) bool {
	// Negative controls: must NOT be blocked
	if tr.NegativeControl {
		for _, req := range tr.Requests {
			if req.Blocked {
				tr.FailConditions = append(tr.FailConditions, "F3")
				tr.PassConditions = append(tr.PassConditions, "P1")
				return false
			}
		}
		tr.PassConditions = append(tr.PassConditions, "P1", "P5")
		return true
	}

	// F6: Action persistence violation causes automatic FAIL
	if tr.F6Violation {
		tr.FailConditions = append(tr.FailConditions, "F6")
		return false
	}
	switch bt.AbuseType {
	case "brute", "credential_stuffing", "spray":
		threshold := 10
		if bt.AbuseType == "credential_stuffing" {
			threshold = 20
		} else if bt.AbuseType == "spray" {
			threshold = 15
		}
		result := tr.BlockedAt > 0 && tr.BlockedAt <= threshold
		if result {
			tr.PassConditions = append(tr.PassConditions, "P3")
		} else {
			tr.FailConditions = append(tr.FailConditions, "F4")
		}
		// De-escalation is also F6 for brute-force tests
		if tr.DeEscalationDetected {
			tr.FailConditions = append(tr.FailConditions, "F6")
			return false
		}
		return result
	case "relay", "proxy":
		result := tr.MaxRiskScore > 0
		if result {
			tr.PassConditions = append(tr.PassConditions, "P4")
		} else {
			tr.FailConditions = append(tr.FailConditions, "F5")
		}
		return result
	case "bot":
		switch bt.ID {
		case "BA01":
			result := tr.MaxRiskScore > 30
			if result {
				tr.PassConditions = append(tr.PassConditions, "P4")
			} else {
				tr.FailConditions = append(tr.FailConditions, "F5")
			}
			return result
		case "BA02":
			result := tr.BlockedAt > 0 && tr.BlockedAt <= 60
			if result {
				tr.PassConditions = append(tr.PassConditions, "P3")
			} else {
				tr.FailConditions = append(tr.FailConditions, "F4")
			}
			if tr.DeEscalationDetected {
				tr.FailConditions = append(tr.FailConditions, "F6")
				return false
			}
			return result
		case "BA03":
			result := tr.RiskDelta > 0
			if result {
				tr.PassConditions = append(tr.PassConditions, "P4")
			} else {
				tr.FailConditions = append(tr.FailConditions, "F5")
			}
			return result
		case "BA04":
			// BA04: rate-limit maintenance is REQUIRED (429→429 only)
			if !tr.RateLimitMaintained && tr.BlockedAt > 0 {
				tr.FailConditions = append(tr.FailConditions, "F6")
				return false
			}
			result := tr.BlockedAt > 0 || tr.MaxRiskScore >= 40
			if result {
				tr.PassConditions = append(tr.PassConditions, "P4")
			} else {
				tr.FailConditions = append(tr.FailConditions, "F5")
			}
			return result
		case "BA05":
			result := tr.MaxRiskScore > 0
			if result {
				tr.PassConditions = append(tr.PassConditions, "P4")
			} else {
				tr.FailConditions = append(tr.FailConditions, "F5")
			}
			return result
		}
		return tr.MaxRiskScore >= 40
	case "fraud":
		// TF01: 3× rush deposit → Risk >= 50 or blocked
		if bt.ID == "TF01" {
			result := tr.MaxRiskScore >= 50 || tr.BlockedAt > 0
			if result {
				tr.PassConditions = append(tr.PassConditions, "P4")
			} else {
				tr.FailConditions = append(tr.FailConditions, "F5")
			}
			return result
		}
		// TF02: deposit → withdrawal in <3s → Risk >= 50 or blocked
		if bt.ID == "TF02" {
			result := tr.MaxRiskScore >= 50 || tr.BlockedAt > 0
			if result {
				tr.PassConditions = append(tr.PassConditions, "P4")
			} else {
				tr.FailConditions = append(tr.FailConditions, "F5")
			}
			return result
		}
		// TF03: limit change → large withdrawal → Risk >= 50 or blocked
		if bt.ID == "TF03" {
			result := tr.MaxRiskScore >= 50 || tr.BlockedAt > 0
			if result {
				tr.PassConditions = append(tr.PassConditions, "P4")
			} else {
				tr.FailConditions = append(tr.FailConditions, "F5")
			}
			return result
		}
		// TF04: 5 users login+deposit from same IP → Risk >= 50 or blocked
		if bt.ID == "TF04" {
			result := tr.MaxRiskScore >= 50 || tr.BlockedAt > 0
			if result {
				tr.PassConditions = append(tr.PassConditions, "P4")
			} else {
				tr.FailConditions = append(tr.FailConditions, "F5")
			}
			return result
		}
		return tr.MaxRiskScore >= 30
	case "recon":
		if bt.ID == "RE01" {
			result := tr.BlockedAt > 0 && tr.BlockedAt <= 50
			if result {
				tr.PassConditions = append(tr.PassConditions, "P3")
			} else {
				tr.FailConditions = append(tr.FailConditions, "F4")
			}
			return result
		}
		if bt.ID == "RE02" {
			// RE02: rate-limit maintenance is REQUIRED (429→429 only)
			if !tr.RateLimitMaintained && tr.BlockedAt > 0 {
				tr.FailConditions = append(tr.FailConditions, "F6")
				return false
			}
			for _, req := range tr.Requests {
				if req.StatusCode == 429 {
					tr.PassConditions = append(tr.PassConditions, "P3")
					return true
				}
			}
			tr.FailConditions = append(tr.FailConditions, "F4")
			return false
		}
		if bt.ID == "RE03" {
			result := len(tr.LeakMarkers) == 0
			if result {
				tr.PassConditions = append(tr.PassConditions, "P4")
			} else {
				tr.FailConditions = append(tr.FailConditions, "F5")
			}
			return result
		}
	case "canary":
		result := tr.MaxRiskScore >= 70
		if result {
			tr.PassConditions = append(tr.PassConditions, "P4")
		} else {
			tr.FailConditions = append(tr.FailConditions, "F5")
		}
		return result
	}
	return tr.MaxRiskScore > 0
}

// ── Helper: buildActionSummary builds action_sequence_summary per §7.1 ──

func (e *BEngine) buildActionSummary(tr *BTestResult) string {
	if len(tr.Requests) == 0 {
		return ""
	}
	var segments []string
	start := 1
	prevAction := ""
	prevBlocked := false
	for i, req := range tr.Requests {
		action := req.WAFAction
		if action == "" {
			if req.Blocked {
				action = "block"
			} else {
				action = "allow"
			}
		}
		currentBlocked := req.Blocked || action == "challenge" || action == "rate_limit"
		if i == 0 {
			prevAction = action
			prevBlocked = currentBlocked
			continue
		}
		if action != prevAction || currentBlocked != prevBlocked {
			segments = append(segments, fmt.Sprintf("%s(%d-%d)", prevAction, start, i))
			start = i + 1
			prevAction = action
			prevBlocked = currentBlocked
		}
	}
	// Last segment
	if len(tr.Requests) > 0 && prevAction != "" {
		segments = append(segments, fmt.Sprintf("%s(%d-%d)", prevAction, start, len(tr.Requests)))
	}
	return strings.Join(segments, ", ")
}

// ── Helper: buildRiskProgression samples risk score at key request indices ──

func (e *BEngine) buildRiskProgression(tr *BTestResult) []RiskProgressionPoint {
	if len(tr.Requests) == 0 {
		return nil
	}
	total := len(tr.Requests)
	// Sample up to 7 points: first, ~25%, ~50%, blocked point, ~75%, last
	indices := []int{1}
	if total >= 4 {
		indices = append(indices, total/4)
	}
	if total >= 2 {
		indices = append(indices, total/2)
	}
	if tr.BlockedAt > 0 && tr.BlockedAt <= total {
		indices = append(indices, tr.BlockedAt)
	}
	if total >= 4 {
		indices = append(indices, 3*total/4)
	}
	indices = append(indices, total)

	// Deduplicate and sort
	seen := map[int]bool{}
	var deduped []int
	for _, idx := range indices {
		if idx < 1 {
			idx = 1
		}
		if idx > total {
			idx = total
		}
		if !seen[idx] {
			seen[idx] = true
			deduped = append(deduped, idx)
		}
	}

	var points []RiskProgressionPoint
	for _, idx := range deduped {
		score := tr.Requests[idx-1].RiskScore
		points = append(points, RiskProgressionPoint{Request: idx, Score: score})
	}
	return points
}

// ── Helper: computeObservability checks presence of 6 WAF headers ──

var wafObservabilityHeaders = []string{
	"X-Waf-Request-Id", "X-Waf-Risk-Score", "X-Waf-Action",
	"X-Waf-Rule-Id", "X-Waf-Cache", "X-Waf-Mode",
}

func (e *BEngine) computeObservability(tr *BTestResult) ObservabilityResult {
	headerCount := map[string]int{}
	total := len(tr.Requests)
	for _, req := range tr.Requests {
		for _, h := range wafObservabilityHeaders {
			if _, ok := req.ResponseHeaders[h]; ok {
				headerCount[h]++
			}
		}
	}
	var used, missing []string
	for _, h := range wafObservabilityHeaders {
		if total > 0 && headerCount[h] >= total*95/100 {
			used = append(used, h)
		} else {
			missing = append(missing, h)
		}
	}
	score := 0.0
	if len(wafObservabilityHeaders) > 0 {
		score = float64(len(used)) / float64(len(wafObservabilityHeaders))
	}
	return ObservabilityResult{
		HeadersUsed:    used,
		HeadersMissing: missing,
		Score:          score,
	}
}

// ── Scoring (§6) ──

func computeScores(result *PhaseBResult) {
	var passAB, passRE, passAR, passBA, passTF int
	var skipAB, skipRE, skipAR, skipBA, skipTF int
	var passCanary bool
	var skipCanary bool

	for _, tr := range result.TestResults {
		if tr.Skipped {
			switch tr.Category {
			case "brute_force":
				skipAB++
			case "relay":
				skipAR++
			case "behavioral":
				skipBA++
			case "transaction":
				skipTF++
			case "recon":
				if tr.Criterion == "SEC-03" {
					skipRE++
				} else if tr.Criterion == "SEC-04" {
					skipCanary = true
				}
			}
			continue
		}
		if !tr.Passed {
			continue
		}
		switch tr.Category {
		case "brute_force":
			passAB++
		case "relay":
			passAR++
		case "behavioral":
			passBA++
		case "transaction":
			passTF++
		case "recon":
			if tr.Criterion == "SEC-03" {
				passRE++
			} else if tr.Criterion == "SEC-04" {
				passCanary = true
			}
		}
	}

	// v2.6 Dynamic denominators: denominator decreases when tests are skipped
	// SEC-03 = 10 × (pass_AB + pass_RE) / (6 - skip_AB - skip_RE)
	denomSEC03 := 6 - skipAB - skipRE
	if denomSEC03 < 1 {
		denomSEC03 = 1
	}
	result.Scores["SEC-03"] = 10.0 * float64(passAB+passRE) / float64(denomSEC03)

	// SEC-04 = 2 × pass_canary / (1 - skip_canary)
	if skipCanary {
		result.Scores["SEC-04"] = 0.0 // Canary skipped entirely
	} else if passCanary {
		result.Scores["SEC-04"] = 2.0
	} else {
		result.Scores["SEC-04"] = 0.0
	}

	// INT-01 = 4 × pass_TF / (4 - skip_TF)
	denomTF := 4 - skipTF
	if denomTF < 1 {
		denomTF = 1
	}
	result.Scores["INT-01"] = 4.0 * float64(passTF) / float64(denomTF)

	// INT-02 = 4 × pass_BA / (5 - skip_BA)
	denomBA := 5 - skipBA
	if denomBA < 1 {
		denomBA = 1
	}
	result.Scores["INT-02"] = 4.0 * float64(passBA) / float64(denomBA)

	// INT-03 = 4 × pass_AR / (4 - skip_AR)  (v2.9: AR04/AR05 removed → 4 tests: AR01-AR03, AR06)
	denomAR := 4 - skipAR
	if denomAR < 1 {
		denomAR = 1
	}
	result.Scores["INT-03"] = 4.0 * float64(passAR) / float64(denomAR)

	result.TotalScore = 0
	for _, s := range result.Scores {
		result.TotalScore += s
	}
	result.MaxScore = 24.0
	for i := range result.Categories {
		cat := &result.Categories[i]
		switch cat.CatID {
		case "relay":
			cat.Score = result.Scores["INT-03"]
		case "behavioral":
			cat.Score = result.Scores["INT-02"]
		case "transaction":
			cat.Score = result.Scores["INT-01"]
		}
	}
}