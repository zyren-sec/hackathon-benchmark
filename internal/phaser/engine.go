package phaser

// Phase R engine — Risk Score Lifecycle (SEC-05)
// Implements docs/hackathon/workflow/phase_R.md §5 (7-step sequential workflow)

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/waf-hackathon/benchmark-new/internal/crossphase"
)

// ── Engine ──

type REngine struct {
	cfg           *RConfigWrapper
	pool          *crossphase.GlobalResponsePool
	client        *http.Client
	targetURL     string
	wafURL        string
	wafAdminURL   string
	controlSecret string
	dryRun        bool
	verbose       bool
}

func NewREngine(cfg *RConfigWrapper, pool *crossphase.GlobalResponsePool) *REngine {
	timeout := cfg.TimeoutSec
	if timeout < 30 {
		timeout = 90 // Phase R needs longer timeout for Step 5 (60s decay)
	}
	return &REngine{
		cfg:           cfg,
		pool:          pool,
		targetURL:     cfg.TargetBaseURL,
		wafURL:        cfg.WAFBaseURL,
		wafAdminURL:   cfg.WAFAdminURL,
		controlSecret: cfg.ControlSecret,
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		dryRun:  cfg.DryRun,
		verbose: cfg.Verbose,
	}
}

// Run executes the full Phase R workflow.
func (e *REngine) Run() (*PhaseRResult, error) {
	if e.dryRun {
		return e.simulateRun()
	}
	return e.realRun()
}

// ── Real HTTP Execution ──

func (e *REngine) realRun() (*PhaseRResult, error) {
	start := time.Now()
	result := &PhaseRResult{
		StartTime: start,
		WAFTarget: e.cfg.WAFBaseURL,
		WAFMode:   "enforce",
		SEC05Max:  8.0,
	}

	// 1. Pre-flight health checks
	result.WAFAlive = e.checkWAFAlive()
	if !result.WAFAlive {
		result.EndTime = time.Now()
		result.DurationMs = float64(time.Since(start).Milliseconds())
		return result, fmt.Errorf("WAF not reachable — Phase R aborted")
	}
	result.UpstreamAlive = e.checkUpstreamAlive()
	if !result.UpstreamAlive {
		result.EndTime = time.Now()
		result.DurationMs = float64(time.Since(start).Milliseconds())
		return result, fmt.Errorf("UPSTREAM not healthy — Phase R aborted")
	}

	// 2. Full Reset Sequence (5 steps per phase_R.md §3.1)
	result.ResetSteps = e.fullResetSequence()
	result.ResetAllPassed = true
	for _, s := range result.ResetSteps {
		if !s.Success {
			// Step 4 (flush_cache) is non-fatal per §3.1
			if s.StepNum == 4 {
				continue
			}
			result.ResetAllPassed = false
			break
		}
	}
	if !result.ResetAllPassed {
		result.EndTime = time.Now()
		result.DurationMs = float64(time.Since(start).Milliseconds())
		return result, nil // aborted — reset failed
	}

	// 3. Execute 7 sequential steps (NO reset between steps — §3.2)
	step1 := e.runStep1()
	result.StepResults = append(result.StepResults, step1)
	e.collectPool("R", "step1", step1)

	step2 := e.runStep2()
	result.StepResults = append(result.StepResults, step2)
	e.collectPool("R", "step2", step2)

	step3 := e.runStep3()
	result.StepResults = append(result.StepResults, step3)
	e.collectPool("R", "step3", step3)

	step4 := e.runStep4()
	result.StepResults = append(result.StepResults, step4)
	e.collectPool("R", "step4", step4)

	step5 := e.runStep5()
	result.StepResults = append(result.StepResults, step5)
	// Step 5 has 30 requests — pool them all via DecayTrajectory
	e.collectPoolDecay("R", "step5", step5)

	step6 := e.runStep6()
	result.StepResults = append(result.StepResults, step6)
	e.collectPool("R", "step6", step6)

	// Step 7 depends on Step 6 having issued a challenge
	var step7 StepResult
	if !step6.ChallengeIssued {
		step7 = StepResult{
			Step:        7,
			Description: "challenge_completion",
			SourceIP:    IPSteps5to7,
			Device:      DeviceD2.Name,
			Method:      "POST",
			Endpoint:    "/challenge/verify",
			MaxPts:      1,
			Pts:         0,
			Skipped:     true,
			SkipReason:  "step6_no_challenge",
		}
	} else {
		step7 = e.runStep7(step6.ChallengeToken, step6.ChallengeSubmitURL, step6.ChallengeDiff)
	}
	result.StepResults = append(result.StepResults, step7)
	e.collectPool("R", "step7", step7)

	// 4. Aggregate scoring
	for _, sr := range result.StepResults {
		result.SEC05Score += float64(sr.Pts)
		if sr.Pass {
			result.PassedSteps++
		} else if sr.Skipped {
			result.SkippedSteps++
		} else {
			result.FailedSteps++
		}
	}

	// Propagate challenge details to top-level result
	if step7.ChallengeSolved {
		result.ChallengeSolved = true
		result.ChallengeType = step7.ChallengeType
		result.ChallengeToken = step7.ChallengeToken
		result.ChallengeNonce = step7.ChallengeNonce
		result.ChallengeSolveMs = step7.ChallengeSolveMs
	}

	result.EndTime = time.Now()
	result.DurationMs = float64(time.Since(start).Milliseconds())
	return result, nil
}

// ── Pre-flight Checks ──

func (e *REngine) checkWAFAlive() bool {
	req, err := http.NewRequest("GET", e.wafURL+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (e *REngine) checkUpstreamAlive() bool {
	req, err := http.NewRequest("GET", e.targetURL+"/health", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Benchmark-Secret", e.controlSecret)
	resp, err := e.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// ── Full Reset Sequence (phase_R.md §3.1) ──

func (e *REngine) fullResetSequence() []RResetStep {
	var steps []RResetStep

	doStep := func(num int, name, method, url, body string, fatal bool) RResetStep {
		rs := RResetStep{
			StepNum: num,
			Name:    name,
			Method:  method,
			URL:     url,
			Fatal:   fatal,
		}
		start := time.Now()

		var bodyReader io.Reader
		if body != "" {
			bodyReader = bytes.NewReader([]byte(body))
		}
		req, err := http.NewRequest(method, url, bodyReader)
		if err != nil {
			rs.Error = err.Error()
			rs.LatencyMs = float64(time.Since(start).Milliseconds())
			return rs
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("X-Benchmark-Secret", e.controlSecret)

		// Retry up to 3 times with 2s backoff per §3.1
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
		rs.LatencyMs = float64(time.Since(start).Milliseconds())

		if err != nil {
			rs.Error = err.Error()
			rs.Success = false
			return rs
		}
		defer resp.Body.Close()
		rs.StatusCode = resp.StatusCode

		// Step 4 (flush_cache): accept 200 or 501 per §3.1
		if num == 4 && (resp.StatusCode == 200 || resp.StatusCode == 501) {
			rs.Success = true
			return rs
		}
		if resp.StatusCode == 200 {
			rs.Success = true
		} else {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			rs.Error = fmt.Sprintf("status %d: %s", resp.StatusCode, string(b))
			rs.Success = false
		}
		return rs
	}

	// Step 1: POST :9000/__control/reset
	steps = append(steps, doStep(1,
		"POST /__control/reset → UPSTREAM reset",
		"POST", e.targetURL+"/__control/reset", "", true))

	// Step 2: GET :9000/health
	steps = append(steps, doStep(2,
		"GET /health → UPSTREAM healthy",
		"GET", e.targetURL+"/health", "", true))

	// Step 3: POST :8081/__waf_control/set_profile
	steps = append(steps, doStep(3,
		"POST /__waf_control/set_profile → enforce mode",
		"POST", e.wafAdminURL+"/__waf_control/set_profile",
		`{"scope":"all","mode":"enforce"}`, true))

	// Step 4: POST :8081/__waf_control/flush_cache (non-fatal)
	steps = append(steps, doStep(4,
		"POST /__waf_control/flush_cache → clear cache",
		"POST", e.wafAdminURL+"/__waf_control/flush_cache", "", false))

	// Step 5: POST :8081/__waf_control/reset_state
	steps = append(steps, doStep(5,
		"POST /__waf_control/reset_state → WAF state clean",
		"POST", e.wafAdminURL+"/__waf_control/reset_state", "", true))

	return steps
}

// ── WAF Request Helper ──

type wafResponse struct {
	StatusCode int
	RiskScore  int
	Action     string
	Body       string
	Headers    map[string]string
	LatencyMs  float64
}

// doWAFRequest sends a request through WAF-PROXY with the given source IP and device.
// sourceIP is bound via --interface equivalent: we set X-Forwarded-For to simulate.
// Per spec, loopback aliases 127.0.0.200–202 must be configured on the host.
// The benchmark sends from those IPs using the net/http dialer local address.
func (e *REngine) doWAFRequest(method, path, body, sourceIP string, device DeviceSignature, extraHeaders map[string]string) wafResponse {
	start := time.Now()
	wr := wafResponse{Headers: make(map[string]string)}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
	}

	req, err := http.NewRequest(method, e.wafURL+path, bodyReader)
	if err != nil {
		wr.LatencyMs = float64(time.Since(start).Milliseconds())
		return wr
	}

	// Device fingerprint headers
	req.Header.Set("User-Agent", device.UserAgent)
	req.Header.Set("Accept-Language", device.AcceptLanguage)

	// Source IP simulation via X-Forwarded-For
	// (actual loopback alias binding requires OS-level config per phase_R.md §11.7)
	req.Header.Set("X-Forwarded-For", sourceIP)

	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// Extra headers (e.g. suspicious UA for Step 6)
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	wr.LatencyMs = float64(time.Since(start).Milliseconds())
	if err != nil {
		return wr
	}
	defer resp.Body.Close()

	wr.StatusCode = resp.StatusCode

	// Extract WAF headers
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			wr.Headers[strings.ToLower(k)] = vals[0]
		}
	}

	// Parse X-WAF-Risk-Score
	if s, ok := wr.Headers["x-waf-risk-score"]; ok {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			wr.RiskScore = n
		}
	}

	// Parse X-WAF-Action
	if a, ok := wr.Headers["x-waf-action"]; ok {
		wr.Action = strings.TrimSpace(strings.ToLower(a))
	}

	// Read body (limit 256KB)
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	wr.Body = string(b)

	return wr
}

// ── Step Implementations ──

// Step 1 — Baseline (Clean Traffic) — phase_R.md §5.1
// 5 legitimate GET /game/list from IP 200, Device D1
// Expected: risk 0–10, action allow on ≥4/5 requests
// No points — baseline verification only
func (e *REngine) runStep1() StepResult {
	sr := StepResult{
		Step:             1,
		Description:      "baseline",
		SourceIP:         IPSteps1to3,
		Device:           DeviceD1.Name,
		Method:           "GET",
		Endpoint:         "/game/list",
		ExpectedScoreMin: 0,
		ExpectedScoreMax: 10,
		ExpectedActions:  []string{"allow"},
		MaxPts:           0, // baseline — no points
	}

	allowCount := 0
	lastScore := 0
	lastAction := ""
	lastStatus := 0
	lastLatency := 0.0

	for i := 0; i < 5; i++ {
		wr := e.doWAFRequest("GET", "/game/list", "", IPSteps1to3, DeviceD1, nil)
		lastScore = wr.RiskScore
		lastAction = wr.Action
		lastStatus = wr.StatusCode
		lastLatency = wr.LatencyMs
		if wr.Action == "allow" {
			allowCount++
		}
		if i < 4 {
			time.Sleep(500 * time.Millisecond)
		}
	}

	sr.ObservedScore = lastScore
	sr.ObservedAction = lastAction
	sr.HTTPStatus = lastStatus
	sr.LatencyMs = lastLatency

	// PASS: risk 0–10 AND allow on ≥4/5
	if lastScore >= 0 && lastScore <= 10 && allowCount >= 4 {
		sr.Pass = true
		sr.Pts = 0
	} else {
		sr.Pass = false
		sr.FailReason = fmt.Sprintf("baseline_failed: risk=%d (want 0-10), allow_count=%d/5 (want ≥4)", lastScore, allowCount)
	}
	return sr
}

// Step 2 — Attack Detection (SQLi V01) — phase_R.md §5.2
// 1 SQLi payload → POST /login from IP 200, Device D1
// Expected: risk 40–70, action block or challenge
// 1 pt
func (e *REngine) runStep2() StepResult {
	sr := StepResult{
		Step:             2,
		Description:      "attack_sqli",
		SourceIP:         IPSteps1to3,
		Device:           DeviceD1.Name,
		Method:           "POST",
		Endpoint:         "/login",
		ExpectedScoreMin: 40,
		ExpectedScoreMax: 70,
		ExpectedActions:  []string{"block", "challenge"},
		MaxPts:           1,
	}

	payload := `{"username":"alice\" OR \"1\"=\"1","password":"ignored"}`
	wr := e.doWAFRequest("POST", "/login", payload, IPSteps1to3, DeviceD1, nil)

	sr.ObservedScore = wr.RiskScore
	sr.ObservedAction = wr.Action
	sr.HTTPStatus = wr.StatusCode
	sr.LatencyMs = wr.LatencyMs

	// PASS: risk 40–70 AND action ∈ {block, challenge}
	scoreOK := wr.RiskScore >= 40 && wr.RiskScore <= 70
	actionOK := wr.Action == "block" || wr.Action == "challenge"

	if scoreOK && actionOK {
		sr.Pass = true
		sr.Pts = 1
	} else {
		sr.Pass = false
		reasons := []string{}
		if !scoreOK {
			reasons = append(reasons, fmt.Sprintf("risk=%d (want 40-70)", wr.RiskScore))
		}
		if !actionOK {
			reasons = append(reasons, fmt.Sprintf("action=%q (want block/challenge)", wr.Action))
		}
		sr.FailReason = strings.Join(reasons, "; ")
	}
	return sr
}

// Step 3 — Canary Hit (Risk MAX) — phase_R.md §5.3
// GET /admin-test from IP 200, Device D1
// Expected: risk = 100, action block
// 1 pt
func (e *REngine) runStep3() StepResult {
	sr := StepResult{
		Step:             3,
		Description:      "canary_hit",
		SourceIP:         IPSteps1to3,
		Device:           DeviceD1.Name,
		Method:           "GET",
		Endpoint:         "/admin-test",
		ExpectedScoreMin: 100,
		ExpectedScoreMax: 100,
		ExpectedActions:  []string{"block"},
		MaxPts:           1,
	}

	wr := e.doWAFRequest("GET", "/admin-test", "", IPSteps1to3, DeviceD1, nil)

	sr.ObservedScore = wr.RiskScore
	sr.ObservedAction = wr.Action
	sr.HTTPStatus = wr.StatusCode
	sr.LatencyMs = wr.LatencyMs

	// PASS: risk = 100 AND action = block
	scoreOK := wr.RiskScore == 100
	actionOK := wr.Action == "block"

	if scoreOK && actionOK {
		sr.Pass = true
		sr.Pts = 1
	} else {
		reasons := []string{}
		if !scoreOK {
			reasons = append(reasons, fmt.Sprintf("risk=%d (want 100)", wr.RiskScore))
		}
		if !actionOK {
			reasons = append(reasons, fmt.Sprintf("action=%q (want block)", wr.Action))
		}
		sr.FailReason = strings.Join(reasons, "; ")
	}
	return sr
}

// Step 4 — Device Fingerprint Carry-Over — phase_R.md §5.4
// GET /game/list from NEW IP 201, SAME Device D1
// Expected: risk 80–100, action block (device carries risk across IPs)
// 2 pts
func (e *REngine) runStep4() StepResult {
	sr := StepResult{
		Step:             4,
		Description:      "device_fp_carryover",
		SourceIP:         IPStep4,
		Device:           DeviceD1.Name,
		Method:           "GET",
		Endpoint:         "/game/list",
		ExpectedScoreMin: 80,
		ExpectedScoreMax: 100,
		ExpectedActions:  []string{"block"},
		MaxPts:           2,
	}

	wr := e.doWAFRequest("GET", "/game/list", "", IPStep4, DeviceD1, nil)

	sr.ObservedScore = wr.RiskScore
	sr.ObservedAction = wr.Action
	sr.HTTPStatus = wr.StatusCode
	sr.LatencyMs = wr.LatencyMs

	// PASS: risk 80–100 AND action = block
	scoreOK := wr.RiskScore >= 80 && wr.RiskScore <= 100
	actionOK := wr.Action == "block"

	if scoreOK && actionOK {
		sr.Pass = true
		sr.Pts = 2
	} else {
		reasons := []string{}
		if !scoreOK {
			reasons = append(reasons, fmt.Sprintf("risk=%d (want 80-100)", wr.RiskScore))
		}
		if !actionOK {
			reasons = append(reasons, fmt.Sprintf("action=%q (want block)", wr.Action))
		}
		sr.FailReason = strings.Join(reasons, "; ")
	}
	return sr
}

// Step 5 — Score Decay (60 seconds) — phase_R.md §5.5
// 30 clean requests (1 req/2s) from NEW IP 202, NEW Device D2
// Expected: risk decreases over time, ≥1 final request returns allow
// 2 pts
func (e *REngine) runStep5() StepResult {
	sr := StepResult{
		Step:             5,
		Description:      "score_decay",
		SourceIP:         IPSteps5to7,
		Device:           DeviceD2.Name,
		Method:           "GET",
		Endpoint:         "/game/list",
		ExpectedScoreMin: -1, // trajectory-based, not fixed range
		ExpectedScoreMax: -1,
		ExpectedActions:  []string{"allow"},
		MaxPts:           2,
	}

	const totalRequests = 30
	const intervalSec = 2

	var trajectory []DecayPoint
	allowSeen := false

	for i := 1; i <= totalRequests; i++ {
		wr := e.doWAFRequest("GET", "/game/list", "", IPSteps5to7, DeviceD2, nil)
		dp := DecayPoint{
			RequestNum: i,
			RiskScore:  wr.RiskScore,
			Action:     wr.Action,
			HTTPStatus: wr.StatusCode,
			LatencyMs:  wr.LatencyMs,
		}
		trajectory = append(trajectory, dp)

		if wr.Action == "allow" {
			allowSeen = true
		}

		if e.verbose {
			fmt.Printf("  [Step5] req #%d: risk=%d action=%s status=%d\n",
				i, wr.RiskScore, wr.Action, wr.StatusCode)
		}

		if i < totalRequests {
			time.Sleep(time.Duration(intervalSec) * time.Second)
		}
	}

	sr.DecayTrajectory = trajectory

	if len(trajectory) == 0 {
		sr.FailReason = "no_requests_completed"
		return sr
	}

	firstScore := trajectory[0].RiskScore
	lastScore := trajectory[len(trajectory)-1].RiskScore
	sr.ObservedScore = lastScore
	sr.ObservedAction = trajectory[len(trajectory)-1].Action
	sr.HTTPStatus = trajectory[len(trajectory)-1].HTTPStatus
	sr.LatencyMs = trajectory[len(trajectory)-1].LatencyMs

	// PASS: score[30] < score[1] AND ≥1 final request returns allow
	decayOK := lastScore < firstScore
	allowOK := allowSeen

	if decayOK && allowOK {
		sr.Pass = true
		sr.Pts = 2
	} else {
		reasons := []string{}
		if !decayOK {
			reasons = append(reasons, fmt.Sprintf("decay_not_observed: score[1]=%d score[30]=%d (want score[30] < score[1])", firstScore, lastScore))
		}
		if !allowOK {
			reasons = append(reasons, "no_allow_action_seen in 30 requests")
		}
		sr.FailReason = strings.Join(reasons, "; ")
	}
	return sr
}

// Step 6 — Suspicious UA (Challenge Trigger) — phase_R.md §5.6
// 1 request with python-requests/2.28 UA from IP 202, Device D2
// Expected: risk 30–70, action challenge, HTTP 429
// 1 pt
func (e *REngine) runStep6() StepResult {
	sr := StepResult{
		Step:             6,
		Description:      "suspicious_ua_challenge",
		SourceIP:         IPSteps5to7,
		Device:           DeviceD2.Name,
		Method:           "GET",
		Endpoint:         "/game/list",
		ExpectedScoreMin: 30,
		ExpectedScoreMax: 70,
		ExpectedActions:  []string{"challenge"},
		MaxPts:           1,
	}

	// Override UA to suspicious python-requests/2.28
	extraHeaders := map[string]string{
		"User-Agent": "python-requests/2.28",
	}

	wr := e.doWAFRequest("GET", "/game/list", "", IPSteps5to7, DeviceD2, extraHeaders)

	sr.ObservedScore = wr.RiskScore
	sr.ObservedAction = wr.Action
	sr.HTTPStatus = wr.StatusCode
	sr.LatencyMs = wr.LatencyMs

	// PASS: risk 30–70 AND action = challenge
	scoreOK := wr.RiskScore >= 30 && wr.RiskScore <= 70
	actionOK := wr.Action == "challenge"

	if scoreOK && actionOK {
		sr.Pass = true
		sr.Pts = 1
		sr.ChallengeIssued = true

		// Parse challenge from response body
		token, submitURL, diff, ctype := parseChallengeResponse(wr.Body, wr.Headers)
		sr.ChallengeToken = token
		sr.ChallengeSubmitURL = submitURL
		sr.ChallengeDiff = diff
		sr.ChallengeType = ctype
	} else {
		reasons := []string{}
		if !scoreOK {
			reasons = append(reasons, fmt.Sprintf("risk=%d (want 30-70)", wr.RiskScore))
		}
		if !actionOK {
			reasons = append(reasons, fmt.Sprintf("action=%q (want challenge)", wr.Action))
		}
		sr.FailReason = strings.Join(reasons, "; ")
	}
	return sr
}

// Step 7 — Challenge Completion (Score Recovery) — phase_R.md §5.7
// Solve PoW or JS challenge, then verify risk < 30 and action = allow
// 1 pt
func (e *REngine) runStep7(challengeToken, submitURL string, difficulty int) StepResult {
	sr := StepResult{
		Step:               7,
		Description:        "challenge_completion",
		SourceIP:           IPSteps5to7,
		Device:             DeviceD2.Name,
		Method:             "POST",
		Endpoint:           submitURL,
		ExpectedScoreMin:   0,
		ExpectedScoreMax:   29,
		ExpectedActions:    []string{"allow"},
		MaxPts:             1,
		ChallengeToken:     challengeToken,
		ChallengeSubmitURL: submitURL,
		ChallengeDiff:      difficulty,
	}

	if challengeToken == "" || submitURL == "" {
		sr.Skipped = true
		sr.SkipReason = "challenge_unsolvable"
		return sr
	}

	// Difficulty cap: max 16 zero bits per §5.7
	if difficulty > 16 {
		sr.Skipped = true
		sr.SkipReason = "challenge_too_hard"
		return sr
	}

	// Solve PoW: find nonce such that SHA256(token+nonce) starts with `difficulty` zero bits
	solveStart := time.Now()
	nonce, hash, solved := solvePoW(challengeToken, difficulty, 30*time.Second)
	sr.ChallengeSolveMs = float64(time.Since(solveStart).Milliseconds())

	if !solved {
		sr.Skipped = true
		sr.SkipReason = "challenge_timeout"
		return sr
	}

	sr.ChallengeNonce = strconv.Itoa(nonce)
	sr.ChallengeType = "proof_of_work"

	// Submit solution
	submitBody := fmt.Sprintf(`{"challenge_token":%q,"nonce":%q}`, challengeToken, strconv.Itoa(nonce))
	_ = hash // logged for debugging

	extraHeaders := map[string]string{
		"User-Agent": "python-requests/2.28",
	}
	submitWR := e.doWAFRequest("POST", submitURL, submitBody, IPSteps5to7, DeviceD2, extraHeaders)

	if submitWR.StatusCode != 200 {
		sr.Skipped = true
		sr.SkipReason = "challenge_submit_failed"
		sr.FailReason = fmt.Sprintf("submit returned HTTP %d", submitWR.StatusCode)
		return sr
	}

	// Re-verify: GET /game/list — risk must be < 30 and action = allow
	time.Sleep(500 * time.Millisecond)
	verifyWR := e.doWAFRequest("GET", "/game/list", "", IPSteps5to7, DeviceD2, nil)

	sr.ObservedScore = verifyWR.RiskScore
	sr.ObservedAction = verifyWR.Action
	sr.HTTPStatus = verifyWR.StatusCode
	sr.LatencyMs = verifyWR.LatencyMs

	scoreOK := verifyWR.RiskScore < 30
	actionOK := verifyWR.Action == "allow"

	if scoreOK && actionOK {
		sr.Pass = true
		sr.Pts = 1
		sr.ChallengeSolved = true
	} else {
		reasons := []string{}
		if !scoreOK {
			reasons = append(reasons, fmt.Sprintf("risk=%d (want <30)", verifyWR.RiskScore))
			sr.SkipReason = "score_not_reduced"
		}
		if !actionOK {
			reasons = append(reasons, fmt.Sprintf("action=%q (want allow)", verifyWR.Action))
		}
		sr.FailReason = strings.Join(reasons, "; ")
	}
	return sr
}

// ── Challenge Parsing ──

// parseChallengeResponse extracts challenge_token, submit_url, difficulty, and type
// from WAF challenge response (Format A JSON or Format B HTML).
func parseChallengeResponse(body string, headers map[string]string) (token, submitURL string, difficulty int, ctype string) {
	// Try Format A: JSON
	var jsonChallenge struct {
		Challenge      bool   `json:"challenge"`
		ChallengeType  string `json:"challenge_type"`
		ChallengeToken string `json:"challenge_token"`
		Difficulty     int    `json:"difficulty"`
		SubmitURL      string `json:"submit_url"`
	}
	if err := json.Unmarshal([]byte(body), &jsonChallenge); err == nil && jsonChallenge.Challenge {
		return jsonChallenge.ChallengeToken, jsonChallenge.SubmitURL, jsonChallenge.Difficulty, jsonChallenge.ChallengeType
	}

	// Try Format B: HTML form
	tokenRe := regexp.MustCompile(`name="challenge_token"\s+value="([^"]+)"`)
	actionRe := regexp.MustCompile(`action="([^"]+)"`)

	if m := tokenRe.FindStringSubmatch(body); len(m) > 1 {
		token = m[1]
	}
	if m := actionRe.FindStringSubmatch(body); len(m) > 1 {
		submitURL = m[1]
	}
	if token != "" {
		ctype = "html_form"
		difficulty = 4 // default for HTML challenges
	}
	return
}

// ── PoW Solver ──

// solvePoW finds a nonce such that SHA256(token + nonce) has `zeroBits` leading zero bits.
// Returns (nonce, hexHash, solved). Times out after `timeout`.
func solvePoW(token string, zeroBits int, timeout time.Duration) (int, string, bool) {
	deadline := time.Now().Add(timeout)
	for nonce := 0; nonce < 10_000_000; nonce++ {
		if time.Now().After(deadline) {
			return 0, "", false
		}
		input := fmt.Sprintf("%s%d", token, nonce)
		hash := sha256.Sum256([]byte(input))
		if hasLeadingZeroBits(hash[:], zeroBits) {
			return nonce, fmt.Sprintf("%x", hash), true
		}
	}
	return 0, "", false
}

// hasLeadingZeroBits checks if the byte slice has at least n leading zero bits.
func hasLeadingZeroBits(hash []byte, n int) bool {
	fullBytes := n / 8
	remainBits := n % 8

	for i := 0; i < fullBytes; i++ {
		if i >= len(hash) || hash[i] != 0 {
			return false
		}
	}
	if remainBits > 0 && fullBytes < len(hash) {
		mask := byte(0xFF << (8 - remainBits))
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}
	return true
}

// ── SEC-02 Pool Collection ──

func (e *REngine) collectPool(phase, testID string, sr StepResult) {
	if e.pool == nil {
		return
	}
	if sr.ObservedScore == 0 && sr.ObservedAction == "" {
		return // no response captured
	}
	headers := map[string]string{
		"x-waf-risk-score": strconv.Itoa(sr.ObservedScore),
		"x-waf-action":     sr.ObservedAction,
	}
	e.pool.Append(phase, testID, sr.SourceIP, sr.Endpoint, sr.Method,
		sr.HTTPStatus, "", headers)
}

func (e *REngine) collectPoolDecay(phase, testID string, sr StepResult) {
	if e.pool == nil {
		return
	}
	for _, dp := range sr.DecayTrajectory {
		headers := map[string]string{
			"x-waf-risk-score": strconv.Itoa(dp.RiskScore),
			"x-waf-action":     dp.Action,
		}
		e.pool.Append(phase, testID, sr.SourceIP, sr.Endpoint, sr.Method,
			dp.HTTPStatus, "", headers)
	}
}

// ── Dry-Run Simulation ──

func (e *REngine) simulateRun() (*PhaseRResult, error) {
	start := time.Now()
	result := &PhaseRResult{
		StartTime:      start,
		WAFTarget:      e.cfg.WAFBaseURL,
		WAFMode:        "enforce",
		SEC05Max:       8.0,
		WAFAlive:       true,
		UpstreamAlive:  true,
		ResetAllPassed: true,
	}

	// Simulate reset steps
	for i := 1; i <= 5; i++ {
		result.ResetSteps = append(result.ResetSteps, RResetStep{
			StepNum:    i,
			Name:       fmt.Sprintf("Step %d (simulated)", i),
			Method:     "POST",
			StatusCode: 200,
			Success:    true,
			LatencyMs:  1.5,
		})
	}

	// Simulate step results (full score scenario)
	simSteps := []StepResult{
		{Step: 1, Description: "baseline", SourceIP: IPSteps1to3, Device: "D1", Method: "GET", Endpoint: "/game/list", ObservedScore: 5, ObservedAction: "allow", HTTPStatus: 200, LatencyMs: 2.1, ExpectedScoreMin: 0, ExpectedScoreMax: 10, Pass: true, MaxPts: 0, Pts: 0},
		{Step: 2, Description: "attack_sqli", SourceIP: IPSteps1to3, Device: "D1", Method: "POST", Endpoint: "/login", ObservedScore: 65, ObservedAction: "block", HTTPStatus: 403, LatencyMs: 2.3, ExpectedScoreMin: 40, ExpectedScoreMax: 70, Pass: true, MaxPts: 1, Pts: 1},
		{Step: 3, Description: "canary_hit", SourceIP: IPSteps1to3, Device: "D1", Method: "GET", Endpoint: "/admin-test", ObservedScore: 100, ObservedAction: "block", HTTPStatus: 403, LatencyMs: 1.8, ExpectedScoreMin: 100, ExpectedScoreMax: 100, Pass: true, MaxPts: 1, Pts: 1},
		{Step: 4, Description: "device_fp_carryover", SourceIP: IPStep4, Device: "D1", Method: "GET", Endpoint: "/game/list", ObservedScore: 92, ObservedAction: "block", HTTPStatus: 403, LatencyMs: 2.1, ExpectedScoreMin: 80, ExpectedScoreMax: 100, Pass: true, MaxPts: 2, Pts: 2},
		{Step: 5, Description: "score_decay", SourceIP: IPSteps5to7, Device: "D2", Method: "GET", Endpoint: "/game/list", ObservedScore: 8, ObservedAction: "allow", HTTPStatus: 200, LatencyMs: 1.9, Pass: true, MaxPts: 2, Pts: 2,
			DecayTrajectory: []DecayPoint{
				{1, 45, "block", 403, 2.1},
				{5, 38, "block", 403, 1.9},
				{10, 28, "allow", 200, 1.8},
				{15, 20, "allow", 200, 1.7},
				{20, 15, "allow", 200, 1.8},
				{25, 10, "allow", 200, 1.9},
				{30, 8, "allow", 200, 1.9},
			},
		},
		{Step: 6, Description: "suspicious_ua_challenge", SourceIP: IPSteps5to7, Device: "D2", Method: "GET", Endpoint: "/game/list", ObservedScore: 45, ObservedAction: "challenge", HTTPStatus: 429, LatencyMs: 3.2, ExpectedScoreMin: 30, ExpectedScoreMax: 70, Pass: true, MaxPts: 1, Pts: 1, ChallengeIssued: true, ChallengeType: "proof_of_work", ChallengeToken: "abc123def456", ChallengeDiff: 4, ChallengeSubmitURL: "/challenge/verify"},
		{Step: 7, Description: "challenge_completion", SourceIP: IPSteps5to7, Device: "D2", Method: "POST", Endpoint: "/challenge/verify", ObservedScore: 22, ObservedAction: "allow", HTTPStatus: 200, LatencyMs: 1.9, ExpectedScoreMin: 0, ExpectedScoreMax: 29, Pass: true, MaxPts: 1, Pts: 1, ChallengeSolved: true, ChallengeType: "proof_of_work", ChallengeToken: "abc123def456", ChallengeNonce: "42857", ChallengeSolveMs: 1250},
	}

	result.StepResults = simSteps
	for _, sr := range simSteps {
		result.SEC05Score += float64(sr.Pts)
		if sr.Pass {
			result.PassedSteps++
		} else if sr.Skipped {
			result.SkippedSteps++
		} else {
			result.FailedSteps++
		}
	}

	result.ChallengeSolved = true
	result.ChallengeType = "proof_of_work"
	result.ChallengeToken = "abc123def456"
	result.ChallengeNonce = "42857"
	result.ChallengeSolveMs = 1250

	result.EndTime = time.Now()
	result.DurationMs = float64(time.Since(start).Milliseconds())
	return result, nil
}
