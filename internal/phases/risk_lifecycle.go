package phases

import (
	"fmt"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/waf-hackathon/benchmark/internal/target"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

// RiskLifecycleResult contains results from the Risk Lifecycle test
// This implements Phase 9: 7-Step Risk Lifecycle Test
type RiskLifecycleResult struct {
	TotalScore   float64           `json:"total_score"`
	Steps        []LifecycleStep   `json:"steps,omitempty"`
	DurationMs   int64             `json:"duration_ms"`
	ObservedRisk []int             `json:"observed_risk_scores"`
	Passed       bool              `json:"passed"`
}

// LifecycleStep represents a single step in the risk lifecycle test
type LifecycleStep struct {
	StepNumber  int    `json:"step_number"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Passed      bool   `json:"passed"`
	RiskScore   int    `json:"risk_score"`
	Action      string `json:"action"`
	ExpectedRisk string `json:"expected_risk_range"`
	Error       string `json:"error,omitempty"`
}

// DeviceFingerprint represents a unique device identifier
type DeviceFingerprint struct {
	UserAgent        string
	AcceptEncoding   string
	AcceptLanguage   string
	ScreenResolution string
	Timezone         string
}

// RiskLifecycleTester performs the 7-step risk lifecycle test
type RiskLifecycleTester struct {
	wafClient    *waf.WAFClient
	targetClient *target.Client
	auth         *target.Auth
}

// NewRiskLifecycleTester creates a new risk lifecycle tester
func NewRiskLifecycleTester(wafClient *waf.WAFClient, targetClient *target.Client) *RiskLifecycleTester {
	return &RiskLifecycleTester{
		wafClient:    wafClient,
		targetClient: targetClient,
		auth:         target.NewAuth(targetClient),
	}
}

// RunRiskLifecycle executes the 7-step risk lifecycle test
// Returns detailed results for each step and overall score
func (rlt *RiskLifecycleTester) RunRiskLifecycle() (*RiskLifecycleResult, error) {
	start := time.Now()
	result := &RiskLifecycleResult{
		Steps:        make([]LifecycleStep, 0, 7),
		ObservedRisk: make([]int, 0),
	}

	// Device D1 fingerprint
	deviceD1 := rlt.generateDeviceFingerprint("D1")

	// Step 1: 5 legit requests from IP 127.0.0.200, device D1
	step1 := rlt.runStep1(deviceD1)
	result.Steps = append(result.Steps, step1)
	result.ObservedRisk = append(result.ObservedRisk, step1.RiskScore)

	// Step 2: 1 SQLi attempt from same IP/device
	step2 := rlt.runStep2(deviceD1)
	result.Steps = append(result.Steps, step2)
	result.ObservedRisk = append(result.ObservedRisk, step2.RiskScore)

	// Step 3: 1 canary hit from same IP/device
	step3 := rlt.runStep3(deviceD1)
	result.Steps = append(result.Steps, step3)
	result.ObservedRisk = append(result.ObservedRisk, step3.RiskScore)

	// Step 4: 1 legit request from new IP 127.0.0.201, same device D1
	step4 := rlt.runStep4(deviceD1)
	result.Steps = append(result.Steps, step4)
	result.ObservedRisk = append(result.ObservedRisk, step4.RiskScore)

	// Step 5: 30 legit requests over 60s from new IP 127.0.0.202, device D2
	deviceD2 := rlt.generateDeviceFingerprint("D2")
	step5 := rlt.runStep5(deviceD2)
	result.Steps = append(result.Steps, step5)
	result.ObservedRisk = append(result.ObservedRisk, step5.RiskScore)

	// Step 6: 1 request with unusual UA from same device D2
	step6 := rlt.runStep6(deviceD2)
	result.Steps = append(result.Steps, step6)
	result.ObservedRisk = append(result.ObservedRisk, step6.RiskScore)

	// Step 7: Solve challenge and submit (if challenged in step 6)
	step7 := rlt.runStep7(deviceD2, step6.Action)
	result.Steps = append(result.Steps, step7)
	result.ObservedRisk = append(result.ObservedRisk, step7.RiskScore)

	// Calculate total score
	result.TotalScore = rlt.calculateScore(result.Steps)
	result.DurationMs = time.Since(start).Milliseconds()
	result.Passed = rlt.allStepsPassed(result.Steps)

	return result, nil
}

// Step 1: 5 legit requests from IP 127.0.0.200, device D1
// Expected: risk 0-10, action=allow
func (rlt *RiskLifecycleTester) runStep1(device DeviceFingerprint) LifecycleStep {
	step := LifecycleStep{
		StepNumber:   1,
		Name:         "Baseline Legitimate Requests",
		Description:  "5 legit requests from IP 127.0.0.200, device D1",
		ExpectedRisk: "0-10",
	}

	sourceIP := "127.0.0.200"
	totalRisk := 0
	var lastAction string

	// Send 5 legitimate requests
	for i := 0; i < 5; i++ {
		req := rlt.buildLegitimateRequest("/", device)
		resp, err := rlt.wafClient.SendRequest(req, sourceIP)
		if err != nil {
			step.Error = fmt.Sprintf("request %d failed: %v", i+1, err)
			return step
		}
		totalRisk += resp.RiskScore
		lastAction = resp.Action
		time.Sleep(100 * time.Millisecond) // Small delay between requests
	}

	avgRisk := totalRisk / 5
	step.RiskScore = avgRisk
	step.Action = lastAction

	// Validate: risk should be 0-10, action=allow
	if avgRisk >= 0 && avgRisk <= 10 {
		if lastAction == "allow" || lastAction == "" {
			step.Passed = true
		}
	}

	return step
}

// Step 2: 1 SQLi attempt from same IP/device
// Expected: risk 40-70, action=block/challenge
func (rlt *RiskLifecycleTester) runStep2(device DeviceFingerprint) LifecycleStep {
	step := LifecycleStep{
		StepNumber:   2,
		Name:         "SQLi Attack Detection",
		Description:  "SQLi attempt from same IP/device",
		ExpectedRisk: "40-70",
	}

	sourceIP := "127.0.0.200"

	// SQLi payload
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(fmt.Sprintf("%s/login", rlt.wafClient.GetBaseURL()))
	req.Header.SetMethod("POST")
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.SetBodyString("username=' OR 1=1--&password=test")
	rlt.setDeviceHeaders(req, device)

	resp, err := rlt.wafClient.SendRequest(req, sourceIP)
	if err != nil {
		step.Error = fmt.Sprintf("request failed: %v", err)
		return step
	}

	step.RiskScore = resp.RiskScore
	step.Action = resp.Action

	// Validate: risk 40-70, action=block or challenge
	if resp.RiskScore >= 40 && resp.RiskScore <= 70 {
		if resp.Action == "block" || resp.Action == "challenge" || resp.Decision == waf.Block || resp.Decision == waf.Challenge {
			step.Passed = true
		}
	}

	return step
}

// Step 3: 1 canary hit from same IP/device
// Expected: risk 100, action=block
func (rlt *RiskLifecycleTester) runStep3(device DeviceFingerprint) LifecycleStep {
	step := LifecycleStep{
		StepNumber:   3,
		Name:         "Canary Endpoint Detection",
		Description:  "Canary endpoint hit from same IP/device",
		ExpectedRisk: "100",
	}

	sourceIP := "127.0.0.200"

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(fmt.Sprintf("%s/admin-test", rlt.wafClient.GetBaseURL()))
	req.Header.SetMethod("GET")
	rlt.setDeviceHeaders(req, device)

	resp, err := rlt.wafClient.SendRequest(req, sourceIP)
	if err != nil {
		step.Error = fmt.Sprintf("request failed: %v", err)
		return step
	}

	step.RiskScore = resp.RiskScore
	step.Action = resp.Action

	// Validate: risk 100, action=block
	if resp.RiskScore >= 90 && resp.RiskScore <= 100 {
		if resp.Action == "block" || resp.Decision == waf.Block {
			step.Passed = true
		}
	}

	return step
}

// Step 4: 1 legit request from new IP 127.0.0.201, same device D1
// Expected: risk 80-100 (device carry - high risk due to same device)
func (rlt *RiskLifecycleTester) runStep4(device DeviceFingerprint) LifecycleStep {
	step := LifecycleStep{
		StepNumber:   4,
		Name:         "Device Risk Carryover",
		Description:  "Legit request from new IP 127.0.0.201, same device D1",
		ExpectedRisk: "80-100",
	}

	sourceIP := "127.0.0.201"

	req := rlt.buildLegitimateRequest("/", device)
	resp, err := rlt.wafClient.SendRequest(req, sourceIP)
	if err != nil {
		step.Error = fmt.Sprintf("request failed: %v", err)
		return step
	}

	step.RiskScore = resp.RiskScore
	step.Action = resp.Action

	// Validate: risk 80-100 due to device carry
	if resp.RiskScore >= 80 && resp.RiskScore <= 100 {
		step.Passed = true
	}

	return step
}

// Step 5: 30 legit requests over 60s from new IP 127.0.0.202, device D2
// Expected: risk decaying (device reputation improves)
func (rlt *RiskLifecycleTester) runStep5(device DeviceFingerprint) LifecycleStep {
	step := LifecycleStep{
		StepNumber:   5,
		Name:         "Risk Decay Over Time",
		Description:  "30 legit requests over 60s from new IP/device",
		ExpectedRisk: "decaying",
	}

	sourceIP := "127.0.0.202"
	riskScores := make([]int, 0, 30)

	// Send 30 requests over 60 seconds (2 second interval)
	for i := 0; i < 30; i++ {
		req := rlt.buildLegitimateRequest("/", device)
		resp, err := rlt.wafClient.SendRequest(req, sourceIP)
		if err != nil {
			step.Error = fmt.Sprintf("request %d failed: %v", i+1, err)
			continue
		}
		riskScores = append(riskScores, resp.RiskScore)
		time.Sleep(2 * time.Second)
	}

	if len(riskScores) == 0 {
		step.Error = "no successful requests"
		return step
	}

	// Get final risk score
	finalRisk := riskScores[len(riskScores)-1]
	step.RiskScore = finalRisk

	// Calculate trend - should be decreasing or staying low
	firstRisk := riskScores[0]
	lastRisk := riskScores[len(riskScores)-1]

	// Risk should decay (decrease) or stay low after legitimate behavior
	if lastRisk < firstRisk || (firstRisk <= 20 && lastRisk <= 20) {
		step.Passed = true
	}

	step.ExpectedRisk = fmt.Sprintf("decaying (%d→%d)", firstRisk, lastRisk)

	return step
}

// Step 6: 1 request with unusual UA from same device D2
// Expected: risk 30-70, action=challenge
func (rlt *RiskLifecycleTester) runStep6(device DeviceFingerprint) LifecycleStep {
	step := LifecycleStep{
		StepNumber:   6,
		Name:         "Anomalous Device Behavior",
		Description:  "Request with unusual User-Agent from same device",
		ExpectedRisk: "30-70",
	}

	sourceIP := "127.0.0.202"

	// Unusual UA
	unusualDevice := DeviceFingerprint{
		UserAgent:      "SuspiciousBot/1.0 (Evil Scanner)",
		AcceptEncoding: device.AcceptEncoding,
		AcceptLanguage: device.AcceptLanguage,
	}

	req := rlt.buildLegitimateRequest("/", unusualDevice)
	resp, err := rlt.wafClient.SendRequest(req, sourceIP)
	if err != nil {
		step.Error = fmt.Sprintf("request failed: %v", err)
		return step
	}

	step.RiskScore = resp.RiskScore
	step.Action = resp.Action

	// Validate: risk 30-70, action=challenge or rate_limit
	if resp.RiskScore >= 30 && resp.RiskScore <= 70 {
		if resp.Action == "challenge" || resp.Action == "rate_limit" ||
			resp.Decision == waf.Challenge || resp.Decision == waf.RateLimit {
			step.Passed = true
		}
	}

	return step
}

// Step 7: Solve challenge and submit
// Expected: risk <30, action=allow
func (rlt *RiskLifecycleTester) runStep7(device DeviceFingerprint, previousAction string) LifecycleStep {
	step := LifecycleStep{
		StepNumber:   7,
		Name:         "Challenge Resolution",
		Description:  "Solve challenge and submit",
		ExpectedRisk: "<30",
	}

	sourceIP := "127.0.0.202"

	// If we weren't challenged in step 6, mark as passed but note it
	if previousAction != "challenge" && previousAction != "rate_limit" {
		step.Error = "no challenge to solve (previous action: " + previousAction + ")"
		// Still try a request to see if risk decreased
	}

	// Simulate solving challenge by waiting briefly and making legitimate request
	time.Sleep(500 * time.Millisecond)

	req := rlt.buildLegitimateRequest("/", device)
	resp, err := rlt.wafClient.SendRequest(req, sourceIP)
	if err != nil {
		step.Error = fmt.Sprintf("request failed: %v", err)
		return step
	}

	step.RiskScore = resp.RiskScore
	step.Action = resp.Action

	// Validate: risk <30, action=allow
	if resp.RiskScore < 30 {
		if resp.Action == "allow" || resp.Action == "" || resp.Decision == waf.Allow {
			step.Passed = true
		}
	}

	return step
}

// generateDeviceFingerprint creates a unique device fingerprint
func (rlt *RiskLifecycleTester) generateDeviceFingerprint(deviceID string) DeviceFingerprint {
	fingerprints := map[string]DeviceFingerprint{
		"D1": {
			UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
			AcceptEncoding: "gzip, deflate, br",
			AcceptLanguage: "en-US,en;q=0.9",
		},
		"D2": {
			UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
			AcceptEncoding: "gzip, deflate, br",
			AcceptLanguage: "en-GB,en;q=0.9",
		},
	}

	if fp, ok := fingerprints[deviceID]; ok {
		return fp
	}

	return fingerprints["D1"]
}

// buildLegitimateRequest creates a legitimate request with device fingerprint
func (rlt *RiskLifecycleTester) buildLegitimateRequest(path string, device DeviceFingerprint) *fasthttp.Request {
	req := fasthttp.AcquireRequest()
	req.SetRequestURI(fmt.Sprintf("%s%s", rlt.wafClient.GetBaseURL(), path))
	req.Header.SetMethod("GET")
	rlt.setDeviceHeaders(req, device)
	return req
}

// setDeviceHeaders sets headers that identify the device
func (rlt *RiskLifecycleTester) setDeviceHeaders(req *fasthttp.Request, device DeviceFingerprint) {
	if device.UserAgent != "" {
		req.Header.Set("User-Agent", device.UserAgent)
	}
	if device.AcceptEncoding != "" {
		req.Header.Set("Accept-Encoding", device.AcceptEncoding)
	}
	if device.AcceptLanguage != "" {
		req.Header.Set("Accept-Language", device.AcceptLanguage)
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
}

// calculateScore calculates the total score for the risk lifecycle test
// Step 7 is worth 2 points, others 1 point each (total 8 points)
func (rlt *RiskLifecycleTester) calculateScore(steps []LifecycleStep) float64 {
	if len(steps) == 0 {
		return 0
	}

	score := 0.0
	for i, step := range steps {
		if step.Passed {
			if i == 6 { // Step 7 (index 6) is worth 2 points
				score += 2.0
			} else {
				score += 1.0
			}
		}
	}

	return score
}

// allStepsPassed returns true if all steps passed
func (rlt *RiskLifecycleTester) allStepsPassed(steps []LifecycleStep) bool {
	for _, step := range steps {
		if !step.Passed {
			return false
		}
	}
	return len(steps) == 7
}

// Summary returns a human-readable summary of the risk lifecycle results
func (r *RiskLifecycleResult) Summary() string {
	passed := 0
	for _, step := range r.Steps {
		if step.Passed {
			passed++
		}
	}

	return fmt.Sprintf(
		"Risk Lifecycle Test - Duration: %dms, Steps: %d/%d passed, Score: %.1f/8",
		r.DurationMs,
		passed,
		len(r.Steps),
		r.TotalScore,
	)
}
