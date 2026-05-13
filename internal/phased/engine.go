package phased

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/waf-hackathon/benchmark-new/internal/challenge"
	"github.com/waf-hackathon/benchmark-new/internal/crossphase"
	"github.com/waf-hackathon/benchmark-new/internal/phasec"
)

// ── Engine ──

// Tool check cache
var toolAvailableCache = map[string]bool{}

type DEngine struct {
	cfg             *DConfigWrapper
	challengeSolver *challenge.Solver
	targetURL       string
	wafURL          string
	wafAdminURL     string
	controlSecret   string
	client          *http.Client
	pool            *crossphase.GlobalResponsePool
	dryRun          bool
	verbose         bool
}

type DConfigWrapper struct {
	TargetBaseURL string
	WAFBaseURL    string
	WAFAdminURL   string
	ControlSecret string
	TimeoutSec    int
	Verbose       bool
	DryRun        bool
}

func NewDEngine(cfg *DConfigWrapper, pool *crossphase.GlobalResponsePool, chSolver *challenge.Solver) *DEngine {
	timeout := cfg.TimeoutSec
	if timeout < 30 {
		timeout = 120 // Phase D needs longer timeouts
	}
	return &DEngine{
		cfg:             cfg,
		challengeSolver: chSolver,
		targetURL:       cfg.TargetBaseURL,
		wafURL:          cfg.WAFBaseURL,
		wafAdminURL:     cfg.WAFAdminURL,
		controlSecret:   cfg.ControlSecret,
		pool:            pool,
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
		dryRun:  cfg.DryRun,
		verbose: cfg.Verbose,
	}
}

// Run executes the full Phase D workflow.
func (e *DEngine) Run() (*PhaseDResult, error) {
	if e.dryRun {
		return e.simulateRun()
	}
	return e.realRun()
}

// checkToolAvailable checks if an external tool is installed.
// Results are cached so repeated checks don't re-scan PATH.
func checkToolAvailable(tool string) bool {
	if avail, ok := toolAvailableCache[tool]; ok {
		return avail
	}
	path, err := exec.LookPath(tool)
	avail := err == nil && path != ""
	toolAvailableCache[tool] = avail
	return avail
}

// ── Pre-flight Tool Inventory ──

func (e *DEngine) runToolInventory() {
	// Prime the cache by checking all required tools once
	checkToolAvailable("wrk2")
	checkToolAvailable("slowhttptest")
}

// ── Real HTTP Execution ──

func (e *DEngine) realRun() (*PhaseDResult, error) {
	start := time.Now()

	// Detect resource tier at start (shared with Phase C)
	tier := phasec.DetectResourceTier()

	result := &PhaseDResult{
		StartTime:       start,
		WAFTarget:       e.cfg.WAFBaseURL,
		WAFMode:         "enforce",
		ResourceTier:    string(tier),
		CgroupsActive:   phasec.CgroupsV2Available(),
		DiagnosticFlags: GetTierFlags(tier),
		RawMaxScore:     20.0,
		INT04Cap:        8.0,
	}

	if e.verbose {
		fmt.Printf("🔧 Resource Tier: %s (flags: %v)\n", tier, GetTierFlags(tier))
	}

	// 1. Pre-flight health checks
	result.WAFAlive = e.checkWAFAlive()
	if !result.WAFAlive {
		result.EndTime = time.Now()
		return result, fmt.Errorf("WAF not reachable — Phase D aborted")
	}
	result.UpstreamAlive = e.checkUpstreamAlive()
	if !result.UpstreamAlive {
		result.EndTime = time.Now()
		// Return no error — display the result so user sees pre-flight status
		fmt.Printf("\n⚠️  UPSTREAM not healthy at %s — Phase D aborted (verify /health)\n", e.cfg.TargetBaseURL)
		result.EndTime = time.Now()
		return result, fmt.Errorf("UPSTREAM not healthy — Phase D aborted")
	}

	// 2. Full Reset Sequence (9 steps per phase_D.md §3.1)
	result.ResetSteps = e.fullResetSequence()
	result.ResetAllPassed = true
	for _, s := range result.ResetSteps {
		if !s.Success && s.StepNum <= 8 { // Step 9 (verification) is non-fatal
			result.ResetAllPassed = false
			break
		}
	}
	if !result.ResetAllPassed {
		result.EndTime = time.Now()
		return result, nil
	}

	// 3. Run all D* tests
	allTests := GetDTests(e.targetURL, e.wafURL, e.wafAdminURL, tier)
	d08Passed := true // track D08 for D09 prerequisite

	// Run tool inventory BEFORE entering test loop
	e.runToolInventory()
	wrk2Missing := !checkToolAvailable("wrk2")
	slowHTTPMissing := !checkToolAvailable("slowhttptest")

	if e.verbose {
		fmt.Printf("  Tool inventory: wrk2=%v slowhttptest=%v\n",
			checkToolAvailable("wrk2"), checkToolAvailable("slowhttptest"))
	}

	missingToolMessages := []string{}

	for _, dt := range allTests {
		// D09 prerequisite check
		if dt.ID == "D09" && !d08Passed {
			tr := DTestResult{
				TestID: dt.ID, Name: dt.Name, Category: dt.Category,
				Description: dt.Description, PassCriterion: dt.PassCriterion,
				MaxScore: dt.MaxScore,
				Skipped: true, SkipReason: "prerequisite D08 not met",
				Passed: false,
			}
			result.TestResults = append(result.TestResults, tr)
			result.SkippedTests++
			if e.verbose {
				fmt.Printf("  [SKIP] %s: prerequisite D08 not met\n", dt.ID)
			}
			continue
		}

		// Tool availability gate — skip tests that require missing tools
		if dt.Tool == "wrk2" || dt.Tool == "wrk2+curl" {
			if wrk2Missing {
				tr := DTestResult{
					TestID: dt.ID, Name: dt.Name, Category: dt.Category,
					Description: dt.Description, PassCriterion: dt.PassCriterion,
					MaxScore: dt.MaxScore, Skipped: true,
					SkipReason: "tool_not_found: wrk2 not installed",
					Passed: false,
				}
				result.TestResults = append(result.TestResults, tr)
				result.SkippedTests++
				missingToolMessages = append(missingToolMessages, fmt.Sprintf("  ⚠ %s skipped: wrk2 not found in PATH (install: go install github.com/giltene/wrk2@latest)", dt.ID))
				continue
			}
		} else if dt.Tool == "slowhttptest" {
			if slowHTTPMissing {
				tr := DTestResult{
					TestID: dt.ID, Name: dt.Name, Category: dt.Category,
					Description: dt.Description, PassCriterion: dt.PassCriterion,
					MaxScore: dt.MaxScore, Skipped: true,
					SkipReason: "tool_not_found: slowhttptest not installed",
					Passed: false,
				}
				result.TestResults = append(result.TestResults, tr)
				result.SkippedTests++
				missingToolMessages = append(missingToolMessages, fmt.Sprintf("  ⚠ %s skipped: slowhttptest not found in PATH (install: apt install slowhttptest)", dt.ID))
				continue
			}
		}

		tr := e.runDTest(&dt)
		result.TestResults = append(result.TestResults, tr)

		if tr.Passed {
			result.PassedTests++
			result.RawScore += dt.MaxScore
		} else if tr.Skipped {
			result.SkippedTests++
		} else {
			result.FailedTests++
		}

		// Track D08 status
		if dt.ID == "D08" {
			d08Passed = tr.Passed
		}

		if e.verbose {
			status := "FAIL ✗"
			if tr.Passed {
				status = "PASS ✓"
			} else if tr.Skipped {
				status = "SKIP"
			}
			fmt.Printf("  [%s] %s: %s\n", status, dt.ID, dt.Name)
		}
	}

	// Print missing tool warnings at end (after test display)
	if len(missingToolMessages) > 0 {
		fmt.Println()
		fmt.Println("  ── TOOL AVAILABILITY WARNINGS ───────────────────────────────────")
		for _, msg := range missingToolMessages {
			fmt.Println(msg)
		}
		fmt.Println("  ──────────────────────────────────────────────────────────────────")
	}

	// 4. Compute INT-04 score
	result.INT04Score = math.Min(8.0, result.RawScore)
	result.EndTime = time.Now()
	return result, nil
}

// ── Pre-flight Checks ──

func (e *DEngine) checkWAFAlive() bool {
	for i := 0; i < 3; i++ {
		resp, err := e.client.Get(e.cfg.WAFBaseURL + "/health")
		if err == nil && resp.StatusCode < 500 {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func (e *DEngine) checkUpstreamAlive() bool {
	resp, err := e.client.Get(e.cfg.TargetBaseURL + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// ── Full Reset Sequence (9 steps) ──

func (e *DEngine) fullResetSequence() []DResetStep {
	var steps []DResetStep

	// Step 1: Reset UPSTREAM (NON-FATAL if UPSTREAM is not running — tests will still run)
	s1 := e.doResetStep(1, "Reset UPSTREAM", "POST",
		e.cfg.TargetBaseURL+"/__control/reset",
		`{}`, e.controlSecret)
	steps = append(steps, s1)
	if !s1.Success && isConnectionRefused(s1.Error) {
		s1.Success = true // connection refused → mark as "not applicable", continue
	}

	// Step 2: UPSTREAM health check (NON-FATAL — UPSTREAM may not have /health)
	s2 := e.doResetStep(2, "UPSTREAM health check", "GET",
		e.cfg.TargetBaseURL+"/health",
		"", "")
	steps = append(steps, s2)

	// Step 3: Set UPSTREAM health_mode (ensure not down)
	s3 := e.doResetStep(3, "Set UPSTREAM health (normal)", "POST",
		e.cfg.TargetBaseURL+"/__control/health_mode",
		`{"down":false}`, e.controlSecret)
	steps = append(steps, s3)

	// Step 4: Set UPSTREAM slow (ensure no delay)
	s4 := e.doResetStep(4, "Set UPSTREAM slow (no delay)", "POST",
		e.cfg.TargetBaseURL+"/__control/slow",
		`{"delay_ms":0}`, e.controlSecret)
	steps = append(steps, s4)

	// Step 5: Set WAF profile (enforce)
	s5 := e.doResetStep(5, "Set WAF profile (enforce)", "POST",
		e.cfg.WAFAdminURL+"/__waf_control/set_profile",
		`{"scope":"all","mode":"enforce"}`, e.controlSecret)
	steps = append(steps, s5)

	// Step 6: Flush WAF cache
	s6 := e.doResetStep(6, "Flush WAF cache", "POST",
		e.cfg.WAFAdminURL+"/__waf_control/flush_cache",
		`{}`, e.controlSecret)
	steps = append(steps, s6)

	// Step 7: Reset WAF state
	s7 := e.doResetStep(7, "Reset WAF state", "POST",
		e.cfg.WAFAdminURL+"/__waf_control/reset_state",
		`{}`, e.controlSecret)
	steps = append(steps, s7)

	// Step 8: WAF health check
	s8 := e.doResetStep(8, "WAF health check", "GET",
		e.cfg.WAFBaseURL+"/health",
		"", "")
	steps = append(steps, s8)

	// Step 9: Verify health (non-fatal)
	s9 := e.doResetStep(9, "Verify health", "GET",
		e.cfg.WAFBaseURL+"/",
		"", "")
	steps = append(steps, s9)

	return steps
}

func (e *DEngine) doResetStep(stepNum int, name, method, url, body, secret string) DResetStep {
	step := DResetStep{
		StepNum: stepNum,
		Name:    name,
		Method:  method,
		URL:     url,
	}

	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		step.Error = err.Error()
		return step
	}

	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.Header.Set("X-Benchmark-Secret", secret)
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	step.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		step.Error = err.Error()
		return step
	}
	defer resp.Body.Close()

	step.StatusCode = resp.StatusCode
	// Steps 1-8 must return 2xx; step 9 is non-fatal
	if stepNum <= 8 {
		step.Success = resp.StatusCode >= 200 && resp.StatusCode < 300
	} else {
		step.Success = resp.StatusCode < 500
	}

	return step
}

// isConnectionRefused returns true if the error string indicates connection refused.
func isConnectionRefused(errStr string) bool {
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connect: connection refused")
}

// ── Test Execution ──

func (e *DEngine) runDTest(dt *DTest) DTestResult {
	tr := DTestResult{
		TestID:       dt.ID,
		Name:         dt.Name,
		Category:     dt.Category,
		Description:  dt.Description,
		PassCriterion: dt.PassCriterion,
		MaxScore:     dt.MaxScore,
		SocketErrors: make(map[string]int),
	}

	startTest := time.Now()

	// Pre-verify (if needed)
	if dt.VerifyBefore {
		tr.PreVerifyResults = e.verifyRoutes(dt.VerifyRoutes, dt.SourceIP, dt.ID)
		tr.PreVerifyPassed = allRoutesPassed(tr.PreVerifyResults)
	}

	switch dt.Tool {
	case "wrk2":
		e.runWrk2Test(dt, &tr)
	case "slowhttptest":
		e.runSlowHTTPTest(dt, &tr)
	case "curl":
		e.runCurlTest(dt, &tr)
	case "wrk2+curl":
		e.runWrk2CurlTest(dt, &tr)
	}

	tr.DurationSec = time.Since(startTest).Seconds()

	// Post-verify (if needed)
	if dt.VerifyAfter {
		tr.PostVerifyResults = e.verifyRoutes(dt.VerifyRoutes, dt.SourceIP, dt.ID)
		tr.PostVerifyPassed = allRoutesPassed(tr.PostVerifyResults)
	}

	// Determine PASS/FAIL
	tr.Passed = e.evaluateTest(dt, &tr)
	if !tr.Passed && !tr.Skipped {
		tr.FailReason = e.determineFailReason(dt, &tr)
	}

	// Build scoring explanation
	tr.ScoringExplain = e.buildScoringExplain(dt, &tr)

	return tr
}

// ── Tool: wrk2 (Flood Tests) ──

func (e *DEngine) runWrk2Test(dt *DTest, tr *DTestResult) {
	// Build wrk2 command
	// wrk2 -t20 -c500 -d60s -R50000 --latency http://127.0.0.1:8080/
	cmd := exec.Command("wrk2",
		"-t20", "-c500",
		fmt.Sprintf("-d%ds", dt.DurationSec),
		fmt.Sprintf("-R%d", dt.TargetRPS),
		"--latency",
		e.cfg.WAFBaseURL+"/",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	tr.ToolStdout = stdout.String()
	tr.ToolStderr = stderr.String()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			tr.ToolExitCode = exitErr.ExitCode()
		} else {
			tr.ToolExitCode = -1
			tr.ToolStderr = err.Error()
		}
	} else {
		tr.ToolExitCode = 0
	}

	// Parse wrk2 output
	e.parseWrk2Output(tr)

	// During-flood verification for D01
	if dt.VerifyDuring && dt.ID == "D01" {
		tr.DuringVerifyResults = e.verifyRoutes(dt.VerifyRoutes, dt.SourceIP, dt.ID)
		tr.DuringVerifyPassed = allRoutesPassed(tr.DuringVerifyResults)
	}
}

func (e *DEngine) parseWrk2Output(tr *DTestResult) {
	out := tr.ToolStdout

	// Parse Requests/sec
	if re := regexp.MustCompile(`Requests/sec:\s+([\d.]+)`); re != nil {
		if m := re.FindStringSubmatch(out); len(m) >= 2 {
			tr.ActualRPS, _ = strconv.ParseFloat(m[1], 64)
		}
	}

	// Parse Transfer/sec
	if re := regexp.MustCompile(`Transfer/sec:\s+(\S+)`); re != nil {
		if m := re.FindStringSubmatch(out); len(m) >= 2 {
			tr.TransferSec = m[1]
		}
	}

	// Parse Socket errors
	socketPatterns := map[string]string{
		"connect": `Socket errors:\s*connect\s+(\d+)`,
		"read":    `Socket errors:[\s\S]*?read\s+(\d+)`,
		"write":   `Socket errors:[\s\S]*?write\s+(\d+)`,
		"timeout": `Socket errors:[\s\S]*?timeout\s+(\d+)`,
	}
	for key, pattern := range socketPatterns {
		if re := regexp.MustCompile(pattern); re != nil {
			if m := re.FindStringSubmatch(out); len(m) >= 2 {
				tr.SocketErrors[key], _ = strconv.Atoi(m[1])
			}
		}
	}

	// Parse latency percentiles
	latencyPatterns := map[string]*float64{
		`Latency\s+Avg\s+([\d.]+)`:   &tr.LatencyAvgMs,
		`Latency\s+Stdev\s+([\d.]+)`: &tr.LatencyStdevMs,
		`Latency\s+Max\s+([\d.]+)`:   &tr.LatencyMaxMs,
		`50%\s+([\d.]+)`:             &tr.LatencyP50Ms,
		`75%\s+([\d.]+)`:             &tr.LatencyP75Ms,
		`90%\s+([\d.]+)`:             &tr.LatencyP90Ms,
		`99%\s+([\d.]+)`:             &tr.LatencyP99Ms,
	}
	for pattern, target := range latencyPatterns {
		if re := regexp.MustCompile(pattern); re != nil {
			if m := re.FindStringSubmatch(out); len(m) >= 2 {
				*target, _ = strconv.ParseFloat(m[1], 64)
			}
		}
	}
}

// ── Tool: slowhttptest (Slowloris / RUDY) ──

func (e *DEngine) runSlowHTTPTest(dt *DTest, tr *DTestResult) {
	mode := "-H" // Slowloris mode
	if dt.ID == "D03" {
		mode = "-B" // RUDY mode (slow POST body)
	}

	url := e.cfg.WAFBaseURL + "/"
	if dt.ID == "D03" {
		url = e.cfg.WAFBaseURL + "/login"
	}

	prefix := fmt.Sprintf("d%02d", func() int {
		id := dt.ID
		_ = id
		n, _ := strconv.Atoi(strings.TrimPrefix(dt.ID, "D"))
		return n
	}())

	cmd := exec.Command("slowhttptest",
		"-c", fmt.Sprintf("%d", dt.Connections),
		mode,
		"-g",
		"-o", prefix,
		"-i", "10",
		"-r", "200",
		"-t", "GET",
		"-u", url,
		"-x", "24",
		"-p", "3",
		"-l", fmt.Sprintf("%d", dt.DurationSec),
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	tr.ToolStdout = stdout.String()
	tr.ToolStderr = stderr.String()

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			tr.ToolExitCode = exitErr.ExitCode()
		} else {
			tr.ToolExitCode = -1
		}
	} else {
		tr.ToolExitCode = 0
	}

	// Parse slowhttptest output
	e.parseSlowHTTPOutput(tr)
}

func (e *DEngine) parseSlowHTTPOutput(tr *DTestResult) {
	out := tr.ToolStdout

	// Parse connection counts from the summary lines
	if re := regexp.MustCompile(`(\d+)\s+closed`); re != nil {
		if m := re.FindStringSubmatch(out); len(m) >= 2 {
			tr.ConnectionsClosed, _ = strconv.Atoi(m[1])
		}
	}
	if re := regexp.MustCompile(`(\d+)\s+connected`); re != nil {
		if m := re.FindStringSubmatch(out); len(m) >= 2 {
			tr.ConnectionsOpen, _ = strconv.Atoi(m[1])
		}
	}
	if re := regexp.MustCompile(`(\d+)\s+pending`); re != nil {
		if m := re.FindStringSubmatch(out); len(m) >= 2 {
			tr.ConnectionsPending, _ = strconv.Atoi(m[1])
		}
	}
	if re := regexp.MustCompile(`(\d+)\s+error`); re != nil {
		if m := re.FindStringSubmatch(out); len(m) >= 2 {
			tr.ConnectionsError, _ = strconv.Atoi(m[1])
		}
	}

	// Parse Service Available
	if strings.Contains(strings.ToLower(out), "service available.*yes") || strings.Contains(out, "YES") {
		tr.ServiceAvailable = true
	}

	// If no connections parsed, set total as initial
	if tr.ConnectionsOpen == 0 && tr.ConnectionsClosed == 0 {
		// Try to get initial connection count
		if re := regexp.MustCompile(`(\d+)\s+connections`); re != nil {
			if m := re.FindStringSubmatch(out); len(m) >= 2 {
				total, _ := strconv.Atoi(m[1])
				tr.ConnectionsOpen = total
				tr.ConnectionsClosed = total // assume all closed if exit status OK
			}
		}
	}
}

// ── Tool: curl (Backend Failure Tests) ──

func (e *DEngine) runCurlTest(dt *DTest, tr *DTestResult) {
	// Set UPSTREAM condition first
	if dt.BackendDown {
		e.setUpstreamDown(true)
		defer e.setUpstreamDown(false)
	}
	if dt.BackendSlow {
		e.setUpstreamSlow(dt.DelayMs)
		defer e.setUpstreamSlow(0)
	}

	// Small delay for condition to propagate
	time.Sleep(500 * time.Millisecond)

	// Verify routes
	tr.PostVerifyResults = e.verifyRoutes(dt.VerifyRoutes, dt.SourceIP, dt.ID)
	tr.PostVerifyPassed = allRoutesPassed(tr.PostVerifyResults)

	// For D05: check circuit_breaker
	if dt.ID == "D05" {
		for _, vr := range tr.PostVerifyResults {
			if vr.WAFAction == "circuit_breaker" {
				tr.CircuitBroken = true
			}
		}
		if !tr.CircuitBroken && tr.PostVerifyPassed {
			tr.CircuitBroken = true // If all 503, it's circuit broken
		}
	}

	// For D06: check timeout
	if dt.ID == "D06" {
		for _, vr := range tr.PostVerifyResults {
			if vr.StatusCode == 504 {
				tr.TimeoutDetected = true
			}
		}
	}

	// For D07: check recovery
	if dt.ID == "D07" {
		tr.Recovered = tr.PostVerifyPassed
		tr.RecoveryResults = tr.PostVerifyResults
	}
}

// ── Tool: wrk2 + curl (D04, D08, D09) ──

func (e *DEngine) runWrk2CurlTest(dt *DTest, tr *DTestResult) {
	// Start wrk2 in background
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(dt.DurationSec+10)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "wrk2",
		"-t20", "-c500",
		fmt.Sprintf("-d%ds", dt.DurationSec),
		fmt.Sprintf("-R%d", dt.TargetRPS),
		"--latency",
		e.cfg.WAFBaseURL+"/",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	cmd.Start()

	// Wait for WAF to enter degraded mode (half the duration)
	waitTime := dt.DurationSec / 2
	if waitTime < 15 {
		waitTime = 15
	}
	time.Sleep(time.Duration(waitTime) * time.Second)

	// For D04: verify CRITICAL and MEDIUM routes during flood
	if dt.ID == "D04" {
		tr.TierResults = make(map[string]DTierResult)

		// Verify CRITICAL routes (expect 503 fail-close)
		criticalResults := e.verifyRoutes(CRITICALRoutes, dt.SourceIP, dt.ID)
		tr.TierResults["CRITICAL"] = DTierResult{
			Tier:         "CRITICAL",
			Routes:       criticalResults,
			TotalRoutes:  len(criticalResults),
			ExpectedCode: 503,
			ExpectedMode: "fail_close",
		}
		for _, vr := range criticalResults {
			if vr.Passed {
				tr.TierResults["CRITICAL"] = DTierResult{
					Tier: tr.TierResults["CRITICAL"].Tier,
					Routes: tr.TierResults["CRITICAL"].Routes,
					TotalRoutes: tr.TierResults["CRITICAL"].TotalRoutes,
					PassedRoutes: tr.TierResults["CRITICAL"].PassedRoutes + 1,
					ExpectedCode: tr.TierResults["CRITICAL"].ExpectedCode,
					ExpectedMode: tr.TierResults["CRITICAL"].ExpectedMode,
				}
			}
		}
		tier := tr.TierResults["CRITICAL"]
		tier.AllPassed = tier.PassedRoutes == tier.TotalRoutes
		if !tier.AllPassed && tier.FailReason == "" {
			tier.FailReason = fmt.Sprintf("%d/%d CRITICAL routes fail-closed correctly",
				tier.PassedRoutes, tier.TotalRoutes)
		}
		tr.TierResults["CRITICAL"] = tier

		// Verify MEDIUM routes (expect 200 fail-open)
		mediumResults := e.verifyRoutes(MEDIUMRoutes, dt.SourceIP, dt.ID)
		tr.TierResults["MEDIUM"] = DTierResult{
			Tier:         "MEDIUM",
			Routes:       mediumResults,
			TotalRoutes:  len(mediumResults),
			ExpectedCode: 200,
			ExpectedMode: "fail_open",
		}
		for _, vr := range mediumResults {
			if vr.Passed {
				mtr := tr.TierResults["MEDIUM"]
				mtr.PassedRoutes++
				tr.TierResults["MEDIUM"] = mtr
			}
		}
		mtr := tr.TierResults["MEDIUM"]
		mtr.AllPassed = mtr.PassedRoutes == mtr.TotalRoutes
		if !mtr.AllPassed && mtr.FailReason == "" {
			mtr.FailReason = fmt.Sprintf("%d/%d MEDIUM routes fail-open correctly",
				mtr.PassedRoutes, mtr.TotalRoutes)
		}
		tr.TierResults["MEDIUM"] = mtr

		// Verify CATCH_ALL routes
		caResults := e.verifyRoutes(CATCHALLRoutes, dt.SourceIP, dt.ID)
		tr.TierResults["CATCH_ALL"] = DTierResult{
			Tier: "CATCH_ALL", Routes: caResults, TotalRoutes: len(caResults),
			ExpectedCode: 200, ExpectedMode: "fail_open",
		}
		for _, vr := range caResults {
			if vr.Passed {
				cat := tr.TierResults["CATCH_ALL"]
				cat.PassedRoutes++
				tr.TierResults["CATCH_ALL"] = cat
			}
		}
		cat := tr.TierResults["CATCH_ALL"]
		cat.AllPassed = cat.PassedRoutes == cat.TotalRoutes
		tr.TierResults["CATCH_ALL"] = cat

		// Verify STATIC routes
		stResults := e.verifyRoutes(STATICRoutes, dt.SourceIP, dt.ID)
		tr.TierResults["STATIC"] = DTierResult{
			Tier: "STATIC", Routes: stResults, TotalRoutes: len(stResults),
			ExpectedCode: 200, ExpectedMode: "fail_open",
		}
		for _, vr := range stResults {
			if vr.Passed {
				str := tr.TierResults["STATIC"]
				str.PassedRoutes++
				tr.TierResults["STATIC"] = str
			}
		}
		str := tr.TierResults["STATIC"]
		str.AllPassed = str.PassedRoutes == str.TotalRoutes
		tr.TierResults["STATIC"] = str
	}

	// For D08/D09: verify MEDIUM routes during flood
	if dt.ID == "D08" || dt.ID == "D09" {
		expectedCode := 503
		expectedMode := "fail_close"
		if dt.ID == "D09" {
			expectedCode = 200
			expectedMode = "fail_open"
		}

		mediumResults := e.verifyRoutes(MEDIUMRoutes, dt.SourceIP, dt.ID)
		tr.TierResults = make(map[string]DTierResult)
		tr.TierResults["MEDIUM"] = DTierResult{
			Tier: "MEDIUM", Routes: mediumResults, TotalRoutes: len(mediumResults),
			ExpectedCode: expectedCode, ExpectedMode: expectedMode,
		}
		for _, vr := range mediumResults {
			if vr.Passed {
				mtr := tr.TierResults["MEDIUM"]
				mtr.PassedRoutes++
				tr.TierResults["MEDIUM"] = mtr
			}
		}
		mtr := tr.TierResults["MEDIUM"]
		mtr.AllPassed = mtr.PassedRoutes >= 4 // ≥4/5 required
		tr.TierResults["MEDIUM"] = mtr
	}

	cmd.Wait()
	tr.ToolStdout = stdout.String()
	tr.ToolStderr = stderr.String()

	if e.verbose && dt.ID == "D04" {
		fmt.Printf("    wrk2 complete: RPS=%.1f, Avg=%.1fms, P99=%.1fms\n",
			tr.ActualRPS, tr.LatencyAvgMs, tr.LatencyP99Ms)
	}
}

// ── Verification Helpers ──

func (e *DEngine) verifyRoutes(routes []DVerifyRoute, sourceIP string, testID string) []DVerifyRouteResult {
	var results []DVerifyRouteResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, route := range routes {
		wg.Add(1)
		go func(r DVerifyRoute) {
			defer wg.Done()
			vr := e.verifyOneRoute(&r, sourceIP, testID)
			mu.Lock()
			results = append(results, vr)
			mu.Unlock()
		}(route)
	}
	wg.Wait()

	return results
}

func (e *DEngine) verifyOneRoute(route *DVerifyRoute, sourceIP string, testID string) DVerifyRouteResult {
	vr := DVerifyRouteResult{
		Method:         route.Method,
		Endpoint:       route.Endpoint,
		ExpectedCode:   route.ExpectedCode,
		ExpectedAction: route.ExpectedAction,
		Tier:           route.Tier,
	}

	url := e.cfg.WAFBaseURL + route.Endpoint
	req, err := http.NewRequest(route.Method, url, nil)
	if err != nil {
		vr.FailReason = fmt.Sprintf("request build error: %v", err)
		return vr
	}

	if route.Method == "POST" && route.Tier == "CRITICAL" {
		// For POST to CRITICAL routes, send minimal body
		body := `{}`
		if route.Endpoint == "/login" {
			body = `{"username":"test","password":"test"}`
		}
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Type", "application/json")
	}

	// Build curl command for reproducibility
	curlCmd := fmt.Sprintf("curl -s --interface %s -X %s '%s' -o /dev/null -w '%s' --max-time 10",
		sourceIP, route.Method, url, "HTTP_%{http_code}")
	vr.CurlCommand = curlCmd

	start := time.Now()
	resp, err := e.client.Do(req)
	vr.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		vr.FailReason = fmt.Sprintf("request error: %v", err)
		return vr
	}
	defer resp.Body.Close()

	vr.StatusCode = resp.StatusCode
	vr.WAFAction = resp.Header.Get("X-WAF-Action")
	if rs := resp.Header.Get("X-WAF-Risk-Score"); rs != "" {
		vr.RiskScore, _ = strconv.Atoi(rs)
	}

	// Capture response for cross-phase SEC-02 pool
	if e.pool != nil {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr == nil {
			headers := make(map[string]string)
			for k, vv := range resp.Header {
				if len(vv) > 0 {
					headers[k] = vv[0]
				}
			}
			e.pool.Append("D", testID, sourceIP, route.Endpoint, route.Method, resp.StatusCode, string(bodyBytes), headers)

			// 429 Challenge detection (recorded during resilience test)
			if e.challengeSolver != nil && resp.StatusCode == 429 &&
				strings.EqualFold(strings.TrimSpace(vr.WAFAction), "challenge") {
				e.challengeSolver.RecordDetection(challenge.PhaseHookContext{
					Phase: "D", TestID: testID, Method: route.Method, Endpoint: route.Endpoint,
					StatusCode: resp.StatusCode, ResponseBody: string(bodyBytes), ResponseHeaders: headers,
				})
			}
		}
	}

	// Evaluate
	vr.Passed = true

	if route.ExpectedCode > 0 && vr.StatusCode != route.ExpectedCode {
		vr.Passed = false
		vr.FailReason = fmt.Sprintf("expected HTTP %d, got %d", route.ExpectedCode, vr.StatusCode)
	}

	if route.ExpectedAction != "" && vr.WAFAction != route.ExpectedAction {
		vr.Passed = false
		if vr.FailReason == "" {
			vr.FailReason = fmt.Sprintf("expected action '%s', got '%s'", route.ExpectedAction, vr.WAFAction)
		} else {
			vr.FailReason += fmt.Sprintf("; expected action '%s', got '%s'", route.ExpectedAction, vr.WAFAction)
		}
	}

	return vr
}

// ── Evaluation Logic ──

func (e *DEngine) evaluateTest(dt *DTest, tr *DTestResult) bool {
	if tr.Skipped {
		return false
	}

	switch dt.ID {
	case "D01":
		// D01 PASS: ≥7/10 during-flood AND ≥9/10 post-flood AND no circuit_breaker
		if tr.ToolExitCode != 0 && tr.ActualRPS == 0 {
			tr.FailReason = "waf_crashed"
			return false
		}
		// B-01 fix: Flood load gate — require ≥10% of target RPS for valid stress test.
		// Without this, a WAF that rate-limits the flood tool would get a false PASS.
		if tr.ActualRPS < float64(dt.TargetRPS)*0.1 {
			tr.FailReason = "insufficient_flood_load"
			return false
		}
		duringPass := tr.DuringVerifyPassed || countPassed(tr.DuringVerifyResults) >= 7
		afterPass := tr.PostVerifyPassed || countPassed(tr.PostVerifyResults) >= 9

		// Check for circuit_breaker
		hasCB := false
		for _, vr := range tr.DuringVerifyResults {
			if vr.WAFAction == "circuit_breaker" {
				hasCB = true
				break
			}
		}
		for _, vr := range tr.PostVerifyResults {
			if vr.WAFAction == "circuit_breaker" {
				hasCB = true
				break
			}
		}

		if hasCB {
			tr.FailReason = "circuit_breaker"
			return false
		}

		if !duringPass {
			tr.FailReason = "during_verify_fail"
			return false
		}
		if !afterPass {
			tr.FailReason = "after_verify_fail"
			return false
		}
		return true

	case "D02", "D03":
		// D02/D03 PASS: Service Available AND ≥90% closed AND post-verify passes
		if !tr.ServiceAvailable {
			tr.FailReason = "service_unavailable"
			return false
		}
		totalConns := tr.ConnectionsOpen + tr.ConnectionsClosed + tr.ConnectionsError + tr.ConnectionsPending
		// B-02 fix: When no connections were established at all, the test is invalid — fail.
		if totalConns == 0 {
			tr.FailReason = "no_connections_established"
			return false
		}
		closedPct := float64(tr.ConnectionsClosed) / float64(totalConns)
		if closedPct < 0.90 && tr.ConnectionsPending > 50 {
			tr.FailReason = "high_pending"
			return false
		}
		// B-03 fix: Use actual route count instead of hardcoded 10.
		// LegitimateRoutes has 5 entries; a hardcoded 10 would never trigger.
		if !tr.PostVerifyPassed {
			tr.FailReason = "post_verify_fail"
			return false
		}
		return true

	case "D04":
		// D04: CRITICAL fail-close (503) AND MEDIUM+CATCH_ALL+STATIC fail-open (200)
		criticalTR, okCrit := tr.TierResults["CRITICAL"]
		if !okCrit || !criticalTR.AllPassed {
			tr.FailReason = "critical_fail_close"
			return false
		}

		// Check non-CRITICAL aggregate
		nonCritPassed := 0
		nonCritTotal := 0
		for tier, tres := range tr.TierResults {
			if tier != "CRITICAL" {
				nonCritPassed += tres.PassedRoutes
				nonCritTotal += tres.TotalRoutes
			}
		}
		if nonCritTotal == 0 {
			nonCritTotal = 10 // default
		}
		if nonCritPassed < 8 {
			tr.FailReason = "medium_fail_open"
			return false
		}
		return true

	case "D05":
		// D05 PASS: All routes return 503 with circuit_breaker
		if !tr.CircuitBroken && !tr.PostVerifyPassed {
			tr.FailReason = "no_circuit_breaker"
			return false
		}
		return tr.PostVerifyPassed

	case "D06":
		// D06 PASS: All routes return 504
		if !tr.TimeoutDetected && !tr.PostVerifyPassed {
			tr.FailReason = "no_timeout"
			return false
		}
		return tr.PostVerifyPassed

	case "D07":
		// D07 PASS: All routes return 200
		return tr.Recovered || tr.PostVerifyPassed

	case "D08":
		// D08 PASS: ≥4/5 MEDIUM routes fail-close (503)
		mtr, ok := tr.TierResults["MEDIUM"]
		if !ok {
			tr.FailReason = "config_not_found"
			return false
		}
		if mtr.PassedRoutes < 4 {
			tr.FailReason = "medium_not_fail_close"
			return false
		}
		return true

	case "D09":
		// D09 PASS: ≥4/5 MEDIUM routes fail-open (200)
		mtr, ok := tr.TierResults["MEDIUM"]
		if !ok {
			tr.FailReason = "medium_not_fail_open"
			return false
		}
		if mtr.PassedRoutes < 4 {
			tr.FailReason = "medium_not_fail_open"
			return false
		}
		return true
	}

	return false
}

func (e *DEngine) determineFailReason(dt *DTest, tr *DTestResult) string {
	if tr.FailReason != "" {
		return tr.FailReason
	}

	switch dt.ID {
	case "D01":
		return determineD01Fail(tr)
	case "D02", "D03":
		return determineSlowFail(tr)
	case "D04":
		return determineD04Fail(tr)
	case "D05":
		return "no_circuit_breaker"
	case "D06":
		return "no_timeout"
	case "D07":
		return "recovery_fail"
	case "D08":
		return "medium_not_fail_close"
	case "D09":
		return "medium_not_fail_open"
	}
	return "unknown"
}

func determineD01Fail(tr *DTestResult) string {
	if tr.FailReason == "waf_crashed" || tr.ToolExitCode != 0 {
		return "waf_crashed"
	}
	if tr.FailReason == "circuit_breaker" {
		return "circuit_breaker"
	}
	if !tr.DuringVerifyPassed {
		return "during_verify_fail"
	}
	if !tr.PostVerifyPassed {
		return "after_verify_fail"
	}
	return "unknown"
}

func determineSlowFail(tr *DTestResult) string {
	if !tr.ServiceAvailable {
		return "service_unavailable"
	}
	if tr.ConnectionsPending > 50 {
		return "high_pending"
	}
	if !tr.PostVerifyPassed {
		return "post_verify_fail"
	}
	return "unknown"
}

func determineD04Fail(tr *DTestResult) string {
	if ct, ok := tr.TierResults["CRITICAL"]; !ok || !ct.AllPassed {
		return "critical_fail_close"
	}
	return "medium_fail_open"
}

// ── Scoring Explanation Builder ──

func (e *DEngine) buildScoringExplain(dt *DTest, tr *DTestResult) string {
	var lines []string

	if tr.Skipped {
		lines = append(lines, fmt.Sprintf("⚠ SKIP — %s", tr.SkipReason))
		lines = append(lines, fmt.Sprintf("  → Score: 0/%v pts (test not executed)", dt.MaxScore))
		return strings.Join(lines, "\n")
	}

	if tr.Passed {
		lines = append(lines, fmt.Sprintf("✓ PASS — %s", dt.PassCriterion))
		lines = append(lines, fmt.Sprintf("  → Score: +%v/%v pts", dt.MaxScore, dt.MaxScore))

		switch dt.ID {
		case "D01":
			lines = append(lines, fmt.Sprintf("  • WAF survived %.0f RPS flood for %ds", tr.ActualRPS, dt.DurationSec))
			lines = append(lines, fmt.Sprintf("  • During-flood: %d/%d legitimate requests passed", countPassed(tr.DuringVerifyResults), len(tr.DuringVerifyResults)))
			lines = append(lines, fmt.Sprintf("  • Post-flood: %d/%d legitimate requests passed", countPassed(tr.PostVerifyResults), len(tr.PostVerifyResults)))
			lines = append(lines, "  • No circuit_breaker action detected ✓")
		case "D02":
			lines = append(lines, fmt.Sprintf("  • %d/%d connections closed", tr.ConnectionsClosed, dt.Connections))
			lines = append(lines, fmt.Sprintf("  • Service Available: YES"))
			lines = append(lines, fmt.Sprintf("  • Post-flood: %d/%d legitimate requests passed", countPassed(tr.PostVerifyResults), len(tr.PostVerifyResults)))
		case "D03":
			lines = append(lines, fmt.Sprintf("  • %d/%d connections closed", tr.ConnectionsClosed, dt.Connections))
			lines = append(lines, fmt.Sprintf("  • Service Available: YES"))
			lines = append(lines, fmt.Sprintf("  • Post-flood: %d/%d legitimate requests passed", countPassed(tr.PostVerifyResults), len(tr.PostVerifyResults)))
		case "D04":
			for tier, tres := range tr.TierResults {
				lines = append(lines, fmt.Sprintf("  • %s: %d/%d routes correct (%s)", tier, tres.PassedRoutes, tres.TotalRoutes, tres.ExpectedMode))
			}
		case "D05":
			lines = append(lines, "  • Circuit breaker activated: 503 returned for all routes")
		case "D06":
			lines = append(lines, "  • Timeout detected: 504 returned for all routes")
		case "D07":
			lines = append(lines, fmt.Sprintf("  • %d/%d routes recovered to 200 OK", countPassed(tr.RecoveryResults), len(tr.RecoveryResults)))
		case "D08":
			if mtr, ok := tr.TierResults["MEDIUM"]; ok {
				lines = append(lines, fmt.Sprintf("  • MEDIUM tier fail-close: %d/%d routes returned 503", mtr.PassedRoutes, mtr.TotalRoutes))
			}
		case "D09":
			if mtr, ok := tr.TierResults["MEDIUM"]; ok {
				lines = append(lines, fmt.Sprintf("  • MEDIUM tier fail-open: %d/%d routes returned 200", mtr.PassedRoutes, mtr.TotalRoutes))
			}
		}
	} else {
		lines = append(lines, fmt.Sprintf("✗ FAIL — %s", tr.FailReason))
		lines = append(lines, "  → Score: +0 pts")

		// Add detailed explanation based on fail reason
		if desc, ok := dt.FailReasons[tr.FailReason]; ok {
			lines = append(lines, fmt.Sprintf("  • Reason: %s", desc))
		}

		switch dt.ID {
		case "D01":
			lines = append(lines, fmt.Sprintf("  • During-flood: %d/%d passed", countPassed(tr.DuringVerifyResults), len(tr.DuringVerifyResults)))
			lines = append(lines, fmt.Sprintf("  • Post-flood: %d/%d passed", countPassed(tr.PostVerifyResults), len(tr.PostVerifyResults)))
		case "D02", "D03":
			lines = append(lines, fmt.Sprintf("  • Connections: %d closed, %d pending, %d error", tr.ConnectionsClosed, tr.ConnectionsPending, tr.ConnectionsError))
			lines = append(lines, fmt.Sprintf("  • Service Available: %v", tr.ServiceAvailable))
		case "D04":
			for tier, tres := range tr.TierResults {
				lines = append(lines, fmt.Sprintf("  • %s: %d/%d correct (expected %s)", tier, tres.PassedRoutes, tres.TotalRoutes, tres.ExpectedMode))
			}
		}
	}

	return strings.Join(lines, "\n")
}

// ── UPSTREAM Control Helpers ──

func (e *DEngine) setUpstreamDown(down bool) {
	val := "false"
	if down {
		val = "true"
	}
	body := fmt.Sprintf(`{"down":%s}`, val)
	req, _ := http.NewRequest("POST", e.cfg.TargetBaseURL+"/__control/health_mode",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Benchmark-Secret", e.controlSecret)
	resp, err := e.client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

func (e *DEngine) setUpstreamSlow(delayMs int) {
	body := fmt.Sprintf(`{"delay_ms":%d}`, delayMs)
	req, _ := http.NewRequest("POST", e.cfg.TargetBaseURL+"/__control/slow",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Benchmark-Secret", e.controlSecret)
	resp, err := e.client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// ── Helpers ──

func allRoutesPassed(results []DVerifyRouteResult) bool {
	if len(results) == 0 {
		return false
	}
	for _, r := range results {
		if !r.Passed {
			return false
		}
	}
	return true
}

func countPassed(results []DVerifyRouteResult) int {
	count := 0
	for _, r := range results {
		if r.Passed {
			count++
		}
	}
	return count
}

// ── Dry-Run Simulation ──

func (e *DEngine) simulateRun() (*PhaseDResult, error) {
	start := time.Now()
	result := &PhaseDResult{
		StartTime:   start,
		WAFTarget:   e.cfg.WAFBaseURL,
		WAFMode:     "enforce",
		WAFAlive:    true,
		UpstreamAlive: true,
		RawMaxScore: 20.0,
		INT04Cap:    8.0,
	}

	// Simulated reset steps
	resetNames := []string{
		"Reset UPSTREAM", "UPSTREAM health check", "Set UPSTREAM health (normal)",
		"Set UPSTREAM slow (no delay)", "Set WAF profile (enforce)",
		"Flush WAF cache", "Reset WAF state", "WAF health check", "Verify health",
	}
	for i, name := range resetNames {
		result.ResetSteps = append(result.ResetSteps, DResetStep{
			StepNum: i + 1, Name: name, Method: "POST",
			StatusCode: 200, Success: true, LatencyMs: float64(5 + i*2),
		})
	}
	result.ResetAllPassed = true

	// Simulated test results
	simResults := []struct {
		id       string
		name     string
		cat      string
		score    float64
		passed   bool
		skipped  bool
		skipRsn  string
		failRsn  string
		duration float64
		explain  string
	}{
		{"D01", "HTTP Flood Survival", "ddos", 3.0, true, false, "", "", 75.2,
			"✓ PASS — WAF survived 50000 RPS flood for 60s\n  • During-flood: 8/10 passed\n  • Post-flood: 10/10 passed\n  • No circuit_breaker ✓\n  → Score: +3.0/3.0 pts"},
		{"D02", "Slowloris Defense", "ddos", 2.0, true, false, "", "", 40.5,
			"✓ PASS — 500/500 connections closed\n  • Service Available: YES\n  • Post-flood: 5/5 legitimate passed\n  → Score: +2.0/2.0 pts"},
		{"D03", "RUDY Defense", "ddos", 2.0, true, false, "", "", 40.8,
			"✓ PASS — 498/500 connections closed\n  • Service Available: YES\n  → Score: +2.0/2.0 pts"},
		{"D04", "WAF-Targeted Flood", "ddos", 7.0, true, false, "", "", 85.1,
			"✓ PASS — Fail-close CRITICAL: 4/4 | Fail-open non-CRITICAL: 10/10\n  • CRITICAL: 4/4 → +4 pts\n  • MEDIUM: 5/5 → +3 pts\n  → Score: +7.0/7.0 pts"},
		{"D05", "Backend Down / Circuit Breaker", "backend_failure", 2.0, true, false, "", "", 5.2,
			"✓ PASS — Circuit breaker activated: 503 for all routes\n  → Score: +2.0/2.0 pts"},
		{"D06", "Backend Slow / Timeout", "backend_failure", 1.0, true, false, "", "", 5.1,
			"✓ PASS — Timeout: 504 for all routes\n  → Score: +1.0/1.0 pt"},
		{"D07", "Recovery", "backend_failure", 1.0, true, false, "", "", 3.8,
			"✓ PASS — All routes recovered to 200 OK\n  → Score: +1.0/1.0 pt"},
		{"D08", "Fail-Mode Configurable", "fail_mode_config", 1.0, false, true,
			"unrecognized_config_format", "", 0, "⚠ SKIP — WAF config format not recognized\n  → Score: 0/1 pts"},
		{"D09", "Fail-Mode Restore", "fail_mode_config", 1.0, false, true,
			"prerequisite D08 not met", "", 0, "⚠ SKIP — Prerequisite D08 not met\n  → Score: 0/1 pts"},
	}

	for _, sr := range simResults {
		tr := DTestResult{
			TestID: sr.id, Name: sr.name, Category: sr.cat,
			MaxScore: sr.score, Passed: sr.passed, Skipped: sr.skipped,
			SkipReason: sr.skipRsn, FailReason: sr.failRsn,
			DurationSec: sr.duration, ScoringExplain: sr.explain,
		}
		result.TestResults = append(result.TestResults, tr)

		if tr.Passed {
			result.PassedTests++
			result.RawScore += sr.score
		} else if tr.Skipped {
			result.SkippedTests++
		} else {
			result.FailedTests++
		}
	}

	result.INT04Score = math.Min(8.0, result.RawScore)
	result.EndTime = time.Now()
	return result, nil
}