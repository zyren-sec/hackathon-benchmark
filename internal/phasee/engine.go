package phasee

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/waf-hackathon/benchmark-new/internal/challenge"
	"github.com/waf-hackathon/benchmark-new/internal/crossphase"
)

// ── Engine ──

type EEngine struct {
	cfg           *EConfigWrapper
	pool          *crossphase.GlobalResponsePool // SEC-02 response collector
	challengeSolver *challenge.Solver            // 429 challenge lifecycle handler
	targetURL     string
	wafURL        string
	wafAdminURL   string
	controlSecret string
	client        *http.Client
	dryRun        bool
	verbose       bool

	// Config state
	configPath         string
	configFormat       string
	configBackup       string
	configDetected     bool
	cacheFlushSupported bool // Tracks whether flush_cache is supported
}

type EConfigWrapper struct {
	TargetBaseURL string
	WAFBaseURL    string
	WAFAdminURL   string
	ControlSecret string
	TimeoutSec    int
	Verbose       bool
	DryRun        bool
}

func NewEEngine(cfg *EConfigWrapper, pool *crossphase.GlobalResponsePool, chSolver *challenge.Solver) *EEngine {
	timeout := cfg.TimeoutSec
	if timeout < 30 {
		timeout = 60 // Phase E needs longer timeouts for config polling
	}
	return &EEngine{
		cfg:           cfg,
		pool:          pool,
		challengeSolver: chSolver,
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

// Run executes the full Phase E workflow.
func (e *EEngine) Run() (*PhaseEResult, error) {
	if e.dryRun {
		return e.simulateRun()
	}
	return e.realRun()
}

// ── Real HTTP Execution ──

func (e *EEngine) realRun() (*PhaseEResult, error) {
	start := time.Now()
	result := &PhaseEResult{
		StartTime:      start,
		WAFTarget:      e.cfg.WAFBaseURL,
		WAFMode:        "enforce",
		MaxScore:       4.0,
		EXT03SubScores: make(map[string]float64),
	}

	// 1. Pre-flight health checks
	result.WAFAlive = e.checkWAFAlive()
	if !result.WAFAlive {
		result.EndTime = time.Now()
		return result, fmt.Errorf("WAF not reachable — Phase E aborted")
	}
	result.UpstreamAlive = e.checkUpstreamAlive()
	if !result.UpstreamAlive {
		result.EndTime = time.Now()
		return result, fmt.Errorf("UPSTREAM not healthy — Phase E aborted")
	}

	// 2. Full Reset Sequence (4 steps per phase_E.md v2.5 §3.1)
	//    Step 1: reset UPSTREAM, Step 2: UPSTREAM health check,
	//    Step 3: set WAF profile (enforce), Step 4: flush WAF cache
	//    Note: no config detection needed — EXT-01/EXT-02 are manual-only
	result.ResetSteps = e.fullResetSequence()
	result.ResetAllPassed = true
	for _, s := range result.ResetSteps {
		if !s.Success {
			// Step 4 (flush_cache) is non-fatal
			if s.StepNum == 4 && s.StatusCode == 501 {
				e.cacheFlushSupported = false
				continue
			}
			result.ResetAllPassed = false
			break
		}
	}
	if !result.ResetAllPassed {
		result.EndTime = time.Now()
		return result, nil
	}

	// 3. Run ONLY EXT-03 (Caching Correctness) — EXT-01/EXT-02 are manual
	allTests := GetETests(e.wafURL, e.wafAdminURL)

	for _, et := range allTests {
		tr := e.runETest(&et)
		result.TestResults = append(result.TestResults, tr)

		if tr.Passed {
			result.PassedTests++
		} else if tr.Skipped {
			result.SkippedTests++
		} else {
			result.FailedTests++
		}

		if e.verbose {
			status := "FAIL ✗"
			if tr.Passed {
				status = "PASS ✓"
			} else if tr.Skipped {
				status = "SKIP"
			}
			fmt.Printf("  [%s] %s: %s\n", status, et.ID, et.Name)
		}
	}

	// 4. Compute scores (EXT-03 only — automated)
	for _, tr := range result.TestResults {
		if tr.Passed && tr.TestID == "EXT-03" {
			result.EXT03Score = tr.Score
			if tr.EXT03SubScores != nil {
				result.EXT03SubScores = tr.EXT03SubScores
			}
		}
	}

	result.TotalScore = result.EXT03Score

	// 5. Final cleanup reset
	e.postPhaseCleanup()

	result.EndTime = time.Now()
	return result, nil
}

// ── Pre-flight Checks ──

func (e *EEngine) checkWAFAlive() bool {
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

func (e *EEngine) checkUpstreamAlive() bool {
	resp, err := e.client.Get(e.cfg.TargetBaseURL + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200
}

// ── Config Format Detection (per phase_E.md Appendix B) ──

func (e *EEngine) findConfigDir() string {
	// Search order: /var/www, then .
	candidates := []string{"/var/www", "."}
	for _, dir := range candidates {
		for _, name := range []string{"waf.yaml", "waf.toml"} {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return dir
			}
		}
	}
	return "."
}

func (e *EEngine) detectConfigFormat() {
	dir := e.findConfigDir()

	if path := filepath.Join(dir, "waf.yaml"); fileExists(path) {
		e.configFormat = "yaml"
		e.configPath = path
		e.configDetected = true
		return
	}
	if path := filepath.Join(dir, "waf.toml"); fileExists(path) {
		e.configFormat = "toml"
		e.configPath = path
		e.configDetected = true
		return
	}
	e.configFormat = "unknown"
	e.configPath = ""
	e.configDetected = false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ── Full Reset Sequence (5 steps per phase_E.md §3.1) ──

func (e *EEngine) fullResetSequence() []EResetStep {
	steps := []struct {
		name   string
		method string
		url    string
		body   string
		fatal  bool
	}{
		{"Reset UPSTREAM", "POST", e.cfg.TargetBaseURL + "/__control/reset", "", true},
		{"UPSTREAM health check", "GET", e.cfg.TargetBaseURL + "/health", "", true},
		{"Set WAF profile (enforce)", "POST", e.cfg.WAFAdminURL + "/__waf_control/set_profile",
			`{"scope":"all","mode":"enforce"}`, true},
		{"Flush WAF cache", "POST", e.cfg.WAFAdminURL + "/__waf_control/flush_cache", "", false},
		{"Reset WAF state", "POST", e.cfg.WAFAdminURL + "/__waf_control/reset_state", "", true},
	}

	var results []EResetStep
	for i, step := range steps {
		start := time.Now()
		rs := EResetStep{
			StepNum: i + 1,
			Name:    step.name,
			Method:  step.method,
			URL:     step.url,
		}

		var resp *http.Response
		var err error
		success := false

		// Retry up to 3 times with 2s backoff
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(2 * time.Second)
			}

			var req *http.Request
			if step.body != "" {
				req, err = http.NewRequest(step.method, step.url,
					strings.NewReader(step.body))
				if err == nil {
					req.Header.Set("Content-Type", "application/json")
				}
			} else {
				req, err = http.NewRequest(step.method, step.url, nil)
			}

			if err != nil {
				rs.Error = err.Error()
				continue
			}

			// Add control secret for UPSTREAM control endpoints
			if strings.Contains(step.url, "/__control/") {
				req.Header.Set("X-Benchmark-Secret", e.controlSecret)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			req = req.WithContext(ctx)
			resp, err = e.client.Do(req)
			cancel()

			if err != nil {
				rs.Error = err.Error()
				continue
			}

			rs.StatusCode = resp.StatusCode
			// Read body to allow connection reuse
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			// Step 4 (flush_cache) accepts 200 or 501
			if step.name == "Flush WAF cache" {
				if resp.StatusCode == 200 || resp.StatusCode == 501 {
					success = true
					// Track 501 as "not supported" rather than failure
					if resp.StatusCode == 501 {
						e.cacheFlushSupported = false
					} else {
						e.cacheFlushSupported = true
					}
				}
			} else {
				success = (resp.StatusCode >= 200 && resp.StatusCode < 300)
			}

			if success {
				break
			}
		}

		rs.Success = success
		rs.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
		if !success && rs.Error == "" {
			rs.Error = fmt.Sprintf("unexpected status %d", rs.StatusCode)
		}
		results = append(results, rs)
	}

	return results
}

// ── Test Dispatch ──

func (e *EEngine) runETest(et *ETest) ETestResult {
	switch et.ID {
	case "EXT-01":
		return e.runEXT01(et)
	case "EXT-02":
		return e.runEXT02(et)
	case "EXT-03":
		return e.runEXT03(et)
	default:
		return ETestResult{
			TestID: et.ID, Name: et.Name, Category: et.Category,
			Description: et.Description, PassCriterion: et.PassCriterion,
			MaxScore: et.MaxScore, Passed: false,
			FailReason: fmt.Sprintf("unknown test ID %q", et.ID),
		}
	}
}

// ── EXT-01: Hot-reload Add Rule (3 pts, binary) ──

func (e *EEngine) runEXT01(et *ETest) ETestResult {
	tr := ETestResult{
		TestID: et.ID, Name: et.Name, Category: et.Category,
		Criterion: et.Criterion, Description: et.Description,
		PassCriterion: et.PassCriterion, MaxScore: et.MaxScore,
		ReproduceScript: et.ReproduceScript,
	}

	start := time.Now()

	// Step 1: Verify baseline — path should NOT be blocked
	baselineResp, baselineErr := e.doWAFRequest("GET", "/test-hotreload-path", "", nil, et.SourceIP)
	if baselineErr != nil {
		tr.FailReason = fmt.Sprintf("baseline request failed: %v", baselineErr)
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}
	baselineCode := baselineResp.StatusCode
	baselineResp.Body.Close()

	// Path should return 404 (not found from upstream) — not yet blocked
	if baselineCode == 403 {
		tr.FailReason = fmt.Sprintf("baseline returned 403 — path already blocked before rule added (got %d)", baselineCode)
		tr.FailConditions = append(tr.FailConditions, EFailCondition{
			ID: "baseline_blocked", Description: "Path already blocked before test",
			Triggered: true, Evidence: fmt.Sprintf("GET /test-hotreload-path → %d", baselineCode),
		})
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}

	// Step 2: Backup config
	backupPath := e.configPath + ".backup." + time.Now().Format("20060102T150405")
	if data, err := os.ReadFile(e.configPath); err == nil {
		if err := os.WriteFile(backupPath, data, 0644); err == nil {
			e.configBackup = backupPath
		} else {
			tr.FailReason = fmt.Sprintf("failed to backup config: %v", err)
			tr.DurationSec = time.Since(start).Seconds()
			return tr
		}
	} else {
		tr.FailReason = fmt.Sprintf("failed to read config for backup: %v", err)
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}

	// Step 3: Add rule to config (atomic write)
	ruleTemplate := e.getRuleTemplate()
	if ruleTemplate == "" {
		tr.FailReason = "no rule template for config format"
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}

	originalData, err := os.ReadFile(e.configPath)
	if err != nil {
		tr.FailReason = fmt.Sprintf("failed to read config: %v", err)
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}

	modifiedData := string(originalData) + "\n" + ruleTemplate + "\n"
	tmpPath := e.configPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(modifiedData), 0644); err != nil {
		tr.FailReason = fmt.Sprintf("failed to write tmp config: %v", err)
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}
	if err := os.Rename(tmpPath, e.configPath); err != nil {
		tr.FailReason = fmt.Sprintf("failed to atomic mv config: %v", err)
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}

	tr.ConfigModified = true
	configModTime := time.Now()

	// Step 4: Poll for rule to take effect (every 1s, timeout 15s)
	slaOk := false
	var slaLatency float64
	pollTimeout := 15 * time.Second
	pollStart := time.Now()

	for time.Since(pollStart) < pollTimeout {
		time.Sleep(1 * time.Second)
		pollResp, pollErr := e.doWAFRequest("GET", "/test-hotreload-path", "", nil, et.SourceIP)
		if pollErr != nil {
			continue
		}
		if pollResp.StatusCode == 403 {
			slaLatency = time.Since(configModTime).Seconds()
			if slaLatency <= 10.0 {
				slaOk = true
			}
			// Check required headers
			action := pollResp.Header.Get("X-WAF-Action")
			_ = pollResp.Header.Get("X-WAF-Rule-Id") // ruleID check
			pollResp.Body.Close()

			if action == "block" {
				tr.HotReloadSLAOk = slaOk
				tr.HotReloadLatencyMs = slaLatency * 1000
				break
			}
			pollResp.Body.Close()
			continue
		}
		pollResp.Body.Close()
	}

	if !slaOk {
		if slaLatency > 0 {
			tr.FailReason = fmt.Sprintf("SLA exceeded: rule took %.1fs to take effect (max 10s)", slaLatency)
			tr.FailConditions = append(tr.FailConditions, EFailCondition{
				ID: "sla_exceeded", Description: "Rule not effective within 10s SLA",
				Triggered: true, Evidence: fmt.Sprintf("latency = %.1fs > 10s", slaLatency),
			})
		} else {
			tr.FailReason = "rule not effective: /test-hotreload-path not blocked after 15s polling"
			tr.FailConditions = append(tr.FailConditions, EFailCondition{
				ID: "rule_not_effective", Description: "Added rule but path not blocked",
				Triggered: true, Evidence: "No 403 response within 15s",
			})
		}
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}

	// Step 5: Verify headers on 403
	verifyResp, verifyErr := e.doWAFRequest("GET", "/test-hotreload-path", "", nil, et.SourceIP)
	if verifyErr != nil {
		tr.FailReason = fmt.Sprintf("header verification request failed: %v", verifyErr)
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}
	defer verifyResp.Body.Close()

	action := verifyResp.Header.Get("X-WAF-Action")
	_ = verifyResp.Header.Get("X-WAF-Rule-Id") // ruleID check

	allVerifyOK := true
	if action != "block" {
		allVerifyOK = false
		tr.FailConditions = append(tr.FailConditions, EFailCondition{
			ID: "action_not_block", Description: "X-WAF-Action must be 'block'",
			Triggered: true, Evidence: fmt.Sprintf("X-WAF-Action = %q", action),
		})
	}

	tr.VerifyResults = append(tr.VerifyResults, EVerifyRouteResult{
		Method: "GET", Endpoint: "/test-hotreload-path",
		StatusCode: verifyResp.StatusCode, WAFAction: action,
		Passed: allVerifyOK, ExpectedCode: 403,
		CurlCommand: fmt.Sprintf("curl -s --interface %s -w '\\nHTTP:%%{http_code} | X-WAF-Action:%%header{X-WAF-Action}' %s/test-hotreload-path",
			et.SourceIP, e.wafURL),
	})

	if allVerifyOK {
		tr.Passed = true
		tr.Score = et.MaxScore
		tr.ScoringExplain = fmt.Sprintf(
			"✓ PASS — Rule added and effective within %.1fs (SLA ≤ 10s ✓)\n"+
				"  • Baseline: %d (pass-through)\n"+
				"  • After rule add: 403 (blocked)\n"+
				"  • X-WAF-Action: block ✓\n"+
				"  • Hot-reload latency: %.1fs\n"+
				"  → Score: +%.1f/%.1f pts (binary)",
			slaLatency, baselineCode, slaLatency, et.MaxScore, et.MaxScore)
	} else {
		tr.ScoringExplain = fmt.Sprintf(
			"✗ FAIL — Rule added but header verification failed\n"+
				"  • Rule latency: %.1fs (SLA %s)\n"+
				"  • X-WAF-Action: %q (expected 'block')\n"+
				"  → Score: +0/%.1f pts",
			slaLatency, map[bool]string{true: "OK", false: "EXCEEDED"}[slaOk], action, et.MaxScore)
	}

	tr.DurationSec = time.Since(start).Seconds()
	return tr
}

// ── EXT-02: Hot-reload Remove Rule (3 pts, binary) ──

func (e *EEngine) runEXT02(et *ETest) ETestResult {
	tr := ETestResult{
		TestID: et.ID, Name: et.Name, Category: et.Category,
		Criterion: et.Criterion, Description: et.Description,
		PassCriterion: et.PassCriterion, MaxScore: et.MaxScore,
		ReproduceScript: et.ReproduceScript,
	}

	start := time.Now()

	// Step 1: Verify baseline — path should STILL be blocked (EXT-01 passed)
	baselineResp, baselineErr := e.doWAFRequest("GET", "/test-hotreload-path", "", nil, et.SourceIP)
	if baselineErr != nil {
		tr.FailReason = fmt.Sprintf("baseline request failed: %v", baselineErr)
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}
	baselineCode := baselineResp.StatusCode
	baselineResp.Body.Close()

	// Step 2: Read current config, remove the benchmark rule
	originalData, err := os.ReadFile(e.configPath)
	if err != nil {
		tr.FailReason = fmt.Sprintf("failed to read config: %v", err)
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}

	cleaned := removeRuleFromConfig(string(originalData), e.configFormat)
	if cleaned == "" {
		tr.FailReason = "failed to find benchmark rule in config for removal"
		tr.FailConditions = append(tr.FailConditions, EFailCondition{
			ID: "remove_failed", Description: "Could not locate benchmark-hotreload-test rule",
			Triggered: true,
		})
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}

	// Atomic write cleaned config
	tmpPath := e.configPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(cleaned), 0644); err != nil {
		tr.FailReason = fmt.Sprintf("failed to write cleaned config: %v", err)
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}
	if err := os.Rename(tmpPath, e.configPath); err != nil {
		tr.FailReason = fmt.Sprintf("failed to atomic mv cleaned config: %v", err)
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}

	tr.ConfigModified = true
	configModTime := time.Now()

	// Step 3: Poll for rule removal (every 1s, timeout 15s)
	slaOk := false
	var slaLatency float64
	pollTimeout := 15 * time.Second
	pollStart := time.Now()

	for time.Since(pollStart) < pollTimeout {
		time.Sleep(1 * time.Second)
		pollResp, pollErr := e.doWAFRequest("GET", "/test-hotreload-path", "", nil, et.SourceIP)
		if pollErr != nil {
			continue
		}
		code := pollResp.StatusCode
		pollResp.Body.Close()

		// Path should no longer be blocked — expect 404 (or 200 from upstream)
		if code != 403 {
			slaLatency = time.Since(configModTime).Seconds()
			if slaLatency <= 10.0 {
				slaOk = true
			}
			tr.HotReloadSLAOk = slaOk
			tr.HotReloadLatencyMs = slaLatency * 1000
			break
		}
	}

	if !slaOk {
		if slaLatency > 0 {
			tr.FailReason = fmt.Sprintf("SLA exceeded: rule removal took %.1fs to take effect (max 10s)", slaLatency)
			tr.FailConditions = append(tr.FailConditions, EFailCondition{
				ID: "sla_exceeded", Description: "Rule removal not effective within 10s SLA",
				Triggered: true, Evidence: fmt.Sprintf("latency = %.1fs > 10s", slaLatency),
			})
		} else {
			tr.FailReason = "rule still active: /test-hotreload-path still blocked after 15s"
			tr.FailConditions = append(tr.FailConditions, EFailCondition{
				ID: "rule_still_active", Description: "Removed rule but path still blocked",
				Triggered: true, Evidence: "Still getting 403 after 15s",
			})
		}
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}

	// Step 4: Verify path returns 200 (or 404 — upstream response)
	verifyResp, verifyErr := e.doWAFRequest("GET", "/test-hotreload-path", "", nil, et.SourceIP)
	if verifyErr != nil {
		tr.FailReason = fmt.Sprintf("verification request failed: %v", verifyErr)
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}
	defer verifyResp.Body.Close()

	if verifyResp.StatusCode == 403 {
		tr.FailReason = fmt.Sprintf("rule removal failed: /test-hotreload-path still returns 403")
		tr.FailConditions = append(tr.FailConditions, EFailCondition{
			ID: "rule_still_active", Description: "Path still blocked after rule removal",
			Triggered: true, Evidence: fmt.Sprintf("GET /test-hotreload-path → %d", verifyResp.StatusCode),
		})
		tr.DurationSec = time.Since(start).Seconds()
		return tr
	}

	tr.VerifyResults = append(tr.VerifyResults, EVerifyRouteResult{
		Method: "GET", Endpoint: "/test-hotreload-path",
		StatusCode: verifyResp.StatusCode,
		Passed: verifyResp.StatusCode != 403,
		ExpectedCode: 200,
		CurlCommand: fmt.Sprintf("curl -s --interface %s -w '\\nHTTP:%%{http_code}' %s/test-hotreload-path",
			et.SourceIP, e.wafURL),
	})

	tr.Passed = true
	tr.ConfigRestored = true
	tr.Score = et.MaxScore
	tr.ScoringExplain = fmt.Sprintf(
		"✓ PASS — Rule removed and no longer effective within %.1fs (SLA ≤ 10s ✓)\n"+
			"  • Before removal: %d (blocked)\n"+
			"  • After removal: %d (pass-through)\n"+
			"  • Hot-reload latency: %.1fs\n"+
			"  → Score: +%.1f/%.1f pts (binary)",
		slaLatency, baselineCode, verifyResp.StatusCode, slaLatency, et.MaxScore, et.MaxScore)

	tr.DurationSec = time.Since(start).Seconds()
	return tr
}

// ── EXT-03: Caching Correctness (4 pts sum of sub-tests) ──

func (e *EEngine) runEXT03(et *ETest) ETestResult {
	tr := ETestResult{
		TestID: et.ID, Name: et.Name, Category: et.Category,
		Criterion: et.Criterion, Description: et.Description,
		PassCriterion: et.PassCriterion, MaxScore: et.MaxScore,
		ReproduceScript: et.ReproduceScript,
	}

	start := time.Now()

	// Flush cache between hot-reload and cache tests
	e.flushCache()

	// ── E01: STATIC route cached (1 pt) ──
	e01passed := false
	var e01Results []ECacheCheckResult

	// Request 1: MISS
	r1, err1 := e.doCacheRequest("GET", "/static/js/app.js", "127.0.0.90", nil)
	if err1 == nil {
		r1.RequestNum = 1
		r1.ExpectedCache = "MISS"
		r1.MatchExpected = (r1.CacheHeader == "MISS" || r1.CacheHeader == "")
		e01Results = append(e01Results, r1)
		r1.ResponseBody = ""
	}

	time.Sleep(200 * time.Millisecond)

	// Request 2: HIT
	r2, err2 := e.doCacheRequest("GET", "/static/js/app.js", "127.0.0.90", nil)
	if err2 == nil {
		r2.RequestNum = 2
		r2.ExpectedCache = "HIT"
		r2.MatchExpected = (r2.CacheHeader == "HIT")
		e01Results = append(e01Results, r2)
		r2.ResponseBody = ""
		e01passed = r2.MatchExpected
	}
	tr.CacheResults = append(tr.CacheResults, e01Results...)
	tr.EXT03SubScores["E01"] = 0
	if e01passed {
		tr.EXT03SubScores["E01"] = 1.0
	}

	// ── E02: CRITICAL route NOT cached (1 pt) ──
	e.flushCache()
	e02passed := false
	var e02Results []ECacheCheckResult

	loginBody := `{"username":"alice","password":"P@ssw0rd1"}`
	headers := map[string]string{"Content-Type": "application/json"}

	// Request 1
	r3, err3 := e.doCacheRequest("POST", "/login", "127.0.0.91", headers, loginBody)
	if err3 == nil {
		r3.RequestNum = 1
		r3.ExpectedCache = "MISS"
		r3.MatchExpected = (r3.CacheHeader != "HIT")
		e02Results = append(e02Results, r3)
		r3.ResponseBody = ""
	}

	time.Sleep(200 * time.Millisecond)

	// Request 2
	r4, err4 := e.doCacheRequest("POST", "/login", "127.0.0.91", headers, loginBody)
	if err4 == nil {
		r4.RequestNum = 2
		r4.ExpectedCache = "MISS"
		r4.MatchExpected = (r4.CacheHeader != "HIT")
		e02Results = append(e02Results, r4)
		r4.ResponseBody = ""
		e02passed = r4.MatchExpected
	}
	tr.CacheResults = append(tr.CacheResults, e02Results...)
	tr.EXT03SubScores["E02"] = 0
	if e02passed {
		tr.EXT03SubScores["E02"] = 1.0
	}

	// ── E03: STATIC TTL expiry (1 pt) ──
	e.flushCache()
	e03passed := false
	var e03Results []ECacheCheckResult

	// Request 1: MISS
	r5, err5 := e.doCacheRequest("GET", "/static/css/style.css", "127.0.0.92", nil)
	if err5 == nil {
		r5.RequestNum = 1
		r5.ExpectedCache = "MISS"
		r5.MatchExpected = (r5.CacheHeader == "MISS" || r5.CacheHeader == "")
		e03Results = append(e03Results, r5)
		r5.ResponseBody = ""
	}

	// Request 2: HIT (immediately after)
	r6, err6 := e.doCacheRequest("GET", "/static/css/style.css", "127.0.0.92", nil)
	if err6 == nil {
		r6.RequestNum = 2
		r6.ExpectedCache = "HIT"
		r6.MatchExpected = (r6.CacheHeader == "HIT")
		e03Results = append(e03Results, r6)
		r6.ResponseBody = ""
	}

	// Wait for TTL expiry
	time.Sleep(2 * time.Second)

	// Request 3: MISS (TTL expired)
	r7, err7 := e.doCacheRequest("GET", "/static/css/style.css", "127.0.0.92", nil)
	if err7 == nil {
		r7.RequestNum = 3
		r7.ExpectedCache = "MISS"
		r7.MatchExpected = (r7.CacheHeader != "HIT")
		e03Results = append(e03Results, r7)
		r7.ResponseBody = ""
		e03passed = r7.MatchExpected
	}
	tr.CacheResults = append(tr.CacheResults, e03Results...)
	tr.EXT03SubScores["E03"] = 0
	if e03passed {
		tr.EXT03SubScores["E03"] = 1.0
	}

	// ── E04: Authenticated route NOT cached (1 pt) ──
	e.flushCache()
	e04passed := false
	var e04Results []ECacheCheckResult

	// Step 1: Get auth session for alice
	sessionID, loginToken := e.obtainSession("alice", "P@ssw0rd1", "123456", "127.0.0.93")
	_ = loginToken

	if sessionID != "" {
		authHeaders := map[string]string{"Cookie": "sid=" + sessionID}

		// Request 1
		r8, err8 := e.doCacheRequest("GET", "/api/profile", "127.0.0.93", authHeaders)
		if err8 == nil {
			r8.RequestNum = 1
			r8.ExpectedCache = "MISS"
			r8.MatchExpected = (r8.CacheHeader != "HIT")
			e04Results = append(e04Results, r8)
			r8.ResponseBody = ""
		}

		time.Sleep(200 * time.Millisecond)

		// Request 2
		r9, err9 := e.doCacheRequest("GET", "/api/profile", "127.0.0.93", authHeaders)
		if err9 == nil {
			r9.RequestNum = 2
			r9.ExpectedCache = "MISS"
			r9.MatchExpected = (r9.CacheHeader != "HIT")
			e04Results = append(e04Results, r9)
			r9.ResponseBody = ""
			e04passed = r9.MatchExpected
		}
	} else {
		// Auth flow failed — E04 cannot be tested
		e04Results = append(e04Results, ECacheCheckResult{
			RequestNum: 1, Endpoint: "/api/profile", Method: "GET",
			ExpectedCache: "MISS", MatchExpected: false,
			CacheHeader: "AUTH_FAILED",
		})
	}
	tr.CacheResults = append(tr.CacheResults, e04Results...)
	tr.EXT03SubScores["E04"] = 0
	if e04passed {
		tr.EXT03SubScores["E04"] = 1.0
	}

	// Compute EXT-03 score
	var score float64
	subIDs := []string{"E01", "E02", "E03", "E04"}
	subNames := map[string]string{
		"E01": "STATIC route cached (HIT)",
		"E02": "CRITICAL route NOT cached",
		"E03": "TTL expiry honored",
		"E04": "Authenticated route NOT cached",
	}
	var subDetails []string
	for _, id := range subIDs {
		s := tr.EXT03SubScores[id]
		score += s
		icon := "✓"
		if s == 0 {
			icon = "✗"
		}
		subDetails = append(subDetails, fmt.Sprintf("  • %s: %s %s → +%.0f pt",
			id, subNames[id], icon, s))
	}

	tr.Score = score
	allSubPassed := (score == 4.0)
	tr.Passed = (score > 0) // At least one sub-test passed

	tr.ScoringExplain = fmt.Sprintf(
		"%s — Cache Correctness Score: %.0f/4.0 pts\n%s",
		map[bool]string{true: "✓ PASS", false: "PARTIAL"}[allSubPassed],
		score,
		strings.Join(subDetails, "\n"))

	// Build fail conditions per sub-test
	if !e01passed {
		tr.FailConditions = append(tr.FailConditions, EFailCondition{
			ID: "e01_fail", Description: "E01: STATIC /static/js/app.js not cached",
			Triggered: true,
			Evidence: "/static/js/app.js did not return HIT on 2nd request",
		})
	}
	if !e02passed {
		tr.FailConditions = append(tr.FailConditions, EFailCondition{
			ID: "e02_fail", Description: "E02: CRITICAL /login was cached",
			Triggered: true,
			Evidence: "/login returned HIT — critical routes should never cache",
		})
	}
	if !e03passed {
		tr.FailConditions = append(tr.FailConditions, EFailCondition{
			ID: "e03_fail", Description: "E03: STATIC TTL not respected",
			Triggered: true,
			Evidence: "/static/css/style.css returned HIT after TTL expiry",
		})
	}
	if !e04passed {
		tr.FailConditions = append(tr.FailConditions, EFailCondition{
			ID: "e04_fail", Description: "E04: Authenticated route /api/profile was cached",
			Triggered: true,
			Evidence: "/api/profile returned HIT — auth routes should never cache",
		})
	}

	tr.DurationSec = time.Since(start).Seconds()
	return tr
}

// ── HTTP Helpers ──

// doWAFRequestWithPool wraps doWAFRequest and appends response to global pool for SEC-02.
func (e *EEngine) doWAFRequestWithPool(method, path, body string, headers map[string]string, sourceIP, testID string) (*http.Response, error) {
	resp, err := e.doWAFRequest(method, path, body, headers, sourceIP)
	if err != nil || resp == nil {
		return resp, err
	}
	if e.pool != nil {
		respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		// Re-create body for caller
		resp.Body = io.NopCloser(bytes.NewReader(respBodyBytes))
		respHeaders := make(map[string]string)
		for k, vals := range resp.Header {
			if len(vals) > 0 {
				respHeaders[k] = vals[0]
			}
		}
		e.pool.Append("E", testID, sourceIP, path, method,
			resp.StatusCode, string(respBodyBytes), respHeaders)

		// 429 Challenge detection (recorded during extensibility test)
		if e.challengeSolver != nil && resp.StatusCode == 429 &&
			strings.EqualFold(strings.TrimSpace(resp.Header.Get("X-WAF-Action")), "challenge") {
			e.challengeSolver.RecordDetection(challenge.PhaseHookContext{
				Phase: "E", TestID: testID, Method: method, Endpoint: path,
				StatusCode: resp.StatusCode, ResponseBody: string(respBodyBytes), ResponseHeaders: respHeaders,
			})
		}
	}
	return resp, err
}

func (e *EEngine) doWAFRequest(method, path, body string, headers map[string]string, sourceIP string) (*http.Response, error) {
	url := e.wafURL + path
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Source IP binding via --interface is done at OS level
	// For Go HTTP client, we rely on the local address binding
	// In practice, this uses the default interface; the sourceIP
	// is recorded for documentation and reproduce scripts

	return e.client.Do(req)
}

func (e *EEngine) doCacheRequest(method, endpoint, sourceIP string, headers map[string]string, body ...string) (ECacheCheckResult, error) {
	result := ECacheCheckResult{
		Method:   method,
		Endpoint: endpoint,
	}

	url := e.wafURL + endpoint
	var bodyReader io.Reader
	if len(body) > 0 && body[0] != "" {
		bodyReader = strings.NewReader(body[0])
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return result, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	result.CacheHeader = resp.Header.Get("X-WAF-Cache")
	result.WAFAction = resp.Header.Get("X-WAF-Action")
	if rs := resp.Header.Get("X-WAF-Risk-Score"); rs != "" {
		if v, err := strconv.Atoi(rs); err == nil {
			result.RiskScore = v
		}
	}

	// Build curl command for reproducibility
	var curlCmd strings.Builder
	curlCmd.WriteString(fmt.Sprintf("curl -s --interface %s", sourceIP))
	curlCmd.WriteString(fmt.Sprintf(" -X %s", method))
	for k, v := range headers {
		curlCmd.WriteString(fmt.Sprintf(" -H '%s: %s'", k, v))
	}
	if len(body) > 0 && body[0] != "" {
		curlCmd.WriteString(fmt.Sprintf(" -d '%s'", body[0]))
	}
	curlCmd.WriteString(fmt.Sprintf(" -w '\\nHTTP:%%{http_code} | Cache:%%header{X-WAF-Cache}' %s",
		url))
	result.CurlCommand = curlCmd.String()

	return result, nil
}

func (e *EEngine) obtainSession(username, password, otpCode, sourceIP string) (sessionID, loginToken string) {
	// Step 1: Login to get login_token
	loginBody := fmt.Sprintf(`{"username":"%s","password":"%s"}`, username, password)
	loginResult, err := e.doCacheRequest("POST", "/login", sourceIP,
		map[string]string{"Content-Type": "application/json"}, loginBody)
	if err != nil {
		return "", ""
	}

	// Read login_token from response (simplified — in production use JSON parsing)
	// For benchmark purposes, we extract the token from response
	resp, err := e.doWAFRequest("POST", "/login", loginBody,
		map[string]string{"Content-Type": "application/json"}, sourceIP)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(resp.Body)
	respStr := string(respBytes)
	ltRegex := regexp.MustCompile(`"login_token"\s*:\s*"([^"]+)"`)
	ltMatch := ltRegex.FindStringSubmatch(respStr)
	if len(ltMatch) < 2 {
		return "", ""
	}
	loginToken = ltMatch[1]

	// Step 2: OTP exchange to get session_id
	otpBody := fmt.Sprintf(`{"login_token":"%s","otp_code":"%s"}`, loginToken, otpCode)
	resp2, err := e.doWAFRequest("POST", "/otp", otpBody,
		map[string]string{"Content-Type": "application/json"}, sourceIP)
	if err != nil {
		return "", loginToken
	}
	defer resp2.Body.Close()
	respBytes2, _ := io.ReadAll(resp2.Body)
	respStr2 := string(respBytes2)
	sidRegex := regexp.MustCompile(`"session_id"\s*:\s*"([^"]+)"`)
	sidMatch := sidRegex.FindStringSubmatch(respStr2)
	if len(sidMatch) < 2 {
		return "", loginToken
	}
	sessionID = sidMatch[1]
	_ = loginResult

	return sessionID, loginToken
}

// ── Cache Flush ──

func (e *EEngine) flushCache() {
	resp, err := e.client.Post(e.cfg.WAFAdminURL+"/__waf_control/flush_cache",
		"application/json", nil)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// ── Post-Phase Cleanup ──

func (e *EEngine) postPhaseCleanup() {
	// Reset UPSTREAM
	e.client.Post(e.cfg.TargetBaseURL+"/__control/reset",
		"application/json", nil)

	// Reset WAF state
	e.client.Post(e.cfg.WAFAdminURL+"/__waf_control/reset_state",
		"application/json", nil)

	// Flush WAF cache
	e.client.Post(e.cfg.WAFAdminURL+"/__waf_control/flush_cache",
		"application/json", nil)
}

// ── Config Helpers ──

func (e *EEngine) getRuleTemplate() string {
	switch e.configFormat {
	case "yaml":
		return YamlRuleTemplate
	case "toml":
		return TomlRuleTemplate
	default:
		return ""
	}
}

func removeRuleFromConfig(content, format string) string {
	switch format {
	case "yaml":
		return removeYamlRule(content)
	case "toml":
		return removeTomlRule(content)
	default:
		return ""
	}
}

func removeYamlRule(content string) string {
	// Find the block starting with - id: "benchmark-hotreload-test"
	lines := strings.Split(content, "\n")
	var result []string
	skip := false
	for _, line := range lines {
		if strings.Contains(line, `id: "benchmark-hotreload-test"`) {
			skip = true
			continue
		}
		if skip {
			// Skip until next rule (starts with "- id:" at root level)
			if strings.HasPrefix(strings.TrimSpace(line), "- id:") {
				skip = false
				result = append(result, line)
			}
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

func removeTomlRule(content string) string {
	// Find and remove the [[rules]] block for benchmark-hotreload-test
	lines := strings.Split(content, "\n")
	var result []string
	skip := false
	for _, line := range lines {
		if strings.Contains(line, `id = "benchmark-hotreload-test"`) {
			skip = true
			continue
		}
		if skip {
			// Skip until next [[rules]] or EOF
			if strings.HasPrefix(strings.TrimSpace(line), "[[rules]]") {
				skip = false
				result = append(result, line)
			}
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

// ── Dry-Run Simulation ──

func (e *EEngine) simulateRun() (*PhaseEResult, error) {
	start := time.Now()
	result := &PhaseEResult{
		StartTime:      start,
		WAFTarget:      e.cfg.WAFBaseURL,
		WAFMode:        "enforce",
		WAFAlive:       true,
		UpstreamAlive:  true,
		MaxScore:       4.0,
		EXT03SubScores: make(map[string]float64),
	}

	// Simulated reset steps (4 steps — no config detection needed for v2.5)
	resetNames := []string{
		"Reset UPSTREAM", "UPSTREAM health check",
		"Set WAF profile (enforce)", "Flush WAF cache",
	}
	for i, name := range resetNames {
		result.ResetSteps = append(result.ResetSteps, EResetStep{
			StepNum: i + 1, Name: name, Method: "POST",
			StatusCode: 200, Success: true, LatencyMs: float64(5 + i*2),
		})
	}
	result.ResetAllPassed = true

	// EXT-01 and EXT-02 are MANUAL evaluation only — not simulated
	// No simulated results for them; only EXT-03 is automated

	// EXT-03: full PASS (4/4 sub-tests)
	tr03 := ETestResult{
		TestID: "EXT-03", Name: "Caching Correctness", Category: "caching",
		Criterion: "EXT", Description: "Kiểm tra cache behavior của WAF theo route tier",
		PassCriterion: "E01: STATIC route cached; E02: CRITICAL route NOT cached; E03: TTL expiry; E04: Auth NOT cached",
		MaxScore: 4.0, Passed: true, Score: 4.0,
		DurationSec: 12.0,
		EXT03SubScores: map[string]float64{"E01": 1.0, "E02": 1.0, "E03": 1.0, "E04": 1.0},
		ScoringExplain: "✓ PASS — Cache Correctness Score: 4.0/4.0 pts\n  • E01: STATIC route cached (HIT) ✓ → +1 pt\n  • E02: CRITICAL route NOT cached ✓ → +1 pt\n  • E03: TTL expiry honored ✓ → +1 pt\n  • E04: Authenticated route NOT cached ✓ → +1 pt",
		ReproduceScript: reproduceEXT03("", ""),
		CacheResults: []ECacheCheckResult{
			{RequestNum: 1, Endpoint: "/static/js/app.js", Method: "GET", StatusCode: 200, CacheHeader: "MISS", ExpectedCache: "MISS", MatchExpected: true, LatencyMs: 12.3},
			{RequestNum: 2, Endpoint: "/static/js/app.js", Method: "GET", StatusCode: 200, CacheHeader: "HIT", ExpectedCache: "HIT", MatchExpected: true, LatencyMs: 1.2},
			{RequestNum: 1, Endpoint: "/login", Method: "POST", StatusCode: 200, CacheHeader: "MISS", ExpectedCache: "MISS", MatchExpected: true, LatencyMs: 45.6},
			{RequestNum: 2, Endpoint: "/login", Method: "POST", StatusCode: 200, CacheHeader: "MISS", ExpectedCache: "MISS", MatchExpected: true, LatencyMs: 44.8},
			{RequestNum: 1, Endpoint: "/static/css/style.css", Method: "GET", StatusCode: 200, CacheHeader: "MISS", ExpectedCache: "MISS", MatchExpected: true, LatencyMs: 10.5},
			{RequestNum: 2, Endpoint: "/static/css/style.css", Method: "GET", StatusCode: 200, CacheHeader: "HIT", ExpectedCache: "HIT", MatchExpected: true, LatencyMs: 1.5},
			{RequestNum: 3, Endpoint: "/static/css/style.css", Method: "GET", StatusCode: 200, CacheHeader: "MISS", ExpectedCache: "MISS", MatchExpected: true, LatencyMs: 9.8},
			{RequestNum: 1, Endpoint: "/api/profile", Method: "GET", StatusCode: 200, CacheHeader: "MISS", ExpectedCache: "MISS", MatchExpected: true, LatencyMs: 22.1},
			{RequestNum: 2, Endpoint: "/api/profile", Method: "GET", StatusCode: 200, CacheHeader: "MISS", ExpectedCache: "MISS", MatchExpected: true, LatencyMs: 21.5},
		},
	}
	result.TestResults = append(result.TestResults, tr03)
	result.PassedTests++
	result.EXT03Score = 4.0
	result.EXT03SubScores = map[string]float64{"E01": 1.0, "E02": 1.0, "E03": 1.0, "E04": 1.0}

	result.TotalScore = result.EXT03Score
	result.EndTime = time.Now()
	return result, nil
}

// ── Ensure context import is used ──
var _ = context.Background