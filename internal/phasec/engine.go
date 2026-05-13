package phasec

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waf-hackathon/benchmark-new/internal/challenge"
	"github.com/waf-hackathon/benchmark-new/internal/crossphase"
)

// ── Engine ──

type CEngine struct {
	cfg           *CConfigWrapper
	pool          *crossphase.GlobalResponsePool // SEC-02 response collector
	challengeSolver *challenge.Solver            // 429 challenge lifecycle handler
	targetURL     string
	wafURL        string
	wafAdminURL   string
	controlSecret string
	client        *http.Client
	dryRun        bool
	thresholds    PhaseCThresholds
}

type CConfigWrapper struct {
	TargetBaseURL string
	WAFBaseURL    string
	WAFAdminURL   string
	ControlSecret string
	TimeoutSec    int
	Verbose       bool
	DryRun        bool
}

func NewCEngine(cfg *CConfigWrapper, pool *crossphase.GlobalResponsePool, chSolver *challenge.Solver) *CEngine {
	return &CEngine{
		cfg:           cfg,
		pool:          pool,
		challengeSolver: chSolver,
		targetURL:     cfg.TargetBaseURL,
		wafURL:        cfg.WAFBaseURL,
		wafAdminURL:   cfg.WAFAdminURL,
		controlSecret: cfg.ControlSecret,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSec) * time.Second,
		},
		dryRun:     cfg.DryRun,
		thresholds: DefaultThresholds(),
	}
}

// Run executes the full Phase C workflow.
func (e *CEngine) Run() (*PhaseCResult, error) {
	if e.dryRun {
		return e.simulateRun(), nil
	}
	return e.realRun()
}

// ── Real HTTP Execution ──

func (e *CEngine) realRun() (*PhaseCResult, error) {
	start := time.Now()

	// Detect resource tier from environment
	tier := DetectResourceTier()
	tc := GetTierConfig(tier)

	result := &PhaseCResult{
		StartTime:    start,
		WAFTarget:    e.cfg.WAFBaseURL,
		WAFMode:      "enforce",
		ResourceTier: tier,
		TierConfig:   tc,
		Scores:       make(map[string]ScoreDetail),
		PhaseCMax:    20.0,
	}

	if e.cfg.Verbose {
		fmt.Printf("🔧 Resource Tier: %s (WAF: %dC/%.0fGB, SLA: %d RPS)\n",
			tier, tc.WAFCores, float64(tc.WAFMemoryMax)/(1024*1024*1024), tc.SLA_RPS)
	}

	// 1. Pre-flight: check WAF & upstream health
	result.WAFCheckPassed = e.checkWAFAlive()
	if !result.WAFCheckPassed {
		result.EndTime = time.Now()
		return result, fmt.Errorf("WAF not reachable after retries — Phase C aborted")
	}
	result.UpstreamCheckOK = e.checkUpstreamHealth()
	if !result.UpstreamCheckOK {
		result.EndTime = time.Now()
		return result, fmt.Errorf("UPSTREAM not healthy — Phase C aborted")
	}

	// Get WAF PID
	result.WAFPID = e.getWAFPid()
	result.MemoryMonitorOK = result.WAFPID != ""

	// Initialize System Health Profiler
	profiler := NewSystemHealthProfiler(ProfilerConfig{
		WAFPID: result.WAFPID,
		Tier:   tier,
	})
	result.ProfilerActive = profiler.IsActive()
	if result.ProfilerActive {
		profiler.Start()
	}

	// Check cgroups v2 availability
	result.CgroupsActive = CgroupsV2Available()
	result.PinningVerified = result.CgroupsActive

	// 2. Full Reset Sequence (UPSTREAM first, then WAF)
	result.ResetSteps = e.fullResetSequence()
	result.ResetAllPassed = true
	for _, s := range result.ResetSteps {
		if !s.Success && s.StepNum != 4 { // Step 4 (flush_cache) non-fatal
			result.ResetAllPassed = false
			break
		}
	}
	if !result.ResetAllPassed {
		result.EndTime = time.Now()
		return result, nil
	}

	// 3. Baseline Latency Measurement (direct to UPSTREAM :9000)
	baseline, err := e.measureBaselineLatency()
	if err != nil {
		result.BaselineFailed = true
		result.BaselineFailReason = err.Error()
		if e.cfg.Verbose {
			fmt.Printf("⚠️  Baseline measurement failed: %v — using WAF latency directly\n", err)
		}
		result.Baseline = &BaselineLatency{} // empty
	} else {
		result.Baseline = baseline
	}

	// 4. WAF Latency Measurement (through WAF :8080)
	wafLat, err := e.measureWAFLatency()
	if err != nil {
		if e.cfg.Verbose {
			fmt.Printf("⚠️  WAF latency measurement failed: %v\n", err)
		}
	} else {
		// Compute overheads against baseline
		result.WAFLatency = e.computeOverheads(wafLat, result.Baseline)
	}

	// 5. Load Test Steps (tier-adjusted)
	steps := GetTierAdjustedLoadTestSteps(tier)
	for _, sc := range steps {
		if result.WAFCrashed {
			break
		}
		stepResult := e.runLoadTestStep(&sc, result)
		result.LoadTestSteps = append(result.LoadTestSteps, stepResult)

		// Aggregate FP counts
		result.FPCount += stepResult.FalsePositiveCount
		result.CollateralCount += stepResult.CollateralCount

		if stepResult.ErrorCount < 0 { // crash detected
			result.WAFCrashed = true
			result.CrashStep = sc.StepNum
			break
		}
	}

	// 6. False Positive Rate
	totalLegit := 0
	for _, s := range result.LoadTestSteps {
		totalLegit += s.TotalRequests
	}
	if totalLegit > 0 {
		result.FPRate = float64(result.FPCount) / float64(totalLegit)
	}

	// 6b. Stop profiler and collect noise report
	if result.ProfilerActive {
		result.NoiseReport = profiler.Stop()
		if peakHWM := profiler.GetPeakHWM(); peakHWM > 0 {
			for i := range result.LoadTestSteps {
				if peakHWM > result.LoadTestSteps[i].MemoryPeakMB {
					result.LoadTestSteps[i].MemoryPeakMB = peakHWM
				}
			}
		}
	}

	// 7. Compute scoring
	e.computeScores(result)

	result.EndTime = time.Now()
	return result, nil
}

// ── Pre-flight Checks ──

func (e *CEngine) checkWAFAlive() bool {
	for i := 0; i < 3; i++ {
		resp, err := e.client.Get(e.cfg.WAFBaseURL + "/health")
		if err == nil && resp.StatusCode < 500 {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}
		if i < 2 {
			time.Sleep(10 * time.Second)
		}
	}
	return false
}

func (e *CEngine) checkUpstreamHealth() bool {
	for i := 0; i < 3; i++ {
		resp, err := e.client.Get(e.cfg.TargetBaseURL + "/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return true
		}
		if resp != nil {
			resp.Body.Close()
		}
		if i < 2 {
			time.Sleep(5 * time.Second)
		}
	}
	return false
}

func (e *CEngine) getWAFPid() string {
	// Try pgrep first, then pidof
	cmd := exec.Command("pgrep", "-f", "waf")
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		pid := strings.TrimSpace(strings.Split(string(out), "\n")[0])
		if pid != "" {
			return pid
		}
	}

	cmd = exec.Command("pidof", "waf")
	out, err = cmd.Output()
	if err == nil && len(out) > 0 {
		pid := strings.TrimSpace(string(out))
		if pid != "" {
			return pid
		}
	}

	return ""
}

// ── Full Reset Sequence ──

func (e *CEngine) fullResetSequence() []CResetStep {
	var steps []CResetStep

	doStep := func(num int, name, method, url string, body string, fatal bool) CResetStep {
		rs := CResetStep{
			StepNum: num,
			Name:    name,
			Method:  method,
			URL:     url,
		}
		t0 := time.Now()

		req, err := http.NewRequest(method, url, bytes.NewReader([]byte(body)))
		if err != nil {
			rs.Error = err.Error()
			rs.LatencyMs = time.Since(t0).Seconds() * 1000
			return rs
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
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
		rs.LatencyMs = time.Since(t0).Seconds() * 1000

		if err != nil {
			rs.Error = err.Error()
			rs.Success = false
			return rs
		}
		defer resp.Body.Close()
		rs.StatusCode = resp.StatusCode

		// Step 4 (flush_cache): accept 200 or 501 (not implemented)
		if num == 4 && (resp.StatusCode == 200 || resp.StatusCode == 501) {
			rs.Success = true
			return rs
		}

		if resp.StatusCode == 200 {
			rs.Success = true
		} else {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			rs.Error = fmt.Sprintf("status %d: %s", resp.StatusCode, string(respBody))
			rs.Success = false
		}
		return rs
	}

	// Step 1: POST /__control/reset → UPSTREAM reset (UPSTREAM FIRST per v2.5)
	steps = append(steps, doStep(1,
		"Reset UPSTREAM",
		"POST",
		e.cfg.TargetBaseURL+"/__control/reset",
		"",
		true))

	// Step 2: GET /health → UPSTREAM health check
	steps = append(steps, doStep(2,
		"UPSTREAM health check",
		"GET",
		e.cfg.TargetBaseURL+"/health",
		"",
		true))

	// Step 3: POST /__waf_control/set_profile → WAF mode enforce
	steps = append(steps, doStep(3,
		"Set WAF profile (enforce)",
		"POST",
		e.cfg.WAFAdminURL+"/__waf_control/set_profile",
		`{"scope":"all","mode":"enforce"}`,
		true))

	// Step 4: POST /__waf_control/flush_cache → WAF cache clear (non-fatal)
	steps = append(steps, doStep(4,
		"Flush WAF cache",
		"POST",
		e.cfg.WAFAdminURL+"/__waf_control/flush_cache",
		"",
		false))

	// Step 5: POST /__waf_control/reset_state → WAF state clean
	steps = append(steps, doStep(5,
		"Reset WAF state",
		"POST",
		e.cfg.WAFAdminURL+"/__waf_control/reset_state",
		"",
		true))

	return steps
}

// ── Baseline Latency Measurement (Direct to UPSTREAM :9000) ──

func (e *CEngine) measureBaselineLatency() (*BaselineLatency, error) {
	classes := GetEndpointClasses()
	bl := &BaselineLatency{}

	for _, cls := range classes {
		lc := LatencyClass{
			Name:      cls.Name,
			Endpoints: cls.Endpoints,
			Samples:   cls.Samples,
		}

		var latencies []float64
		perEndpoint := cls.Samples / len(cls.Endpoints)
		if perEndpoint < 1 {
			perEndpoint = 1
		}

		for _, ep := range cls.Endpoints {
			for i := 0; i < perEndpoint; i++ {
				t0 := time.Now()
				resp, err := e.client.Get(e.cfg.TargetBaseURL + ep)
				lat := time.Since(t0).Seconds() * 1000
				if err == nil {
					latencies = append(latencies, lat)
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				} else {
					latencies = append(latencies, lat)
				}
			}
		}

		if len(latencies) == 0 {
			continue
		}

		sort.Float64s(latencies)
		n := len(latencies)
		lc.P50Ms = latencies[n*50/100]
		lc.P99Ms = latencies[n*99/100]

		var sum float64
		for _, l := range latencies {
			sum += l
		}
		lc.AvgMs = sum / float64(n)

		bl.Classes = append(bl.Classes, lc)
		bl.TotalSamples += cls.Samples
	}

	if len(bl.Classes) == 0 {
		return bl, fmt.Errorf("failed to collect baseline measurements")
	}
	return bl, nil
}

// ── WAF Latency Measurement (Through WAF :8080) ──

func (e *CEngine) measureWAFLatency() (*WAFLatencyResult, error) {
	classes := GetEndpointClasses()
	wl := &WAFLatencyResult{}

	for _, cls := range classes {
		wlc := WAFLatencyClass{
			Name:      cls.Name,
			Endpoints: cls.Endpoints,
			Samples:   cls.Samples,
		}

		var latencies []float64
		perEndpoint := cls.Samples / len(cls.Endpoints)
		if perEndpoint < 1 {
			perEndpoint = 1
		}

		for _, ep := range cls.Endpoints {
			for i := 0; i < perEndpoint; i++ {
				t0 := time.Now()
				resp, err := e.client.Get(e.cfg.WAFBaseURL + ep)
				lat := time.Since(t0).Seconds() * 1000
				if err == nil {
					latencies = append(latencies, lat)
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				} else {
					latencies = append(latencies, lat)
				}
			}
		}

		if len(latencies) == 0 {
			continue
		}

		sort.Float64s(latencies)
		n := len(latencies)
		wlc.P50Ms = latencies[n*50/100]
		wlc.P99Ms = latencies[n*99/100]

		var sum float64
		for _, l := range latencies {
			sum += l
		}
		wlc.AvgMs = sum / float64(n)

		wl.Classes = append(wl.Classes, wlc)
		wl.TotalSamples += cls.Samples
	}

	return wl, nil
}

// computeOverheads calculates WAF overhead relative to baseline.
func (e *CEngine) computeOverheads(wafLat *WAFLatencyResult, baseline *BaselineLatency) *WAFLatencyResult {
	if baseline == nil || len(baseline.Classes) == 0 {
		// No baseline — set all overheads to WAF latency (treat baseline as 0)
		for i := range wafLat.Classes {
			wc := &wafLat.Classes[i]
			wc.OverheadP50 = wc.P50Ms
			wc.OverheadP99 = wc.P99Ms
			if wc.AvgMs > 0 {
				wc.OverheadPct = 100.0
			}
		}
		return wafLat
	}

	baselineByClass := make(map[string]*LatencyClass)
	for i := range baseline.Classes {
		baselineByClass[baseline.Classes[i].Name] = &baseline.Classes[i]
	}

	for i := range wafLat.Classes {
		wc := &wafLat.Classes[i]
		if bl, ok := baselineByClass[wc.Name]; ok {
			wc.OverheadP50 = wc.P50Ms - bl.P50Ms
			if wc.OverheadP50 < 0 {
				wc.OverheadP50 = 0
			}
			wc.OverheadP99 = wc.P99Ms - bl.P99Ms
			if wc.OverheadP99 < 0 {
				wc.OverheadP99 = 0
			}
			if bl.AvgMs > 0 {
				wc.OverheadPct = ((wc.AvgMs - bl.AvgMs) / bl.AvgMs) * 100.0
				if wc.OverheadPct < 0 {
					wc.OverheadPct = 0
				}
			}
		} else {
			wc.OverheadP50 = wc.P50Ms
			wc.OverheadP99 = wc.P99Ms
			wc.OverheadPct = 100.0
		}
	}
	return wafLat
}

// ── Load Test Step Execution ──

func (e *CEngine) runLoadTestStep(sc *LoadTestConfig, result *PhaseCResult) LoadTestStepResult {
	step := LoadTestStepResult{
		StepNum:     sc.StepNum,
		TargetRPS:   sc.TargetRPS,
		DurationSec: sc.DurationSec,
	}

	// Worker pool config
	numWorkers := 10
	mix := DefaultTrafficMix()
	sourceIPs := GetSourceIPPool()
	userAgents := GetUserAgents()
	acceptLangs := GetAcceptLanguages()
	goldenPath := GetGoldenPath()
	suspiciousEndpoints := GetSuspiciousEndpoints()
	exploitPayloads := GetExploitPayloads()
	abusePatterns := GetAbusePatterns()
	ddosEndpoints := GetDDoSBurstEndpoints()

	// Concurrency-safe counters
	var totalReqs, successReqs, errorReqs, blockedReqs int64
	var fpCount, collateralCount int64
	var allLatencies []float64
	var latMu sync.Mutex
	var fpDetails []FPDetail
	var fpMu sync.Mutex
	crashDetected := int32(0)

	// DDoS burst scheduling
	ddosActive := int32(0)
	burstInterval := 10 * time.Second
	burstDuration := 2 * time.Second

	// Start DDoS burst scheduler
	stopDDoS := make(chan struct{})
	go func() {
		ticker := time.NewTicker(burstInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				atomic.StoreInt32(&ddosActive, 1)
				time.Sleep(burstDuration)
				atomic.StoreInt32(&ddosActive, 0)
			case <-stopDDoS:
				return
			}
		}
	}()

	// Memory sampler
	memStop := make(chan struct{})
	var memSamples []float64
	var memMu sync.Mutex
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if result.WAFPID != "" {
					memMB := e.sampleMemory(result.WAFPID)
					memMu.Lock()
					memSamples = append(memSamples, memMB)
					memMu.Unlock()
				}
			case <-memStop:
				return
			}
		}
	}()

	// Throughput time-series sampler
	tsStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		startTS := time.Now()
		for {
			select {
			case <-ticker.C:
				elapsed := time.Since(startTS).Seconds()
				current := atomic.LoadInt64(&totalReqs)
				rps := float64(current) / elapsed
				result.ThroughputTS = append(result.ThroughputTS, ThroughputPoint{
					TimestampSec: int(elapsed),
					ActualRPS:    rps,
				})
			case <-tsStop:
				return
			}
		}
	}()

	// Rate limiter: targetRPS requests per second across all workers
	interval := time.Second / time.Duration(sc.TargetRPS)
	if interval < time.Microsecond {
		interval = time.Microsecond
	}

	// End time for this step
	deadline := time.Now().Add(time.Duration(sc.DurationSec) * time.Second)

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerID)))
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for {
				if atomic.LoadInt32(&crashDetected) == 1 {
					return
				}
				if time.Now().After(deadline) {
					return
				}
				<-ticker.C

				// Check if DDoS burst is active
				inDDoS := atomic.LoadInt32(&ddosActive) == 1

				// Select traffic type based on mix ratios
				trafficType := selectTrafficType(rng, mix, inDDoS)
				method := "GET"
				endpoint := "/"
				body := ""
				contentType := ""

				switch trafficType {
				case TrafficLegitimate:
					step := goldenPath[rng.Intn(len(goldenPath))]
					method = step.Method
					endpoint = step.Endpoint
					if step.Body != "" {
						body = step.Body
						contentType = step.ContentType
					}
				case TrafficSuspicious:
					sus := suspiciousEndpoints[rng.Intn(len(suspiciousEndpoints))]
					method = sus.Method
					endpoint = sus.Endpoint
					if sus.Body != "" {
						body = sus.Body
						contentType = sus.ContentType
					}
				case TrafficExploit:
					exp := exploitPayloads[rng.Intn(len(exploitPayloads))]
					method = exp.Method
					if exp.Method == "GET" && exp.Payload != "" && !strings.Contains(exp.Payload, `{"`) {
						endpoint = exp.Endpoint + "?" + exp.Payload
					} else {
						endpoint = exp.Endpoint
						body = exp.Payload
						contentType = exp.ContentType
					}
				case TrafficAbuse:
					ab := abusePatterns[rng.Intn(len(abusePatterns))]
					method = ab.Method
					endpoint = ab.Endpoint
					if ab.Body != "" {
						body = ab.Body
						contentType = ab.ContentType
					}
				case TrafficDDoS:
					endpoint = ddosEndpoints[rng.Intn(len(ddosEndpoints))]
				}

				// Select source IP randomly
				sourceIP := sourceIPs[rng.Intn(len(sourceIPs))]

				// Build request
				url := e.cfg.WAFBaseURL + endpoint
				var reqBody io.Reader
				if body != "" {
					reqBody = bytes.NewReader([]byte(body))
				}

				req, err := http.NewRequest(method, url, reqBody)
				if err != nil {
					atomic.AddInt64(&errorReqs, 1)
					atomic.AddInt64(&totalReqs, 1)
					continue
				}

				// Rotate headers
				req.Header.Set("User-Agent", userAgents[rng.Intn(len(userAgents))])
				req.Header.Set("Accept-Language", acceptLangs[rng.Intn(len(acceptLangs))])
				if contentType != "" {
					req.Header.Set("Content-Type", contentType)
				}
				req.Header.Set("X-Forwarded-For", sourceIP)

				// Send request
				t0 := time.Now()
				resp, err := e.client.Do(req)
				lat := time.Since(t0).Seconds() * 1000

				atomic.AddInt64(&totalReqs, 1)

				if err != nil {
					atomic.AddInt64(&errorReqs, 1)
					latMu.Lock()
					allLatencies = append(allLatencies, lat)
					latMu.Unlock()

					// Check for crash (connection refused after WAF was alive)
					if strings.Contains(err.Error(), "connection refused") ||
						strings.Contains(err.Error(), "EOF") {
						atomic.StoreInt32(&crashDetected, 1)
						return
					}
					continue
				}

				respBodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
				resp.Body.Close()

				latMu.Lock()
				allLatencies = append(allLatencies, lat)
				latMu.Unlock()

				// Classify response
				statusCode := resp.StatusCode

				// Append to cross-phase response pool (SEC-02)
				if e.pool != nil {
					headers := make(map[string]string)
					for k, vals := range resp.Header {
						if len(vals) > 0 {
							headers[k] = vals[0]
						}
					}
					e.pool.Append("C", sc.Marker, sourceIP, endpoint, method, statusCode, string(respBodyBytes), headers)

					// 429 Challenge detection (recorded, not fully solved during load test)
					if e.challengeSolver != nil && statusCode == 429 &&
						strings.EqualFold(strings.TrimSpace(resp.Header.Get("X-WAF-Action")), "challenge") {
						e.challengeSolver.RecordDetection(challenge.PhaseHookContext{
							Phase: "C", TestID: sc.Marker, Method: method, Endpoint: endpoint,
							StatusCode: statusCode, ResponseBody: string(respBodyBytes), ResponseHeaders: headers,
						})
					}
				}

				wafAction := resp.Header.Get("X-WAF-Action")
				riskScore := 0
				if rs := resp.Header.Get("X-WAF-Risk-Score"); rs != "" {
					fmt.Sscanf(rs, "%d", &riskScore)
				}

				isBlocked := false
				if statusCode == 403 || wafAction == "block" || wafAction == "challenge" {
					isBlocked = true
					atomic.AddInt64(&blockedReqs, 1)
				}

				// Determine if this was a legitimate request
				isLegitimate := trafficType == TrafficLegitimate || trafficType == TrafficSuspicious

				if isBlocked && isLegitimate && !inDDoS {
					atomic.AddInt64(&fpCount, 1)
					fpMu.Lock()
					if len(fpDetails) < 20 {
						fpDetails = append(fpDetails, FPDetail{
							Endpoint:   endpoint,
							StatusCode: statusCode,
							ResponseBody: string(respBodyBytes),
							LatencyMs:  lat,
							WAFAction:  wafAction,
							RiskScore:  riskScore,
							DuringDDoS: inDDoS,
						})
					}
					fpMu.Unlock()
				}

				if isBlocked && isLegitimate && inDDoS {
					atomic.AddInt64(&collateralCount, 1)
				}

				if statusCode < 500 {
					atomic.AddInt64(&successReqs, 1)
				} else {
					atomic.AddInt64(&errorReqs, 1)
				}
			}
		}(w)
	}

	wg.Wait()
	close(stopDDoS)
	close(memStop)
	close(tsStop)

	// Compute metrics from collected data
	step.TotalRequests = int(atomic.LoadInt64(&totalReqs))
	step.SuccessCount = int(atomic.LoadInt64(&successReqs))
	step.ErrorCount = int(atomic.LoadInt64(&errorReqs))
	step.BlockedCount = int(atomic.LoadInt64(&blockedReqs))
	step.FalsePositiveCount = int(atomic.LoadInt64(&fpCount))
	step.CollateralCount = int(atomic.LoadInt64(&collateralCount))
	step.DDoSBurstsTriggered = sc.DurationSec / 10

	if step.TotalRequests > 0 {
		step.SuccessRate = float64(step.SuccessCount) / float64(step.TotalRequests)
		step.ErrorRate = float64(step.ErrorCount) / float64(step.TotalRequests)
		step.BlockedRate = float64(step.BlockedCount) / float64(step.TotalRequests)
	}

	step.ActualRPS = float64(step.TotalRequests) / float64(sc.DurationSec)

	// Latency percentiles
	if len(allLatencies) > 0 {
		sort.Float64s(allLatencies)
		n := len(allLatencies)
		step.P50Ms = allLatencies[n*50/100]
		step.P99Ms = allLatencies[n*99/100]
		step.MaxMs = allLatencies[n-1]

		// Round
		step.P50Ms = math.Round(step.P50Ms*1000) / 1000
		step.P99Ms = math.Round(step.P99Ms*1000) / 1000
		step.MaxMs = math.Round(step.MaxMs*1000) / 1000
	}

	// Memory peak
	step.MemoryPeakMB = 0
	memMu.Lock()
	for _, m := range memSamples {
		if m > step.MemoryPeakMB {
			step.MemoryPeakMB = m
		}
	}
	memMu.Unlock()

	// Save memory time series to result
	for i, m := range memSamples {
		result.MemoryTS = append(result.MemoryTS, MemoryPoint{
			TimestampSec: i * 5,
			MemoryMB:     m,
		})
	}

	// Save FP details to result
	result.FPDetails = append(result.FPDetails, fpDetails...)

	// Determine PASS/FAIL: error rate < 5%
	step.Passed = step.ErrorRate < e.thresholds.ErrorRateMax
	if !step.Passed {
		step.FailReason = fmt.Sprintf("error rate %.2f%% ≥ %.0f%%", step.ErrorRate*100, e.thresholds.ErrorRateMax*100)
	}

	// If crash detected, mark as not passed
	if atomic.LoadInt32(&crashDetected) == 1 {
		step.Passed = false
		step.FailReason = "WAF crashed during load test"
		step.ErrorCount = -1 // signal crash
	}

	return step
}

// ── Traffic Type Selection ──

func selectTrafficType(rng *rand.Rand, mix []TrafficMixEntry, inDDoS bool) TrafficType {
	if inDDoS {
		// During DDoS burst: 85% DDoS, 15% legitimate (mixed)
		if rng.Float64() < 0.85 {
			return TrafficDDoS
		}
		return TrafficLegitimate
	}

	roll := rng.Float64()
	cumulative := 0.0
	for _, m := range mix {
		cumulative += m.Ratio
		if roll < cumulative {
			return m.Type
		}
	}
	return TrafficLegitimate
}

// ── Memory Sampling ──

func (e *CEngine) sampleMemory(pid string) float64 {
	// Read VmRSS from /proc/{pid}/status
	data, err := exec.Command("sh", "-c",
		fmt.Sprintf("grep VmRSS /proc/%s/status 2>/dev/null | awk '{print $2}'", pid),
	).Output()
	if err != nil {
		return 0
	}
	var kb int
	fmt.Sscanf(string(data), "%d", &kb)
	return float64(kb) / 1024.0 // Convert KB to MB
}

// ── Scoring ──

func (e *CEngine) computeScores(result *PhaseCResult) {
	t := e.thresholds

	// PERF-01: p99 latency ≤ 5ms at 5000 RPS (Step 3)
	perf01 := ScoreDetail{
		MaxPoints: 10.0,
		Threshold: t.P99MaxMs,
	}
	for _, s := range result.LoadTestSteps {
		if s.TargetRPS == 5000 {
			perf01.Measured = s.P99Ms
			perf01.Pass = s.P99Ms <= t.P99MaxMs
			if perf01.Pass {
				perf01.Points = 10.0
				perf01.Explanation = fmt.Sprintf("p99 latency %.3fms ≤ %.0fms ✓", s.P99Ms, t.P99MaxMs)
			} else {
				perf01.Explanation = fmt.Sprintf("p99 latency %.3fms > %.0fms ✗", s.P99Ms, t.P99MaxMs)
			}
			break
		}
	}
	result.Scores["PERF-01"] = perf01

	// PERF-02: Sustained throughput ≥ 5000 RPS at 5000 RPS (Step 3)
	perf02 := ScoreDetail{
		MaxPoints: 5.0,
		Threshold: t.SustainedMinRPS,
	}
	for _, s := range result.LoadTestSteps {
		if s.TargetRPS == 5000 {
			perf02.Measured = s.ActualRPS
			perf02.Pass = s.ActualRPS >= t.SustainedMinRPS
			if perf02.Pass {
				perf02.Points = 5.0
				perf02.Explanation = fmt.Sprintf("actual throughput %.1f RPS ≥ %.0f RPS ✓", s.ActualRPS, t.SustainedMinRPS)
			} else {
				perf02.Explanation = fmt.Sprintf("actual throughput %.1f RPS < %.0f RPS ✗", s.ActualRPS, t.SustainedMinRPS)
			}
			break
		}
	}
	result.Scores["PERF-02"] = perf02

	// PERF-03: Peak RSS < 100MB
	perf03 := ScoreDetail{
		MaxPoints: 3.0,
		Threshold: t.MemoryMaxMB,
	}
	var peakMem float64
	for _, s := range result.LoadTestSteps {
		if s.MemoryPeakMB > peakMem {
			peakMem = s.MemoryPeakMB
		}
	}
	perf03.Measured = peakMem
	perf03.Pass = peakMem < t.MemoryMaxMB
	if perf03.Pass {
		perf03.Points = 3.0
		perf03.Explanation = fmt.Sprintf("peak RSS %.1f MB < %.0f MB ✓", peakMem, t.MemoryMaxMB)
	} else {
		perf03.Explanation = fmt.Sprintf("peak RSS %.1f MB ≥ %.0f MB ✗", peakMem, t.MemoryMaxMB)
	}
	result.Scores["PERF-03"] = perf03

	// PERF-04: No crash + error rate < 5% at 10000 RPS (Step 4)
	perf04 := ScoreDetail{
		MaxPoints: 2.0,
		Threshold: t.ErrorRateMax,
	}
	for _, s := range result.LoadTestSteps {
		if s.TargetRPS == 10000 {
			perf04.Measured = s.ErrorRate
			perf04.Pass = !result.WAFCrashed && s.ErrorRate < t.ErrorRateMax
			if perf04.Pass {
				perf04.Points = 2.0
				perf04.Explanation = fmt.Sprintf("no crash ✓ | error rate %.2f%% < %.0f%% ✓", s.ErrorRate*100, t.ErrorRateMax*100)
			} else if result.WAFCrashed {
				perf04.Explanation = "WAF crashed during step 4 ✗"
			} else {
				perf04.Explanation = fmt.Sprintf("error rate %.2f%% ≥ %.0f%% ✗", s.ErrorRate*100, t.ErrorRateMax*100)
			}
			break
		}
	}
	result.Scores["PERF-04"] = perf04

	// Total
	result.PhaseCTotal = perf01.Points + perf02.Points + perf03.Points + perf04.Points
}

// ── Dry Run / Simulation ──

func (e *CEngine) simulateRun() *PhaseCResult {
	now := time.Now()
	result := &PhaseCResult{
		StartTime:        now,
		WAFTarget:        e.cfg.WAFBaseURL,
		WAFMode:          "enforce",
		WAFCheckPassed:   true,
		UpstreamCheckOK:  true,
		WAFPID:           "12345",
		MemoryMonitorOK:  true,
		ResetAllPassed:   true,
		Scores:           make(map[string]ScoreDetail),
		PhaseCMax:        20.0,
	}

	// Simulated reset steps
	for i := 1; i <= 5; i++ {
		result.ResetSteps = append(result.ResetSteps, CResetStep{
			StepNum:    i,
			Name:       []string{"Reset UPSTREAM", "UPSTREAM health check", "Set WAF profile (enforce)", "Flush WAF cache", "Reset WAF state"}[i-1],
			Method:     []string{"POST", "GET", "POST", "POST", "POST"}[i-1],
			URL:        []string{"/__control/reset", "/health", "/__waf_control/set_profile", "/__waf_control/flush_cache", "/__waf_control/reset_state"}[i-1],
			StatusCode: 200,
			Success:    true,
			LatencyMs:  float64(5+i*2),
		})
	}

	// Simulated baseline
	result.Baseline = &BaselineLatency{
		TotalSamples: 1000,
		Classes: []LatencyClass{
			{Name: "critical", Endpoints: []string{"/login", "/deposit", "/withdraw"}, Samples: 250, P50Ms: 8.2, P99Ms: 15.4, AvgMs: 9.5},
			{Name: "high", Endpoints: []string{"/api/profile", "/game/list"}, Samples: 250, P50Ms: 5.7, P99Ms: 12.1, AvgMs: 6.8},
			{Name: "medium", Endpoints: []string{"/static/js/app.js", "/static/css/style.css", "/api/transactions"}, Samples: 250, P50Ms: 3.2, P99Ms: 8.9, AvgMs: 4.1},
			{Name: "catch_all", Endpoints: []string{"/health", "/"}, Samples: 250, P50Ms: 2.1, P99Ms: 6.3, AvgMs: 2.8},
		},
	}

	// Simulated WAF latency
	wafLat := &WAFLatencyResult{
		TotalSamples: 1000,
		Classes: []WAFLatencyClass{
			{Name: "critical", Endpoints: []string{"/login", "/deposit", "/withdraw"}, Samples: 250, P50Ms: 10.5, P99Ms: 18.2, AvgMs: 11.8, OverheadP50: 2.3, OverheadP99: 2.8, OverheadPct: 24.2},
			{Name: "high", Endpoints: []string{"/api/profile", "/game/list"}, Samples: 250, P50Ms: 7.1, P99Ms: 14.5, AvgMs: 8.3, OverheadP50: 1.4, OverheadP99: 2.4, OverheadPct: 22.1},
			{Name: "medium", Endpoints: []string{"/static/js/app.js", "/static/css/style.css", "/api/transactions"}, Samples: 250, P50Ms: 4.5, P99Ms: 10.2, AvgMs: 5.3, OverheadP50: 1.3, OverheadP99: 1.3, OverheadPct: 29.3},
			{Name: "catch_all", Endpoints: []string{"/health", "/"}, Samples: 250, P50Ms: 3.0, P99Ms: 7.8, AvgMs: 3.6, OverheadP50: 0.9, OverheadP99: 1.5, OverheadPct: 28.6},
		},
	}
	result.WAFLatency = wafLat

	// Simulated load test steps
	simSteps := []struct {
		rps, dur int
		p50, p99, max float64
		actualRPS float64
		errRate    float64
		memMB      float64
		fp, coll   int
	}{
		{1000, 30, 4.2, 8.5, 25.3, 998, 0.01, 45.2, 0, 0},
		{3000, 30, 5.1, 10.8, 35.7, 2987, 0.02, 62.4, 2, 0},
		{5000, 60, 6.8, 14.2, 48.1, 4982, 0.03, 78.1, 5, 1},
		{10000, 30, 12.3, 28.7, 85.4, 9920, 0.04, 95.3, 12, 3},
	}

	for i, ss := range simSteps {
		lsr := LoadTestStepResult{
			StepNum:       i + 1,
			TargetRPS:     ss.rps,
			ActualRPS:     ss.actualRPS,
			DurationSec:   ss.dur,
			TotalRequests: int(ss.actualRPS) * ss.dur,
			SuccessCount:  int(float64(int(ss.actualRPS)*ss.dur) * (1 - ss.errRate)),
			ErrorCount:    int(float64(int(ss.actualRPS)*ss.dur) * ss.errRate),
			BlockedCount:  50,
			P50Ms:         ss.p50,
			P99Ms:         ss.p99,
			MaxMs:         ss.max,
			SuccessRate:   1.0 - ss.errRate,
			ErrorRate:     ss.errRate,
			BlockedRate:   0.001,
			MemoryPeakMB:  ss.memMB,
			FalsePositiveCount: ss.fp,
			CollateralCount:    ss.coll,
			Passed:        ss.errRate < 0.05,
		}
		result.LoadTestSteps = append(result.LoadTestSteps, lsr)
	}

	// Throughput time series
	for i := 0; i < 6; i++ {
		result.ThroughputTS = append(result.ThroughputTS, ThroughputPoint{TimestampSec: i * 5, ActualRPS: float64(5000 + i*10)})
	}
	for i := 0; i < 10; i++ {
		result.MemoryTS = append(result.MemoryTS, MemoryPoint{TimestampSec: i * 5, MemoryMB: float64(60 + i*3)})
	}

	result.FPCount = 19
	result.FPRate = 0.001
	result.CollateralCount = 4

	// Simulated FP details
	result.FPDetails = []FPDetail{
		{Endpoint: "/game/list", StatusCode: 403, LatencyMs: 6.2, WAFAction: "block", RiskScore: 45},
		{Endpoint: "/api/profile", StatusCode: 403, LatencyMs: 5.8, WAFAction: "block", RiskScore: 50},
	}

	result.WAFCrashed = false
	e.computeScores(result)
	result.EndTime = time.Now()

	return result
}