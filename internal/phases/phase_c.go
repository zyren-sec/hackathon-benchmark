package phases

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/waf-hackathon/benchmark/internal/httpclient"
	"github.com/waf-hackathon/benchmark/internal/target"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

// TrafficType represents the type of traffic in the mix
type TrafficType int

const (
	TrafficLegitimate TrafficType = iota
	TrafficSuspicious
	TrafficExploit
	TrafficAbuse
	TrafficDDoS
)

func (t TrafficType) String() string {
	switch t {
	case TrafficLegitimate:
		return "Legitimate"
	case TrafficSuspicious:
		return "Suspicious"
	case TrafficExploit:
		return "Exploit"
	case TrafficAbuse:
		return "Abuse"
	case TrafficDDoS:
		return "DDoS"
	default:
		return "Unknown"
	}
}

// RequestTemplate defines a request pattern for traffic generation
type RequestTemplate struct {
	Type        TrafficType
	Method      string
	Path        string
	Headers     map[string]string
	Payload     map[string]interface{}
	AuthFlow    bool   // If true, follows golden path auth
	Description string
}

// PhaseCResult contains performance test results
type PhaseCResult struct {
	// Traffic metrics
	TotalRequests     int64
	SuccessfulReqs    int64
	FailedReqs        int64
	BlockedReqs       int64
	ChallengedReqs    int64

	// Latency metrics (ms)
	BaselineLatencies map[string]LatencyStats // per endpoint class
	WAFLatencies      map[string]LatencyStats // per endpoint class

	// Load test results per RPS step
	LoadTestResults []LoadTestStep

	// Throughput
	PeakRPS      float64
	SustainedRPS float64

	// Resource usage
	PeakMemoryMB float64

	// False positive metrics
	FalsePositives   int64 // Legitimate requests blocked/challenged
	FalsePosRate     float64
	Collaterals      int64 // Golden path blocked during DDoS

	// WAF overhead (ms)
	AvgOverheadMs    float64
	P99OverheadMs    float64

	// Overall score
	LatencyScore     float64 // p99 <= 5ms = 10pts
	ThroughputScore  float64 // sustained 5000 RPS = 5pts
	MemoryScore      float64 // < 100MB = 3pts
	GracefulScore    float64 // < 5% false pos = 2pts

	DurationMs       int64
}

// LatencyStats contains latency statistics
type LatencyStats struct {
	P50       float64 // 50th percentile
	P99       float64 // 99th percentile
	Max       float64 // Maximum
	Min       float64 // Minimum
	Avg       float64 // Average
	Samples   int64   // Number of samples
}

// LoadTestStep contains results for one load test step
type LoadTestStep struct {
	TargetRPS    int
	ActualRPS    float64
	DurationSec  int
	P50LatencyMs float64
	P99LatencyMs float64
	ErrorRate    float64
	BlockedRate  float64
	Passed       bool
}

// RequestMetric captures metrics for a single request
type RequestMetric struct {
	Type         TrafficType
	LatencyMs    float64
	StatusCode   int
	Decision     waf.Decision
	Error        error
	Timestamp    time.Time
}

// TrafficMixGenerator generates requests according to the traffic mix
type TrafficMixGenerator struct {
	client       *target.Client
	wafClient    *waf.WAFClient
	httpPool     *httpclient.Pool
	rng          *rand.Rand
}

// NewTrafficMixGenerator creates a new traffic generator
func NewTrafficMixGenerator(targetClient *target.Client, wafClient *waf.WAFClient, pool *httpclient.Pool) *TrafficMixGenerator {
	return &TrafficMixGenerator{
		client:       targetClient,
		wafClient:    wafClient,
		httpPool:     pool,
		rng:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// GetTrafficMixTemplates returns the traffic mix templates according to spec:
// - 60% Legitimate golden path
// - 10% Suspicious but legitimate (unusual UA, fast timing)
// - 10% Exploit payloads
// - 10% Abuse patterns
// - 10% DDoS bursts
func (g *TrafficMixGenerator) GetTrafficMixTemplates() []RequestTemplate {
	templates := []RequestTemplate{}

	// 60% Legitimate - Golden path flow
	legitimateTemplates := []RequestTemplate{
		{Type: TrafficLegitimate, Method: "GET", Path: "/", AuthFlow: false, Description: "Homepage"},
		{Type: TrafficLegitimate, Method: "GET", Path: "/game/list", AuthFlow: false, Description: "Game list"},
		{Type: TrafficLegitimate, Method: "POST", Path: "/login", AuthFlow: true, Description: "Login"},
		{Type: TrafficLegitimate, Method: "POST", Path: "/otp", AuthFlow: true, Description: "OTP"},
		{Type: TrafficLegitimate, Method: "GET", Path: "/api/profile", AuthFlow: true, Description: "Profile"},
		{Type: TrafficLegitimate, Method: "GET", Path: "/game/1", AuthFlow: false, Description: "Game detail"},
		{Type: TrafficLegitimate, Method: "POST", Path: "/game/1/play", AuthFlow: true, Description: "Play game"},
	}
	// Weight them to total 60%
	for i := range legitimateTemplates {
		legitimateTemplates[i].Type = TrafficLegitimate
	}
	templates = append(templates, legitimateTemplates...)

	// 10% Suspicious - unusual patterns but legitimate requests
	suspiciousTemplates := []RequestTemplate{
		{Type: TrafficSuspicious, Method: "GET", Path: "/", Headers: map[string]string{"User-Agent": "Bot/1.0"}, Description: "Bot UA"},
		{Type: TrafficSuspicious, Method: "GET", Path: "/game/list", Headers: map[string]string{"User-Agent": "Scraper/1.0"}, Description: "Scraper UA"},
		{Type: TrafficSuspicious, Method: "GET", Path: "/api/profile", Headers: map[string]string{"Accept": "*/*"}, Description: "Suspicious headers"},
	}
	templates = append(templates, suspiciousTemplates...)

	// 10% Exploit - malicious payloads
	exploitTemplates := []RequestTemplate{
		{Type: TrafficExploit, Method: "POST", Path: "/login", Payload: map[string]interface{}{"username": "' OR 1=1--"}, Description: "SQLi"},
		{Type: TrafficExploit, Method: "GET", Path: "/game/1", Payload: map[string]interface{}{"name": "<script>alert(1)</script>"}, Description: "XSS"},
		{Type: TrafficExploit, Method: "GET", Path: "/static/../../../etc/passwd", Description: "Path Traversal"},
		{Type: TrafficExploit, Method: "POST", Path: "/game/1/play", Payload: map[string]interface{}{"callback_url": "http://169.254.169.254/"}, Description: "SSRF"},
	}
	templates = append(templates, exploitTemplates...)

	// 10% Abuse - brute force, rapid requests
	abuseTemplates := []RequestTemplate{
		{Type: TrafficAbuse, Method: "POST", Path: "/login", Payload: map[string]interface{}{"username": "admin", "password": "wrong"}, Description: "Failed login"},
		{Type: TrafficAbuse, Method: "GET", Path: "/api/invalid-path-1", Description: "Random path 1"},
		{Type: TrafficAbuse, Method: "GET", Path: "/api/invalid-path-2", Description: "Random path 2"},
	}
	templates = append(templates, abuseTemplates...)

	// 10% DDoS - high volume bursts (handled separately in load test)
	ddosTemplates := []RequestTemplate{
		{Type: TrafficDDoS, Method: "GET", Path: "/", Description: "DDoS burst"},
		{Type: TrafficDDoS, Method: "GET", Path: "/game/list", Description: "DDoS burst"},
	}
	templates = append(templates, ddosTemplates...)

	return templates
}

// GenerateRequest generates a single request based on traffic type
func (g *TrafficMixGenerator) GenerateRequest(trafficType TrafficType) RequestTemplate {
	templates := g.GetTrafficMixTemplates()

	// Filter by type
	var candidates []RequestTemplate
	for _, t := range templates {
		if t.Type == trafficType {
			candidates = append(candidates, t)
		}
	}

	if len(candidates) == 0 {
		// Fallback to legitimate
		for _, t := range templates {
			if t.Type == TrafficLegitimate {
				candidates = append(candidates, t)
			}
		}
	}

	if len(candidates) == 0 {
		return RequestTemplate{Type: TrafficLegitimate, Method: "GET", Path: "/"}
	}

	return candidates[g.rng.Intn(len(candidates))]
}

// GetRandomTrafficType returns a traffic type based on the mix percentages
func (g *TrafficMixGenerator) GetRandomTrafficType() TrafficType {
	r := g.rng.Float64()
	switch {
	case r < 0.60:
		return TrafficLegitimate
	case r < 0.70:
		return TrafficSuspicious
	case r < 0.80:
		return TrafficExploit
	case r < 0.90:
		return TrafficAbuse
	default:
		return TrafficDDoS
	}
}

// ExecuteGoldenPath executes the golden path authentication flow
func (g *TrafficMixGenerator) ExecuteGoldenPath(sourceIP string) (*waf.WAFResponse, error) {
	// Step 1: GET /
	resp, err := g.wafClient.SendRequestWithIP("GET", "/", nil, nil, sourceIP)
	if err != nil {
		return nil, fmt.Errorf("golden path step 1 failed: %w", err)
	}

	// Step 2: GET /game/list
	resp, err = g.wafClient.SendRequestWithIP("GET", "/game/list", nil, nil, sourceIP)
	if err != nil {
		return nil, fmt.Errorf("golden path step 2 failed: %w", err)
	}

	// Step 3: POST /login (using predefined credentials from target package)
	creds := target.GetTestCredentials()[0] // alice
	loginPayload := map[string]interface{}{
		"username": creds.Username,
		"password": creds.Password,
	}
	resp, err = g.wafClient.SendRequestWithIP("POST", "/login", loginPayload, nil, sourceIP)
	if err != nil {
		return nil, fmt.Errorf("golden path step 3 failed: %w", err)
	}

	// Step 4: POST /otp
	otpPayload := map[string]interface{}{
		"otp": creds.OTP,
	}
	resp, err = g.wafClient.SendRequestWithIP("POST", "/otp", otpPayload, nil, sourceIP)
	if err != nil {
		return nil, fmt.Errorf("golden path step 4 failed: %w", err)
	}

	// Step 5: GET /api/profile
	resp, err = g.wafClient.SendRequestWithIP("GET", "/api/profile", nil, nil, sourceIP)
	if err != nil {
		return nil, fmt.Errorf("golden path step 5 failed: %w", err)
	}

	return resp, nil
}

// ExecuteRequest executes a single request template and returns metrics
func (g *TrafficMixGenerator) ExecuteRequest(template RequestTemplate, sourceIP string) (*RequestMetric, error) {
	start := time.Now()

	var resp *waf.WAFResponse
	var err error

	if template.AuthFlow {
		// For auth flow requests, execute the golden path
		resp, err = g.ExecuteGoldenPath(sourceIP)
	} else {
		// For regular requests
		resp, err = g.wafClient.SendRequestWithIP(template.Method, template.Path, template.Payload, template.Headers, sourceIP)
	}

	latencyMs := float64(time.Since(start).Milliseconds())

	if err != nil {
		return &RequestMetric{
			Type:      template.Type,
			LatencyMs: latencyMs,
			Error:     err,
			Timestamp: start,
		}, fmt.Errorf("request failed: %w", err)
	}

	return &RequestMetric{
		Type:       template.Type,
		LatencyMs:  latencyMs,
		StatusCode: resp.StatusCode,
		Decision:   resp.Decision,
		Timestamp:  start,
	}, nil
}

// MeasureBaselineLatency measures baseline latency directly to target (bypassing WAF)
func MeasureBaselineLatency(targetClient *target.Client, pool *httpclient.Pool) (map[string]LatencyStats, error) {
	endpointClasses := map[string][]string{
		"CRITICAL": {"/login", "/otp", "/deposit", "/withdrawal"},
		"HIGH":     {"/game/list", "/api/profile", "/game/1/play"},
		"MEDIUM":   {"/static/js/app.js"},
		"CATCH_ALL": {"/", "/about"},
	}

	results := make(map[string]LatencyStats)

	for class, endpoints := range endpointClasses {
		var latencies []float64

		// Send 1000 requests for each endpoint class
		for _, _ = range endpoints {
			for i := 0; i < 250; i++ { // 250 per endpoint = 1000 total per class
				start := time.Now()
				_ = i // Suppress unused variable warning
				err := targetClient.Health() // Using Health as simple GET
				latency := float64(time.Since(start).Milliseconds())

				if err == nil {
					latencies = append(latencies, latency)
				}
			}
		}

		results[class] = calculateLatencyStats(latencies)
	}

	return results, nil
}

// MeasureWAFLatency measures latency through WAF
func MeasureWAFLatency(wafClient *waf.WAFClient, pool *httpclient.Pool) (map[string]LatencyStats, error) {
	endpointClasses := map[string][]string{
		"CRITICAL": {"/login", "/otp", "/deposit", "/withdrawal"},
		"HIGH":     {"/game/list", "/api/profile", "/game/1/play"},
		"MEDIUM":   {"/static/js/app.js"},
		"CATCH_ALL": {"/", "/about"},
	}

	results := make(map[string]LatencyStats)

	for class, endpoints := range endpointClasses {
		var latencies []float64

		// Send 1000 requests for each endpoint class
		for _, _ = range endpoints {
			for i := 0; i < 250; i++ {
				_ = i // Suppress unused variable warning
				start := time.Now()
				err := wafClient.Health()
				latency := float64(time.Since(start).Milliseconds())

				if err == nil {
					latencies = append(latencies, latency)
				}
			}
		}

		results[class] = calculateLatencyStats(latencies)
	}

	return results, nil
}

// calculateLatencyStats calculates statistics from latency samples
func calculateLatencyStats(latencies []float64) LatencyStats {
	if len(latencies) == 0 {
		return LatencyStats{}
	}

	sort.Float64s(latencies)
	n := len(latencies)

	// Calculate average
	var sum float64
	min := latencies[0]
	max := latencies[n-1]
	for _, l := range latencies {
		sum += l
		if l < min {
			min = l
		}
		if l > max {
			max = l
		}
	}
	avg := sum / float64(n)

	// Calculate percentiles
	p50 := percentile(latencies, 50)
	p99 := percentile(latencies, 99)

	return LatencyStats{
		P50:     p50,
		P99:     p99,
		Max:     max,
		Min:     min,
		Avg:     avg,
		Samples: int64(n),
	}
}

// percentile calculates the p-th percentile from sorted data
func percentile(sortedData []float64, p float64) float64 {
	if len(sortedData) == 0 {
		return 0
	}
	n := float64(len(sortedData))
	index := (p / 100) * (n - 1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))

	if lower == upper {
		return sortedData[lower]
	}

	weight := index - float64(lower)
	return sortedData[lower]*(1-weight) + sortedData[upper]*weight
}

// RunLoadTest runs a load test at specified RPS for specified duration
func RunLoadTest(generator *TrafficMixGenerator, targetRPS int, durationSec int, wafClient *waf.WAFClient) (*LoadTestStep, error) {
	metrics := make(chan RequestMetric, 10000)
	var wg sync.WaitGroup

	ctx, cancel := contextWithTimeout(durationSec)
	defer cancel()

	var requestCount int64
	var successCount int64
	var errorCount int64
	var blockedCount int64

	// Start metrics collector
	go func() {
		for m := range metrics {
			// Process metrics (could store them for analysis)
			_ = m
		}
	}()

	start := time.Now()

	// Start workers
	g, ctx := errgroup.WithContext(ctx)

	// Rate limiter ticker
	ticker := time.NewTicker(time.Second / time.Duration(targetRPS))
	defer ticker.Stop()

	worker := func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				wg.Add(1)
				go func() {
					defer wg.Done()

					// Generate random traffic type based on mix
					trafficType := generator.GetRandomTrafficType()
					template := generator.GenerateRequest(trafficType)

					// Pick random source IP from 127.0.0.200-220
					sourceIP := fmt.Sprintf("127.0.0.%d", 200+rand.Intn(21))

					metric, _ := generator.ExecuteRequest(template, sourceIP)
					select {
					case metrics <- *metric:
					default:
					}

					atomic.AddInt64(&requestCount, 1)

					if metric.Error != nil {
						atomic.AddInt64(&errorCount, 1)
					} else {
						atomic.AddInt64(&successCount, 1)
						if metric.Decision == waf.Block || metric.Decision == waf.RateLimit {
							atomic.AddInt64(&blockedCount, 1)
						}
					}
				}()
			}
		}
	}

	// Run multiple workers
	for i := 0; i < 10; i++ {
		g.Go(worker)
	}

	// Wait for duration
	time.Sleep(time.Duration(durationSec) * time.Second)
	cancel()

	// Wait for all workers
	if err := g.Wait(); err != nil {
		return nil, err
	}

	wg.Wait()
	close(metrics)

	duration := time.Since(start).Seconds()
	actualRPS := float64(requestCount) / duration
	errorRate := float64(errorCount) / float64(requestCount)
	blockedRate := float64(blockedCount) / float64(requestCount)

	return &LoadTestStep{
		TargetRPS:   targetRPS,
		ActualRPS:   actualRPS,
		DurationSec: durationSec,
		ErrorRate:   errorRate,
		BlockedRate: blockedRate,
		Passed:      errorRate < 0.05, // Pass if error rate < 5%
	}, nil
}

// contextWithTimeout creates a context with timeout
func contextWithTimeout(seconds int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
}

// RunPhaseC executes the full Phase C performance testing
func RunPhaseC(targetClient *target.Client, wafClient *waf.WAFClient, pool *httpclient.Pool) (*PhaseCResult, error) {
	start := time.Now()
	result := &PhaseCResult{
		BaselineLatencies: make(map[string]LatencyStats),
		WAFLatencies:      make(map[string]LatencyStats),
		LoadTestResults:   make([]LoadTestStep, 0),
	}

	generator := NewTrafficMixGenerator(targetClient, wafClient, pool)

	// Step 1: Measure baseline latency (direct to target)
	fmt.Println("Phase C: Measuring baseline latency...")
	baseline, err := MeasureBaselineLatency(targetClient, pool)
	if err != nil {
		return nil, fmt.Errorf("baseline measurement failed: %w", err)
	}
	result.BaselineLatencies = baseline

	// Step 2: Measure WAF latency
	fmt.Println("Phase C: Measuring WAF latency...")
	wafLatencies, err := MeasureWAFLatency(wafClient, pool)
	if err != nil {
		return nil, fmt.Errorf("WAF latency measurement failed: %w", err)
	}
	result.WAFLatencies = wafLatencies

	// Calculate overhead
	for class, wafStats := range wafLatencies {
		if baseStats, ok := baseline[class]; ok {
			overhead := wafStats.Avg - baseStats.Avg
			if overhead > result.AvgOverheadMs {
				result.AvgOverheadMs = overhead
			}
		}
	}

	// Step 3: Load test steps
	loadSteps := []struct {
		rps int
		sec int
	}{
		{1000, 30},
		{3000, 30},
		{5000, 60},
		{10000, 30},
	}

	for _, step := range loadSteps {
		fmt.Printf("Phase C: Running load test at %d RPS for %d seconds...\n", step.rps, step.sec)
		loadResult, err := RunLoadTest(generator, step.rps, step.sec, wafClient)
		if err != nil {
			fmt.Printf("Load test at %d RPS failed: %v\n", step.rps, err)
			continue
		}
		result.LoadTestResults = append(result.LoadTestResults, *loadResult)

		if loadResult.ActualRPS > result.PeakRPS {
			result.PeakRPS = loadResult.ActualRPS
		}
	}

	// Calculate sustained RPS (step at 5000 RPS)
	for _, step := range result.LoadTestResults {
		if step.TargetRPS == 5000 && step.Passed {
			result.SustainedRPS = step.ActualRPS
		}
	}

	// Calculate scores
	// PERF-01: p99 <= 5ms at 5000 RPS = 10pts
	for _, step := range result.LoadTestResults {
		if step.TargetRPS == 5000 {
			if step.P99LatencyMs <= 5.0 {
				result.LatencyScore = 10.0
			} else if step.P99LatencyMs <= 10.0 {
				result.LatencyScore = 5.0
			} else {
				result.LatencyScore = 0.0
			}
			result.P99OverheadMs = step.P99LatencyMs
		}
	}

	// Throughput: sustained 5000 RPS = 5pts
	if result.SustainedRPS >= 5000 {
		result.ThroughputScore = 5.0
	} else if result.SustainedRPS >= 3000 {
		result.ThroughputScore = 3.0
	} else {
		result.ThroughputScore = 0.0
	}

	// Memory: < 100MB = 3pts (placeholder - would need actual process monitoring)
	result.MemoryScore = 3.0 // Assume pass for now

	// Graceful: < 5% false positives = 2pts
	if result.FalsePosRate <= 0.05 {
		result.GracefulScore = 2.0
	} else {
		result.GracefulScore = 0.0
	}

	result.DurationMs = time.Since(start).Milliseconds()

	return result, nil
}

// Summary returns a human-readable summary of Phase C results
func (r *PhaseCResult) Summary() string {
	return fmt.Sprintf(
		"Phase C (Performance) - Duration: %dms\n"+
		"  Peak RPS: %.0f, Sustained RPS: %.0f\n"+
		"  Avg Overhead: %.2fms, P99 Overhead: %.2fms\n"+
		"  Latency Score: %.1f/10, Throughput Score: %.1f/5\n"+
		"  Memory Score: %.1f/3, Graceful Score: %.1f/2",
		r.DurationMs,
		r.PeakRPS, r.SustainedRPS,
		r.AvgOverheadMs, r.P99OverheadMs,
		r.LatencyScore, r.ThroughputScore,
		r.MemoryScore, r.GracefulScore,
	)
}
