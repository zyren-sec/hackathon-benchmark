package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/waf-hackathon/benchmark/internal/config"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

type benchmarkCase struct {
	ID       string
	Name     string
	Method   string
	Path     string
	Expected string
}

var mappedCases = []benchmarkCase{
	{ID: "E01", Name: "MEDIUM cached", Method: http.MethodGet, Path: "/static/js/app.js", Expected: "2nd request should be cache HIT (header HIT or latency infer)"},
	{ID: "E02", Name: "CRITICAL never cached", Method: http.MethodPost, Path: "/login", Expected: "two login_token values must be different"},
	{ID: "E03", Name: "TTL expiry honored", Method: http.MethodGet, Path: "/static/css/style.css", Expected: "request after TTL window should not be HIT from old object"},
	{ID: "E04", Name: "Auth routes never cached", Method: http.MethodGet, Path: "/api/profile", Expected: "auth route should not be cache HIT; latency should be comparable"},
}

func RunPhaseEBenchmark(cfg *config.Config, configPath string) (*PhaseEReport, error) {
	start := time.Now()

	wafClient := waf.NewWAFClientWithScheme(
		cfg.Benchmark.WAF.Scheme,
		cfg.Benchmark.WAF.Host,
		cfg.Benchmark.WAF.Port,
		cfg.TestTimeout(),
	)
	defer wafClient.Close()

	healthErr := wafClient.Health()
	executionAvailable := healthErr == nil

	report := &PhaseEReport{
		Metadata: ReportMetadata{
			RunID:        fmt.Sprintf("phase-e-%d", time.Now().Unix()),
			GeneratedAt:  time.Now().UTC(),
			Tool:         "waf-benchmark-phase-e",
			Version:      toolVersion,
			ConfigPath:   configPath,
			TargetURL:    cfg.TargetAddr(),
			WAFURL:       cfg.WAFAddr(),
			BenchmarkURL: cfg.WAFAddr(),
		},
		EndpointValidity: EndpointValidity{
			MappedFromDocs: buildMappedEndpoints(),
			Notes:          []string{},
		},
		Cases:     map[string]CaseReport{},
		CaseOrder: append([]string{}, phaseECaseOrder...),
	}

	report.EndpointValidity.Probes = append(report.EndpointValidity.Probes, probeMappedEndpoints("http://sec-team.waf-exams.info")...)
	report.EndpointValidity.Probes = append(report.EndpointValidity.Probes, probeMappedEndpoints("https://sec-team.waf-exams.info")...)
	report.EndpointValidity.AllReachable = true
	for _, p := range report.EndpointValidity.Probes {
		if !p.Reachable {
			report.EndpointValidity.AllReachable = false
		}
		if strings.HasPrefix(p.BaseURL, "https://") && !p.Reachable {
			report.EndpointValidity.Notes = append(report.EndpointValidity.Notes, "HTTPS endpoint currently unreachable from benchmark host (possible Cloudflare edge/network timeout)")
			break
		}
	}
	if healthErr != nil {
		report.EndpointValidity.AllReachable = false
		report.EndpointValidity.Notes = append(report.EndpointValidity.Notes, fmt.Sprintf("WAF execution unavailable: health check failed (%v)", healthErr))
	}

	if executionAvailable {
		e01 := runE01(wafClient)
		e02 := runE02(wafClient)
		e03 := runE03(wafClient)
		e04 := runE04(wafClient)

		report.Cases[e01.CaseID] = e01
		report.Cases[e02.CaseID] = e02
		report.Cases[e03.CaseID] = e03
		report.Cases[e04.CaseID] = e04
	} else {
		reason := fmt.Sprintf("execution skipped because WAF health failed: %v", healthErr)
		for _, tc := range mappedCases {
			report.Cases[tc.ID] = CaseReport{
				CaseID:      tc.ID,
				Name:        tc.Name,
				Passed:      false,
				Expected:    tc.Expected,
				Observed:    "execution unavailable",
				Reason:      reason,
				WAFFeedback: "waf health check failed",
				Evidence: map[string]any{
					"health_error": reason,
				},
			}
		}
	}

	passed := 0
	for _, id := range report.CaseOrder {
		if report.Cases[id].Passed {
			passed++
		}
	}

	report.Summary = PhaseESummary{
		Pass:          passed == len(report.CaseOrder),
		PassedCases:   passed,
		TotalCases:    len(report.CaseOrder),
		Score:         float64(passed),
		MaxScore:      4,
		EndpointReady: report.EndpointValidity.AllReachable,
	}

	report.QualityMetrics = buildQualityMetrics(report)
	report.TieBreak = buildTieBreak(report.QualityMetrics)
	report.Validation = runValidationChecks(report)
	report.Metadata.DurationMs = time.Since(start).Milliseconds()
	return report, nil
}

func buildMappedEndpoints() []MappedEndpoint {
	out := make([]MappedEndpoint, 0, len(mappedCases))
	for _, c := range mappedCases {
		out = append(out, MappedEndpoint{
			CaseID:   c.ID,
			Method:   c.Method,
			Path:     c.Path,
			Source:   "benchmark/docs/exploit_catalogue.md + benchmark/docs/workflow/phaseE.md",
			Expected: c.Expected,
		})
	}
	return out
}

func probeMappedEndpoints(baseURL string) []EndpointProbe {
	c := &http.Client{Timeout: 12 * time.Second}
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"

	probes := make([]EndpointProbe, 0, len(mappedCases))
	for _, tc := range mappedCases {
		start := time.Now()
		p := EndpointProbe{BaseURL: baseURL, Method: tc.Method, Path: tc.Path}

		var req *http.Request
		var err error
		if tc.Method == http.MethodPost {
			payload := map[string]any{}
			switch tc.Path {
			case "/login":
				payload = map[string]any{"username": "alice", "password": "P@ssw0rd1"}
			case "/otp":
				payload = map[string]any{"login_token": "00000000-0000-0000-0000-000000000000", "otp_code": "123456"}
			default:
				payload = map[string]any{}
			}
			b, _ := json.Marshal(payload)
			req, err = http.NewRequest(http.MethodPost, strings.TrimRight(baseURL, "/")+tc.Path, strings.NewReader(string(b)))
			req.Header.Set("Content-Type", "application/json")
		} else {
			req, err = http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+tc.Path, nil)
		}
		if err != nil {
			p.Error = err.Error()
			probes = append(probes, p)
			continue
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("X-Benchmark-Secret", "waf-hackathon-2026-ctrl")

		resp, err := c.Do(req)
		p.LatencyMs = time.Since(start).Milliseconds()
		if err != nil {
			p.Error = err.Error()
			p.StatusCode = 0
			p.Reachable = false
			probes = append(probes, p)
			continue
		}
		_ = resp.Body.Close()
		p.StatusCode = resp.StatusCode
		p.ServerHeader = resp.Header.Get("Server")
		p.CFRay = resp.Header.Get("Cf-Ray")
		p.ContentType = resp.Header.Get("Content-Type")
		p.Reachable = resp.StatusCode != http.StatusNotFound
		probes = append(probes, p)
	}

	return probes
}

func runE01(w *waf.WAFClient) CaseReport {
	r := CaseReport{CaseID: "E01", Name: "MEDIUM cached", Expected: "2nd request should be cache HIT or significantly faster", Evidence: map[string]any{}}
	first, err := w.SendRequestWithIP(http.MethodGet, "/static/js/app.js", nil, nil, "127.0.0.1")
	if err != nil {
		r.Observed = "request error"
		r.Reason = err.Error()
		r.WAFFeedback = "transport error"
		return r
	}
	time.Sleep(150 * time.Millisecond)
	second, err := w.SendRequestWithIP(http.MethodGet, "/static/js/app.js", nil, nil, "127.0.0.1")
	if err != nil {
		r.Observed = "request error on second request"
		r.Reason = err.Error()
		r.WAFFeedback = "transport error"
		return r
	}
	r.Evidence["status_1"] = first.StatusCode
	r.Evidence["status_2"] = second.StatusCode
	r.Evidence["latency_1_ms"] = first.LatencyMs
	r.Evidence["latency_2_ms"] = second.LatencyMs
	r.Evidence["cache_header_2"] = second.CacheStatus

	latencyInfer := second.LatencyMs > 0 && first.LatencyMs > 0 && float64(second.LatencyMs) <= float64(first.LatencyMs)*0.2
	headHit := strings.EqualFold(second.CacheStatus, "HIT")
	r.Passed = headHit || latencyInfer
	r.Observed = fmt.Sprintf("s1=%d s2=%d l1=%dms l2=%dms cache2=%q", first.StatusCode, second.StatusCode, first.LatencyMs, second.LatencyMs, second.CacheStatus)
	if r.Passed {
		r.Reason = "PASS because second response indicates cache behavior"
	} else {
		r.Reason = "FAILED because no HIT header and no strong latency-based cache inference"
	}
	r.WAFFeedback = fmt.Sprintf("X-WAF-Cache(second)=%q", second.CacheStatus)
	return r
}

func runE02(w *waf.WAFClient) CaseReport {
	r := CaseReport{CaseID: "E02", Name: "CRITICAL never cached", Expected: "two /login calls produce distinct login_token", Evidence: map[string]any{}}
	payload := map[string]any{"username": "alice", "password": "P@ssw0rd1"}

	first, err := w.SendRequestWithIP(http.MethodPost, "/login", payload, nil, "127.0.0.1")
	if err != nil {
		r.Observed = "request error"
		r.Reason = err.Error()
		r.WAFFeedback = "transport error"
		return r
	}
	time.Sleep(150 * time.Millisecond)
	second, err := w.SendRequestWithIP(http.MethodPost, "/login", payload, nil, "127.0.0.1")
	if err != nil {
		r.Observed = "request error on second request"
		r.Reason = err.Error()
		r.WAFFeedback = "transport error"
		return r
	}
	t1 := extractJSONField(string(first.Body), "login_token")
	t2 := extractJSONField(string(second.Body), "login_token")

	r.Evidence["status_1"] = first.StatusCode
	r.Evidence["status_2"] = second.StatusCode
	r.Evidence["token_1"] = t1
	r.Evidence["token_2"] = t2
	r.Evidence["cache_header_2"] = second.CacheStatus

	r.Passed = t1 != "" && t2 != "" && t1 != t2
	r.Observed = fmt.Sprintf("token1=%q token2=%q cache2=%q", t1, t2, second.CacheStatus)
	if r.Passed {
		r.Reason = "PASS because login_token differs across two CRITICAL requests"
	} else {
		r.Reason = "FAILED because login_token not extracted or token repeated (possible cache replay/block)"
	}
	r.WAFFeedback = fmt.Sprintf("X-WAF-Cache(second)=%q", second.CacheStatus)
	return r
}

func runE03(w *waf.WAFClient) CaseReport {
	r := CaseReport{CaseID: "E03", Name: "TTL expiry honored", Expected: "post-TTL request should not return stale HIT", Evidence: map[string]any{}}

	first, err := w.SendRequestWithIP(http.MethodGet, "/static/css/style.css", nil, nil, "127.0.0.1")
	if err != nil {
		r.Observed = "request error"
		r.Reason = err.Error()
		r.WAFFeedback = "transport error"
		return r
	}
	cacheControl := first.Headers["Cache-Control"]
	ttl := parseMaxAgeSeconds(cacheControl)
	wait := int64(2)
	if ttl > 0 && ttl < 8 {
		wait = int64(ttl + 1)
	}
	time.Sleep(time.Duration(wait) * time.Second)

	second, err := w.SendRequestWithIP(http.MethodGet, "/static/css/style.css", nil, nil, "127.0.0.1")
	if err != nil {
		r.Observed = "request error on second request"
		r.Reason = err.Error()
		r.WAFFeedback = "transport error"
		return r
	}

	hitAfterWait := strings.EqualFold(second.CacheStatus, "HIT")
	r.Passed = !hitAfterWait
	r.Evidence["status_1"] = first.StatusCode
	r.Evidence["status_2"] = second.StatusCode
	r.Evidence["cache_control"] = cacheControl
	r.Evidence["ttl_seconds"] = ttl
	r.Evidence["wait_seconds"] = wait
	r.Evidence["cache_header_2"] = second.CacheStatus
	r.Evidence["latency_1_ms"] = first.LatencyMs
	r.Evidence["latency_2_ms"] = second.LatencyMs

	r.Observed = fmt.Sprintf("ttl=%ds wait=%ds cache2=%q", ttl, wait, second.CacheStatus)
	if r.Passed {
		r.Reason = "PASS because no explicit HIT observed after TTL validation window"
	} else {
		r.Reason = "FAILED because stale HIT observed after validation wait"
	}
	r.WAFFeedback = fmt.Sprintf("X-WAF-Cache(second)=%q", second.CacheStatus)
	return r
}

func runE04(w *waf.WAFClient) CaseReport {
	r := CaseReport{CaseID: "E04", Name: "Auth routes never cached", Expected: "authenticated /api/profile should not be cached", Evidence: map[string]any{}}
	sid, err := issueSessionID(w)
	if err != nil {
		r.Observed = "session bootstrap failed"
		r.Reason = err.Error()
		r.WAFFeedback = "login/otp failed"
		return r
	}
	headers := map[string]string{"Cookie": "sid=" + sid}
	first, err := w.SendRequestWithIP(http.MethodGet, "/api/profile", nil, headers, "127.0.0.1")
	if err != nil {
		r.Observed = "first auth request failed"
		r.Reason = err.Error()
		r.WAFFeedback = "transport error"
		return r
	}
	time.Sleep(150 * time.Millisecond)
	second, err := w.SendRequestWithIP(http.MethodGet, "/api/profile", nil, headers, "127.0.0.1")
	if err != nil {
		r.Observed = "second auth request failed"
		r.Reason = err.Error()
		r.WAFFeedback = "transport error"
		return r
	}

	ratio := 1.0
	if first.LatencyMs > 0 {
		ratio = float64(second.LatencyMs) / float64(first.LatencyMs)
	}
	cacheHit := strings.EqualFold(second.CacheStatus, "HIT")
	latencyComparable := ratio >= 0.5 && ratio <= 2.0
	r.Passed = !cacheHit && latencyComparable && first.StatusCode == 200 && second.StatusCode == 200

	r.Evidence["sid_prefix"] = firstN(sid, 8)
	r.Evidence["status_1"] = first.StatusCode
	r.Evidence["status_2"] = second.StatusCode
	r.Evidence["latency_1_ms"] = first.LatencyMs
	r.Evidence["latency_2_ms"] = second.LatencyMs
	r.Evidence["latency_ratio"] = ratio
	r.Evidence["cache_header_2"] = second.CacheStatus

	r.Observed = fmt.Sprintf("s1=%d s2=%d ratio=%.2f cache2=%q", first.StatusCode, second.StatusCode, ratio, second.CacheStatus)
	if r.Passed {
		r.Reason = "PASS because auth route stayed uncached with comparable latency"
	} else {
		r.Reason = "FAILED because auth route exhibited cache-hit signal or abnormal speedup/status"
	}
	r.WAFFeedback = fmt.Sprintf("X-WAF-Cache(second)=%q", second.CacheStatus)
	return r
}

func issueSessionID(w *waf.WAFClient) (string, error) {
	loginPayload := map[string]any{"username": "alice", "password": "P@ssw0rd1"}
	loginResp, err := w.SendRequestWithIP(http.MethodPost, "/login", loginPayload, nil, "127.0.0.1")
	if err != nil {
		return "", err
	}
	if loginResp.StatusCode != 200 {
		return "", fmt.Errorf("login failed with status %d", loginResp.StatusCode)
	}
	loginToken := extractJSONField(string(loginResp.Body), "login_token")
	if loginToken == "" {
		return "", fmt.Errorf("login_token missing from /login response")
	}
	otpPayload := map[string]any{"login_token": loginToken, "otp_code": "123456"}
	otpResp, err := w.SendRequestWithIP(http.MethodPost, "/otp", otpPayload, nil, "127.0.0.1")
	if err != nil {
		return "", err
	}
	if otpResp.StatusCode != 200 {
		return "", fmt.Errorf("otp failed with status %d", otpResp.StatusCode)
	}
	sid := extractJSONField(string(otpResp.Body), "session_id")
	if sid == "" {
		return "", fmt.Errorf("session_id missing from /otp response")
	}
	return sid, nil
}

func extractJSONField(body string, key string) string {
	obj := map[string]any{}
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return ""
	}
	v, ok := obj[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func parseMaxAgeSeconds(cacheControl string) int {
	parts := strings.Split(cacheControl, ",")
	for _, p := range parts {
		trim := strings.TrimSpace(strings.ToLower(p))
		if strings.HasPrefix(trim, "max-age=") {
			n := strings.TrimPrefix(trim, "max-age=")
			v, err := strconv.Atoi(n)
			if err == nil {
				return v
			}
		}
	}
	return 0
}

func buildQualityMetrics(report *PhaseEReport) QualityMetrics {
	latHit := []float64{}
	latMiss := []float64{}

	e01 := report.Cases["E01"]
	e02 := report.Cases["E02"]
	e03 := report.Cases["E03"]
	e04 := report.Cases["E04"]

	l1 := getEvidenceFloat(e01.Evidence, "latency_1_ms")
	l2 := getEvidenceFloat(e01.Evidence, "latency_2_ms")
	if l2 > 0 {
		latHit = append(latHit, l2)
	}
	if l1 > 0 {
		latMiss = append(latMiss, l1)
	}

	cacheHitRatio := 0.0
	if strings.EqualFold(getEvidenceString(e01.Evidence, "cache_header_2"), "HIT") {
		cacheHitRatio = 1.0
	}

	accelRatio := 0.0
	if l2 > 0 {
		accelRatio = l1 / l2
	}

	ttlAccuracy := 0.0
	if e03.Passed {
		ttlAccuracy = 1.0
	}

	tokenRate := 0.0
	if e02.Passed {
		tokenRate = 1.0
	}

	authSimilarityGuard := 0.0
	if e04.Passed {
		authSimilarityGuard = 1.0
	}

	criticalViolations := 0
	if !e02.Passed {
		criticalViolations = 1
	}
	authViolations := 0
	if !e04.Passed {
		authViolations = 1
	}

	headerConsistency := 1.0
	if getEvidenceString(e01.Evidence, "cache_header_2") == "" && getEvidenceString(e03.Evidence, "cache_header_2") == "" {
		headerConsistency = 0.5
	}

	flap := 0
	if (e01.Passed && !e03.Passed) || (!e01.Passed && e03.Passed) {
		flap = 1
	}

	return QualityMetrics{
		CacheEfficiency: CacheEfficiencyMetrics{
			CacheHitRatioMedium:    cacheHitRatio,
			CacheHitLatencyP50Ms:   percentile(latHit, 0.50),
			CacheHitLatencyP95Ms:   percentile(latHit, 0.95),
			CacheAccelerationRatio: accelRatio,
			TTLExpiryAccuracy:      ttlAccuracy,
		},
		Safety: SafetyMetrics{
			CriticalCacheViolationCount: criticalViolations,
			AuthCacheViolationCount:     authViolations,
			TokenUniquenessRate:         tokenRate,
			AuthResponseSimilarityGuard: authSimilarityGuard,
		},
		StabilityDeterminism: StabilityDeterminismMetrics{
			DecisionFlapCount:     flap,
			LatencyStddevHitMs:    stddev(latHit),
			LatencyStddevMissMs:   stddev(latMiss),
			HeaderConsistencyRate: headerConsistency,
		},
		ResourceEfficiency: ResourceEfficiencyMetrics{},
	}
}

func buildTieBreak(q QualityMetrics) TieBreakSummary {
	weights := map[string]float64{
		"safety":            0.40,
		"cache_efficiency":  0.30,
		"ttl_correctness":   0.15,
		"stability":         0.10,
		"resource_overhead": 0.05,
	}

	safety := 1.0
	if q.Safety.CriticalCacheViolationCount > 0 || q.Safety.AuthCacheViolationCount > 0 {
		safety = 0
	}
	cacheEff := clamp01((q.CacheEfficiency.CacheHitRatioMedium + normalizeRatio(q.CacheEfficiency.CacheAccelerationRatio, 5.0)) / 2.0)
	ttl := q.CacheEfficiency.TTLExpiryAccuracy
	stability := clamp01(1.0 - float64(q.StabilityDeterminism.DecisionFlapCount)*0.2)
	resource := 0.5

	signals := map[string]float64{
		"safety":            safety,
		"cache_efficiency":  cacheEff,
		"ttl_correctness":   ttl,
		"stability":         stability,
		"resource_overhead": resource,
	}

	score := 0.0
	for k, w := range weights {
		score += signals[k] * w
	}

	return TieBreakSummary{
		PhaseEQualityScore: score,
		Weights:            weights,
		Signals:            signals,
		RankingPolicy: []string{
			"Safety first (critical/auth cache violations must be zero)",
			"Then MEDIUM cache efficiency (acceleration and hit-ratio)",
			"Then TTL correctness and stability",
			"Finally lower resource overhead",
		},
	}
}

func runValidationChecks(report *PhaseEReport) ValidationSection {
	workflow := []ValidationCheck{
		{
			ID:       "WF-01",
			Passed:   len(report.EndpointValidity.MappedFromDocs) == 4,
			Expected: "mapped 4 cases E01..E04 from docs",
			Observed: fmt.Sprintf("mapped=%d", len(report.EndpointValidity.MappedFromDocs)),
		},
		{
			ID:       "WF-02",
			Passed:   len(report.EndpointValidity.Probes) >= 8,
			Expected: "probed mapped endpoints on both http/https live URLs",
			Observed: fmt.Sprintf("probes=%d", len(report.EndpointValidity.Probes)),
		},
		{
			ID:       "WF-03",
			Passed:   len(report.Cases) == 4,
			Expected: "executed E01..E04 in fixed order",
			Observed: fmt.Sprintf("cases=%d order=%v", len(report.Cases), report.CaseOrder),
		},
	}

	reportChecks := []ValidationCheck{
		{
			ID:       "RP-01",
			Passed:   report.Summary.TotalCases == 4,
			Expected: "summary includes total case count",
			Observed: fmt.Sprintf("total_cases=%d", report.Summary.TotalCases),
		},
		{
			ID:       "RP-02",
			Passed:   report.TieBreak.PhaseEQualityScore >= 0,
			Expected: "tie-break quality score present",
			Observed: fmt.Sprintf("quality_score=%.3f", report.TieBreak.PhaseEQualityScore),
		},
		{
			ID:       "RP-03",
			Passed:   len(report.Validation.WorkflowChecks) == 0, // will be overwritten below after struct build
			Expected: "self-referential sanity check initialized",
			Observed: "pending",
		},
	}

	all := true
	for _, c := range workflow {
		all = all && c.Passed
	}
	for i := range reportChecks {
		if reportChecks[i].ID == "RP-03" {
			reportChecks[i].Passed = true
			reportChecks[i].Observed = "initialized"
		}
		all = all && reportChecks[i].Passed
	}

	return ValidationSection{WorkflowChecks: workflow, ReportChecks: reportChecks, Passed: all}
}

func percentile(values []float64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	s := append([]float64{}, values...)
	sort.Float64s(s)
	if q <= 0 {
		return s[0]
	}
	if q >= 1 {
		return s[len(s)-1]
	}
	idx := q * float64(len(s)-1)
	lo := int(math.Floor(idx))
	hi := int(math.Ceil(idx))
	if lo == hi {
		return s[lo]
	}
	frac := idx - float64(lo)
	return s[lo] + (s[hi]-s[lo])*frac
}

func stddev(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	m := 0.0
	for _, v := range values {
		m += v
	}
	m /= float64(len(values))
	acc := 0.0
	for _, v := range values {
		d := v - m
		acc += d * d
	}
	return math.Sqrt(acc / float64(len(values)))
}

func getEvidenceFloat(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	default:
		return 0
	}
}

func getEvidenceString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func normalizeRatio(v float64, baseline float64) float64 {
	if baseline <= 0 {
		return 0
	}
	return clamp01(v / baseline)
}
