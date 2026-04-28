package main

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/waf-hackathon/benchmark/internal/config"
	"github.com/waf-hackathon/benchmark/internal/phases"
	"github.com/waf-hackathon/benchmark/internal/target"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

var caseOrder = []string{"D01", "D02", "D03", "D04", "D05", "D06", "D07", "D08", "D09"}

func RunPhaseDBenchmark(cfg *config.Config, configPath string) (*PhaseDReport, error) {
	targetClient := target.NewClientWithScheme(
		cfg.Benchmark.TargetApp.Host,
		cfg.Benchmark.TargetApp.Port,
		cfg.Benchmark.TargetApp.Scheme,
		cfg.Benchmark.TargetApp.ControlSecret,
	)
	control := target.NewControl(targetClient)
	wafClient := waf.NewWAFClientWithScheme(
		cfg.Benchmark.WAF.Scheme,
		cfg.Benchmark.WAF.Host,
		cfg.Benchmark.WAF.Port,
		cfg.TestTimeout(),
	)
	defer wafClient.Close()

	if err := wafClient.Health(); err != nil {
		return nil, fmt.Errorf("waf health check failed: %w", err)
	}

	// Live environments may not expose /__control/health publicly.
	// We only require that a control operation works when Phase D needs it.
	if err := control.SetHealthMode(false); err != nil {
		return nil, fmt.Errorf("control-plane precheck failed (SetHealthMode false): %w", err)
	}

	start := time.Now()
	phaseD, err := phases.RunPhaseD(wafClient, targetClient, control)
	if err != nil {
		return nil, err
	}
	report := &PhaseDReport{
		Metadata: ReportMetadata{
			RunID:       fmt.Sprintf("phase-d-%d", time.Now().Unix()),
			GeneratedAt: time.Now().UTC(),
			Tool:        "waf-benchmark-phase-d",
			Version:     toolVersion,
			ConfigPath:  configPath,
			TargetURL:   cfg.TargetAddr(),
			WAFURL:      cfg.WAFAddr(),
			DurationMs:  time.Since(start).Milliseconds(),
		},
		Cases:     make(map[string]CaseReport),
		CaseOrder: append([]string{}, caseOrder...),
	}

	all := flattenPhaseD(phaseD)
	passed := 0
	for _, raw := range all {
		caseReport := toCaseReport(raw)
		report.Cases[raw.TestID] = caseReport
		if caseReport.Passed {
			passed++
		}
	}

	report.PhaseDSummary = PhaseDSummary{
		Pass:          passed == len(caseOrder),
		PassedCases:   passed,
		TotalCases:    len(caseOrder),
		Score:         phaseD.TotalScore,
		MaxScore:      9,
		DDoSScore:     phaseD.DDoSScore,
		BackendScore:  phaseD.BackendScore,
		FailModeScore: phaseD.FailModeScore,
	}

	report.QualityMetrics = computeQualityMetrics(report)
	report.TieBreak = computeTieBreak(report.QualityMetrics)
	return report, nil
}

func flattenPhaseD(p *phases.PhaseDResult) []phases.ResilienceResult {
	all := make([]phases.ResilienceResult, 0, 9)
	all = append(all, p.DDoSTests...)
	all = append(all, p.SlowAttackTests...)
	all = append(all, p.BackendFailureTests...)
	all = append(all, p.FailModeTests...)
	sort.SliceStable(all, func(i, j int) bool {
		return all[i].TestID < all[j].TestID
	})
	return all
}

func toCaseReport(t phases.ResilienceResult) CaseReport {
	expected := expectedByCase(t.TestID)
	observed := observedSummary(t.TestID, t.Details)
	reason := reasonFromCase(t.TestID, t.Passed, t.Details)
	wafFeedback := wafFeedbackForCase(t.TestID, t.Details)

	return CaseReport{
		TestID:      t.TestID,
		Name:        t.Name,
		Category:    t.Category,
		Passed:      t.Passed,
		Expected:    expected,
		Observed:    observed,
		Reason:      reason,
		WAFFeedback: wafFeedback,
		Evidence:    t.Details,
	}
}

func expectedByCase(id string) string {
	switch id {
	case "D01":
		return "After flood window, 10/10 legitimate probes must still be accepted (200 or tolerated 429)"
	case "D02":
		return "WAF should terminate stale slowloris sockets and still accept a fresh valid connection"
	case "D03":
		return "WAF should kill slow POST connection within 30 seconds"
	case "D04":
		return "Under overload, CRITICAL traffic should fail-close (503) while MEDIUM stays fail-open (200)"
	case "D05":
		return "With backend down=true: all 10 requests through WAF return 503 and each response <= 5s"
	case "D06":
		return "With backend delay_ms=10000: all 50 requests should timeout as 504 within <= 5s"
	case "D07":
		return "After restoring backend controls, WAF should recover to 200 traffic within 5 seconds"
	case "D08":
		return "Fail-mode mutation should force MEDIUM-like traffic to 503 consistently"
	case "D09":
		return "Fail-mode restore should return MEDIUM-like traffic to consistent 200"
	default:
		return "Expected behavior not defined"
	}
}

func observedSummary(id string, details map[string]interface{}) string {
	intv := func(k string) int64 {
		if details == nil {
			return 0
		}
		v, ok := details[k]
		if !ok {
			return 0
		}
		switch n := v.(type) {
		case int:
			return int64(n)
		case int32:
			return int64(n)
		case int64:
			return n
		case float64:
			return int64(n)
		default:
			return 0
		}
	}

	switch id {
	case "D01":
		return fmt.Sprintf("legitimate_passed=%d/%d after flood", intv("legitimate_passed"), intv("legitimate_total"))
	case "D02":
		return fmt.Sprintf("opened=%d, killed=%d, new_connection_accepted=%v", intv("connections_opened"), intv("connections_killed"), details["new_connection_accepted"])
	case "D03":
		return fmt.Sprintf("connection_killed=%v, kill_at_s=%d", details["connection_killed"], intv("connection_killed_at_seconds"))
	case "D04":
		return fmt.Sprintf("critical_503=%d/%d, medium_200=%d/%d", intv("critical_503_count"), intv("critical_total"), intv("medium_200_count"), intv("medium_total"))
	case "D05":
		return fmt.Sprintf("503=%d/%d, <=5s=%d/%d, request_errors=%d", intv("returned_503"), intv("attempted_requests"), intv("within_5s"), intv("attempted_requests"), intv("request_errors"))
	case "D06":
		return fmt.Sprintf("504=%d/%d, <=5s=%d/%d, request_errors=%d", intv("returned_504"), intv("attempted_requests"), intv("within_5s"), intv("attempted_requests"), intv("request_errors"))
	case "D07":
		return fmt.Sprintf("recovered=%v, recovery_time_ms=%d", details["recovered"], intv("recovery_time_ms"))
	case "D08":
		return fmt.Sprintf("returned_503=%d/5, request_errors=%d", intv("returned_503"), intv("request_errors"))
	case "D09":
		return fmt.Sprintf("returned_200=%d/5, request_errors=%d", intv("returned_200"), intv("request_errors"))
	default:
		return "No observed summary"
	}
}

func reasonFromCase(id string, passed bool, details map[string]interface{}) string {
	if passed {
		switch id {
		case "D05":
			return "PASS because all backend-down probes fast-failed with consistent 503 within the 5s SLA"
		case "D06":
			return "PASS because WAF did not wait full upstream delay and returned consistent 504 timeout responses"
		default:
			return "PASS because observed behavior matched Phase D acceptance criteria"
		}
	}

	if details == nil {
		return "FAILED because benchmark evidence map is empty"
	}
	if v, ok := details["control_error"]; ok {
		return fmt.Sprintf("FAILED due to control-plane error: %v", v)
	}
	if v, ok := details["set_health_mode_error"]; ok {
		return fmt.Sprintf("FAILED because health-mode mutation failed: %v", v)
	}
	if v, ok := details["set_slow_error"]; ok {
		return fmt.Sprintf("FAILED because slow-mode mutation failed: %v", v)
	}
	if v, ok := details["request_errors"]; ok && fmt.Sprint(v) != "0" {
		return fmt.Sprintf("FAILED due to request transport/proxy errors during verification window: %v", v)
	}
	if id == "D05" {
		return "FAILED because backend-down did not produce deterministic fast 503 for all 10 attempts"
	}
	if id == "D06" {
		return "FAILED because backend-slow did not produce deterministic fast 504 for all 50 attempts"
	}
	return "FAILED because observed runtime behavior diverged from expected Phase D policy"
}

func wafFeedbackForCase(id string, details map[string]interface{}) string {
	codes, ok := details["status_codes"]
	if ok {
		return fmt.Sprintf("status_codes=%v", codes)
	}
	if id == "D02" || id == "D03" {
		parts := []string{}
		if v, ok := details["waf_dial_addr"]; ok {
			parts = append(parts, fmt.Sprintf("dial=%v", v))
		}
		if v, ok := details["new_connection_accepted"]; ok {
			parts = append(parts, fmt.Sprintf("new_connection_accepted=%v", v))
		}
		if len(parts) > 0 {
			return strings.Join(parts, ", ")
		}
	}
	return "No explicit status code series captured; inspect evidence payload"
}

func computeQualityMetrics(report *PhaseDReport) QualityMetrics {
	qm := QualityMetrics{
		AccuracyDeterminism: AccuracyDeterminismMetrics{
			StatusOKRatioByCase:     map[string]float64{},
			DecisionFlapCountByCase: map[string]int{},
		},
		LatencyQuality: LatencyQualityMetrics{
			ByCase: map[string]LatencyStats{},
		},
	}

	for _, id := range report.CaseOrder {
		c, ok := report.Cases[id]
		if !ok {
			continue
		}

		codes := toIntSlice(c.Evidence["status_codes"])
		expected := expectedStatusForCase(id)
		okRatio := statusOKRatio(codes, expected)
		qm.AccuracyDeterminism.StatusOKRatioByCase[id] = okRatio
		qm.AccuracyDeterminism.DecisionFlapCountByCase[id] = decisionFlapCount(codes)

		lat := toInt64Slice(c.Evidence["latency_ms"])
		if len(lat) > 0 {
			qm.LatencyQuality.ByCase[id] = calcLatencyStats(lat)
		}
	}

	qm.AccuracyDeterminism.PolicyConsistencyScore = computePolicyConsistency(report)

	if d01, ok := qm.LatencyQuality.ByCase["D01"]; ok {
		qm.LatencyQuality.LegitRecoveryLatencyP95 = d01.P95Ms
	}
	if d05, ok := qm.LatencyQuality.ByCase["D05"]; ok {
		qm.LatencyQuality.FastFailP95 = d05.P95Ms
	}
	if d06, ok := qm.LatencyQuality.ByCase["D06"]; ok {
		timeoutMs := 5000.0
		qm.LatencyQuality.TimeoutAlignmentErrorMs = math.Abs(d06.P50Ms - timeoutMs)
	}

	qm.ServiceContinuity = computeServiceContinuity(report)
	qm.RecoveryControl = computeRecoveryControl(report)
	qm.ResourceEfficiency = ResourceEfficiencyMetrics{}
	return qm
}

func computeServiceContinuity(report *PhaseDReport) ServiceContinuityMetrics {
	sc := ServiceContinuityMetrics{}
	var legitTotal float64
	var legitOK float64

	if d01, ok := report.Cases["D01"]; ok {
		passed := toFloat64(d01.Evidence["legitimate_passed"])
		total := toFloat64(d01.Evidence["legitimate_total"])
		legitOK += passed
		legitTotal += total
	}
	if d04, ok := report.Cases["D04"]; ok {
		mOK := toFloat64(d04.Evidence["medium_200_count"])
		mTotal := toFloat64(d04.Evidence["medium_total"])
		legitOK += mOK
		legitTotal += mTotal

		// Collateral: medium expected 200 but got non-200
		sc.CollateralBlockCount = int(math.Max(0, mTotal-mOK))
	}

	if legitTotal > 0 {
		sc.LegitSuccessRatioUnderAttack = legitOK / legitTotal
	}

	if d02, ok := report.Cases["D02"]; ok {
		if b, ok := d02.Evidence["new_connection_accepted"].(bool); ok && b {
			sc.NewConnAcceptRatio = 1.0
		}
	}

	return sc
}

func computeRecoveryControl(report *PhaseDReport) RecoveryControlMetrics {
	rc := RecoveryControlMetrics{}
	if d07, ok := report.Cases["D07"]; ok {
		rc.RecoveryTimeToGreenMs = toFloat64(d07.Evidence["recovery_time_ms"])
	}
	// We don't currently measure exact config apply latency; use observed polling window fallback.
	if d08, ok := report.Cases["D08"]; ok {
		rc.ConfigApplyLatencyMs = toFloat64(d08.Evidence["total_wait_ms"])
	}
	if report.Cases["D09"].Passed {
		rc.ConfigRollbackSafety = 1.0
	}
	return rc
}

func computePolicyConsistency(report *PhaseDReport) float64 {
	d04 := report.Cases["D04"].Evidence
	crit503 := toFloat64(d04["critical_503_count"])
	critTotal := toFloat64(d04["critical_total"])
	med200 := toFloat64(d04["medium_200_count"])
	medTotal := toFloat64(d04["medium_total"])

	d08OK := boolToFloat(report.Cases["D08"].Passed)
	d09OK := boolToFloat(report.Cases["D09"].Passed)

	p1 := ratioOrZero(crit503, critTotal)
	p2 := ratioOrZero(med200, medTotal)
	return (p1 + p2 + d08OK + d09OK) / 4.0
}

func computeTieBreak(qm QualityMetrics) TieBreakSummary {
	weights := map[string]float64{
		"continuity":          0.30,
		"tail_latency":        0.25,
		"stability":           0.15,
		"recovery_speed":      0.15,
		"config_agility":      0.10,
		"resource_efficiency": 0.05,
	}

	cont := qm.ServiceContinuity.LegitSuccessRatioUnderAttack
	tail := normalizeLowerBetter(qm.LatencyQuality.FastFailP95, 5000)
	stab := normalizeLowerBetter(float64(sumIntMap(qm.AccuracyDeterminism.DecisionFlapCountByCase)), 20)
	recover := normalizeLowerBetter(qm.RecoveryControl.RecoveryTimeToGreenMs, 5000)
	agility := normalizeLowerBetter(qm.RecoveryControl.ConfigApplyLatencyMs, 3000)
	resource := 0.5 // placeholder until CPU/RAM/FD instrumentation exists

	signals := map[string]float64{
		"continuity":          cont,
		"tail_latency":        tail,
		"stability":           stab,
		"recovery_speed":      recover,
		"config_agility":      agility,
		"resource_efficiency": resource,
	}

	score := cont*weights["continuity"] +
		tail*weights["tail_latency"] +
		stab*weights["stability"] +
		recover*weights["recovery_speed"] +
		agility*weights["config_agility"] +
		resource*weights["resource_efficiency"]

	return TieBreakSummary{
		PhaseDQualityScore: score,
		Weights:            weights,
		Signals:            signals,
	}
}

func expectedStatusForCase(id string) int {
	switch id {
	case "D04":
		return 503
	case "D05":
		return 503
	case "D06":
		return 504
	case "D07", "D09":
		return 200
	case "D08":
		return 503
	default:
		return 0
	}
}

func statusOKRatio(codes []int, expected int) float64 {
	if len(codes) == 0 {
		return 0
	}
	if expected == 0 {
		return 1
	}
	ok := 0
	for _, c := range codes {
		if c == expected {
			ok++
		}
	}
	return float64(ok) / float64(len(codes))
}

func decisionFlapCount(codes []int) int {
	if len(codes) < 2 {
		return 0
	}
	count := 0
	for i := 1; i < len(codes); i++ {
		if codes[i] != codes[i-1] {
			count++
		}
	}
	return count
}

func calcLatencyStats(values []int64) LatencyStats {
	if len(values) == 0 {
		return LatencyStats{}
	}
	f := make([]float64, 0, len(values))
	for _, v := range values {
		f = append(f, float64(v))
	}
	sort.Float64s(f)

	mean := 0.0
	for _, v := range f {
		mean += v
	}
	mean /= float64(len(f))

	var variance float64
	for _, v := range f {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(f))

	return LatencyStats{
		P50Ms:    percentileSorted(f, 0.50),
		P95Ms:    percentileSorted(f, 0.95),
		P99Ms:    percentileSorted(f, 0.99),
		MaxMs:    f[len(f)-1],
		StdDevMs: math.Sqrt(variance),
	}
}

func percentileSorted(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if q <= 0 {
		return sorted[0]
	}
	if q >= 1 {
		return sorted[len(sorted)-1]
	}
	idx := q * float64(len(sorted)-1)
	lo := int(math.Floor(idx))
	hi := int(math.Ceil(idx))
	if lo == hi {
		return sorted[lo]
	}
	frac := idx - float64(lo)
	return sorted[lo] + (sorted[hi]-sorted[lo])*frac
}

func normalizeLowerBetter(value, baseline float64) float64 {
	if baseline <= 0 {
		return 0
	}
	r := 1 - (value / baseline)
	if r < 0 {
		return 0
	}
	if r > 1 {
		return 1
	}
	return r
}

func ratioOrZero(num, den float64) float64 {
	if den <= 0 {
		return 0
	}
	return num / den
}

func boolToFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func sumIntMap(m map[string]int) int {
	s := 0
	for _, v := range m {
		s += v
	}
	return s
}

func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int32:
		return float64(n)
	case int64:
		return float64(n)
	case float32:
		return float64(n)
	case float64:
		return n
	default:
		return 0
	}
}

func toIntSlice(v interface{}) []int {
	if v == nil {
		return nil
	}
	raw, ok := v.([]interface{})
	if !ok {
		if out, ok := v.([]int); ok {
			return out
		}
		return nil
	}
	out := make([]int, 0, len(raw))
	for _, x := range raw {
		out = append(out, int(toFloat64(x)))
	}
	return out
}

func toInt64Slice(v interface{}) []int64 {
	if v == nil {
		return nil
	}
	raw, ok := v.([]interface{})
	if !ok {
		if out, ok := v.([]int64); ok {
			return out
		}
		return nil
	}
	out := make([]int64, 0, len(raw))
	for _, x := range raw {
		out = append(out, int64(toFloat64(x)))
	}
	return out
}
