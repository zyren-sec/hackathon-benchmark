package phasec

import (
	"fmt"
	"strings"
	"time"
)

// ── Console Display: Phase C §10.1 Template ──

func DisplayPhaseCResult(r *PhaseCResult) {
	w := 66

	// ═══ HEADER ═══
	printCSeparator("═", w)
	fmt.Println("  WAF-BENCHMARK — PHASE C: PERFORMANCE & THROUGHPUT TESTS")
	fmt.Printf("  Timestamp : %s\n", r.StartTime.Format(time.RFC3339))
	fmt.Printf("  WAF Target: %s\n", r.WAFTarget)
	fmt.Printf("  WAF Mode  : %s\n", r.WAFMode)
	fmt.Println("  Traffic Mix: 60% Legitimate | 10% Suspicious | 10% Exploit | 10% Abuse | 10% DDoS")
	fmt.Printf("  Source IPs: 127.0.0.200–220 (21 loopback aliases)\n")
	printCSeparator("═", w)
	fmt.Println()

	// ═══ FULL RESET SEQUENCE ═══
	fmt.Println("── FULL RESET SEQUENCE (5 bước — §3.1) ──────────────────────────")
	for _, s := range r.ResetSteps {
		icon := "✓"
		if !s.Success {
			icon = "✗"
		}
		fmt.Printf("  [%d/5] %-4s %-33s → %s\n",
			s.StepNum, s.Method, "", formatCResetStepStatus(s, icon))
	}
	if r.ResetAllPassed {
		fmt.Println("  Result: ALL 5/5 OK ✓")
	} else {
		fmt.Println("  Result: FAIL ✗")
		fmt.Println()
		printCSeparator("═", w)
		fmt.Println("  PHASE C ABORTED — Reset sequence failed")
		printCSeparator("═", w)
		return
	}
	printCDivider(w)
	fmt.Println()

	// ═══ WAF PID ═══
	if r.MemoryMonitorOK {
		fmt.Printf("  WAF PID: %s — Memory monitoring: enabled ✓\n\n", r.WAFPID)
	} else {
		fmt.Println("  WAF PID: not found — Memory monitoring: disabled ⚠")
	}

	// ═══ BASELINE LATENCY ═══
	fmt.Println("── BASELINE LATENCY (Direct to UPSTREAM :9000) ──────────────────")
	if r.BaselineFailed {
		fmt.Printf("  FAILED: %s\n", r.BaselineFailReason)
		fmt.Println("  → Using WAF latency directly (no overhead calculation possible)")
	} else if r.Baseline != nil {
		fmt.Println("  Class          Endpoints                          P50      P99      Avg       Samples")
		printCDivider(w)
		for _, cls := range r.Baseline.Classes {
			endpoints := strings.Join(cls.Endpoints, ", ")
			if len(endpoints) > 35 {
				endpoints = endpoints[:32] + "..."
			}
			fmt.Printf("  %-14s %-35s %7.3f  %7.3f  %7.3f  %7d\n",
				cls.Name, endpoints, cls.P50Ms, cls.P99Ms, cls.AvgMs, cls.Samples)
		}
	}
	printCDivider(w)
	fmt.Println()

	// ═══ WAF LATENCY ═══
	if r.WAFLatency != nil {
		fmt.Println("── WAF LATENCY (Through WAF :8080) ──────────────────────────────")
		fmt.Println("  Class          P50      P99      Avg       OverheadP50  OverheadP99  Overhead%")
		printCDivider(w)
		for _, cls := range r.WAFLatency.Classes {
			fmt.Printf("  %-14s %7.3f  %7.3f  %7.3f  %10.3f  %10.3f  %8.1f%%\n",
				cls.Name, cls.P50Ms, cls.P99Ms, cls.AvgMs,
				cls.OverheadP50, cls.OverheadP99, cls.OverheadPct)
		}
		printCDivider(w)
		fmt.Println()
	}

	// ═══ LOAD TEST STEPS ═══
	for _, s := range r.LoadTestSteps {
		displayCLoadTestStep(&s, w, r)
	}

	// ═══ FALSE POSITIVE ANALYSIS ═══
	fmt.Println("── FALSE POSITIVE ANALYSIS ──────────────────────────────────────")
	fmt.Printf("  Total Legitimate Requests:   %d\n", totalLegitFromSteps(r))
	fmt.Printf("  False Positives (outside DDoS): %d\n", r.FPCount)
	fmt.Printf("  Collaterals (during DDoS):      %d\n", r.CollateralCount)
	if r.FPRate > 0 {
		fmt.Printf("  FP Rate:                        %.3f%%\n", r.FPRate*100)
	} else {
		fmt.Println("  FP Rate:                        0.000%")
	}
	if len(r.FPDetails) > 0 {
		fmt.Println("  Sample False Positives:")
		for i, fp := range r.FPDetails {
			if i >= 5 {
				fmt.Printf("  ... and %d more\n", len(r.FPDetails)-5)
				break
			}
			ddsTag := ""
			if fp.DuringDDoS {
				ddsTag = " [DDoS]"
			}
			fmt.Printf("    %s → HTTP %d (WAF: %s, Risk: %d) %.2fms%s\n",
				fp.Endpoint, fp.StatusCode, fp.WAFAction, fp.RiskScore, fp.LatencyMs, ddsTag)
		}
	}
	printCDivider(w)
	fmt.Println()

	// ═══ DIAGNOSTIC ═══
	fmt.Println("── DIAGNOSTIC ──────────────────────────────────────────────────")
	fmt.Printf("  Resource Tier:     %s (WAF: %dC/%.0fGB)\n",
		r.ResourceTier, r.TierConfig.WAFCores, float64(r.TierConfig.WAFMemoryMax)/(1024*1024*1024))
	if r.CgroupsActive {
		fmt.Printf("  CPU Pinning:       ✅ Active (WAF: %s, Bench: %s)\n",
			r.TierConfig.WAFCpuset, r.TierConfig.BenchCpuset)
	} else {
		fmt.Println("  CPU Pinning:       ⚠️  Not active (cgroups v2 unavailable)")
	}
	if r.ProfilerActive && r.NoiseReport != nil {
		icon := "🟢"
		if r.NoiseReport.Flag == NoiseNoisy || r.NoiseReport.Flag == NoisePotentiallyNoisy {
			icon = "🟡"
		} else if r.NoiseReport.Flag == NoiseContaminated {
			icon = "🔴"
		}
		fmt.Printf("  Noise Flag:        %s %s (±%.1fms estimate)\n",
			icon, r.NoiseReport.Flag, r.NoiseReport.EstimateMs)
		if r.NoiseReport.CorrelationBench > 0 {
			fmt.Printf("  Correlation:       latency↔waf_cpu     r=%.2f\n", r.NoiseReport.CorrelationWAF)
			fmt.Printf("                     latency↔bench_cpu   r=%.2f\n", r.NoiseReport.CorrelationBench)
			fmt.Printf("                     latency↔ctx_switch  r=%.2f\n", r.NoiseReport.CorrelationCtx)
		}
	} else {
		fmt.Println("  Noise Flag:        DISABLED (profiler inactive)")
	}
	if r.NoiseReport != nil && r.NoiseReport.MemoryLeakDetected {
		fmt.Println("  Memory:            ⚠️  Potential leak detected")
	}
	printCDivider(w)
	fmt.Println()

	// ═══ SCORING SUMMARY ═══
	displayCScoringSummary(r, w)
}

// displayCLoadTestStep prints one load test step block.
func displayCLoadTestStep(step *LoadTestStepResult, w int, r *PhaseCResult) {
	// Step header
	marker := ""
	switch step.StepNum {
	case 3:
		marker = "  ⬤ SLA TARGET"
	case 4:
		marker = "  ⚡ STRESS TEST"
	}

	fmt.Printf("── STEP %d: %d RPS × %ds%s ──────────────────────────────\n",
		step.StepNum, step.TargetRPS, step.DurationSec, marker)

	// Key-value display
	items := []struct {
		label string
		value string
	}{
		{"Target RPS", fmt.Sprintf("%d", step.TargetRPS)},
		{"Actual RPS", fmt.Sprintf("%.1f", step.ActualRPS)},
		{"Total Requests", fmt.Sprintf("%d", step.TotalRequests)},
		{"Success Rate", fmt.Sprintf("%.2f%%", step.SuccessRate*100)},
		{"Error Rate", fmt.Sprintf("%.2f%%", step.ErrorRate*100)},
		{"Blocked Rate", fmt.Sprintf("%.2f%%", step.BlockedRate*100)},
		{"Latency P50", fmt.Sprintf("%.3fms", step.P50Ms)},
		{"Latency P99", fmt.Sprintf("%.3fms", step.P99Ms)},
		{"Latency Max", fmt.Sprintf("%.3fms", step.MaxMs)},
		{"Memory Peak", fmt.Sprintf("%.1f MB", step.MemoryPeakMB)},
		{"False Positives", fmt.Sprintf("%d", step.FalsePositiveCount)},
		{"Collateral Blocks", fmt.Sprintf("%d", step.CollateralCount)},
	}

	for _, item := range items {
		fmt.Printf("  %-22s %s\n", item.label+":", item.value)
	}

	// PERF checks for specific steps
	if step.StepNum == 3 {
		fmt.Println()
		fmt.Printf("  PERF-01 Check (p99 ≤ %.0fms): %s\n", r.Scores["PERF-01"].Threshold, passFailStr(step.P99Ms <= r.Scores["PERF-01"].Threshold))
		fmt.Printf("  PERF-02 Check (RPS ≥ %.0f): %s\n", r.Scores["PERF-02"].Threshold, passFailStr(step.ActualRPS >= r.Scores["PERF-02"].Threshold))
	}
	if step.StepNum == 4 {
		fmt.Println()
		fmt.Printf("  PERF-04 Check (no crash + error < %.0f%%): %s\n",
			r.Scores["PERF-04"].Threshold*100, passFailStr(r.Scores["PERF-04"].Pass))
	}

	// Step result
	if step.Passed {
		fmt.Printf("  Result: PASS ✓\n")
	} else {
		fmt.Printf("  Result: FAIL ✗ (%s)\n", step.FailReason)
	}
	fmt.Println()
}

func displayCScoringSummary(r *PhaseCResult, w int) {
	printCSeparator("═", w)
	fmt.Println("  PHASE C — SCORING SUMMARY")
	printCDivider(w)

	criteria := []struct {
		id          string
		description string
	}{
		{"PERF-01", "p99 Latency ≤ 5ms at 5k RPS"},
		{"PERF-02", "Throughput ≥ 5000 RPS"},
		{"PERF-03", "Memory Peak < 100MB"},
		{"PERF-04", "No Crash + Error < 5% at 10k RPS"},
	}

	for _, c := range criteria {
		sc, ok := r.Scores[c.id]
		if !ok {
			continue
		}
		status := "PASS ✓"
		if !sc.Pass {
			status = "FAIL ✗"
		}
		fmt.Printf("  %-8s %-37s %-10s %s\n",
			c.id, c.description, status, sc.Explanation)
	}
	printCDivider(w)
	fmt.Printf("  PHASE C TOTAL                                    =  %4.0f / %.0f\n",
		r.PhaseCTotal, r.PhaseCMax)
	printCSeparator("═", w)
}

// ── Helpers ──

func printCSeparator(ch string, width int) {
	fmt.Println(strings.Repeat(ch, width))
}

func printCDivider(width int) {
	fmt.Println(strings.Repeat("─", width))
}

func formatCResetStepStatus(s CResetStep, icon string) string {
	if s.Success {
		switch s.StepNum {
		case 1:
			return fmt.Sprintf("UPSTREAM ....... %d OK ✓", s.StatusCode)
		case 2:
			return "UPSTREAM ....... healthy ✓"
		case 3:
			return "WAF mode ....... enforce ✓"
		case 4:
			if s.StatusCode == 200 {
				return "WAF cache ...... cleared ✓"
			}
			return "WAF cache ...... not supported (501) ✓"
		case 5:
			return "WAF state ...... clean ✓"
		}
		return fmt.Sprintf("status %d ✓", s.StatusCode)
	}

	if s.Error != "" {
		return fmt.Sprintf("FAIL ✗ (%s)", s.Error)
	}
	return fmt.Sprintf("status %d ✗", s.StatusCode)
}

func passFailStr(cond bool) string {
	if cond {
		return "PASS ✓"
	}
	return "FAIL ✗"
}

func totalLegitFromSteps(r *PhaseCResult) int {
	total := 0
	for _, s := range r.LoadTestSteps {
		total += s.TotalRequests
	}
	return total
}
