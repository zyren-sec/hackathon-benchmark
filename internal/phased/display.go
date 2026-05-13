package phased

import (
	"fmt"
	"strings"
	"time"
)

// ── Console Display: matches phase_D.md §10.2 template ──

// DisplayPhaseDResult prints the full Phase D result to stdout.
func DisplayPhaseDResult(r *PhaseDResult) {
	w := 66

	// ═══ HEADER ═══
	printDSeparator("═", w)
	fmt.Println("  WAF-BENCHMARK — PHASE D: RESILIENCE & DEGRADATION TESTS")
	fmt.Printf("  Timestamp : %s\n", r.StartTime.Format(time.RFC3339))
	fmt.Printf("  WAF Target: %s\n", r.WAFTarget)
	fmt.Printf("  WAF Mode  : %s\n", r.WAFMode)
	printDSeparator("═", w)
	fmt.Println()

	// ═══ PRE-FLIGHT ═══
	fmt.Println("── PRE-FLIGHT HEALTH CHECKS ────────────────────────────────────")
	if r.WAFAlive {
		fmt.Println("  WAF alive ......... ✓")
	} else {
		fmt.Println("  WAF alive ......... ✗")
	}
	if r.UpstreamAlive {
		fmt.Println("  UPSTREAM healthy .. ✓")
	} else {
		fmt.Println("  UPSTREAM healthy .. ✗")
	}
	printDDivider(w)
	fmt.Println()

	// ═══ RESET SEQUENCE ═══
	fmt.Println("── FULL RESET SEQUENCE (9 bước — §3.1) ────────────────────────")
	for _, s := range r.ResetSteps {
		icon := "✓"
		if !s.Success {
			icon = "✗"
		}
		fmt.Printf("  [%d/9] %-4s %-33s → %s\n",
			s.StepNum, s.Method, s.Name, formatDResetStepStatus(s, icon))
	}
	if r.ResetAllPassed {
		fmt.Println("  Result: ALL 9/9 OK ✓")
	} else {
		fmt.Println("  Result: FAIL ✗")
		fmt.Println()
		printDSeparator("═", w)
		fmt.Println("  PHASE D ABORTED — Reset sequence failed")
		printDSeparator("═", w)
		return
	}
	printDDivider(w)
	fmt.Println()

	// ═══ TEST RESULTS BY CATEGORY ═══
	catOrder := []struct {
		id    string
		name  string
	}{
		{"ddos", "DDoS Stress Tests"},
		{"backend_failure", "Backend Failure Tests"},
		{"fail_mode_config", "Fail-Mode Configurability"},
	}

	for ci, cat := range catOrder {
		catTests := filterTestsByCategory(r, cat.id)
		if len(catTests) == 0 {
			continue
		}

		catPassed := 0
		catTotal := 0
		catScore := 0.0
		for _, tr := range catTests {
			catTotal++
			if tr.Passed {
				catPassed++
				catScore += tr.MaxScore
			}
		}

		label := fmt.Sprintf("── CAT %d: %s ", ci+1, cat.name)
		pad := w - len(label)
		if pad < 0 {
			pad = 0
		}
		fmt.Println(label + strings.Repeat("─", pad))
		fmt.Println("  Criterion: INT-04 (Resilience & DDoS) — Cap 8 pts")
		printDDivider(w)

		for _, tr := range catTests {
			displayDTest(&tr, w)
		}

		printDDivider(w)
		fmt.Printf("  CAT %d Result: %d/%d passed | Score: %.1f pts\n",
			ci+1, catPassed, catTotal, catScore)
		fmt.Println()
	}

	// ═══ DIAGNOSTIC ═══
	if r.ResourceTier != "" {
		fmt.Printf("── DIAGNOSTIC ──────────────────────────────────────────────────\n")
		fmt.Printf("  Resource Tier:     %s\n", r.ResourceTier)
		if len(r.DiagnosticFlags) > 0 {
			fmt.Printf("  Flags:             %v\n", r.DiagnosticFlags)
		}
		if r.CgroupsActive {
			fmt.Println("  CPU Pinning:       ✅ Active (cgroups v2)")
		}
		printDDivider(w)
		fmt.Println()
	}

	// ═══ SCORING SUMMARY ═══
	printDSeparator("═", w)
	fmt.Println("  PHASE D — SCORING SUMMARY")
	printDDivider(w)

	// Raw breakdown
	for _, tr := range r.TestResults {
		score := 0.0
		status := "FAIL ✗"
		if tr.Passed {
			score = tr.MaxScore
			status = "PASS ✓"
		} else if tr.Skipped {
			status = "SKIP ⚠"
		}
		fmt.Printf("  %-5s %-38s %s   +%.1f pts\n",
			tr.TestID, tr.Name, status, score)
	}

	printDDivider(w)
	fmt.Printf("  Raw score:  %.1f / %.1f\n", r.RawScore, r.RawMaxScore)
	fmt.Printf("  INT-04 cap:  %.1f\n", r.INT04Cap)
	printDDivider(w)
	fmt.Printf("  INT-04 (Resilience & DDoS):   %.1f / %.0f  %s\n",
		r.INT04Score, r.INT04Cap,
		map[bool]string{true: "(capped)", false: ""}[r.INT04Score < r.RawScore])
	printDSeparator("═", w)
}

func displayDTest(tr *DTestResult, w int) {
	// Test header
	fmt.Printf("\n  %s — %s", tr.TestID, tr.Name)
	if tr.Skipped {
		fmt.Printf(" (SKIPPED: %s)", tr.SkipReason)
	}
	fmt.Println()
	fmt.Println("  " + strings.Repeat("─", w-2))

	// Tool output summary
	switch {
	case tr.ActualRPS > 0:
		fmt.Printf("    wrk2: %.1f RPS | Avg: %.1fms | P99: %.1fms | Errors: connect=%d read=%d write=%d timeout=%d\n",
			tr.ActualRPS, tr.LatencyAvgMs, tr.LatencyP99Ms,
			tr.SocketErrors["connect"], tr.SocketErrors["read"],
			tr.SocketErrors["write"], tr.SocketErrors["timeout"])
	case tr.TestID == "D02" || tr.TestID == "D03":
		fmt.Printf("    slowhttptest: %d closed, %d pending, %d error | Service Available: %v\n",
			tr.ConnectionsClosed, tr.ConnectionsPending, tr.ConnectionsError, tr.ServiceAvailable)
	case tr.TestID == "D05" || tr.TestID == "D06" || tr.TestID == "D07":
		action := "N/A"
		if tr.CircuitBroken {
			action = "circuit_breaker"
		} else if tr.TimeoutDetected {
			action = "timeout"
		}
		fmt.Printf("    WAF action: %s\n", action)
	}

	// Verification results
	if len(tr.DuringVerifyResults) > 0 {
		fmt.Printf("    During-flood verify: %d/%d passed\n",
			countPassed(tr.DuringVerifyResults), len(tr.DuringVerifyResults))
	}
	if len(tr.PostVerifyResults) > 0 {
		fmt.Printf("    Post-test verify: %d/%d passed\n",
			countPassed(tr.PostVerifyResults), len(tr.PostVerifyResults))
	}
	if len(tr.TierResults) > 0 {
		for tier, tres := range tr.TierResults {
			cls := "✓"
			if !tres.AllPassed {
				cls = "✗"
			}
			fmt.Printf("    %s tier: %d/%d correct %s (expect %s)\n",
				tier, tres.PassedRoutes, tres.TotalRoutes, cls, tres.ExpectedMode)
		}
	}
	if len(tr.RecoveryResults) > 0 {
		fmt.Printf("    Recovery verify: %d/%d passed\n",
			countPassed(tr.RecoveryResults), len(tr.RecoveryResults))
	}

	// Result
	if tr.Passed {
		fmt.Printf("    %s Result: PASS ✓ (+%.1f pts)   (%.1fs)\n",
			tr.TestID, tr.MaxScore, tr.DurationSec)
	} else if tr.Skipped {
		fmt.Printf("    %s Result: SKIPPED (%s)\n", tr.TestID, tr.SkipReason)
	} else {
		fmt.Printf("    %s Result: FAIL ✗ (+0.0 pts) — %s   (%.1fs)\n",
			tr.TestID, tr.FailReason, tr.DurationSec)
	}

	// Scoring explanation (compact)
	if tr.ScoringExplain != "" {
		for _, line := range strings.Split(tr.ScoringExplain, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Printf("      %s\n", strings.TrimSpace(line))
			}
		}
	}
}

// ── Helpers ──

func printDSeparator(ch string, width int) {
	fmt.Println(strings.Repeat(ch, width))
}

func printDDivider(width int) {
	fmt.Println(strings.Repeat("─", width))
}

func formatDResetStepStatus(s DResetStep, icon string) string {
	if s.Success {
		if s.StatusCode == 200 || s.StatusCode == 201 || s.StatusCode == 204 {
			return fmt.Sprintf("status %d ✓", s.StatusCode)
		}
		return fmt.Sprintf("status %d ✓", s.StatusCode)
	}
	if s.Error != "" {
		return fmt.Sprintf("FAIL ✗ (%s)", s.Error)
	}
	return fmt.Sprintf("status %d ✗", s.StatusCode)
}

func filterTestsByCategory(r *PhaseDResult, catID string) []DTestResult {
	var filtered []DTestResult
	for _, tr := range r.TestResults {
		if tr.Category == catID {
			filtered = append(filtered, tr)
		}
	}
	return filtered
}
