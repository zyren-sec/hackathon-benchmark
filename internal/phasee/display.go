package phasee

import (
	"fmt"
	"strings"
	"time"
)

// ── Console Display: consistent with Phase A/B/D output format ──

// DisplayPhaseEResult prints the full Phase E result to stdout.
func DisplayPhaseEResult(r *PhaseEResult) {
	w := 66

	// ═══ HEADER ═══
	printESeparator("═", w)
	fmt.Println("  WAF-BENCHMARK — PHASE E: EXTENSIBILITY TESTS")
	fmt.Printf("  Timestamp : %s\n", r.StartTime.Format(time.RFC3339))
	fmt.Printf("  WAF Target: %s\n", r.WAFTarget)
	fmt.Printf("  WAF Mode  : %s\n", r.WAFMode)
	if r.ConfigDetected {
		fmt.Printf("  Config    : %s (%s)\n", r.ConfigPath, r.ConfigFormat)
	}
	printESeparator("═", w)
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
	if !r.ConfigDetected {
		// v2.5: EXT-01/EXT-02 are manual-only — config detection not needed
		fmt.Println("  WAF config ........ (not detected — EXT-01/EXT-02 are manual)")
	} else {
		fmt.Printf("  WAF config ........ %s (%s)\n", r.ConfigPath, r.ConfigFormat)
	}
	printEDivider(w)
	fmt.Println()

	// ═══ RESET SEQUENCE ═══
	fmt.Println("── FULL RESET SEQUENCE (4 bước — §3.1) ────────────────────────")
	for _, s := range r.ResetSteps {
		icon := "✓"
		if !s.Success {
			icon = "✗"
		}
		fmt.Printf("  [%d/%d] %-4s %-40s → %s\n",
			s.StepNum, len(r.ResetSteps), s.Method, s.Name, formatEResetStepStatus(s, icon))
	}
	if r.ResetAllPassed {
		fmt.Printf("  Result: ALL %d/%d OK ✓\n", len(r.ResetSteps), len(r.ResetSteps))
	} else {
		fmt.Println("  Result: FAIL ✗")
		fmt.Println()
		printESeparator("═", w)
		fmt.Println("  PHASE E ABORTED — Reset sequence failed")
		printESeparator("═", w)
		return
	}
	printEDivider(w)
	fmt.Println()

	// ═══ TEST RESULTS BY CATEGORY ═══
	catOrder := []struct {
		id    string
		name  string
	}{
		{"caching", "Caching Correctness (Automated)"},
	}

	for ci, cat := range catOrder {
		catTests := eFilterTestsByCategory(r, cat.id)
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
				catScore += tr.Score
			}
		}

		label := fmt.Sprintf("── CAT %d: %s ", ci+1, cat.name)
		pad := w - len(label)
		if pad < 0 {
			pad = 0
		}
		fmt.Println(label + strings.Repeat("─", pad))
		fmt.Println("  Criterion: EXT (Extensibility)")
		printEDivider(w)

		for _, tr := range catTests {
			displayETest(&tr, w)
		}

		printEDivider(w)
		fmt.Printf("  CAT %d Result: %d/%d passed | Score: %.1f pts\n",
			ci+1, catPassed, catTotal, catScore)
		fmt.Println()
	}

	// ═══ SCORING SUMMARY ═══
	printESeparator("═", w)
	fmt.Println("  PHASE E — SCORING SUMMARY")
	printEDivider(w)

	// EXT-01 — Manual
	fmt.Println("  EXT-01 — Hot-reload Add Rule         MANUAL ⚠   +0/3 pts (BTC)")
	fmt.Println("           ── Đánh giá thủ công bởi BTC trong demo/live")

	// EXT-02 — Manual
	fmt.Println("  EXT-02 — Hot-reload Remove Rule      MANUAL ⚠   +0/3 pts (BTC)")
	fmt.Println("           ── Đánh giá thủ công bởi BTC trong demo/live")

	// EXT-03 — Automated
	if r.EXT03Score > 0 {
		fmt.Printf("  EXT-03 — Caching Correctness         PASS ✓   +%.0f/4 pts\n", r.EXT03Score)
		// Show sub-scores
		subIDs := []string{"E01", "E02", "E03", "E04"}
		subNames := map[string]string{
			"E01": "STATIC route cached (HIT)",
			"E02": "CRITICAL route NOT cached",
			"E03": "TTL expiry honored",
			"E04": "Auth route NOT cached",
		}
		for _, id := range subIDs {
			icon := "✗"
			if r.EXT03SubScores[id] > 0 {
				icon = "✓"
			}
			fmt.Printf("    %s: %s %s\n", id, subNames[id], icon)
		}
	} else if isSkipped(r, "EXT-03") {
		fmt.Println("  EXT-03 — Caching Correctness         SKIP ⚠   +0/4 pts")
	} else {
		fmt.Println("  EXT-03 — Caching Correctness         FAIL ✗   +0/4 pts")
	}

	printEDivider(w)
	fmt.Printf("  Automated Score (EXT-03):  %.0f / %.0f pts\n", r.TotalScore, r.MaxScore)
	fmt.Println()
	fmt.Printf("  Full Phase E (incl. manual): %.0f + (EXT-01/EXT-02 manual) / 10 pts\n", r.TotalScore)
	printESeparator("═", w)
	fmt.Println()
	fmt.Println("  Scoring Methodology (v2.5):")
	fmt.Println("    EXT-01 — Hot-reload Add Rule    : 3 pts — MANUAL (BTC demo/live)")
	fmt.Println("    EXT-02 — Hot-reload Remove Rule  : 3 pts — MANUAL (BTC demo/live)")
	fmt.Println("    EXT-03 — Caching Correctness     : 4 pts — AUTOMATED (1 pt × 4 sub-tests)")
	fmt.Println("    Automated Total: 4 pts | Full Total: 10 pts")
}

func displayETest(tr *ETestResult, w int) {
	// Test header
	fmt.Printf("\n  %s — %s", tr.TestID, tr.Name)
	if tr.Skipped {
		fmt.Printf(" (SKIPPED: %s)", tr.SkipReason)
	}
	fmt.Println()
	fmt.Println("  " + strings.Repeat("─", w-2))

	// Description
	fmt.Printf("    %s\n", wrapText(tr.Description, w-4))

	// Hot-reload metrics
	if tr.TestID == "EXT-01" || tr.TestID == "EXT-02" {
		if tr.HotReloadSLAOk {
			fmt.Printf("    Hot-reload latency: %.1fms (SLA ≤ 10s ✓)\n", tr.HotReloadLatencyMs)
		} else if tr.ConfigModified {
			fmt.Printf("    Hot-reload latency: %.1fms (SLA exceeded)\n", tr.HotReloadLatencyMs)
		}
		if tr.ConfigModified {
			if tr.ConfigRestored {
				fmt.Println("    Config state: modified → restored ✓")
			} else {
				fmt.Println("    Config state: modified")
			}
		}
	}

	// Cache test results
	if len(tr.CacheResults) > 0 {
		fmt.Println("    Cache checks:")
		for _, cr := range tr.CacheResults {
			icon := "✓"
			if !cr.MatchExpected {
				icon = "✗"
			}
			fmt.Printf("      #%d: %s %s → HTTP %d | X-WAF-Cache: %s %s (expect %s) | %.1fms\n",
				cr.RequestNum, cr.Method, cr.Endpoint,
				cr.StatusCode, cr.CacheHeader, icon, cr.ExpectedCache, cr.LatencyMs)
		}
	}

	// Verification results
	if len(tr.VerifyResults) > 0 {
		fmt.Printf("    Verification: ")
		allPassed := true
		for _, vr := range tr.VerifyResults {
			if !vr.Passed {
				allPassed = false
			}
		}
		if allPassed {
			fmt.Println("PASS ✓")
		} else {
			fmt.Println("FAIL ✗")
		}
	}

	// Fail conditions
	for _, fc := range tr.FailConditions {
		if fc.Triggered {
			fmt.Printf("    ⚠ %s: %s\n", fc.ID, fc.Description)
			if fc.Evidence != "" {
				fmt.Printf("      → %s\n", fc.Evidence)
			}
		}
	}

	// Result
	if tr.Passed {
		fmt.Printf("    %s Result: PASS ✓ (+%.1f pts)   (%.1fs)\n",
			tr.TestID, tr.Score, tr.DurationSec)
	} else if tr.Skipped {
		fmt.Printf("    %s Result: SKIPPED (%s)\n", tr.TestID, tr.SkipReason)
	} else {
		fmt.Printf("    %s Result: FAIL ✗ (+0.0 pts) — %s   (%.1fs)\n",
			tr.TestID, tr.FailReason, tr.DurationSec)
	}

	// Scoring explanation
	if tr.ScoringExplain != "" {
		for _, line := range strings.Split(tr.ScoringExplain, "\n") {
			if strings.TrimSpace(line) != "" {
				fmt.Printf("      %s\n", strings.TrimSpace(line))
			}
		}
	}
}

// ── Helpers ──

func printESeparator(ch string, width int) {
	fmt.Println(strings.Repeat(ch, width))
}

func printEDivider(width int) {
	fmt.Println(strings.Repeat("─", width))
}

func formatEResetStepStatus(s EResetStep, icon string) string {
	if s.Success {
		if s.StatusCode == 200 || s.StatusCode == 201 || s.StatusCode == 204 {
			return fmt.Sprintf("status %d ✓", s.StatusCode)
		}
		if s.StatusCode == 501 {
			return fmt.Sprintf("status 501 (not supported) ✓")
		}
		return fmt.Sprintf("status %d ✓", s.StatusCode)
	}
	if s.Error != "" {
		return fmt.Sprintf("FAIL ✗ (%s)", s.Error)
	}
	return fmt.Sprintf("status %d ✗", s.StatusCode)
}

func eFilterTestsByCategory(r *PhaseEResult, catID string) []ETestResult {
	var filtered []ETestResult
	for _, tr := range r.TestResults {
		if tr.Category == catID {
			filtered = append(filtered, tr)
		}
	}
	return filtered
}

func isSkipped(r *PhaseEResult, testID string) bool {
	for _, tr := range r.TestResults {
		if tr.TestID == testID && tr.Skipped {
			return true
		}
	}
	return false
}

func wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}
	return text[:width-3] + "..."
}
