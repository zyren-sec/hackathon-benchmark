package phasea

import (
	"fmt"
	"strings"
	"time"
)

// ── Console Display: matches phase_A.md §10.2 Template chi tiết ──

// DisplayPhaseAResult prints the full Phase A result to stdout in the exact format.
func DisplayPhaseAResult(r *PhaseAResult, tierFilter string) {
	totalWidth := 66

	// ── HEADER ──
	printSeparator("═", totalWidth)
	fmt.Println("  WAF-BENCHMARK — PHASE A: EXPLOIT PREVENTION TESTS")
	fmt.Printf("  Timestamp : %s\n", r.StartTime.Format(time.RFC3339))
	fmt.Printf("  WAF Target: %s\n", r.WAFTarget)
	fmt.Printf("  WAF Mode  : %s\n", r.WAFMode)
	if tierFilter != "" && tierFilter != "all" {
		fmt.Printf("  Payload Tier: %s\n", tierFilter)
	}
	printSeparator("═", totalWidth)
	fmt.Println()

	// ── FULL RESET SEQUENCE ──
	fmt.Println("── FULL RESET SEQUENCE (5 bước — §3.1) ──────────────────────────")
	for _, s := range r.ResetSteps {
		statusIcon := "✓"
		if !s.Success {
			statusIcon = "✗"
		}
		fmt.Printf("  [%d/5] %-4s %-33s → %s\n",
			s.StepNum, s.Method, s.URL, formatResetStepStatus(s, statusIcon))
	}

	if r.ResetAllPassed {
		fmt.Println("  Result: ALL 5/5 OK ✓")
	} else {
		fmt.Println("  Result: FAIL ✗")
		fmt.Println()
		fmt.Println("══════════════════════════════════════════════════════════════════")
		fmt.Println("  PHASE A ABORTED — Reset sequence failed")
		printSeparator("═", totalWidth)
		return
	}
	printDivider(totalWidth)
	fmt.Println()

	// ── NEGATIVE CONTROL ──
	fmt.Println("── NEGATIVE CONTROL ─────────────────────────────────────────────")
	if r.NegControlSkipped {
		fmt.Println("  SKIPPED — UPSTREAM cố ý trả về proof marker trên GET /.")
		fmt.Println("  Việc kiểm tra negative control tạm thời bị skip.")
	}
	printDivider(totalWidth)
	fmt.Println()

	// ── CATEGORY RESULTS ──
	for _, cat := range r.Categories {
		if cat.TotalCount == 0 {
			continue
		}

		// Category header
		label := fmt.Sprintf("── CAT %d: %s (%s) ", cat.CatNum, cat.Title, cat.IDRange)
		pad := totalWidth - len(label)
		if pad < 0 {
			pad = 0
		}
		fmt.Println(label + strings.Repeat("─", pad))
		fmt.Println("  Criterion: SEC-01 (15 pts)")

		for _, vr := range cat.VulnResults {
			displayVulnResult(&vr)
		}

		printDivider(totalWidth)
		fmt.Printf("  CAT %d Result: %d/%d V* passed\n", cat.CatNum, cat.PassedCount, cat.TotalCount)
		fmt.Println()
	}

	// ── SCORING SUMMARY ──
	printSeparator("═", totalWidth)
	fmt.Println("  PHASE A — SCORING SUMMARY")
	printDivider(totalWidth)

	fmt.Printf("  SEC-01   (Exploit Prevention)     %2d/%-2d × 15  =  %6.2f pts\n",
		r.PassedTests, r.TotalTests, r.SEC01Score)
	fmt.Printf("  RS-BONUS (Risk Score Accuracy)       %2d/%-2d      =  %6.2f pts  (tiebreaker)\n",
		r.RSBonusScore, r.RSBonusMax, float64(r.RSBonusScore))
	printDivider(totalWidth)
	fmt.Printf("  PHASE A TOTAL                                    = %6.2f / 15\n", r.SEC01Score)
	fmt.Printf("  BONUS (tiebreaker only)                          = %6.2f / %d\n",
		float64(r.RSBonusScore), r.RSBonusMax)
	printSeparator("═", totalWidth)
}

// displayVulnResult prints a single V* test per §10.2 template.
func displayVulnResult(vr *VulnResult) {
	totalWidth := 66

	// V* header line
	authLabel := "No"
	if vr.AuthRequired {
		authLabel = "Yes"
	}
	riskRange := fmt.Sprintf("%d–%d", vr.RiskMin, vr.RiskMax)
	fmt.Printf("\n  %s — %s | Auth: %s | %s | Risk: %s\n",
		vr.VulnID, vr.Name, authLabel, vr.Tier, riskRange)
	fmt.Println("  " + strings.Repeat("─", totalWidth-2))

	// Session status
	if vr.Skipped {
		if vr.SkipReason == "auth failed" {
			fmt.Println("    Session: failed")
			fmt.Printf("    %s Result: FAIL ✗ (auth failed)\n", vr.VulnID)
			return
		}
		fmt.Printf("    Session: N/A (skipped: %s)\n", vr.SkipReason)
		fmt.Printf("    %s Result: SKIP\n", vr.VulnID)
		return
	}

	if vr.AuthRequired {
		if vr.AuthSuccess {
			sidDisplay := vr.SessionID
			if len(sidDisplay) > 12 {
				sidDisplay = sidDisplay[:12] + "..."
			}
			fmt.Printf("    Session: ok (sid=%s)\n", sidDisplay)
		} else {
			fmt.Println("    Session: failed")
			fmt.Printf("    %s Result: FAIL ✗ (auth failed)\n", vr.VulnID)
			return
		}
	} else {
		fmt.Println("    Session: N/A")
	}

	// Payload list
	totalPayloads := len(vr.PayloadResults)
	blockedCount := vr.PassCount
	fmt.Printf("    Payloads: %d run, %d blocked\n", totalPayloads, blockedCount)

	// Sort: PASS first, FAIL after
	sorted := make([]PayloadResult, len(vr.PayloadResults))
	copy(sorted, vr.PayloadResults)
	// Simple bubble: move PASS items to front
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if !sorted[i].Passed && sorted[j].Passed {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Print each payload
	for _, pr := range sorted {
		displayPayloadResult(vr, &pr)
	}

	// V* Result
	if vr.OverallPassed {
		fmt.Printf("    %s Result: PASS ✓\n", vr.VulnID)
	} else {
		reason := fmt.Sprintf("%d/%d payloads bypassed", vr.FailCount, len(vr.PayloadResults))
		fmt.Printf("    %s Result: FAIL ✗ (%s)\n", vr.VulnID, reason)
	}
}

// failReasonDisplay maps internal FailReason to §10.3 display format.
func failReasonDisplay(failReason string) string {
	switch failReason {
	case "MISSING HDR":
		return "F1: MISSING HDR"
	case "OTHER MKR":
		return "F2: OTHER MKR"
	case "OWN MKR":
		return "F3: OWN MKR"
	case "WRONG ACTION":
		return "thiếu P2"
	case "WRONG STATUS":
		return "thiếu P3"
	default:
		return failReason
	}
}

// displayPayloadResult prints a single payload result line per §10.2.
func displayPayloadResult(vr *VulnResult, pr *PayloadResult) {
	// For V03 timing, show special marker
	markerDisplay := failReasonDisplay(pr.FailReason)
	if pr.Passed {
		markerDisplay = "CLEAN"
	}
	if vr.Special == "v03_timing" && pr.Passed {
		markerDisplay = "<5000ms"
	}

	icon := "✓"
	if !pr.Passed {
		icon = "✗"
	}

	// Truncate payload name for display
	name := pr.PayloadName
	if len(name) > 24 {
		name = name[:21] + "..."
	}

	fmt.Printf("      #%-2d %-24s %-4d %-12s %-8.3fms %s\n",
		pr.Index, name, pr.StatusCode, markerDisplay, pr.LatencyMs, icon)
}

// ── Helpers ──

func printSeparator(ch string, width int) {
	fmt.Println(strings.Repeat(ch, width))
}

func printDivider(width int) {
	fmt.Println(strings.Repeat("─", width))
}

func formatResetStepStatus(s ResetStep, icon string) string {
	if s.Success {
		switch s.StepNum {
		case 1:
			return fmt.Sprintf("UPSTREAM ... %d OK ✓", s.StatusCode)
		case 2:
			return "UPSTREAM ... healthy ✓"
		case 3:
			return "WAF mode ..... enforce ✓"
		case 4:
			if s.StatusCode == 200 {
				return "WAF cache .... cleared ✓"
			}
			return "WAF cache .... not supported (501) ✓"
		case 5:
			return "WAF state .... clean ✓"
		}
		return fmt.Sprintf("status %d ✓", s.StatusCode)
	}

	if s.Error != "" {
		return fmt.Sprintf("FAIL ✗ (%s)", s.Error)
	}
	return fmt.Sprintf("status %d ✗", s.StatusCode)
}

// ── Summary Print (for post-display) ──

// PrintSummaryLine prints a one-line summary of Phase A results.
func PrintSummaryLine(r *PhaseAResult) {
	fmt.Printf("\nPhase A: %d/%d tests passed | SEC-01: %.2f/15 | RS-BONUS: %d/%d\n",
		r.PassedTests, r.TotalTests, r.SEC01Score, r.RSBonusScore, r.RSBonusMax)
}
