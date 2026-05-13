package phaseb

import (
	"fmt"
	"strings"
	"time"
)

// ── Console Display: matches phase_B.md §10.2 template ──

// DisplayPhaseBResult prints the full Phase B result to stdout.
func DisplayPhaseBResult(r *PhaseBResult) {
	w := 66

	// ═══ HEADER ═══
	printBSeparator("═", w)
	fmt.Println("  WAF-BENCHMARK — PHASE B: ABUSE DETECTION TESTS")
	fmt.Printf("  Timestamp : %s\n", r.StartTime.Format(time.RFC3339))
	fmt.Printf("  WAF Target: %s\n", r.WAFTarget)
	fmt.Printf("  WAF Mode  : %s\n", r.WAFMode)
	printBSeparator("═", w)
	fmt.Println()

	// ═══ PRE-CHECK ═══
	fmt.Println("── PRE-CHECK: PROXY HEALTH GATE ─────────────────────────────────")
	fmt.Printf("  Proxies tested: %d/%d alive\n", r.PreCheckAlive, r.PreCheckTotal)
	if r.PreCheckPassed {
		fmt.Println("  Result: PASS ✓")
	} else {
		fmt.Println("  Result: FAIL ✗ (warning — continuing with loopback fallback)")
	}
	printBDivider(w)
	fmt.Println()

	// ═══ RESET SEQUENCE ═══
	fmt.Println("── FULL RESET SEQUENCE (5 bước — §3.1) ──────────────────────────")
	for _, s := range r.ResetSteps {
		fmt.Printf("  [%d/5] %-4s %-33s → %s\n",
			s.StepNum, s.Method, "", formatBResetStepStatus(s, ""))
	}
	if r.ResetAllPassed {
		fmt.Println("  Result: ALL 5/5 OK ✓")
	} else {
		fmt.Println("  Result: FAIL ✗")
		fmt.Println()
		printBSeparator("═", w)
		fmt.Println("  PHASE B ABORTED — Reset sequence failed")
		printBSeparator("═", w)
		return
	}
	printBDivider(w)
	fmt.Println()

	// ═══ CATEGORIES ═══
	// v2.9: Relay unified — no sub-phase split (AR04/AR05 removed)
	for _, cat := range r.Categories {
		displayBCategory(&cat, w)
	}

	// ═══ SCORING SUMMARY ═══
	displayBScoringSummary(r, w)
}

func displayBCategory(cat *BCategoryResult, w int) {
	// Category header
	pad := w - len(cat.Name) - 8
	if pad < 0 {
		pad = 0
	}
	label := fmt.Sprintf("── CAT %d: %s ", catIndex(cat.CatID), cat.Name)
	fmt.Println(label + strings.Repeat("─", pad))
	fmt.Printf("  Criterion: %s (%.0f pts)   IP Range: %s\n", cat.Criterion, cat.MaxScore, cat.IPRange)
	printBDivider(w)

	for _, tr := range cat.Tests {
		displayBTest(&tr, w)
	}

	printBDivider(w)
	fmt.Printf("  CAT %d Result: %d/%d passed\n", catIndex(cat.CatID), cat.PassedCount, cat.TotalCount)
	fmt.Println()
}

func displayBTest(tr *BTestResult, w int) {
	negTag := ""
	if tr.NegativeControl {
		negTag = " (Negative control)"
	}

	// Reset transition line
	if tr.ResetBefore {
		fmt.Printf("  ── [RESET] %s ──\n", tr.ResetType)
	} else {
		fmt.Println("  │  (no reset — same category, risk accumulates)")
	}

	// Auth line
	if tr.AuthUsed {
		fmt.Printf("  │  Auth: Yes | Session: ok (sid=%s)\n", tr.SessionID)
	} else if tr.SessionID != "" {
		fmt.Printf("  │  Auth: Yes | Session: ok (sid=%s)\n", tr.SessionID)
	} else {
		fmt.Println("  │  Auth: No  | Session: N/A")
	}

	// Determine key metric for display
	metric := ""
	switch {
	case tr.AbuseType == "brute" || tr.AbuseType == "credential_stuffing" || tr.AbuseType == "spray":
		metric = fmt.Sprintf("Blocked at: %d/%d", tr.BlockedAt, tr.TotalRequests)
	case tr.AbuseType == "relay" || tr.AbuseType == "proxy":
		metric = fmt.Sprintf("Risk: %d", tr.MaxRiskScore)
	case tr.AbuseType == "bot":
		metric = fmt.Sprintf("Max Risk: %d", tr.MaxRiskScore)
	case tr.AbuseType == "fraud":
		metric = fmt.Sprintf("Risk: %d", tr.MaxRiskScore)
	case tr.AbuseType == "recon":
		if tr.TestID == "RE01" {
			metric = fmt.Sprintf("Blocked at: %d/%d", tr.BlockedAt, tr.TotalRequests)
		} else if tr.TestID == "RE02" {
			metric = fmt.Sprintf("Status: %d", tr.Requests[len(tr.Requests)-1].StatusCode)
		} else {
			metric = fmt.Sprintf("Risk: %d", tr.MaxRiskScore)
		}
	case tr.AbuseType == "canary":
		metric = fmt.Sprintf("All blocked: %v", tr.CanaryResult != nil && tr.CanaryResult.AllBlocked)
	default:
		metric = fmt.Sprintf("Risk: %d", tr.MaxRiskScore)
	}

	latencyShort := fmt.Sprintf("%.3fms", tr.AvgLatencyMs)

	fmt.Printf("  %s  %-24s IP: %s   %s   Latency: %s%s\n",
		tr.TestID, tr.Name, tr.SourceIP, metric, latencyShort, negTag)

	// Challenge lifecycle display (v2.9)
	if tr.ChallengeResult != nil && tr.ChallengeResult.Encountered {
		status := "PASS"
		if !tr.ChallengeResult.Passed {
			status = "FAIL"
		}
		fmt.Printf("        Challenge: %s | Token: %s | Solve: %dms | Access restored: %s\n",
			tr.ChallengeResult.Format,
			truncateToken(tr.ChallengeResult.ChallengeToken, 16),
			tr.ChallengeResult.DurationMs,
			passFailCheck(tr.ChallengeResult.AccessRestored))
		if tr.ChallengeResult.SessionSuspended {
			fmt.Printf("        Session Suspension: ✓ (old session revoked)\n")
		}
		if !tr.ChallengeResult.Passed {
			fmt.Printf("        Challenge Fail Codes: %s\n", strings.Join(tr.ChallengeResult.FailCodes, ", "))
		}
		fmt.Printf("        [P6: %s]\n", status)
	}

	// Result line
	if tr.Passed {
		fmt.Printf("        Result: PASS ✓   (%s)\n", tr.PassCriterion)
	} else if tr.Skipped {
		fmt.Printf("        Result: SKIP ⚠   (%s)\n", tr.SkipReason)
	} else {
		fmt.Printf("        Result: FAIL ✗   (%s)\n", tr.FailReason)
	}

	// Canary details for RE04
	if tr.CanaryResult != nil {
		fmt.Printf("        ")
		for _, ep := range tr.CanaryResult.Endpoints {
			status := tr.CanaryResult.Results[ep]
			fmt.Printf("%s: %d  ", ep, status)
		}
		fmt.Println()
		if tr.CanaryResult.FollowUpBlocked {
			fmt.Println("        Follow-up: 403 (locked)")
		}
	}
}

// displayBRelayCategory is no longer used (v2.9: AR04/AR05 removed, relay unified).
// Kept as documentation — relay tests now displayed via displayBCategory like all others.
func displayBRelayCategory(_ *BCategoryResult, _ int) {
	// v2.9: No sub-phase split. Relay tests (AR01-AR03, AR06) run as single category.
}

func displayBScoringSummary(r *PhaseBResult, w int) {
	printBSeparator("═", w)
	fmt.Println("  PHASE B — SCORING SUMMARY")
	printBDivider(w)

	// Compute the display numbers
	var passAB, passRE, passAR, passBA, passTF int
	var passCanary int
	for _, tr := range r.TestResults {
		if !tr.Passed {
			continue
		}
		switch tr.Category {
		case "brute_force":
			passAB++
		case "relay":
			passAR++
		case "behavioral":
			passBA++
		case "transaction":
			passTF++
		case "recon":
			if tr.Criterion == "SEC-03" {
				passRE++
			} else if tr.Criterion == "SEC-04" {
				passCanary = 1
			}
		}
	}

	sec03 := r.Scores["SEC-03"]
	sec04 := r.Scores["SEC-04"]
	int01 := r.Scores["INT-01"]
	int02 := r.Scores["INT-02"]
	int03 := r.Scores["INT-03"]

	fmt.Printf("  SEC-03   (Abuse Detection)       (%d+%d)/6 × 10  =  %6.2f pts\n", passAB, passRE, sec03)
	fmt.Printf("  SEC-04   (Canary Detection)        %d/1   × 2   =  %6.2f pts\n", passCanary, sec04)
	fmt.Printf("  INT-01   (Transaction Fraud)       %d/4   × 4   =  %6.2f pts\n", passTF, int01)
	fmt.Printf("  INT-02   (Behavioral Anomaly)      %d/5   × 4   =  %6.2f pts\n", passBA, int02)
	fmt.Printf("  INT-03   (Relay Detection)         %d/4   × 4   =  %6.2f pts  (v2.9: AR04/AR05 removed)\n", passAR, int03)
	printBDivider(w)
	fmt.Printf("  PHASE B TOTAL                                    = %6.2f / %.0f\n", r.TotalScore, r.MaxScore)
	printBSeparator("═", w)
}

// ── Helpers ──

func printBSeparator(ch string, width int) {
	fmt.Println(strings.Repeat(ch, width))
}

func printBDivider(width int) {
	fmt.Println(strings.Repeat("─", width))
}

func formatBResetStepStatus(s BResetStep, _ string) string {
	if s.Success {
		switch s.StepNum {
		case 1:
			return "UPSTREAM .... reset ✓"
		case 2:
			return "UPSTREAM .... healthy ✓"
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

func catIndex(catID string) int {
	switch catID {
	case "brute_force":
		return 1
	case "relay":
		return 2
	case "behavioral":
		return 3
	case "transaction":
		return 4
	case "recon":
		return 5
	}
	return 0
}

// truncateToken truncates a token for display purposes.
func truncateToken(token string, maxLen int) string {
	if len(token) <= maxLen {
		return token
	}
	return token[:maxLen] + "..."
}

// passFailCheck returns "✓" or "✗" based on boolean.
func passFailCheck(passed bool) string {
	if passed {
		return "✓"
	}
	return "✗"
}
