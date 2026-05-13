package phaser

// display.go — CLI output for Phase R per phase_R.md §10 template

import (
	"fmt"
	"strings"
)

const (
	lineWidth = 66
	separator = "══════════════════════════════════════════════════════════════════"
	divider   = "──────────────────────────────────────────────────────────────────"
)

// DisplayPhaseRResult prints the full Phase R CLI output per phase_R.md §10.2.
func DisplayPhaseRResult(result *PhaseRResult) {
	// ── HEADER ──
	fmt.Println(separator)
	fmt.Println("  WAF-BENCHMARK — PHASE R: RISK SCORE LIFECYCLE TEST")
	fmt.Printf("  Timestamp : %s\n", result.StartTime.Format("2006-01-02T15:04:05-07:00"))
	fmt.Printf("  WAF Target: %s\n", result.WAFTarget)
	fmt.Printf("  WAF Mode  : %s\n", result.WAFMode)
	fmt.Println("  Note      : Phase R runs LAST — fresh IPs 127.0.0.200–202")
	fmt.Println(separator)
	fmt.Println()

	// ── FULL RESET SEQUENCE ──
	fmt.Println("── FULL RESET SEQUENCE (5 bước — §3.1) " + strings.Repeat("─", 27))
	if len(result.ResetSteps) == 0 {
		fmt.Println("  [!] Reset sequence not executed")
	} else {
		allOK := true
		for _, s := range result.ResetSteps {
			icon := "✓"
			status := "OK"
			if !s.Success {
				icon = "✗"
				status = "FAIL"
				if s.StepNum == 4 {
					icon = "⚠"
					status = "WARN (non-fatal)"
				}
				allOK = false
			}
			fmt.Printf("  [%d/5] %-44s %s %s\n", s.StepNum, s.Name, icon, status)
			if s.Error != "" && s.StepNum != 4 {
				fmt.Printf("        Error: %s\n", s.Error)
			}
		}
		if allOK {
			fmt.Println("  Result: ALL 5/5 OK ✓")
		} else {
			fmt.Println("  Result: RESET FAILED ✗ — Phase R ABORTED")
		}
	}
	fmt.Println(divider)
	fmt.Println()

	if !result.ResetAllPassed {
		fmt.Println(separator)
		fmt.Println("  PHASE R ABORTED — Reset sequence failed")
		fmt.Println(separator)
		return
	}

	// ── STEP RESULTS ──
	for _, sr := range result.StepResults {
		displayStep(sr)
	}

	// ── SCORING SUMMARY ──
	fmt.Println(separator)
	fmt.Println("  PHASE R — SCORING SUMMARY")
	fmt.Println(divider)

	for _, sr := range result.StepResults {
		if sr.Step == 1 {
			fmt.Printf("  Step 1  (Baseline)              N/A  (verification only)\n")
			continue
		}
		status := "✓"
		ptsStr := fmt.Sprintf("%d/%d", sr.Pts, sr.MaxPts)
		label := stepLabel(sr.Step)
		if sr.Skipped {
			status = "⚠ SKIP"
			ptsStr = fmt.Sprintf("0/%d", sr.MaxPts)
		} else if !sr.Pass {
			status = "✗"
		}
		fmt.Printf("  Step %d  %-28s %s  pts  %s\n", sr.Step, "("+label+")", ptsStr, status)
	}

	fmt.Println(divider)
	fmt.Printf("  SEC-05 (Risk Lifecycle)                    =  %5.2f / %.0f\n",
		result.SEC05Score, result.SEC05Max)
	fmt.Println(separator)
	fmt.Printf("\nDuration: %.1fs\n", result.DurationMs/1000)
}

// displayStep prints one step block per phase_R.md §10.3 rules.
func displayStep(sr StepResult) {
	label := stepLabel(sr.Step)
	fmt.Printf("── STEP %d: %s %s\n", sr.Step, label, strings.Repeat("─", max(0, lineWidth-10-len(label))))
	fmt.Printf("  IP: %s  Device: %s\n", sr.SourceIP, deviceDesc(sr.Device))

	if sr.Skipped {
		fmt.Printf("  Step %d Result: SKIP ⚠  (0/%d pts)  Reason: %s\n", sr.Step, sr.MaxPts, sr.SkipReason)
		fmt.Println(divider)
		fmt.Println()
		return
	}

	// Step 5: decay trajectory
	if sr.Step == 5 {
		displayDecayTrajectory(sr)
	} else if sr.Step == 7 && (sr.ChallengeSolved || sr.ChallengeToken != "") {
		displayChallengeCompletion(sr)
	} else if sr.Step == 6 && sr.ChallengeIssued {
		displayChallengeIssued(sr)
	} else {
		// Standard request line
		fmt.Printf("  ────────────────────────────────────────────────────────────────\n")
		fmt.Printf("    %s %s\n", sr.Method, sr.Endpoint)
		if sr.ObservedScore > 0 || sr.ObservedAction != "" {
			fmt.Printf("    Risk: %d  Action: %s  HTTP: %d  Latency: %.1fms\n",
				sr.ObservedScore, sr.ObservedAction, sr.HTTPStatus, sr.LatencyMs)
		}
		fmt.Printf("  Expected: %s\n", expectedDesc(sr))
	}

	// Result line
	if sr.Pass {
		fmt.Printf("  Step %d Result: PASS ✓  (%d/%d pts)\n", sr.Step, sr.Pts, sr.MaxPts)
	} else {
		reason := sr.FailReason
		if reason == "" {
			reason = "see above"
		}
		fmt.Printf("  Step %d Result: FAIL ✗  (0/%d pts)  Reason: %s\n", sr.Step, sr.MaxPts, reason)
	}
	fmt.Println(divider)
	fmt.Println()
}

func displayDecayTrajectory(sr StepResult) {
	fmt.Printf("  Interval: 2s  Requests: 30  Duration: ~60s\n")
	fmt.Printf("  ────────────────────────────────────────────────────────────────\n")

	// Show representative points: #1, #5, #10, #15, #20, #25, #30
	showAt := map[int]bool{1: true, 5: true, 10: true, 15: true, 20: true, 25: true, 30: true}
	for _, dp := range sr.DecayTrajectory {
		if showAt[dp.RequestNum] {
			fmt.Printf("    Req #%-3d  GET /game/list  Risk: %-3d  Action: %-10s  HTTP: %d\n",
				dp.RequestNum, dp.RiskScore, dp.Action, dp.HTTPStatus)
		}
	}

	if len(sr.DecayTrajectory) >= 2 {
		first := sr.DecayTrajectory[0].RiskScore
		last := sr.DecayTrajectory[len(sr.DecayTrajectory)-1].RiskScore
		arrow := "→"
		if last < first {
			fmt.Printf("  Trajectory: %d %s %d (giảm dần ✓)  Final action: %s\n",
				first, arrow, last, sr.ObservedAction)
		} else {
			fmt.Printf("  Trajectory: %d %s %d (KHÔNG giảm ✗)\n", first, arrow, last)
		}
	}
}

func displayChallengeIssued(sr StepResult) {
	fmt.Printf("  UA: python-requests/2.28\n")
	fmt.Printf("  ────────────────────────────────────────────────────────────────\n")
	fmt.Printf("    GET %s  [User-Agent: python-requests/2.28]\n", sr.Endpoint)
	fmt.Printf("    Risk: %d  Action: %s  HTTP: %d  Latency: %.1fms\n",
		sr.ObservedScore, sr.ObservedAction, sr.HTTPStatus, sr.LatencyMs)
	if sr.ChallengeType != "" {
		fmt.Printf("    Challenge: %s\n", challengeTypeLabel(sr.ChallengeType))
		if sr.ChallengeToken != "" {
			tok := sr.ChallengeToken
			if len(tok) > 20 {
				tok = tok[:20] + "..."
			}
			fmt.Printf("      challenge_token: %s\n", tok)
		}
		if sr.ChallengeDiff > 0 {
			fmt.Printf("      difficulty: %d\n", sr.ChallengeDiff)
		}
		if sr.ChallengeSubmitURL != "" {
			fmt.Printf("      submit_url: %s\n", sr.ChallengeSubmitURL)
		}
	}
	fmt.Printf("  Expected: risk 30–70, action challenge\n")
}

func displayChallengeCompletion(sr StepResult) {
	ctype := sr.ChallengeType
	if ctype == "" {
		ctype = "proof_of_work"
	}
	fmt.Printf("  Type: %s\n", challengeTypeLabel(ctype))
	fmt.Printf("  ────────────────────────────────────────────────────────────────\n")
	diff := sr.ChallengeDiff
	if diff == 0 {
		diff = 4 // default difficulty per spec
	}
	if ctype == "proof_of_work" || ctype == "" {
		fmt.Printf("    PoW solving: SHA256(token + nonce) starts with %d zero bits\n", diff)
		if sr.ChallengeNonce != "" {
			fmt.Printf("    Nonce found: %s  Solve time: %.2fs\n",
				sr.ChallengeNonce, sr.ChallengeSolveMs/1000)
		}
	}
	endpoint := sr.Endpoint
	if endpoint == "" {
		endpoint = "/challenge/verify"
	}
	fmt.Printf("    POST %s\n", endpoint)
	if sr.ObservedScore > 0 || sr.ObservedAction != "" {
		fmt.Printf("    Submit: 200  Risk after: %d  Action: %s  HTTP: %d\n",
			sr.ObservedScore, sr.ObservedAction, sr.HTTPStatus)
	}
	fmt.Printf("  Expected: risk < 30, action allow\n")
}

// ── Helpers ──

func stepLabel(step int) string {
	labels := map[int]string{
		1: "Baseline (Clean Traffic)",
		2: "Attack Detection (SQLi V01)",
		3: "Canary Hit (Risk MAX)",
		4: "Device Fingerprint Carry-Over",
		5: "Score Decay (30 requests / 60s)",
		6: "Suspicious UA (Challenge Trigger)",
		7: "Challenge Completion (Score Recovery)",
	}
	if l, ok := labels[step]; ok {
		return l
	}
	return fmt.Sprintf("Step %d", step)
}

func deviceDesc(device string) string {
	switch device {
	case "D1":
		return "D1 (en-US UA)"
	case "D2":
		return "D2 (fr-FR UA)"
	}
	return device
}

func challengeTypeLabel(ctype string) string {
	switch ctype {
	case "proof_of_work":
		return "JSON Format A (PoW)"
	case "html_form":
		return "HTML Format B"
	}
	return ctype
}

func expectedDesc(sr StepResult) string {
	parts := []string{}
	if sr.ExpectedScoreMin >= 0 && sr.ExpectedScoreMax >= 0 {
		if sr.ExpectedScoreMin == sr.ExpectedScoreMax {
			parts = append(parts, fmt.Sprintf("risk = %d", sr.ExpectedScoreMin))
		} else {
			parts = append(parts, fmt.Sprintf("risk %d–%d", sr.ExpectedScoreMin, sr.ExpectedScoreMax))
		}
	}
	if len(sr.ExpectedActions) > 0 {
		parts = append(parts, "action "+strings.Join(sr.ExpectedActions, "/"))
	}
	return strings.Join(parts, ", ")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
