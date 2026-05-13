package challenge

import (
	"fmt"
	"strings"
)

// DisplayChallengeResult prints a single challenge lifecycle result to console.
func DisplayChallengeResult(lr LifecycleResult) {
	w := 66

	printChallengeSep("─", w)
	fmt.Printf("  🔐 CHALLENGE LIFECYCLE: %s/%s (%s %s)\n", lr.Phase, lr.TestID, lr.Method, lr.Endpoint)
	printChallengeSep("─", w)

	// BA01/BA02: Body checks
	fmt.Printf("  CL-F1 — Body Well-Formed:     %s\n", passFail(lr.BA01Passed))
	if lr.BA01Detail != "" {
		fmt.Printf("    %s\n", lr.BA01Detail)
	}
	fmt.Printf("  CL-F2 — Required Fields:      %s\n", passFail(lr.BA02Passed))
	if lr.BA02Detail != "" {
		fmt.Printf("    %s\n", lr.BA02Detail)
	}

	// Mandatory
	if lr.MandatoryChallengeCheck {
		fmt.Printf("  Mandatory Challenge Scored:   %s\n", passFail(lr.MandatoryPassed))
	}

	// Session suspension
	if lr.SessionSuspensionCheck {
		fmt.Printf("  CL-F6a/F6b — Session Susp.:   %s\n", passFail(lr.SessionSuspensionPassed))
		if lr.SessionSuspensionDetail != "" {
			fmt.Printf("    %s\n", lr.SessionSuspensionDetail)
		}
	}

	// Submit
	fmt.Printf("  CL-F3 — Submit Token:         %s\n", passFail(lr.SubmitPassed))
	if lr.SubmitDetail != "" {
		fmt.Printf("    %s (HTTP %d)\n", lr.SubmitDetail, lr.SubmitStatusCode)
	}

	// New session
	if lr.NewSessionExtracted {
		fmt.Printf("  CL-F4 — New Session:          ✓ extracted\n")
	} else if lr.SubmitPassed {
		fmt.Printf("  CL-F4 — New Session:          ✗ not extracted\n")
	}

	// Access restore
	fmt.Printf("  CL-F5 — Access Restored:      %s\n", passFail(lr.AccessRestored))
	if lr.AccessRestoreDetail != "" {
		fmt.Printf("    %s\n", lr.AccessRestoreDetail)
	}

	// Fail codes
	if len(lr.FailCodes) > 0 {
		fmt.Printf("  Fail Codes:                   %s\n", strings.Join(lr.FailCodes, ", "))
	}

	// Notes (security notes, non-fatal)
	if len(lr.Notes) > 0 {
		fmt.Printf("  Notes:                        %s\n", strings.Join(lr.Notes, "; "))
	}

	// Overall
	printChallengeSep("─", w)
	status := "✓ PASS"
	if !lr.OverallPassed {
		status = "✗ FAIL"
	}
	fmt.Printf("  Verdict:                      %s  (%dms)\n", status, lr.DurationMs)
	printChallengeSep("─", w)
}

// DisplayPhaseChallengeSummary prints a per-phase challenge summary.
func DisplayPhaseChallengeSummary(summary PhaseChallengeSummary) {
	w := 66

	printChallengeSep("═", w)
	fmt.Printf("  🔐 PHASE %s — CHALLENGE SUMMARY\n", summary.Phase)
	printChallengeSep("═", w)

	if summary.TotalChallenges == 0 {
		fmt.Println("  No 429 challenges encountered in this phase.")
		printChallengeSep("═", w)
		return
	}

	fmt.Printf("  Total Challenges:             %d\n", summary.TotalChallenges)
	fmt.Printf("  Passed:                       %d\n", summary.PassedChallenges)
	fmt.Printf("  Failed:                       %d\n", summary.FailedChallenges)
	fmt.Printf("  Skipped:                      %d\n", summary.SkippedChallenges)
	fmt.Println()

	if summary.BA01Passed+summary.BA02Passed > 0 {
		fmt.Println("  Body Format Checks:")
		fmt.Printf("    BA01 (well-formed):         %d/%d\n", summary.BA01Passed, summary.TotalChallenges)
		fmt.Printf("    BA02 (required fields):     %d/%d\n", summary.BA02Passed, summary.TotalChallenges)
	}
	if summary.MandatoryPassed > 0 {
		fmt.Printf("  Mandatory Scored:             %d/%d\n", summary.MandatoryPassed, summary.TotalChallenges)
	}
	if summary.SessionSuspension > 0 {
		fmt.Printf("  Session Suspension OK:        %d/%d\n", summary.SessionSuspensionOK, summary.SessionSuspension)
	}
	if summary.SubmitOK > 0 {
		fmt.Printf("  Submit OK:                    %d/%d\n", summary.SubmitOK, summary.TotalChallenges)
	}
	if summary.AccessRestoredOK > 0 {
		fmt.Printf("  Access Restored:              %d/%d\n", summary.AccessRestoredOK, summary.TotalChallenges)
	}

	printChallengeSep("═", w)
}

// DisplayCrossPhaseChallengeReport prints the cross-phase challenge report.
func DisplayCrossPhaseChallengeReport(report CrossPhaseChallengeReport) {
	w := 72

	printChallengeSep("═", w)
	fmt.Println("  🔐 CROSS-PHASE CHALLENGE REPORT")
	printChallengeSep("═", w)

	fmt.Printf("  Total 429 Challenges Detected: %d\n", report.TotalDetected)
	fmt.Printf("  Total Passed:                  %d\n", report.TotalPassed)
	fmt.Printf("  Total Failed:                  %d\n", report.TotalFailed)
	fmt.Println()

	for _, p := range report.Phases {
		if p.TotalChallenges == 0 {
			continue
		}
		fmt.Printf("  Phase %s: %d detected, %d passed, %d failed\n",
			p.Phase, p.TotalChallenges, p.PassedChallenges, p.FailedChallenges)
	}

	printChallengeSep("═", w)
}

// ── Helpers ──

func passFail(passed bool) string {
	if passed {
		return "✓ PASS"
	}
	return "✗ FAIL"
}

func printChallengeSep(ch string, w int) {
	fmt.Println(strings.Repeat(ch, w))
}
