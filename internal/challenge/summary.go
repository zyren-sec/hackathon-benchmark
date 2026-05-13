package challenge

// ── Summary Aggregation ──

// BuildPhaseSummary aggregates lifecycle results for one phase.
func BuildPhaseSummary(phase string, results []LifecycleResult) PhaseChallengeSummary {
	summary := PhaseChallengeSummary{
		Phase:            phase,
		LifecycleResults: results,
		TotalChallenges:  len(results),
	}

	for _, lr := range results {
		if lr.OverallPassed {
			summary.PassedChallenges++
		} else {
			summary.FailedChallenges++
		}
		if lr.BA01Passed {
			summary.BA01Passed++
		}
		if lr.BA02Passed {
			summary.BA02Passed++
		}
		if lr.MandatoryPassed {
			summary.MandatoryPassed++
		}
		if lr.SessionSuspensionCheck {
			summary.SessionSuspension++
			if lr.SessionSuspensionPassed {
				summary.SessionSuspensionOK++
			}
		}
		if lr.SubmitPassed {
			summary.SubmitOK++
		}
		if lr.AccessRestored {
			summary.AccessRestoredOK++
		}
	}

	return summary
}

// BuildCrossPhaseReport aggregates challenge results across all phases.
func BuildCrossPhaseReport(phaseResults map[string][]LifecycleResult) CrossPhaseChallengeReport {
	report := CrossPhaseChallengeReport{}

	for phase, results := range phaseResults {
		summary := BuildPhaseSummary(phase, results)
		report.Phases = append(report.Phases, summary)
		report.TotalDetected += summary.TotalChallenges
		report.TotalPassed += summary.PassedChallenges
		report.TotalFailed += summary.FailedChallenges
	}

	return report
}
