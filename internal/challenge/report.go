package challenge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ── JSON Report Types ──

// ChallengeReportJSON is the top-level JSON report structure.
type ChallengeReportJSON struct {
	Phase       string                    `json:"phase"`
	Summary     ChallengeSummaryJSON      `json:"summary"`
	Lifecycles  []LifecycleResultJSON     `json:"lifecycles"`
}

// ChallengeSummaryJSON is the summary part of the JSON report.
type ChallengeSummaryJSON struct {
	TotalDetected        int `json:"total_detected"`
	Passed               int `json:"passed"`
	Failed               int `json:"failed"`
	BA01Passed           int `json:"ba01_passed"`
	BA02Passed           int `json:"ba02_passed"`
	MandatoryScored      int `json:"mandatory_scored"`
	SessionSuspensionOK  int `json:"session_suspension_ok"`
	SubmitOK             int `json:"submit_ok"`
	AccessRestoredOK     int `json:"access_restored_ok"`
}

// LifecycleResultJSON is one lifecycle result for JSON export.
type LifecycleResultJSON struct {
	TestID                  string   `json:"test_id"`
	Phase                   string   `json:"phase"`
	Endpoint                string   `json:"endpoint"`
	Method                  string   `json:"method"`
	BA01Passed              bool     `json:"ba01_passed"`
	BA01Detail              string   `json:"ba01_detail,omitempty"`
	BA02Passed              bool     `json:"ba02_passed"`
	BA02Detail              string   `json:"ba02_detail,omitempty"`
	MandatoryPassed         bool     `json:"mandatory_passed"`
	SubmitPassed            bool     `json:"submit_passed"`
	SubmitStatusCode        int      `json:"submit_status_code"`
	NewSessionExtracted     bool     `json:"new_session_extracted"`
	AccessRestored          bool     `json:"access_restored"`
	ResendStatusCode        int      `json:"resend_status_code"`
	ResendWAFAction         string   `json:"resend_waf_action,omitempty"`
	SessionSuspensionCheck  bool     `json:"session_suspension_check,omitempty"`
	SessionSuspensionPassed bool     `json:"session_suspension_passed,omitempty"`
	SessionSuspensionDetail string   `json:"session_suspension_detail,omitempty"`
	OverallPassed           bool     `json:"overall_passed"`
	FailCodes               []string `json:"fail_codes,omitempty"`
	Notes                   []string `json:"notes,omitempty"`
	DurationMs              int64    `json:"duration_ms"`
}

// GenerateReport writes a JSON report for one phase's challenge results.
func GenerateReport(summary PhaseChallengeSummary, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("cannot create output dir: %w", err)
	}

	lifecyclesJSON := make([]LifecycleResultJSON, 0, len(summary.LifecycleResults))
	for _, lr := range summary.LifecycleResults {
		lifecyclesJSON = append(lifecyclesJSON, LifecycleResultJSON{
			TestID:                  lr.TestID,
			Phase:                   lr.Phase,
			Endpoint:                lr.Endpoint,
			Method:                  lr.Method,
			BA01Passed:              lr.BA01Passed,
			BA01Detail:              lr.BA01Detail,
			BA02Passed:              lr.BA02Passed,
			BA02Detail:              lr.BA02Detail,
			MandatoryPassed:         lr.MandatoryPassed,
			SubmitPassed:            lr.SubmitPassed,
			SubmitStatusCode:        lr.SubmitStatusCode,
			NewSessionExtracted:     lr.NewSessionExtracted,
			AccessRestored:          lr.AccessRestored,
			ResendStatusCode:        lr.ResendStatusCode,
			ResendWAFAction:         lr.ResendWAFAction,
			SessionSuspensionCheck:  lr.SessionSuspensionCheck,
			SessionSuspensionPassed: lr.SessionSuspensionPassed,
			SessionSuspensionDetail: lr.SessionSuspensionDetail,
			OverallPassed:           lr.OverallPassed,
			FailCodes:               lr.FailCodes,
			Notes:                   lr.Notes,
			DurationMs:              lr.DurationMs,
		})
	}

	report := ChallengeReportJSON{
		Phase: summary.Phase,
		Summary: ChallengeSummaryJSON{
			TotalDetected:       summary.TotalChallenges,
			Passed:              summary.PassedChallenges,
			Failed:              summary.FailedChallenges,
			BA01Passed:          summary.BA01Passed,
			BA02Passed:          summary.BA02Passed,
			MandatoryScored:     summary.MandatoryPassed,
			SessionSuspensionOK: summary.SessionSuspensionOK,
			SubmitOK:            summary.SubmitOK,
			AccessRestoredOK:    summary.AccessRestoredOK,
		},
		Lifecycles: lifecyclesJSON,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal challenge report: %w", err)
	}

	filename := filepath.Join(outputDir, fmt.Sprintf("challenge_phase_%s.json", summary.Phase))
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("cannot write challenge report: %w", err)
	}

	return nil
}
