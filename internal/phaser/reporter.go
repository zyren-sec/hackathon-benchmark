package phaser

// reporter.go — JSON and HTML report generation for Phase R (SEC-05)
// Output schema per phase_R.md §9

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GenerateReport writes report_phase_r.json and report_phase_r.html to outputDir.
func GenerateReport(result *PhaseRResult, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("cannot create output dir: %w", err)
	}

	report := buildReport(result)

	// JSON
	jsonPath := filepath.Join(outputDir, "report_phase_r.json")
	if err := writeJSON(report, jsonPath); err != nil {
		return fmt.Errorf("JSON report: %w", err)
	}

	// HTML
	htmlPath := filepath.Join(outputDir, "report_phase_r.html")
	if err := writeHTML(report, result, htmlPath); err != nil {
		return fmt.Errorf("HTML report: %w", err)
	}

	fmt.Printf("📄 Phase R reports: %s, %s\n", jsonPath, htmlPath)
	return nil
}

// buildReport converts PhaseRResult → PhaseRReport (JSON schema §9.1).
func buildReport(result *PhaseRResult) PhaseRReport {
	r := PhaseRReport{
		Phase:     "R",
		Timestamp: result.StartTime,
		WAFTarget: result.WAFTarget,
		WAFMode:   result.WAFMode,
	}

	r.SourceIPs.Steps1to3 = IPSteps1to3
	r.SourceIPs.Step4 = IPStep4
	r.SourceIPs.Steps5to7 = IPSteps5to7

	r.DeviceSignatures.D1 = DeviceSig{UA: DeviceD1.UserAgent, AcceptLang: DeviceD1.AcceptLanguage}
	r.DeviceSignatures.D2 = DeviceSig{UA: DeviceD2.UserAgent, AcceptLang: DeviceD2.AcceptLanguage}

	r.ResetPassed = result.ResetAllPassed
	for _, rs := range result.ResetSteps {
		r.ResetSequence = append(r.ResetSequence, RResetStepReport{
			Step:       rs.StepNum,
			Name:       rs.Name,
			Method:     rs.Method,
			URL:        rs.URL,
			StatusCode: rs.StatusCode,
			Success:    rs.Success,
			LatencyMs:  rs.LatencyMs,
			Error:      rs.Error,
		})
	}

	for _, sr := range result.StepResults {
		scoreRange := fmt.Sprintf("%d-%d", sr.ExpectedScoreMin, sr.ExpectedScoreMax)
		if sr.ExpectedScoreMin == sr.ExpectedScoreMax {
			scoreRange = fmt.Sprintf("%d", sr.ExpectedScoreMin)
		}
		if sr.ExpectedScoreMin < 0 {
			scoreRange = "trajectory"
		}

		expectedAction := ""
		if len(sr.ExpectedActions) > 0 {
			expectedAction = strings.Join(sr.ExpectedActions, "_or_")
		}

		r.Steps = append(r.Steps, StepReport{
			Step:               sr.Step,
			Description:        sr.Description,
			SourceIP:           sr.SourceIP,
			Device:             sr.Device,
			ExpectedAction:     expectedAction,
			ObservedAction:     sr.ObservedAction,
			ObservedScore:      sr.ObservedScore,
			ExpectedScoreRange: scoreRange,
			Pass:               sr.Pass,
			Skipped:            sr.Skipped,
			SkipReason:         sr.SkipReason,
			FailReason:         sr.FailReason,
			Pts:                sr.Pts,
			MaxPts:             sr.MaxPts,
			DecayTrajectory:    sr.DecayTrajectory,
		})
	}

	r.ChallengeSolved = result.ChallengeSolved
	r.ChallengeType = result.ChallengeType
	r.ChallengeToken = result.ChallengeToken
	r.ChallengeNonce = result.ChallengeNonce
	r.ChallengeSolveMs = result.ChallengeSolveMs
	r.SEC05Score = result.SEC05Score
	r.SEC05Max = result.SEC05Max
	r.DurationMs = result.DurationMs

	return r
}

func writeJSON(report PhaseRReport, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// ── HTML Report ──

func writeHTML(report PhaseRReport, result *PhaseRResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	html := buildHTML(report, result)
	_, err = f.WriteString(html)
	return err
}

func buildHTML(report PhaseRReport, result *PhaseRResult) string {
	var sb strings.Builder

	scoreColor := "#e53e3e"
	if report.SEC05Score >= 6 {
		scoreColor = "#38a169"
	} else if report.SEC05Score >= 4 {
		scoreColor = "#d69e2e"
	}

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF Benchmark — Phase R: Risk Score Lifecycle</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #f7fafc; color: #2d3748; margin: 0; padding: 20px; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { color: #2b6cb0; border-bottom: 3px solid #2b6cb0; padding-bottom: 8px; }
  h2 { color: #2d3748; margin-top: 32px; }
  .header-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  .card { background: white; border-radius: 8px; padding: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); }
  .score-card { text-align: center; }
  .score-big { font-size: 3rem; font-weight: bold; }
  .score-label { font-size: 0.9rem; color: #718096; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  th { background: #2b6cb0; color: white; padding: 8px 12px; text-align: left; font-size: 0.85rem; }
  td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; font-size: 0.85rem; }
  tr:hover { background: #ebf8ff; }
  .pass { color: #38a169; font-weight: bold; }
  .fail { color: #e53e3e; font-weight: bold; }
  .skip { color: #d69e2e; font-weight: bold; }
  .na { color: #718096; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; }
  .badge-pass { background: #c6f6d5; color: #276749; }
  .badge-fail { background: #fed7d7; color: #9b2c2c; }
  .badge-skip { background: #fefcbf; color: #744210; }
  .badge-na { background: #e2e8f0; color: #4a5568; }
  .step-block { background: white; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); border-left: 4px solid #2b6cb0; }
  .step-block.pass-border { border-left-color: #38a169; }
  .step-block.fail-border { border-left-color: #e53e3e; }
  .step-block.skip-border { border-left-color: #d69e2e; }
  .step-block.na-border { border-left-color: #718096; }
  .step-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .step-title { font-weight: bold; font-size: 1rem; }
  .step-meta { font-size: 0.8rem; color: #718096; margin-bottom: 8px; }
  .decay-table td, .decay-table th { padding: 4px 8px; font-size: 0.8rem; }
  .reset-ok { color: #38a169; }
  .reset-fail { color: #e53e3e; }
  .reset-warn { color: #d69e2e; }
  .footer { margin-top: 32px; font-size: 0.8rem; color: #718096; text-align: center; }
</style>
</head>
<body>
<div class="container">
`)

	// Title
	sb.WriteString(fmt.Sprintf(`<h1>🛡️ WAF Benchmark — Phase R: Risk Score Lifecycle</h1>
<p><strong>Timestamp:</strong> %s &nbsp;|&nbsp; <strong>WAF:</strong> %s &nbsp;|&nbsp; <strong>Mode:</strong> %s</p>
`,
		report.Timestamp.Format(time.RFC3339),
		report.WAFTarget,
		report.WAFMode,
	))

	// Score card + IP table
	sb.WriteString(`<div class="header-grid">`)
	sb.WriteString(fmt.Sprintf(`<div class="card score-card">
  <div class="score-big" style="color:%s">%.0f / %.0f</div>
  <div class="score-label">SEC-05 — Risk Lifecycle Score</div>
  <div style="margin-top:8px;font-size:0.85rem">Duration: %.1fs</div>
</div>`, scoreColor, report.SEC05Score, report.SEC05Max, report.DurationMs/1000))

	sb.WriteString(`<div class="card">
<strong>Source IPs (fresh — not used in other phases)</strong>
<table><tr><th>IP</th><th>Steps</th></tr>`)
	sb.WriteString(fmt.Sprintf("<tr><td><code>%s</code></td><td>Steps 1–3 (baseline → attack → canary)</td></tr>", IPSteps1to3))
	sb.WriteString(fmt.Sprintf("<tr><td><code>%s</code></td><td>Step 4 (device FP carry-over)</td></tr>", IPStep4))
	sb.WriteString(fmt.Sprintf("<tr><td><code>%s</code></td><td>Steps 5–7 (decay → challenge → recovery)</td></tr>", IPSteps5to7))
	sb.WriteString(`</table></div></div>`)

	// Reset sequence
	sb.WriteString(`<h2>Full Reset Sequence</h2>
<div class="card"><table>
<tr><th>#</th><th>Step</th><th>Status</th><th>HTTP</th><th>Latency</th></tr>`)
	for _, rs := range report.ResetSequence {
		cls := "reset-ok"
		icon := "✓"
		if !rs.Success {
			if rs.Step == 4 {
				cls = "reset-warn"
				icon = "⚠"
			} else {
				cls = "reset-fail"
				icon = "✗"
			}
		}
		sb.WriteString(fmt.Sprintf(`<tr><td>%d</td><td>%s</td><td class="%s">%s</td><td>%d</td><td>%.1fms</td></tr>`,
			rs.Step, rs.Name, cls, icon, rs.StatusCode, rs.LatencyMs))
	}
	sb.WriteString(`</table></div>`)

	// Step results
	sb.WriteString(`<h2>Risk Lifecycle Steps</h2>`)
	for _, step := range report.Steps {
		borderClass := "pass-border"
		badgeClass := "badge-pass"
		badgeText := "PASS ✓"
		if step.Skipped {
			borderClass = "skip-border"
			badgeClass = "badge-skip"
			badgeText = "SKIP ⚠"
		} else if !step.Pass {
			borderClass = "fail-border"
			badgeClass = "badge-fail"
			badgeText = "FAIL ✗"
		}
		if step.Step == 1 {
			borderClass = "na-border"
			badgeClass = "badge-na"
			badgeText = "N/A"
		}

		ptsStr := fmt.Sprintf("%d/%d pts", step.Pts, step.MaxPts)
		if step.Step == 1 {
			ptsStr = "— (baseline)"
		}

		sb.WriteString(fmt.Sprintf(`<div class="step-block %s">
<div class="step-header">
		<span class="step-title">Step %d — %s</span>
		<span><span class="badge %s">%s</span> &nbsp; %s</span>
</div>
<div class="step-meta">IP: <code>%s</code> &nbsp;|&nbsp; Device: %s</div>
`,
			borderClass,
			step.Step, stepLabel(step.Step),
			badgeClass, badgeText, ptsStr,
			step.SourceIP, step.Device,
		))

		// Decay trajectory table (Step 5)
		if step.Step == 5 && len(step.DecayTrajectory) > 0 {
			sb.WriteString(`<table class="decay-table"><tr><th>Req#</th><th>Risk Score</th><th>Action</th><th>HTTP</th><th>Latency</th></tr>`)
			showAt := map[int]bool{1: true, 5: true, 10: true, 15: true, 20: true, 25: true, 30: true}
			for _, dp := range step.DecayTrajectory {
				if showAt[dp.RequestNum] {
					sb.WriteString(fmt.Sprintf(`<tr><td>#%d</td><td>%d</td><td>%s</td><td>%d</td><td>%.1fms</td></tr>`,
						dp.RequestNum, dp.RiskScore, dp.Action, dp.HTTPStatus, dp.LatencyMs))
				}
			}
			sb.WriteString(`</table>`)
		} else if step.Step != 1 {
			// Standard metrics
			sb.WriteString(fmt.Sprintf(`<table><tr><th>Observed Risk</th><th>Expected Range</th><th>Observed Action</th><th>Expected Action</th><th>HTTP</th><th>Latency</th></tr>
<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%.1fms</td></tr></table>`,
				step.ObservedScore, step.ExpectedScoreRange,
				step.ObservedAction, step.ExpectedAction,
				0, 0.0, // HTTPStatus and LatencyMs not in StepReport — use observed
			))
		}

		if step.FailReason != "" {
			sb.WriteString(fmt.Sprintf(`<p style="color:#e53e3e;margin-top:8px;font-size:0.85rem">⚠ %s</p>`, step.FailReason))
		}
		if step.SkipReason != "" {
			sb.WriteString(fmt.Sprintf(`<p style="color:#d69e2e;margin-top:8px;font-size:0.85rem">⚠ Skipped: %s</p>`, step.SkipReason))
		}

		sb.WriteString(`</div>`)
	}

	// Scoring summary table
	sb.WriteString(`<h2>SEC-05 Scoring Summary</h2>
<div class="card"><table>
<tr><th>Step</th><th>Description</th><th>Max Pts</th><th>Earned</th><th>Result</th></tr>`)

	for _, step := range report.Steps {
		resultStr := `<span class="pass">PASS ✓</span>`
		if step.Step == 1 {
			resultStr = `<span class="na">N/A (baseline)</span>`
		} else if step.Skipped {
			resultStr = `<span class="skip">SKIP ⚠</span>`
		} else if !step.Pass {
			resultStr = `<span class="fail">FAIL ✗</span>`
		}
		sb.WriteString(fmt.Sprintf(`<tr><td>%d</td><td>%s</td><td>%d</td><td>%d</td><td>%s</td></tr>`,
			step.Step, stepLabel(step.Step), step.MaxPts, step.Pts, resultStr))
	}

	sb.WriteString(fmt.Sprintf(`<tr style="background:#ebf8ff;font-weight:bold">
<td colspan="3">SEC-05 Total</td><td>%.0f</td><td>/ %.0f</td></tr>`,
		report.SEC05Score, report.SEC05Max))
	sb.WriteString(`</table></div>`)

	// Challenge details
	if report.ChallengeSolved {
		sb.WriteString(fmt.Sprintf(`<h2>Challenge Details</h2>
<div class="card">
<p><strong>Type:</strong> %s &nbsp;|&nbsp; <strong>Solved:</strong> ✓ &nbsp;|&nbsp; <strong>Solve time:</strong> %.2fs</p>
<p><strong>Token:</strong> <code>%s</code></p>
<p><strong>Nonce:</strong> <code>%s</code></p>
</div>`,
			report.ChallengeType,
			report.ChallengeSolveMs/1000,
			report.ChallengeToken,
			report.ChallengeNonce,
		))
	}

	sb.WriteString(fmt.Sprintf(`<div class="footer">
Generated by WAF-BENCHMARK Phase R &nbsp;|&nbsp; %s
</div>
</div>
</body>
</html>`, time.Now().Format(time.RFC3339)))

	return sb.String()
}
