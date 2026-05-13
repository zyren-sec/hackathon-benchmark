package phasee

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
)

// GenerateReport writes report_phase_e.html and report_phase_e.json.
func GenerateReport(r *PhaseEResult, outputDir string) error {
	report := buildEReport(r)

	// JSON
	jsonPath := filepath.Join(outputDir, "report_phase_e.json")
	if err := writeEJSON(report, jsonPath); err != nil {
		return fmt.Errorf("JSON report: %w", err)
	}
	fmt.Printf("📄 JSON report: %s\n", jsonPath)

	// HTML
	htmlPath := filepath.Join(outputDir, "report_phase_e.html")
	if err := writeEHTML(report, htmlPath); err != nil {
		return fmt.Errorf("HTML report: %w", err)
	}
	fmt.Printf("📄 HTML report: %s\n", htmlPath)

	return nil
}

func buildEReport(r *PhaseEResult) PhaseEReport {
	report := PhaseEReport{
		Phase:             "E",
		Timestamp:         r.StartTime.Format("2006-01-02T15:04:05Z07:00"),
		WAFTarget:         r.WAFTarget,
		WAFMode:           r.WAFMode,
		DurationMs:        r.EndTime.Sub(r.StartTime).Milliseconds(),
		PreCheckPassed:    r.WAFAlive && r.UpstreamAlive,
		WAFAlive:          r.WAFAlive,
		UpstreamAlive:     r.UpstreamAlive,
		ResetAllPassed:    r.ResetAllPassed,
		EXT01Score:        r.EXT01Score,
		EXT01Max:          3.0,
		EXT01Manual:       true,
		EXT02Score:        r.EXT02Score,
		EXT02Max:          3.0,
		EXT02Manual:       true,
		EXT03Score:        r.EXT03Score,
		EXT03Max:          4.0,
		EXT03SubScores:    r.EXT03SubScores,
		TotalScore:        r.TotalScore,
		MaxScore:          r.MaxScore,
		PassedTests:       r.PassedTests,
		FailedTests:       r.FailedTests,
		SkippedTests:      r.SkippedTests,
		ScoringMethodology: ScoringMapDoc,
	}

	total := r.PassedTests + r.FailedTests + r.SkippedTests
	if total > 0 {
		report.PassRate = float64(r.PassedTests) / float64(total)
	}

	// Reset sequence
	for _, s := range r.ResetSteps {
		report.ResetSequence = append(report.ResetSequence, EResetStepJSON{
			Step: s.StepNum, Name: s.Name, StatusCode: s.StatusCode,
			Success: s.Success, LatencyMs: s.LatencyMs,
		})
	}

	// Category summaries
	catMap := map[string]struct {
		name   string
		passed int
		total  int
		score  float64
		max    float64
	}{
		"caching": {name: "Caching Correctness (Automated)"},
	}
	for catID := range catMap {
		for _, tr := range r.TestResults {
			if tr.Category == catID {
				cm := catMap[catID]
				cm.total++
				if tr.Passed {
					cm.passed++
					cm.score += tr.Score
				}
				cm.max += tr.MaxScore
				catMap[catID] = cm
			}
		}
	}
	for catID, cm := range catMap {
		if cm.total > 0 {
			report.Categories = append(report.Categories, ECategorySummaryJSON{
				ID: catID, Name: cm.name, Criterion: "EXT",
				Passed: cm.passed, Total: cm.total,
				Score: cm.score, MaxScore: cm.max,
			})
		}
	}

	// Test entries
	for _, tr := range r.TestResults {
		entry := buildETestEntry(&tr)
		report.Tests = append(report.Tests, entry)

		// Scoring breakdown
		sb := EScoringBreakdownJSON{
			TestID: tr.TestID, Name: tr.Name, MaxScore: tr.MaxScore,
			Passed: tr.Passed, Skipped: tr.Skipped,
		}
		if tr.Passed {
			sb.ScoreEarned = tr.Score
		}
		if tr.TestID == "EXT-03" && tr.EXT03SubScores != nil {
			sb.SubScores = tr.EXT03SubScores
		}
		report.ScoringBreakdown = append(report.ScoringBreakdown, sb)
	}

	// Scoring map
	report.ScoringMap = EScoringMapJSON{
		Criterion:   "EXT",
		Description: "Extensibility (v2.5: EXT-01/EXT-02 manual, EXT-03 automated)",
		MaxPoints:   10,
		Formula:     "EXT-01 (3 pts, MANUAL) + EXT-02 (3 pts, MANUAL) + EXT-03 (4 pts, AUTOMATED sum of sub-tests)",
	}

	return report
}

func buildETestEntry(tr *ETestResult) ETestEntryJSON {
	entry := ETestEntryJSON{
		TestID:          tr.TestID,
		Name:            tr.Name,
		Category:        tr.Category,
		Criterion:       tr.Criterion,
		Description:     tr.Description,
		PassCriterion:   tr.PassCriterion,
		MaxScore:        tr.MaxScore,
		Passed:          tr.Passed,
		Skipped:         tr.Skipped,
		SkipReason:      tr.SkipReason,
		FailReason:      tr.FailReason,
		DurationSec:     tr.DurationSec,
		ScoringExplain:  tr.ScoringExplain,
		ReproduceScript: tr.ReproduceScript,
		ConfigModified:  tr.ConfigModified,
		ConfigRestored:  tr.ConfigRestored,
		HotReloadSLAOk:  tr.HotReloadSLAOk,
		HotReloadLatencyMs: tr.HotReloadLatencyMs,
	}

	if tr.Passed {
		entry.Result = "PASS"
		entry.Score = tr.Score
	} else if tr.Skipped {
		entry.Result = "SKIP"
	} else {
		entry.Result = "FAIL"
	}

	// Fail conditions
	for _, fc := range tr.FailConditions {
		entry.FailConditions = append(entry.FailConditions, EFailCondJSON{
			ID: fc.ID, Description: fc.Description,
			Triggered: fc.Triggered, Evidence: fc.Evidence,
		})
	}

	// Cache results
	for _, cr := range tr.CacheResults {
		entry.CacheResults = append(entry.CacheResults, ECacheCheckResultJSON{
			RequestNum:    cr.RequestNum,
			Endpoint:      cr.Endpoint,
			Method:        cr.Method,
			StatusCode:    cr.StatusCode,
			CacheHeader:   cr.CacheHeader,
			ExpectedCache: cr.ExpectedCache,
			MatchExpected: cr.MatchExpected,
			LatencyMs:     cr.LatencyMs,
			WAFAction:     cr.WAFAction,
			RiskScore:     cr.RiskScore,
			CurlCommand:   cr.CurlCommand,
		})
	}

	// Verify results
	for _, vr := range tr.VerifyResults {
		entry.VerifyResults = append(entry.VerifyResults, EVerifyRouteResultJSON{
			Method:        vr.Method,
			Endpoint:      vr.Endpoint,
			StatusCode:    vr.StatusCode,
			LatencyMs:     vr.LatencyMs,
			WAFCache:      vr.WAFCache,
			WAFAction:     vr.WAFAction,
			RiskScore:     vr.RiskScore,
			Passed:        vr.Passed,
			ExpectedCode:  vr.ExpectedCode,
			ExpectedCache: vr.ExpectedCache,
			FailReason:    vr.FailReason,
			CurlCommand:   vr.CurlCommand,
			Tier:          vr.Tier,
		})
	}

	return entry
}

// ── JSON Writer ──

func writeEJSON(report PhaseEReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ── HTML Writer ──

func writeEHTML(report PhaseEReport, path string) error {
	var sb strings.Builder
	sb.WriteString(ephaseHTMLPreamble(report))
	sb.WriteString(ephaseResetSequence(report))
	sb.WriteString(ephaseCategorySummaries(report))
	sb.WriteString(ephaseTestDetails(report))
	sb.WriteString(ephaseScoringSummary(report))
	sb.WriteString(ephaseHTMLPostamble(report))
	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// ── HTML Components ──

func ephaseHTMLPreamble(report PhaseEReport) string {
	precheckIcon := "✓"
	precheckColor := "var(--green)"
	if !report.PreCheckPassed {
		precheckIcon = "✗"
		precheckColor = "var(--red)"
	}
	configInfo := fmt.Sprintf("%s (%s)", report.ConfigPath, report.ConfigFormat)
	if !report.ConfigDetected {
		configInfo = "NOT DETECTED"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF Benchmark — Phase E: Extensibility Tests</title>
<style>
:root {
  --bg: #0f1117;
  --surface: #161822;
  --surface2: #1e2030;
  --border: #2a2d3e;
  --text: #c9d1d9;
  --subtle: #8b949e;
  --green: #3fb950;
  --red: #f85149;
  --yellow: #d29922;
  --blue: #58a6ff;
  --purple: #bc8cff;
  --orange: #f0883e;
  --code-bg: #0d1117;
  --code-border: #30363d;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  background: var(--bg); color: var(--text); line-height: 1.6; padding: 24px;
}
h1 { font-size: 1.5rem; margin-bottom: 8px; color: var(--blue); }
h2 { font-size: 1.25rem; margin: 24px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 8px; color: var(--purple); }
h3 { font-size: 1.1rem; margin: 16px 0 8px; color: var(--text); }
h4 { font-size: 0.95rem; margin: 12px 0 6px; color: var(--subtle); }
.meta { color: var(--subtle); font-size: 0.85rem; margin-bottom: 16px; }
.card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px; margin-bottom: 16px;
}
.row { display: flex; gap: 12px; flex-wrap: wrap; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; }
.badge-pass { background: rgba(63,185,80,0.15); color: var(--green); }
.badge-fail { background: rgba(248,81,73,0.15); color: var(--red); }
.badge-skip { background: rgba(210,153,34,0.15); color: var(--yellow); }
table { width: 100%%; border-collapse: collapse; margin: 8px 0; font-size: 0.85rem; }
th, td { padding: 6px 10px; text-align: left; border-bottom: 1px solid var(--border); }
th { color: var(--subtle); font-weight: 600; }
.code-block { background: var(--code-bg); border: 1px solid var(--code-border); border-radius: 6px; padding: 12px; overflow-x: auto; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.8rem; line-height: 1.45; }
.scoring-explain { padding: 10px 14px; border-radius: 6px; font-size: 0.85rem; margin: 8px 0; }
.scoring-explain.pass { background: rgba(63,185,80,0.08); border-left: 3px solid var(--green); }
.scoring-explain.fail { background: rgba(248,81,73,0.08); border-left: 3px solid var(--red); }
.detail-section { padding: 8px 0; }
details { margin: 8px 0; }
details summary { cursor: pointer; font-weight: 600; color: var(--blue); padding: 4px 0; }
details[open] summary { margin-bottom: 8px; }
.pass-rate { font-size: 1.5rem; font-weight: 700; }
.pass-rate.good { color: var(--green); }
.pass-rate.bad { color: var(--red); }
.score-card { text-align: center; padding: 12px; }
.score-card .value { font-size: 2rem; font-weight: 800; }
.score-card .label { font-size: 0.8rem; color: var(--subtle); margin-top: 4px; }
.tier-item { margin: 8px 0; padding: 8px 12px; background: var(--surface2); border-radius: 6px; }
.cache-table th { font-size: 0.78rem; }
</style>
</head>
<body>

<h1>WAF-BENCHMARK — Phase E: Extensibility Tests</h1>
<div class="meta">
  Timestamp: %s | WAF Target: %s | WAF Mode: %s<br>
  Config: %s | Duration: %.1fs
</div>

<div class="card">
<h3>Pre-Flight Health Checks</h3>
<table>
<tr><td>WAF Alive</td><td style="color:%s;">%s %v</td></tr>
<tr><td>UPSTREAM Healthy</td><td style="color:var(--%s);">%s %v</td></tr>
<tr><td>WAF Config Detected</td><td style="color:var(--%s);">%s %v</td></tr>
</table>
</div>
`,
		report.Timestamp, report.WAFTarget, report.WAFMode,
		configInfo, float64(report.DurationMs)/1000.0,
		precheckColor, precheckIcon, report.WAFAlive,
		map[bool]string{true: "green", false: "red"}[report.UpstreamAlive],
		map[bool]string{true: "✓", false: "✗"}[report.UpstreamAlive], report.UpstreamAlive,
		map[bool]string{true: "green", false: "red"}[report.ConfigDetected],
		map[bool]string{true: "✓", false: "✗"}[report.ConfigDetected], report.ConfigDetected,
	)
}

func ephaseResetSequence(report PhaseEReport) string {
	if len(report.ResetSequence) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<div class="card">
<h3>🔄 Reset Sequence (5 steps — §3.1)</h3>
<table>
<tr><th>#</th><th>Step</th><th>Status</th><th>Latency</th></tr>`)

	for _, s := range report.ResetSequence {
		sc := "var(--green)"
		icon := "✓"
		if !s.Success {
			sc = "var(--red)"
			icon = "✗"
		} else if s.StatusCode == 501 {
			icon = "✓ (not supported)"
		}
		sb.WriteString(fmt.Sprintf(`<tr>
<td>%d</td><td>%s</td>
<td style="color:%s;">%d %s</td>
<td>%.1fms</td></tr>`,
			s.Step, html.EscapeString(s.Name), sc, s.StatusCode, icon, s.LatencyMs))
	}

	allIcon := "✓"
	allColor := "var(--green)"
	if !report.ResetAllPassed {
		allIcon = "✗"
		allColor = "var(--red)"
	}
	sb.WriteString(fmt.Sprintf(`</table>
<div style="margin-top:8px;">Result: <span style="color:%s;font-weight:700;">%s ALL 5/5 OK</span></div>
</div>`, allColor, allIcon))
	return sb.String()
}

func ephaseCategorySummaries(report PhaseEReport) string {
	if len(report.Categories) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<div class="row">`)
	for _, cat := range report.Categories {
		sb.WriteString(fmt.Sprintf(`<div class="card" style="flex:1;min-width:200px;">
<h4>%s</h4>
<div class="score-card">
<div class="value" style="color:var(--green);">%.0f<span style="font-size:0.5em;color:var(--subtle);">/%.0f</span></div>
<div class="label">%d/%d tests passed</div>
</div>
</div>`, html.EscapeString(cat.Name), cat.Score, cat.MaxScore, cat.Passed, cat.Total))
	}
	sb.WriteString(`</div>`)
	return sb.String()
}

func ephaseTestDetails(report PhaseEReport) string {
	if len(report.Tests) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<h2>📋 Test Results</h2>`)

	for _, t := range report.Tests {
		badgeColor := "var(--green)"
		badgeClass := "badge-pass"
		if t.Result == "FAIL" {
			badgeColor = "var(--red)"
			badgeClass = "badge-fail"
		} else if t.Result == "SKIP" {
			badgeColor = "var(--yellow)"
			badgeClass = "badge-skip"
		}

		sb.WriteString(fmt.Sprintf(`<div class="card">
<div style="display:flex;justify-content:space-between;align-items:center;">
<h3>%s — %s <span class="badge %s" style="color:%s;">%s</span></h3>
<span style="font-weight:700;color:%s;">+%.1f/%.0f pts</span>
</div>
<p style="color:var(--subtle);margin:4px 0;">%s</p>
`, html.EscapeString(t.TestID), html.EscapeString(t.Name), badgeClass, badgeColor, t.Result,
			badgeColor, t.Score, t.MaxScore,
			html.EscapeString(t.Description)))

		if t.SkipReason != "" {
			sb.WriteString(fmt.Sprintf(`<p style="color:var(--yellow);">⚠ Skip: %s</p>`, html.EscapeString(t.SkipReason)))
		}
		if t.FailReason != "" {
			sb.WriteString(fmt.Sprintf(`<p style="color:var(--red);">✗ %s</p>`, html.EscapeString(t.FailReason)))
		}

		// Hot-reload metrics
		if t.ConfigModified {
			sb.WriteString(fmt.Sprintf(`<details open><summary>🔧 Hot-Reload Metrics</summary>
<div class="detail-section">
<table>
<tr><td>Config Modified</td><td style="color:var(--green);">✓</td></tr>
<tr><td>Config Restored</td><td style="color:var(--%s);">%v</td></tr>
<tr><td>SLA OK (≤10s)</td><td style="color:var(--%s);">%v</td></tr>
<tr><td>Hot-Reload Latency</td><td>%.1f ms</td></tr>
</table>
</div></details>`,
				map[bool]string{true: "green", false: "red"}[t.ConfigRestored], t.ConfigRestored,
				map[bool]string{true: "green", false: "red"}[t.HotReloadSLAOk], t.HotReloadSLAOk,
				t.HotReloadLatencyMs))
		}

		// Cache check results
		if len(t.CacheResults) > 0 {
			sb.WriteString(`<details open><summary>📦 Cache Check Results</summary>
<div class="detail-section">
<table class="cache-table"><tr><th>#</th><th>Method</th><th>Endpoint</th><th>Status</th><th>X-WAF-Cache</th><th>Expect</th><th>Match</th><th>Latency</th></tr>`)
			for _, cr := range t.CacheResults {
				mc := "var(--green)"
				mv := "✓"
				if !cr.MatchExpected {
					mc = "var(--red)"
					mv = "✗"
				}
				sb.WriteString(fmt.Sprintf(`<tr>
<td>%d</td><td>%s</td><td>%s</td><td>%d</td>
<td>%s</td><td>%s</td>
<td style="color:%s;">%s</td><td>%.1fms</td></tr>`,
					cr.RequestNum, html.EscapeString(cr.Method), html.EscapeString(cr.Endpoint),
					cr.StatusCode, cr.CacheHeader, cr.ExpectedCache, mc, mv, cr.LatencyMs))
			}
			sb.WriteString(`</table></div></details>`)
		}

		// Verification results
		if len(t.VerifyResults) > 0 {
			sb.WriteString(`<details open><summary>✅ Verification</summary>
<div class="detail-section"><table><tr><th>Route</th><th>Status</th><th>Expected</th><th>WAF Action</th></tr>`)
			for _, vr := range t.VerifyResults {
				sc := "var(--green)"
				if !vr.Passed {
					sc = "var(--red)"
				}
				sb.WriteString(fmt.Sprintf(`<tr>
<td>%s %s</td><td style="color:%s;">%d</td><td>%d</td><td>%s</td></tr>`,
					html.EscapeString(vr.Method), html.EscapeString(vr.Endpoint), sc, vr.StatusCode,
					vr.ExpectedCode, html.EscapeString(vr.WAFAction)))
			}
			sb.WriteString(`</table></div></details>`)
		}

		// Pass/Fail criteria
		if len(t.FailConditions) > 0 {
			sb.WriteString(`<details><summary>📋 PASS/FAIL Criteria</summary>
<div class="detail-section"><table><tr><th>Condition</th><th>Description</th><th>Triggered</th></tr>`)
			for _, fc := range t.FailConditions {
				tc := `<span style="color:var(--green);">No</span>`
				if fc.Triggered {
					tc = fmt.Sprintf(`<span style="color:var(--red);">Yes — %s</span>`, html.EscapeString(fc.Evidence))
				}
				sb.WriteString(fmt.Sprintf(`<tr>
<td style="font-family:monospace;">%s</td><td>%s</td><td>%s</td></tr>`,
					html.EscapeString(fc.ID), html.EscapeString(fc.Description), tc))
			}
			sb.WriteString(`</table></div></details>`)
		}

		// Pass criterion
		sb.WriteString(fmt.Sprintf(`<details><summary>🎯 Pass Criterion</summary>
<div class="detail-section"><p style="font-size:0.85rem;color:var(--subtle);">%s</p></div></details>`,
			html.EscapeString(t.PassCriterion)))

		// Scoring explanation
		sb.WriteString(fmt.Sprintf(`<details open><summary>📊 Scoring Explanation</summary>
<div class="scoring-explain %s">%s</div></details>`,
			map[bool]string{true: "pass", false: "fail"}[t.Passed],
			strings.ReplaceAll(html.EscapeString(t.ScoringExplain), "\n", "<br>")))

		// Reproduce script
		if t.ReproduceScript != "" {
			sb.WriteString(fmt.Sprintf(`<details><summary>🔄 Reproduce Script (copy-paste)</summary>
<div class="code-block"><pre>%s</pre></div></details>`, html.EscapeString(t.ReproduceScript)))
		}

		sb.WriteString(fmt.Sprintf(`<div style="margin-top:8px;font-size:0.8rem;color:var(--subtle);">Duration: %.1fs</div>`,
			t.DurationSec))
		sb.WriteString(`</div>`)
	}
	return sb.String()
}

func ephaseScoringSummary(report PhaseEReport) string {
	passRateClass := "good"
	if report.PassRate < 0.5 {
		passRateClass = "bad"
	}

	// Automated score label
	automatedLabel := "EXT Score (Automated)"

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<h2>📊 Scoring Summary</h2>
<div class="row">
<div class="card" style="flex:1;min-width:120px;">
<div class="score-card">
<div class="value pass-rate %s">%.0f<span style="font-size:0.5em;">%%</span></div>
<div class="label">Pass Rate</div>
<div style="font-size:0.8rem;color:var(--subtle);">%d/%d/%d tests</div>
</div>
</div>
<div class="card" style="flex:1;min-width:120px;">
<div class="score-card">
<div class="value" style="color:var(--blue);">%.0f<span style="font-size:0.5em;color:var(--subtle);">/%.0f</span></div>
<div class="label">%s</div>
</div>
</div>
</div>

<div class="card" style="border-left:3px solid var(--yellow);">
<h3>⚠️ Manual Evaluation (BTC Demo/Live)</h3>
<table>
<tr><th>Test</th><th>Max</th><th>Evaluation</th><th>Earned</th></tr>
<tr>
<td>EXT-01 — Hot-Reload Add Rule</td><td>3</td>
<td style="color:var(--yellow);">MANUAL ⚠</td><td>—</td></tr>
<tr>
<td>EXT-02 — Hot-Reload Remove Rule</td><td>3</td>
<td style="color:var(--yellow);">MANUAL ⚠</td><td>—</td></tr>
</table>
<p style="font-size:0.82rem;color:var(--subtle);margin-top:8px;">
EXT-01 and EXT-02 are evaluated manually by BTC during demo/live evaluation.
Not included in automated benchmark score.
</p>
</div>

<div class="card">
<h3>Scoring Breakdown (Automated)</h3>
<table>
<tr><th>Test</th><th>Max</th><th>Result</th><th>Earned</th><th>Sub-Scores</th></tr>`,
		passRateClass, report.PassRate*100,
		report.PassedTests, report.FailedTests, report.SkippedTests,
		report.TotalScore, report.MaxScore, automatedLabel))

	for _, br := range report.ScoringBreakdown {
		sc := "var(--green)"
		rs := "PASS ✓"
		if br.Skipped {
			sc = "var(--yellow)"
			rs = "SKIP ⚠"
		} else if !br.Passed {
			sc = "var(--red)"
			rs = "FAIL ✗"
		}
		subInfo := ""
		if len(br.SubScores) > 0 {
			var parts []string
			for k, v := range br.SubScores {
				parts = append(parts, fmt.Sprintf("%s:%.0f", k, v))
			}
			subInfo = strings.Join(parts, ", ")
		}
		sb.WriteString(fmt.Sprintf(`<tr>
<td>%s — %s</td><td>%.0f</td>
<td style="color:%s;">%s</td><td>%.0f</td>
<td style="font-size:0.78rem;color:var(--subtle);">%s</td></tr>`,
			html.EscapeString(br.TestID), html.EscapeString(br.Name),
			br.MaxScore, sc, rs, br.ScoreEarned, subInfo))
	}
	sb.WriteString(fmt.Sprintf(`</table></div>

<div class="card">
<h3>Scoring Map</h3>
<table>
<tr><th>Criterion</th><th>Description</th><th>Max</th><th>Formula</th></tr>
<tr>
<td>%s</td><td>%s</td><td>%d</td>
<td><code>%s</code></td></tr>
</table>
</div>

<div class="card">
<h3>📐 Scoring Methodology</h3>
<pre style="font-size:0.82rem;line-height:1.5;">%s</pre>
</div>`,
		html.EscapeString(report.ScoringMap.Criterion),
		html.EscapeString(report.ScoringMap.Description),
		report.ScoringMap.MaxPoints,
		html.EscapeString(report.ScoringMap.Formula),
		html.EscapeString(report.ScoringMethodology)))

	return sb.String()
}

func ephaseHTMLPostamble(report PhaseEReport) string {
	return fmt.Sprintf(`
<div class="meta" style="margin-top:24px;text-align:center;">
WAF Benchmark Tool v2.9.0 — Phase E Report (v2.5) | Generated: %s | Duration: %.1fs
</div>
</body></html>`, report.Timestamp, float64(report.DurationMs)/1000.0)
}
