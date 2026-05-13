package phased

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"

	"github.com/waf-hackathon/benchmark-new/internal/phasec"
)

// GenerateReport writes report_phase_d.html and report_phase_d.json.
func GenerateReport(r *PhaseDResult, outputDir string) error {
	report := buildDReport(r)

	// JSON
	jsonPath := filepath.Join(outputDir, "report_phase_d.json")
	if err := writeDJSON(report, jsonPath); err != nil {
		return fmt.Errorf("JSON report: %w", err)
	}
	fmt.Printf("📄 JSON report: %s\n", jsonPath)

	// HTML
	htmlPath := filepath.Join(outputDir, "report_phase_d.html")
	if err := writeDHTML(report, htmlPath); err != nil {
		return fmt.Errorf("HTML report: %w", err)
	}
	fmt.Printf("📄 HTML report: %s\n", htmlPath)

	return nil
}

func buildDReport(r *PhaseDResult) PhaseDReport {
	report := PhaseDReport{
		Phase:             "D",
		Timestamp:         r.StartTime.Format("2006-01-02T15:04:05Z07:00"),
		WAFTarget:         r.WAFTarget,
		WAFMode:           r.WAFMode,
		DurationMs:        r.EndTime.Sub(r.StartTime).Milliseconds(),
		PreCheckPassed:    r.WAFAlive && r.UpstreamAlive,
		WAFAlive:          r.WAFAlive,
		UpstreamAlive:     r.UpstreamAlive,
		ResetAllPassed:    r.ResetAllPassed,
		RawScore:          r.RawScore,
		RawMaxScore:       r.RawMaxScore,
		INT04Score:        r.INT04Score,
		INT04Cap:          r.INT04Cap,
		PassedTests:       r.PassedTests,
		FailedTests:       r.FailedTests,
		SkippedTests:      r.SkippedTests,
		ScoringMethodology: ScoringMapDoc,
		ResourceTier:       r.ResourceTier,
		CgroupsActive:      r.CgroupsActive,
		DiagnosticFlags:    r.DiagnosticFlags,
		ProfilerActive:     r.ProfilerActive,
	}

	total := r.PassedTests + r.FailedTests + r.SkippedTests
	if total > 0 {
		report.PassRate = float64(r.PassedTests) / float64(total)
	}

	// Reset sequence
	for _, s := range r.ResetSteps {
		report.ResetSequence = append(report.ResetSequence, DResetStepJSON{
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
		"ddos":              {name: "DDoS Stress Tests"},
		"backend_failure":   {name: "Backend Failure Tests"},
		"fail_mode_config":  {name: "Fail-Mode Configurability"},
	}
	for catID := range catMap {
		for _, tr := range r.TestResults {
			if tr.Category == catID {
				cm := catMap[catID]
				cm.total++
				if tr.Passed {
					cm.passed++
					cm.score += tr.MaxScore
				}
				cm.max += tr.MaxScore
				catMap[catID] = cm
			}
		}
	}
	for catID, cm := range catMap {
		if cm.total > 0 {
			report.Categories = append(report.Categories, DCategorySummaryJSON{
				ID: catID, Name: cm.name, Criterion: "INT-04",
				Passed: cm.passed, Total: cm.total,
				Score: cm.score, MaxScore: cm.max,
			})
		}
	}

	// Test entries
	for _, tr := range r.TestResults {
		entry := buildDTestEntry(&tr)
		report.Tests = append(report.Tests, entry)

		// Scoring breakdown
		sb := DScoringBreakdownJSON{
			TestID: tr.TestID, Name: tr.Name, MaxScore: tr.MaxScore,
			Passed: tr.Passed, Skipped: tr.Skipped,
		}
		if tr.Passed {
			sb.ScoreEarned = tr.MaxScore
		}
		report.ScoringBreakdown = append(report.ScoringBreakdown, sb)
	}

	// Scoring map
	report.ScoringMap = DSScoringMapJSON{
		Criterion:   "INT-04",
		Description: "Resilience & Degradation",
		MaxPoints:   8,
		Formula:     "min(8, sum(D01..D09 sub-scores))",
		Cap:         8,
		RawMax:      20,
	}

	return report
}

func buildDTestEntry(tr *DTestResult) DTestEntryJSON {
	entry := DTestEntryJSON{
		TestID:          tr.TestID,
		Name:            tr.Name,
		Category:        tr.Category,
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
	}

	if tr.Passed {
		entry.Result = "PASS"
		entry.Score = tr.MaxScore
	} else if tr.Skipped {
		entry.Result = "SKIP"
	} else {
		entry.Result = "FAIL"
	}

	// Tool output
	if tr.ToolStdout != "" {
		entry.ToolOutput = &DToolOutputJSON{
			Tool:     func() string {
				switch tr.TestID {
				case "D01", "D04", "D08", "D09":
					return "wrk2"
				case "D02", "D03":
					return "slowhttptest"
				default:
					return "curl"
				}
			}(),
			ExitCode: tr.ToolExitCode,
			Stdout:   tr.ToolStdout,
			Stderr:   tr.ToolStderr,
			Summary:  tr.ToolSummary,
		}
	}

	// Flood metrics
	if tr.ActualRPS > 0 {
		entry.FloodMetrics = &DFloodMetricsJSON{
			TargetRPS:      float64(func() int { return 50000 }()),
			ActualRPS:      tr.ActualRPS,
			TransferSec:    tr.TransferSec,
			LatencyAvgMs:   tr.LatencyAvgMs,
			LatencyStdevMs: tr.LatencyStdevMs,
			LatencyMaxMs:   tr.LatencyMaxMs,
			LatencyP50Ms:   tr.LatencyP50Ms,
			LatencyP75Ms:   tr.LatencyP75Ms,
			LatencyP90Ms:   tr.LatencyP90Ms,
			LatencyP99Ms:   tr.LatencyP99Ms,
			SocketErrors:   tr.SocketErrors,
		}
	}

	// Slow metrics
	if tr.TestID == "D02" || tr.TestID == "D03" {
		entry.SlowMetrics = &DSlowMetricsJSON{
			ConnectionsOpen:    tr.ConnectionsOpen,
			ConnectionsClosed:  tr.ConnectionsClosed,
			ConnectionsError:   tr.ConnectionsError,
			ConnectionsPending: tr.ConnectionsPending,
			ServiceAvailable:   tr.ServiceAvailable,
			ExitStatus:         tr.ToolExitCode,
		}
	}

	// Verification
	if len(tr.PreVerifyResults) > 0 {
		entry.PreVerify = buildVerifyBlock(tr.PreVerifyResults, "Pre-test")
	}
	if len(tr.DuringVerifyResults) > 0 {
		entry.DuringVerify = buildVerifyBlock(tr.DuringVerifyResults, "During-flood")
	}
	if len(tr.PostVerifyResults) > 0 {
		entry.PostVerify = buildVerifyBlock(tr.PostVerifyResults, "Post-test")
	}

	// Tier results
	if len(tr.TierResults) > 0 {
		entry.TierResults = make(map[string]DTierResultJSON)
		for tier, tres := range tr.TierResults {
			tj := DTierResultJSON{
				Tier: tres.Tier, ExpectedCode: tres.ExpectedCode,
				ExpectedMode: tres.ExpectedMode,
				TotalRoutes: tres.TotalRoutes, PassedRoutes: tres.PassedRoutes,
				AllPassed: tres.AllPassed, FailReason: tres.FailReason,
			}
			for _, vr := range tres.Routes {
				tj.Routes = append(tj.Routes, DVerifyRouteJSON{
					Method: vr.Method, Endpoint: vr.Endpoint,
					StatusCode: vr.StatusCode, ExpectedCode: vr.ExpectedCode,
					LatencyMs: vr.LatencyMs, WAFAction: vr.WAFAction,
					RiskScore: vr.RiskScore, Passed: vr.Passed,
					FailReason: vr.FailReason, CurlCommand: vr.CurlCommand,
					Tier: vr.Tier,
				})
			}
			entry.TierResults[tier] = tj
		}
	}

	// D05/D06/D07
	entry.CircuitBroken = tr.CircuitBroken
	entry.TimeoutDetected = tr.TimeoutDetected
	entry.WAFAction = tr.WAFAction

	if len(tr.RecoveryResults) > 0 {
		entry.Recovered = tr.Recovered
		for _, vr := range tr.RecoveryResults {
			entry.RecoveryResults = append(entry.RecoveryResults, DVerifyRouteJSON{
				Method: vr.Method, Endpoint: vr.Endpoint,
				StatusCode: vr.StatusCode, ExpectedCode: vr.ExpectedCode,
				LatencyMs: vr.LatencyMs, WAFAction: vr.WAFAction,
				RiskScore: vr.RiskScore, Passed: vr.Passed,
				FailReason: vr.FailReason, CurlCommand: vr.CurlCommand,
			})
		}
	}

	// Pass/fail criteria
	dt := findTestDef(tr.TestID)
	if dt != nil {
		// WAF Action expectations
		entry.AcceptActions = e.determineAcceptActions(dt)

		// Fail conditions
		for key, desc := range dt.FailReasons {
			triggered := (tr.FailReason == key)
			evidence := ""
			if triggered {
				evidence = tr.FailReason
			}
			entry.FailConditions = append(entry.FailConditions, DFailConditionJSON{
				ID: key, Description: desc, Triggered: triggered, Evidence: evidence,
			})
		}

		entry.ScoringFormula = fmt.Sprintf("PASS → +%.0f pts | FAIL/SKIP → 0 pts | INT-04 = min(8, sum(all))", dt.MaxScore)
	}

	return entry
}

func buildVerifyBlock(results []DVerifyRouteResult, phase string) *DVerifyBlockJSON {
	block := &DVerifyBlockJSON{
		Phase:     phase,
		TotalCount: len(results),
	}
	for _, vr := range results {
		if vr.Passed {
			block.PassedCount++
		}
		block.Routes = append(block.Routes, DVerifyRouteJSON{
			Method: vr.Method, Endpoint: vr.Endpoint,
			StatusCode: vr.StatusCode, ExpectedCode: vr.ExpectedCode,
			LatencyMs: vr.LatencyMs, WAFAction: vr.WAFAction,
			RiskScore: vr.RiskScore, Passed: vr.Passed,
			FailReason: vr.FailReason, CurlCommand: vr.CurlCommand,
			Tier: vr.Tier,
		})
	}
	block.AllPassed = block.PassedCount == block.TotalCount
	return block
}

func (e *DEngine) determineAcceptActions(dt *DTest) []string {
	switch dt.ID {
	case "D01", "D04":
		return []string{"rate_limit", "block"}
	case "D02", "D03":
		return []string{"timeout", "block"}
	case "D05":
		return []string{"circuit_breaker"}
	case "D06":
		return []string{"timeout"}
	case "D07":
		return []string{"allow"}
	case "D08", "D09":
		return []string{"rate_limit", "block"}
	}
	return nil
}

var e DEngine // dummy for method receiver

func findTestDef(id string) *DTest {
	for _, dt := range GetDTests("", "", "", phasec.TierMid) {
		if dt.ID == id {
			return &dt
		}
	}
	return nil
}

// ── JSON I/O ──

func writeDJSON(report PhaseDReport, path string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ── HTML Generation ──

func writeDHTML(report PhaseDReport, path string) error {
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>WAF Benchmark — Phase D: Resilience & Degradation Report</title>
<style>
:root{--bg:#0b1120;--card:#111827;--card2:#1a2332;--text:#e2e8f0;--muted:#94a3b8;--subtle:#64748b;--green:#22c55e;--red:#ef4444;--yellow:#eab308;--blue:#3b82f6;--purple:#8b5cf6;--orange:#f97316;--border:#1e293b;--border2:#334155;--code-bg:#0f172a;--pre-bg:#0f172a}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.7;padding:0}
.container{max-width:1400px;margin:0 auto;padding:20px 24px 60px}
.main-header{background:linear-gradient(135deg,var(--card),var(--card2));border:1px solid var(--border);border-radius:16px;padding:28px 32px;margin-bottom:24px}
.main-header h1{font-size:1.6rem;font-weight:800;letter-spacing:-.02em}
.main-header .sub{color:var(--muted);font-size:.85rem;margin-top:4px}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-top:16px}
.meta-item{display:flex;flex-direction:column}
.meta-item .lbl{font-size:.7rem;color:var(--subtle);text-transform:uppercase;letter-spacing:.05em}
.meta-item .val{font-size:.95rem;font-weight:600;word-break:break-all}
.score-card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:24px 28px;margin-bottom:24px}
.score-card h2{font-size:1.1rem;font-weight:700;margin-bottom:12px}
.score-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:12px}
.score-item{background:var(--card2);border:1px solid var(--border2);border-radius:10px;padding:14px 16px;text-align:center}
.score-item .crit{font-size:.7rem;color:var(--subtle);text-transform:uppercase;letter-spacing:.04em}
.score-item .val{font-size:1.6rem;font-weight:800;color:var(--blue);margin:4px 0}
.score-item .max{font-size:.75rem;color:var(--muted)}
.score-item.pass .val{color:var(--green)}
.score-item.fail .val{color:var(--red)}
.section{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:24px 28px;margin-bottom:24px}
.section h2{font-size:1.1rem;font-weight:700;margin-bottom:16px}
.reset-steps{display:flex;flex-direction:column;gap:6px}
.reset-step{display:flex;align-items:center;gap:10px;padding:6px 0;font-family:monospace;font-size:.85rem}
.reset-step .ok{color:var(--green);font-weight:700}
.reset-step .fail{color:var(--red);font-weight:700}
.step-num{color:var(--subtle);min-width:40px}
.test-card{background:var(--card2);border:1px solid var(--border2);border-radius:12px;margin-bottom:16px;overflow:hidden}
.test-card-header{display:flex;align-items:center;gap:12px;padding:16px 20px;background:var(--card);border-bottom:1px solid var(--border2);cursor:pointer}
.test-card-header:hover{background:var(--border)}
.test-id{font-family:monospace;font-weight:700;color:var(--blue);min-width:40px}
.test-name{font-weight:600;font-size:.95rem}
.test-badge{margin-left:auto;padding:3px 10px;border-radius:6px;font-size:.75rem;font-weight:700;text-transform:uppercase}
.badge-pass{background:rgba(34,197,94,.15);color:var(--green);border:1px solid rgba(34,197,94,.3)}
.badge-fail{background:rgba(239,68,68,.15);color:var(--red);border:1px solid rgba(239,68,68,.3)}
.badge-skip{background:rgba(234,179,8,.15);color:var(--yellow);border:1px solid rgba(234,179,8,.3)}
.test-card-body{padding:16px 20px}
.test-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-bottom:12px}
.test-meta-item{font-size:.82rem}
.ml{color:var(--subtle);font-weight:500;margin-right:6px}
.mv{color:var(--text)}
.detail-section{margin:12px 0;padding:12px 16px;background:var(--card);border-radius:8px;border:1px solid var(--border)}
.detail-section h4{font-size:.82rem;color:var(--blue);margin-bottom:8px;text-transform:uppercase;letter-spacing:.03em}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid var(--border2)}
th{color:var(--subtle);font-weight:600;font-size:.75rem;text-transform:uppercase}
td{font-family:monospace;font-size:.8rem}
pre{background:var(--pre-bg);border:1px solid var(--border2);border-radius:8px;padding:12px 16px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:.78rem;color:var(--muted);overflow-x:auto;max-height:400px;line-height:1.5}
.scoring-explain{white-space:pre-wrap;font-family:monospace;font-size:.8rem;color:var(--muted);padding:8px 0;line-height:1.6}
.scoring-explain.pass{color:var(--green)}
.scoring-explain.fail{color:var(--red)}
.fail-reason{padding:8px 16px;margin:8px 0;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:6px;font-size:.82rem;color:var(--red)}
hr{border:none;border-top:1px solid var(--border2);margin:16px 0}
.summary-bar{display:flex;gap:24px;flex-wrap:wrap;padding:12px 0}
.summary-stat{text-align:center}
.summary-stat .num{font-size:2rem;font-weight:800;color:var(--blue)}
.summary-stat .lbl{font-size:.7rem;color:var(--subtle);text-transform:uppercase}
.tag-pass{color:var(--green);background:rgba(34,197,94,.1);padding:2px 6px;border-radius:4px;font-size:.75rem}
.tag-fail{color:var(--red);background:rgba(239,68,68,.1);padding:2px 6px;border-radius:4px;font-size:.75rem}
details summary{cursor:pointer;font-weight:600;color:var(--blue);font-size:.85rem;padding:4px 0}
details summary:hover{color:var(--purple)}
.code-block{position:relative}
.code-block pre{margin:0}
.footer{text-align:center;color:var(--subtle);font-size:.75rem;margin-top:32px;padding:16px}
.tier-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}
.tier-item{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px}
.tier-item h5{font-size:.82rem;color:var(--muted);margin-bottom:6px}
</style>
</head>
<body>
<div class="container">
`)

	// ═══ HEADER ═══
	sb.WriteString(`<div class="main-header">
<h1>🛡️ WAF Benchmark — Phase D: Resilience & Degradation</h1>
<div class="sub">INT-04 Scoring | Cap 8 pts | Raw Max 20 pts | ` + report.Timestamp + `</div>
<div class="meta-grid">
<div class="meta-item"><span class="lbl">WAF Target</span><span class="val">` + html.EscapeString(report.WAFTarget) + `</span></div>
<div class="meta-item"><span class="lbl">WAF Mode</span><span class="val">` + html.EscapeString(report.WAFMode) + `</span></div>
<div class="meta-item"><span class="lbl">Duration</span><span class="val">` + fmt.Sprintf("%.1fs", float64(report.DurationMs)/1000.0) + `</span></div>
<div class="meta-item"><span class="lbl">Pre-Check</span><span class="val">` + func() string {
		if report.PreCheckPassed {
			return `<span style="color:var(--green);">✓ PASS</span>`
		}
		return `<span style="color:var(--red);">✗ FAIL</span>`
	}() + `</span></div>
</div>
</div>`)

	// ═══ SCORE CARD ═══
	sb.WriteString(`<div class="score-card">
<h2>📊 Scoring Summary</h2>
<div class="summary-bar">
<div class="summary-stat"><div class="num">` + fmt.Sprintf("%.1f", report.INT04Score) + `</div><div class="lbl">INT-04 Score</div></div>
<div class="summary-stat"><div class="num"` + func() string {
		if report.INT04Score >= 8.0 {
			return ` style="color:var(--green)"`
		}
		return ""
	}() + `>` + fmt.Sprintf("%.0f", report.INT04Cap) + `</div><div class="lbl">Cap</div></div>
<div class="summary-stat"><div class="num">` + fmt.Sprintf("%.1f", report.RawScore) + `</div><div class="lbl">Raw Score</div></div>
<div class="summary-stat"><div class="num">` + fmt.Sprintf("%.0f", report.RawMaxScore) + `</div><div class="lbl">Raw Max</div></div>
<div class="summary-stat"><div class="num">` + fmt.Sprintf("%d", report.PassedTests) + `</div><div class="lbl">Passed</div></div>
<div class="summary-stat"><div class="num">` + fmt.Sprintf("%d", report.FailedTests) + `</div><div class="lbl">Failed</div></div>
<div class="summary-stat"><div class="num">` + fmt.Sprintf("%d", report.SkippedTests) + `</div><div class="lbl">Skipped</div></div>
</div>
<div class="score-grid">`)

	for _, scr := range report.ScoringBreakdown {
		cls := "fail"
		if scr.Passed {
			cls = "pass"
		} else if scr.Skipped {
			cls = "skip"
		}
		bg := "var(--red)"
		if scr.Passed {
			bg = "var(--green)"
		} else if scr.Skipped {
			bg = "var(--yellow)"
		}
		statusText := "FAIL"
		if scr.Passed {
			statusText = "PASS"
		} else if scr.Skipped {
			statusText = "SKIP"
		}
		sb.WriteString(fmt.Sprintf(`<div class="score-item %s">
<div class="crit">%s</div><div class="val" style="color:%s;">%s</div>
<div class="max">%.0f / %.0f pts</div>
</div>`, cls, html.EscapeString(scr.TestID), bg, statusText, scr.ScoreEarned, scr.MaxScore))
}

	sb.WriteString(`</div></div>`)

	// ═══ RESET SEQUENCE ═══
	sb.WriteString(`<div class="section">
<h2>🔄 Full Reset Sequence (9 steps — §3.1)</h2>
<div class="reset-steps">`)
	for _, s := range report.ResetSequence {
		cls := "ok"
		if !s.Success {
			cls = "fail"
		}
		sb.WriteString(fmt.Sprintf(`<div class="reset-step">
<span class="step-num">[%d/9]</span>
<span class="%s">%s</span>
<span style="color:var(--muted);">%s</span>
<span style="color:var(--subtle);">→ %d</span>
</div>`, s.Step, cls, html.EscapeString(s.Name), map[bool]string{true: "✓", false: "✗"}[s.Success], s.StatusCode))
	}
	sb.WriteString(`</div></div>`)

	// ═══ SCORING METHODOLOGY ═══
	sb.WriteString(`<div class="section">
<h2>📐 Scoring Methodology</h2>
<pre style="white-space:pre-wrap;">` + html.EscapeString(report.ScoringMethodology) + `</pre>
</div>`)

	// ═══ CATEGORIES & TESTS ═══
	catOrder := []struct {
		id   string
		name string
	}{
		{"ddos", "DDoS Stress Tests"},
		{"backend_failure", "Backend Failure Tests"},
		{"fail_mode_config", "Fail-Mode Configurability"},
	}

	for ci, cat := range catOrder {
		var catTests []DTestEntryJSON
		catPassed, catTotal := 0, 0
		for _, t := range report.Tests {
			if t.Category == cat.id {
				catTests = append(catTests, t)
				catTotal++
				if t.Passed {
					catPassed++
				}
			}
		}
		if len(catTests) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf(`<div class="section">
<h2>📂 CAT %d: %s <span style="font-weight:400;color:var(--muted);font-size:.85rem;">(%d/%d passed)</span></h2>
`, ci+1, html.EscapeString(cat.name), catPassed, catTotal))

		for _, t := range catTests {
			buildDTestHTML(&sb, &t)
		}

		sb.WriteString(`</div>`)
	}

	// ═══ SCORING MAP ═══
	sb.WriteString(fmt.Sprintf(`<div class="section">
<h2>🗺️ Scoring Map</h2>
<pre>%s</pre>
</div>`, html.EscapeString(ScoringMapDoc)))

	// ═══ FOOTER ═══
	sb.WriteString(`<div class="footer">
WAF Benchmark Tool v2.7 — Phase D: Resilience & Degradation Tests
<br>Generated by WAF-BENCHMARK-NEW | INT-04 Criterion
</div>`)

	sb.WriteString(`</div></body></html>`)

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func buildDTestHTML(sb *strings.Builder, t *DTestEntryJSON) {
	badgeCls := "badge-fail"
	if t.Passed {
		badgeCls = "badge-pass"
	} else if t.Skipped {
		badgeCls = "badge-skip"
	}

	sb.WriteString(fmt.Sprintf(`
<div class="test-card">
<div class="test-card-header">
<span class="test-id">%s</span>
<span class="test-name">%s</span>
<span class="test-badge %s">%s</span>
</div>
<div class="test-card-body">
`, t.TestID, html.EscapeString(t.Name), badgeCls, t.Result))

	// Meta
	sb.WriteString(fmt.Sprintf(`<div class="test-meta">
<div class="test-meta-item"><span class="ml">Category:</span><span class="mv">%s</span></div>
<div class="test-meta-item"><span class="ml">Max Score:</span><span class="mv">%.0f pts</span></div>
<div class="test-meta-item"><span class="ml">Duration:</span><span class="mv">%.1fs</span></div>
<div class="test-meta-item"><span class="ml">Score Earned:</span><span class="mv" style="color:var(--%s);">%.0f pts</span></div>
</div>`,
		html.EscapeString(t.Category), t.MaxScore, t.DurationSec,
		map[bool]string{true: "green", false: "red"}[t.Passed],
		map[bool]float64{true: t.MaxScore}[t.Passed]))

	// Description & pass criterion
	sb.WriteString(fmt.Sprintf(`<div class="detail-section">
<div class="test-meta-item"><span class="ml">Description:</span><span class="mv">%s</span></div>
<div class="test-meta-item"><span class="ml">Pass Criterion:</span><span class="mv">%s</span></div>
</div>`, html.EscapeString(t.Description), html.EscapeString(t.PassCriterion)))

	// Fail reason
	if t.FailReason != "" {
		sb.WriteString(fmt.Sprintf(`<div class="fail-reason">❌ Fail Reason: %s</div>`, html.EscapeString(t.FailReason)))
	}

	// Skip reason
	if t.Skipped && t.SkipReason != "" {
		sb.WriteString(fmt.Sprintf(`<div class="fail-reason" style="color:var(--yellow);background:rgba(234,179,8,.08);border-color:rgba(234,179,8,.2);">⚠️ Skip Reason: %s</div>`, html.EscapeString(t.SkipReason)))
	}

	// Flood metrics
	if t.FloodMetrics != nil {
		sb.WriteString(fmt.Sprintf(`<details open><summary>📈 Flood Metrics (wrk2)</summary>
<div class="detail-section">
<table><tr><th>Metric</th><th>Value</th></tr>
<tr><td>Actual RPS</td><td>%.1f</td></tr>
<tr><td>Transfer/sec</td><td>%s</td></tr>
<tr><td>Latency Avg</td><td>%.1fms</td></tr>
<tr><td>Latency Stdev</td><td>%.1fms</td></tr>
<tr><td>Latency Max</td><td>%.1fms</td></tr>
<tr><td>P50</td><td>%.1fms</td></tr>
<tr><td>P75</td><td>%.1fms</td></tr>
<tr><td>P90</td><td>%.1fms</td></tr>
<tr><td>P99</td><td>%.1fms</td></tr>
<tr><td>Socket Errors (connect)</td><td>%d</td></tr>
<tr><td>Socket Errors (read)</td><td>%d</td></tr>
<tr><td>Socket Errors (write)</td><td>%d</td></tr>
<tr><td>Socket Errors (timeout)</td><td>%d</td></tr>
</table></div></details>`,
			t.FloodMetrics.ActualRPS, html.EscapeString(t.FloodMetrics.TransferSec),
			t.FloodMetrics.LatencyAvgMs, t.FloodMetrics.LatencyStdevMs, t.FloodMetrics.LatencyMaxMs,
			t.FloodMetrics.LatencyP50Ms, t.FloodMetrics.LatencyP75Ms, t.FloodMetrics.LatencyP90Ms, t.FloodMetrics.LatencyP99Ms,
			t.FloodMetrics.SocketErrors["connect"], t.FloodMetrics.SocketErrors["read"],
			t.FloodMetrics.SocketErrors["write"], t.FloodMetrics.SocketErrors["timeout"]))
	}

	// Slow metrics
	if t.SlowMetrics != nil {
		svcCls := "var(--green)"
		if !t.SlowMetrics.ServiceAvailable {
			svcCls = "var(--red)"
		}
		sb.WriteString(fmt.Sprintf(`<details open><summary>🐢 Slow Connection Metrics (slowhttptest)</summary>
<div class="detail-section">
<table><tr><th>Metric</th><th>Value</th></tr>
<tr><td>Connections Open</td><td>%d</td></tr>
<tr><td>Connections Closed</td><td>%d</td></tr>
<tr><td>Connections Error</td><td>%d</td></tr>
<tr><td>Connections Pending</td><td>%d</td></tr>
<tr><td>Service Available</td><td style="color:%s;">%v</td></tr>
<tr><td>Exit Status</td><td>%d</td></tr>
</table></div></details>`,
			t.SlowMetrics.ConnectionsOpen, t.SlowMetrics.ConnectionsClosed,
			t.SlowMetrics.ConnectionsError, t.SlowMetrics.ConnectionsPending,
			svcCls, t.SlowMetrics.ServiceAvailable, t.SlowMetrics.ExitStatus))
	}

	// Verification blocks
	renderVerifyBlock(sb, t.PreVerify)
	renderVerifyBlock(sb, t.DuringVerify)
	renderVerifyBlock(sb, t.PostVerify)

	// Tier results
	if len(t.TierResults) > 0 {
		sb.WriteString(`<details open><summary>🏷️ Route Tier Results</summary><div class="tier-grid">`)
		for _, tier := range []string{"CRITICAL", "MEDIUM", "CATCH_ALL", "STATIC"} {
			if tres, ok := t.TierResults[tier]; ok {
				cls := "var(--green)"
				if !tres.AllPassed {
					cls = "var(--red)"
				}
				sb.WriteString(fmt.Sprintf(`<div class="tier-item">
<h5>%s Tier <span style="color:%s;">(%d/%d)</span> <span style="color:var(--subtle);">expect %s</span></h5>
<table><tr><th>Route</th><th>Status</th><th>Action</th></tr>`, tres.Tier, cls, tres.PassedRoutes, tres.TotalRoutes, tres.ExpectedMode))
				for _, vr := range tres.Routes {
					sc := "var(--green)"
					if !vr.Passed {
						sc = "var(--red)"
					}
					sb.WriteString(fmt.Sprintf(`<tr><td>%s %s</td><td style="color:%s;">%d</td><td>%s</td></tr>`,
						vr.Method, html.EscapeString(vr.Endpoint), sc, vr.StatusCode, html.EscapeString(vr.WAFAction)))
				}
				sb.WriteString(`</table></div>`)
			}
		}
		sb.WriteString(`</div></details>`)
	}

	// Recovery results
	if len(t.RecoveryResults) > 0 {
		sb.WriteString(fmt.Sprintf(`<details open><summary>🔄 Recovery Results (%d routes)</summary>
<div class="detail-section"><table><tr><th>Route</th><th>Status</th></tr>`, len(t.RecoveryResults)))
		for _, vr := range t.RecoveryResults {
			sc := "var(--green)"
			if !vr.Passed {
				sc = "var(--red)"
			}
			sb.WriteString(fmt.Sprintf(`<tr><td>%s %s</td><td style="color:%s;">%d</td></tr>`,
				vr.Method, html.EscapeString(vr.Endpoint), sc, vr.StatusCode))
		}
		sb.WriteString(fmt.Sprintf(`</table></div>
<div>Recovered: <span style="color:var(--%s);font-weight:700;">%v</span></div>
</details>`, map[bool]string{true: "green", false: "red"}[t.Recovered], t.Recovered))
	}

	// Scoring explanation
	sb.WriteString(fmt.Sprintf(`<details open><summary>📊 Scoring Explanation</summary>
<div class="scoring-explain %s">%s</div></details>`,
		map[bool]string{true: "pass", false: "fail"}[t.Passed],
		strings.ReplaceAll(html.EscapeString(t.ScoringExplain), "\n", "<br>")))

	// Pass/Fail criteria box
	if len(t.FailConditions) > 0 {
		sb.WriteString(`<details><summary>📋 PASS/FAIL Criteria</summary><div class="detail-section"><table><tr><th>Condition</th><th>Description</th><th>Triggered</th></tr>`)
		for _, fc := range t.FailConditions {
			tc := `<span style="color:var(--green);">No</span>`
			if fc.Triggered {
				tc = fmt.Sprintf(`<span style="color:var(--red);">Yes — %s</span>`, html.EscapeString(fc.Evidence))
			}
			sb.WriteString(fmt.Sprintf(`<tr><td style="font-family:monospace;">%s</td><td>%s</td><td>%s</td></tr>`,
				html.EscapeString(fc.ID), html.EscapeString(fc.Description), tc))
		}
		sb.WriteString(`</table></div></details>`)
	}

	// Reproduce script
	if t.ReproduceScript != "" {
		sb.WriteString(fmt.Sprintf(`<details><summary>🔄 Reproduce Script (copy-paste)</summary>
<div class="code-block"><pre>%s</pre></div></details>`, html.EscapeString(t.ReproduceScript)))
	}

	// Tool output
	if t.ToolOutput != nil && t.ToolOutput.Stdout != "" {
		sb.WriteString(fmt.Sprintf(`<details><summary>🔧 %s Raw Output</summary>
<div class="code-block"><pre>%s</pre></div></details>`,
			html.EscapeString(t.ToolOutput.Tool), html.EscapeString(t.ToolOutput.Stdout)))
	}

	sb.WriteString(`</div></div>`)
}

func renderVerifyBlock(sb *strings.Builder, block *DVerifyBlockJSON) {
	if block == nil || len(block.Routes) == 0 {
		return
	}
	cls := "var(--green)"
	if !block.AllPassed {
		cls = "var(--red)"
	}
	sb.WriteString(fmt.Sprintf(`<details open><summary>✅ %s Verification <span style="color:%s;">(%d/%d passed)</span></summary>
<div class="detail-section"><table><tr><th>Route</th><th>Status</th><th>Expected</th><th>Latency</th><th>WAF Action</th><th>Risk</th></tr>`,
		html.EscapeString(block.Phase), cls, block.PassedCount, block.TotalCount))
	for _, vr := range block.Routes {
		sc := "var(--green)"
		if !vr.Passed {
			sc = "var(--red)"
		}
		sb.WriteString(fmt.Sprintf(`<tr>
<td>%s %s</td>
<td style="color:%s;">%d</td>
<td>%d</td>
<td>%.1fms</td>
<td>%s</td>
<td>%d</td>
</tr>`,
			vr.Method, html.EscapeString(vr.Endpoint), sc, vr.StatusCode,
			vr.ExpectedCode, vr.LatencyMs, html.EscapeString(vr.WAFAction), vr.RiskScore))
	}
	sb.WriteString(`</table></div></details>`)
}
