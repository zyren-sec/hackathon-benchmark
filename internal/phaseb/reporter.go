package phaseb

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
)

// GenerateReport writes report_phase_b.html and report_phase_b.json.
func GenerateReport(r *PhaseBResult, outputDir string) error {
	report := buildReport(r)

	jsonPath := filepath.Join(outputDir, "report_phase_b.json")
	if err := writeJSON2(report, jsonPath); err != nil {
		return fmt.Errorf("JSON report: %w", err)
	}
	fmt.Printf("📄 JSON report: %s\n", jsonPath)

	htmlPath := filepath.Join(outputDir, "report_phase_b.html")
	if err := writeHTML2(report, htmlPath); err != nil {
		return fmt.Errorf("HTML report: %w", err)
	}
	fmt.Printf("📄 HTML report: %s\n", htmlPath)

	return nil
}

func buildReport(r *PhaseBResult) PhaseBReport {
	report := PhaseBReport{
		Phase:        "B",
		Timestamp:    r.StartTime.Format("2006-01-02T15:04:05Z07:00"),
		WAFTarget:    r.WAFTarget,
		WAFMode:      r.WAFMode,
		DurationMs:   r.EndTime.Sub(r.StartTime).Milliseconds(),
		PreCheckPassed: r.PreCheckPassed,
		PreCheckAlive: r.PreCheckAlive,
		PreCheckTotal: r.PreCheckTotal,
		PreCheckWarning: !r.PreCheckPassed,
		Scores:       r.Scores,
		TotalScore:   r.TotalScore,
		MaxScore:     r.MaxScore,
	}

	for _, s := range r.ResetSteps {
		report.ResetSequence = append(report.ResetSequence, BResetStepJSON{
			Step: s.StepNum, Name: s.Name, StatusCode: s.StatusCode,
			Success: s.Success, LatencyMs: s.LatencyMs,
		})
	}

	for _, cat := range r.Categories {
		report.Categories = append(report.Categories, BCatSummaryJSON{
			ID: cat.CatID, Name: cat.Name, Criterion: cat.Criterion,
			MaxScore: cat.MaxScore, IPRange: cat.IPRange,
			Passed: cat.PassedCount, Total: cat.TotalCount, Score: cat.Score,
		})
	}

	for _, tr := range r.TestResults {
		entry := BTestEntryJSON{
			TestID: tr.TestID, Name: tr.Name, Category: tr.Category,
			Criterion: tr.Criterion, SourceIP: tr.SourceIP,
			Endpoint: tr.Endpoint, Method: tr.Method,
			Description: tr.Description, PassCriterion: tr.PassCriterion,
			NegativeControl: tr.NegativeControl,
			TotalRequests: tr.TotalRequests, BlockedAt: tr.BlockedAt,
			Passed: tr.Passed, FailReason: tr.FailReason,
			Skipped: tr.Skipped, SkipReason: tr.SkipReason,
			AvgLatencyMs: tr.AvgLatencyMs, MaxLatencyMs: tr.MaxLatencyMs,
			MaxRiskScore: tr.MaxRiskScore, AvgRiskScore: tr.AvgRiskScore,
			RiskBaseline: tr.RiskBaseline, RiskDelta: tr.RiskDelta,
			InterventionPoint: tr.InterventionPoint,
			AuthUsed: tr.AuthUsed, SessionID: tr.SessionID,
			ResetBefore: tr.ResetBefore, ResetType: tr.ResetType,
			F6Violation: tr.F6Violation, F6Details: tr.F6Details,
			EscalationDetected: tr.EscalationDetected,
			DeEscalationDetected: tr.DeEscalationDetected,
			RateLimitMaintained: tr.RateLimitMaintained,
			FirstBlockAt: tr.FirstBlockAt,
			ActionSequenceSummary: tr.ActionSequenceSummary,
			PassConditions: tr.PassConditions,
			FailConditions: tr.FailConditions,
			ChallengeResult: tr.ChallengeResult,
			ReproduceScript: tr.ReproduceScript,
			LeakMarkers: tr.LeakMarkers,
		}
		if tr.Passed {
			entry.Result = "PASS"
		} else if tr.Skipped {
			entry.Result = "SKIP"
		} else {
			entry.Result = "FAIL"
		}

		// Sample requests (first 3, last 3, blocked)
		samples := selectSamples(tr.Requests, tr.BlockedAt)
		for _, req := range samples {
			entry.SampleRequests = append(entry.SampleRequests, BReqSampleJSON{
				Index: req.Index, URL: req.URL, Method: req.Method,
				RequestBody: req.RequestBody, RequestHeaders: req.RequestHeaders,
				StatusCode: req.StatusCode, LatencyMs: req.LatencyMs,
				ResponseBody: req.ResponseBody, ResponseHeaders: req.ResponseHeaders,
				WAFAction: req.WAFAction, RiskScore: req.RiskScore,
				Blocked: req.Blocked, CurlCommand: req.CurlCommand,
			})
		}

		if tr.CanaryResult != nil {
			entry.CanaryResult = &CanaryResultJSON{
				Endpoints: tr.CanaryResult.Endpoints,
				Results: tr.CanaryResult.Results,
				AllBlocked: tr.CanaryResult.AllBlocked,
				FollowUpBlocked: tr.CanaryResult.FollowUpBlocked,
			}
		}
		if tr.NegControlResult != nil {
			entry.NegControlResult = &NegControlResultJSON{
				ExpectedAction: tr.NegControlResult.ExpectedAction,
				ActualAction:   tr.NegControlResult.ActualAction,
				ExpectedStatus: tr.NegControlResult.ExpectedStatus,
				ActualStatus:   tr.NegControlResult.ActualStatus,
				FalsePositive:  tr.NegControlResult.FalsePositive,
				RiskExpected:   tr.NegControlResult.RiskExpected,
				RiskActual:     tr.NegControlResult.RiskActual,
			}
		}
		// Risk progression
		for _, rp := range tr.RiskProgression {
			entry.RiskProgression = append(entry.RiskProgression, RiskProgressionPointJSON{
				Request: rp.Request, Score: rp.Score,
			})
		}
		// Observability
		entry.Observability = &ObservabilityResultJSON{
			HeadersUsed:    tr.Observability.HeadersUsed,
			HeadersMissing: tr.Observability.HeadersMissing,
			Score:          tr.Observability.Score,
		}
		report.Tests = append(report.Tests, entry)
	}

	return report
}

func selectSamples(reqs []BRequestResult, blockedAt int) []BRequestResult {
	if len(reqs) == 0 {
		return nil
	}
	seen := make(map[int]bool)
	var samples []BRequestResult

	add := func(i int) {
		if i >= 0 && i < len(reqs) && !seen[i] {
			samples = append(samples, reqs[i])
			seen[i] = true
		}
	}

	// First 3
	for i := 0; i < 3 && i < len(reqs); i++ {
		add(i)
	}
	// Last 3
	for i := len(reqs) - 3; i < len(reqs); i++ {
		add(i)
	}
	// Blocked/intervention point
	if blockedAt > 0 && blockedAt <= len(reqs) {
		add(blockedAt - 1)
	}

	return samples
}

func writeJSON2(report PhaseBReport, path string) error {
	os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func writeHTML2(report PhaseBReport, path string) error {
	os.MkdirAll(filepath.Dir(path), 0755)
	safeJSON, _ := json.Marshal(report)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF Benchmark — Phase B: Abuse Detection Report</title>
<style>
:root{--bg:#0b1120;--card:#111827;--card2:#1a2332;--text:#e2e8f0;--muted:#94a3b8;--subtle:#64748b;--green:#22c55e;--red:#ef4444;--yellow:#eab308;--blue:#3b82f6;--purple:#8b5cf6;--orange:#f97316;--border:#1e293b;--border2:#334155;--code-bg:#0f172a;--pre-bg:#0f172a}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);line-height:1.7;padding:0}
.container{max-width:1400px;margin:0 auto;padding:20px 24px 60px}
.main-header{background:linear-gradient(135deg,var(--card),var(--card2));border:1px solid var(--border);border-radius:16px;padding:28px 32px;margin-bottom:24px}
.main-header h1{font-size:1.6rem;font-weight:700;margin-bottom:4px}
.main-header .subtitle{color:var(--muted);font-size:.85rem;margin-bottom:16px}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
.meta-item{display:flex;flex-direction:column}
.meta-item .lbl{font-size:.7rem;color:var(--subtle);text-transform:uppercase;letter-spacing:.05em}
.meta-item .val{font-size:.95rem;font-weight:600;word-break:break-all}
.score-card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:24px 28px;margin-bottom:24px}
.score-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-top:12px}
.score-item{background:var(--card2);border:1px solid var(--border2);border-radius:10px;padding:14px 16px;text-align:center}
.score-item .crit{font-size:.7rem;color:var(--subtle);text-transform:uppercase;letter-spacing:.04em}
.score-item .val{font-size:1.6rem;font-weight:800;color:var(--blue);margin:4px 0}
.score-item .max{font-size:.75rem;color:var(--muted)}
.score-total{grid-column:1/-1;text-align:center;padding:16px;background:rgba(139,92,246,.08);border:1px solid rgba(139,92,246,.2);border-radius:10px}
.score-total .val{font-size:2rem;font-weight:800;color:var(--purple)}
.section{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:20px 28px;margin-bottom:24px}
.section h2{font-size:1.25rem;color:var(--blue);margin-bottom:16px}
.reset-steps{display:flex;flex-direction:column;gap:6px}
.reset-step{display:flex;align-items:center;gap:10px;padding:6px 0;font-family:monospace;font-size:.85rem}
.reset-step .ok{color:var(--green);font-weight:700}
.reset-step .fail{color:var(--red);font-weight:700}
.step-num{color:var(--subtle);min-width:40px}
.table-wrap{overflow-x:auto}
table{width:100%%;border-collapse:collapse;font-size:.9rem}
th{text-align:left;padding:10px 12px;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;color:var(--subtle);background:rgba(0,0,0,.2);border-bottom:1px solid var(--border2)}
td{padding:8px 12px;border-bottom:1px solid var(--border)}
tr:hover{background:rgba(255,255,255,.02)}
.cat-row{background:rgba(59,130,246,.06)}
.cat-row td{font-weight:600;color:var(--blue);padding:12px}
.badge{display:inline-block;padding:2px 10px;border-radius:4px;font-size:.72rem;font-weight:700;letter-spacing:.03em}
.badge-pass{background:rgba(34,197,94,.15);color:var(--green)}
.badge-fail{background:rgba(239,68,68,.15);color:var(--red)}
.badge-skip{background:rgba(148,163,184,.15);color:var(--muted)}
.vuln-card{background:var(--card2);border:1px solid var(--border2);border-radius:12px;margin:16px 0;overflow:hidden}
.vuln-card-header{display:flex;align-items:center;gap:12px;padding:14px 20px;background:rgba(0,0,0,.15);cursor:pointer;user-select:none;border-bottom:1px solid transparent}
.vuln-card-header:hover{background:rgba(255,255,255,.03)}
.vuln-id{font-weight:800;font-size:1rem;min-width:46px}
.vuln-name{font-weight:600;flex:1}
.vuln-card-body{display:none;padding:0}
.vuln-card.open .vuln-card-header{border-bottom-color:var(--border2)}
.vuln-card.open .vuln-card-body{display:block}
.vuln-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px;padding:16px 20px;font-size:.85rem;border-bottom:1px solid var(--border)}
.vuln-meta .ml{color:var(--subtle)}
.vuln-meta .mv{font-weight:600}
.perf-row{display:flex;gap:12px;flex-wrap:wrap;margin:12px 20px;font-size:.82rem}
.perf-item{padding:6px 14px;border-radius:6px;background:rgba(0,0,0,.2);display:flex;align-items:center;gap:6px}
.perf-item .pl{color:var(--subtle)}
.perf-item .pv{font-weight:700;font-family:monospace}
details{margin:8px 20px;border:1px solid var(--border);border-radius:8px;background:var(--code-bg);overflow:hidden}
details summary{padding:10px 16px;cursor:pointer;font-size:.82rem;font-weight:600;color:var(--blue);background:rgba(59,130,246,.06);user-select:none;list-style:none}
details summary::before{content:'▶ ';font-size:.7rem;margin-right:6px}
details[open] summary::before{content:'▼ '}
details summary:hover{background:rgba(59,130,246,.1)}
pre{margin:0;padding:14px 16px;font-family:monospace;font-size:.78rem;line-height:1.5;overflow-x:auto;background:var(--pre-bg);color:var(--text);white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto}
pre.curl{border-left:3px solid var(--orange);color:#fcd34d}
.method-g{color:var(--green)}.method-p{color:var(--blue)}.method-u{color:var(--orange)}.method-d{color:var(--red)}.method-o{color:var(--purple)}
.canary-table{margin:8px 20px}.canary-table th{font-size:.78rem}.canary-table td{font-size:.82rem}
.fail-reason{margin:8px 20px;padding:10px 16px;background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.2);border-radius:8px;font-size:.85rem;color:var(--red)}
.leak-marker{margin:8px 20px;padding:8px 14px;background:rgba(234,179,8,.08);border:1px solid rgba(234,179,8,.2);border-radius:6px;font-size:.82rem;color:var(--yellow);font-family:monospace}
.cond-row{margin:4px 20px;display:flex;align-items:flex-start;gap:12px;font-size:.82rem;flex-wrap:wrap}
.cond-list{display:flex;gap:6px;flex-wrap:wrap}
.cond-pass{color:var(--green);background:rgba(34,197,94,.1);padding:2px 8px;border-radius:4px;font-weight:600;font-size:.78rem}
.cond-fail{color:var(--red);background:rgba(239,68,68,.1);padding:2px 8px;border-radius:4px;font-weight:600;font-size:.78rem}
.neg-ctrl-table{font-size:.8rem;border-collapse:collapse;margin:4px 0}
.neg-ctrl-table td{padding:2px 10px;border-bottom:1px solid var(--border2)}
.neg-ctrl-table td:first-child{color:var(--subtle);font-weight:600}
.methodology-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-top:12px}
.method-card{background:var(--code-bg);border:1px solid var(--border);border-radius:10px;padding:14px 18px}
.method-card h4{font-size:.9rem;color:var(--blue);margin-bottom:6px}
.method-card p,.method-card code{font-size:.82rem;color:var(--muted);line-height:1.6}
.method-card code{background:rgba(255,255,255,.06);padding:1px 6px;border-radius:3px;font-size:.8rem}
.footer{text-align:center;padding:32px;color:var(--subtle);font-size:.8rem;border-top:1px solid var(--border);margin-top:32px}
@media(max-width:768px){.container{padding:12px}.score-grid{grid-template-columns:1fr 1fr}.meta-grid{grid-template-columns:1fr}.vuln-meta{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div class="container">
<div class="main-header">
<h1>🛡️ WAF Benchmark — Phase B: Abuse Detection Tests</h1>
<p class="subtitle">Comprehensive Behavioral & Anomaly Detection Report — v2.5</p>
<div class="meta-grid">
<div class="meta-item"><span class="lbl">Timestamp</span><span class="val">%s</span></div>
<div class="meta-item"><span class="lbl">WAF Target</span><span class="val">%s</span></div>
<div class="meta-item"><span class="lbl">WAF Mode</span><span class="val">%s</span></div>
<div class="meta-item"><span class="lbl">Duration</span><span class="val">%.1fs</span></div>
<div class="meta-item"><span class="lbl">Categories</span><span class="val">%d</span></div>
<div class="meta-item"><span class="lbl">Total Tests</span><span class="val">%d</span></div>
</div>
</div>

<div class="score-card">
<h3 style="margin-bottom:12px;">📊 Phase B — Scoring Dashboard</h3>
<div class="score-grid">
%s
<div class="score-total"><div class="crit">TOTAL SCORE</div><div class="val">%.2f<span style="font-size:.9rem;color:var(--muted)">/%.0f</span></div></div>
</div>
</div>

<div class="section"><h2>🔍 Pre-check: Proxy Health Gate</h2>
<p style="font-size:.9rem;color:var(--muted);">Proxies tested: <strong>%d/%d alive</strong> — %s</p>
</div>

<div class="section"><h2>🔄 Full Reset Sequence</h2><div class="reset-steps">%s</div></div>

<div class="section"><h2>📊 Category Results</h2><div class="table-wrap"><table>
<thead><tr><th>#</th><th>Category</th><th>Criterion</th><th>Max Pts</th><th>IP Range</th><th>Passed/Total</th><th>Score</th></tr></thead>
<tbody>%s</tbody></table></div></div>

<div class="section"><h2>📐 Scoring Methodology (§6)</h2><div class="methodology-grid">
%s
</div></div>

%s

%s

<div class="section"><h2>📋 Test Details — Abuse Detection Results</h2>
<p style="color:var(--muted);font-size:.85rem;margin-bottom:16px;">Click any test to expand. Each test shows sample requests with curl commands for reproduction.</p>
%s
</div>

<div class="footer">
<p>WAF Benchmark Tool v2.5 — Phase B: Abuse Detection Tests</p>
<p style="margin-top:4px;">Report generated for <strong>%s</strong></p>
<p style="margin-top:8px;font-size:.75rem;">Spec: docs/hackathon/workflow/phase_B.md</p>
</div>
</div>
<script>
document.querySelectorAll('.vuln-card-header').forEach(function(h){h.addEventListener('click',function(){this.parentElement.classList.toggle('open')})});
window.PHASE_B_REPORT = %s;
</script>
</body></html>`,
		report.Timestamp, report.WAFTarget, report.WAFMode,
		float64(report.DurationMs)/1000.0, len(report.Categories), len(report.Tests),
		buildScoreGridHTML(report),
		report.TotalScore, report.MaxScore,
		report.PreCheckAlive, report.PreCheckTotal,
		map[bool]string{true: "PASS ✓", false: "FAIL ✗ (continuing with loopback)"}[report.PreCheckPassed],
		buildBResetHTML(report.ResetSequence),
		buildBCatSummaryHTML(report.Categories),
		buildMethodologyHTML(),
		buildPassFailLegendHTML(),
		buildSkipRulesHTML(),
		buildBTestCards(report.Tests)+buildSEC02HTML(report),
		html.EscapeString(report.WAFTarget),
		safeJSON,
	)

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(html)
	return err
}

func buildScoreGridHTML(r PhaseBReport) string {
	criteria := []struct{ id, name string; max float64 }{
		{"SEC-03", "Abuse Detection", 10.0},
		{"SEC-04", "Canary Detection", 2.0},
		{"INT-01", "Transaction Fraud", 4.0},
		{"INT-02", "Behavioral Anomaly", 4.0},
		{"INT-03", "Relay Detection", 4.0},
	}
	var items []string
	for _, c := range criteria {
		score := r.Scores[c.id]
		color := "var(--green)"
		if score < c.max*0.5 {
			color = "var(--red)"
		} else if score < c.max*0.8 {
			color = "var(--yellow)"
		}
		items = append(items, fmt.Sprintf(
			`<div class="score-item"><div class="crit">%s — %s</div><div class="val" style="color:%s">%.2f</div><div class="max">/ %.0f</div></div>`,
			c.id, c.name, color, score, c.max))
	}
	return strings.Join(items, "\n")
}

func buildBResetHTML(steps []BResetStepJSON) string {
	var lines []string
	for _, s := range steps {
		cls, icon := "ok", "✓"
		if !s.Success {
			cls, icon = "fail", "✗"
		}
		lines = append(lines, fmt.Sprintf(
			`<div class="reset-step"><span class="step-num">[%d/5]</span><span class="%s">%s</span> %s — HTTP %d (%.3fms)</div>`,
			s.Step, cls, icon, html.EscapeString(s.Name), s.StatusCode, s.LatencyMs))
	}
	return strings.Join(lines, "\n")
}

func buildBCatSummaryHTML(cats []BCatSummaryJSON) string {
	var rows []string
	for i, c := range cats {
		pct := 0.0
		if c.Total > 0 {
			pct = float64(c.Passed) / float64(c.Total) * 100
		}
		rows = append(rows, fmt.Sprintf(
			`<tr class="cat-row"><td>%d</td><td>%s</td><td>%s</td><td>%.0f</td><td>%s</td><td>%d/%d</td><td>%.0f%%</td></tr>`,
			i+1, html.EscapeString(c.Name), c.Criterion, c.MaxScore, c.IPRange, c.Passed, c.Total, pct))
	}
	return strings.Join(rows, "\n")
}

// buildSkipRulesHTML documents skip rules and denominator behavior per §6.2.
func buildSkipRulesHTML() string {
	return `<div class="section"><h2>⏭️ Skip Rules &amp; Denominator Behavior (§6.2)</h2>
<div style="font-size:.85rem;color:var(--muted);line-height:1.8;">
<p><b>When a test is skipped</b> (e.g. proxy unreachable, WAF headers missing → F1), the denominator for its criterion decreases so the skipped test does not penalise the score:</p>
<table style="font-size:.82rem;margin-top:8px;"><thead><tr><th>Criterion</th><th>Base Denominator</th><th>Dynamic Formula</th></tr></thead><tbody>
<tr><td><b>SEC-03</b></td><td>6 (AB×3 + RE×3)</td><td><code>denom = 6 − skip_AB − skip_RE (min 1)</code></td></tr>
<tr><td><b>SEC-04</b></td><td>1 (RE04)</td><td><code>skip_canary → score = 0</code></td></tr>
<tr><td><b>INT-01</b></td><td>4 (TF×4)</td><td><code>denom = 4 − skip_TF (min 1)</code></td></tr>
<tr><td><b>INT-02</b></td><td>5 (BA×5)</td><td><code>denom = 5 − skip_BA (min 1)</code></td></tr>
<tr><td><b>INT-03</b></td><td>4 (AR×4)</td><td><code>denom = 4 − skip_AR (min 1)</code> <span style="font-size:0.7rem;color:var(--muted);">(v2.9: AR04/AR05 removed)</span></td></tr>
</tbody></table>
<p style="margin-top:12px;"><b>Skip triggers:</b> F1 (missing required WAF headers), proxy timeout, upstream unhealthy, WAF control endpoint error. Skipped tests show <span style="color:var(--yellow);">SKIP ⚠</span> in results.</p><p style="margin-top:4px;font-size:0.8rem;color:var(--muted);"><b>v2.9 Note:</b> AR04 (Tor exit nodes) and AR05 (datacenter IPs) removed — loopback fallback defeats threat intel detection purpose.</p>
</div></div>`
}

// buildSEC02HTML adds the SEC-02 cross-phase outbound filtering summary.
func buildSEC02HTML(report PhaseBReport) string {
	// Note: Full SEC-02 is computed by crossphase package.
	// This section shows the mapping since full response data lives in crossphase.
	_ = report
	return `<div class="section"><h2>🔗 SEC-02 Cross-Phase Contributions (§6.3)</h2>
<div style="font-size:.85rem;color:var(--muted);line-height:1.8;">
<p>Phase B contributes response bodies to the global outbound filtering pool (cross_phase.md §4.2). Key leak markers monitored:</p>
<table style="font-size:.82rem;margin-top:8px;"><thead><tr><th>Marker</th><th>Source</th><th>Description</th></tr></thead><tbody>
<tr><td><code>__L01_STACKTRACE__</code></td><td>RE03 (500 error responses)</td><td>Stack traces in error pages</td></tr>
<tr><td><code>__L03_DEBUG_SQL__</code></td><td>All responses</td><td>Debug SQL in response headers/bodies</td></tr>
<tr><td><code>__L04_PII__</code></td><td>BA03/BA04/BA05 (profile responses)</td><td>PII in profile/transaction data</td></tr>
<tr><td><code>__L05_VERBOSE_404__</code></td><td>RE01 (404 responses)</td><td>Verbose 404 with internal paths</td></tr>
</tbody></table>
<p style="margin-top:12px;"><b>Formula:</b> <code>SEC-02 = 5 × count(clean) / count(total_all_phases)</code></p>
<p style="color:var(--subtle);font-size:.78rem;">Full SEC-02 breakdown is available in <code>report_cross_phase.json</code> and the terminal output.</p>
</div></div>`
}

func buildMethodologyHTML() string {
	cards := []struct{ title, desc string }{
		{"SEC-03: Abuse Detection (10 pts)", "<code>10 × (pass_AB + pass_RE) / (6 − skip_count)</code><br>AB01-AB03: Brute force login ≤10 attempts, credential stuffing ≤20 pairs, password spraying ≤15 users.<br>RE01-RE03: Path enumeration ≤50 requests, OPTIONS abuse rate-limit, error harvesting (no L01 stack traces)."},
		{"SEC-04: Canary Detection (2 pts)", "<code>2 × (RE04 all-or-nothing)</code><br>RE04 probes 4 canary endpoints. All 4 must return 403 AND follow-up request from same IP must also be blocked (IP locked). All-or-nothing binary."},
		{"INT-01: Transaction Fraud (4 pts)", "<code>4 × pass_TF / (4 − skip_count)</code><br>TF01-TF04: Rush deposit (3× in &lt;5s), instant withdrawal (&lt;3s after deposit), limit change + large withdrawal, multi-account device (5 users from same IP)."},
		{"INT-02: Behavioral Anomaly (4 pts)", "<code>4 × pass_BA / (5 − skip_count)</code><br>BA01-BA05: Zero-depth session (POST /login directly), uniform timing bot (100ms intervals), missing Referer, sub-50ms cadence (rate-limit maintained), spoofed Referer."},
		{"INT-03: Relay Detection (4 pts)", "<code>4 × pass_AR / (6 − skip_count)</code><br>AR01-AR06: XFF matches source (negative control), XFF spoofed, XFF multi-hop (3+), Tor exit node, datacenter IP, clean IP (negative control). 2 negative controls."},
	}
	var items []string
	for _, c := range cards {
		items = append(items, fmt.Sprintf(`<div class="method-card"><h4>%s</h4><p>%s</p></div>`, c.title, c.desc))
	}
	return strings.Join(items, "\n")
}

// buildPassFailLegendHTML builds the PASS/FAIL criteria legend per phase_B.md §5.
func buildPassFailLegendHTML() string {
	return `<div class="section"><h2>🔍 PASS / FAIL Criteria (phase_B.md §5)</h2>
<div style="font-size:.85rem;line-height:1.7;">

<div style="margin-bottom:16px;">
<h4 style="color:var(--green);margin-bottom:6px;">✅ PASS Conditions — all of the following must be met for a test to pass</h4>
<table style="width:100%;font-size:.82rem;border-collapse:collapse;"><tbody>
<tr style="border-bottom:1px solid var(--border2);"><td style="padding:5px 10px;font-weight:700;color:var(--green);min-width:36px;">P1</td><td style="padding:5px 10px;">All 6 required WAF headers present: <code>X-WAF-Request-Id</code>, <code>X-WAF-Risk-Score</code>, <code>X-WAF-Action</code>, <code>X-WAF-Rule-Id</code>, <code>X-WAF-Cache</code>, <code>X-WAF-Mode</code></td></tr>
<tr style="border-bottom:1px solid var(--border2);"><td style="padding:5px 10px;font-weight:700;color:var(--green);">P2</td><td style="padding:5px 10px;"><code>X-WAF-Action</code> in acceptable set for the threat category</td></tr>
<tr style="border-bottom:1px solid var(--border2);"><td style="padding:5px 10px;font-weight:700;color:var(--green);">P3</td><td style="padding:5px 10px;">WAF intervenes BEFORE threshold — AB01 ≤10 attempts, AB02 ≤20 pairs, AB03 ≤15 users, BA02 ≤60 requests, RE01 ≤50 requests</td></tr>
<tr style="border-bottom:1px solid var(--border2);"><td style="padding:5px 10px;font-weight:700;color:var(--green);">P4</td><td style="padding:5px 10px;">Risk score increases OR action in acceptable set — applies to BA03, TF01–TF04, AR02–AR03, AR06, BA01, BA05, RE03, RE04</td></tr>
<tr style="border-bottom:1px solid var(--border2);"><td style="padding:5px 10px;font-weight:700;color:var(--green);">P5</td><td style="padding:5px 10px;">Negative control NOT blocked: <code>X-WAF-Action: allow</code> when expected — AR01, AR06</td></tr>
</tbody></table>
</div>

<div>
<h4 style="color:var(--red);margin-bottom:6px;">❌ FAIL Conditions — any single condition triggers FAIL</h4>
<table style="width:100%;font-size:.82rem;border-collapse:collapse;"><tbody>
<tr style="border-bottom:1px solid var(--border2);"><td style="padding:5px 10px;font-weight:700;color:var(--red);min-width:36px;">F1</td><td style="padding:5px 10px;">Missing or incomplete required WAF headers → test is <b>SKIPPED</b> (cannot classify)</td></tr>
<tr style="border-bottom:1px solid var(--border2);"><td style="padding:5px 10px;font-weight:700;color:var(--red);">F2</td><td style="padding:5px 10px;"><code>X-WAF-Action</code> not in acceptable set for threat category</td></tr>
<tr style="border-bottom:1px solid var(--border2);"><td style="padding:5px 10px;font-weight:700;color:var(--red);">F3</td><td style="padding:5px 10px;">Negative control blocked (false positive) — AR01, AR06</td></tr>
<tr style="border-bottom:1px solid var(--border2);"><td style="padding:5px 10px;font-weight:700;color:var(--red);">F4</td><td style="padding:5px 10px;">Threshold not met — WAF did not react within allowed attempts</td></tr>
<tr style="border-bottom:1px solid var(--border2);"><td style="padding:5px 10px;font-weight:700;color:var(--red);">F5</td><td style="padding:5px 10px;">Risk score did not increase when expected</td></tr>
<tr><td style="padding:5px 10px;font-weight:700;color:var(--red);">F6</td><td style="padding:5px 10px;">Action flip-flop — after blocking, subsequent request returns <code>allow</code> (200) or de-escalation (403→429). <i>Exception: BA04/RE02 only accept 429→429; escalation (429→403) is OK for other tests.</i></td></tr>
</tbody></table>
</div>

</div></div>`
}

func buildBTestCards(tests []BTestEntryJSON) string {
	var cards []string
	for _, t := range tests {
		cards = append(cards, buildBTestCard(t))
	}
	return strings.Join(cards, "\n")
}

func buildBTestCard(t BTestEntryJSON) string {
	badgeCls, icon := "badge-pass", "✅"
	if t.Result == "FAIL" {
		badgeCls, icon = "badge-fail", "❌"
	} else if t.Result == "SKIP" {
		badgeCls, icon = "badge-skip", "⏭️"
	}
	openAttr := ""
	if t.Result == "FAIL" {
		openAttr = " open"
	}

	methodClass := "method-g"
	switch t.Method {
	case "POST": methodClass = "method-p"
	case "PUT": methodClass = "method-u"
	case "DELETE": methodClass = "method-d"
	case "OPTIONS": methodClass = "method-o"
	}

	negTag := ""
	if t.NegativeControl {
		negTag = ` <span style="color:var(--yellow);font-size:.75rem;">(Negative Control)</span>`
	}

	perfHTML := fmt.Sprintf(`<div class="perf-row">
<div class="perf-item"><span class="pl">📊 Requests:</span><span class="pv">%d</span></div>
<div class="perf-item"><span class="pl">🎯 Blocked At:</span><span class="pv">%d</span></div>
<div class="perf-item"><span class="pl">⏱️ Avg Latency:</span><span class="pv">%.3fms</span></div>
<div class="perf-item"><span class="pl">📈 Max Risk:</span><span class="pv">%d</span></div>
<div class="perf-item"><span class="pl">Δ Risk:</span><span class="pv">+%d</span></div>
</div>`, t.TotalRequests, t.BlockedAt, t.AvgLatencyMs, t.MaxRiskScore, t.RiskDelta)

	samplesHTML := ""
	for _, req := range t.SampleRequests {
		blockedTag := ""
		if req.Blocked {
			blockedTag = ` <span style="color:var(--red);">BLOCKED</span>`
		}
		curlContent := html.EscapeString(req.CurlCommand)
		respHeadersHTML := formatResponseHeadersHTML(req)
		samplesHTML += fmt.Sprintf(`
<details><summary>#%d — <span class="%s">%s</span> %s — HTTP %d (Risk: %d) %.3fms%s</summary>
<pre class="curl">%s</pre>%s
</details>`, req.Index, methodClass, req.Method, html.EscapeString(req.URL), req.StatusCode, req.RiskScore, req.LatencyMs, blockedTag, curlContent, respHeadersHTML)
	}

	failHTML := ""
	if t.FailReason != "" {
		failHTML = fmt.Sprintf(`<div class="fail-reason">❌ FAIL Reason: %s</div>`, html.EscapeString(t.FailReason))
	}

	leakHTML := ""
	for _, lm := range t.LeakMarkers {
		leakHTML += fmt.Sprintf(`<div class="leak-marker">⚠️ Leak Marker Found: <code>%s</code></div>`, html.EscapeString(lm))
	}

	canaryHTML := ""
	if t.CanaryResult != nil {
		canaryHTML += `<div class="canary-table"><table style="max-width:500px;"><thead><tr><th>Endpoint</th><th>Status</th></tr></thead><tbody>`
		for _, ep := range t.CanaryResult.Endpoints {
			status := t.CanaryResult.Results[ep]
			statusCls := "var(--green)"
			if status != 403 {
				statusCls = "var(--red)"
			}
			canaryHTML += fmt.Sprintf(`<tr><td style="font-family:monospace;">%s</td><td style="color:%s;font-weight:700;">%d</td></tr>`, html.EscapeString(ep), statusCls, status)
		}
		canaryHTML += `</tbody></table>`
		followCls := "var(--green)"
		if !t.CanaryResult.FollowUpBlocked {
			followCls = "var(--red)"
		}
		canaryHTML += fmt.Sprintf(`<div style="padding:8px 0;font-size:.85rem;">Follow-up: <span style="color:%s;font-weight:700;">%s</span></div></div>`,
			followCls, map[bool]string{true: "403 (IP locked)", false: "NOT locked"}[t.CanaryResult.FollowUpBlocked])
	}

	return fmt.Sprintf(`
<div class="vuln-card%s">
<div class="vuln-card-header">
<span>%s</span><span class="vuln-id">%s</span><span class="vuln-name">%s</span>%s
<span class="badge %s" style="margin-left:auto;">%s</span>
</div>
<div class="vuln-card-body">
<div class="vuln-meta">
<div><span class="ml">Category:</span><span class="mv">%s</span></div>
<div><span class="ml">Criterion:</span><span class="mv">%s</span></div>
<div><span class="ml">Source IP:</span><span class="mv" style="font-family:monospace;">%s</span></div>
<div><span class="ml">Auth:</span><span class="mv">%s</span></div>
<div><span class="ml">Reset:</span><span class="mv">%s</span></div>
<div><span class="ml">Endpoint:</span><span class="mv" style="font-family:monospace;">%s <span class="%s">%s</span></span></div>
<div style="grid-column:1/-1;"><span class="ml">Description:</span><span class="mv">%s</span></div>
<div style="grid-column:1/-1;"><span class="ml">Pass Criterion:</span><span class="mv" style="white-space:nowrap;">%s</span></div>
</div>
%s
%s%s%s%s%s%s%s
<details open><summary>📋 Sample Requests (%d total)</summary>%s</details>
%s%s%s%s
</div></div>`,
		openAttr, icon, t.TestID, html.EscapeString(t.Name), negTag, badgeCls, t.Result,
		html.EscapeString(t.Category), t.Criterion, t.SourceIP,
		formatAuthHTML(t), formatResetHTML(t),
		t.Endpoint, methodClass, t.Method,
		html.EscapeString(t.Description), html.EscapeString(t.PassCriterion),
		perfHTML,
		formatConditionsHTML(t), formatRiskProgressionHTML(t),
		formatPersistenceHTML(t), formatRateLimitHTML(t), formatObservabilityHTML(t), formatNegControlHTML(t),
		formatChallengeHTML(t),
		len(t.SampleRequests), samplesHTML,
		failHTML, leakHTML, canaryHTML, formatReproduceHTML(t),
	)
}

// ── PASS/FAIL Condition Helpers (§5) ──

func formatConditionsHTML(t BTestEntryJSON) string {
	if len(t.PassConditions) == 0 && len(t.FailConditions) == 0 {
		return ""
	}
	descMap := map[string]string{
		"P1": "All 6 WAF headers present",
		"P2": "X-WAF-Action in acceptable set",
		"P3": "WAF blocked before threshold",
		"P4": "Risk score increased / action valid",
		"P5": "Negative control NOT blocked",
		"F1": "Missing required WAF headers → SKIP",
		"F2": "X-WAF-Action not in acceptable set",
		"F3": "Negative control blocked (false positive)",
		"F4": "Threshold not met — no WAF reaction within limit",
		"F5": "Risk score did not increase when expected",
		"F6": "Action flip-flop — block/rate-limit not maintained",
	}
	var condParts []string
	for _, pc := range t.PassConditions {
		desc := pc
		if d, ok := descMap[pc]; ok {
			desc = pc + ": " + d
		}
		condParts = append(condParts, fmt.Sprintf(`<span class="cond-pass">✅ %s</span>`, html.EscapeString(desc)))
	}
	for _, fc := range t.FailConditions {
		desc := fc
		if d, ok := descMap[fc]; ok {
			desc = fc + ": " + d
		}
		condParts = append(condParts, fmt.Sprintf(`<span class="cond-fail">❌ %s</span>`, html.EscapeString(desc)))
	}
	return fmt.Sprintf(`<div class="cond-row"><span class="pl">🔍 Conditions:</span><div class="cond-list">%s</div></div>`,
		strings.Join(condParts, " "))
}

func formatPersistenceHTML(t BTestEntryJSON) string {
	if t.F6Details == "" && t.ActionSequenceSummary == "" {
		return ""
	}
	f6Color := "var(--green)"
	f6Icon := "✅"
	if t.F6Violation {
		f6Color = "var(--red)"
		f6Icon = "❌ FLIP-FLOP"
	} else if t.DeEscalationDetected {
		f6Color = "var(--red)"
		f6Icon = "❌ DE-ESCALATION"
	} else if t.EscalationDetected {
		f6Color = "var(--yellow)"
		f6Icon = "⚠️ ESCALATION"
	}
	summaryHTML := ""
	if t.ActionSequenceSummary != "" {
		summaryHTML = fmt.Sprintf(`<div style="font-family:monospace;font-size:.78rem;color:var(--muted);margin-top:4px;">Sequence: <code style="color:var(--blue);">%s</code></div>`,
			html.EscapeString(t.ActionSequenceSummary))
	}
	return fmt.Sprintf(`<div class="cond-row"><span class="pl">🔒 Action Persistence (F6):</span><span style="color:%s;font-size:.82rem;">%s %s</span>%s</div>`,
		f6Color, f6Icon, html.EscapeString(t.F6Details), summaryHTML)
}

func formatRateLimitHTML(t BTestEntryJSON) string {
	if t.TestID != "BA04" && t.TestID != "RE02" {
		return ""
	}
	rlColor := "var(--green)"
	rlIcon := "✅"
	rlText := "429 maintained throughout burst"
	if !t.RateLimitMaintained {
		rlColor = "var(--red)"
		rlIcon = "❌"
		rlText = "Rate-limit NOT maintained"
	}
	return fmt.Sprintf(`<div class="cond-row"><span class="pl">⚡ Rate-Limit Maintenance:</span><span style="color:%s;font-size:.82rem;">%s %s</span></div>`,
		rlColor, rlIcon, rlText)
}

func formatRiskProgressionHTML(t BTestEntryJSON) string {
	if len(t.RiskProgression) == 0 {
		return ""
	}
	maxScore := 1
	for _, p := range t.RiskProgression {
		if p.Score > maxScore {
			maxScore = p.Score
		}
	}
	var bars []string
	for _, p := range t.RiskProgression {
		pct := 0
		if maxScore > 0 {
			pct = p.Score * 100 / maxScore
		}
		if pct < 3 {
			pct = 3
		}
		barColor := "var(--blue)"
		if p.Score >= 70 {
			barColor = "var(--red)"
		} else if p.Score >= 40 {
			barColor = "var(--yellow)"
		}
		bars = append(bars, fmt.Sprintf(
			`<div style="flex:1;min-width:28px;text-align:center;font-size:.65rem;">
<div style="font-weight:600;color:var(--muted);">%d</div>
<div style="height:4px;background:var(--border2);border-radius:2px;margin:3px 0;position:relative;">
<div style="height:4px;width:%d%%;background:%s;border-radius:2px;min-width:3px;"></div>
</div>
<div style="color:var(--subtle);">#%d</div>
</div>`, p.Score, pct, barColor, p.Request))
	}
	return fmt.Sprintf(`<div class="cond-row" style="align-items:stretch;"><span class="pl">📈 Risk:</span><div style="display:flex;align-items:flex-end;gap:2px;flex:1;min-width:200px;">%s</div></div>`,
		strings.Join(bars, ""))
}

func formatObservabilityHTML(t BTestEntryJSON) string {
	if t.Observability == nil {
		return ""
	}
	usedHTML := ""
	for _, h := range t.Observability.HeadersUsed {
		usedHTML += fmt.Sprintf(`<span class="cond-pass" style="font-size:.72rem;">✅ %s</span>`, html.EscapeString(h))
	}
	missingHTML := ""
	for _, h := range t.Observability.HeadersMissing {
		missingHTML += fmt.Sprintf(`<span class="cond-fail" style="font-size:.72rem;">❌ %s</span>`, html.EscapeString(h))
	}
	return fmt.Sprintf(`<div class="cond-row"><span class="pl">🔭 Observability (%.0f/6):</span><div class="cond-list">%s%s</div></div>`,
		t.Observability.Score*6, usedHTML, missingHTML)
}

func formatResponseHeadersHTML(req BReqSampleJSON) string {
	wafHeaders := []string{"X-Waf-Request-Id", "X-Waf-Risk-Score", "X-Waf-Action", "X-Waf-Rule-Id", "X-Waf-Cache", "X-Waf-Mode"}
	var found []string
	for _, h := range wafHeaders {
		if v, ok := req.ResponseHeaders[h]; ok {
			found = append(found, fmt.Sprintf(`<span style="color:var(--green);">%s: %s</span>`, html.EscapeString(h), html.EscapeString(v)))
		}
	}
	if len(found) == 0 {
		return ""
	}
	return fmt.Sprintf(`<div style="font-size:.72rem;color:var(--muted);margin-top:4px;">%s</div>`, strings.Join(found, " | "))
}

func formatNegControlHTML(t BTestEntryJSON) string {
	if t.NegControlResult == nil {
		return ""
	}
	fpColor := "var(--green)"
	fpText := "No — PASS ✓"
	if t.NegControlResult.FalsePositive {
		fpColor = "var(--red)"
		fpText = "YES — FALSE POSITIVE ✗"
	}
	return fmt.Sprintf(`<div class="cond-row" style="margin-top:8px;">
<span class="pl">🎯 Negative Control Result:</span>
<table class="neg-ctrl-table"><tbody>
<tr><td>Expected:</td><td style="font-family:monospace;">Action=<code>%s</code> Status=<code>%d</code> Risk=<code>%d</code></td></tr>
<tr><td>Actual:</td><td style="font-family:monospace;">Action=<code>%s</code> Status=<code>%d</code> Risk=<code>%d</code></td></tr>
<tr><td>False Positive:</td><td style="color:%s;font-weight:700;">%s</td></tr>
</tbody></table></div>`,
		html.EscapeString(t.NegControlResult.ExpectedAction), t.NegControlResult.ExpectedStatus, t.NegControlResult.RiskExpected,
		html.EscapeString(t.NegControlResult.ActualAction), t.NegControlResult.ActualStatus, t.NegControlResult.RiskActual,
		fpColor, fpText)
}

func formatAuthHTML(t BTestEntryJSON) string {
	if t.AuthUsed {
		return fmt.Sprintf(`<span style="color:var(--green);">✅ Yes</span> <code style="font-size:0.75rem;">sid=%s</code>`, html.EscapeString(t.SessionID))
	}
	return `<span style="color:var(--text-dim);">❌ No — Session: N/A</span>`
}

func formatResetHTML(t BTestEntryJSON) string {
	if t.ResetBefore {
		return fmt.Sprintf(`<span style="color:var(--yellow);">⚠️ Yes</span> <span style="font-size:0.75rem;">(%s)</span>`, html.EscapeString(t.ResetType))
	}
	return `<span style="color:var(--text-dim);">No (same category)</span>`
}

func formatChallengeHTML(t BTestEntryJSON) string {
	if t.ChallengeResult == nil || !t.ChallengeResult.Encountered {
		return ""
	}
	p6Status := "PASS"
	p6Color := "var(--green)"
	if !t.ChallengeResult.Passed {
		p6Status = "FAIL"
		p6Color = "var(--red)"
	}
	accessIcon := "✓"
	accessColor := "var(--green)"
	if !t.ChallengeResult.AccessRestored {
		accessIcon = "✗"
		accessColor = "var(--red)"
	}
	out := fmt.Sprintf(`<div class="cond-row"><span class="pl">🔐 Challenge [P6: %s]:</span>
<span style="color:%s;font-weight:700;">%s</span> | 
Token: <code>%s</code> | 
Solve: %dms | 
Access: <span style="color:%s;">%s</span></div>`,
		p6Status, p6Color, html.EscapeString(t.ChallengeResult.Format),
		html.EscapeString(truncateStr(t.ChallengeResult.ChallengeToken, 16)),
		t.ChallengeResult.DurationMs, accessColor, accessIcon)
	if t.ChallengeResult.SessionSuspended {
		out += `<div class="cond-row"><span class="pl"></span><span style="color:var(--green);">✓ Session properly suspended</span></div>`
	}
	if len(t.ChallengeResult.FailCodes) > 0 {
		out += fmt.Sprintf(`<div class="cond-row"><span class="pl"></span><span style="color:var(--red);">Fail Codes: %s</span></div>`,
			html.EscapeString(strings.Join(t.ChallengeResult.FailCodes, ", ")))
	}
	return out
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func formatReproduceHTML(t BTestEntryJSON) string {
	if t.ReproduceScript == "" {
		return ""
	}
	escaped := html.EscapeString(t.ReproduceScript)
	return fmt.Sprintf(`<details style="margin-top:12px;"><summary>🔄 Reproduce (copy-paste)</summary><pre class="curl" style="max-height:400px;overflow-y:auto;">%s</pre></details>`, escaped)
}
