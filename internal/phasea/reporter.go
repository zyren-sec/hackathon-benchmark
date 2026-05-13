package phasea

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
)

// ── Report Generation: HTML + JSON ──

// GenerateReport writes both report_phase_a.html and report_phase_a.json.
func GenerateReport(r *PhaseAResult, outputDir, tierFilter string) error {
	report := buildReport(r, tierFilter)

	// JSON
	jsonPath := filepath.Join(outputDir, "report_phase_a.json")
	if err := writeJSON(report, jsonPath); err != nil {
		return fmt.Errorf("JSON report: %w", err)
	}
	fmt.Printf("📄 JSON report: %s\n", jsonPath)

	// HTML
	htmlPath := filepath.Join(outputDir, "report_phase_a.html")
	if err := writeHTML(report, htmlPath); err != nil {
		return fmt.Errorf("HTML report: %w", err)
	}
	fmt.Printf("📄 HTML report: %s\n", htmlPath)

	return nil
}

// buildReport converts PhaseAResult to the serializable PhaseAReport.
func buildReport(r *PhaseAResult, tierFilter string) PhaseAReport {
	report := PhaseAReport{
		Phase:                 "A",
		Timestamp:             r.StartTime.Format("2006-01-02T15:04:05Z07:00"),
		WAFTarget:             r.WAFTarget,
		WAFMode:               r.WAFMode,
		PayloadTier:           tierFilter,
		ExploitPreventionRate: 0,
		TotalExploits:         r.TotalTests,
		PassedExploits:        r.PassedTests,
		FailedExploits:        r.FailedTests,
		SEC01Score:            r.SEC01Score,
		SEC01Max:              15.0,
		RSBonus:               r.RSBonusScore,
		RSBonusMax:            r.RSBonusMax,
		DurationMs:            r.EndTime.Sub(r.StartTime).Milliseconds(),
	}

	if r.TotalTests > 0 {
		report.ExploitPreventionRate = float64(r.PassedTests) / float64(r.TotalTests)
	}

	// Reset sequence
	for _, s := range r.ResetSteps {
		report.ResetSequence = append(report.ResetSequence, ResetStepJSON{
			Step:       s.StepNum,
			Name:       s.Name,
			StatusCode: s.StatusCode,
			Success:    s.Success,
			LatencyMs:  s.LatencyMs,
		})
	}

	// Categories
	for _, cat := range r.Categories {
		report.Categories = append(report.Categories, CatSummary{
			Num:    cat.CatNum,
			Title:  cat.Title,
			Passed: cat.PassedCount,
			Total:  cat.TotalCount,
		})
	}

	// Exploits
	for _, vr := range r.VulnResults {
		entry := buildReportEntry(&vr)
		report.Exploits = append(report.Exploits, entry)
	}

	return report
}

// buildReportEntry converts one VulnResult to ReportEntry with full details.
func buildReportEntry(vr *VulnResult) ReportEntry {
	entry := ReportEntry{
		VulnID:       vr.VulnID,
		Name:         vr.Name,
		Category:     vr.Category,
		Tier:         vr.Tier,
		AuthRequired: vr.AuthRequired,
		ProofMarker:  vr.ProofMarker,
		RiskRange:    fmt.Sprintf("%d–%d", vr.RiskMin, vr.RiskMax),
		Special:      vr.Special,
		Passed:       vr.OverallPassed,
		Skipped:      vr.Skipped,
		SkipReason:   vr.SkipReason,
		AuthSuccess:  vr.AuthSuccess,
		SessionID:    vr.SessionID,
		PassCount:    vr.PassCount,
		FailCount:    vr.FailCount,
	}

	if vr.OverallPassed {
		entry.Result = "PASS"
	} else if vr.Skipped {
		entry.Result = "SKIP"
	} else {
		entry.Result = "FAIL"
		entry.ResultReason = fmt.Sprintf("%d/%d payloads bypassed", vr.FailCount, len(vr.PayloadResults))
	}

	// Build decision matrix info
	entry.DecisionExplain = buildDecisionExplain(vr)

	// Payload results with full details
	for _, pr := range vr.PayloadResults {
		rp := ReportPayload{
			Index:        pr.Index,
			Name:         pr.PayloadName,
			Tier:         pr.Tier,
			Payload:      pr.Payload,
			StatusCode:   pr.StatusCode,
			LatencyMs:    pr.LatencyMs,
			Passed:       pr.Passed,
			FailReason:   pr.FailReason,
			MarkerFound:  pr.MarkerFound,
			WAFAction:    pr.WAFAction,
			RiskScore:    pr.RiskScore,
			Headers:      pr.ResponseHeaders,
			ResponseBody: pr.ResponseBody,

			// Reproducibility
			RequestURL:     pr.RequestURL,
			RequestMethod:  pr.RequestMethod,
			RequestBody:    pr.RequestBody,
			RequestHeaders: pr.RequestHeaders,
			FullRequest:    pr.FullRequest,
			CurlCommand:    pr.CurlCommand,

			// Scoring
			ScoringExplain: pr.ScoringExplain,
			RiskRange:      entry.RiskRange,
			RiskInRange:    pr.RiskScore >= vr.RiskMin && pr.RiskScore <= vr.RiskMax,
		}
		entry.Payloads = append(entry.Payloads, rp)
	}

	return entry
}

// buildDecisionExplain returns a human-readable decision matrix explanation.
func buildDecisionExplain(vr *VulnResult) string {
	if vr.Skipped {
		return fmt.Sprintf("SKIPPED: %s", vr.SkipReason)
	}

	tc, ok := ThreatCategories[vr.Category]
	if !ok {
		// Try by threat group mapping
		for _, vt := range GetVulnTests() {
			if vt.ID == vr.VulnID {
				tc, ok = ThreatCategories[vt.ThreatGroup]
				break
			}
		}
	}
	if !ok {
		tc = ThreatCategory{
			AcceptActions: []string{"block", "challenge"},
			StatusCodes:   []int{403, 429},
		}
	}

	statusStrs := make([]string, len(tc.StatusCodes))
	for i, s := range tc.StatusCodes {
		statusStrs[i] = fmt.Sprintf("%d", s)
	}

	return fmt.Sprintf(
		"Decision Matrix: Acceptable Actions ∈ %v | Expected Status Codes ∈ %v | Proof Marker: %s",
		tc.AcceptActions, statusStrs, vr.ProofMarker,
	)
}

// writeJSON writes the report as pretty JSON.
func writeJSON(report PhaseAReport, path string) error {
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

// writeHTML writes the report as a self-contained, comprehensive HTML page.
func writeHTML(report PhaseAReport, path string) error {
	os.MkdirAll(filepath.Dir(path), 0755)

	safeJSON, _ := json.Marshal(report)

	passPct := 0.0
	if report.TotalExploits > 0 {
		passPct = float64(report.PassedExploits) / float64(report.TotalExploits) * 100
	}

	scoreColor := "#22c55e" // green
	if passPct < 80 {
		scoreColor = "#eab308" // yellow
	}
	if passPct < 50 {
		scoreColor = "#ef4444" // red
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF Benchmark — Phase A: Exploit Prevention Report</title>
<style>
  :root {
    --bg: #0b1120; --card: #111827; --card2: #1a2332;
    --text: #e2e8f0; --muted: #94a3b8; --subtle: #64748b;
    --green: #22c55e; --red: #ef4444; --yellow: #eab308;
    --blue: #3b82f6; --purple: #8b5cf6; --orange: #f97316;
    --border: #1e293b; --border2: #334155;
    --code-bg: #0f172a; --pre-bg: #0f172a;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Noto Sans', sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.7; padding: 0;
  }
  .container { max-width: 1400px; margin: 0 auto; padding: 20px 24px 60px; }

  /* Header */
  .main-header {
    background: linear-gradient(135deg, var(--card) 0%%, var(--card2) 100%%);
    border: 1px solid var(--border); border-radius: 16px; padding: 28px 32px;
    margin-bottom: 24px;
  }
  .main-header h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: 4px; }
  .main-header .subtitle { color: var(--muted); font-size: 0.85rem; margin-bottom: 16px; }
  .meta-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
  }
  .meta-item { display: flex; flex-direction: column; }
  .meta-item .lbl { font-size: 0.7rem; color: var(--subtle); text-transform: uppercase; letter-spacing: 0.05em; }
  .meta-item .val { font-size: 0.95rem; font-weight: 600; word-break: break-all; }

  /* Score Card */
  .score-card {
    background: var(--card); border: 1px solid var(--border); border-radius: 16px;
    padding: 24px 28px; margin-bottom: 24px;
    display: grid; grid-template-columns: auto 1fr auto; gap: 24px; align-items: center;
  }
  .score-big { font-size: 3.2rem; font-weight: 800; line-height: 1; }
  .score-info h3 { font-size: 1.1rem; margin-bottom: 4px; }
  .progress-bar { height: 14px; border-radius: 7px; background: var(--border); margin: 10px 0; overflow: hidden; }
  .progress-fill { height: 100%%; border-radius: 7px; transition: width 0.6s ease; }
  .score-detail { font-size: 0.85rem; color: var(--muted); }
  .bonus-box { text-align: right; }
  .bonus-box .bonus-title { font-weight: 700; font-size: 0.85rem; color: var(--purple); }
  .bonus-box .bonus-val { font-size: 2rem; font-weight: 800; color: var(--purple); }

  /* Sections */
  .section {
    background: var(--card); border: 1px solid var(--border); border-radius: 16px;
    padding: 20px 28px; margin-bottom: 24px;
  }
  .section h2 { font-size: 1.25rem; color: var(--blue); margin-bottom: 16px; }

  /* Reset Steps */
  .reset-steps { display: flex; flex-direction: column; gap: 6px; }
  .reset-step {
    display: flex; align-items: center; gap: 10px; padding: 6px 0;
    font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.85rem;
  }
  .reset-step .ok { color: var(--green); font-weight: 700; }
  .reset-step .fail { color: var(--red); font-weight: 700; }
  .step-num { color: var(--subtle); min-width: 40px; }
  .reset-result { margin-top: 12px; padding: 8px 12px; border-radius: 6px; font-weight: 600; }
  .reset-result.all-ok { background: rgba(34,197,94,0.1); color: var(--green); }
  .reset-result.failed { background: rgba(239,68,68,0.1); color: var(--red); }

  /* Tables */
  .table-wrap { overflow-x: auto; }
  table { width: 100%%; border-collapse: collapse; font-size: 0.9rem; }
  th {
    text-align: left; padding: 10px 12px; font-size: 0.7rem; text-transform: uppercase;
    letter-spacing: 0.04em; color: var(--subtle); background: rgba(0,0,0,0.2);
    border-bottom: 1px solid var(--border2);
  }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
  tr:hover { background: rgba(255,255,255,0.02); }
  .cat-row { background: rgba(59,130,246,0.06); }
  .cat-row td { font-weight: 600; color: var(--blue); padding: 12px 12px; }

  /* Badges */
  .badge {
    display: inline-block; padding: 2px 10px; border-radius: 4px;
    font-size: 0.72rem; font-weight: 700; letter-spacing: 0.03em;
  }
  .badge-pass { background: rgba(34,197,94,0.15); color: var(--green); }
  .badge-fail { background: rgba(239,68,68,0.15); color: var(--red); }
  .badge-skip { background: rgba(148,163,184,0.15); color: var(--muted); }
  .badge-critical { background: rgba(239,68,68,0.2); color: #fca5a5; }
  .badge-high { background: rgba(234,179,8,0.2); color: #fde047; }
  .badge-medium { background: rgba(59,130,246,0.2); color: #93c5fd; }

  /* V* Test Cards */
  .vuln-card {
    background: var(--card2); border: 1px solid var(--border2); border-radius: 12px;
    margin: 16px 0; overflow: hidden;
  }
  .vuln-card-header {
    display: flex; align-items: center; gap: 12px; padding: 14px 20px;
    background: rgba(0,0,0,0.15); cursor: pointer; user-select: none;
    border-bottom: 1px solid transparent;
  }
  .vuln-card-header:hover { background: rgba(255,255,255,0.03); }
  .vuln-id { font-weight: 800; font-size: 1rem; min-width: 40px; }
  .vuln-name { font-weight: 600; flex: 1; }
  .vuln-card-body { padding: 0; display: none; }
  .vuln-card.open .vuln-card-header { border-bottom-color: var(--border2); }
  .vuln-card.open .vuln-card-body { display: block; }

  /* Meta rows */
  .vuln-meta {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 8px; padding: 16px 20px; font-size: 0.85rem;
    border-bottom: 1px solid var(--border);
  }
  .vuln-meta .ml { color: var(--subtle); }
  .vuln-meta .mv { font-weight: 600; }

  /* Payload detail card */
  .payload-detail {
    border-top: 1px solid var(--border); padding: 16px 20px;
  }
  .payload-detail:first-child { border-top: none; }
  .payload-header {
    display: flex; align-items: center; gap: 12px; margin-bottom: 12px;
    font-size: 0.9rem;
  }
  .payload-idx { color: var(--subtle); font-family: monospace; min-width: 28px; }
  .payload-name { font-weight: 600; font-family: monospace; flex: 1; }
  .payload-status { font-family: monospace; font-weight: 700; min-width: 48px; text-align: right; }

  /* Expandable sections within payloads */
  details {
    margin: 8px 0; border: 1px solid var(--border); border-radius: 8px;
    background: var(--code-bg); overflow: hidden;
  }
  details summary {
    padding: 10px 16px; cursor: pointer; font-size: 0.82rem; font-weight: 600;
    color: var(--blue); background: rgba(59,130,246,0.06);
    user-select: none; list-style: none;
  }
  details summary::-webkit-details-marker { display: none; }
  details summary::before { content: '▶ '; font-size: 0.7rem; margin-right: 6px; }
  details[open] summary::before { content: '▼ '; }
  details summary:hover { background: rgba(59,130,246,0.1); }

  /* Pre blocks */
  pre {
    margin: 0; padding: 14px 16px; font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.78rem; line-height: 1.5; overflow-x: auto;
    background: var(--pre-bg); color: var(--text);
    white-space: pre-wrap; word-break: break-all;
    max-height: 500px; overflow-y: auto;
  }
  pre.http-req { border-left: 3px solid var(--blue); }
  pre.http-resp { border-left: 3px solid var(--green); }
  pre.curl-cmd { border-left: 3px solid var(--orange); color: #fcd34d; }

  /* Scoring explanation */
  .scoring-explain {
    margin: 8px 0; padding: 12px 16px; border-radius: 8px;
    font-size: 0.82rem; line-height: 1.7; white-space: pre-wrap;
    font-family: 'SF Mono', 'Fira Code', monospace;
  }
  .scoring-explain.pass { background: rgba(34,197,94,0.08); border: 1px solid rgba(34,197,94,0.2); }
  .scoring-explain.fail { background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.2); }

  /* Perf indicators */
  .perf-row {
    display: flex; gap: 16px; flex-wrap: wrap; margin: 8px 0;
    font-size: 0.82rem;
  }
  .perf-item {
    padding: 6px 14px; border-radius: 6px; background: rgba(0,0,0,0.2);
    display: flex; align-items: center; gap: 6px;
  }
  .perf-item .pl { color: var(--subtle); }
  .perf-item .pv { font-weight: 700; font-family: monospace; }
  .perf-item.risk-in { border: 1px solid rgba(34,197,94,0.3); }
  .perf-item.risk-out { border: 1px solid rgba(239,68,68,0.3); }

  /* Scoring Methodology Section */
  .methodology-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 12px; margin-top: 12px;
  }
  .method-card {
    background: var(--code-bg); border: 1px solid var(--border);
    border-radius: 10px; padding: 14px 18px;
  }
  .method-card h4 { font-size: 0.9rem; color: var(--blue); margin-bottom: 6px; }
  .method-card p { font-size: 0.82rem; color: var(--muted); line-height: 1.6; }
  .method-card code { background: rgba(255,255,255,0.06); padding: 1px 6px; border-radius: 3px; font-size: 0.8rem; }

  /* Negative control */
  .neg-control { color: var(--yellow); font-size: 0.9rem; padding: 10px 0; }

  /* Footer */
  .footer {
    text-align: center; padding: 32px; color: var(--subtle); font-size: 0.8rem;
    border-top: 1px solid var(--border); margin-top: 32px;
  }
  .footer a { color: var(--blue); text-decoration: none; }

  /* Tabs for request/response */
  .tab-bar { display: flex; gap: 4px; margin-bottom: 0; }
  .tab-btn {
    padding: 8px 16px; border: 1px solid var(--border); border-bottom: none;
    border-radius: 8px 8px 0 0; background: var(--code-bg); color: var(--muted);
    cursor: pointer; font-size: 0.78rem; font-weight: 600;
  }
  .tab-btn.active { background: var(--pre-bg); color: var(--blue); border-color: var(--border2); }
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  @media (max-width: 768px) {
    .container { padding: 12px; }
    .score-card { grid-template-columns: 1fr; text-align: center; }
    .bonus-box { text-align: center; }
    .meta-grid { grid-template-columns: 1fr; }
    .vuln-meta { grid-template-columns: 1fr 1fr; }
  }
</style>
<script>
// Tab switching for request/response/curl tabs
function switchTab(evt, tabGroupId, tabIdx) {
  // Find the parent tab container
  var container = evt.currentTarget.closest('.tab-bar').parentElement;
  if (!container) return;
  // Deactivate all tab buttons in this group
  var buttons = container.querySelectorAll(':scope > .tab-bar .tab-btn');
  buttons.forEach(function(btn) { btn.classList.remove('active'); });
  // Activate clicked button
  evt.currentTarget.classList.add('active');
  // Deactivate all tab contents in this group
  var contents = container.querySelectorAll(':scope > .tab-content');
  contents.forEach(function(c) { c.classList.remove('active'); });
  // Activate the target tab content
  if (contents[tabIdx]) {
    contents[tabIdx].classList.add('active');
  }
  evt.preventDefault();
}
</script>
</head>
<body>
<div class="container">

  <!-- ═══ HEADER ═══ -->
  <div class="main-header">
    <h1>🔒 WAF Benchmark — Phase A: Exploit Prevention Tests</h1>
    <p class="subtitle">Comprehensive Security Evaluation Report — v2.3</p>
    <div class="meta-grid">
      <div class="meta-item"><span class="lbl">Timestamp</span><span class="val">%s</span></div>
      <div class="meta-item"><span class="lbl">WAF Target</span><span class="val">%s</span></div>
      <div class="meta-item"><span class="lbl">WAF Mode</span><span class="val">%s</span></div>
      <div class="meta-item"><span class="lbl">Payload Tier</span><span class="val">%s</span></div>
      <div class="meta-item"><span class="lbl">Duration</span><span class="val">%.1fs</span></div>
      <div class="meta-item"><span class="lbl">Test Cases</span><span class="val">%d exploits</span></div>
    </div>
  </div>

  <!-- ═══ SCORE CARD ═══ -->
  <div class="score-card">
    <div class="score-big" style="color:%s">%.2f<span style="font-size:1.2rem;color:var(--muted)">/15</span></div>
    <div class="score-info">
      <h3>SEC-01: Exploit Prevention Rate</h3>
      <div class="progress-bar"><div class="progress-fill" style="width:%.1f%%;background:%s"></div></div>
      <div class="score-detail">%d/%d exploits prevented (%.1f%%)</div>
      <div class="score-detail" style="margin-top:4px;">
        Formula: <code>15 × exploit_prevention_rate = 15 × %.4f = %.2f</code>
      </div>
    </div>
    <div class="bonus-box">
      <div class="bonus-title">RS-BONUS</div>
      <div class="bonus-val">%d<span style="font-size:0.9rem;color:var(--muted)">/%d</span></div>
      <div style="font-size:0.78rem;color:var(--subtle);">Risk Score Accuracy (tiebreaker)</div>
    </div>
  </div>

  <!-- ═══ RESET SEQUENCE ═══ -->
  <div class="section">
    <h2>🔄 Full Reset Sequence (5 bước — §3.1)</h2>
    <div class="reset-steps">
      %s
    </div>
    %s
  </div>

  <!-- ═══ NEGATIVE CONTROL ═══ -->
  <div class="section">
    <h2>🧪 Negative Control</h2>
    <p class="neg-control">⏭️ SKIPPED — UPSTREAM cố ý trả về proof marker trên GET /. Việc kiểm tra negative control tạm thời bị skip.</p>
  </div>

  <!-- ═══ CATEGORY RESULTS ═══ -->
  <div class="section">
    <h2>📊 Category Results</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Category</th><th>ID Range</th><th>Tests</th><th>Passed</th><th>Rate</th></tr></thead>
        <tbody>
          %s
        </tbody>
      </table>
    </div>
  </div>

  <!-- ═══ SCORING METHODOLOGY ═══ -->
  <div class="section">
    <h2>📐 Scoring Methodology</h2>
    <div class="methodology-grid">
      <div class="method-card">
        <h4>🔍 STEP 0: Required Headers (§5.1)</h4>
        <p>All responses MUST include 6 mandatory headers: <code>X-WAF-Request-Id</code>, <code>X-WAF-Risk-Score</code>, <code>X-WAF-Action</code>, <code>X-WAF-Rule-Id</code>, <code>X-WAF-Mode</code>, <code>X-WAF-Cache</code>. Missing any → <strong>FAIL (MISSING HDR)</strong>.</p>
      </div>
      <div class="method-card">
        <h4>🏷️ STEP 1: Marker Scan (§5.2-F2/F3)</h4>
        <p>Response body + headers are scanned for proof markers. Own marker (<code>__V{id}_{name}__</code>) found → <strong>FAIL (OWN MKR)</strong>. Other V* markers found → <strong>FAIL (OTHER MKR)</strong> — indicates side-effect / cross-contamination.</p>
      </div>
      <div class="method-card">
        <h4>🎯 STEP 2: X-WAF-Action Validation (§5.4)</h4>
        <p><code>X-WAF-Action</code> must be in the acceptable set for the threat category (e.g., <code>block</code> or <code>challenge</code> for injection attacks, <code>block</code> or <code>rate_limit</code> for DoS). Wrong action → <strong>FAIL (WRONG ACTION)</strong>.</p>
      </div>
      <div class="method-card">
        <h4>📡 STEP 3: Status Code Validation (§4)</h4>
        <p>HTTP status must match the <code>X-WAF-Action</code>: <code>block</code>→403, <code>challenge</code>/<code>rate_limit</code>→429, <code>timeout</code>→504, <code>circuit_breaker</code>→503. Mismatch → <strong>FAIL (WRONG STATUS)</strong>.</p>
      </div>
      <div class="method-card">
        <h4>⭐ RS-BONUS (Risk Score Accuracy)</h4>
        <p>For PASS tests only: if <code>X-WAF-Risk-Score</code> falls within the expected range (<code>RiskMin–RiskMax</code>), the test earns RS-BONUS points (tiebreaker). Score range depends on tier: CRITICAL: 70–100, HIGH: 50–85, MEDIUM: 30–65.</p>
      </div>
      <div class="method-card">
        <h4>📈 SEC-01 Score</h4>
        <p><code>SEC-01 = 15 × (PASS_count / total_tests)</code>. Each V* test is counted once — all of its payloads must PASS for the V* to PASS. Maximum: 15 points across V01–V24.</p>
      </div>
    </div>
  </div>

  <!-- ═══ TEST DETAILS ═══ -->
  <div class="section">
    <h2>📋 Test Details — V* Exploit Prevention Results</h2>
    <p style="color:var(--muted);font-size:0.85rem;margin-bottom:16px;">
      Click any V* test to expand. Each payload includes: full HTTP request, full HTTP response, curl command for reproduction, and detailed scoring explanation.
    </p>
    %s
  </div>

  <!-- ═══ SCORING SUMMARY ═══ -->
  <div class="score-card">
    <div class="score-big" style="color:%s">%.2f<span style="font-size:1.2rem;color:var(--muted)">/15</span></div>
    <div class="score-info">
      <h3>PHASE A — SCORING SUMMARY</h3>
      <div style="font-size:0.9rem;color:var(--muted);margin-top:6px;">
        SEC-01 (Exploit Prevention) = 15 × (%d/%d) = %.2f
      </div>
      <div style="font-size:0.9rem;color:var(--muted);">
        RS-BONUS (Risk Score Accuracy) = %d/%d (tiebreaker only)
      </div>
    </div>
    <div class="bonus-box">
      <div class="bonus-title">BONUS</div>
      <div class="bonus-val">%d<span style="font-size:0.9rem;color:var(--muted)">/20</span></div>
    </div>
  </div>

  <!-- ═══ FOOTER ═══ -->
  <div class="footer">
    <p>WAF Benchmark Tool v2.3 — Phase A: Exploit Prevention Tests</p>
    <p style="margin-top:4px;">Report generated for <strong>%s</strong> | Payload Tier: <strong>%s</strong></p>
    <p style="margin-top:8px;font-size:0.75rem;">
      Specification: <code>docs/hackathon/workflow/phase_A.md</code> |
      Contract: <code>docs/hackathon/VN_waf_interop_contract_v2.3.md</code>
    </p>
  </div>

</div>

<script>
  // Full report data available for inspection in browser console
  window.PHASE_A_REPORT = %s;

  // Vuln card toggle
  document.querySelectorAll('.vuln-card-header').forEach(function(hdr) {
    hdr.addEventListener('click', function() {
      this.parentElement.classList.toggle('open');
    });
  });

  // Tab switching
  document.querySelectorAll('.tab-bar').forEach(function(bar) {
    var btns = bar.querySelectorAll('.tab-btn');
    var contents = bar.parentElement.querySelectorAll('.tab-content');
    btns.forEach(function(btn, i) {
      btn.addEventListener('click', function() {
        btns.forEach(function(b) { b.classList.remove('active'); });
        contents.forEach(function(c) { c.classList.remove('active'); });
        btn.classList.add('active');
        if (contents[i]) contents[i].classList.add('active');
      });
    });
  });
</script>
</body>
</html>`,
		// Header meta
		report.Timestamp, report.WAFTarget, report.WAFMode, report.PayloadTier,
		float64(report.DurationMs)/1000.0, report.TotalExploits,

		// Score card
		scoreColor, report.SEC01Score,
		passPct, scoreColor,
		report.PassedExploits, report.TotalExploits, passPct,
		float64(report.PassedExploits)/float64(report.TotalExploits), report.SEC01Score,
		report.RSBonus, report.RSBonusMax,

		// Reset sequence
		buildResetHTML(report.ResetSequence),
		buildResetResultHTML(report.ResetSequence),

		// Category summary
		buildCatSummaryHTML(report.Categories),

		// Test details
		buildTestDetailsHTML(report.Exploits),

		// Scoring summary
		scoreColor, report.SEC01Score,
		report.PassedExploits, report.TotalExploits, report.SEC01Score,
		report.RSBonus, report.RSBonusMax,
		report.RSBonus,

		// Footer
		report.WAFTarget, report.PayloadTier,

		// JSON data
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

// ── HTML Builders ──

func buildResetHTML(steps []ResetStepJSON) string {
	if len(steps) == 0 {
		return `<div class="reset-step"><span class="muted">No reset data</span></div>`
	}
	var lines []string
	for _, s := range steps {
		cls := "ok"
		icon := "✓"
		if !s.Success {
			cls = "fail"
			icon = "✗"
		}
		lines = append(lines, fmt.Sprintf(
			`<div class="reset-step"><span class="step-num">[%d/5]</span><span class="%s">%s</span> %s — HTTP %d (%.3fms)</div>`,
			s.Step, cls, icon, html.EscapeString(s.Name), s.StatusCode, s.LatencyMs,
		))
	}
	return strings.Join(lines, "\n      ")
}

func buildResetResultHTML(steps []ResetStepJSON) string {
	allOK := true
	for _, s := range steps {
		if !s.Success && s.Step != 4 { // Step 4 is non-fatal
			allOK = false
			break
		}
	}
	if allOK {
		return `<div class="reset-result all-ok">✅ All 5/5 reset steps completed successfully</div>`
	}
	return `<div class="reset-result failed">❌ Reset sequence FAILED — Phase A cannot proceed</div>`
}

func buildCatSummaryHTML(cats []CatSummary) string {
	if len(cats) == 0 {
		return `<tr><td colspan="5" style="color:var(--muted);text-align:center;">No category data</td></tr>`
	}
	var rows []string
	for _, c := range cats {
		pct := 0.0
		if c.Total > 0 {
			pct = float64(c.Passed) / float64(c.Total) * 100
		}
		rows = append(rows, fmt.Sprintf(
			`<tr class="cat-row"><td>CAT %d: %s</td><td>—</td><td>%d</td><td>%d</td><td>%.0f%%</td></tr>`,
			c.Num, html.EscapeString(c.Title), c.Total, c.Passed, pct,
		))
	}
	return strings.Join(rows, "\n          ")
}

func buildTestDetailsHTML(exploits []ReportEntry) string {
	if len(exploits) == 0 {
		return `<p style="color:var(--muted);">No test results available.</p>`
	}

	var cards []string
	for _, e := range exploits {
		cards = append(cards, buildVulnCard(e))
	}
	return strings.Join(cards, "\n    ")
}

// buildVulnCard builds an expandable card for a single V* test.
func buildVulnCard(e ReportEntry) string {
	badgeCls := "badge-pass"
	icon := "✅"
	if e.Result == "FAIL" {
		badgeCls = "badge-fail"
		icon = "❌"
	} else if e.Result == "SKIP" {
		badgeCls = "badge-skip"
		icon = "⏭️"
	}

	tierCls := "badge-medium"
	switch e.Tier {
	case "CRITICAL":
		tierCls = "badge-critical"
	case "HIGH":
		tierCls = "badge-high"
	}

	authLabel := "No"
	if e.AuthRequired {
		authLabel = "Yes"
	}

	var sb strings.Builder

	// Card header
	sb.WriteString(fmt.Sprintf(`
    <div class="vuln-card%s">
      <div class="vuln-card-header">
        <span style="font-size:1.2rem;">%s</span>
        <span class="vuln-id">%s</span>
        <span class="vuln-name">%s</span>
        <span class="badge %s">%s</span>
        <span class="badge %s" style="margin-left:auto;">%s</span>
      </div>
      <div class="vuln-card-body">`,
		map[bool]string{true: " open", false: ""}[e.Result == "FAIL"],
		icon, e.VulnID, html.EscapeString(e.Name), tierCls, e.Tier, badgeCls, e.Result,
	))

	// Meta row
	sb.WriteString(fmt.Sprintf(`
        <div class="vuln-meta">
          <div><span class="ml">Category:</span> <span class="mv">%s</span></div>
          <div><span class="ml">Auth Required:</span> <span class="mv">%s</span></div>
          <div><span class="ml">Risk Range:</span> <span class="mv">%s</span></div>
          <div><span class="ml">Proof Marker:</span> <span class="mv" style="font-family:monospace;font-size:0.8rem;">%s</span></div>
          <div><span class="ml">Payloads:</span> <span class="mv">%d/%d passed</span></div>
          <div><span class="ml">Special:</span> <span class="mv">%s</span></div>
        </div>`,
		html.EscapeString(e.Category), authLabel, e.RiskRange, html.EscapeString(e.ProofMarker),
		e.PassCount, e.PassCount+e.FailCount, html.EscapeString(map[bool]string{true: e.Special, false: "none"}[e.Special != ""]),
	))

	// Session status
	sessionHTML := buildSessionHTML(e)
	sb.WriteString(sessionHTML)

	// Decision matrix
	if e.DecisionExplain != "" {
		sb.WriteString(fmt.Sprintf(`
        <div style="padding:8px 20px;font-size:0.82rem;color:var(--muted);background:rgba(0,0,0,0.1);">
          📐 %s
        </div>`, html.EscapeString(e.DecisionExplain)))
	}

	// Payload details
	if e.Skipped {
		sb.WriteString(fmt.Sprintf(`
        <div style="padding:16px 20px;color:var(--muted);">
          ⏭️ SKIPPED: %s
        </div>`, html.EscapeString(e.SkipReason)))
	} else {
		for _, p := range e.Payloads {
			sb.WriteString(buildPayloadDetail(e, p))
		}
	}

	sb.WriteString(`
      </div>
    </div>`)

	return sb.String()
}

// buildSessionHTML builds the session status section.
func buildSessionHTML(e ReportEntry) string {
	if e.Skipped && e.SkipReason == "auth failed" {
		return `
        <div style="padding:8px 20px;color:var(--red);font-size:0.85rem;">
          🔐 Session: <strong>FAILED</strong> — Authentication error, all payloads skipped
        </div>`
	}
	if e.AuthRequired {
		if e.AuthSuccess {
			sidDisplay := e.SessionID
			if len(sidDisplay) > 16 {
				sidDisplay = sidDisplay[:16] + "..."
			}
			return fmt.Sprintf(`
        <div style="padding:8px 20px;color:var(--green);font-size:0.85rem;">
          🔐 Session: <strong>OK</strong> (sid=%s)
        </div>`, html.EscapeString(sidDisplay))
		}
		return `
        <div style="padding:8px 20px;color:var(--red);font-size:0.85rem;">
          🔐 Session: <strong>FAILED</strong>
        </div>`
	}
	return `
        <div style="padding:8px 20px;color:var(--subtle);font-size:0.85rem;">
          🔐 Session: N/A (no auth required)
        </div>`
}

// buildPayloadDetail builds the detailed expandable section for one payload.
func buildPayloadDetail(e ReportEntry, p ReportPayload) string {
	passCls := "pass"
	passIcon := "✅"
	if !p.Passed {
		passCls = "fail"
		passIcon = "❌"
	}

	failMsg := ""
	if p.FailReason != "" {
		failMsg = fmt.Sprintf(` <span style="color:var(--red);font-weight:600;">[%s]</span>`, html.EscapeString(p.FailReason))
	}

	riskCls := "risk-in"
	if !p.RiskInRange {
		riskCls = "risk-out"
	}

	methodColor := "#3b82f6"
	switch p.RequestMethod {
	case "POST":
		methodColor = "#22c55e"
	case "PUT":
		methodColor = "#f97316"
	case "DELETE":
		methodColor = "#ef4444"
	}

	// Escape for HTML
	respBody := html.EscapeString(p.ResponseBody)
	fullReq := html.EscapeString(p.FullRequest)
	curlCmd := html.EscapeString(p.CurlCommand)
	scoringExplain := html.EscapeString(p.ScoringExplain)
	payloadContent := html.EscapeString(p.Payload)

	// Build response headers
	var respHeaders strings.Builder
	for k, v := range p.Headers {
		respHeaders.WriteString(fmt.Sprintf("%s: %s\n", html.EscapeString(k), html.EscapeString(v)))
	}

	// Build request headers
	var reqHeaders strings.Builder
	for k, v := range p.RequestHeaders {
		reqHeaders.WriteString(fmt.Sprintf("%s: %s\n", html.EscapeString(k), html.EscapeString(v)))
	}

	return fmt.Sprintf(`
        <div class="payload-detail">
          <div class="payload-header">
            <span class="payload-idx">#%d</span>
            <span class="payload-name">%s</span>
            <span style="color:%s;font-weight:700;font-family:monospace;">%s</span>
            <span class="payload-status" style="color:var(--%s);">HTTP %d</span>
            <span>%s</span>%s
          </div>

          <!-- Performance Indicators -->
          <div class="perf-row">
            <div class="perf-item">
              <span class="pl">⏱️ Latency:</span>
              <span class="pv">%.3fms</span>
            </div>
            <div class="perf-item %s">
              <span class="pl">🎯 Risk Score:</span>
              <span class="pv">%d</span>
              <span style="font-size:0.75rem;color:var(--subtle);">(range: %s)</span>
            </div>
            <div class="perf-item">
              <span class="pl">🛡️ WAF Action:</span>
              <span class="pv">%s</span>
            </div>
            <div class="perf-item">
              <span class="pl">📦 Tier:</span>
              <span class="pv">%s</span>
            </div>
          </div>

          <!-- Payload Content -->
          <details>
            <summary>💣 Payload Content</summary>
            <pre>%s</pre>
          </details>

          <!-- Request + Response + Curl Tabs -->
          <div style="margin:8px 0;">
            <div class="tab-bar">
              <button class="tab-btn active" onclick="switchTab(event,0,0)">📤 Full Request</button>
              <button class="tab-btn" onclick="switchTab(event,0,1)">📥 Full Response</button>
              <button class="tab-btn" onclick="switchTab(event,0,2)">🔄 curl Command</button>
            </div>
            <div class="tab-content active">
              <pre class="http-req">%s</pre>
            </div>
            <div class="tab-content">
              <div style="padding:8px 16px;font-size:0.78rem;color:var(--subtle);background:var(--code-bg);">Response Headers:</div>
              <pre class="http-resp" style="max-height:200px;">%s</pre>
              <div style="padding:8px 16px;font-size:0.78rem;color:var(--subtle);background:var(--code-bg);">Response Body:</div>
              <pre class="http-resp">%s</pre>
            </div>
            <div class="tab-content">
              <pre class="curl-cmd">%s</pre>
            </div>
          </div>

          <!-- Scoring Explanation -->
          <details open>
            <summary>📊 Scoring Explanation</summary>
            <div class="scoring-explain %s">%s</div>
          </details>

          <!-- Markers Found -->
          %s
        </div>`,
		p.Index, html.EscapeString(p.Name),
		methodColor, p.RequestMethod,
		map[bool]string{true: "green", false: "red"}[p.Passed], p.StatusCode,
		passIcon, failMsg,
		p.LatencyMs,
		riskCls, p.RiskScore, html.EscapeString(p.RiskRange),
		html.EscapeString(p.WAFAction),
		html.EscapeString(p.Tier),
		payloadContent,
		fullReq,
		respHeaders.String(),
		respBody,
		curlCmd,
		passCls, scoringExplain,
		buildMarkerInfo(p),
	)
}

// buildMarkerInfo shows marker detection results.
func buildMarkerInfo(p ReportPayload) string {
	if p.MarkerFound != "" {
		return fmt.Sprintf(`
          <div style="padding:8px 16px;margin:8px 0;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);border-radius:6px;font-size:0.82rem;">
            ⚠️ Marker Found: <code style="color:var(--red);">%s</code>
          </div>`, html.EscapeString(p.MarkerFound))
	}
	return ""
}