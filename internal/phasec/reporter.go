package phasec

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
)

// GenerateReport writes report_phase_c.html and report_phase_c.json.
func GenerateReport(r *PhaseCResult, outputDir string) error {
	report := buildCReport(r)

	jsonPath := filepath.Join(outputDir, "report_phase_c.json")
	if err := writeCJSON(report, jsonPath); err != nil {
		return fmt.Errorf("JSON report: %w", err)
	}
	fmt.Printf("📄 JSON report: %s\n", jsonPath)

	htmlPath := filepath.Join(outputDir, "report_phase_c.html")
	if err := writeCHTML(report, htmlPath); err != nil {
		return fmt.Errorf("HTML report: %w", err)
	}
	fmt.Printf("📄 HTML report: %s\n", htmlPath)

	return nil
}

func buildCReport(r *PhaseCResult) PhaseCReport {
	report := PhaseCReport{
		Phase:               "C",
		Timestamp:           r.StartTime.Format("2006-01-02T15:04:05Z07:00"),
		WAFTarget:           r.WAFTarget,
		WAFMode:             r.WAFMode,
		DurationMs:          r.EndTime.Sub(r.StartTime).Milliseconds(),
		WAFPID:              r.WAFPID,
		MemoryMonitorOK:     r.MemoryMonitorOK,
		ResetAllPassed:      r.ResetAllPassed,
		FPCount:             r.FPCount,
		FPRate:              r.FPRate,
		CollateralCount:     r.CollateralCount,
		PhaseCTotal:         r.PhaseCTotal,
		PhaseCMax:           r.PhaseCMax,
		WAFCrashed:          r.WAFCrashed,
		GracefulDegradation: !r.WAFCrashed,
	}

	for _, s := range r.ResetSteps {
		report.ResetSequence = append(report.ResetSequence, CResetStepJSON{
			Step: s.StepNum, Name: s.Name, StatusCode: s.StatusCode,
			Success: s.Success, LatencyMs: s.LatencyMs,
		})
	}

	if r.Baseline != nil {
		report.BaselineFailed = r.BaselineFailed
		bl := &CBaselineJSON{TotalSamples: r.Baseline.TotalSamples}
		for _, cls := range r.Baseline.Classes {
			bl.Classes = append(bl.Classes, CLatencyClassJSON{
				Name: cls.Name, Endpoints: cls.Endpoints, Samples: cls.Samples,
				P50Ms: cls.P50Ms, P99Ms: cls.P99Ms, AvgMs: cls.AvgMs,
			})
		}
		report.Baseline = bl
	}

	if r.WAFLatency != nil {
		wl := &CWAFLatencyJSON{TotalSamples: r.WAFLatency.TotalSamples}
		for _, cls := range r.WAFLatency.Classes {
			wl.Classes = append(wl.Classes, CWAFLatencyClassJSON{
				Name: cls.Name, Endpoints: cls.Endpoints, Samples: cls.Samples,
				P50Ms: cls.P50Ms, P99Ms: cls.P99Ms, AvgMs: cls.AvgMs,
				OverheadP50: cls.OverheadP50, OverheadP99: cls.OverheadP99, OverheadPct: cls.OverheadPct,
			})
		}
		report.WAFLatency = wl
	}

	for _, s := range r.LoadTestSteps {
		report.LoadTestSteps = append(report.LoadTestSteps, CLoadTestStepJSON{
			StepNum: s.StepNum, TargetRPS: s.TargetRPS, ActualRPS: s.ActualRPS,
			DurationSec: s.DurationSec, TotalRequests: s.TotalRequests,
			SuccessCount: s.SuccessCount, ErrorCount: s.ErrorCount, BlockedCount: s.BlockedCount,
			SuccessRate: s.SuccessRate, ErrorRate: s.ErrorRate, BlockedRate: s.BlockedRate,
			P50Ms: s.P50Ms, P99Ms: s.P99Ms, MaxMs: s.MaxMs,
			MemoryPeakMB: s.MemoryPeakMB, FPCount: s.FalsePositiveCount,
			CollateralCount: s.CollateralCount, DDoSBurstsTriggered: s.DDoSBurstsTriggered,
			Passed: s.Passed, FailReason: s.FailReason,
		})
	}

	for _, ts := range r.ThroughputTS {
		report.ThroughputTS = append(report.ThroughputTS, CThroughputPointJSON{
			TimestampSec: ts.TimestampSec, ActualRPS: ts.ActualRPS,
		})
	}
	for _, ms := range r.MemoryTS {
		report.MemoryTS = append(report.MemoryTS, CMemoryPointJSON{
			TimestampSec: ms.TimestampSec, MemoryMB: ms.MemoryMB,
		})
	}

	for _, fp := range r.FPDetails {
		report.FPDetails = append(report.FPDetails, CFPDetailJSON{
			Endpoint: fp.Endpoint, StatusCode: fp.StatusCode, LatencyMs: fp.LatencyMs,
			WAFAction: fp.WAFAction, RiskScore: fp.RiskScore, DuringDDoS: fp.DuringDDoS,
		})
	}

	// Diagnostic section
	report.ResourceTier = string(r.ResourceTier)
	report.CgroupsActive = r.CgroupsActive
	report.PinningVerified = r.PinningVerified
	report.ProfilerActive = r.ProfilerActive
	if r.NoiseReport != nil {
		report.NoiseFlag = string(r.NoiseReport.Flag)
		report.NoiseEstimateMs = r.NoiseReport.EstimateMs
		report.NoiseCorrelation = &NoiseCorrelationJSON{
			WAFCPU:    r.NoiseReport.CorrelationWAF,
			BenchCPU:  r.NoiseReport.CorrelationBench,
			CtxSwitch: r.NoiseReport.CorrelationCtx,
		}
	} else {
		report.NoiseFlag = string(NoiseDisabled)
	}

	report.Scoring = make(map[string]CScoreDetailJSON)
	for k, s := range r.Scores {
		report.Scoring[k] = CScoreDetailJSON{
			Pass: s.Pass, Points: s.Points, MaxPoints: s.MaxPoints,
			Measured: s.Measured, Threshold: s.Threshold, Explanation: s.Explanation,
		}
	}

	return report
}

func writeCJSON(report PhaseCReport, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func writeCHTML(report PhaseCReport, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(buildCHTML(report))
	return err
}

// ── Shared CSS (matches Phase A/B exactly) ──

func sharedCSS() string {
	return `
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

  .main-header {
    background: linear-gradient(135deg, var(--card) 0%, var(--card2) 100%);
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

  .score-card {
    background: var(--card); border: 1px solid var(--border); border-radius: 16px;
    padding: 24px 28px; margin-bottom: 24px;
    display: grid; grid-template-columns: auto 1fr; gap: 24px; align-items: center;
  }
  .score-big { font-size: 3.2rem; font-weight: 800; line-height: 1; }
  .score-info h3 { font-size: 1.1rem; margin-bottom: 4px; }
  .progress-bar { height: 14px; border-radius: 7px; background: var(--border); margin: 10px 0; overflow: hidden; }
  .progress-fill { height: 100%; border-radius: 7px; transition: width 0.6s ease; }
  .score-detail { font-size: 0.85rem; color: var(--muted); }

  .section {
    background: var(--card); border: 1px solid var(--border); border-radius: 16px;
    padding: 20px 28px; margin-bottom: 24px;
  }
  .section h2 { font-size: 1.25rem; color: var(--blue); margin-bottom: 16px; }

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

  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th {
    text-align: left; padding: 10px 12px; font-size: 0.7rem; text-transform: uppercase;
    letter-spacing: 0.04em; color: var(--subtle); background: rgba(0,0,0,0.2);
    border-bottom: 1px solid var(--border2);
  }
  td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
  tr:hover { background: rgba(255,255,255,0.02); }

  .badge {
    display: inline-block; padding: 2px 10px; border-radius: 4px;
    font-size: 0.72rem; font-weight: 700; letter-spacing: 0.03em;
  }
  .badge-pass { background: rgba(34,197,94,0.15); color: var(--green); }
  .badge-fail { background: rgba(239,68,68,0.15); color: var(--red); }
  .badge-warn { background: rgba(234,179,8,0.15); color: var(--yellow); }

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

  .vuln-meta {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 8px; padding: 16px 20px; font-size: 0.85rem;
    border-bottom: 1px solid var(--border);
  }
  .vuln-meta .ml { color: var(--subtle); }
  .vuln-meta .mv { font-weight: 600; }

  .perf-row {
    display: flex; gap: 16px; flex-wrap: wrap; margin: 8px 0;
    font-size: 0.82rem; padding: 12px 20px;
  }
  .perf-item {
    padding: 6px 14px; border-radius: 6px; background: rgba(0,0,0,0.2);
    display: flex; align-items: center; gap: 6px;
  }
  .perf-item .pl { color: var(--subtle); }
  .perf-item .pv { font-weight: 700; font-family: monospace; }
  .perf-item.risk-in { border: 1px solid rgba(34,197,94,0.3); }
  .perf-item.risk-out { border: 1px solid rgba(239,68,68,0.3); }

  details {
    margin: 8px 20px; border: 1px solid var(--border); border-radius: 8px;
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

  pre {
    margin: 0; padding: 14px 16px; font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.78rem; line-height: 1.5; overflow-x: auto;
    background: var(--pre-bg); color: var(--text);
    white-space: pre-wrap; word-break: break-all;
    max-height: 500px; overflow-y: auto;
  }
  pre.curl-cmd { border-left: 3px solid var(--orange); color: #fcd34d; }

  .scoring-explain {
    margin: 8px 20px 16px; padding: 12px 16px; border-radius: 8px;
    font-size: 0.82rem; line-height: 1.7; white-space: pre-wrap;
    font-family: 'SF Mono', 'Fira Code', monospace;
  }
  .scoring-explain.pass { background: rgba(34,197,94,0.08); border: 1px solid rgba(34,197,94,0.2); }
  .scoring-explain.fail { background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.2); }

  .fail-reason {
    padding: 10px 16px; margin: 8px 20px; border-radius: 6px;
    background: rgba(239,68,68,0.08); border: 1px solid rgba(239,68,68,0.2);
    color: var(--red); font-size: 0.85rem; font-weight: 600;
  }

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

  .footer {
    text-align: center; padding: 32px; color: var(--subtle); font-size: 0.8rem;
    border-top: 1px solid var(--border); margin-top: 32px;
  }
  .footer a { color: var(--blue); text-decoration: none; }

  @media (max-width: 768px) {
    .container { padding: 12px; }
    .score-card { grid-template-columns: 1fr; text-align: center; }
    .meta-grid { grid-template-columns: 1fr; }
    .vuln-meta { grid-template-columns: 1fr 1fr; }
  }
`
}

// ── Full HTML Builder ──

func buildCHTML(r PhaseCReport) string {
	var sb strings.Builder
	passCount := 0
	for _, s := range r.Scoring {
		if s.Pass {
			passCount++
		}
	}
	totalCriteria := len(r.Scoring)
	scorePct := 0.0
	if r.PhaseCMax > 0 {
		scorePct = r.PhaseCTotal / r.PhaseCMax * 100
	}
	scoreColor := r.PhaseCTotal >= 15.0

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF Benchmark — Phase C: Performance & Throughput Report</title>
<style>`)
	sb.WriteString(sharedCSS())
	sb.WriteString(`</style>
<script>
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.vuln-card-header').forEach(function(hdr) {
    hdr.addEventListener('click', function() {
      this.parentElement.classList.toggle('open');
    });
  });
  // Open first card by default
  var first = document.querySelector('.vuln-card');
  if (first) first.classList.add('open');
});
</script>
</head>
<body>
<div class="container">
`)

	// ═══ MAIN HEADER ═══
	sb.WriteString(fmt.Sprintf(`
<div class="main-header">
<h1>⚡ WAF-BENCHMARK — PHASE C: PERFORMANCE &amp; THROUGHPUT REPORT</h1>
<div class="subtitle">Performance evaluation under blended traffic load — Latency, Throughput, Memory, Graceful Degradation</div>
<div class="meta-grid">
<div class="meta-item"><span class="lbl">Timestamp</span><span class="val">%s</span></div>
<div class="meta-item"><span class="lbl">WAF Target</span><span class="val">%s</span></div>
<div class="meta-item"><span class="lbl">WAF Mode</span><span class="val">%s</span></div>
<div class="meta-item"><span class="lbl">Duration</span><span class="val">%dms</span></div>
<div class="meta-item"><span class="lbl">Traffic Mix</span><span class="val">60%% Legit / 10%% Suspicious / 10%% Exploit / 10%% Abuse / 10%% DDoS</span></div>
<div class="meta-item"><span class="lbl">Source IPs</span><span class="val">127.0.0.200–220 (21 loopback aliases)</span></div>
<div class="meta-item"><span class="lbl">WAF PID</span><span class="val">%s</span></div>
<div class="meta-item"><span class="lbl">Memory Monitor</span><span class="val">%s</span></div>
</div>
</div>`,
		html.EscapeString(r.Timestamp),
		html.EscapeString(r.WAFTarget),
		html.EscapeString(r.WAFMode),
		r.DurationMs,
		html.EscapeString(r.WAFPID),
		map[bool]string{true: `<span style="color:var(--green);">✅ enabled</span>`, false: `<span style="color:var(--yellow);">⚠️ disabled</span>`}[r.MemoryMonitorOK],
	))

	// ═══ SCORE CARD ═══
	sb.WriteString(fmt.Sprintf(`
<div class="score-card">
<div class="score-big" style="color:%s;">%.0f<span style="font-size:1.2rem;color:var(--muted);">/%.0f</span></div>
<div class="score-info">
<h3>Phase C Total Score</h3>
<div class="progress-bar"><div class="progress-fill" style="width:%.1f%%; background:%s;"></div></div>
<div class="score-detail">%d/%d criteria passed | %d points from performance evaluation</div>
</div>
</div>`,
		map[bool]string{true: "var(--green)", false: "var(--yellow)"}[scoreColor],
		r.PhaseCTotal, r.PhaseCMax,
		scorePct,
		map[bool]string{true: "var(--green)", false: "var(--yellow)"}[scoreColor],
		passCount, totalCriteria,
		int(r.PhaseCTotal),
	))

	// ═══ EXECUTIVE SUMMARY ═══
	sb.WriteString(buildExecutiveSummary(&r))

	// ═══ RESET SEQUENCE ═══
	sb.WriteString(`<div class="section"><h2>🔄 Full Reset Sequence (5 steps — §3.1)</h2><div class="reset-steps">`)
	for _, s := range r.ResetSequence {
		ico := "✓"
		cls := "ok"
		if !s.Success {
			ico = "✗"
			cls = "fail"
		}
		sb.WriteString(fmt.Sprintf(`<div class="reset-step"><span class="step-num">[%d/5]</span><span class="%s">%s</span> %s — HTTP %d (%.3fms)</div>`,
			s.Step, cls, ico, html.EscapeString(s.Name), s.StatusCode, s.LatencyMs))
	}
	if r.ResetAllPassed {
		sb.WriteString(`<div class="reset-result all-ok">✅ ALL 5/5 STEPS PASSED — Phase C continues</div>`)
	} else {
		sb.WriteString(`<div class="reset-result failed">❌ RESET FAILED — PHASE C ABORTED</div>`)
	}
	sb.WriteString(`</div></div>`)

	if !r.ResetAllPassed {
		sb.WriteString(`<div class="footer">WAF Benchmark Tool v2.7 | Phase C — Performance &amp; Throughput Tests</div></div></body></html>`)
		return sb.String()
	}

	// ═══ SCORING METHODOLOGY ═══
	sb.WriteString(`
<div class="section"><h2>📐 Scoring Methodology (§5.2)</h2><div class="methodology-grid">
<div class="method-card"><h4>PERF-01: p99 Latency (10 pts)</h4><p><code>Binary: p99 ≤ 5ms at 5000 RPS → 10; else 0</code><br>Measured at Step 3 (5000 RPS × 60s — SLA TARGET). WAF must add &lt;5ms overhead at p99 compared to baseline.</p></div>
<div class="method-card"><h4>PERF-02: Sustained Throughput (5 pts)</h4><p><code>Binary: actual RPS ≥ 5000 at 5000 RPS target → 5; else 0</code><br>Measured at Step 3. WAF must sustain target throughput without dropping below 5000 RPS.</p></div>
<div class="method-card"><h4>PERF-03: Memory Footprint (3 pts)</h4><p><code>Binary: Peak RSS &lt; 100MB → 3; else 0</code><br>Measured across all 4 load test steps via <code>/proc/{pid}/status</code> VmRSS sampling every 5s.</p></div>
<div class="method-card"><h4>PERF-04: Graceful Degradation (2 pts)</h4><p><code>Binary: No crash AND Error rate &lt; 5% at 10000 RPS → 2; else 0</code><br>Measured at Step 4 (STRESS TEST). WAF must not crash and keep error rate under 5%.</p></div>
</div></div>`)

	// ═══ BASELINE LATENCY ═══
	if r.Baseline != nil && !r.BaselineFailed {
		sb.WriteString(fmt.Sprintf(`
<div class="section"><h2>📊 Baseline Latency (Direct to UPSTREAM :9000)</h2>
<p style="color:var(--muted);font-size:.85rem;margin-bottom:12px;">%d total samples — direct requests to UPSTREAM bypassing WAF. Used to compute WAF overhead.</p>
<div class="table-wrap"><table>
<thead><tr><th>Class</th><th>Endpoints</th><th>P50 (ms)</th><th>P99 (ms)</th><th>Avg (ms)</th><th>Samples</th></tr></thead><tbody>`,
			r.Baseline.TotalSamples))
		for _, cls := range r.Baseline.Classes {
			sb.WriteString(fmt.Sprintf(`<tr><td style="font-weight:600;">%s</td><td style="font-family:monospace;">%s</td><td>%.3f</td><td>%.3f</td><td>%.3f</td><td>%d</td></tr>`,
				html.EscapeString(cls.Name), html.EscapeString(strings.Join(cls.Endpoints, ", ")),
				cls.P50Ms, cls.P99Ms, cls.AvgMs, cls.Samples))
		}
		sb.WriteString(`</tbody></table></div></div>`)
	} else {
		sb.WriteString(`<div class="section"><h2>📊 Baseline Latency</h2><p style="color:var(--yellow);">⚠️ Baseline measurement failed or skipped — WAF overhead cannot be computed</p></div>`)
	}

	// ═══ WAF LATENCY ═══
	if r.WAFLatency != nil {
		sb.WriteString(fmt.Sprintf(`
<div class="section"><h2>🛡️ WAF Latency (Through WAF-PROXY :8080)</h2>
<p style="color:var(--muted);font-size:.85rem;margin-bottom:12px;">%d total samples — requests through WAF proxy. Overhead = WAF latency − Baseline latency.</p>
<div class="table-wrap"><table>
<thead><tr><th>Class</th><th>P50 (ms)</th><th>P99 (ms)</th><th>Avg (ms)</th><th>Overhead P50</th><th>Overhead P99</th><th>Overhead %%</th></tr></thead><tbody>`,
			r.WAFLatency.TotalSamples))
		for _, cls := range r.WAFLatency.Classes {
			overheadCls := ""
			if cls.OverheadP99 > 5.0 {
				overheadCls = ` style="color:var(--red);font-weight:700;"`
			}
			sb.WriteString(fmt.Sprintf(`<tr><td style="font-weight:600;">%s</td><td>%.3f</td><td>%.3f</td><td>%.3f</td><td%s>%.3f ms</td><td%s>%.3f ms</td><td>%.1f%%</td></tr>`,
				html.EscapeString(cls.Name), cls.P50Ms, cls.P99Ms, cls.AvgMs,
				overheadCls, cls.OverheadP50,
				overheadCls, cls.OverheadP99,
				cls.OverheadPct))
		}
		sb.WriteString(`</tbody></table>
<details style="margin:12px 0 0;"><summary>🔄 Reproduce — Baseline Measurement (Go)</summary>
<pre class="curl-cmd">// Save as reproduce_baseline.go, then: go run reproduce_baseline.go
// Mirrors benchmark tool's measureBaselineLatency() exactly.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"
)

func main() {
	baseURL := "http://127.0.0.1:9000"
	if v := os.Getenv("UPSTREAM_URL"); v != "" { baseURL = v }

	type cls struct {
		Name  string
		EPs   []string
		Samps int
	}
	classes := []cls{
		{"critical", []string{"/login", "/deposit", "/withdraw"}, 150},
		{"high", []string{"/api/profile", "/game/list"}, 100},
		{"medium", []string{"/static/js/app.js", "/static/css/style.css", "/api/transactions"}, 100},
		{"catch_all", []string{"/health", "/"}, 100},
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, c := range classes {
		var lats []float64
		perEP := c.Samps / len(c.EPs)
		for _, ep := range c.EPs {
			for i := 0; i < perEP; i++ {
				t0 := time.Now()
				resp, _ := client.Get(baseURL + ep)
				lats = append(lats, float64(time.Since(t0).Nanoseconds())/1e6)
				if resp != nil { io.Copy(io.Discard, resp.Body); resp.Body.Close() }
			}
		}
		sort.Float64s(lats)
		n := len(lats)
		sum := 0.0
		for _, l := range lats { sum += l }
		fmt.Printf("%-10s Samples:%-4d P50:%.3fms P99:%.3fms Avg:%.3fms\n",
			c.Name, n, lats[n*50/100], lats[n*99/100], sum/float64(n))
	}
}</pre>
</details>
<details style="margin:8px 0 0;"><summary>🔄 Reproduce — WAF Latency Measurement (Go)</summary>
<pre class="curl-cmd">// Save as reproduce_waf_latency.go, then: go run reproduce_waf_latency.go
// Mirrors benchmark tool: baseline → WAF → overhead → PERF-01 check.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"
)

type cls struct {
	Name  string
	EPs   []string
	Samps int
}

var classes = []cls{
	{"critical", []string{"/login", "/deposit", "/withdraw"}, 150},
	{"high", []string{"/api/profile", "/game/list"}, 100},
	{"medium", []string{"/static/js/app.js", "/static/css/style.css", "/api/transactions"}, 100},
	{"catch_all", []string{"/health", "/"}, 100},
}

func measure(client *http.Client, base string, c cls) (p50, p99, avg float64, n int) {
	var lats []float64
	perEP := c.Samps / len(c.EPs)
	for _, ep := range c.EPs {
		for i := 0; i < perEP; i++ {
			t0 := time.Now()
			resp, _ := client.Get(base + ep)
			lats = append(lats, float64(time.Since(t0).Nanoseconds())/1e6)
			if resp != nil { io.Copy(io.Discard, resp.Body); resp.Body.Close() }
		}
	}
	n = len(lats)
	if n == 0 { return }
	sort.Float64s(lats)
	p50, p99 = lats[n*50/100], lats[n*99/100]
	sum := 0.0
	for _, l := range lats { sum += l }
	avg = sum / float64(n)
	return
}

func main() {
	wafURL := "http://127.0.0.1:8080"
	upURL := "http://127.0.0.1:9000"
	if v := os.Getenv("WAF_URL"); v != "" { wafURL = v }
	if v := os.Getenv("UPSTREAM_URL"); v != "" { upURL = v }

	client := &http.Client{Timeout: 10 * time.Second}

	fmt.Println("=== BASELINE (Direct → UPSTREAM) ===")
	type res struct {
		Name          string
		BP50, BP99, BAvg float64
		WP50, WP99, WAvg float64
	}
	var results []res
	for _, c := range classes {
		bp50, bp99, bavg, _ := measure(client, upURL, c)
		fmt.Printf("  %-10s P50:%.3fms P99:%.3fms Avg:%.3fms\n", c.Name, bp50, bp99, bavg)
		results = append(results, res{Name: c.Name, BP50: bp50, BP99: bp99, BAvg: bavg})
	}

	fmt.Println("\n=== WAF LATENCY (Through WAF → UPSTREAM) ===")
	for i, c := range classes {
		wp50, wp99, wavg, _ := measure(client, wafURL, c)
		results[i].WP50, results[i].WP99, results[i].WAvg = wp50, wp99, wavg
		fmt.Printf("  %-10s P50:%.3fms P99:%.3fms Avg:%.3fms\n", c.Name, wp50, wp99, wavg)
	}

	fmt.Println("\n=== OVERHEAD (WAF − Baseline) ===")
	totalOverhead := 0.0
	for _, r := range results {
		dP99 := r.WP99 - r.BP99
		ovPct := 0.0
		if r.BAvg > 0 { ovPct = (r.WAvg - r.BAvg) / r.BAvg * 100 }
		fmt.Printf("  %-10s ΔP50:%+.3fms ΔP99:%+.3fms Overhead:%+.1f%%\n",
			r.Name, r.WP50-r.BP50, dP99, ovPct)
		totalOverhead += dP99
	}
	avgOv := totalOverhead / float64(len(results))
	fmt.Printf("\n  Average ΔP99: %+.3fms\n", avgOv)
	if avgOv <= 5.0 {
		fmt.Println("  PERF-01: PASS ✓ (≤ 5ms)")
	} else {
		fmt.Println("  PERF-01: FAIL ✗ (> 5ms)")
	}
}</pre>
</details>
</div>`)
	}

	// ═══ LOAD TEST STEPS ═══
	sb.WriteString(`<div class="section"><h2>⚙️ Load Test Steps — Blended Traffic</h2>
<p style="color:var(--muted);font-size:.85rem;margin-bottom:16px;">4 sequential load steps with blended traffic (60% Legit / 10% Suspicious / 10% Exploit / 10% Abuse / 10% DDoS). DDoS bursts every 10s for 2s at ≥1000 RPS. Memory sampled every 5s.</p>`)

	// Traffic mix explanation
	sb.WriteString(buildTrafficMixTable())

	stepConfigs := GetLoadTestSteps()
	for i, step := range r.LoadTestSteps {
		cfg := stepConfigs[i]
		markerHTML := ""
		if cfg.Marker != "" {
			markerHTML = fmt.Sprintf(` <span class="badge badge-%s">%s</span>`,
				map[int]string{3: "warn", 4: "fail"}[step.StepNum], html.EscapeString(cfg.Marker))
		}

		passIcon := "✅"
		passCls := "badge-pass"
		resultLabel := "PASS"
		scoreCls := "pass"
		if !step.Passed {
			passIcon = "❌"
			passCls = "badge-fail"
			resultLabel = "FAIL"
			scoreCls = "fail"
		}

		sb.WriteString(fmt.Sprintf(`
<div class="vuln-card">
<div class="vuln-card-header">
<span>%s</span><span class="vuln-id">Step %d</span><span class="vuln-name">%d RPS × %ds%s</span>
<span class="badge %s" style="margin-left:auto;">%s</span>
</div>
<div class="vuln-card-body">
<div class="vuln-meta">
<div><span class="ml">Target RPS:</span><span class="mv">%d</span></div>
<div><span class="ml">Actual RPS:</span><span class="mv">%.1f</span></div>
<div><span class="ml">Total Requests:</span><span class="mv">%d</span></div>
<div><span class="ml">Success Rate:</span><span class="mv">%.2f%%</span></div>
<div><span class="ml">Error Rate:</span><span class="mv" style="color:%s;">%.2f%%</span></div>
<div><span class="ml">Blocked Rate:</span><span class="mv">%.2f%%</span></div>
<div><span class="ml">False Positives:</span><span class="mv">%d</span></div>
<div><span class="ml">Collateral Blocks:</span><span class="mv">%d</span></div>
</div>
<div class="perf-row">
<div class="perf-item"><span class="pl">⏱️ P50 Latency:</span><span class="pv">%.3fms</span></div>
<div class="perf-item %s"><span class="pl">⏱️ P99 Latency:</span><span class="pv">%.3fms</span></div>
<div class="perf-item"><span class="pl">⏱️ Max Latency:</span><span class="pv">%.3fms</span></div>
<div class="perf-item %s"><span class="pl">💾 Memory Peak:</span><span class="pv">%.1f MB</span></div>
<div class="perf-item"><span class="pl">⚡ DDoS Bursts:</span><span class="pv">%d</span></div>
</div>`,
			passIcon, step.StepNum, step.TargetRPS, step.DurationSec, markerHTML,
			passCls, resultLabel,
			step.TargetRPS, step.ActualRPS,
			step.TotalRequests,
			step.SuccessRate*100,
			map[bool]string{true: "var(--green)", false: "var(--red)"}[step.ErrorRate < 0.05], step.ErrorRate*100,
			step.BlockedRate*100,
			step.FPCount, step.CollateralCount,
			step.P50Ms,
			map[bool]string{true: "risk-in", false: "risk-out"}[step.P99Ms <= 5.0], step.P99Ms,
			step.MaxMs,
			map[bool]string{true: "risk-in", false: "risk-out"}[step.MemoryPeakMB < 100], step.MemoryPeakMB,
			step.DDoSBurstsTriggered,
		))

		// Scoring explanation for this step
		scoringLines := buildStepScoringExplanation(&step, &r)
		sb.WriteString(fmt.Sprintf(`<div class="scoring-explain %s">%s</div>`, scoreCls, scoringLines))

		// PERF checks for steps 3 and 4
		if step.StepNum == 3 {
			perf01 := r.Scoring["PERF-01"]
			perf02 := r.Scoring["PERF-02"]
			sb.WriteString(fmt.Sprintf(`
<details open><summary>📊 PERF-01 &amp; PERF-02 Evaluation</summary>
<div style="padding:12px 16px;font-size:0.85rem;">
<div style="margin:4px 0;"><strong>PERF-01</strong> — p99 Latency ≤ 5ms: %s → <span style="color:%s;font-weight:700;">%s</span> (%.3fms vs threshold %.0fms)</div>
<div style="margin:4px 0;"><strong>PERF-02</strong> — Sustained Throughput ≥ 5000 RPS: %s → <span style="color:%s;font-weight:700;">%s</span> (%.1f RPS vs threshold %.0f RPS)</div>
<div style="margin-top:8px;color:var(--muted);font-size:0.8rem;">%s</div>
</div>
</details>`,
				map[bool]string{true: "measured", false: "measured"}[perf01.Pass],
				map[bool]string{true: "var(--green)", false: "var(--red)"}[perf01.Pass],
				map[bool]string{true: "PASS ✓", false: "FAIL ✗"}[perf01.Pass],
				perf01.Measured, perf01.Threshold,
				map[bool]string{true: "measured", false: "measured"}[perf02.Pass],
				map[bool]string{true: "var(--green)", false: "var(--red)"}[perf02.Pass],
				map[bool]string{true: "PASS ✓", false: "FAIL ✗"}[perf02.Pass],
				perf02.Measured, perf02.Threshold,
				html.EscapeString(perf01.Explanation+" | "+perf02.Explanation),
			))
		}

		if step.StepNum == 4 {
			perf04 := r.Scoring["PERF-04"]
			sb.WriteString(fmt.Sprintf(`
<details open><summary>📊 PERF-04 Evaluation — Graceful Degradation</summary>
<div style="padding:12px 16px;font-size:0.85rem;">
<div style="margin:4px 0;"><strong>PERF-04</strong> — No Crash + Error &lt; 5%% at 10k RPS: → <span style="color:%s;font-weight:700;">%s</span></div>
<div style="margin:4px 0;">Crash detected: <span style="color:%s;">%v</span> | Error rate: %.2f%% (threshold: 5%%)</div>
<div style="margin-top:8px;color:var(--muted);font-size:0.8rem;">%s</div>
</div>
</details>`,
				map[bool]string{true: "var(--green)", false: "var(--red)"}[perf04.Pass],
				map[bool]string{true: "PASS ✓", false: "FAIL ✗"}[perf04.Pass],
				map[bool]string{true: "var(--green)", false: "var(--red)"}[!r.WAFCrashed],
				r.WAFCrashed,
				step.ErrorRate*100,
				html.EscapeString(perf04.Explanation),
			))
		}

		// Fail reason
		if !step.Passed && step.FailReason != "" {
			sb.WriteString(fmt.Sprintf(`<div class="fail-reason">❌ %s</div>`, html.EscapeString(step.FailReason)))
		}

		// Reproduce script
		reproduceScript := buildStepReproduceScript(step.StepNum, step.TargetRPS, step.DurationSec, r.WAFTarget)
		sb.WriteString(fmt.Sprintf(`
<details style="margin-top:12px;"><summary>🔄 Reproduce — Step %d Load Test</summary>
<pre class="curl-cmd">%s</pre>
</details>`,
			step.StepNum, html.EscapeString(reproduceScript)))

		sb.WriteString(`</div></div>`)
	}
	sb.WriteString(`</div>`)

	// ═══ FALSE POSITIVE ANALYSIS ═══
	sb.WriteString(fmt.Sprintf(`
<div class="section"><h2>🔍 False Positive Analysis</h2>
<div class="perf-row" style="margin-bottom:16px;">
<div class="perf-item"><span class="pl">Total Legitimate Requests:</span><span class="pv">%d</span></div>
<div class="perf-item %s"><span class="pl">False Positives:</span><span class="pv">%d</span></div>
<div class="perf-item"><span class="pl">Collaterals (DDoS):</span><span class="pv">%d</span></div>
<div class="perf-item %s"><span class="pl">FP Rate:</span><span class="pv">%.3f%%</span></div>
</div>`,
		totalLegitFromReport(r),
		map[bool]string{true: "risk-in", false: "risk-out"}[r.FPCount == 0], r.FPCount,
		r.CollateralCount,
		map[bool]string{true: "risk-in", false: "risk-out"}[r.FPRate < 0.01], r.FPRate*100,
	))

	if len(r.FPDetails) > 0 {
		sb.WriteString(`<p style="color:var(--muted);font-size:0.85rem;margin:12px 0 8px;">Sample False Positive Incidents (legitimate requests incorrectly blocked by WAF):</p>`)
		sb.WriteString(`<div class="table-wrap"><table><thead><tr><th>#</th><th>Endpoint</th><th>HTTP Status</th><th>WAF Action</th><th>Risk Score</th><th>Latency</th><th>During DDoS?</th></tr></thead><tbody>`)
		for i, fp := range r.FPDetails {
			if i >= 15 {
				sb.WriteString(fmt.Sprintf(`<tr><td colspan="7" style="color:var(--muted);">... and %d more</td></tr>`, len(r.FPDetails)-15))
				break
			}
			ddsTag := "No"
			ddsCls := ""
			if fp.DuringDDoS {
				ddsTag = "Yes ⚡"
				ddsCls = ` style="color:var(--yellow);"`
			}
			sb.WriteString(fmt.Sprintf(`<tr><td>%d</td><td style="font-family:monospace;">%s</td><td>%d</td><td>%s</td><td>%d</td><td>%.2fms</td><td%s>%s</td></tr>`,
				i+1, html.EscapeString(fp.Endpoint), fp.StatusCode,
				html.EscapeString(fp.WAFAction), fp.RiskScore, fp.LatencyMs, ddsCls, ddsTag))
		}
		sb.WriteString(`</tbody></table></div>`)
	}

	sb.WriteString(`
<details style="margin-top:12px;"><summary>🧪 How BTC Validates False Positives</summary>
<pre class="curl-cmd"># Replay a legitimate request through WAF and check if blocked
curl -s -o /dev/null -w "HTTP %%{http_code} | WAF-Action: %%header{X-WAF-Action}" \
  --interface 127.0.0.200 \
  http://127.0.0.1:8080/game/list
# Expected: HTTP 200 with X-WAF-Action: allow (or absent)
# False Positive if: HTTP 403 or X-WAF-Action: block on legitimate endpoint</pre>
</details>
</div>`)

	// ═══ SCORING SUMMARY TABLE ═══
	sb.WriteString(`
<div class="section"><h2>🏆 Scoring Summary — Phase C</h2>
<div class="table-wrap"><table>
<thead><tr><th>Criterion</th><th>Description</th><th>Measured</th><th>Threshold</th><th>Result</th><th>Points</th></tr></thead><tbody>`)

	criteria := []struct {
		id, desc string
	}{
		{"PERF-01", "p99 Latency ≤ 5ms at 5000 RPS"},
		{"PERF-02", "Sustained Throughput ≥ 5000 RPS"},
		{"PERF-03", "Memory Peak < 100MB"},
		{"PERF-04", "No Crash + Error < 5% at 10000 RPS"},
	}
	for _, c := range criteria {
		sc, ok := r.Scoring[c.id]
		if !ok {
			continue
		}
		resultCls := "badge-pass"
		resultLabel := "PASS"
		measuredStr := fmt.Sprintf("%.3f", sc.Measured)
		thresholdStr := fmt.Sprintf("%.0f", sc.Threshold)
		if c.id == "PERF-02" {
			measuredStr = fmt.Sprintf("%.1f RPS", sc.Measured)
			thresholdStr = fmt.Sprintf("%.0f RPS", sc.Threshold)
		} else if c.id == "PERF-03" {
			measuredStr = fmt.Sprintf("%.1f MB", sc.Measured)
			thresholdStr = fmt.Sprintf("%.0f MB", sc.Threshold)
		} else if c.id == "PERF-04" {
			measuredStr = fmt.Sprintf("%.2f%%", sc.Measured*100)
			thresholdStr = fmt.Sprintf("<%.0f%%", sc.Threshold*100)
		} else {
			measuredStr = fmt.Sprintf("%.3f ms", sc.Measured)
			thresholdStr = fmt.Sprintf("≤%.0f ms", sc.Threshold)
		}
		if !sc.Pass {
			resultCls = "badge-fail"
			resultLabel = "FAIL"
		}
		sb.WriteString(fmt.Sprintf(`<tr><td style="font-weight:700;">%s</td><td>%s</td><td>%s</td><td>%s</td><td><span class="badge %s">%s</span></td><td style="font-weight:700;">%.0f / %.0f</td></tr>`,
			c.id, c.desc, measuredStr, thresholdStr, resultCls, resultLabel, sc.Points, sc.MaxPoints))
	}

	// Total row
	totalCls := "var(--green)"
	if r.PhaseCTotal < 15 {
		totalCls = "var(--yellow)"
	}
	if r.PhaseCTotal < 5 {
		totalCls = "var(--red)"
	}
	sb.WriteString(fmt.Sprintf(`<tr style="background:rgba(59,130,246,0.06);"><td colspan="5" style="font-weight:700;text-align:right;">PHASE C TOTAL</td><td style="font-weight:800;font-size:1.1rem;color:%s;">%.0f / %.0f</td></tr>`,
		totalCls, r.PhaseCTotal, r.PhaseCMax))
	sb.WriteString(`</tbody></table></div></div>`)

	// PERF-* interpretation for failed criteria
	sb.WriteString(buildPERFInterpretation(&r))

	// ═══ TIMESERIES ═══
	if len(r.ThroughputTS) > 0 || len(r.MemoryTS) > 0 {
		sb.WriteString(`<div class="section"><h2>📈 Time Series Data</h2>`)
		if len(r.ThroughputTS) > 0 {
			sb.WriteString(`<details open><summary>Throughput (RPS) over time</summary><pre>`)
			for _, ts := range r.ThroughputTS {
				sb.WriteString(fmt.Sprintf("T+%3ds: %8.1f RPS\n", ts.TimestampSec, ts.ActualRPS))
			}
			sb.WriteString(`</pre></details>`)
		}
		if len(r.MemoryTS) > 0 {
			sb.WriteString(`<details open><summary>Memory (MB) over time</summary><pre>`)
			for _, ms := range r.MemoryTS {
				sb.WriteString(fmt.Sprintf("T+%3ds: %8.1f MB\n", ms.TimestampSec, ms.MemoryMB))
			}
			sb.WriteString(`</pre></details>`)
		}
		sb.WriteString(`</div>`)
	}

	// ═══ FOOTER ═══
	sb.WriteString(fmt.Sprintf(`
<div class="footer">
WAF Benchmark Tool v2.7 | Phase C — Performance &amp; Throughput Tests<br>
Report generated: %s | Duration: %dms<br>
Scoring per <a href="#">phase_C.md §5.2</a> | <a href="#">VN_waf_interop_contract_v2.3.md</a>
</div>
</div></body></html>`, html.EscapeString(r.Timestamp), r.DurationMs))

	return sb.String()
}

// ── Scoring Explanation Builder ──

func buildStepScoringExplanation(step *CLoadTestStepJSON, r *PhaseCReport) string {
	var lines []string
	lines = append(lines, fmt.Sprintf("Step %d: %d RPS × %ds — Scoring Analysis", step.StepNum, step.TargetRPS, step.DurationSec))
	lines = append(lines, "")

	// Load test cfg
	cfgs := GetLoadTestSteps()
	cfg := cfgs[step.StepNum-1]

	if cfg.Marker != "" {
		lines = append(lines, fmt.Sprintf("  Purpose: %s", cfg.Purpose))
		lines = append(lines, "")
	}

	// Basic metrics
	lines = append(lines, fmt.Sprintf("  Actual Throughput: %.1f RPS (target: %d RPS)", step.ActualRPS, step.TargetRPS))
	lines = append(lines, fmt.Sprintf("  Total Requests:    %d", step.TotalRequests))
	lines = append(lines, fmt.Sprintf("  Success Rate:      %.2f%% (%d/%d)", step.SuccessRate*100, step.SuccessCount, step.TotalRequests))
	lines = append(lines, fmt.Sprintf("  Error Rate:        %.2f%% (%d errors)", step.ErrorRate*100, step.ErrorCount))
	lines = append(lines, fmt.Sprintf("  Blocked Rate:      %.2f%% (%d blocked)", step.BlockedRate*100, step.BlockedCount))
	lines = append(lines, "")

	// Latency
	lines = append(lines, fmt.Sprintf("  P50 Latency:       %.3f ms", step.P50Ms))
	lines = append(lines, fmt.Sprintf("  P99 Latency:       %.3f ms", step.P99Ms))
	lines = append(lines, fmt.Sprintf("  Max Latency:       %.3f ms", step.MaxMs))
	lines = append(lines, "")

	// Memory
	lines = append(lines, fmt.Sprintf("  Memory Peak:       %.1f MB", step.MemoryPeakMB))
	lines = append(lines, "")

	// FP
	lines = append(lines, fmt.Sprintf("  False Positives:   %d (outside DDoS bursts)", step.FPCount))
	lines = append(lines, fmt.Sprintf("  Collateral Blocks: %d (during DDoS bursts)", step.CollateralCount))
	lines = append(lines, "")

	// Step-specific evaluation
	if step.StepNum == 3 {
		perf01, _ := r.Scoring["PERF-01"]
		perf02, _ := r.Scoring["PERF-02"]
		lines = append(lines, "── PERF-01 & PERF-02 Evaluation (SLA TARGET) ──")
		if perf01.Pass {
			lines = append(lines, fmt.Sprintf("  ✓ PERF-01 PASS: p99 (%.3fms) ≤ 5ms → +10 pts", perf01.Measured))
		} else {
			lines = append(lines, fmt.Sprintf("  ✗ PERF-01 FAIL: p99 (%.3fms) > 5ms → 0 pts", perf01.Measured))
		}
		if perf02.Pass {
			lines = append(lines, fmt.Sprintf("  ✓ PERF-02 PASS: throughput (%.1f RPS) ≥ 5000 RPS → +5 pts", perf02.Measured))
		} else {
			lines = append(lines, fmt.Sprintf("  ✗ PERF-02 FAIL: throughput (%.1f RPS) < 5000 RPS → 0 pts", perf02.Measured))
		}
	}

	if step.StepNum == 4 {
		perf04, _ := r.Scoring["PERF-04"]
		lines = append(lines, "── PERF-04 Evaluation (STRESS TEST) ──")
		if perf04.Pass {
			lines = append(lines, fmt.Sprintf("  ✓ PERF-04 PASS: no crash + error rate %.2f%% < 5%% → +2 pts", step.ErrorRate*100))
		} else {
			if r.WAFCrashed {
				lines = append(lines, "  ✗ PERF-04 FAIL: WAF crashed during step 4 → 0 pts")
			} else {
				lines = append(lines, fmt.Sprintf("  ✗ PERF-04 FAIL: error rate %.2f%% ≥ 5%% → 0 pts", step.ErrorRate*100))
			}
		}
	}

	// Step overall
	if step.Passed {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("  Step Result: PASS ✓ (error rate %.2f%% < 5%%)", step.ErrorRate*100))
	} else {
		lines = append(lines, "")
		lines = append(lines, fmt.Sprintf("  Step Result: FAIL ✗ — %s", step.FailReason))
	}

	return strings.Join(lines, "\n")
}

// ── Reproduce Script Builder ──

func buildStepReproduceScript(stepNum, targetRPS, durationSec int, wafBaseURL string) string {
	return fmt.Sprintf(`// Save as reproduce_step%d.go, then: go run reproduce_step%d.go
// Mirrors benchmark tool: blended traffic load test at %d RPS for %ds.
package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	wafURL := "%s"
	if v := os.Getenv("WAF_URL"); v != "" { wafURL = v }

	targetRPS := %d
	durationSec := %d
	fmt.Printf("=== STEP %d: %%d RPS x %%ds ===\n", targetRPS, durationSec)
	fmt.Printf("WAF: %%s\n\n", wafURL)

	legitPaths := []string{"/","/health","/game/list","/api/transactions","/api/profile","/user/settings"}
	abusePaths := []string{"/admin/config","/wp-admin","/.env","/config.php"}
	exploits := []string{
		`+"`"+`{"username":"admin' OR 1=1--","password":"x"}`+"`"+`,
		`+"`"+`{"username":"<script>alert(1)</script>","password":"x"}`+"`"+`,
	}

	client := &http.Client{Timeout: 10 * time.Second}
	var (
		ok, errs, blocked int64
		lats              []float64
		mu                sync.Mutex
	)

	interval := time.Second / time.Duration(targetRPS)
	if interval < 1 { interval = 1 }
	deadline := time.Now().Add(time.Duration(durationSec) * time.Second)

	var wg sync.WaitGroup
	workers := 20
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				method, path, body := "GET", "/", ""
				r := rand.Float64()
				switch {
				case r < 0.60:
					path = legitPaths[rand.Intn(len(legitPaths))]
				case r < 0.70:
					method = "POST"; path = "/login"
					body = `+"`"+`{"username":"test","password":"wrong"}`+"`"+`
				case r < 0.80:
					method = "POST"; path = "/login"
					body = exploits[rand.Intn(len(exploits))]
				case r < 0.90:
					path = abusePaths[rand.Intn(len(abusePaths))]
				}

				t0 := time.Now()
				var resp *http.Response
				var err error
				if method == "POST" {
					resp, err = client.Post(wafURL+path, "application/json", strings.NewReader(body))
				} else {
					resp, err = client.Get(wafURL + path)
				}
				lat := float64(time.Since(t0).Nanoseconds()) / 1e6

				mu.Lock()
				lats = append(lats, lat)
				mu.Unlock()

				if err != nil {
					atomic.AddInt64(&errs, 1)
				} else {
					if resp.StatusCode == 403 || resp.StatusCode == 429 {
						atomic.AddInt64(&blocked, 1)
					}
					atomic.AddInt64(&ok, 1)
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				time.Sleep(interval)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	sort.Float64s(lats)
	n := len(lats)
	p50, p99 := 0.0, 0.0
	if n > 0 { p50, p99 = lats[n*50/100], lats[n*99/100] }
	mu.Unlock()

	total := ok + errs
	eRate := 0.0
	if total > 0 { eRate = float64(errs)/float64(total)*100 }

	fmt.Println("\n=== RESULTS ===")
	fmt.Printf("Total: %%d  Success: %%d  Errors: %%d  Blocked: %%d\n", total, ok, errs, blocked)
	fmt.Printf("Error Rate: %%.2f%%%%  P50: %%.3fms  P99: %%.3fms\n", eRate, p50, p99)
	if eRate < 5.0 { fmt.Println("PERF-04: PASS") } else { fmt.Println("PERF-04: FAIL") }
}`, stepNum, stepNum, targetRPS, durationSec, wafBaseURL, targetRPS, durationSec, stepNum)
}

func totalLegitFromReport(r PhaseCReport) int {
	total := 0
	for _, s := range r.LoadTestSteps {
		total += s.TotalRequests
	}
	return total
}
