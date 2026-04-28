package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
)

func WriteJSONReport(report *PhaseDReport, outputPath string) error {
	if report == nil {
		return fmt.Errorf("report is nil")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}

func WriteHTMLReport(report *PhaseDReport, outputPath string) error {
	if report == nil {
		return fmt.Errorf("report is nil")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	view := htmlViewModel{Report: report}
	for _, id := range report.CaseOrder {
		c := report.Cases[id]
		view.Cases = append(view.Cases, htmlCaseView{
			Case:         c,
			EvidenceJSON: prettyEvidence(c.Evidence),
			VerdictClass: verdictClass(c.Passed),
		})
	}
	view.BannerClass = verdictClass(report.PhaseDSummary.Pass)
	view.GeneratedAt = report.Metadata.GeneratedAt.Local().Format("2006-01-02 15:04:05 MST")

	tpl, err := template.New("phase_d_html").Parse(phaseDHTMLTemplate)
	if err != nil {
		return fmt.Errorf("parse html template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create html report: %w", err)
	}
	defer f.Close()

	if err := tpl.Execute(f, view); err != nil {
		return fmt.Errorf("render html report: %w", err)
	}
	return nil
}

type htmlViewModel struct {
	Report      *PhaseDReport
	Cases       []htmlCaseView
	BannerClass string
	GeneratedAt string
}

type htmlCaseView struct {
	Case         CaseReport
	EvidenceJSON string
	VerdictClass string
}

func verdictClass(passed bool) string {
	if passed {
		return "pass"
	}
	return "fail"
}

func prettyEvidence(v map[string]interface{}) string {
	if v == nil {
		return "{}"
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{\n  \"error\": \"unable to marshal evidence\"\n}"
	}
	return string(b)
}

const phaseDHTMLTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Phase D Report</title>
  <style>
    :root { --bg:#0b1020; --panel:#11182e; --text:#e6ebff; --muted:#9fb0e6; --ok:#18b26b; --bad:#ea5455; --border:#243055; --accent:#7aa2ff; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--bg); color:var(--text); font-family: Inter,Segoe UI,Arial,sans-serif; }
    .wrap { max-width:1200px; margin:0 auto; padding:20px; }
    .card { background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:16px; margin-bottom:16px; }
    .banner { display:flex; justify-content:space-between; align-items:center; gap:12px; }
    .badge { padding:8px 12px; border-radius:999px; font-weight:700; }
    .pass .badge { background:rgba(24,178,107,.15); color:#8df0be; border:1px solid rgba(24,178,107,.45); }
    .fail .badge { background:rgba(234,84,85,.15); color:#ffacac; border:1px solid rgba(234,84,85,.45); }
    h1,h2,h3 { margin:0 0 10px; }
    .meta { color:var(--muted); font-size:13px; line-height:1.6; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; }
    .kpi { border:1px solid var(--border); border-radius:10px; padding:10px; background:#0d1429; }
    .kpi .k { color:var(--muted); font-size:12px; }
    .kpi .v { font-size:20px; font-weight:700; margin-top:3px; }
    table { width:100%; border-collapse:collapse; font-size:14px; }
    th,td { border-bottom:1px solid var(--border); padding:10px; vertical-align:top; text-align:left; }
    th { color:var(--muted); font-weight:600; }
    .verdict.pass { color:#8df0be; font-weight:700; }
    .verdict.fail { color:#ffacac; font-weight:700; }
    .section-title { color:var(--accent); margin-bottom:8px; }
    .case-block { border:1px solid var(--border); border-radius:10px; padding:12px; margin-bottom:10px; background:#0d1429; }
    .label { font-size:12px; color:var(--muted); margin-bottom:4px; }
    pre { margin:0; overflow:auto; background:#070b16; color:#d8e2ff; border:1px solid #1f294d; border-radius:10px; padding:12px; font-size:12px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card banner {{.BannerClass}}">
      <div>
        <h1>Phase D — Resilience Detailed Report</h1>
        <div class="meta">Run: {{.Report.Metadata.RunID}} · Generated: {{.GeneratedAt}} · Tool: {{.Report.Metadata.Tool}} v{{.Report.Metadata.Version}}</div>
      </div>
      <div class="badge">{{if .Report.PhaseDSummary.Pass}}PHASE D PASS{{else}}PHASE D FAIL{{end}}</div>
    </div>

    <div class="card">
      <h2 class="section-title">Environment</h2>
      <div class="meta">Config: {{.Report.Metadata.ConfigPath}}<br/>Target: {{.Report.Metadata.TargetURL}}<br/>WAF: {{.Report.Metadata.WAFURL}}<br/>Duration: {{.Report.Metadata.DurationMs}} ms</div>
    </div>

    <div class="card">
      <h2 class="section-title">Score Summary</h2>
      <div class="grid">
        <div class="kpi"><div class="k">Cases</div><div class="v">{{.Report.PhaseDSummary.PassedCases}} / {{.Report.PhaseDSummary.TotalCases}}</div></div>
        <div class="kpi"><div class="k">Phase D Score</div><div class="v">{{printf "%.0f" .Report.PhaseDSummary.Score}} / {{printf "%.0f" .Report.PhaseDSummary.MaxScore}}</div></div>
        <div class="kpi"><div class="k">DDoS</div><div class="v">{{printf "%.0f" .Report.PhaseDSummary.DDoSScore}}</div></div>
        <div class="kpi"><div class="k">Backend</div><div class="v">{{printf "%.0f" .Report.PhaseDSummary.BackendScore}}</div></div>
        <div class="kpi"><div class="k">Fail-Mode</div><div class="v">{{printf "%.0f" .Report.PhaseDSummary.FailModeScore}}</div></div>
      </div>
    </div>

    <div class="card">
      <h2 class="section-title">Case Matrix (Expected vs Observed vs Verdict)</h2>
      <table>
        <thead>
          <tr><th>Case</th><th>Expected</th><th>Observed</th><th>Why PASS/FAIL</th><th>WAF Returned</th><th>Verdict</th></tr>
        </thead>
        <tbody>
          {{range .Cases}}
          <tr>
            <td><strong>{{.Case.TestID}}</strong><br/>{{.Case.Name}}</td>
            <td>{{.Case.Expected}}</td>
            <td>{{.Case.Observed}}</td>
            <td>{{.Case.Reason}}</td>
            <td>{{.Case.WAFFeedback}}</td>
            <td class="verdict {{.VerdictClass}}">{{if .Case.Passed}}PASS{{else}}FAIL{{end}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2 class="section-title">Post-PASS Quality Metrics (Workflow §4)</h2>
      <div class="meta">These metrics are tie-break/optimization signals after functional PASS/FAIL, matching workflow section 4.</div>
      <div class="grid" style="margin-top:10px;">
        <div class="kpi"><div class="k">Policy Consistency</div><div class="v">{{printf "%.3f" .Report.QualityMetrics.AccuracyDeterminism.PolicyConsistencyScore}}</div></div>
        <div class="kpi"><div class="k">Legit Success Under Attack</div><div class="v">{{printf "%.3f" .Report.QualityMetrics.ServiceContinuity.LegitSuccessRatioUnderAttack}}</div></div>
        <div class="kpi"><div class="k">Collateral Block Count</div><div class="v">{{.Report.QualityMetrics.ServiceContinuity.CollateralBlockCount}}</div></div>
        <div class="kpi"><div class="k">New Conn Accept Ratio</div><div class="v">{{printf "%.3f" .Report.QualityMetrics.ServiceContinuity.NewConnAcceptRatio}}</div></div>
        <div class="kpi"><div class="k">Recovery To Green (ms)</div><div class="v">{{printf "%.1f" .Report.QualityMetrics.RecoveryControl.RecoveryTimeToGreenMs}}</div></div>
        <div class="kpi"><div class="k">Config Apply Latency (ms)</div><div class="v">{{printf "%.1f" .Report.QualityMetrics.RecoveryControl.ConfigApplyLatencyMs}}</div></div>
      </div>

      <h3 style="margin-top:16px;">Latency Quality</h3>
      <table>
        <thead>
          <tr><th>Case</th><th>p50</th><th>p95</th><th>p99</th><th>max</th><th>stddev</th></tr>
        </thead>
        <tbody>
          {{range $id, $lat := .Report.QualityMetrics.LatencyQuality.ByCase}}
          <tr>
            <td>{{$id}}</td>
            <td>{{printf "%.1f" $lat.P50Ms}}</td>
            <td>{{printf "%.1f" $lat.P95Ms}}</td>
            <td>{{printf "%.1f" $lat.P99Ms}}</td>
            <td>{{printf "%.1f" $lat.MaxMs}}</td>
            <td>{{printf "%.1f" $lat.StdDevMs}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>

      <h3 style="margin-top:16px;">Accuracy & Determinism</h3>
      <table>
        <thead>
          <tr><th>Case</th><th>Status OK Ratio</th><th>Decision Flap Count</th></tr>
        </thead>
        <tbody>
          {{range $id, $ratio := .Report.QualityMetrics.AccuracyDeterminism.StatusOKRatioByCase}}
          <tr>
            <td>{{$id}}</td>
            <td>{{printf "%.3f" $ratio}}</td>
            <td>{{index $.Report.QualityMetrics.AccuracyDeterminism.DecisionFlapCountByCase $id}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2 class="section-title">Tie-Break Summary</h2>
      <div class="grid">
        <div class="kpi"><div class="k">Phase D Quality Score</div><div class="v">{{printf "%.3f" .Report.TieBreak.PhaseDQualityScore}}</div></div>
      </div>
      <h3 style="margin-top:16px;">Signals</h3>
      <table>
        <thead><tr><th>Signal</th><th>Value</th><th>Weight</th></tr></thead>
        <tbody>
          {{range $k, $v := .Report.TieBreak.Signals}}
          <tr>
            <td>{{$k}}</td>
            <td>{{printf "%.3f" $v}}</td>
            <td>{{printf "%.2f" (index $.Report.TieBreak.Weights $k)}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2 class="section-title">Evidence (raw benchmark artifacts)</h2>
      {{range .Cases}}
      <div class="case-block">
        <h3>{{.Case.TestID}} — {{.Case.Name}}</h3>
        <div class="label">Raw evidence JSON</div>
        <pre>{{.EvidenceJSON}}</pre>
      </div>
      {{end}}
    </div>
  </div>
</body>
</html>`

func sanitizeOneLine(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.Join(strings.Fields(s), " ")
}
