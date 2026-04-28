package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
)

func WriteJSONReport(report *PhaseEReport, outputPath string) error {
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

func WriteHTMLReport(report *PhaseEReport, outputPath string) error {
	if report == nil {
		return fmt.Errorf("report is nil")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	vm := htmlViewModel{Report: report}
	for _, id := range report.CaseOrder {
		c := report.Cases[id]
		vm.Cases = append(vm.Cases, htmlCaseView{
			Case:         c,
			EvidenceJSON: prettyEvidence(c.Evidence),
			VerdictClass: verdictClass(c.Passed),
		})
	}
	for _, p := range report.EndpointValidity.Probes {
		vm.Probes = append(vm.Probes, htmlProbeView{
			Probe:        p,
			VerdictClass: verdictClass(p.Reachable),
		})
	}
	vm.BannerClass = verdictClass(report.Summary.Pass)
	vm.GeneratedAt = report.Metadata.GeneratedAt.Local().Format("2006-01-02 15:04:05 MST")

	tpl, err := template.New("phase_e_html").Parse(phaseEHTMLTemplate)
	if err != nil {
		return fmt.Errorf("parse html template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create html report: %w", err)
	}
	defer f.Close()

	if err := tpl.Execute(f, vm); err != nil {
		return fmt.Errorf("render html report: %w", err)
	}
	return nil
}

type htmlViewModel struct {
	Report      *PhaseEReport
	Cases       []htmlCaseView
	Probes      []htmlProbeView
	BannerClass string
	GeneratedAt string
}

type htmlCaseView struct {
	Case         CaseReport
	EvidenceJSON string
	VerdictClass string
}

type htmlProbeView struct {
	Probe        EndpointProbe
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

const phaseEHTMLTemplate = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Phase E Caching Report</title>
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
        <h1>Phase E — Caching Correctness Report</h1>
        <div class="meta">Run: {{.Report.Metadata.RunID}} · Generated: {{.GeneratedAt}} · Tool: {{.Report.Metadata.Tool}} v{{.Report.Metadata.Version}}</div>
      </div>
      <div class="badge">{{if .Report.Summary.Pass}}PHASE E PASS{{else}}PHASE E FAIL{{end}}</div>
    </div>

    <div class="card">
      <h2 class="section-title">Environment</h2>
      <div class="meta">Config: {{.Report.Metadata.ConfigPath}}<br/>Target: {{.Report.Metadata.TargetURL}}<br/>WAF: {{.Report.Metadata.WAFURL}}<br/>Duration: {{.Report.Metadata.DurationMs}} ms</div>
    </div>

    <div class="card">
      <h2 class="section-title">Official PASS/FAIL (E01..E04)</h2>
      <div class="grid">
        <div class="kpi"><div class="k">Cases</div><div class="v">{{.Report.Summary.PassedCases}} / {{.Report.Summary.TotalCases}}</div></div>
        <div class="kpi"><div class="k">Score</div><div class="v">{{printf "%.0f" .Report.Summary.Score}} / {{printf "%.0f" .Report.Summary.MaxScore}}</div></div>
        <div class="kpi"><div class="k">Endpoint readiness</div><div class="v">{{.Report.Summary.EndpointReady}}</div></div>
      </div>
    </div>

    <div class="card">
      <h2 class="section-title">Endpoint Validity Check (Step 1)</h2>
      <table>
        <thead><tr><th>Base</th><th>Method</th><th>Path</th><th>Status</th><th>Latency</th><th>Server</th><th>CF-Ray</th><th>Reachable</th></tr></thead>
        <tbody>
          {{range .Probes}}
          <tr>
            <td>{{.Probe.BaseURL}}</td>
            <td>{{.Probe.Method}}</td>
            <td>{{.Probe.Path}}</td>
            <td>{{.Probe.StatusCode}}</td>
            <td>{{.Probe.LatencyMs}} ms</td>
            <td>{{.Probe.ServerHeader}}</td>
            <td>{{.Probe.CFRay}}</td>
            <td class="verdict {{.VerdictClass}}">{{.Probe.Reachable}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{if .Report.EndpointValidity.Notes}}
      <h3 style="margin-top:12px;">Notes</h3>
      <ul>
        {{range .Report.EndpointValidity.Notes}}<li>{{.}}</li>{{end}}
      </ul>
      {{end}}
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
            <td><strong>{{.Case.CaseID}}</strong><br/>{{.Case.Name}}</td>
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
      <h2 class="section-title">Tie-break Metrics (Workflow §5)</h2>
      <div class="grid">
        <div class="kpi"><div class="k">Phase E Quality Score</div><div class="v">{{printf "%.3f" .Report.TieBreak.PhaseEQualityScore}}</div></div>
        <div class="kpi"><div class="k">Critical Cache Violations</div><div class="v">{{.Report.QualityMetrics.Safety.CriticalCacheViolationCount}}</div></div>
        <div class="kpi"><div class="k">Auth Cache Violations</div><div class="v">{{.Report.QualityMetrics.Safety.AuthCacheViolationCount}}</div></div>
        <div class="kpi"><div class="k">Cache Acceleration Ratio</div><div class="v">{{printf "%.3f" .Report.QualityMetrics.CacheEfficiency.CacheAccelerationRatio}}</div></div>
      </div>
      <h3 style="margin-top:12px;">Ranking policy</h3>
      <ol>
        {{range .Report.TieBreak.RankingPolicy}}<li>{{.}}</li>{{end}}
      </ol>
    </div>

    <div class="card">
      <h2 class="section-title">Validation Checks (Step 4)</h2>
      <table>
        <thead><tr><th>ID</th><th>Expected</th><th>Observed</th><th>Passed</th></tr></thead>
        <tbody>
          {{range .Report.Validation.WorkflowChecks}}
          <tr><td>{{.ID}}</td><td>{{.Expected}}</td><td>{{.Observed}}</td><td class="verdict {{if .Passed}}pass{{else}}fail{{end}}">{{.Passed}}</td></tr>
          {{end}}
          {{range .Report.Validation.ReportChecks}}
          <tr><td>{{.ID}}</td><td>{{.Expected}}</td><td>{{.Observed}}</td><td class="verdict {{if .Passed}}pass{{else}}fail{{end}}">{{.Passed}}</td></tr>
          {{end}}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2 class="section-title">Evidence (raw benchmark artifacts)</h2>
      {{range .Cases}}
      <div class="case-block">
        <h3>{{.Case.CaseID}} — {{.Case.Name}}</h3>
        <div class="label">Raw evidence JSON</div>
        <pre>{{.EvidenceJSON}}</pre>
      </div>
      {{end}}
    </div>
  </div>
</body>
</html>`
