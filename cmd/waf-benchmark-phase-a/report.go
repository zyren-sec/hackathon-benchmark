// HTML Report Template Generator

package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ReportData struct for JSON serialization
type ReportData struct {
	Target           string                   `json:"target"`
	TargetProfile    string                   `json:"targetProfile"`
	TestDuration     string                   `json:"testDuration"`
	GeneratedAt      string                   `json:"generatedAt"`
	OverallScore     float64                  `json:"overallScore"`
	TotalScore       float64                  `json:"totalScore"`
	MaxPossibleScore float64                  `json:"maxPossibleScore"`
	Passed           int                      `json:"passed"`
	Failed           int                      `json:"failed"`
	TotalTests       int                      `json:"totalTests"`
	ScoreClass       string                   `json:"scoreClass"`
	PassClass        string                   `json:"passClass"`
	FailClass        string                   `json:"failClass"`
	CategoryScores   map[string]CategoryScore `json:"categoryScores"`
	Tests            []ReportTestData         `json:"tests"`
}

// ReportTestData for JSON serialization
type ReportTestData struct {
	ID               string `json:"id"`
	Category         string `json:"category"`
	Technique        string `json:"technique"`
	Severity         string `json:"severity"`
	Status           string `json:"status"`
	Score            string `json:"score"`
	MaxScore         string `json:"maxScore"`
	Duration         string `json:"duration"`
	Method           string `json:"method"`
	ResponseStatus   int    `json:"responseStatus"`
	Auth             bool   `json:"auth"`
	Timestamp        string `json:"timestamp"`
	AttackMode       string `json:"attackMode"`
	Payload          string `json:"payload"`
	OriginalPayload  string `json:"originalPayload"`
	Curl             string `json:"curl"`
	RawRequest       string `json:"rawRequest"`
	RawResponse      string `json:"rawResponse"`
	ReproductionScript string `json:"reproductionScript"`
	Response         string `json:"response"`
	ResponseHeaders  string `json:"responseHeaders"`
	Marker               string `json:"marker"`
	MainMarkerFound      bool   `json:"mainMarkerFound"`
	MainMarkerLocation   string `json:"mainMarkerLocation"`
	OtherExpectedPattern string `json:"otherExpectedPattern"`
	OtherMarker          string `json:"otherMarker"`
	OtherMarkerFound     bool   `json:"otherMarkerFound"`
	OtherMarkerLocation  string `json:"otherMarkerLocation"`
	MarkerFound          bool   `json:"markerFound"`
	MarkerFoundInBody    bool   `json:"markerFoundInBody"`
	MarkerFoundInHeader  bool   `json:"markerFoundInHeader"`
	StatusCompliant      bool   `json:"statusCompliant"`
	StatusEvidence       string `json:"statusEvidence"`
	Evidence             string `json:"evidence"`
}

// generateHTMLTemplate creates comprehensive HTML report with proper XSS protection
func generateHTMLTemplate(ts *TestSuiteResults) string {
	// Prepare data for the report
	data := prepareReportData(ts)

	// Serialize test data to JSON
	// json.Marshal automatically escapes special characters for JSON safety
	// XSS protection is handled by JavaScript escapeHtml() when rendering to DOM
	jsonData, err := json.Marshal(data.Tests)
	if err != nil {
		// Fallback: return error message in HTML
		return fmt.Sprintf("<html><body><h1>Error generating report: %s</h1></body></html>",
			escapeHtml(err.Error()))
	}

	// Safely embed JSON in <script> by escaping sequences that could break out
	// of the script context: </script>, <!-- , and U+2028/U+2029 line separators
	safeJSON := strings.ReplaceAll(string(jsonData), "</", "<\\/")
	safeJSON = strings.ReplaceAll(safeJSON, "<!--", "<\\!--")
	safeJSON = strings.ReplaceAll(safeJSON, "\u2028", "\\u2028")
	safeJSON = strings.ReplaceAll(safeJSON, "\u2029", "\\u2029")

	// Start building the HTML
	html := `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Benchmark Phase A - Security Effectiveness Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #3b82f6;
            --primary-dark: #2563eb;
            --primary-light: #dbeafe;
            --success: #10b981;
            --success-light: #d1fae5;
            --danger: #ef4444;
            --danger-light: #fee2e2;
            --warning: #f59e0b;
            --warning-light: #fef3c7;
            --info: #6366f1;
            --info-light: #e0e7ff;
            --gray-50: #f8fafc;
            --gray-100: #f1f5f9;
            --gray-200: #e2e8f0;
            --gray-300: #cbd5e1;
            --gray-400: #94a3b8;
            --gray-500: #64748b;
            --gray-600: #475569;
            --gray-700: #334155;
            --gray-800: #1e293b;
            --gray-900: #0f172a;
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --bg-tertiary: #f1f5f9;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --radius-sm: 4px;
            --radius: 6px;
            --radius-md: 8px;
            --radius-lg: 12px;
            --transition: all 0.15s cubic-bezier(0.4, 0, 0.2, 1);
        }

        [data-theme="dark"] {
            --gray-50: #0f172a;
            --gray-100: #1e293b;
            --gray-200: #334155;
            --gray-300: #475569;
            --gray-400: #64748b;
            --gray-500: #94a3b8;
            --gray-600: #cbd5e1;
            --gray-700: #e2e8f0;
            --gray-800: #f1f5f9;
            --gray-900: #f8fafc;
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #cbd5e1;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.3);
            --shadow: 0 1px 3px 0 rgb(0 0 0 / 0.4), 0 1px 2px -1px rgb(0 0 0 / 0.4);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.5), 0 2px 4px -2px rgb(0 0 0 / 0.5);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.5), 0 4px 6px -4px rgb(0 0 0 / 0.5);
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-secondary);
            color: var(--text-primary);
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
            font-size: 13px;
        }

        .app { display: flex; height: 100vh; overflow: hidden; }

        .sidebar {
            width: 240px;
            background: var(--bg-primary);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
        }
        .sidebar-header { padding: 16px; border-bottom: 1px solid var(--border-color); }
        .logo { display: flex; align-items: center; gap: 10px; }
        .logo-icon {
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, var(--primary) 0%, var(--info) 100%);
            border-radius: var(--radius);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
        }
        .logo-text { font-size: 14px; font-weight: 700; }
        .logo-subtext { font-size: 11px; color: var(--text-muted); }

        .nav-section { padding: 12px 0; }
        .nav-title {
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            padding: 0 16px;
            margin-bottom: 4px;
        }
        .nav-link {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 16px;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 13px;
            cursor: pointer;
            border-left: 2px solid transparent;
            transition: var(--transition);
        }
        .nav-link:hover { background: var(--bg-secondary); color: var(--text-primary); }
        .nav-link.active {
            background: var(--primary-light);
            color: var(--primary-dark);
            border-left-color: var(--primary);
        }
        [data-theme="dark"] .nav-link.active { background: rgba(59, 130, 246, 0.15); }
        .nav-icon { font-size: 14px; width: 18px; text-align: center; }
        .nav-badge {
            margin-left: auto;
            background: var(--danger);
            color: white;
            font-size: 10px;
            font-weight: 600;
            padding: 2px 6px;
            border-radius: 9999px;
        }

        .main { flex: 1; display: flex; flex-direction: column; min-width: 0; }

        .top-bar {
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            flex-shrink: 0;
        }
        .top-bar-left { display: flex; align-items: center; gap: 12px; flex: 1; }
        .breadcrumbs { font-size: 13px; color: var(--text-muted); }
        .breadcrumbs strong { color: var(--text-primary); }

        .search-box { position: relative; flex: 1; max-width: 400px; }
        .search-box input {
            width: 100%;
            padding: 8px 12px 8px 32px;
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 13px;
            transition: var(--transition);
        }
        .search-box input:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 2px var(--primary-light); }
        .search-icon { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); font-size: 14px; color: var(--text-muted); }

        .top-bar-right { display: flex; align-items: center; gap: 8px; }
        .btn-icon {
            width: 32px;
            height: 32px;
            border: 1px solid var(--border-color);
            background: var(--bg-primary);
            border-radius: var(--radius);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            color: var(--text-secondary);
            transition: var(--transition);
        }
        .btn-icon:hover { border-color: var(--primary); color: var(--primary); }
        .btn {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: var(--primary);
            color: white;
            border: none;
            border-radius: var(--radius);
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
        }
        .btn:hover { background: var(--primary-dark); }
        .btn-secondary {
            background: var(--bg-secondary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }
        .btn-secondary:hover { background: var(--bg-tertiary); border-color: var(--gray-300); }

        .content { flex: 1; display: flex; overflow: hidden; }

        .test-list-panel {
            flex: 1;
            display: flex;
            flex-direction: column;
            min-width: 0;
            border-right: 1px solid var(--border-color);
        }

        .summary-bar {
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 16px;
            display: flex;
            align-items: center;
            gap: 20px;
            flex-shrink: 0;
        }
        .summary-item { display: flex; align-items: center; gap: 6px; }
        .summary-value { font-size: 18px; font-weight: 700; }
        .summary-value.success { color: var(--success); }
        .summary-value.danger { color: var(--danger); }
        .summary-value.warning { color: var(--warning); }
        .summary-label { font-size: 12px; color: var(--text-muted); }
        .summary-separator { width: 1px; height: 24px; background: var(--border-color); }

        .filter-bar {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 8px 16px;
            display: flex;
            align-items: center;
            gap: 8px;
            flex-shrink: 0;
            overflow-x: auto;
        }
        .filter-btn {
            padding: 4px 10px;
            border: 1px solid var(--border-color);
            background: var(--bg-primary);
            border-radius: var(--radius-sm);
            cursor: pointer;
            font-size: 12px;
            color: var(--text-secondary);
            transition: var(--transition);
            white-space: nowrap;
        }
        .filter-btn:hover { border-color: var(--primary); color: var(--primary); }
        .filter-btn.active { background: var(--primary); border-color: var(--primary); color: white; }
        .filter-select {
            padding: 4px 8px;
            border: 1px solid var(--border-color);
            background: var(--bg-primary);
            border-radius: var(--radius-sm);
            font-size: 12px;
            color: var(--text-primary);
        }
        .filter-label {
            font-size: 11px;
            color: var(--text-muted);
            margin-left: 4px;
            margin-right: -2px;
            white-space: nowrap;
        }

        .test-table-container { flex: 1; overflow: auto; }
        .test-table { width: 100%; border-collapse: collapse; font-size: 12px; }
        .test-table th {
            position: sticky;
            top: 0;
            background: var(--bg-tertiary);
            padding: 8px 12px;
            text-align: left;
            font-weight: 600;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-color);
            white-space: nowrap;
        }
        .test-table td {
            padding: 8px 12px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }
        .test-table tbody tr { cursor: pointer; transition: var(--transition); }
        .test-table tbody tr:hover { background: var(--bg-tertiary); }
        .test-table tbody tr.selected { background: var(--primary-light); }
        [data-theme="dark"] .test-table tbody tr.selected { background: rgba(59, 130, 246, 0.2); }

        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 2px 8px;
            border-radius: var(--radius-sm);
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .status-pass { background: var(--success-light); color: var(--success); }
        .status-fail { background: var(--danger-light); color: var(--danger); }

        .severity-badge {
            display: inline-flex;
            padding: 2px 6px;
            border-radius: var(--radius-sm);
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-critical { background: var(--danger-light); color: var(--danger); }
        .severity-high { background: var(--warning-light); color: var(--warning); }
        .severity-medium { background: var(--info-light); color: var(--info); }
        .severity-low { background: var(--bg-tertiary); color: var(--text-muted); }

        .test-id { font-family: 'Fira Code', monospace; font-weight: 600; color: var(--text-primary); }
        .test-category { color: var(--text-secondary); }
        .test-technique { color: var(--text-muted); font-size: 11px; }
        .test-score { font-family: 'Fira Code', monospace; color: var(--text-muted); }
        .test-duration { color: var(--text-muted); font-size: 11px; }
        .result-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 66px;
            padding: 3px 8px;
            border-radius: var(--radius-sm);
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.3px;
            text-transform: uppercase;
        }
        .result-pill.pass {
            background: var(--success-light);
            color: var(--success);
            border: 1px solid var(--success);
        }
        .result-pill.fail {
            background: var(--danger-light);
            color: var(--danger);
            border: 1px solid var(--danger);
        }

        .detail-panel {
            width: 480px;
            background: var(--bg-primary);
            display: flex;
            flex-direction: column;
            flex-shrink: 0;
        }
        .detail-panel.empty {
            align-items: center;
            justify-content: center;
            color: var(--text-muted);
        }
        .detail-empty-state { text-align: center; }
        .detail-empty-icon { font-size: 48px; margin-bottom: 16px; opacity: 0.5; }
        .detail-empty-title { font-size: 16px; font-weight: 600; margin-bottom: 8px; }
        .detail-empty-text { font-size: 13px; }

        .detail-header {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: flex-start;
            gap: 12px;
        }
        .detail-status {
            width: 40px;
            height: 40px;
            border-radius: var(--radius);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            flex-shrink: 0;
        }
        .detail-status.pass { background: var(--success-light); color: var(--success); }
        .detail-status.fail { background: var(--danger-light); color: var(--danger); }
        .detail-title { flex: 1; }
        .detail-id { font-family: 'Fira Code', monospace; font-size: 16px; font-weight: 700; margin-bottom: 4px; }
        .detail-meta { font-size: 12px; color: var(--text-muted); }
        .detail-badges { display: flex; gap: 6px; margin-top: 8px; }

        .detail-tabs {
            display: flex;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-secondary);
        }
        .detail-tab {
            padding: 10px 16px;
            font-size: 12px;
            font-weight: 500;
            color: var(--text-secondary);
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: var(--transition);
            white-space: nowrap;
        }
        .detail-tab:hover { color: var(--text-primary); background: var(--bg-tertiary); }
        .detail-tab.active { color: var(--primary); border-bottom-color: var(--primary); background: var(--bg-primary); }

        .detail-content { flex: 1; overflow: auto; padding: 16px; }
        .detail-section { margin-bottom: 20px; }
        .detail-section-title {
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 8px;
        }
        .info-item {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 8px 12px;
        }
        .info-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 2px; }
        .info-value { font-size: 12px; font-weight: 500; font-family: 'Fira Code', monospace; }
        .info-value.method-get { color: var(--success); }
        .info-value.method-post { color: var(--primary); }
        .info-value.method-put { color: var(--warning); }
        .info-value.method-delete { color: var(--danger); }

        .code-block-wrapper { margin-bottom: 12px; }
        .code-block-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 6px 10px;
            background: var(--gray-800);
            border-radius: var(--radius) var(--radius) 0 0;
        }
        .code-block-title { font-size: 10px; font-weight: 600; text-transform: uppercase; color: var(--gray-400); }
        .btn-copy-sm {
            padding: 2px 8px;
            background: transparent;
            border: 1px solid var(--gray-600);
            border-radius: var(--radius-sm);
            color: var(--gray-400);
            font-size: 10px;
            cursor: pointer;
            transition: var(--transition);
        }
        .btn-copy-sm:hover { border-color: var(--primary); color: var(--primary); }
        .btn-copy-sm.copied { border-color: var(--success); color: var(--success); }
        .code-block {
            background: var(--gray-900);
            color: #e2e8f0;
            padding: 12px;
            border-radius: 0 0 var(--radius) var(--radius);
            font-family: 'Fira Code', monospace;
            font-size: 11px;
            line-height: 1.6;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 200px;
            overflow-y: auto;
        }
        .code-block.curl { background: #1e3a5f; }
        .code-block.response { background: #451a1a; }
        .code-block.payload { background: #1a1a2e; }

        .evidence-box {
            padding: 12px;
            border-radius: var(--radius);
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }
        .evidence-box.success { background: var(--success-light); border: 1px solid var(--success); color: var(--success); }
        .evidence-box.danger { background: var(--danger-light); border: 1px solid var(--danger); color: var(--danger); }
        .evidence-icon { font-size: 16px; flex-shrink: 0; }
        .evidence-content { flex: 1; }
        .evidence-title { font-weight: 600; font-size: 12px; margin-bottom: 2px; }
        .evidence-text { font-size: 11px; opacity: 0.9; }

        .tab-panel { display: none; }
        .tab-panel.active { display: block; }

        .toast-container { position: fixed; bottom: 16px; right: 16px; z-index: 1000; display: flex; flex-direction: column; gap: 8px; }
        .toast {
            background: var(--gray-800);
            color: white;
            padding: 10px 16px;
            border-radius: var(--radius);
            font-size: 12px;
            font-weight: 500;
            box-shadow: var(--shadow-lg);
            animation: toastIn 0.2s ease-out;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        @keyframes toastIn {
            from { opacity: 0; transform: translateX(100%); }
            to { opacity: 1; transform: translateX(0); }
        }
        .toast.success { background: var(--success); }

        @media (max-width: 1200px) {
            .detail-panel { width: 400px; }
        }
        @media (max-width: 992px) {
            .sidebar { display: none; }
            .detail-panel { position: fixed; right: 0; top: 0; bottom: 0; z-index: 100; transform: translateX(100%); transition: transform 0.3s; }
            .detail-panel.open { transform: translateX(0); }
        }
    </style>
</head>
<body>
    <div class="app">
        <aside class="sidebar">
            <div class="sidebar-header">
                <div class="logo">
                    <div class="logo-icon">&#x1F6E1;&#xFE0F;</div>
                    <div>
                        <div class="logo-text">WAF Benchmark</div>
                        <div class="logo-subtext">Phase A Report</div>
                    </div>
                </div>
            </div>
            <nav>
                <div class="nav-section">
                    <div class="nav-title">Overview</div>
                    <a class="nav-link active" onclick="showDashboard()">
                        <span class="nav-icon">&#x1F4CA;</span>
                        Dashboard
                    </a>
                    <a class="nav-link" onclick="showCategories()">
                        <span class="nav-icon">&#x1F4C8;</span>
                        Categories
                    </a>
                </div>
                <div class="nav-section">
                    <div class="nav-title">Test Results</div>
                    <a class="nav-link" onclick="filterTests('fail')">
                        <span class="nav-icon">&#x274C;</span>
                        Failed Only
                        <span class="nav-badge" id="nav-fail-count">0</span>
                    </a>
                    <a class="nav-link" onclick="filterTests('critical')">
                        <span class="nav-icon">&#x1F6A8;</span>
                        Critical Issues
                    </a>
                </div>
            </nav>
        </aside>

        <main class="main">
            <header class="top-bar">
                <div class="top-bar-left">
                    <div class="breadcrumbs">Reports / <strong>Phase A - Security Effectiveness</strong></div>
                    <div class="search-box">
                        <span class="search-icon">&#x1F50D;</span>
                        <input type="text" id="searchInput" placeholder="Search test ID, category, payload..." oninput="searchTests()">
                    </div>
                </div>
                <div class="top-bar-right">
                    <button class="btn-icon" id="themeToggle" onclick="toggleTheme()" title="Toggle Dark Mode">&#x1F319;</button>
                    <button class="btn btn-secondary" onclick="collapseAll()">Collapse All</button>
                    <button class="btn" onclick="exportReport()">&#x2B07;&#xFE0F; Export</button>
                </div>
            </header>

            <div class="content">
                <div class="test-list-panel">
                    <div class="summary-bar">
                        <div class="summary-item">
                            <span class="summary-value ` + data.ScoreClass + `" id="total-score">` + fmt.Sprintf("%.1f%%", data.OverallScore) + `</span>
                            <span class="summary-label">Security Score</span>
                        </div>
                        <div class="summary-separator"></div>
                        <div class="summary-item">
                            <span class="summary-value success" id="pass-count">` + fmt.Sprintf("%d", data.Passed) + `</span>
                            <span class="summary-label">Passed</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-value danger" id="fail-count">` + fmt.Sprintf("%d", data.Failed) + `</span>
                            <span class="summary-label">Failed</span>
                        </div>
                        <div class="summary-separator"></div>
                        <div class="summary-item">
                            <span class="summary-value" id="total-tests">` + fmt.Sprintf("%d", data.TotalTests) + `</span>
                            <span class="summary-label">Total Tests</span>
                        </div>
                        <div class="summary-item">
                            <span class="summary-value" id="current-score">` + fmt.Sprintf("%.1f", data.TotalScore) + `</span>
                            <span class="summary-label">Points</span>
                        </div>
                    </div>

                    <div class="filter-bar">
                        <button class="filter-btn active" data-filter="all" onclick="setFilter('all')">All <span id="count-all">` + fmt.Sprintf("%d", data.TotalTests) + `</span></button>
                        <button class="filter-btn" data-filter="pass" onclick="setFilter('pass')">Passed <span id="count-pass">` + fmt.Sprintf("%d", data.Passed) + `</span></button>
                        <button class="filter-btn" data-filter="fail" onclick="setFilter('fail')">Failed <span id="count-fail">` + fmt.Sprintf("%d", data.Failed) + `</span></button>
                        <button class="filter-btn" data-filter="critical" onclick="setFilter('critical')">Critical <span id="count-critical">` + fmt.Sprintf("%d", countCriticalTests(data.Tests)) + `</span></button>
                        <span class="filter-label">Result:</span>
                        <select class="filter-select" id="resultSelect" onchange="filterByResult()">
                            <option value="">All Results</option>
                            <option value="pass">PASSED</option>
                            <option value="fail">FAILED</option>
                        </select>
                        <span class="filter-label">Category:</span>
                        <select class="filter-select" id="categorySelect" onchange="filterByCategory()">
                            <option value="">All Categories</option>
                        </select>
                        <span class="filter-label">Technique/Mode:</span>
                        <select class="filter-select" id="modeSelect" onchange="filterByMode()">
                            <option value="">All Modes</option>
                        </select>
                    </div>

                    <div class="test-table-container">
                        <table class="test-table">
                            <thead>
                                <tr>
                                    <th style="width: 60px">Status</th>
                                    <th style="width: 70px">ID</th>
                                    <th style="width: 95px">Result</th>
                                    <th>Category</th>
                                    <th style="width: 260px">Technique</th>
                                    <th style="width: 80px">Severity</th>
                                    <th style="width: 90px">Score</th>
                                    <th style="width: 70px">Time</th>
                                </tr>
                            </thead>
                            <tbody id="testTableBody">
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="detail-panel empty" id="detailPanel">
                    <div class="detail-empty-state">
                        <div class="detail-empty-icon">&#x1F9EA;</div>
                        <div class="detail-empty-title">Select a test</div>
                        <div class="detail-empty-text">Click on any test row to view details</div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <div class="toast-container" id="toastContainer"></div>

    <script>
        const testData = ` + safeJSON + `;

        let currentFilter = 'all';
        let searchQuery = '';
        let selectedResult = '';
        let selectedCategory = '';
        let selectedMode = '';
        let selectedIdx = null;
        let activeDetailTab = 'overview';

        // Assign unique index to each test for individual row selection
        testData.forEach(function(t, i) { t._idx = i; });

        document.addEventListener('DOMContentLoaded', function() {
            renderTestTable();
            updateCounts();
            populateCategoryFilter();
            populateModeFilter();
        });

        function populateCategoryFilter() {
            const select = document.getElementById('categorySelect');
            const categories = [...new Set(testData.map(t => t.category))].sort();
            categories.forEach(cat => {
                const option = document.createElement('option');
                option.value = cat;
                option.textContent = cat;
                select.appendChild(option);
            });
        }

        function populateModeFilter() {
            const select = document.getElementById('modeSelect');
            const modes = [...new Set(testData.map(t => formatAttackMode(t.attackMode)))].sort();
            modes.forEach(mode => {
                const option = document.createElement('option');
                option.value = mode;
                option.textContent = mode;
                select.appendChild(option);
            });
        }

        function renderTestTable() {
            const tbody = document.getElementById('testTableBody');
            tbody.innerHTML = '';

            const filteredTests = getFilteredTests();

            filteredTests.forEach(test => {
                const row = document.createElement('tr');
                row.dataset.idx = String(test._idx);
                row.className = selectedIdx === test._idx ? 'selected' : '';
                row.onclick = () => selectTest(test._idx);

                row.innerHTML = '<td><span class="status-badge status-' + test.status + '">' + (test.status === 'pass' ? '&#x2713;' : '&#x2715;') + '</span></td>' +
                    '<td><span class="test-id">' + escapeHtml(test.id) + '</span></td>' +
                    '<td><span class="result-pill ' + test.status + '">' + (test.status === 'pass' ? 'PASSED' : 'FAILED') + '</span></td>' +
                    '<td><div class="test-category">' + escapeHtml(test.category) + '</div></td>' +
                    '<td><div class="test-technique">' + escapeHtml(formatAttackMode(test.attackMode)) + '</div></td>' +
                    '<td><span class="severity-badge severity-' + test.severity.toLowerCase() + '">' + escapeHtml(test.severity) + '</span></td>' +
                    '<td><span class="test-score">' + escapeHtml(test.score) + '/' + escapeHtml(test.maxScore) + '</span></td>' +
                    '<td><span class="test-duration">' + escapeHtml(test.duration) + '</span></td>';

                tbody.appendChild(row);
            });
        }

        function getFilteredTests() {
            return testData.filter(test => {
                let matchesQuickFilter = false;
                if (currentFilter === 'all') matchesQuickFilter = true;
                else if (currentFilter === 'pass' && test.status === 'pass') matchesQuickFilter = true;
                else if (currentFilter === 'fail' && test.status === 'fail') matchesQuickFilter = true;
                else if (currentFilter === 'critical' && test.severity === 'Critical') matchesQuickFilter = true;

                const modeLabel = formatAttackMode(test.attackMode);
                let matchesSearch = !searchQuery ||
                    test.id.toLowerCase().includes(searchQuery) ||
                    test.category.toLowerCase().includes(searchQuery) ||
                    test.technique.toLowerCase().includes(searchQuery) ||
                    modeLabel.toLowerCase().includes(searchQuery) ||
                    test.payload.toLowerCase().includes(searchQuery);

                const matchesResult = !selectedResult || test.status === selectedResult;
                const matchesCategory = !selectedCategory || test.category === selectedCategory;
                const matchesMode = !selectedMode || modeLabel === selectedMode;

                return matchesQuickFilter && matchesSearch && matchesResult && matchesCategory && matchesMode;
            }).sort((a, b) => {
                const modeOrder = {
                    'mode1_malformed_request_only': 1,
                    'mode2_smuggling': 2,
                    'mode3_header_cannibalism': 3,
                    'mode4_slow_post': 4,
                    'mode5_chunked_variation': 5,
                };
                const am = modeOrder[a.attackMode] || 99;
                const bm = modeOrder[b.attackMode] || 99;
                if (am !== bm) return am - bm;
                if (a.id !== b.id) return a.id.localeCompare(b.id);
                return (a.payload || '').localeCompare(b.payload || '');
            });
        }

        function selectTest(idx) {
            selectedIdx = idx;
            const test = testData.find(t => t._idx === idx);
            if (!test) return;

            document.querySelectorAll('.test-table tbody tr').forEach(row => {
                row.classList.toggle('selected', row.dataset.idx === String(idx));
            });

            renderDetailPanel(test);
        }

        function renderDetailPanel(test) {
            const panel = document.getElementById('detailPanel');
            panel.className = 'detail-panel';

            const markerExposureDetected = !!(test.markerFound || test.mainMarkerFound || test.otherMarkerFound);
            const statusContractViolation = !markerExposureDetected && !test.statusCompliant;

            let analysisFail = false;
            let analysisTitle = 'WAF Protection Active';
            let analysisText = test.evidence || '';

            if (markerExposureDetected) {
                analysisFail = true;
                analysisTitle = 'Marker Exposure Detected';
                analysisText = 'Marker Exposure Detected. The WAF failed to intercept or sanitize the sensitive marker string in the response.';
            } else if (statusContractViolation) {
                analysisFail = true;
                analysisTitle = 'Status Contract Violation';
                analysisText = test.statusEvidence ? ('Status contract violation: ' + test.statusEvidence) : 'Status contract violation detected.';
            }

            const analysisStatusClass = analysisFail ? 'fail' : 'pass';
            const analysisStatusIcon = analysisFail ? '&#x2715;' : '&#x2713;';

            panel.innerHTML = '<div class="detail-header">' +
                '<div class="detail-status ' + test.status + '">' + (test.status === 'pass' ? '&#x2713;' : '&#x2715;') + '</div>' +
                '<div class="detail-title">' +
                    '<div class="detail-id">' + escapeHtml(test.id) + '</div>' +
                    '<div class="detail-meta">' + escapeHtml(test.category) + ' &#x2022; ' + escapeHtml(test.technique) + ' &#x2022; ' + escapeHtml(test.timestamp) + '</div>' +
                    '<div class="detail-badges">' +
                        '<span class="status-badge status-' + test.status + '">' + test.status.toUpperCase() + '</span>' +
                        '<span class="severity-badge severity-' + test.severity.toLowerCase() + '">' + escapeHtml(test.severity) + '</span>' +
                    '</div>' +
                '</div>' +
            '</div>' +
            '<div class="detail-tabs">' +
                '<div class="detail-tab' + (activeDetailTab === 'overview' ? ' active' : '') + '" onclick="switchTab(this, ' + "'" + 'overview' + "'" + ')">Overview</div>' +
                '<div class="detail-tab' + (activeDetailTab === 'request' ? ' active' : '') + '" onclick="switchTab(this, ' + "'" + 'request' + "'" + ')">Request</div>' +
                '<div class="detail-tab' + (activeDetailTab === 'response' ? ' active' : '') + '" onclick="switchTab(this, ' + "'" + 'response' + "'" + ')">Response</div>' +
                '<div class="detail-tab' + (activeDetailTab === 'evidence' ? ' active' : '') + '" onclick="switchTab(this, ' + "'" + 'evidence' + "'" + ')">Evidence</div>' +
            '</div>' +
            '<div class="detail-content">' +
                '<div class="tab-panel' + (activeDetailTab === 'overview' ? ' active' : '') + '" id="tab-overview">' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Test Information</div>' +
                        '<div class="info-grid">' +
                            '<div class="info-item"><div class="info-label">Test ID</div><div class="info-value">' + escapeHtml(test.id) + '</div></div>' +
                            '<div class="info-item"><div class="info-label">Category</div><div class="info-value">' + escapeHtml(test.category) + '</div></div>' +
                            '<div class="info-item"><div class="info-label">Method</div><div class="info-value method-' + test.method.toLowerCase() + '">' + escapeHtml(test.method) + '</div></div>' +
                            '<div class="info-item"><div class="info-label">Response Status</div><div class="info-value">' + escapeHtml(test.responseStatus.toString()) + '</div></div>' +
                            '<div class="info-item"><div class="info-label">Technique</div><div class="info-value">' + escapeHtml(test.technique) + '</div></div>' +
                            '<div class="info-item"><div class="info-label">Attack Mode</div><div class="info-value">' + escapeHtml(test.attackMode || 'standard') + '</div></div>' +
                            '<div class="info-item"><div class="info-label">Duration</div><div class="info-value">' + escapeHtml(test.duration) + '</div></div>' +
                            '<div class="info-item"><div class="info-label">Auth Required</div><div class="info-value">' + escapeHtml(test.auth.toString()) + '</div></div>' +
                            '<div class="info-item"><div class="info-label">Timestamp</div><div class="info-value">' + escapeHtml(test.timestamp) + '</div></div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Score</div>' +
                        '<div class="info-grid">' +
                            '<div class="info-item"><div class="info-label">Score Earned</div><div class="info-value">' + escapeHtml(test.score) + '</div></div>' +
                            '<div class="info-item"><div class="info-label">Max Possible</div><div class="info-value">' + escapeHtml(test.maxScore) + '</div></div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Payload Preview</div>' +
                        '<div class="code-block-wrapper">' +
                            '<div class="code-block-header"><span class="code-block-title">Payload</span><button class="btn-copy-sm" onclick="copyAdjacentBlock(this)">&#x1F4CB; Copy</button></div>' +
                            '<div class="code-block payload">' + escapeHtml(test.originalPayload) + '</div>' +
                        '</div>' +
                    '</div>' +
                '</div>' +
                '<div class="tab-panel' + (activeDetailTab === 'request' ? ' active' : '') + '" id="tab-request">' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Payload</div>' +
                        '<div class="code-block-wrapper">' +
                            '<div class="code-block-header"><span class="code-block-title">Payload Used</span><button class="btn-copy-sm" onclick="copyAdjacentBlock(this)">&#x1F4CB; Copy</button></div>' +
                            '<div class="code-block payload">' + escapeHtml(test.payload) + '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Original Payload</div>' +
                        '<div class="code-block-wrapper">' +
                            '<div class="code-block-header"><span class="code-block-title">Original</span><button class="btn-copy-sm" onclick="copyAdjacentBlock(this)">&#x1F4CB; Copy</button></div>' +
                            '<div class="code-block">' + escapeHtml(test.originalPayload) + '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Curl Command</div>' +
                        '<div class="code-block-wrapper">' +
                            '<div class="code-block-header"><span class="code-block-title">Curl</span><button class="btn-copy-sm" onclick="copyAdjacentBlock(this)">&#x1F4CB; Copy</button></div>' +
                            '<div class="code-block curl">' + escapeHtml(test.curl) + '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Raw Request (bytes)</div>' +
                        '<div class="code-block-wrapper">' +
                            '<div class="code-block-header"><span class="code-block-title">Raw Request</span><button class="btn-copy-sm" onclick="copyAdjacentBlock(this)">&#x1F4CB; Copy</button></div>' +
                            '<div class="code-block curl">' + escapeHtml(test.rawRequest || '[not captured]') + '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Reproduction Script</div>' +
                        '<div class="code-block-wrapper">' +
                            '<div class="code-block-header"><span class="code-block-title">Python requests + .http</span><button class="btn-copy-sm" onclick="copyAdjacentBlock(this)">&#x1F4CB; Copy</button></div>' +
                            '<div class="code-block curl">' + escapeHtml(test.reproductionScript || '[not available]') + '</div>' +
                        '</div>' +
                    '</div>' +
                '</div>' +
                '<div class="tab-panel' + (activeDetailTab === 'response' ? ' active' : '') + '" id="tab-response">' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Marker Check</div>' +
                            '<div class="info-grid">' +
                                '<div class="info-item"><div class="info-label">Expected Marker</div><div class="info-value">' + escapeHtml(test.marker) + '</div></div>' +
                                '<div class="info-item"><div class="info-label">Expected Marker Status</div><div class="info-status ' + (test.mainMarkerFound ? 'status-fail' : 'status-pass') + '">' + (test.mainMarkerFound ? '&#x2715; FOUND (' + escapeHtml(test.mainMarkerLocation || 'unknown') + ')' : '&#x2713; NOT FOUND') + '</div></div>' +
                                '<div class="info-item"><div class="info-label">Other Expected Marker</div><div class="info-value">' + escapeHtml(test.otherExpectedPattern || '__[A-Za-z0-9_]+__ (exclude main)') + '</div></div>' +
                                '<div class="info-item"><div class="info-label">Other Marker Status</div><div class="info-status ' + (test.otherMarkerFound ? 'status-fail' : 'status-pass') + '">' + (test.otherMarkerFound ? '&#x2715; FOUND ' + escapeHtml(test.otherMarker || '') + ' (' + escapeHtml(test.otherMarkerLocation || 'unknown') + ')' : '&#x2713; NOT FOUND') + '</div></div>' +
                            '</div>' +
                        '</div>' +
                        '<div class="detail-section">' +
                            '<div class="detail-section-title">Response Headers</div>' +
                            '<div class="code-block-wrapper">' +
                                '<div class="code-block-header"><span class="code-block-title">Headers</span><button class="btn-copy-sm" onclick="copyAdjacentBlock(this)">&#x1F4CB; Copy</button></div>' +
                                '<div class="code-block response">' + escapeHtml(test.responseHeaders) + '</div>' +
                            '</div>' +
                        '</div>' +
                        '<div class="detail-section">' +
                            '<div class="detail-section-title">Response Body</div>' +
                            '<div class="code-block-wrapper">' +
                                '<div class="code-block-header"><span class="code-block-title">Response (first 2000 chars)</span><button class="btn-copy-sm" onclick="copyAdjacentBlock(this)">&#x1F4CB; Copy</button></div>' +
                                '<div class="code-block response">' + escapeHtml(test.response) + '</div>' +
                            '</div>' +
                        '</div>' +
                        '<div class="detail-section">' +
                            '<div class="detail-section-title">Raw Response (bytes)</div>' +
                            '<div class="code-block-wrapper">' +
                                '<div class="code-block-header"><span class="code-block-title">Raw Response</span><button class="btn-copy-sm" onclick="copyAdjacentBlock(this)">&#x1F4CB; Copy</button></div>' +
                                '<div class="code-block response">' + escapeHtml(test.rawResponse || '[not captured]') + '</div>' +
                            '</div>' +
                        '</div>' +
                '</div>' +
                '<div class="tab-panel' + (activeDetailTab === 'evidence' ? ' active' : '') + '" id="tab-evidence">' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Analysis Result</div>' +
                        '<div class="evidence-box ' + analysisStatusClass + '">' +
                            '<span class="evidence-icon">' + analysisStatusIcon + '</span>' +
                            '<div class="evidence-content">' +
                                '<div class="evidence-title">' + escapeHtml(analysisTitle) + '</div>' +
                                '<div class="evidence-text">' + escapeHtml(analysisText) + '</div>' +
                            '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Pass Criteria</div>' +
                        '<ul style="font-size: 12px; color: var(--text-secondary); line-height: 1.8; margin-left: 16px;">' +
                            '<li>No Main Marker FOUND</li>' +
                            '<li>No Other Markers FOUND</li>' +
                            '<li>Status complies with test type contract</li>' +
                        '</ul>' +
                    '</div>' +
                    '<div class="detail-section">' +
                        '<div class="detail-section-title">Fail Criteria</div>' +
                        '<ul style="font-size: 12px; color: var(--text-secondary); line-height: 1.8; margin-left: 16px;">' +
                            '<li>Main/Other Marker detected (Priority Fail)</li>' +
                            '<li>OR Status contract violation</li>' +
                        '</ul>' +
                    '</div>' +
                '</div>' +
            '</div>';
        }

        function formatAttackMode(mode) {
            const modeLabels = {
                mode1_malformed_request_only: 'Mode 1: Malformed Request Only',
                mode2_smuggling: 'Mode 2: HTTP Request Smuggling',
                mode3_header_cannibalism: 'Mode 3: Header Cannibalism',
                mode4_slow_post: 'Mode 4: Slow Post / Read Evasion',
                mode5_chunked_variation: 'Mode 5: Chunked Encoding Variation',
            };
            return modeLabels[mode] || (mode || 'standard');
        }

        function switchTab(tabElement, tabName) {
            activeDetailTab = tabName;
            document.querySelectorAll('.detail-tab').forEach(t => t.classList.remove('active'));
            tabElement.classList.add('active');
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            document.getElementById('tab-' + tabName).classList.add('active');
        }

        function setFilter(filter) {
            currentFilter = filter;
            if (filter === 'pass' || filter === 'fail') {
                selectedResult = filter;
                const resultSelect = document.getElementById('resultSelect');
                if (resultSelect) resultSelect.value = filter;
            }
            if (filter === 'all') {
                selectedResult = '';
                const resultSelect = document.getElementById('resultSelect');
                if (resultSelect) resultSelect.value = '';
            }
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.filter === filter);
            });
            renderTestTable();
        }

        function filterTests(filter) {
            setFilter(filter);
        }

        function filterByResult() {
            selectedResult = document.getElementById('resultSelect').value;
            if (selectedResult === 'pass' || selectedResult === 'fail') {
                currentFilter = selectedResult;
            } else if (currentFilter === 'pass' || currentFilter === 'fail') {
                currentFilter = 'all';
            }
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.filter === currentFilter);
            });
            renderTestTable();
        }

        function filterByCategory() {
            selectedCategory = document.getElementById('categorySelect').value;
            renderTestTable();
        }

        function filterByMode() {
            selectedMode = document.getElementById('modeSelect').value;
            renderTestTable();
        }

        function searchTests() {
            searchQuery = document.getElementById('searchInput').value.toLowerCase();
            renderTestTable();
        }

        function updateCounts() {
            const all = testData.length;
            const pass = testData.filter(t => t.status === 'pass').length;
            const fail = testData.filter(t => t.status === 'fail').length;
            const critical = testData.filter(t => t.severity === 'Critical').length;

            document.getElementById('count-all').textContent = all;
            document.getElementById('count-pass').textContent = pass;
            document.getElementById('count-fail').textContent = fail;
            document.getElementById('count-critical').textContent = critical;
            document.getElementById('nav-fail-count').textContent = fail;
        }

        function collapseAll() {
            selectedIdx = null;
            document.querySelectorAll('.test-table tbody tr').forEach(row => row.classList.remove('selected'));
            document.getElementById('detailPanel').className = 'detail-panel empty';
            document.getElementById('detailPanel').innerHTML = '<div class="detail-empty-state"><div class="detail-empty-icon">&#x1F9EA;</div><div class="detail-empty-title">Select a test</div><div class="detail-empty-text">Click on any test row to view details</div></div>';
        }

        function toggleTheme() {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('waf-report-theme', newTheme);
            document.getElementById('themeToggle').textContent = newTheme === 'light' ? '&#x1F319;' : '&#x2600;&#xFE0F;';
        }

        const savedTheme = localStorage.getItem('waf-report-theme') || 'light';
        document.documentElement.setAttribute('data-theme', savedTheme);
        document.getElementById('themeToggle').textContent = savedTheme === 'light' ? '&#x1F319;' : '&#x2600;&#xFE0F;';

        function copyAdjacentBlock(button) {
            const wrapper = button.closest('.code-block-wrapper');
            const codeBlock = wrapper ? wrapper.querySelector('.code-block') : null;
            const text = codeBlock ? codeBlock.textContent : '';
            navigator.clipboard.writeText(text).then(() => {
                button.classList.add('copied');
                button.textContent = '&#x2713; Copied';
                showToast('Copied to clipboard!', 'success');
                setTimeout(() => {
                    button.classList.remove('copied');
                    button.textContent = '&#x1F4CB; Copy';
                }, 2000);
            }).catch(() => {
                // Fallback for non-HTTPS contexts
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
                button.classList.add('copied');
                button.textContent = '&#x2713; Copied';
                showToast('Copied to clipboard!', 'success');
                setTimeout(() => {
                    button.classList.remove('copied');
                    button.textContent = '&#x1F4CB; Copy';
                }, 2000);
            });
        }

        function showToast(message, type) {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = 'toast ' + type;
            toast.innerHTML = (type === 'success' ? '&#x2713; ' : '') + message;
            container.appendChild(toast);
            setTimeout(() => {
                toast.style.opacity = '0';
                toast.style.transform = 'translateX(100%)';
                setTimeout(() => toast.remove(), 300);
            }, 3000);
        }

        function exportReport() {
            const html = document.documentElement.outerHTML;
            const blob = new Blob([html], { type: 'text/html' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'waf-benchmark-phase-a-report.html';
            a.click();
            URL.revokeObjectURL(url);
            showToast('Report exported successfully!', 'success');
        }

        function escapeHtml(text) {
            if (typeof text !== 'string') {
                text = String(text);
            }
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function showDashboard() {
            currentFilter = 'all';
            selectedResult = '';
            selectedCategory = '';
            selectedMode = '';
            searchQuery = '';
            document.getElementById('searchInput').value = '';
            var resultSelect = document.getElementById('resultSelect');
            if (resultSelect) resultSelect.value = '';
            var catSelect = document.getElementById('categorySelect');
            if (catSelect) catSelect.value = '';
            var modeSelect = document.getElementById('modeSelect');
            if (modeSelect) modeSelect.value = '';
            document.querySelectorAll('.filter-btn').forEach(function(btn) {
                btn.classList.toggle('active', btn.dataset.filter === 'all');
            });
            document.querySelectorAll('.nav-link').forEach(function(l) { l.classList.remove('active'); });
            document.querySelectorAll('.nav-link').forEach(function(l) {
                if (l.getAttribute('onclick') && l.getAttribute('onclick').indexOf('showDashboard') >= 0) l.classList.add('active');
            });
            renderTestTable();
            collapseAll();
        }

        function showCategories() {
            currentFilter = 'all';
            searchQuery = '';
            document.getElementById('searchInput').value = '';
            document.querySelectorAll('.nav-link').forEach(function(l) { l.classList.remove('active'); });
            document.querySelectorAll('.nav-link').forEach(function(l) {
                if (l.getAttribute('onclick') && l.getAttribute('onclick').indexOf('showCategories') >= 0) l.classList.add('active');
            });
            var catSelect = document.getElementById('categorySelect');
            if (catSelect) catSelect.focus();
            renderTestTable();
        }

        document.addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                document.getElementById('searchInput').focus();
            }
            if (e.key === 'Escape') {
                collapseAll();
            }
        });
    </script>
</body>
</html>`

	return html
}

// prepareReportData prepares all data for the HTML report
// NOTE: We do NOT HTML-escape here because:
// 1. Data is serialized to JSON which safely handles special characters
// 2. JavaScript escapeHtml() function handles escaping when rendering to DOM
// 3. This prevents double-escaping issues (e.g., < becoming &lt;)
func prepareReportData(ts *TestSuiteResults) ReportData {
	data := ReportData{
		Target:           ts.Target,
		TargetProfile:    ts.TargetProfile,
		TestDuration:     formatDuration(ts.StartTime, ts.EndTime),
		GeneratedAt:      ts.EndTime.Format("2006-01-02 15:04:05 MST"),
		OverallScore:     ts.Summary.Percentage,
		TotalScore:       ts.Summary.TotalScore,
		MaxPossibleScore: ts.Summary.MaxPossibleScore,
		Passed:           ts.Summary.Passed,
		Failed:           ts.Summary.Failed,
		TotalTests:       ts.Summary.TotalTests,
		ScoreClass:       getScoreCardClass(ts.Summary.Percentage),
		CategoryScores:   ts.Summary.CategoryScores,
		Tests:            make([]ReportTestData, 0, len(ts.Results)),
	}

	data.PassClass = getScoreCardClass(float64(ts.Summary.Passed) / float64(ts.Summary.TotalTests) * 100)
	data.FailClass = getScoreCardClass(float64(ts.Summary.Failed) / float64(ts.Summary.TotalTests) * 100)

	// Process each test result
	for _, r := range ts.Results {
		// Determine severity
		severity := "Medium"
		if isCriticalTest(r.TestID) {
			severity = "Critical"
		} else if isHighSeverityTest(r.TestID) {
			severity = "High"
		}

		status := "fail"
		if r.Passed {
			status = "pass"
		}

		// Build response headers block
		headerKeys := make([]string, 0, len(r.ResponseHeaders))
		for k := range r.ResponseHeaders {
			headerKeys = append(headerKeys, k)
		}
		sort.Strings(headerKeys)
		headerLines := make([]string, 0, len(headerKeys))
		for _, k := range headerKeys {
			headerLines = append(headerLines, fmt.Sprintf("%s: %s", k, r.ResponseHeaders[k]))
		}
		responseHeaders := strings.Join(headerLines, "\n")
		if responseHeaders == "" {
			responseHeaders = "[no response headers]"
		}

		// Truncate response body if needed
		response := r.ResponseBody
		if len(response) > 2000 {
			response = response[:2000] + "\n\n[... truncated for display ...]"
		}

		testData := ReportTestData{
			ID:               r.TestID,
			Category:         r.Category,
			Technique:        r.Technique,
			Severity:         severity,
			Status:           status,
			Score:            fmt.Sprintf("%.2f", r.Score),
			MaxScore:         fmt.Sprintf("%.2f", r.MaxScore),
			Duration:         fmt.Sprintf("%dms", r.DurationMs),
			Method:           r.Method,
			ResponseStatus:   r.ResponseStatus,
			Auth:             r.AuthRequired,
			Timestamp:        r.Timestamp.Format("15:04:05"),
			AttackMode:       r.AttackMode,
			Payload:          r.PayloadVariant,
			OriginalPayload:  r.PayloadUsed,
			Curl:               r.CurlCommand,
			RawRequest:         r.RawRequest,
			RawResponse:        r.RawResponse,
			ReproductionScript: r.ReproductionScript,
			Response:           response,
			ResponseHeaders:  responseHeaders,
			Marker:               r.MarkerExpected,
			MainMarkerFound:      r.MainMarkerFound,
			MainMarkerLocation:   r.MainMarkerLocation,
			OtherExpectedPattern: "__[A-Za-z0-9_]+__ (exclude main expected marker)",
			OtherMarker:          r.OtherMarker,
			OtherMarkerFound:     r.OtherMarkerFound,
			OtherMarkerLocation:  r.OtherMarkerLocation,
			MarkerFound:          r.MarkerFound,
			MarkerFoundInBody:    r.MarkerFoundInBody,
			MarkerFoundInHeader:  r.MarkerFoundInHeader,
			StatusCompliant:      r.StatusCompliant,
			StatusEvidence:       r.StatusEvidence,
			Evidence:             r.Evidence,
		}

		data.Tests = append(data.Tests, testData)
	}

	return data
}

// countCriticalTests counts the number of critical severity tests
func countCriticalTests(tests []ReportTestData) int {
	count := 0
	for _, t := range tests {
		if t.Severity == "Critical" {
			count++
		}
	}
	return count
}

// isCriticalTest determines if a test ID is critical severity
func isCriticalTest(testID string) bool {
	criticalTests := []string{"V01", "V02", "V04", "V05", "V06", "V07", "V08", "V20", "V22", "V23"}
	for _, id := range criticalTests {
		if testID == id {
			return true
		}
	}
	return false
}

// isHighSeverityTest determines if a test ID is high severity
func isHighSeverityTest(testID string) bool {
	highTests := []string{"V03", "V09", "V10"}
	for _, id := range highTests {
		if testID == id {
			return true
		}
	}
	return false
}

// Helper functions for HTML generation
func getScoreCardClass(percentage float64) string {
	if percentage >= 90 {
		return "success"
	} else if percentage >= 70 {
		return "warning"
	}
	return "danger"
}

func formatDuration(start, end time.Time) string {
	d := end.Sub(start)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
}

// escapeHtml escapes special HTML characters to prevent XSS
// Used for error messages and any direct HTML string insertion
func escapeHtml(s string) string {
	return strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
	).Replace(s)
}
