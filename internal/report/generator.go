package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/waf-hackathon/benchmark/internal/phases"
	"github.com/waf-hackathon/benchmark/internal/scoring"
)

// ReportGenerator generates benchmark reports
type ReportGenerator struct {
	IncludeDetails bool
	IncludeRawData bool
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(includeDetails, includeRawData bool) *ReportGenerator {
	return &ReportGenerator{
		IncludeDetails: includeDetails,
		IncludeRawData: includeRawData,
	}
}

// BenchmarkReport is the main report structure
type BenchmarkReport struct {
	Metadata      ReportMetadata       `json:"metadata"`
	Summary       ReportSummary        `json:"summary"`
	Scores        ScoringBreakdown     `json:"scores"`
	PhaseResults  PhaseResults         `json:"phase_results"`
	Observability ObservabilityData    `json:"observability,omitempty"`
}

// ReportMetadata contains report metadata
type ReportMetadata struct {
	Version               string    `json:"version"`
	GeneratedAt           time.Time `json:"generated_at"`
	ToolVersion           string    `json:"tool_version"`
	ScoringProfile        string    `json:"scoring_profile,omitempty"`
	ScoringProfileVersion string    `json:"scoring_profile_version,omitempty"`
	WAFProduct            string    `json:"waf_product,omitempty"`
	WAFVersion            string    `json:"waf_version,omitempty"`
	TestDuration          int64     `json:"test_duration_ms"`
}

// ReportSummary contains the overall summary
type ReportSummary struct {
	TotalScore      float64 `json:"total_score"`
	MaxPossible     float64 `json:"max_possible"`
	Percentage      float64 `json:"percentage"`
	Grade           string  `json:"grade"`
	TotalTests      int     `json:"total_tests"`
	PassedTests     int     `json:"passed_tests"`
	FailedTests     int     `json:"failed_tests"`
}

// ScoringBreakdown contains score breakdown by phase
type ScoringBreakdown struct {
	PhaseA        PhaseScore `json:"phase_a"`
	PhaseB        PhaseScore `json:"phase_b"`
	PhaseC        PhaseScore `json:"phase_c"`
	PhaseD        PhaseScore `json:"phase_d"`
	PhaseE        PhaseScore `json:"phase_e"`
	RiskLifecycle PhaseScore `json:"risk_lifecycle"`
}

// PhaseScore contains scores for a single phase
type PhaseScore struct {
	Score       float64 `json:"score"`
	MaxPossible float64 `json:"max_possible"`
	Percentage  float64 `json:"percentage"`
	Passed      int     `json:"passed"`
	Total       int     `json:"total"`
}

// PhaseResults contains detailed phase results
type PhaseResults struct {
	PhaseA        *PhaseAResults        `json:"phase_a,omitempty"`
	PhaseB        *PhaseBResults        `json:"phase_b,omitempty"`
	PhaseC        *PhaseCResults        `json:"phase_c,omitempty"`
	PhaseD        *PhaseDResults        `json:"phase_d,omitempty"`
	PhaseE        *PhaseEResults        `json:"phase_e,omitempty"`
	RiskLifecycle *RiskLifecycleResults `json:"risk_lifecycle,omitempty"`
}

// PhaseAResults contains Phase A detailed results
type PhaseAResults struct {
	ExploitPreventionRate float64        `json:"exploit_prevention_rate"`
	OutboundFilterRate    float64        `json:"outbound_filter_rate"`
	BlockedExploits       int            `json:"blocked_exploits"`
	TotalExploits         int            `json:"total_exploits"`
	FilteredLeaks         int            `json:"filtered_leaks"`
	TotalLeaks            int            `json:"total_leaks"`
	ExploitTests          []TestResult   `json:"exploit_tests,omitempty"`
	LeakTests             []TestResult   `json:"leak_tests,omitempty"`
}

// PhaseBResults contains Phase B detailed results
type PhaseBResults struct {
	AbuseDetectionRate float64           `json:"abuse_detection_rate"`
	PassedTests        int               `json:"passed_tests"`
	TotalTests         int               `json:"total_tests"`
	CategorySummary    map[string]CategoryResult `json:"category_summary,omitempty"`
	AbuseTests         []TestResult      `json:"abuse_tests,omitempty"`
}

// PhaseCResults contains Phase C detailed results
type PhaseCResults struct {
	PeakRPS          float64            `json:"peak_rps"`
	SustainedRPS     float64            `json:"sustained_rps"`
	P99LatencyMs     float64            `json:"p99_latency_ms"`
	ErrorRate        float64            `json:"error_rate"`
	FalsePositiveRate float64           `json:"false_positive_rate"`
	LatencyScore     float64            `json:"latency_score"`
	ThroughputScore  float64            `json:"throughput_score"`
	MemoryScore      float64            `json:"memory_score"`
	GracefulScore    float64            `json:"graceful_score"`
}

// PhaseDResults contains Phase D detailed results
type PhaseDResults struct {
	DDoSScore         float64      `json:"ddos_score"`
	BackendScore      float64      `json:"backend_score"`
	FailModeScore     float64      `json:"fail_mode_score"`
	DDoSTests         []TestResult `json:"ddos_tests,omitempty"`
	SlowAttackTests   []TestResult `json:"slow_attack_tests,omitempty"`
	BackendTests      []TestResult `json:"backend_tests,omitempty"`
	FailModeTests     []TestResult `json:"fail_mode_tests,omitempty"`
}

// PhaseEResults contains Phase E detailed results
type PhaseEResults struct {
	HotReloadScore float64              `json:"hot_reload_score"`
	CachingScore   float64              `json:"caching_score"`
	HotReloadTests []TestResult         `json:"hot_reload_tests,omitempty"`
	CacheTests     []TestResult         `json:"cache_tests,omitempty"`
}

// RiskLifecycleResults contains Risk Lifecycle detailed results
type RiskLifecycleResults struct {
	TotalScore float64                  `json:"total_score"`
	Steps      []LifecycleStepResult    `json:"steps,omitempty"`
}

// LifecycleStepResult contains a single step result
type LifecycleStepResult struct {
	StepNumber  int     `json:"step_number"`
	Name        string  `json:"name"`
	Passed      bool    `json:"passed"`
	RiskScore   int     `json:"risk_score"`
	Action      string  `json:"action"`
}

// CategoryResult contains results for a category
type CategoryResult struct {
	Category string `json:"category"`
	Passed   int    `json:"passed"`
	Total    int    `json:"total"`
}

// TestResult contains a single test result
type TestResult struct {
	TestID      string  `json:"test_id"`
	Name        string  `json:"name"`
	Passed      bool    `json:"passed"`
	Description string  `json:"description,omitempty"`
}

// ObservabilityData contains observability headers data
type ObservabilityData struct {
	RiskScores    []int    `json:"risk_scores,omitempty"`
	Actions       []string `json:"actions,omitempty"`
	RequestIDs    []string `json:"request_ids,omitempty"`
	RuleIDs       []string `json:"rule_ids,omitempty"`
	CacheStatuses []string `json:"cache_statuses,omitempty"`
}

// GenerateJSONReport generates a JSON report from the score report
func (rg *ReportGenerator) GenerateJSONReport(scoreReport *scoring.ScoreReport) ([]byte, error) {
	if scoreReport == nil {
		return nil, fmt.Errorf("score report is nil")
	}

	report := rg.buildBenchmarkReport(scoreReport)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report: %w", err)
	}

	return data, nil
}

// buildBenchmarkReport builds the complete benchmark report
func (rg *ReportGenerator) buildBenchmarkReport(scoreReport *scoring.ScoreReport) *BenchmarkReport {
	overall := scoreReport.OverallScore

	report := &BenchmarkReport{
		Metadata: ReportMetadata{
			Version:               "2.1",
			GeneratedAt:           time.Now(),
			ToolVersion:           "2.1.0",
			ScoringProfile:        "option_a_full_120",
			ScoringProfileVersion: "scoring_matrix.csv@v2.1",
			TestDuration:          0, // Will be calculated from phases
		},
		Summary: ReportSummary{
			TotalScore:  overall.Total,
			MaxPossible: overall.MaxPossible,
			Percentage:  overall.Percentage,
			Grade:       overall.Grade,
		},
		Scores: ScoringBreakdown{
			PhaseA: PhaseScore{
				Score:       overall.PhaseA,
				MaxPossible: 20,
				Percentage:  safePercentage(overall.PhaseA, 20),
			},
			PhaseB: PhaseScore{
				Score:       overall.PhaseB,
				MaxPossible: 10,
				Percentage:  safePercentage(overall.PhaseB, 10),
			},
			PhaseC: PhaseScore{
				Score:       overall.PhaseC,
				MaxPossible: 20,
				Percentage:  safePercentage(overall.PhaseC, 20),
			},
			PhaseD: PhaseScore{
				Score:       overall.PhaseD,
				MaxPossible: 9,
				Percentage:  safePercentage(overall.PhaseD, 9),
			},
			PhaseE: PhaseScore{
				Score:       overall.PhaseE,
				MaxPossible: 10,
				Percentage:  safePercentage(overall.PhaseE, 10),
			},
			RiskLifecycle: PhaseScore{
				Score:       overall.RiskLifecycle,
				MaxPossible: 8,
				Percentage:  safePercentage(overall.RiskLifecycle, 8),
			},
		},
	}

	// Count tests and add details if requested
	totalDuration := int64(0)
	totalTests := 0
	passedTests := 0

	// Phase A
	if scoreReport.PhaseADetails != nil && rg.IncludeDetails {
		report.PhaseResults.PhaseA = rg.buildPhaseAResults(scoreReport.PhaseADetails)
		totalDuration += scoreReport.PhaseADetails.DurationMs
		totalTests += scoreReport.PhaseADetails.TotalExploits + scoreReport.PhaseADetails.TotalLeaks
		passedTests += scoreReport.PhaseADetails.BlockedExploits + scoreReport.PhaseADetails.FilteredLeaks
		report.Scores.PhaseA.Passed = scoreReport.PhaseADetails.BlockedExploits + scoreReport.PhaseADetails.FilteredLeaks
		report.Scores.PhaseA.Total = scoreReport.PhaseADetails.TotalExploits + scoreReport.PhaseADetails.TotalLeaks
	}

	// Phase B
	if scoreReport.PhaseBDetails != nil && rg.IncludeDetails {
		report.PhaseResults.PhaseB = rg.buildPhaseBResults(scoreReport.PhaseBDetails)
		totalDuration += scoreReport.PhaseBDetails.DurationMs
		totalTests += scoreReport.PhaseBDetails.TotalTests
		passedTests += scoreReport.PhaseBDetails.PassedTests
		report.Scores.PhaseB.Passed = scoreReport.PhaseBDetails.PassedTests
		report.Scores.PhaseB.Total = scoreReport.PhaseBDetails.TotalTests
	}

	// Phase C
	if scoreReport.PhaseCDetails != nil && rg.IncludeDetails {
		report.PhaseResults.PhaseC = rg.buildPhaseCResults(scoreReport.PhaseCDetails)
		totalDuration += scoreReport.PhaseCDetails.DurationMs
	}

	// Phase D
	if scoreReport.PhaseDDetails != nil && rg.IncludeDetails {
		report.PhaseResults.PhaseD = rg.buildPhaseDResults(scoreReport.PhaseDDetails)
		totalDuration += scoreReport.PhaseDDetails.DurationMs

		// Count DDoS + Backend + FailMode tests
		dDoSPassed := 0
		for _, t := range scoreReport.PhaseDDetails.DDoSTests {
			if t.Passed {
				dDoSPassed++
			}
		}
		backendPassed := 0
		for _, t := range scoreReport.PhaseDDetails.BackendFailureTests {
			if t.Passed {
				backendPassed++
			}
		}
		failModePassed := 0
		for _, t := range scoreReport.PhaseDDetails.FailModeTests {
			if t.Passed {
				failModePassed++
			}
		}
		report.Scores.PhaseD.Passed = dDoSPassed + backendPassed + failModePassed
		report.Scores.PhaseD.Total = len(scoreReport.PhaseDDetails.DDoSTests) + len(scoreReport.PhaseDDetails.BackendFailureTests) + len(scoreReport.PhaseDDetails.FailModeTests)
	}

	// Phase E
	if scoreReport.PhaseEDetails != nil && rg.IncludeDetails {
		report.PhaseResults.PhaseE = rg.buildPhaseEResults(scoreReport.PhaseEDetails)
		totalDuration += scoreReport.PhaseEDetails.DurationMs

		hotReloadPassed := 0
		for _, t := range scoreReport.PhaseEDetails.HotReloadTests {
			if t.Passed {
				hotReloadPassed++
			}
		}
		cachePassed := 0
		for _, t := range scoreReport.PhaseEDetails.CacheTests {
			if t.Passed {
				cachePassed++
			}
		}
		report.Scores.PhaseE.Passed = hotReloadPassed + cachePassed
		report.Scores.PhaseE.Total = len(scoreReport.PhaseEDetails.HotReloadTests) + len(scoreReport.PhaseEDetails.CacheTests)
	}

	// Risk Lifecycle
	if scoreReport.RiskLifecycleDetails != nil && rg.IncludeDetails {
		report.PhaseResults.RiskLifecycle = rg.buildRiskLifecycleResults(scoreReport.RiskLifecycleDetails)
		totalDuration += scoreReport.RiskLifecycleDetails.DurationMs

		passed := 0
		for _, step := range scoreReport.RiskLifecycleDetails.Steps {
			if step.Passed {
				passed++
			}
		}
		report.Scores.RiskLifecycle.Passed = passed
		report.Scores.RiskLifecycle.Total = len(scoreReport.RiskLifecycleDetails.Steps)
	}

	report.Metadata.TestDuration = totalDuration
	report.Summary.TotalTests = totalTests
	report.Summary.PassedTests = passedTests
	report.Summary.FailedTests = totalTests - passedTests

	return report
}

// buildPhaseAResults builds Phase A results
func (rg *ReportGenerator) buildPhaseAResults(details *phases.PhaseAResult) *PhaseAResults {
	result := &PhaseAResults{
		ExploitPreventionRate: details.ExploitPreventionRate,
		OutboundFilterRate:    details.OutboundFilterRate,
		BlockedExploits:       details.BlockedExploits,
		TotalExploits:         details.TotalExploits,
		FilteredLeaks:         details.FilteredLeaks,
		TotalLeaks:            details.TotalLeaks,
	}

	if rg.IncludeRawData {
		result.ExploitTests = make([]TestResult, 0)
		for _, test := range details.ExploitTests {
			result.ExploitTests = append(result.ExploitTests, TestResult{
				TestID:      test.TestID,
				Passed:      test.IsPassed(),
				Description: test.Description,
			})
		}
	}

	return result
}

// buildPhaseBResults builds Phase B results
func (rg *ReportGenerator) buildPhaseBResults(details *phases.PhaseBResult) *PhaseBResults {
	result := &PhaseBResults{
		AbuseDetectionRate: details.AbuseDetectionRate,
		PassedTests:        details.PassedTests,
		TotalTests:         details.TotalTests,
	}

	if rg.IncludeRawData {
		result.AbuseTests = make([]TestResult, 0)
		for _, test := range details.AbuseTests {
			result.AbuseTests = append(result.AbuseTests, TestResult{
				TestID:      test.TestID,
				Passed:      test.Passed,
				Description: "", // Would need to get from catalog
			})
		}
	}

	return result
}

// buildPhaseCResults builds Phase C results
func (rg *ReportGenerator) buildPhaseCResults(details *phases.PhaseCResult) *PhaseCResults {
	errorRate := 0.0
	if details.TotalRequests > 0 {
		errorRate = float64(details.FailedReqs) / float64(details.TotalRequests)
	}
	return &PhaseCResults{
		PeakRPS:           details.PeakRPS,
		SustainedRPS:      details.SustainedRPS,
		P99LatencyMs:      details.P99OverheadMs,
		ErrorRate:         errorRate,
		FalsePositiveRate: details.FalsePosRate,
		LatencyScore:      details.LatencyScore,
		ThroughputScore:   details.ThroughputScore,
		MemoryScore:       details.MemoryScore,
		GracefulScore:     details.GracefulScore,
	}
}

// buildPhaseDResults builds Phase D results
func (rg *ReportGenerator) buildPhaseDResults(details *phases.PhaseDResult) *PhaseDResults {
	result := &PhaseDResults{
		DDoSScore:     details.DDoSScore,
		BackendScore:  details.BackendScore,
		FailModeScore: details.FailModeScore,
	}

	if rg.IncludeRawData {
		result.DDoSTests = make([]TestResult, 0)
		for _, test := range details.DDoSTests {
			result.DDoSTests = append(result.DDoSTests, TestResult{
				TestID: test.TestID,
				Name:   test.Name,
				Passed: test.Passed,
			})
		}

		result.SlowAttackTests = make([]TestResult, 0)
		for _, test := range details.SlowAttackTests {
			result.SlowAttackTests = append(result.SlowAttackTests, TestResult{
				TestID: test.TestID,
				Name:   test.Name,
				Passed: test.Passed,
			})
		}

		result.BackendTests = make([]TestResult, 0)
		for _, test := range details.BackendFailureTests {
			result.BackendTests = append(result.BackendTests, TestResult{
				TestID: test.TestID,
				Name:   test.Name,
				Passed: test.Passed,
			})
		}
		result.FailModeTests = make([]TestResult, 0)
		for _, test := range details.FailModeTests {
			result.FailModeTests = append(result.FailModeTests, TestResult{
				TestID: test.TestID,
				Name:   test.Name,
				Passed: test.Passed,
			})
		}
	}

	return result
}

// buildPhaseEResults builds Phase E results
func (rg *ReportGenerator) buildPhaseEResults(details *phases.PhaseEResult) *PhaseEResults {
	result := &PhaseEResults{
		HotReloadScore: details.HotReloadScore,
		CachingScore:   details.CachingScore,
	}

	if rg.IncludeRawData {
		result.HotReloadTests = make([]TestResult, 0)
		for _, test := range details.HotReloadTests {
			result.HotReloadTests = append(result.HotReloadTests, TestResult{
				TestID:      test.TestID,
				Name:        test.Name,
				Passed:      test.Passed,
				Description: test.Description,
			})
		}

		result.CacheTests = make([]TestResult, 0)
		for _, test := range details.CacheTests {
			result.CacheTests = append(result.CacheTests, TestResult{
				TestID:      test.TestID,
				Name:        test.Name,
				Passed:      test.Passed,
				Description: test.Description,
			})
		}
	}

	return result
}

// buildRiskLifecycleResults builds Risk Lifecycle results
func (rg *ReportGenerator) buildRiskLifecycleResults(details *phases.RiskLifecycleResult) *RiskLifecycleResults {
	result := &RiskLifecycleResults{
		TotalScore: details.TotalScore,
	}

	if rg.IncludeRawData {
		result.Steps = make([]LifecycleStepResult, 0)
		for i, step := range details.Steps {
			result.Steps = append(result.Steps, LifecycleStepResult{
				StepNumber: i + 1,
				Name:       step.Name,
				Passed:     step.Passed,
				RiskScore:  step.RiskScore,
				Action:     step.Action,
			})
		}
	}

	return result
}

// GenerateTextReport generates a plain text report
func (rg *ReportGenerator) GenerateTextReport(scoreReport *scoring.ScoreReport) string {
	if scoreReport == nil {
		return "Error: No score report available"
	}

	overall := scoreReport.OverallScore

	report := fmt.Sprintf(
		"WAF Benchmark Report v2.1\n"+
		"========================\n\n"+
		"Generated: %s\n"+
		"Tool Version: 2.1.0\n\n"+
		"OVERALL SCORE: %.1f/%.0f (%.1f%%) - Grade: %s\n\n"+
		"Category Breakdown (Option A - 120):\n"+
		"  SEC Security Effectiveness: %.1f/40 (%.0f%%)\n"+
		"  PERF Performance:           %.1f/20 (%.0f%%)\n"+
		"  INT Intelligence:           %.1f/20 (%.0f%%)\n"+
		"  EXT Extensibility:          %.1f/10 (%.0f%%)\n"+
		"  ARCH Architecture:          %.1f/15 (%.0f%%)\n"+
		"  UI Dashboard:               %.1f/10 (%.0f%%)\n"+
		"  DEP Deployment:             %.1f/5  (%.0f%%)\n",
		time.Now().Format("2006-01-02 15:04:05"),
		overall.Total, overall.MaxPossible, overall.Percentage, overall.Grade,
		overall.SecurityEffectiveness, (overall.SecurityEffectiveness/40)*100,
		overall.Performance, (overall.Performance/20)*100,
		overall.Intelligence, (overall.Intelligence/20)*100,
		overall.Extensibility, (overall.Extensibility/10)*100,
		overall.Architecture, (overall.Architecture/15)*100,
		overall.Dashboard, (overall.Dashboard/10)*100,
		overall.Deployment, (overall.Deployment/5)*100,
	)

	return report
}

// GenerateHTMLReport generates an HTML dashboard report from the score report
// This implements Phase 10.4: HTML Report (Optional)
func (rg *ReportGenerator) GenerateHTMLReport(scoreReport *scoring.ScoreReport) ([]byte, error) {
	if scoreReport == nil {
		return nil, fmt.Errorf("score report is nil")
	}

	overall := scoreReport.OverallScore

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Benchmark Report v2.1</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 100%%);
            color: #eee;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            text-align: center;
            padding: 40px 20px;
            background: rgba(255,255,255,0.05);
            border-radius: 20px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
        }
        h1 { font-size: 2.5em; margin-bottom: 10px; color: #00d4aa; }
        .timestamp { color: #888; font-size: 0.9em; }
        .grade-badge {
            display: inline-block;
            padding: 15px 40px;
            border-radius: 50px;
            font-size: 3em;
            font-weight: bold;
            margin: 20px 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .grade-a-plus { background: linear-gradient(135deg, #00d4aa, #00a884); }
        .grade-a { background: linear-gradient(135deg, #00d4aa, #00a884); }
        .grade-a-minus { background: linear-gradient(135deg, #00c9a7, #00a884); }
        .grade-b-plus { background: linear-gradient(135deg, #4facfe, #00f2fe); }
        .grade-b { background: linear-gradient(135deg, #43e97b, #38f9d7); }
        .grade-b-minus { background: linear-gradient(135deg, #38f9d7, #4facfe); }
        .grade-c-plus { background: linear-gradient(135deg, #fa709a, #fee140); }
        .grade-c { background: linear-gradient(135deg, #feca57, #ff9ff3); }
        .grade-d { background: linear-gradient(135deg, #ff9ff3, #feca57); }
        .grade-f { background: linear-gradient(135deg, #ff6b6b, #ee5a24); }
        .score-overview {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .score-card {
            background: rgba(255,255,255,0.05);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            transition: transform 0.3s, box-shadow 0.3s;
            backdrop-filter: blur(10px);
        }
        .score-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }
        .score-card.pass { border-top: 4px solid #00d4aa; }
        .score-card.fail { border-top: 4px solid #ff6b6b; }
        .score-card.warning { border-top: 4px solid #feca57; }
        .score-value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .score-label { color: #888; font-size: 0.9em; text-transform: uppercase; }
        .phase-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .phase-card {
            background: rgba(255,255,255,0.03);
            border-radius: 15px;
            padding: 25px;
            backdrop-filter: blur(10px);
        }
        .phase-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        .phase-title { font-size: 1.2em; color: #00d4aa; }
        .phase-score { font-size: 1.5em; font-weight: bold; }
        .progress-bar {
            height: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-fill {
            height: 100%%;
            border-radius: 4px;
            transition: width 1s ease;
        }
        .progress-fill.high { background: linear-gradient(90deg, #00d4aa, #00a884); }
        .progress-fill.medium { background: linear-gradient(90deg, #feca57, #ff9ff3); }
        .progress-fill.low { background: linear-gradient(90deg, #ff6b6b, #ee5a24); }
        .details-section {
            background: rgba(255,255,255,0.03);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
        }
        .details-title {
            color: #00d4aa;
            margin-bottom: 20px;
            font-size: 1.3em;
        }
        table {
            width: 100%%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }
        th {
            color: #888;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
        }
        .status-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .status-pass { background: rgba(0,212,170,0.2); color: #00d4aa; }
        .status-fail { background: rgba(255,107,107,0.2); color: #ff6b6b; }
        .status-warn { background: rgba(254,202,87,0.2); color: #feca57; }
        footer {
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9em;
        }
        @media (max-width: 768px) {
            .phase-grid { grid-template-columns: 1fr; }
            .score-overview { grid-template-columns: repeat(2, 1fr); }
            h1 { font-size: 1.8em; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ WAF Benchmark Report v2.1</h1>
            <div class="timestamp">Generated: %s</div>
            <div class="grade-badge %s">%s</div>
            <div style="font-size: 1.5em; margin-top: 10px;">
                Overall Score: <strong>%.1f/%.0f (%.1f%%)</strong>
            </div>
        </header>

        <div class="score-overview">
            <div class="score-card %s">
                <div class="score-label">Exploit Prevention</div>
                <div class="score-value" style="color: %s;">%.1f<span style="font-size: 0.5em;">/20</span></div>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
            <div class="score-card %s">
                <div class="score-label">Abuse Detection</div>
                <div class="score-value" style="color: %s;">%.1f<span style="font-size: 0.5em;">/10</span></div>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
            <div class="score-card %s">
                <div class="score-label">Performance</div>
                <div class="score-value" style="color: %s;">%.1f<span style="font-size: 0.5em;">/20</span></div>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
            <div class="score-card %s">
                <div class="score-label">Resilience</div>
                <div class="score-value" style="color: %s;">%.1f<span style="font-size: 0.5em;">/9</span></div>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
            <div class="score-card %s">
                <div class="score-label">Extensibility</div>
                <div class="score-value" style="color: %s;">%.1f<span style="font-size: 0.5em;">/10</span></div>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
            <div class="score-card %s">
                <div class="score-label">Risk Lifecycle</div>
                <div class="score-value" style="color: %s;">%.1f<span style="font-size: 0.5em;">/8</span></div>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
        </div>

        <div class="phase-grid">
            <div class="phase-card">
                <div class="phase-header">
                    <span class="phase-title">🔒 Phase A: Exploit Prevention</span>
                    <span class="phase-score">%.1f/20</span>
                </div>
                <p>Tests 24 vulnerability types and 5 outbound leak scenarios</p>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
            <div class="phase-card">
                <div class="phase-header">
                    <span class="phase-title">🚦 Phase B: Abuse Detection</span>
                    <span class="phase-score">%.1f/10</span>
                </div>
                <p>Brute force, relay, behavioral, fraud, and reconnaissance detection</p>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
            <div class="phase-card">
                <div class="phase-header">
                    <span class="phase-title">⚡ Phase C: Performance</span>
                    <span class="phase-score">%.1f/20</span>
                </div>
                <p>Latency, throughput, memory usage, and graceful degradation under load</p>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
            <div class="phase-card">
                <div class="phase-header">
                    <span class="phase-title">🛡️ Phase D: Resilience</span>
                    <span class="phase-score">%.1f/9</span>
                </div>
                <p>DDoS resistance, slow attack handling, and backend failure modes</p>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
            <div class="phase-card">
                <div class="phase-header">
                    <span class="phase-title">🔧 Phase E: Extensibility</span>
                    <span class="phase-score">%.1f/10</span>
                </div>
                <p>Hot-reload capabilities and caching behavior per tier</p>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
            <div class="phase-card">
                <div class="phase-header">
                    <span class="phase-title">📊 Risk Lifecycle</span>
                    <span class="phase-score">%.1f/8</span>
                </div>
                <p>7-step risk scoring and device reputation tracking</p>
                <div class="progress-bar"><div class="progress-fill %s" style="width: %.1f%%;"></div></div>
            </div>
        </div>

        <footer>
            <p>WAF Benchmark Tool v2.1.0 | Automated Security Validation Framework</p>
            <p style="margin-top: 10px; font-size: 0.85em;">Report generated by WAF Benchmark Tool</p>
        </footer>
    </div>
</body>
</html>`,
		time.Now().Format("2006-01-02 15:04:05"),
		getGradeClass(overall.Grade),
		overall.Grade,
		overall.Total, overall.MaxPossible, overall.Percentage,
		// Phase A card
		getScoreCardClass(overall.PhaseA, 20),
		getScoreColor(overall.PhaseA, 20),
		overall.PhaseA,
		getProgressClass(overall.PhaseA, 20),
		(overall.PhaseA/20)*100,
		// Phase B card
		getScoreCardClass(overall.PhaseB, 10),
		getScoreColor(overall.PhaseB, 10),
		overall.PhaseB,
		getProgressClass(overall.PhaseB, 10),
		(overall.PhaseB/10)*100,
		// Phase C card
		getScoreCardClass(overall.PhaseC, 20),
		getScoreColor(overall.PhaseC, 20),
		overall.PhaseC,
		getProgressClass(overall.PhaseC, 20),
		(overall.PhaseC/20)*100,
		// Phase D card
		getScoreCardClass(overall.PhaseD, 9),
		getScoreColor(overall.PhaseD, 9),
		overall.PhaseD,
		getProgressClass(overall.PhaseD, 9),
		(overall.PhaseD/9)*100,
		// Phase E card
		getScoreCardClass(overall.PhaseE, 10),
		getScoreColor(overall.PhaseE, 10),
		overall.PhaseE,
		getProgressClass(overall.PhaseE, 10),
		(overall.PhaseE/10)*100,
		// Risk Lifecycle card
		getScoreCardClass(overall.RiskLifecycle, 8),
		getScoreColor(overall.RiskLifecycle, 8),
		overall.RiskLifecycle,
		getProgressClass(overall.RiskLifecycle, 8),
		(overall.RiskLifecycle/8)*100,
		// Phase cards progress bars
		overall.PhaseA,
		getProgressClass(overall.PhaseA, 20),
		(overall.PhaseA/20)*100,
		overall.PhaseB,
		getProgressClass(overall.PhaseB, 10),
		(overall.PhaseB/10)*100,
		overall.PhaseC,
		getProgressClass(overall.PhaseC, 20),
		(overall.PhaseC/20)*100,
		overall.PhaseD,
		getProgressClass(overall.PhaseD, 9),
		(overall.PhaseD/9)*100,
		overall.PhaseE,
		getProgressClass(overall.PhaseE, 10),
		(overall.PhaseE/10)*100,
		overall.RiskLifecycle,
		getProgressClass(overall.RiskLifecycle, 8),
		(overall.RiskLifecycle/8)*100,
	)

	return []byte(html), nil
}

// safePercentage calculates percentage safely avoiding NaN
func safePercentage(score, max float64) float64 {
	if max <= 0 {
		return 0
	}
	return (score / max) * 100
}
func getGradeClass(grade string) string {
	switch grade {
	case "A+":
		return "grade-a-plus"
	case "A":
		return "grade-a"
	case "A-":
		return "grade-a-minus"
	case "B+":
		return "grade-b-plus"
	case "B":
		return "grade-b"
	case "B-":
		return "grade-b-minus"
	case "C+", "C":
		return "grade-c"
	case "D":
		return "grade-d"
	default:
		return "grade-f"
	}
}

// getScoreCardClass returns the CSS class for a score card based on performance
func getScoreCardClass(score, max float64) string {
	percentage := (score / max) * 100
	switch {
	case percentage >= 80:
		return "pass"
	case percentage >= 50:
		return "warning"
	default:
		return "fail"
	}
}

// getScoreColor returns the color for a score
func getScoreColor(score, max float64) string {
	percentage := (score / max) * 100
	switch {
	case percentage >= 80:
		return "#00d4aa"
	case percentage >= 50:
		return "#feca57"
	default:
		return "#ff6b6b"
	}
}

// getProgressClass returns the CSS class for a progress bar
func getProgressClass(score, max float64) string {
	percentage := (score / max) * 100
	switch {
	case percentage >= 80:
		return "high"
	case percentage >= 50:
		return "medium"
	default:
		return "low"
	}
}
