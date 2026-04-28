package report

import (
	"encoding/json"
	"testing"

	"github.com/waf-hackathon/benchmark/internal/phases"
	"github.com/waf-hackathon/benchmark/internal/scoring"
)

func TestNewReportGenerator(t *testing.T) {
	rg := NewReportGenerator(true, true)

	if rg == nil {
		t.Fatal("NewReportGenerator returned nil")
	}

	if !rg.IncludeDetails {
		t.Error("IncludeDetails should be true")
	}

	if !rg.IncludeRawData {
		t.Error("IncludeRawData should be true")
	}
}

func TestGenerateJSONReport(t *testing.T) {
	rg := NewReportGenerator(true, false)

	scoreReport := scoring.NewScoreReport(
		&phases.PhaseAResult{
			ExploitPreventionRate: 90.0,
			OutboundFilterRate:    80.0,
			BlockedExploits:       18,
			TotalExploits:         20,
			FilteredLeaks:         4,
			TotalLeaks:            5,
			DurationMs:          5000,
		},
		&phases.PhaseBResult{
			AbuseDetectionRate: 85.0,
			PassedTests:        19,
			TotalTests:         22,
			DurationMs:         8000,
		},
		&phases.PhaseCResult{
			PeakRPS:       8000,
			SustainedRPS:  5000,
			LatencyScore:  10,
			ThroughputScore: 5,
			MemoryScore:   3,
			GracefulScore: 2,
			DurationMs:    120000,
		},
		&phases.PhaseDResult{
			DDoSScore:     3,
			BackendScore:  2,
			FailModeScore: 0,
			DurationMs:    300000,
		},
		&phases.PhaseEResult{
			HotReloadScore: 6,
			CachingScore:   4,
			DurationMs:     30000,
		},
		&phases.RiskLifecycleResult{
			TotalScore: 6,
			DurationMs: 60000,
			Steps: []phases.LifecycleStep{
				{StepNumber: 1, Passed: true},
				{StepNumber: 2, Passed: true},
				{StepNumber: 3, Passed: false},
				{StepNumber: 4, Passed: true},
				{StepNumber: 5, Passed: true},
				{StepNumber: 6, Passed: false},
				{StepNumber: 7, Passed: true},
			},
		},
	)

	jsonData, err := rg.GenerateJSONReport(scoreReport)
	if err != nil {
		t.Fatalf("GenerateJSONReport failed: %v", err)
	}

	if len(jsonData) == 0 {
		t.Error("JSON report should not be empty")
	}

	// Verify it's valid JSON
	var report BenchmarkReport
	if err := json.Unmarshal(jsonData, &report); err != nil {
		t.Errorf("Generated JSON is invalid: %v", err)
	}

	// Verify basic structure
	if report.Metadata.Version != "2.1" {
		t.Error("Report version should be 2.1")
	}

	if report.Summary.TotalScore == 0 {
		t.Error("Summary should have total score")
	}
}

func TestGenerateJSONReportNil(t *testing.T) {
	rg := NewReportGenerator(true, true)

	_, err := rg.GenerateJSONReport(nil)
	if err == nil {
		t.Error("GenerateJSONReport should return error for nil input")
	}
}

func TestGenerateTextReport(t *testing.T) {
	rg := NewReportGenerator(false, false)

	scoreReport := scoring.NewScoreReport(
		&phases.PhaseAResult{ExploitPreventionRate: 100, OutboundFilterRate: 100},
		&phases.PhaseBResult{AbuseDetectionRate: 100},
		&phases.PhaseCResult{
			LatencyScore: 10, ThroughputScore: 5, MemoryScore: 3, GracefulScore: 2,
		},
		&phases.PhaseDResult{DDoSScore: 4, BackendScore: 3, FailModeScore: 2},
		&phases.PhaseEResult{HotReloadScore: 6, CachingScore: 4},
		&phases.RiskLifecycleResult{
			Steps: []phases.LifecycleStep{
				{Passed: true}, {Passed: true}, {Passed: true},
				{Passed: true}, {Passed: true}, {Passed: true}, {Passed: true},
			},
		},
	)

	text := rg.GenerateTextReport(scoreReport)

	if text == "" {
		t.Error("Text report should not be empty")
	}

	if !containsString(text, "WAF Benchmark Report") {
		t.Error("Text report should have title")
	}

	if !containsString(text, "92.0/120") {
		t.Error("Text report should show automated total on 120-point profile")
	}

	if !containsString(text, "Grade: B") {
		t.Error("Text report should show B grade for current automated coverage")
	}
}

func TestGenerateTextReportNil(t *testing.T) {
	rg := NewReportGenerator(false, false)

	text := rg.GenerateTextReport(nil)

	if !containsString(text, "Error") {
		t.Error("Text report should show error for nil input")
	}
}

func TestBenchmarkReportStructure(t *testing.T) {
	report := BenchmarkReport{
		Metadata: ReportMetadata{
			Version:     "2.1",
			ToolVersion: "2.1.0",
		},
		Summary: ReportSummary{
			TotalScore:  65.5,
			MaxPossible: 120.0,
			Percentage:  85.1,
			Grade:       "A-",
		},
		Scores: ScoringBreakdown{
			PhaseA: PhaseScore{
				Score:       18.0,
				MaxPossible: 20,
				Percentage:  90,
				Passed:      22,
				Total:       25,
			},
		},
	}

	if report.Metadata.Version != "2.1" {
		t.Error("Version mismatch")
	}

	if report.Summary.TotalScore != 65.5 {
		t.Errorf("TotalScore = %v, want 65.5", report.Summary.TotalScore)
	}

	if report.Summary.Grade != "A-" {
		t.Errorf("Grade = %v, want A-", report.Summary.Grade)
	}

	if report.Scores.PhaseA.Score != 18.0 {
		t.Errorf("PhaseA Score = %v, want 18.0", report.Scores.PhaseA.Score)
	}
}

func TestReportSerialization(t *testing.T) {
	report := &BenchmarkReport{
		Metadata: ReportMetadata{
			Version:      "2.1",
			ToolVersion:  "2.1.0",
			WAFProduct:   "TestWAF",
			WAFVersion:   "1.0.0",
			TestDuration: 300000,
		},
		Summary: ReportSummary{
			TotalScore:  65.5,
			MaxPossible: 120.0,
			Percentage:  85.1,
			Grade:       "A-",
			TotalTests:  100,
			PassedTests: 85,
			FailedTests: 15,
		},
	}

	// Serialize
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Failed to marshal report: %v", err)
	}

	// Deserialize
	var decoded BenchmarkReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal report: %v", err)
	}

	// Verify
	if decoded.Metadata.Version != report.Metadata.Version {
		t.Error("Version mismatch after serialization")
	}

	if decoded.Summary.TotalScore != report.Summary.TotalScore {
		t.Error("TotalScore mismatch after serialization")
	}

	if decoded.Summary.Grade != report.Summary.Grade {
		t.Error("Grade mismatch after serialization")
	}
}

func TestPhaseResultsStructure(t *testing.T) {
	phaseResults := PhaseResults{
		PhaseA: &PhaseAResults{
			ExploitPreventionRate: 90.0,
			OutboundFilterRate:    80.0,
			BlockedExploits:     18,
			TotalExploits:       20,
			FilteredLeaks:       4,
			TotalLeaks:          5,
		},
		PhaseC: &PhaseCResults{
			PeakRPS:       8000,
			SustainedRPS:  5000,
			P99LatencyMs:  5.0,
			LatencyScore:  10,
			ThroughputScore: 5,
		},
	}

	if phaseResults.PhaseA.BlockedExploits != 18 {
		t.Error("BlockedExploits mismatch")
	}

	if phaseResults.PhaseC.PeakRPS != 8000 {
		t.Error("PeakRPS mismatch")
	}

	if phaseResults.PhaseB != nil {
		t.Error("PhaseB should be nil")
	}
}

func TestTestResultStructure(t *testing.T) {
	tr := TestResult{
		TestID:      "V01",
		Name:        "SQL Injection",
		Passed:      true,
		Description: "Classic SQLi test",
	}

	if tr.TestID != "V01" {
		t.Error("TestID mismatch")
	}

	if !tr.Passed {
		t.Error("Passed should be true")
	}
}

func TestObservabilityDataStructure(t *testing.T) {
	obs := ObservabilityData{
		RiskScores:    []int{10, 20, 30},
		Actions:       []string{"allow", "challenge", "block"},
		RequestIDs:    []string{"req1", "req2", "req3"},
		RuleIDs:       []string{"rule1", "rule2"},
		CacheStatuses: []string{"HIT", "MISS", "HIT"},
	}

	if len(obs.RiskScores) != 3 {
		t.Error("RiskScores length mismatch")
	}

	if len(obs.Actions) != 3 {
		t.Error("Actions length mismatch")
	}
}

func TestBuildBenchmarkReport(t *testing.T) {
	rg := NewReportGenerator(true, true)

	scoreReport := scoring.NewScoreReport(
		&phases.PhaseAResult{
			ExploitPreventionRate: 90.0,
			OutboundFilterRate:    80.0,
			BlockedExploits:       18,
			TotalExploits:         20,
			FilteredLeaks:         4,
			TotalLeaks:            5,
			DurationMs:            5000,
		},
		&phases.PhaseBResult{
			AbuseDetectionRate: 85.0,
			PassedTests:        19,
			TotalTests:         22,
			DurationMs:         8000,
		},
		&phases.PhaseCResult{
			PeakRPS:         8000,
			SustainedRPS:    5000,
			LatencyScore:    10,
			ThroughputScore: 5,
			MemoryScore:     3,
			GracefulScore:   2,
			TotalRequests:   50000,
			DurationMs:      120000,
		},
		&phases.PhaseDResult{
			DDoSTests: []phases.ResilienceResult{
				{TestID: "D01", Passed: true, Name: "HTTP Flood"},
				{TestID: "D02", Passed: true, Name: "Slowloris"},
				{TestID: "D03", Passed: false, Name: "RUDY"},
			},
			DDoSScore:     2.0,
			BackendScore:  3.0,
			FailModeScore: 0.0,
			DurationMs:    300000,
		},
		&phases.PhaseEResult{
			HotReloadTests: []phases.ExtensibilityResult{
				{TestID: "E-Add", Passed: true, Name: "Add Rule"},
				{TestID: "E-Remove", Passed: true, Name: "Remove Rule"},
			},
			CacheTests: []phases.ExtensibilityResult{
				{TestID: "E01", Passed: true, Name: "Static Cache"},
				{TestID: "E02", Passed: true, Name: "Dynamic Not Cached"},
			},
			HotReloadScore: 6.0,
			CachingScore:   4.0,
			DurationMs:     30000,
		},
		&phases.RiskLifecycleResult{
			Steps: []phases.LifecycleStep{
				{StepNumber: 1, Passed: true, Name: "Baseline"},
				{StepNumber: 2, Passed: true, Name: "Exploit"},
				{StepNumber: 7, Passed: true, Name: "Challenge"},
			},
			TotalScore: 6.0,
			DurationMs: 60000,
		},
	)

	report := rg.buildBenchmarkReport(scoreReport)

	if report == nil {
		t.Fatal("buildBenchmarkReport returned nil")
	}

	// Verify phase results are included
	if report.PhaseResults.PhaseA == nil {
		t.Error("PhaseA results should be included")
	}

	if report.PhaseResults.PhaseB == nil {
		t.Error("PhaseB results should be included")
	}

	if report.PhaseResults.PhaseD == nil {
		t.Error("PhaseD results should be included")
	}

	if report.PhaseResults.PhaseE == nil {
		t.Error("PhaseE results should be included")
	}

	if report.PhaseResults.RiskLifecycle == nil {
		t.Error("Risk Lifecycle results should be included")
	}

	// Verify test counts
	if report.Summary.TotalTests == 0 {
		t.Error("Should have non-zero total tests")
	}
}

func TestBuildBenchmarkReportNoDetails(t *testing.T) {
	rg := NewReportGenerator(false, false)

	scoreReport := scoring.NewScoreReport(
		&phases.PhaseAResult{
			ExploitPreventionRate: 90.0,
			OutboundFilterRate:    80.0,
		},
		nil, nil, nil, nil, nil,
	)

	report := rg.buildBenchmarkReport(scoreReport)

	if report.PhaseResults.PhaseA != nil {
		t.Error("PhaseA should be nil when IncludeDetails is false")
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
