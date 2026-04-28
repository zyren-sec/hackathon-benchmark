package report

import (
	"strings"
	"testing"

	"github.com/waf-hackathon/benchmark/internal/phases"
	"github.com/waf-hackathon/benchmark/internal/scoring"
)

func TestGenerateHTMLReport(t *testing.T) {
	rg := NewReportGenerator(true, true)

	scoreReport := scoring.NewScoreReport(
		&phases.PhaseAResult{
			ExploitPreventionRate: 90.0,
			OutboundFilterRate:    80.0,
		},
		&phases.PhaseBResult{
			AbuseDetectionRate: 85.0,
		},
		&phases.PhaseCResult{
			LatencyScore:    10,
			ThroughputScore: 5,
			MemoryScore:     3,
			GracefulScore:   2,
		},
		&phases.PhaseDResult{
			DDoSScore:    4,
			BackendScore: 3,
			FailModeScore: 2,
		},
		&phases.PhaseEResult{
			HotReloadScore: 6,
			CachingScore:   4,
		},
		&phases.RiskLifecycleResult{
			Steps: []phases.LifecycleStep{
				{StepNumber: 1, Passed: true, RiskScore: 5, Action: "allow"},
				{StepNumber: 2, Passed: true, RiskScore: 50, Action: "block"},
				{StepNumber: 3, Passed: true, RiskScore: 100, Action: "block"},
				{StepNumber: 4, Passed: true, RiskScore: 90, Action: "block"},
				{StepNumber: 5, Passed: true, RiskScore: 10, Action: "allow"},
				{StepNumber: 6, Passed: true, RiskScore: 40, Action: "challenge"},
				{StepNumber: 7, Passed: true, RiskScore: 15, Action: "allow"},
			},
		},
	)

	html, err := rg.GenerateHTMLReport(scoreReport)
	if err != nil {
		t.Fatalf("GenerateHTMLReport failed: %v", err)
	}

	htmlStr := string(html)

	// Check for essential HTML structure
	if !strings.Contains(htmlStr, "<!DOCTYPE html>") {
		t.Error("HTML report should contain DOCTYPE")
	}

	if !strings.Contains(htmlStr, "<html") {
		t.Error("HTML report should contain html tag")
	}

	if !strings.Contains(htmlStr, "</html>") {
		t.Error("HTML report should contain closing html tag")
	}

	// Check for report content
	if !strings.Contains(htmlStr, "WAF Benchmark Report") {
		t.Error("HTML report should contain title")
	}

	// Check for overall score
	if !strings.Contains(htmlStr, "Overall Score:") {
		t.Error("HTML report should contain overall score")
	}

	// Check for phase sections
	phases := []string{
		"Exploit Prevention",
		"Abuse Detection",
		"Performance",
		"Resilience",
		"Extensibility",
		"Risk Lifecycle",
	}

	for _, phase := range phases {
		if !strings.Contains(htmlStr, phase) {
			t.Errorf("HTML report should contain phase: %s", phase)
		}
	}

	// Check for CSS styling
	if !strings.Contains(htmlStr, "<style>") {
		t.Error("HTML report should contain CSS styles")
	}

	// Check for grade badge (should have grade class)
	if !strings.Contains(htmlStr, "grade-") {
		t.Error("HTML report should contain grade CSS class")
	}
}

func TestGenerateHTMLReportNil(t *testing.T) {
	rg := NewReportGenerator(true, true)

	_, err := rg.GenerateHTMLReport(nil)
	if err == nil {
		t.Error("GenerateHTMLReport should return error for nil input")
	}
}

func TestGetGradeClass(t *testing.T) {
	tests := []struct {
		grade    string
		expected string
	}{
		{"A+", "grade-a-plus"},
		{"A", "grade-a"},
		{"A-", "grade-a-minus"},
		{"B+", "grade-b-plus"},
		{"B", "grade-b"},
		{"B-", "grade-b-minus"},
		{"C", "grade-c"},
		{"D", "grade-d"},
		{"F", "grade-f"},
		{"X", "grade-f"}, // Unknown grade defaults to F
	}

	for _, tt := range tests {
		result := getGradeClass(tt.grade)
		if result != tt.expected {
			t.Errorf("getGradeClass(%s) = %s, want %s", tt.grade, result, tt.expected)
		}
	}
}

func TestGetScoreCardClass(t *testing.T) {
	tests := []struct {
		score    float64
		max      float64
		expected string
	}{
		{90, 100, "pass"},      // 90%% >= 80%%
		{80, 100, "pass"},      // 80%% >= 80%%
		{70, 100, "warning"},   // 70%% >= 50%% but < 80%%
		{50, 100, "warning"},   // 50%% == 50%%
		{40, 100, "fail"},      // 40%% < 50%%
		{0, 100, "fail"},       // 0%% < 50%%
	}

	for _, tt := range tests {
		result := getScoreCardClass(tt.score, tt.max)
		if result != tt.expected {
			t.Errorf("getScoreCardClass(%.0f, %.0f) = %s, want %s", tt.score, tt.max, result, tt.expected)
		}
	}
}

func TestGetScoreColor(t *testing.T) {
	tests := []struct {
		score    float64
		max      float64
		expected string
	}{
		{90, 100, "#00d4aa"},   // High
		{80, 100, "#00d4aa"},   // High boundary
		{70, 100, "#feca57"},   // Medium
		{50, 100, "#feca57"},   // Medium boundary
		{40, 100, "#ff6b6b"},   // Low
		{0, 100, "#ff6b6b"},    // Low
	}

	for _, tt := range tests {
		result := getScoreColor(tt.score, tt.max)
		if result != tt.expected {
			t.Errorf("getScoreColor(%.0f, %.0f) = %s, want %s", tt.score, tt.max, result, tt.expected)
		}
	}
}

func TestGetProgressClass(t *testing.T) {
	tests := []struct {
		score    float64
		max      float64
		expected string
	}{
		{90, 100, "high"},      // >= 80%%
		{80, 100, "high"},      // == 80%%
		{70, 100, "medium"},    // >= 50%% but < 80%%
		{50, 100, "medium"},    // == 50%%
		{40, 100, "low"},       // < 50%%
		{0, 100, "low"},        // < 50%%
	}

	for _, tt := range tests {
		result := getProgressClass(tt.score, tt.max)
		if result != tt.expected {
			t.Errorf("getProgressClass(%.0f, %.0f) = %s, want %s", tt.score, tt.max, result, tt.expected)
		}
	}
}
