package scoring

import (
	"testing"

	"github.com/waf-hackathon/benchmark/internal/phases"
)

func TestNewScoringMatrix(t *testing.T) {
	sm := NewScoringMatrix()

	if sm == nil {
		t.Fatal("NewScoringMatrix returned nil")
	}

	if len(sm.Entries) != 0 {
		t.Error("New matrix should have no entries")
	}

	if sm.ByID == nil {
		t.Error("ByID map should be initialized")
	}
}

func TestDefaultScoringMatrix(t *testing.T) {
	sm := DefaultScoringMatrix()

	if sm == nil {
		t.Fatal("DefaultScoringMatrix returned nil")
	}

	if len(sm.Entries) == 0 {
		t.Error("Default matrix should have entries")
	}

	// Check for key entries
	if _, ok := sm.ByID["SEC-01"]; !ok {
		t.Error("Should have SEC-01 entry")
	}

	if _, ok := sm.ByID["SEC-03"]; !ok {
		t.Error("Should have SEC-03 entry")
	}

	if _, ok := sm.ByID["PERF-01"]; !ok {
		t.Error("Should have PERF-01 entry")
	}
}

func TestGetPoints(t *testing.T) {
	sm := DefaultScoringMatrix()

	tests := []struct {
		testID   string
		expected float64
	}{
		{"SEC-01", 15.0},
		{"SEC-02", 5.0},
		{"SEC-03", 10.0},
		{"PERF-01", 10.0},
		{"NONEXISTENT", 0.0},
	}

	for _, tt := range tests {
		got := sm.GetPoints(tt.testID)
		if got != tt.expected {
			t.Errorf("GetPoints(%s) = %v, want %v", tt.testID, got, tt.expected)
		}
	}
}

func TestGetTotalPossiblePoints(t *testing.T) {
	sm := DefaultScoringMatrix()

	total := sm.GetTotalPossiblePoints()

	// Option A full matrix total: 120 points
	if total != 120.0 {
		t.Errorf("GetTotalPossiblePoints() = %v, want 120.0", total)
	}
}

func TestGetCategoryBreakdown(t *testing.T) {
	sm := DefaultScoringMatrix()

	breakdown := sm.GetCategoryBreakdown()

	if len(breakdown) == 0 {
		t.Error("Category breakdown should not be empty")
	}

	if breakdown["Security Effectiveness"] != 40.0 {
		t.Errorf("Security Effectiveness total = %v, want 40.0", breakdown["Security Effectiveness"])
	}

	if breakdown["Performance"] != 20.0 {
		t.Errorf("Performance total = %v, want 20.0", breakdown["Performance"])
	}
}

func TestNewScoreCalculator(t *testing.T) {
	sm := DefaultScoringMatrix()
	calc := NewScoreCalculator(sm)

	if calc == nil {
		t.Fatal("NewScoreCalculator returned nil")
	}

	if calc.Matrix != sm {
		t.Error("Calculator matrix not set correctly")
	}
}

func TestCalculatePhaseAScore(t *testing.T) {
	sm := DefaultScoringMatrix()
	calc := NewScoreCalculator(sm)

	// Perfect score
	perfect := &phases.PhaseAResult{
		ExploitPreventionRate: 100.0,
		OutboundFilterRate:    100.0,
	}
	score := calc.CalculatePhaseAScore(perfect)
	if score != 20.0 {
		t.Errorf("Perfect Phase A score = %v, want 20.0", score)
	}

	// Zero score
	zero := &phases.PhaseAResult{
		ExploitPreventionRate: 0.0,
		OutboundFilterRate:    0.0,
	}
	score = calc.CalculatePhaseAScore(zero)
	if score != 0.0 {
		t.Errorf("Zero Phase A score = %v, want 0.0", score)
	}

	// Partial score
	partial := &phases.PhaseAResult{
		ExploitPreventionRate: 90.0, // 90% of 15 = 13.5
		OutboundFilterRate:    80.0, // 80% of 5 = 4.0
	}
	score = calc.CalculatePhaseAScore(partial)
	expected := 17.5 // 13.5 + 4.0
	if score != expected {
		t.Errorf("Partial Phase A score = %v, want %v", score, expected)
	}
}

func TestCalculatePhaseBScore(t *testing.T) {
	sm := DefaultScoringMatrix()
	calc := NewScoreCalculator(sm)

	// Perfect score
	perfect := &phases.PhaseBResult{
		AbuseDetectionRate: 100.0,
	}
	score := calc.CalculatePhaseBScore(perfect)
	if score != 10.0 {
		t.Errorf("Perfect Phase B score = %v, want 10.0", score)
	}

	// 85% detection
	partial := &phases.PhaseBResult{
		AbuseDetectionRate: 85.0,
	}
	score = calc.CalculatePhaseBScore(partial)
	expected := 8.5 // 85% of 10
	if score != expected {
		t.Errorf("Partial Phase B score = %v, want %v", score, expected)
	}
}

func TestCalculatePhaseCScore(t *testing.T) {
	sm := DefaultScoringMatrix()
	calc := NewScoreCalculator(sm)

	// Perfect score
	perfect := &phases.PhaseCResult{
		LatencyScore:    10.0,
		ThroughputScore: 5.0,
		MemoryScore:     3.0,
		GracefulScore:   2.0,
	}
	score := calc.CalculatePhaseCScore(perfect)
	if score != 20.0 {
		t.Errorf("Perfect Phase C score = %v, want 20.0", score)
	}

	// Zero score
	zero := &phases.PhaseCResult{
		LatencyScore:    0.0,
		ThroughputScore: 0.0,
		MemoryScore:     0.0,
		GracefulScore:   0.0,
	}
	score = calc.CalculatePhaseCScore(zero)
	if score != 0.0 {
		t.Errorf("Zero Phase C score = %v, want 0.0", score)
	}
}

func TestCalculatePhaseDScore(t *testing.T) {
	sm := DefaultScoringMatrix()
	calc := NewScoreCalculator(sm)

	perfect := &phases.PhaseDResult{
		DDoSScore:     4.0,
		BackendScore:  3.0,
		FailModeScore: 2.0,
	}
	score := calc.CalculatePhaseDScore(perfect)
	if score != 9.0 {
		t.Errorf("Perfect Phase D score = %v, want 9.0", score)
	}
}

func TestCalculatePhaseEScore(t *testing.T) {
	sm := DefaultScoringMatrix()
	calc := NewScoreCalculator(sm)

	perfect := &phases.PhaseEResult{
		HotReloadScore: 6.0,
		CachingScore:   4.0,
	}
	score := calc.CalculatePhaseEScore(perfect)
	if score != 10.0 {
		t.Errorf("Perfect Phase E score = %v, want 10.0", score)
	}
}

func TestCalculateRiskLifecycleScore(t *testing.T) {
	sm := DefaultScoringMatrix()
	calc := NewScoreCalculator(sm)

	// Perfect score - all steps passed
	perfect := &phases.RiskLifecycleResult{
		Steps: []phases.LifecycleStep{
			{StepNumber: 1, Passed: true},
			{StepNumber: 2, Passed: true},
			{StepNumber: 3, Passed: true},
			{StepNumber: 4, Passed: true},
			{StepNumber: 5, Passed: true},
			{StepNumber: 6, Passed: true},
			{StepNumber: 7, Passed: true}, // Worth 2 points
		},
	}
	score := calc.CalculateRiskLifecycleScore(perfect)
	if score != 8.0 {
		t.Errorf("Perfect Risk Lifecycle score = %v, want 8.0", score)
	}

	// Some steps failed
	partial := &phases.RiskLifecycleResult{
		Steps: []phases.LifecycleStep{
			{StepNumber: 1, Passed: true},  // 1 point
			{StepNumber: 2, Passed: false}, // 0
			{StepNumber: 3, Passed: true},  // 1 point
			{StepNumber: 4, Passed: false}, // 0
			{StepNumber: 5, Passed: true},  // 1 point
			{StepNumber: 6, Passed: false}, // 0
			{StepNumber: 7, Passed: true},  // 2 points
		},
	}
	score = calc.CalculateRiskLifecycleScore(partial)
	expected := 5.0 // 1 + 0 + 1 + 0 + 1 + 0 + 2
	if score != expected {
		t.Errorf("Partial Risk Lifecycle score = %v, want %v", score, expected)
	}
}

func TestCalculateGrade(t *testing.T) {
	tests := []struct {
		percentage float64
		expected   string
	}{
		{100.0, "A+"},
		{95.0, "A+"},
		{94.9, "A"},
		{90.0, "A"},
		{89.9, "A-"},
		{85.0, "A-"},
		{84.9, "B+"},
		{80.0, "B+"},
		{79.9, "B"},
		{75.0, "B"},
		{74.9, "B-"},
		{70.0, "B-"},
		{69.9, "C+"},
		{65.0, "C+"},
		{64.9, "C"},
		{60.0, "C"},
		{59.9, "C-"},
		{55.0, "C-"},
		{54.9, "D"},
		{50.0, "D"},
		{49.9, "F"},
		{0.0, "F"},
	}

	for _, tt := range tests {
		got := calculateGrade(tt.percentage)
		if got != tt.expected {
			t.Errorf("calculateGrade(%v) = %v, want %v", tt.percentage, got, tt.expected)
		}
	}
}

func TestOverallScore(t *testing.T) {
	sm := DefaultScoringMatrix()
	calc := NewScoreCalculator(sm)

	overall := calc.CalculateOverallScore(
		&phases.PhaseAResult{ExploitPreventionRate: 100, OutboundFilterRate: 100},
		&phases.PhaseBResult{AbuseDetectionRate: 100},
		&phases.PhaseCResult{LatencyScore: 10, ThroughputScore: 5, MemoryScore: 3, GracefulScore: 2},
		&phases.PhaseDResult{DDoSScore: 4, BackendScore: 3, FailModeScore: 2},
		&phases.PhaseEResult{HotReloadScore: 6, CachingScore: 4},
		&phases.RiskLifecycleResult{
			Steps: []phases.LifecycleStep{
				{Passed: true}, {Passed: true}, {Passed: true},
				{Passed: true}, {Passed: true}, {Passed: true}, {Passed: true},
			},
		},
	)

	if overall.Total != 92.0 {
		t.Errorf("Perfect automated overall score = %v, want 92.0", overall.Total)
	}

	if overall.Grade != "B" {
		t.Errorf("Perfect automated grade = %v, want B", overall.Grade)
	}

	if overall.MaxPossible != 120.0 {
		t.Errorf("Max possible = %v, want 120.0", overall.MaxPossible)
	}
}

func TestOverallScoreNilInputs(t *testing.T) {
	sm := DefaultScoringMatrix()
	calc := NewScoreCalculator(sm)

	// Test with nil inputs
	overall := calc.CalculateOverallScore(nil, nil, nil, nil, nil, nil)

	if overall.Total != 0 {
		t.Errorf("Nil inputs score = %v, want 0", overall.Total)
	}

	if overall.Grade != "F" {
		t.Errorf("Nil inputs grade = %v, want F", overall.Grade)
	}
}

func TestNewScoreReport(t *testing.T) {
	report := NewScoreReport(
		&phases.PhaseAResult{ExploitPreventionRate: 90, OutboundFilterRate: 80},
		&phases.PhaseBResult{AbuseDetectionRate: 85},
		&phases.PhaseCResult{LatencyScore: 10, ThroughputScore: 5, MemoryScore: 3, GracefulScore: 2},
		&phases.PhaseDResult{DDoSScore: 4, BackendScore: 3, FailModeScore: 2},
		&phases.PhaseEResult{HotReloadScore: 6, CachingScore: 4},
		&phases.RiskLifecycleResult{
			Steps: []phases.LifecycleStep{
				{Passed: true}, {Passed: true}, {Passed: true},
				{Passed: true}, {Passed: true}, {Passed: true}, {Passed: true},
			},
		},
	)

	if report == nil {
		t.Fatal("NewScoreReport returned nil")
	}

	if report.OverallScore == nil {
		t.Error("OverallScore should not be nil")
	}

	if report.PhaseADetails == nil {
		t.Error("PhaseADetails should not be nil")
	}
}

func TestOverallScoreSummary(t *testing.T) {
	overall := &OverallScore{
		PhaseA:        18.0,
		PhaseB:        8.5,
		PhaseC:        17.0,
		PhaseD:        7.0,
		PhaseE:        9.0,
		RiskLifecycle: 6.0,
		Total:         65.5,
		MaxPossible:   120.0,
		Percentage:    85.1,
		Grade:         "A-",
	}

	summary := overall.Summary()

	if summary == "" {
		t.Error("Summary should not be empty")
	}

	if !containsString(summary, "65.5") {
		t.Error("Summary should contain total score")
	}

	if !containsString(summary, "A-") {
		t.Error("Summary should contain grade")
	}

	if !containsString(summary, "SEC (Security Effectiveness)") {
		t.Error("Summary should contain SEC category")
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
