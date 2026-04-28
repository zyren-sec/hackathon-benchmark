package phases

import (
	"testing"
	"time"

	"github.com/waf-hackathon/benchmark/internal/target"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

func TestResilienceResultStructure(t *testing.T) {
	result := ResilienceResult{
		TestID:      "D01",
		Name:        "HTTP Flood",
		Category:    "DDoS",
		Passed:      true,
		Description: "Test description",
		Details: map[string]interface{}{
			"requests": 1000,
		},
	}

	if result.TestID != "D01" {
		t.Error("TestID mismatch")
	}

	if result.Category != "DDoS" {
		t.Error("Category mismatch")
	}

	if !result.Passed {
		t.Error("Passed should be true")
	}

	if result.Details["requests"] != 1000 {
		t.Error("Details mismatch")
	}
}

func TestPhaseDResultStructure(t *testing.T) {
	result := &PhaseDResult{
		DDoSTests: []ResilienceResult{
			{TestID: "D01", Passed: true},
			{TestID: "D02", Passed: false},
			{TestID: "D03", Passed: true},
			{TestID: "D04", Passed: true},
		},
		SlowAttackTests: []ResilienceResult{
			{TestID: "D02", Passed: false},
			{TestID: "D03", Passed: true},
		},
		BackendFailureTests: []ResilienceResult{
			{TestID: "D05", Passed: true},
			{TestID: "D06", Passed: true},
			{TestID: "D07", Passed: false},
		},
		FailModeTests: []ResilienceResult{},
		DDoSScore:     3.0,
		BackendScore:  2.0,
		FailModeScore: 0.0,
		TotalScore:    5.0,
		DurationMs:    120000,
	}

	if len(result.DDoSTests) != 4 {
		t.Errorf("Expected 4 DDoS tests, got %d", len(result.DDoSTests))
	}

	if len(result.BackendFailureTests) != 3 {
		t.Errorf("Expected 3 backend tests, got %d", len(result.BackendFailureTests))
	}

	if result.DDoSScore != 3.0 {
		t.Errorf("DDoSScore = %v, want 3.0", result.DDoSScore)
	}

	if result.TotalScore != 5.0 {
		t.Errorf("TotalScore = %v, want 5.0", result.TotalScore)
	}
}

func TestPhaseDResultSummary(t *testing.T) {
	result := &PhaseDResult{
		DDoSTests: []ResilienceResult{
			{TestID: "D01", Passed: true, Name: "HTTP Flood"},
			{TestID: "D04", Passed: false, Name: "WAF Flood"},
		},
		SlowAttackTests: []ResilienceResult{
			{TestID: "D02", Passed: true, Name: "Slowloris"},
			{TestID: "D03", Passed: true, Name: "RUDY"},
		},
		BackendFailureTests: []ResilienceResult{
			{TestID: "D05", Passed: true, Name: "Backend Down"},
			{TestID: "D06", Passed: false, Name: "Backend Slow"},
			{TestID: "D07", Passed: true, Name: "Recovery"},
		},
		FailModeTests: []ResilienceResult{},
		DDoSScore:     1.0,
		BackendScore:   2.0,
		FailModeScore: 0.0,
		TotalScore:    3.0,
		DurationMs:    60000,
	}

	summary := result.Summary()

	if summary == "" {
		t.Error("Summary should not be empty")
	}

	if !containsString(summary, "Phase D") {
		t.Error("Summary should mention Phase D")
	}

	// Summary should show counts, not necessarily all test IDs
	if !containsString(summary, "DDoS Tests") {
		t.Error("Summary should include DDoS Tests section")
	}

	if !containsString(summary, "Backend Tests") {
		t.Error("Summary should include Backend Tests section")
	}

	// D04 is failed, should appear in the list
	if !containsString(summary, "D04") {
		t.Error("Summary should include failed test D04")
	}
}

func TestDDoSTesterStructure(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	targetClient := &target.Client{}

	tester := NewDDoSTester(wafClient, targetClient)

	if tester == nil {
		t.Fatal("NewDDoSTester returned nil")
	}

	if tester.wafClient != wafClient {
		t.Error("DDoSTester wafClient not set correctly")
	}

	if tester.targetClient != targetClient {
		t.Error("DDoSTester targetClient not set correctly")
	}
}

func TestBackendTesterStructure(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	targetClient := &target.Client{}
	control := &target.Control{}

	tester := NewBackendTester(wafClient, targetClient, control)

	if tester == nil {
		t.Fatal("NewBackendTester returned nil")
	}

	if tester.wafClient != wafClient {
		t.Error("BackendTester wafClient not set correctly")
	}

	if tester.control != control {
		t.Error("BackendTester control not set correctly")
	}
}

func TestCountPassedResilience(t *testing.T) {
	tests := []ResilienceResult{
		{TestID: "1", Passed: true},
		{TestID: "2", Passed: false},
		{TestID: "3", Passed: true},
		{TestID: "4", Passed: false},
		{TestID: "5", Passed: true},
	}

	passed := countPassedResilience(tests)

	if passed != 3 {
		t.Errorf("countPassedResilience() = %d, want 3", passed)
	}
}

func TestCountPassedResilienceEmpty(t *testing.T) {
	passed := countPassedResilience([]ResilienceResult{})

	if passed != 0 {
		t.Errorf("countPassedResilience(empty) = %d, want 0", passed)
	}
}

func TestCountPassedResilienceAllPassed(t *testing.T) {
	tests := []ResilienceResult{
		{TestID: "1", Passed: true},
		{TestID: "2", Passed: true},
		{TestID: "3", Passed: true},
	}

	passed := countPassedResilience(tests)

	if passed != 3 {
		t.Errorf("countPassedResilience(all passed) = %d, want 3", passed)
	}
}

func TestCountPassedResilienceAllFailed(t *testing.T) {
	tests := []ResilienceResult{
		{TestID: "1", Passed: false},
		{TestID: "2", Passed: false},
	}

	passed := countPassedResilience(tests)

	if passed != 0 {
		t.Errorf("countPassedResilience(all failed) = %d, want 0", passed)
	}
}

func TestPhaseDScores(t *testing.T) {
	// Perfect score
	perfect := &PhaseDResult{
		DDoSTests: []ResilienceResult{
			{Passed: true}, {Passed: true}, {Passed: true}, {Passed: true},
		},
		BackendFailureTests: []ResilienceResult{
			{Passed: true}, {Passed: true}, {Passed: true},
		},
		FailModeTests: []ResilienceResult{
			{Passed: true}, {Passed: true},
		},
	}

	applyPhaseDScores(perfect)
	if perfect.TotalScore != 9.0 {
		t.Errorf("Perfect score = %v, want 9.0", perfect.TotalScore)
	}

	// Zero score
	zero := &PhaseDResult{
		DDoSTests:           []ResilienceResult{{Passed: false}},
		BackendFailureTests: []ResilienceResult{{Passed: false}},
		FailModeTests:       []ResilienceResult{{Passed: false}},
	}
	applyPhaseDScores(zero)
	if zero.TotalScore != 0 {
		t.Errorf("Zero score = %v, want 0", zero.TotalScore)
	}
}

func TestApplyPhaseDScoresUsesFailModeTests(t *testing.T) {
	result := &PhaseDResult{
		DDoSTests: []ResilienceResult{
			{TestID: "D01", Passed: true},
			{TestID: "D04", Passed: true},
		},
		BackendFailureTests: []ResilienceResult{
			{TestID: "D05", Passed: true},
			{TestID: "D06", Passed: false},
			{TestID: "D07", Passed: false},
		},
		FailModeTests: []ResilienceResult{
			{TestID: "D08", Passed: true},
			{TestID: "D09", Passed: false},
		},
	}

	applyPhaseDScores(result)

	if result.DDoSScore != 2.0 {
		t.Errorf("DDoSScore = %v, want 2.0", result.DDoSScore)
	}
	if result.BackendScore != 1.0 {
		t.Errorf("BackendScore = %v, want 1.0", result.BackendScore)
	}
	if result.FailModeScore != 1.0 {
		t.Errorf("FailModeScore = %v, want 1.0", result.FailModeScore)
	}
	if result.TotalScore != 4.0 {
		t.Errorf("TotalScore = %v, want 4.0", result.TotalScore)
	}
}

func TestApplyPhaseDScoresNil(t *testing.T) {
	applyPhaseDScores(nil)
}

func TestResilienceResultPassed(t *testing.T) {
	passed := ResilienceResult{
		TestID: "D01",
		Passed: true,
	}

	if !passed.Passed {
		t.Error("Passed result should have Passed=true")
	}

	failed := ResilienceResult{
		TestID: "D02",
		Passed: false,
	}

	if failed.Passed {
		t.Error("Failed result should have Passed=false")
	}
}
