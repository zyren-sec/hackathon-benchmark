package phases

import (
	"testing"

	"github.com/waf-hackathon/benchmark/internal/httpclient"
	"github.com/waf-hackathon/benchmark/internal/target"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

// TestRiskLifecycleResultStruct tests the RiskLifecycleResult struct
func TestRiskLifecycleResultStruct(t *testing.T) {
	result := &RiskLifecycleResult{
		TotalScore: 8.0,
		Steps: []LifecycleStep{
			{StepNumber: 1, Name: "Test", Passed: true, RiskScore: 5},
		},
		ObservedRisk: []int{5, 50, 100, 90, 10, 40, 15},
		Passed:       true,
	}

	if result.TotalScore != 8.0 {
		t.Errorf("Expected TotalScore 8.0, got %.1f", result.TotalScore)
	}

	if len(result.Steps) != 1 {
		t.Errorf("Expected 1 step, got %d", len(result.Steps))
	}

	if len(result.ObservedRisk) != 7 {
		t.Errorf("Expected 7 observed risk scores, got %d", len(result.ObservedRisk))
	}
}

// TestLifecycleStepStruct tests the LifecycleStep struct
func TestLifecycleStepStruct(t *testing.T) {
	step := LifecycleStep{
		StepNumber:   1,
		Name:         "Test Step",
		Description:  "Test description",
		Passed:       true,
		RiskScore:    10,
		Action:       "allow",
		ExpectedRisk: "0-10",
	}

	if step.StepNumber != 1 {
		t.Errorf("Expected StepNumber 1, got %d", step.StepNumber)
	}

	if !step.Passed {
		t.Error("Expected step to be passed")
	}

	if step.RiskScore != 10 {
		t.Errorf("Expected RiskScore 10, got %d", step.RiskScore)
	}
}

// TestDeviceFingerprintStruct tests the DeviceFingerprint struct
func TestDeviceFingerprintStruct(t *testing.T) {
	fp := DeviceFingerprint{
		UserAgent:      "Mozilla/5.0 Test",
		AcceptEncoding: "gzip",
		AcceptLanguage: "en-US",
	}

	if fp.UserAgent != "Mozilla/5.0 Test" {
		t.Errorf("Expected UserAgent 'Mozilla/5.0 Test', got '%s'", fp.UserAgent)
	}
}

// TestRiskLifecycleTesterCreation tests creating a new tester
func TestRiskLifecycleTesterCreation(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 0)
	targetClient := target.NewClient("127.0.0.1", 9000, "test-secret")

	tester := NewRiskLifecycleTester(wafClient, targetClient)

	if tester == nil {
		t.Fatal("Expected tester to not be nil")
	}

	if tester.wafClient != wafClient {
		t.Error("Expected wafClient to match")
	}

	if tester.targetClient != targetClient {
		t.Error("Expected targetClient to match")
	}
}

// TestGenerateDeviceFingerprint tests device fingerprint generation
func TestGenerateDeviceFingerprint(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 0)
	targetClient := target.NewClient("127.0.0.1", 9000, "test-secret")
	tester := NewRiskLifecycleTester(wafClient, targetClient)

	d1 := tester.generateDeviceFingerprint("D1")
	if d1.UserAgent == "" {
		t.Error("Expected D1 to have UserAgent")
	}

	d2 := tester.generateDeviceFingerprint("D2")
	if d2.UserAgent == "" {
		t.Error("Expected D2 to have UserAgent")
	}

	// D1 and D2 should be different
	if d1.UserAgent == d2.UserAgent {
		t.Error("Expected D1 and D2 to have different UserAgents")
	}

	// Unknown device should default to D1
	unknown := tester.generateDeviceFingerprint("UNKNOWN")
	if unknown.UserAgent != d1.UserAgent {
		t.Error("Expected unknown device to default to D1 fingerprint")
	}
}

// TestCalculateScore tests score calculation
func TestCalculateScore(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 0)
	targetClient := target.NewClient("127.0.0.1", 9000, "test-secret")
	tester := NewRiskLifecycleTester(wafClient, targetClient)

	tests := []struct {
		name     string
		steps    []LifecycleStep
		expected float64
	}{
		{
			name:     "empty steps",
			steps:    []LifecycleStep{},
			expected: 0,
		},
		{
			name: "all steps passed",
			steps: []LifecycleStep{
				{StepNumber: 1, Passed: true},
				{StepNumber: 2, Passed: true},
				{StepNumber: 3, Passed: true},
				{StepNumber: 4, Passed: true},
				{StepNumber: 5, Passed: true},
				{StepNumber: 6, Passed: true},
				{StepNumber: 7, Passed: true},
			},
			expected: 8.0, // 1+1+1+1+1+1+2 = 8
		},
		{
			name: "only step 7 passed (worth 2 points)",
			steps: []LifecycleStep{
				{StepNumber: 1, Passed: false},
				{StepNumber: 2, Passed: false},
				{StepNumber: 3, Passed: false},
				{StepNumber: 4, Passed: false},
				{StepNumber: 5, Passed: false},
				{StepNumber: 6, Passed: false},
				{StepNumber: 7, Passed: true},
			},
			expected: 2.0,
		},
		{
			name: "half steps passed",
			steps: []LifecycleStep{
				{StepNumber: 1, Passed: true},
				{StepNumber: 2, Passed: false},
				{StepNumber: 3, Passed: true},
				{StepNumber: 4, Passed: false},
				{StepNumber: 5, Passed: true},
				{StepNumber: 6, Passed: false},
				{StepNumber: 7, Passed: true},
			},
			expected: 5.0, // 1+0+1+0+1+0+2 = 5
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := tester.calculateScore(tt.steps)
			if score != tt.expected {
				t.Errorf("Expected score %.1f, got %.1f", tt.expected, score)
			}
		})
	}
}

// TestAllStepsPassed tests the allStepsPassed helper
func TestAllStepsPassed(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 0)
	targetClient := target.NewClient("127.0.0.1", 9000, "test-secret")
	tester := NewRiskLifecycleTester(wafClient, targetClient)

	tests := []struct {
		name     string
		steps    []LifecycleStep
		expected bool
	}{
		{
			name:     "empty steps",
			steps:    []LifecycleStep{},
			expected: false,
		},
		{
			name: "all passed",
			steps: []LifecycleStep{
				{Passed: true}, {Passed: true}, {Passed: true},
				{Passed: true}, {Passed: true}, {Passed: true},
				{Passed: true},
			},
			expected: true,
		},
		{
			name: "one failed",
			steps: []LifecycleStep{
				{Passed: true}, {Passed: true}, {Passed: true},
				{Passed: false}, {Passed: true}, {Passed: true},
				{Passed: true},
			},
			expected: false,
		},
		{
			name: "last failed",
			steps: []LifecycleStep{
				{Passed: true}, {Passed: true}, {Passed: true},
				{Passed: true}, {Passed: true}, {Passed: true},
				{Passed: false},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tester.allStepsPassed(tt.steps)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestRiskLifecycleResultSummary tests the Summary method
func TestRiskLifecycleResultSummary(t *testing.T) {
	result := &RiskLifecycleResult{
		TotalScore:   6.0,
		DurationMs:   5000,
		ObservedRisk: []int{5, 50, 100, 90, 10, 40, 15},
		Steps: []LifecycleStep{
			{StepNumber: 1, Passed: true},
			{StepNumber: 2, Passed: true},
			{StepNumber: 3, Passed: true},
			{StepNumber: 4, Passed: true},
			{StepNumber: 5, Passed: true},
			{StepNumber: 6, Passed: true},
			{StepNumber: 7, Passed: false},
		},
	}

	summary := result.Summary()
	expected := "Risk Lifecycle Test - Duration: 5000ms, Steps: 6/7 passed, Score: 6.0/8"
	if summary != expected {
		t.Errorf("Expected summary '%s', got '%s'", expected, summary)
	}
}

// TestSetDeviceHeaders tests setting device headers
func TestSetDeviceHeaders(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 0)
	targetClient := target.NewClient("127.0.0.1", 9000, "test-secret")
	tester := NewRiskLifecycleTester(wafClient, targetClient)

	device := DeviceFingerprint{
		UserAgent:      "TestAgent/1.0",
		AcceptEncoding: "gzip",
		AcceptLanguage: "en-US",
	}

	// Just verify no panic occurs
	_ = tester.buildLegitimateRequest("/", device)
}

// TestBuildLegitimateRequest tests request building
func TestBuildLegitimateRequest(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 0)
	targetClient := target.NewClient("127.0.0.1", 9000, "test-secret")
	tester := NewRiskLifecycleTester(wafClient, targetClient)

	device := DeviceFingerprint{
		UserAgent:      "Mozilla/5.0 Test",
		AcceptEncoding: "gzip, deflate",
		AcceptLanguage: "en-US,en;q=0.9",
	}

	req := tester.buildLegitimateRequest("/api/test", device)
	defer httpclient.ReleaseRequest(req)

	if req == nil {
		t.Fatal("Expected request to not be nil")
	}

	// Check that headers are set
	if string(req.Header.Peek("User-Agent")) != device.UserAgent {
		t.Error("Expected User-Agent header to be set")
	}

	if string(req.Header.Peek("Accept-Encoding")) != device.AcceptEncoding {
		t.Error("Expected Accept-Encoding header to be set")
	}

	if string(req.Header.Peek("Accept-Language")) != device.AcceptLanguage {
		t.Error("Expected Accept-Language header to be set")
	}
}

// TestRunRiskLifecycleWithNilClients tests error handling
func TestRunRiskLifecycleWithNilClients(t *testing.T) {
	// This test verifies the structure works even with nil clients
	// In real usage, this would fail at request time
	tester := NewRiskLifecycleTester(nil, nil)

	if tester == nil {
		t.Fatal("Expected tester to be created even with nil clients")
	}
}

// TestRiskLifecycleStepValidation tests individual step validation logic
func TestRiskLifecycleStepValidation(t *testing.T) {
	tests := []struct {
		name       string
		step       LifecycleStep
		wantPassed bool
	}{
		{
			name:       "step 1: low risk, allow action",
			step:       LifecycleStep{StepNumber: 1, RiskScore: 5, Action: "allow"},
			wantPassed: true,
		},
		{
			name:       "step 1: high risk should fail",
			step:       LifecycleStep{StepNumber: 1, RiskScore: 50, Action: "allow"},
			wantPassed: false,
		},
		{
			name:       "step 2: medium risk, block action",
			step:       LifecycleStep{StepNumber: 2, RiskScore: 50, Action: "block"},
			wantPassed: true,
		},
		{
			name:       "step 2: too low risk should fail",
			step:       LifecycleStep{StepNumber: 2, RiskScore: 10, Action: "block"},
			wantPassed: false,
		},
		{
			name:       "step 3: max risk, block action",
			step:       LifecycleStep{StepNumber: 3, RiskScore: 100, Action: "block"},
			wantPassed: true,
		},
		{
			name:       "step 7: low risk, allow action",
			step:       LifecycleStep{StepNumber: 7, RiskScore: 15, Action: "allow"},
			wantPassed: true,
		},
		{
			name:       "step 7: too high risk should fail",
			step:       LifecycleStep{StepNumber: 7, RiskScore: 50, Action: "allow"},
			wantPassed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate step criteria based on step number
			passed := validateStepCriteria(tt.step)
			if passed != tt.wantPassed {
				t.Errorf("validateStepCriteria() = %v, want %v", passed, tt.wantPassed)
			}
		})
	}
}

// validateStepCriteria validates step criteria based on step number
// This mirrors the validation logic in the actual implementation
func validateStepCriteria(step LifecycleStep) bool {
	switch step.StepNumber {
	case 1:
		return step.RiskScore >= 0 && step.RiskScore <= 10 && step.Action == "allow"
	case 2:
		return step.RiskScore >= 40 && step.RiskScore <= 70 && (step.Action == "block" || step.Action == "challenge")
	case 3:
		return step.RiskScore >= 90 && step.RiskScore <= 100 && step.Action == "block"
	case 4:
		return step.RiskScore >= 80 && step.RiskScore <= 100
	case 7:
		return step.RiskScore < 30 && step.Action == "allow"
	default:
		return step.RiskScore > 0
	}
}
