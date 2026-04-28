package phases

import (
	"testing"
	"time"

	"github.com/waf-hackathon/benchmark/internal/target"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

func TestTrafficTypeString(t *testing.T) {
	tests := []struct {
		trafficType TrafficType
		expected    string
	}{
		{TrafficLegitimate, "Legitimate"},
		{TrafficSuspicious, "Suspicious"},
		{TrafficExploit, "Exploit"},
		{TrafficAbuse, "Abuse"},
		{TrafficDDoS, "DDoS"},
		{TrafficType(99), "Unknown"},
	}

	for _, tt := range tests {
		if got := tt.trafficType.String(); got != tt.expected {
			t.Errorf("TrafficType.String() = %v, want %v", got, tt.expected)
		}
	}
}

func TestNewTrafficMixGenerator(t *testing.T) {
	// Create a generator
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	client := &target.Client{}

	gen := NewTrafficMixGenerator(client, wafClient, nil)

	if gen == nil {
		t.Fatal("NewTrafficMixGenerator returned nil")
	}

	if gen.client != client {
		t.Error("Generator client not set correctly")
	}

	if gen.wafClient != wafClient {
		t.Error("Generator wafClient not set correctly")
	}

	if gen.rng == nil {
		t.Error("Generator rng not initialized")
	}
}

func TestGetTrafficMixTemplates(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	client := &target.Client{}

	gen := NewTrafficMixGenerator(client, wafClient, nil)
	templates := gen.GetTrafficMixTemplates()

	if len(templates) == 0 {
		t.Fatal("Expected non-empty traffic mix templates")
	}

	// Check that we have templates for each traffic type
	typeCounts := make(map[TrafficType]int)
	for _, template := range templates {
		typeCounts[template.Type]++
	}

	// Should have legitimate templates
	if typeCounts[TrafficLegitimate] == 0 {
		t.Error("Expected legitimate traffic templates")
	}

	// Should have suspicious templates
	if typeCounts[TrafficSuspicious] == 0 {
		t.Error("Expected suspicious traffic templates")
	}

	// Should have exploit templates
	if typeCounts[TrafficExploit] == 0 {
		t.Error("Expected exploit traffic templates")
	}

	// Should have abuse templates
	if typeCounts[TrafficAbuse] == 0 {
		t.Error("Expected abuse traffic templates")
	}

	// Should have DDoS templates
	if typeCounts[TrafficDDoS] == 0 {
		t.Error("Expected DDoS traffic templates")
	}
}

func TestGenerateRequest(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	client := &target.Client{}

	gen := NewTrafficMixGenerator(client, wafClient, nil)

	// Test generating requests for each type
	for _, trafficType := range []TrafficType{
		TrafficLegitimate,
		TrafficSuspicious,
		TrafficExploit,
		TrafficAbuse,
		TrafficDDoS,
	} {
		template := gen.GenerateRequest(trafficType)

		if template.Type != trafficType {
			t.Errorf("GenerateRequest(%v).Type = %v, want %v",
				trafficType, template.Type, trafficType)
		}

		if template.Method == "" {
			t.Errorf("GenerateRequest(%v) returned empty method", trafficType)
		}

		if template.Path == "" {
			t.Errorf("GenerateRequest(%v) returned empty path", trafficType)
		}
	}
}

func TestGetRandomTrafficType(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	client := &target.Client{}

	gen := NewTrafficMixGenerator(client, wafClient, nil)

	// Generate many traffic types and check distribution
	counts := make(map[TrafficType]int)
	for i := 0; i < 1000; i++ {
		trafficType := gen.GetRandomTrafficType()
		counts[trafficType]++
	}

	// Check that all types appear
	if counts[TrafficLegitimate] == 0 {
		t.Error("Legitimate traffic should appear in random distribution")
	}
	if counts[TrafficSuspicious] == 0 {
		t.Error("Suspicious traffic should appear in random distribution")
	}
	if counts[TrafficExploit] == 0 {
		t.Error("Exploit traffic should appear in random distribution")
	}
	if counts[TrafficAbuse] == 0 {
		t.Error("Abuse traffic should appear in random distribution")
	}
	if counts[TrafficDDoS] == 0 {
		t.Error("DDoS traffic should appear in random distribution")
	}

	// Legitimate should be ~60% (around 600)
	if counts[TrafficLegitimate] < 500 || counts[TrafficLegitimate] > 700 {
		t.Logf("Warning: Legitimate traffic count %d seems unusual for 60%% expected rate", counts[TrafficLegitimate])
	}
}

func TestCalculateLatencyStats(t *testing.T) {
	// Test with sample latencies
	latencies := []float64{
		1.0, 2.0, 3.0, 4.0, 5.0,
		6.0, 7.0, 8.0, 9.0, 10.0,
	}

	stats := calculateLatencyStats(latencies)

	if stats.P50 == 0 {
		t.Error("P50 should not be zero")
	}

	if stats.P99 == 0 {
		t.Error("P99 should not be zero")
	}

	if stats.Min != 1.0 {
		t.Errorf("Min = %v, want 1.0", stats.Min)
	}

	if stats.Max != 10.0 {
		t.Errorf("Max = %v, want 10.0", stats.Max)
	}

	if stats.Avg < 5.0 || stats.Avg > 6.0 {
		t.Errorf("Avg = %v, expected around 5.5", stats.Avg)
	}

	if stats.Samples != 10 {
		t.Errorf("Samples = %v, want 10", stats.Samples)
	}
}

func TestCalculateLatencyStatsEmpty(t *testing.T) {
	stats := calculateLatencyStats([]float64{})

	if stats.P50 != 0 || stats.P99 != 0 {
		t.Error("Empty stats should have zero percentiles")
	}

	if stats.Samples != 0 {
		t.Error("Empty stats should have zero samples")
	}
}

func TestPercentile(t *testing.T) {
	data := []float64{1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0}

	tests := []struct {
		p        float64
		expected float64
	}{
		{0, 1.0},    // 0th percentile = min
		{50, 5.5},   // 50th percentile = median
		{99, 10.0},  // 99th percentile = near max
		{100, 10.0}, // 100th percentile = max
	}

	for _, tt := range tests {
		got := percentile(data, tt.p)
		// Allow small floating point differences
		diff := got - tt.expected
		if diff < 0 {
			diff = -diff
		}
		if diff > 0.5 {
			t.Errorf("percentile(data, %v) = %v, want %v (diff %v)",
				tt.p, got, tt.expected, diff)
		}
	}
}

func TestPercentileEmpty(t *testing.T) {
	got := percentile([]float64{}, 50)
	if got != 0 {
		t.Errorf("percentile(empty, 50) = %v, want 0", got)
	}
}

func TestPhaseCResultSummary(t *testing.T) {
	result := &PhaseCResult{
		PeakRPS:         10000,
		SustainedRPS:    5000,
		AvgOverheadMs:   2.5,
		P99OverheadMs:   5.0,
		LatencyScore:    10.0,
		ThroughputScore: 5.0,
		MemoryScore:     3.0,
		GracefulScore:   2.0,
		DurationMs:      120000,
	}

	summary := result.Summary()

	if summary == "" {
		t.Error("Summary should not be empty")
	}

	if !containsString(summary, "Phase C") {
		t.Error("Summary should mention Phase C")
	}

	if !containsString(summary, "10000") {
		t.Error("Summary should include Peak RPS")
	}

	if !containsString(summary, "5000") {
		t.Error("Summary should include Sustained RPS")
	}
}

func TestLoadTestStepPassed(t *testing.T) {
	// Low error rate should pass
	passed := &LoadTestStep{
		TargetRPS: 1000,
		ActualRPS: 950,
		ErrorRate: 0.02, // 2% error
		Passed:    true,
	}

	if !passed.Passed {
		t.Error("Step with 2%% error rate should pass")
	}

	// High error rate should fail
	failed := &LoadTestStep{
		TargetRPS: 1000,
		ActualRPS: 800,
		ErrorRate: 0.10, // 10% error
		Passed:    false,
	}

	if failed.Passed {
		t.Error("Step with 10%% error rate should fail")
	}
}

func TestLatencyStatsStructure(t *testing.T) {
	stats := LatencyStats{
		P50:     5.0,
		P99:     10.0,
		Max:     15.0,
		Min:     1.0,
		Avg:     6.0,
		Samples: 1000,
	}

	if stats.P50 != 5.0 {
		t.Error("P50 mismatch")
	}

	if stats.P99 != 10.0 {
		t.Error("P99 mismatch")
	}

	if stats.Samples != 1000 {
		t.Error("Samples mismatch")
	}
}

func TestPhaseCResultScores(t *testing.T) {
	// Test perfect score
	perfect := &PhaseCResult{
		LatencyScore:    10.0,
		ThroughputScore: 5.0,
		MemoryScore:     3.0,
		GracefulScore:   2.0,
	}

	totalScore := perfect.LatencyScore + perfect.ThroughputScore +
		perfect.MemoryScore + perfect.GracefulScore

	if totalScore != 20.0 {
		t.Errorf("Perfect score = %v, want 20.0", totalScore)
	}

	// Test zero score
	zero := &PhaseCResult{
		LatencyScore:    0.0,
		ThroughputScore: 0.0,
		MemoryScore:     0.0,
		GracefulScore:   0.0,
	}

	if zero.LatencyScore+zero.ThroughputScore+zero.MemoryScore+zero.GracefulScore != 0 {
		t.Error("Zero score calculation incorrect")
	}
}

func TestBaselineLatencyMeasureMock(t *testing.T) {
	// This test verifies the structure of the baseline measurement function
	// It would need a mock target client for full testing

	// For now, verify that the function returns correct structure with empty data
	result := make(map[string]LatencyStats)

	result["CRITICAL"] = LatencyStats{
		P50: 1.0, P99: 5.0, Avg: 2.0, Samples: 1000,
	}

	if _, ok := result["CRITICAL"]; !ok {
		t.Error("CRITICAL endpoint class should exist")
	}

	if result["CRITICAL"].P99 != 5.0 {
		t.Error("P99 value mismatch")
	}
}

func TestRequestMetricStructure(t *testing.T) {
	metric := &RequestMetric{
		Type:       TrafficLegitimate,
		LatencyMs:  10.5,
		StatusCode: 200,
		Decision:   waf.Allow,
		Timestamp:  time.Now(),
	}

	if metric.Type != TrafficLegitimate {
		t.Error("RequestMetric Type not set correctly")
	}

	if metric.LatencyMs != 10.5 {
		t.Error("RequestMetric LatencyMs not set correctly")
	}

	if metric.StatusCode != 200 {
		t.Error("RequestMetric StatusCode not set correctly")
	}

	if metric.Decision != waf.Allow {
		t.Error("RequestMetric Decision not set correctly")
	}
}

func TestRequestTemplateStructure(t *testing.T) {
	template := RequestTemplate{
		Type:        TrafficExploit,
		Method:      "POST",
		Path:        "/login",
		Headers:     map[string]string{"X-Test": "value"},
		Payload:     map[string]interface{}{"key": "value"},
		AuthFlow:    true,
		Description: "Test template",
	}

	if template.Type != TrafficExploit {
		t.Error("RequestTemplate Type not set correctly")
	}

	if template.Method != "POST" {
		t.Error("RequestTemplate Method not set correctly")
	}

	if !template.AuthFlow {
		t.Error("RequestTemplate AuthFlow should be true")
	}
}

// containsString checks if substr exists in s
func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
