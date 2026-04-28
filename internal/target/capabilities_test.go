package target

import (
	"testing"
)

func TestAppCapabilitiesIsVulnActive(t *testing.T) {
	caps := &AppCapabilities{
		VulnsActive: []string{"V01", "V02", "V03"},
	}

	if !caps.IsVulnActive("V01") {
		t.Error("Expected V01 to be active")
	}
	if !caps.IsVulnActive("V02") {
		t.Error("Expected V02 to be active")
	}
	if caps.IsVulnActive("V04") {
		t.Error("Expected V04 to be inactive")
	}
	if caps.IsVulnActive("V99") {
		t.Error("Expected V99 to be inactive")
	}
}

func TestAppCapabilitiesIsLeakActive(t *testing.T) {
	caps := &AppCapabilities{
		LeaksActive: []string{"L01", "L02"},
	}

	if !caps.IsLeakActive("L01") {
		t.Error("Expected L01 to be active")
	}
	if caps.IsLeakActive("L03") {
		t.Error("Expected L03 to be inactive")
	}
}

func TestAppCapabilitiesGetActiveVulns(t *testing.T) {
	caps := &AppCapabilities{
		VulnsActive: []string{"V01", "V02"},
	}

	vulns := caps.GetActiveVulns()
	if len(vulns) != 2 {
		t.Errorf("Expected 2 active vulns, got %d", len(vulns))
	}
}

func TestAppCapabilitiesGetActiveLeaks(t *testing.T) {
	caps := &AppCapabilities{
		LeaksActive: []string{"L01", "L02", "L03"},
	}

	leaks := caps.GetActiveLeaks()
	if len(leaks) != 3 {
		t.Errorf("Expected 3 active leaks, got %d", len(leaks))
	}
}

func TestAppCapabilitiesGetVulnsByCategory(t *testing.T) {
	caps := &AppCapabilities{
		VulnsActive: []string{"V01", "V02", "V03", "V10a", "V10b"},
	}

	// Test exact match
	vulns := caps.GetVulnsByCategory("V01")
	if len(vulns) != 1 || vulns[0] != "V01" {
		t.Errorf("Expected [V01], got %v", vulns)
	}

	// Test prefix match
	vulns = caps.GetVulnsByCategory("V10")
	if len(vulns) != 2 {
		t.Errorf("Expected 2 vulns with prefix V10, got %d", len(vulns))
	}

	// Test non-matching prefix
	vulns = caps.GetVulnsByCategory("V99")
	if len(vulns) != 0 {
		t.Errorf("Expected 0 vulns, got %d", len(vulns))
	}
}

func TestAppCapabilitiesValidatePayload(t *testing.T) {
	caps := &AppCapabilities{
		VulnsActive: []string{"V01", "V02"},
	}

	err := caps.ValidatePayload("V01")
	if err != nil {
		t.Errorf("Expected no error for active vuln, got %v", err)
	}

	err = caps.ValidatePayload("V99")
	if err == nil {
		t.Error("Expected error for inactive vuln")
	}
	if err != nil && err.Error() != "vulnerability V99 is not active (skipped)" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestAppStateIsHealthy(t *testing.T) {
	state := &AppState{Healthy: true}
	if !state.IsHealthy() {
		t.Error("Expected state to be healthy")
	}

	state.Healthy = false
	if state.IsHealthy() {
		t.Error("Expected state to be unhealthy")
	}
}

func TestAppStateIsSlow(t *testing.T) {
	state := &AppState{SlowDelay: 0}
	if state.IsSlow() {
		t.Error("Expected state to not be slow")
	}

	state.SlowDelay = 1000
	if !state.IsSlow() {
		t.Error("Expected state to be slow")
	}
}

func TestAppStateHasErrorMode(t *testing.T) {
	state := &AppState{ErrorMode: ""}
	if state.HasErrorMode() {
		t.Error("Expected no error mode")
	}

	state.ErrorMode = "none"
	if state.HasErrorMode() {
		t.Error("Expected no error mode for 'none'")
	}

	state.ErrorMode = "500_error"
	if !state.HasErrorMode() {
		t.Error("Expected error mode to be active")
	}
}

func TestGetVulnCategories(t *testing.T) {
	categories := GetVulnCategories()
	expectedCount := 20 // V01-V11, V14-V16, V19-V24

	if len(categories) != expectedCount {
		t.Errorf("Expected %d vuln categories, got %d", expectedCount, len(categories))
	}

	// Check a few specific ones
	hasV01 := false
	hasV24 := false
	for _, c := range categories {
		if c == "V01" {
			hasV01 = true
		}
		if c == "V24" {
			hasV24 = true
		}
	}
	if !hasV01 {
		t.Error("Expected V01 in categories")
	}
	if !hasV24 {
		t.Error("Expected V24 in categories")
	}
}

func TestGetLeakCategories(t *testing.T) {
	categories := GetLeakCategories()
	expectedCount := 5 // L01-L05

	if len(categories) != expectedCount {
		t.Errorf("Expected %d leak categories, got %d", expectedCount, len(categories))
	}
}
