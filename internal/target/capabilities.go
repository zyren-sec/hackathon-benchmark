package target

import (
	"fmt"
	"strings"
)

// AppCapabilities describes the vulnerabilities and features available in the target app
type AppCapabilities struct {
	VulnsActive []string `json:"vulns_active"`
	VulnsSkipped []string `json:"vulns_skipped"`
	LeaksActive  []string `json:"leaks_active"`
	LeaksSkipped []string `json:"leaks_skipped"`
	Version      string   `json:"version"`
}

// IsVulnActive checks if a vulnerability ID is active
func (c *AppCapabilities) IsVulnActive(id string) bool {
	return contains(c.VulnsActive, id)
}

// IsLeakActive checks if a leak ID is active
func (c *AppCapabilities) IsLeakActive(id string) bool {
	return contains(c.LeaksActive, id)
}

// GetActiveVulns returns all active vulnerability IDs
func (c *AppCapabilities) GetActiveVulns() []string {
	return c.VulnsActive
}

// GetActiveLeaks returns all active leak IDs
func (c *AppCapabilities) GetActiveLeaks() []string {
	return c.LeaksActive
}

// GetVulnsByCategory returns vulnerability IDs filtered by category prefix
// e.g., GetVulnsByCategory("V01") returns ["V01"] if active
func (c *AppCapabilities) GetVulnsByCategory(prefix string) []string {
	var result []string
	for _, v := range c.VulnsActive {
		if strings.HasPrefix(v, prefix) {
			result = append(result, v)
		}
	}
	return result
}

// ValidatePayload validates that a payload can be tested
func (c *AppCapabilities) ValidatePayload(vulnID string) error {
	if !c.IsVulnActive(vulnID) {
		return fmt.Errorf("vulnerability %s is not active (skipped)", vulnID)
	}
	return nil
}

// AppState represents the current state of the target application
type AppState struct {
	Healthy    bool              `json:"healthy"`
	SlowDelay  int               `json:"slow_delay_ms"`
	ErrorMode  string            `json:"error_mode"`
	ResetCount int               `json:"reset_count"`
	Metadata   map[string]string `json:"metadata"`
}

// IsHealthy returns true if the app is healthy
func (s *AppState) IsHealthy() bool {
	return s.Healthy
}

// IsSlow returns true if the app is configured with a delay
func (s *AppState) IsSlow() bool {
	return s.SlowDelay > 0
}

// HasErrorMode returns true if the app is in an error mode
func (s *AppState) HasErrorMode() bool {
	return s.ErrorMode != "" && s.ErrorMode != "none"
}

// Helper function to check if a string slice contains a value
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetVulnCategories returns the list of all vulnerability categories
func GetVulnCategories() []string {
	return []string{
		"V01", "V02", "V03", "V04", "V05", "V06", "V07", "V08",
		"V09", "V10", "V11", "V14", "V15", "V16", "V19", "V20",
		"V21", "V22", "V23", "V24",
	}
}

// GetLeakCategories returns the list of all leak categories
func GetLeakCategories() []string {
	return []string{
		"L01", "L02", "L03", "L04", "L05",
	}
}
