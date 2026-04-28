package phases

import (
	"os"
	"testing"
	"time"

	"github.com/waf-hackathon/benchmark/internal/waf"
)

func TestWAFConfigStructure(t *testing.T) {
	config := WAFConfig{
		Version: "1.0",
		Server: ServerConfig{
			Listen:       ":8080",
			Upstream:     "localhost:9000",
			ReadTimeout:  30,
			WriteTimeout: 30,
		},
		Rules: []RuleConfig{
			{
				ID:       "rule-1",
				Name:     "Block test path",
				Path:     "/test",
				Action:   "block",
				Enabled:  true,
				Priority: 100,
			},
		},
		Cache: CacheConfig{
			Enabled: true,
			TTL:     60,
			MaxSize: 100,
		},
	}

	if config.Version != "1.0" {
		t.Error("Version mismatch")
	}

	if config.Server.Listen != ":8080" {
		t.Error("Server.Listen mismatch")
	}

	if len(config.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(config.Rules))
	}

	if !config.Cache.Enabled {
		t.Error("Cache should be enabled")
	}
}

func TestExtensibilityResultStructure(t *testing.T) {
	result := ExtensibilityResult{
		TestID:      "E01",
		Name:        "Test Name",
		Passed:      true,
		Description: "Test description",
		Details: map[string]interface{}{
			"status": 200,
		},
	}

	if result.TestID != "E01" {
		t.Error("TestID mismatch")
	}

	if !result.Passed {
		t.Error("Passed should be true")
	}

	if result.Details["status"] != 200 {
		t.Error("Details mismatch")
	}
}

func TestPhaseEResultStructure(t *testing.T) {
	result := &PhaseEResult{
		HotReloadTests: []ExtensibilityResult{
			{TestID: "E-Add", Passed: true},
			{TestID: "E-Remove", Passed: true},
		},
		CacheTests: []ExtensibilityResult{
			{TestID: "E01", Passed: true},
			{TestID: "E02", Passed: true},
			{TestID: "E03", Passed: true},
			{TestID: "E04", Passed: true},
		},
		HotReloadScore: 6.0,
		CachingScore:   4.0,
		TotalScore:     10.0,
		DurationMs:     5000,
	}

	if len(result.HotReloadTests) != 2 {
		t.Errorf("Expected 2 hot-reload tests, got %d", len(result.HotReloadTests))
	}

	if len(result.CacheTests) != 4 {
		t.Errorf("Expected 4 cache tests, got %d", len(result.CacheTests))
	}

	if result.HotReloadScore != 6.0 {
		t.Errorf("HotReloadScore = %v, want 6.0", result.HotReloadScore)
	}

	if result.CachingScore != 4.0 {
		t.Errorf("CachingScore = %v, want 4.0", result.CachingScore)
	}

	if result.TotalScore != 10.0 {
		t.Errorf("TotalScore = %v, want 10.0", result.TotalScore)
	}
}

func TestPhaseEResultSummary(t *testing.T) {
	result := &PhaseEResult{
		HotReloadTests: []ExtensibilityResult{
			{TestID: "E-Add", Passed: true, Name: "Add Rule"},
			{TestID: "E-Remove", Passed: false, Name: "Remove Rule"},
		},
		CacheTests: []ExtensibilityResult{
			{TestID: "E01", Passed: true, Name: "E01"},
			{TestID: "E02", Passed: true, Name: "E02"},
			{TestID: "E03", Passed: false, Name: "E03"},
			{TestID: "E04", Passed: true, Name: "E04"},
		},
		HotReloadScore: 3.0,
		CachingScore:   3.0,
		TotalScore:     6.0,
		DurationMs:     10000,
	}

	summary := result.Summary()

	if summary == "" {
		t.Error("Summary should not be empty")
	}

	if !containsString(summary, "Phase E") {
		t.Error("Summary should mention Phase E")
	}

	if !containsString(summary, "3/2") && !containsString(summary, "passed") {
		t.Error("Summary should include test counts")
	}
}

func TestCacheTestStructure(t *testing.T) {
	test := CacheTest{
		ID:          "E01",
		Name:        "Static Asset Caching",
		Method:      "GET",
		Path:        "/static/js/app.js",
		Auth:        false,
		ShouldCache: true,
		TTLSeconds:  60,
	}

	if test.ID != "E01" {
		t.Error("ID mismatch")
	}

	if test.Method != "GET" {
		t.Error("Method mismatch")
	}

	if test.ShouldCache != true {
		t.Error("ShouldCache should be true")
	}
}

func TestHotReloadTestStructure(t *testing.T) {
	test := HotReloadTest{
		ID:          "E-Add",
		Name:        "Add Rule Test",
		Path:        "/test-path",
		Expected404: true,
		Expected403: false,
	}

	if test.ID != "E-Add" {
		t.Error("ID mismatch")
	}

	if !test.Expected404 {
		t.Error("Expected404 should be true")
	}
}

func TestLatencyStatsEmpty(t *testing.T) {
	stats := calculateLatencyStats([]float64{})

	if stats.Samples != 0 {
		t.Error("Empty stats should have 0 samples")
	}

	if stats.P50 != 0 || stats.P99 != 0 {
		t.Error("Empty stats should have zero percentiles")
	}
}

func TestCountPassed(t *testing.T) {
	tests := []ExtensibilityResult{
		{TestID: "1", Passed: true},
		{TestID: "2", Passed: false},
		{TestID: "3", Passed: true},
		{TestID: "4", Passed: false},
	}

	passed := countPassed(tests)

	if passed != 2 {
		t.Errorf("countPassed() = %d, want 2", passed)
	}
}

func TestCountPassedEmpty(t *testing.T) {
	passed := countPassed([]ExtensibilityResult{})

	if passed != 0 {
		t.Errorf("countPassed(empty) = %d, want 0", passed)
	}
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		body     string
		expected string
	}{
		{`{"login_token":"abc123"}`, "abc123"},
		{`{"login_token": "def456"}`, "def456"},
		{`{"login_token":"ghi789", "other":"value"}`, "ghi789"},
		{`{"other":"value"}`, ""},
		{`invalid json`, ""},
	}

	for _, tt := range tests {
		got := extractToken(tt.body)
		if got != tt.expected {
			t.Errorf("extractToken(%q) = %q, want %q", tt.body, got, tt.expected)
		}
	}
}

func TestFindWAFConfigFile(t *testing.T) {
	// Test with non-existent paths
	result := FindWAFConfigFile([]string{"/nonexistent/path.yaml"})
	// Should return empty string since file doesn't exist
	if result != "" {
		t.Logf("Expected empty string for non-existent path, got: %s", result)
	}

	// Test with empty search paths (uses common locations)
	result = FindWAFConfigFile([]string{})
	// Just verify it doesn't panic - may or may not find a file
	_ = result
}

func TestCacheTesterStructure(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	tester := NewCacheTester(wafClient)

	if tester == nil {
		t.Fatal("NewCacheTester returned nil")
	}

	if tester.wafClient != wafClient {
		t.Error("CacheTester wafClient not set correctly")
	}
}

func TestHotReloadTesterStructure(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	tester := NewHotReloadTester("/tmp/test-waf.yaml", wafClient)

	if tester == nil {
		t.Fatal("NewHotReloadTester returned nil")
	}

	if tester.configPath != "/tmp/test-waf.yaml" {
		t.Error("HotReloadTester configPath not set correctly")
	}

	if tester.wafClient != wafClient {
		t.Error("HotReloadTester wafClient not set correctly")
	}

	if tester.backupPath != "/tmp/test-waf.yaml.backup" {
		t.Errorf("Expected backup path %s, got %s", "/tmp/test-waf.yaml.backup", tester.backupPath)
	}
}

func TestLoadSaveConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := tmpDir + "/test-waf.yaml"

	// Write initial config
	initialConfig := `version: "1.0"
server:
  listen: ":8080"
  upstream: "localhost:9000"
rules:
  - id: "test-rule"
    name: "Test Rule"
    path: "/test"
    action: "block"
    enabled: true
    priority: 100
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Create tester and load config
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	tester := NewHotReloadTester(configPath, wafClient)

	config, err := tester.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", config.Version)
	}

	// Modify config
	config.Version = "2.0"

	// Save config
	if err := tester.SaveConfig(config); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Reload and verify
	config2, err := tester.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to reload config: %v", err)
	}

	if config2.Version != "2.0" {
		t.Errorf("Expected version 2.0 after save, got %s", config2.Version)
	}
}

func TestBackupRestoreConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := tmpDir + "/test-waf.yaml"

	initialContent := []byte("version: 1.0\nserver:\n  listen: :8080\n")
	if err := os.WriteFile(configPath, initialContent, 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Create tester
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	tester := NewHotReloadTester(configPath, wafClient)

	// Backup config
	if err := tester.BackupConfig(); err != nil {
		t.Fatalf("Failed to backup config: %v", err)
	}

	// Verify backup exists
	_, err := os.Stat(configPath + ".backup")
	if err != nil {
		t.Error("Backup file should exist")
	}

	// Modify original
	modifiedContent := []byte("version: 2.0\nserver:\n  listen :9090\n")
	if err := os.WriteFile(configPath, modifiedContent, 0644); err != nil {
		t.Fatalf("Failed to modify test config: %v", err)
	}

	// Restore from backup
	if err := tester.RestoreConfig(); err != nil {
		t.Fatalf("Failed to restore config: %v", err)
	}

	// Verify restoration
	restoredContent, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read restored config: %v", err)
	}

	if string(restoredContent) != string(initialContent) {
		t.Error("Restored config should match original")
	}
}

func TestAddBlockRule(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := tmpDir + "/test-waf.yaml"

	initialConfig := `version: "1.0"
server:
  listen: ":8080"
  upstream: "localhost:9000"
rules:
  - id: "existing-rule"
    name: "Existing Rule"
    path: "/existing"
    action: "allow"
    enabled: true
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Create tester
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	tester := NewHotReloadTester(configPath, wafClient)

	// Add new rule
	if err := tester.AddBlockRule("/blocked", "new-block-rule"); err != nil {
		t.Fatalf("Failed to add block rule: %v", err)
	}

	// Load and verify
	config, err := tester.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(config.Rules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(config.Rules))
	}

	// Find new rule
	var found bool
	for _, rule := range config.Rules {
		if rule.ID == "new-block-rule" {
			found = true
			if rule.Path != "/blocked" {
				t.Errorf("Expected path /blocked, got %s", rule.Path)
			}
			if rule.Action != "block" {
				t.Errorf("Expected action block, got %s", rule.Action)
			}
			if !rule.Enabled {
				t.Error("Rule should be enabled")
			}
		}
	}

	if !found {
		t.Error("New rule should exist in config")
	}
}

func TestRemoveBlockRule(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := tmpDir + "/test-waf.yaml"

	initialConfig := `version: "1.0"
rules:
  - id: "keep-rule"
    name: "Keep Rule"
    path: "/keep"
    action: "allow"
    enabled: true
  - id: "remove-rule"
    name: "Remove Rule"
    path: "/remove"
    action: "block"
    enabled: true
`
	if err := os.WriteFile(configPath, []byte(initialConfig), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Create tester
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	tester := NewHotReloadTester(configPath, wafClient)

	// Remove rule
	if err := tester.RemoveBlockRule("remove-rule"); err != nil {
		t.Fatalf("Failed to remove block rule: %v", err)
	}

	// Load and verify
	config, err := tester.LoadConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(config.Rules) != 1 {
		t.Errorf("Expected 1 rule after removal, got %d", len(config.Rules))
	}

	// Verify removed rule is gone
	for _, rule := range config.Rules {
		if rule.ID == "remove-rule" {
			t.Error("Removed rule should not exist")
		}
	}

	// Verify kept rule exists
	if config.Rules[0].ID != "keep-rule" {
		t.Error("Kept rule should exist")
	}
}

func TestLoadConfigNotFound(t *testing.T) {
	wafClient := waf.NewWAFClient("127.0.0.1", 8080, 30*time.Second)
	tester := NewHotReloadTester("/nonexistent/path.yaml", wafClient)

	_, err := tester.LoadConfig()
	if err == nil {
		t.Error("Expected error when loading non-existent config")
	}
}
