package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Benchmark.TargetApp.Host != "127.0.0.1" {
		t.Errorf("Expected target host 127.0.0.1, got %s", cfg.Benchmark.TargetApp.Host)
	}

	if cfg.Benchmark.TargetApp.Port != 9000 {
		t.Errorf("Expected target port 9000, got %d", cfg.Benchmark.TargetApp.Port)
	}

	if cfg.Benchmark.WAF.Port != 8080 {
		t.Errorf("Expected WAF port 8080, got %d", cfg.Benchmark.WAF.Port)
	}

	if cfg.Benchmark.TargetApp.ControlSecret == "" {
		t.Error("Expected control secret to be set")
	}
}

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test_config.yaml")

	configContent := `
benchmark:
  version: "2.1"
  target_app:
    host: "192.168.1.100"
    port: 9090
    control_secret: "test-secret"
  waf:
    host: "192.168.1.101"
    port: 8081
    binary_path: "/opt/waf/waf"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Benchmark.TargetApp.Host != "192.168.1.100" {
		t.Errorf("Expected host 192.168.1.100, got %s", cfg.Benchmark.TargetApp.Host)
	}

	if cfg.Benchmark.TargetApp.Port != 9090 {
		t.Errorf("Expected port 9090, got %d", cfg.Benchmark.TargetApp.Port)
	}

	if cfg.Benchmark.WAF.Port != 8081 {
		t.Errorf("Expected WAF port 8081, got %d", cfg.Benchmark.WAF.Port)
	}
}

func TestLoadConfigInvalidFile(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	if err := os.WriteFile(configPath, []byte("invalid: yaml: content: ["), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Error("Expected error for invalid YAML")
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		modify    func(*Config)
		wantError bool
	}{
		{
			name:      "valid config",
			modify:    func(c *Config) {},
			wantError: false,
		},
		{
			name: "missing target host",
			modify: func(c *Config) {
				c.Benchmark.TargetApp.Host = ""
			},
			wantError: true,
		},
		{
			name: "invalid target port",
			modify: func(c *Config) {
				c.Benchmark.TargetApp.Port = 0
			},
			wantError: true,
		},
		{
			name: "missing WAF host",
			modify: func(c *Config) {
				c.Benchmark.WAF.Host = ""
			},
			wantError: true,
		},
		{
			name: "missing control secret",
			modify: func(c *Config) {
				c.Benchmark.TargetApp.ControlSecret = ""
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantError {
				t.Errorf("Validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestTargetAddr(t *testing.T) {
	cfg := DefaultConfig()
	addr := cfg.TargetAddr()
	expected := "http://127.0.0.1:9000"
	if addr != expected {
		t.Errorf("Expected %s, got %s", expected, addr)
	}
}

func TestWAFAddr(t *testing.T) {
	cfg := DefaultConfig()
	addr := cfg.WAFAddr()
	expected := "http://127.0.0.1:8080"
	if addr != expected {
		t.Errorf("Expected %s, got %s", expected, addr)
	}
}

func TestIPRangeToList(t *testing.T) {
	tests := []struct {
		ipRange string
		want    int
		wantErr bool
	}{
		{"127.0.0.10-12", 3, false},
		{"127.0.0.10-10", 1, false},
		{"127.0.0.10-19", 10, false},
		{"invalid", 0, true},
		{"10.0.0.1-5", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.ipRange, func(t *testing.T) {
			ips, err := IPRangeToList(tt.ipRange)
			if (err != nil) != tt.wantErr {
				t.Errorf("IPRangeToList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(ips) != tt.want {
				t.Errorf("Expected %d IPs, got %d", tt.want, len(ips))
			}
		})
	}
}

func TestIPRangeToListContent(t *testing.T) {
	ips, err := IPRangeToList("127.0.0.10-12")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expected := []string{"127.0.0.10", "127.0.0.11", "127.0.0.12"}
	for i, ip := range expected {
		if ips[i] != ip {
			t.Errorf("Expected IP %s at index %d, got %s", ip, i, ips[i])
		}
	}
}
