package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ── YAML File Structure ──

// BenchmarkConfigFile mirrors the benchmark_config.yaml structure.
type BenchmarkConfigFile struct {
	Benchmark BenchmarkSection `yaml:"benchmark"`
}

// BenchmarkSection is the top-level "benchmark" key.
type BenchmarkSection struct {
	Version       string           `yaml:"version"`
	TargetApp     TargetAppSection `yaml:"target_app"`
	WAF           WAFSection       `yaml:"waf"`
	WAFFE         WAFFESection     `yaml:"waf_fe"`
	ProxyPoolPath string           `yaml:"proxy_pool_path"`
}

// TargetAppSection holds UPSTREAM target application settings.
type TargetAppSection struct {
	Scheme        string `yaml:"scheme"`
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	ControlSecret string `yaml:"control_secret"`
}

// WAFSection holds WAF-PROXY settings.
type WAFSection struct {
	Scheme       string `yaml:"scheme"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	AdminPort    int    `yaml:"admin_port"`
	MetricsPort  int    `yaml:"metrics_port"`
	BinaryPath   string `yaml:"binary_path"`
	ConfigPath   string `yaml:"config_path"`
	AuditLogPath string `yaml:"audit_log_path"`
}

// WAFFESection holds WAF-FE Dashboard settings.
type WAFFESection struct {
	Host              string `yaml:"host"`
	Port              int    `yaml:"port"`
	Enabled           bool   `yaml:"enabled"`
	SkipIfUnavailable bool   `yaml:"skip_if_unavailable"`
}

// ── Runtime Config ──

// Config holds all configuration for the benchmark tool.
type Config struct {
	// Phase is the phase to run (e.g., "a")
	Phase string

	// PayloadTier filters payloads: "basic", "advanced", "bypass", or "all"
	PayloadTier string

	// OutputDir is where reports are written
	OutputDir string

	// Target app (UPSTREAM) settings
	TargetScheme string
	TargetHost   string
	TargetPort   int

	// WAF proxy settings
	WAFScheme string
	WAFHost   string
	WAFPort   int

	// WAF Admin API port
	WAFAdminPort int

	// Control secret
	ControlSecret string

	// Timeout per request in seconds
	RequestTimeoutSec int

	// Exploit payloads directory
	ExploitsDir string

	// WAF-FE Dashboard
	WAFFEHost            string
	WAFFEPort            int
	WAFFEEnabled         bool
	WAFFESkipUnavailable bool

	// WAF binary/config paths
	WAFBinaryPath   string
	WAFConfigPath   string
	WAFAuditLogPath string

	// Proxy IP pool
	ProxyPoolPath string

	// Config file path that was loaded
	ConfigFilePath string

	// Verbose output
	Verbose bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Phase:             "a",
		PayloadTier:       "all",
		OutputDir:         "./reports/phase_a",
		TargetScheme:      "http",
		TargetHost:        "127.0.0.1",
		TargetPort:        9000,
		WAFScheme:         "http",
		WAFHost:           "127.0.0.1",
		WAFPort:           8080,
		WAFAdminPort:      8081,
		ControlSecret:     "waf-hackathon-2026-ctrl",
		RequestTimeoutSec: 30,
		ExploitsDir:       "exploits",
		Verbose:           false,
	}
}

// TargetBaseURL returns the UPSTREAM base URL.
func (c *Config) TargetBaseURL() string {
	return fmt.Sprintf("%s://%s:%d", c.TargetScheme, c.TargetHost, c.TargetPort)
}

// WAFBaseURL returns the WAF proxy base URL.
func (c *Config) WAFBaseURL() string {
	return fmt.Sprintf("%s://%s:%d", c.WAFScheme, c.WAFHost, c.WAFPort)
}

// WAFAdminURL returns the WAF admin API base URL.
func (c *Config) WAFAdminURL() string {
	return fmt.Sprintf("%s://%s:%d", c.WAFScheme, c.WAFHost, c.WAFAdminPort)
}

// Validate checks that required configuration is present.
func (c *Config) Validate() error {
	if c.Phase != "a" && c.Phase != "b" && c.Phase != "c" && c.Phase != "d" && c.Phase != "e" && c.Phase != "r" {
		return fmt.Errorf("only phases 'a', 'b', 'c', 'd', 'e', and 'r' are supported")
	}
	switch c.PayloadTier {
	case "basic", "advanced", "bypass", "all":
		// ok
	default:
		return fmt.Errorf("invalid payload-tier: %q (valid: basic, advanced, bypass, all)", c.PayloadTier)
	}
	if c.OutputDir == "" {
		return fmt.Errorf("output directory is required")
	}
	if c.TargetHost == "" {
		return fmt.Errorf("target host is required")
	}
	if c.WAFHost == "" {
		return fmt.Errorf("WAF host is required")
	}
	return nil
}

// EnsureOutputDir creates the output directory if it doesn't exist.
func (c *Config) EnsureOutputDir() error {
	return os.MkdirAll(c.OutputDir, 0755)
}

// ── YAML Loading ──

// DefaultConfigFileName is the auto-detected config file name.
const DefaultConfigFileName = "benchmark_config.yaml"

// LoadConfig loads configuration from a YAML file and merges it into the given Config.
// Fields in the YAML file override zero/default values in the Config.
// Returns the path that was actually loaded and any error.
func LoadConfig(cfg *Config, configPath string) (string, error) {
	// Determine which file to load
	path := configPath
	if path == "" {
		// Auto-detect: look in current directory
		path = DefaultConfigFileName
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if configPath != "" {
			// User explicitly specified a path — this is an error
			return "", fmt.Errorf("cannot read config file %q: %w", path, err)
		}
		// Auto-detect failure is not fatal — use defaults silently
		return "", nil
	}

	var bcf BenchmarkConfigFile
	if err := yaml.Unmarshal(data, &bcf); err != nil {
		if configPath != "" {
			return "", fmt.Errorf("cannot parse config file %q: %w", path, err)
		}
		return "", nil // silent fallback for auto-detect
	}

	// Apply YAML values to Config (only when the Config field is still at its default)
	applyYAMLToConfig(cfg, &bcf)

	absPath, _ := filepath.Abs(path)
	return absPath, nil
}

// applyYAMLToConfig merges YAML file values into the Config.
// YAML values always take precedence over the defaults already in the Config.
func applyYAMLToConfig(cfg *Config, bcf *BenchmarkConfigFile) {
	b := bcf.Benchmark

	// Target App
	if b.TargetApp.Scheme != "" {
		cfg.TargetScheme = b.TargetApp.Scheme
	}
	if b.TargetApp.Host != "" {
		cfg.TargetHost = b.TargetApp.Host
	}
	if b.TargetApp.Port != 0 {
		cfg.TargetPort = b.TargetApp.Port
	}
	if b.TargetApp.ControlSecret != "" {
		cfg.ControlSecret = b.TargetApp.ControlSecret
	}

	// WAF
	if b.WAF.Scheme != "" {
		cfg.WAFScheme = b.WAF.Scheme
	}
	if b.WAF.Host != "" {
		cfg.WAFHost = b.WAF.Host
	}
	if b.WAF.Port != 0 {
		cfg.WAFPort = b.WAF.Port
	}
	if b.WAF.AdminPort != 0 {
		cfg.WAFAdminPort = b.WAF.AdminPort
	}
	if b.WAF.BinaryPath != "" {
		cfg.WAFBinaryPath = b.WAF.BinaryPath
	}
	if b.WAF.ConfigPath != "" {
		cfg.WAFConfigPath = b.WAF.ConfigPath
	}
	if b.WAF.AuditLogPath != "" {
		cfg.WAFAuditLogPath = b.WAF.AuditLogPath
	}

	// WAF-FE
	if b.WAFFE.Host != "" {
		cfg.WAFFEHost = b.WAFFE.Host
	}
	if b.WAFFE.Port != 0 {
		cfg.WAFFEPort = b.WAFFE.Port
	}
	cfg.WAFFEEnabled = b.WAFFE.Enabled
	cfg.WAFFESkipUnavailable = b.WAFFE.SkipIfUnavailable

	// Proxy pool
	if b.ProxyPoolPath != "" {
		cfg.ProxyPoolPath = b.ProxyPoolPath
	}
}
