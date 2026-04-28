package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the benchmark tool configuration
type Config struct {
	Benchmark BenchmarkConfig `yaml:"benchmark"`
}

// BenchmarkConfig holds the main benchmark settings
type BenchmarkConfig struct {
	Version    string              `yaml:"version"`
	TargetApp  TargetAppConfig     `yaml:"target_app"`
	WAF        WAFConfig           `yaml:"waf"`
	Phases     PhasesConfig        `yaml:"phases"`
	Scoring    ScoringConfig       `yaml:"scoring"`
	Thresholds ThresholdsConfig    `yaml:"thresholds"`
}

// TargetAppConfig holds target application settings
type TargetAppConfig struct {
	Scheme        string `yaml:"scheme"`
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	ControlSecret string `yaml:"control_secret"`
}

// WAFConfig holds WAF settings
type WAFConfig struct {
	Scheme       string `yaml:"scheme"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	BinaryPath   string `yaml:"binary_path"`
	ConfigPath   string `yaml:"config_path"`
	AuditLogPath string `yaml:"audit_log_path"`
}

// PhasesConfig holds phase-specific settings
type PhasesConfig struct {
	PhaseA PhaseAConfig `yaml:"phase_a"`
	PhaseB PhaseBConfig `yaml:"phase_b"`
	PhaseC PhaseCConfig `yaml:"phase_c"`
	PhaseD PhaseDConfig `yaml:"phase_d"`
}

// PhaseAConfig settings for exploit prevention tests
type PhaseAConfig struct {
	ResetBeforeEach  bool `yaml:"reset_before_each"`
	TimeoutPerTestMs int  `yaml:"timeout_per_test_ms"`
}

// IPRangeConfig defines IP ranges for testing
type IPRangeConfig struct {
	BruteForce string `yaml:"brute_force"`
	Relay      string `yaml:"relay"`
	Behavioral string `yaml:"behavioral"`
	Fraud      string `yaml:"fraud"`
	Recon      string `yaml:"recon"`
}

// PhaseBConfig settings for abuse detection tests
type PhaseBConfig struct {
	IPRanges IPRangeConfig `yaml:"ip_ranges"`
}

// PhaseCConfig settings for performance tests
type PhaseCConfig struct {
	DurationPerStepSeconds int   `yaml:"duration_per_step_seconds"`
	TargetRPSSteps         []int `yaml:"target_rps_steps"`
}

// PhaseDConfig settings for resilience tests
type PhaseDConfig struct {
	DDoSDurationSeconds   int `yaml:"ddos_duration_seconds"`
	SlowlorisConnections  int `yaml:"slowloris_connections"`
}

// ScoringConfig holds scoring weights
type ScoringConfig struct {
	SecurityEffectiveness    int `yaml:"security_effectiveness"`
	Performance              int `yaml:"performance"`
	Intelligence             int `yaml:"intelligence"`
	Extensibility            int `yaml:"extensibility"`
	Architecture             int `yaml:"architecture"`
	Dashboard                int `yaml:"dashboard"`
	Deployment               int `yaml:"deployment"`
}

// ThresholdsConfig holds pass/fail thresholds
type ThresholdsConfig struct {
	P99LatencyMs         int     `yaml:"p99_latency_ms"`
	MaxMemoryMb          int     `yaml:"max_memory_mb"`
	FalsePositiveRateMax float64 `yaml:"false_positive_rate_max"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		Benchmark: BenchmarkConfig{
			Version: "2.1",
			TargetApp: TargetAppConfig{
				Scheme:        "http",
				Host:          "127.0.0.1",
				Port:          9000,
				ControlSecret: "waf-hackathon-2026-ctrl",
			},
			WAF: WAFConfig{
				Scheme:       "http",
				Host:         "127.0.0.1",
				Port:         8080,
				BinaryPath:   "./waf",
				ConfigPath:   "./waf.yaml",
				AuditLogPath: "./waf_audit.log",
			},
			Phases: PhasesConfig{
				PhaseA: PhaseAConfig{
					ResetBeforeEach:  true,
					TimeoutPerTestMs: 5000,
				},
				PhaseB: PhaseBConfig{
					IPRanges: IPRangeConfig{
						BruteForce: "127.0.0.10-19",
						Relay:      "127.0.0.20-39",
						Behavioral: "127.0.0.40-59",
						Fraud:      "127.0.0.60-79",
						Recon:      "127.0.0.80-99",
					},
				},
				PhaseC: PhaseCConfig{
					DurationPerStepSeconds: 30,
					TargetRPSSteps:         []int{1000, 3000, 5000, 10000},
				},
				PhaseD: PhaseDConfig{
					DDoSDurationSeconds:  60,
					SlowlorisConnections: 500,
				},
			},
			Scoring: ScoringConfig{
				SecurityEffectiveness: 40,
				Performance:           20,
				Intelligence:          20,
				Extensibility:         10,
				Architecture:          15,
				Dashboard:             10,
				Deployment:            5,
			},
			Thresholds: ThresholdsConfig{
				P99LatencyMs:         5,
				MaxMemoryMb:          100,
				FalsePositiveRateMax: 0.01,
			},
		},
	}
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Benchmark.TargetApp.Host == "" {
		return fmt.Errorf("target_app.host is required")
	}
	if c.Benchmark.TargetApp.Port <= 0 {
		return fmt.Errorf("target_app.port must be > 0")
	}
	if c.Benchmark.WAF.Host == "" {
		return fmt.Errorf("waf.host is required")
	}
	if c.Benchmark.WAF.Port <= 0 {
		return fmt.Errorf("waf.port must be > 0")
	}
	if c.Benchmark.TargetApp.ControlSecret == "" {
		return fmt.Errorf("target_app.control_secret is required")
	}

	if c.Benchmark.TargetApp.Scheme == "" {
		c.Benchmark.TargetApp.Scheme = "http"
	}
	if c.Benchmark.WAF.Scheme == "" {
		c.Benchmark.WAF.Scheme = "http"
	}

	if c.Benchmark.TargetApp.Scheme != "http" && c.Benchmark.TargetApp.Scheme != "https" {
		return fmt.Errorf("target_app.scheme must be http or https")
	}
	if c.Benchmark.WAF.Scheme != "http" && c.Benchmark.WAF.Scheme != "https" {
		return fmt.Errorf("waf.scheme must be http or https")
	}
	return nil
}

// TargetAddr returns the full target app address (scheme://host:port)
func (c *Config) TargetAddr() string {
	return fmt.Sprintf("%s://%s:%d", c.Benchmark.TargetApp.Scheme, c.Benchmark.TargetApp.Host, c.Benchmark.TargetApp.Port)
}

// WAFAddr returns the full WAF address (scheme://host:port)
func (c *Config) WAFAddr() string {
	return fmt.Sprintf("%s://%s:%d", c.Benchmark.WAF.Scheme, c.Benchmark.WAF.Host, c.Benchmark.WAF.Port)
}

// TestTimeout returns the per-test timeout duration
func (c *Config) TestTimeout() time.Duration {
	return time.Duration(c.Benchmark.Phases.PhaseA.TimeoutPerTestMs) * time.Millisecond
}

// IPRangeToList converts an IP range string (e.g., "127.0.0.10-19") to a list of IPs
func IPRangeToList(ipRange string) ([]string, error) {
	var start, end int
	_, err := fmt.Sscanf(ipRange, "127.0.0.%d-%d", &start, &end)
	if err != nil {
		return nil, fmt.Errorf("invalid IP range format: %s (expected 127.0.0.start-end)", ipRange)
	}

	var ips []string
	for i := start; i <= end; i++ {
		ips = append(ips, fmt.Sprintf("127.0.0.%d", i))
	}
	return ips, nil
}
