package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/waf-hackathon/benchmark/internal/config"
	"github.com/waf-hackathon/benchmark/internal/logger"
	"github.com/waf-hackathon/benchmark/internal/orchestrator"
)

var (
	version = "dev"
	commit  = "unknown"
)

// CLI flags
var (
	// Config
	configFile string

	// Output
	outputDir  string
	jsonFormat bool
	htmlFormat bool

	// Overrides
	wafBinary   string
	wafConfig   string
	targetHost  string
	targetPort  int
	wafHost     string
	wafPort     int
	controlSecret string

	// Phase selection
	phases     []string
	skipReset  bool
	skipHealth bool
	timeout    time.Duration

	// Logging
	verbose bool
	debug   bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "waf-benchmark",
	Short: "WAF Benchmark Tool - Automated Security Validation Framework",
	Long: `WAF Benchmark Tool v2.1

Automated Security Validation Framework for WAF Evaluation.

This tool runs comprehensive benchmark tests against Web Application Firewalls
to evaluate their security effectiveness, performance, and resilience.

Example:
  # Run all phases with default config
  waf-benchmark

  # Run specific phases
  waf-benchmark -p a,b,c

  # Run with custom config and generate HTML report
  waf-benchmark -c myconfig.yaml --html

For more information: https://github.com/waf-hackathon/benchmark`,
	RunE: runBenchmark,
}

// versionCmd prints the version
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("WAF Benchmark Tool v%s (commit: %s)\n", version, commit)
		fmt.Println("Protocol Version: 2.1")
		fmt.Println("Supported Phases: A, B, C, D, E, Risk Lifecycle")
	},
}

// healthCmd checks pre-flight health
var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Run pre-flight health checks only",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load config
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		// Create logger
		log := createLogger()
		defer log.Close()

		// Create runner and run health checks
		runner := orchestrator.NewBenchmarkRunner(cfg, log)
		checks, allPassed := runner.RunHealthChecks()

		fmt.Println("\n" + strings.Repeat("=", 60))
		fmt.Println("Health Check Results:")
		fmt.Println(strings.Repeat("=", 60))

		for _, check := range checks {
			status := "PASS"
			if !check.Passed {
				status = "FAIL"
			}
			fmt.Printf("  [%s] %s\n", status, check.Name)
			if check.Error != "" {
				fmt.Printf("       Error: %s\n", check.Error)
			}
		}

		fmt.Println(strings.Repeat("=", 60))
		if allPassed {
			fmt.Println("All health checks passed!")
			return nil
		}
		return fmt.Errorf("some health checks failed")
	},
}

// phasesCmd lists available phases
var phasesCmd = &cobra.Command{
	Use:   "phases",
	Short: "List available benchmark phases",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Available Benchmark Phases:")
		fmt.Println()
		fmt.Println("  a      - Phase A: Exploit Prevention Tests (V01-V24, L01-L05)")
		fmt.Println("  b      - Phase B: Abuse Detection Tests (22 tests)")
		fmt.Println("  c      - Phase C: Performance Tests (RPS, Latency)")
		fmt.Println("  d      - Phase D: Resilience Tests (DDoS, Backend Failure)")
		fmt.Println("  e      - Phase E: Extensibility Tests (Hot-Reload, Caching)")
		fmt.Println("  risk   - Risk Lifecycle Test (7-step risk scoring)")
		fmt.Println("  all    - Run all phases")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  waf-benchmark -p a          # Run only Phase A")
		fmt.Println("  waf-benchmark -p a,b,c        # Run phases A, B, C")
		fmt.Println("  waf-benchmark -p all          # Run all phases")
	},
}

// init initializes CLI flags
func init() {
	// Config flag
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "benchmark_config.yaml", "Path to benchmark configuration file")

	// Output flags
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", "./reports", "Output directory for reports")
	rootCmd.PersistentFlags().BoolVar(&jsonFormat, "json", true, "Generate JSON report")
	rootCmd.PersistentFlags().BoolVar(&htmlFormat, "html", false, "Generate HTML report")

	// Override flags
	rootCmd.PersistentFlags().StringVar(&wafBinary, "waf-binary", "", "Override WAF binary path")
	rootCmd.PersistentFlags().StringVar(&wafConfig, "waf-config", "", "Override WAF config path")
	rootCmd.PersistentFlags().StringVar(&targetHost, "target-host", "", "Override target host")
	rootCmd.PersistentFlags().IntVar(&targetPort, "target-port", 0, "Override target port")
	rootCmd.PersistentFlags().StringVar(&wafHost, "waf-host", "", "Override WAF host")
	rootCmd.PersistentFlags().IntVar(&wafPort, "waf-port", 0, "Override WAF port")
	rootCmd.PersistentFlags().StringVar(&controlSecret, "control-secret", "", "Override control secret")

	// Phase selection
	rootCmd.PersistentFlags().StringSliceVarP(&phases, "phases", "p", []string{"all"}, "Phases to run (a,b,c,d,e,risk,all)")
	rootCmd.PersistentFlags().BoolVar(&skipReset, "skip-reset", false, "Skip target reset between phases")
	rootCmd.PersistentFlags().BoolVar(&skipHealth, "skip-health", false, "Skip pre-flight health checks")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 0, "Global timeout for benchmark (e.g., 30m)")

	// Logging flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug logging (very verbose)")

	// Add subcommands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(phasesCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// loadConfig loads and applies overrides to configuration
func loadConfig() (*config.Config, error) {
	var cfg *config.Config
	var err error

	// Try to load config file, fallback to defaults if not found
	if _, statErr := os.Stat(configFile); statErr == nil {
		cfg, err = config.LoadConfig(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
	} else {
		cfg = config.DefaultConfig()
		fmt.Fprintf(os.Stderr, "Config file not found, using defaults\n")
	}

	// Apply CLI overrides
	if wafBinary != "" {
		cfg.Benchmark.WAF.BinaryPath = wafBinary
	}
	if wafConfig != "" {
		cfg.Benchmark.WAF.ConfigPath = wafConfig
	}
	if targetHost != "" {
		cfg.Benchmark.TargetApp.Host = targetHost
	}
	if targetPort > 0 {
		cfg.Benchmark.TargetApp.Port = targetPort
	}
	if wafHost != "" {
		cfg.Benchmark.WAF.Host = wafHost
	}
	if wafPort > 0 {
		cfg.Benchmark.WAF.Port = wafPort
	}
	if controlSecret != "" {
		cfg.Benchmark.TargetApp.ControlSecret = controlSecret
	}

	return cfg, nil
}

// createLogger creates a logger based on CLI flags
func createLogger() *logger.Logger {
	level := logger.INFO
	if debug {
		level = logger.DEBUG
	} else if verbose {
		level = logger.INFO
	}

	return logger.New(
		logger.WithLevel(level),
		logger.WithFileOutput("benchmark.log"),
		logger.WithJSONOutput(false),
	)
}

// runBenchmark executes the main benchmark
func runBenchmark(cmd *cobra.Command, args []string) error {
	fmt.Printf("WAF Benchmark Tool v%s (%s)\n\n", version, commit)

	// Load configuration
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Create logger
	log := createLogger()
	defer log.Close()

	// Validate phases
	validPhases := map[string]bool{"a": true, "b": true, "c": true, "d": true, "e": true, "risk": true, "all": true}
	for _, p := range phases {
		p = strings.ToLower(p)
		if !validPhases[p] {
			return fmt.Errorf("invalid phase: %s. Valid phases: a, b, c, d, e, risk, all", p)
		}
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Setup context with timeout if specified
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		log.Info(fmt.Sprintf("Benchmark timeout set to: %v", timeout))
	}

	// Print configuration summary
	log.Info("Configuration:")
	log.Info(fmt.Sprintf("  Target: %s", cfg.TargetAddr()))
	log.Info(fmt.Sprintf("  WAF: %s", cfg.WAFAddr()))
	log.Info(fmt.Sprintf("  Phases: %s", strings.Join(phases, ", ")))
	log.Info(fmt.Sprintf("  Output: %s", outputDir))

	// Run benchmark
	if err := orchestrator.RunBenchmarkWithContext(ctx, cfg, log, phases, outputDir, jsonFormat, htmlFormat, skipHealth); err != nil {
		if err == context.DeadlineExceeded {
			return fmt.Errorf("benchmark timed out after %v", timeout)
		}
		return fmt.Errorf("benchmark failed: %w", err)
	}

	// Print final message
	jsonPath := filepath.Join(outputDir, "benchmark_report.json")
	htmlPath := filepath.Join(outputDir, "benchmark_report.html")

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Benchmark Complete!")
	fmt.Println(strings.Repeat("=", 60))
	if jsonFormat {
		fmt.Printf("JSON Report: %s\n", jsonPath)
	}
	if htmlFormat {
		fmt.Printf("HTML Report: %s\n", htmlPath)
	}
	fmt.Println(strings.Repeat("=", 60))

	return nil
}
