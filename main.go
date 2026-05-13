package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/waf-hackathon/benchmark-new/internal/challenge"
	"github.com/waf-hackathon/benchmark-new/internal/config"
	"github.com/waf-hackathon/benchmark-new/internal/crossphase"
	"github.com/waf-hackathon/benchmark-new/internal/phasea"
	"github.com/waf-hackathon/benchmark-new/internal/phaseb"
	"github.com/waf-hackathon/benchmark-new/internal/phasec"
	"github.com/waf-hackathon/benchmark-new/internal/phased"
	"github.com/waf-hackathon/benchmark-new/internal/phasee"
	"github.com/waf-hackathon/benchmark-new/internal/phaser"
)

var (
	version = "2.9.0"
	commit  = "phase-e-v2.5"

	// CLI flags
	configPath   string
	phase        string
	payloadTier  string
	outputDir    string
	targetHost   string
	targetPort   int
	wafHost      string
	wafPort      int
	wafAdminPort int
	verbose      bool
	dryRun       bool
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "waf-benchmark",
	Short: "WAF Benchmark Tool — Phase A, B, C, D, E & R",
	Long: `WAF Benchmark Tool v2.9

Automated WAF Evaluation Framework — Phase A (Exploit Prevention), Phase B (Abuse Detection), Phase C (Performance & Throughput), Phase D (Resilience & Degradation), Phase E (Extensibility: EXT-03 automated caching tests), and Phase R (Risk Score Lifecycle: SEC-05).

Configuration:
  The tool auto-detects benchmark_config.yaml in the current directory.
  Use --config to specify a custom path. CLI flags override config file values.

Examples:
  # Run Phase A with basic payloads (auto-detect config)
  waf-benchmark -p a --payload-tier basic -o ./reports/phase_a

  # Run with custom config file
  waf-benchmark --config /path/to/custom_config.yaml -p b

  # Run Phase C (Performance & Throughput)
  waf-benchmark -p c -o ./reports/phase_c

  # Run Phase D (Resilience & Degradation)
  waf-benchmark -p d -o ./reports/phase_d

  # Run Phase E (Extensibility: EXT-03 automated caching, EXT-01/EXT-02 manual)
  waf-benchmark -p e -o ./reports/phase_e

  # Run Phase R (Risk Score Lifecycle — runs LAST, after all other phases)
  waf-benchmark -p r -o ./reports/phase_r

  # Dry-run to verify display format
  waf-benchmark --dry-run -o ./reports/phase_r
`,
	RunE: runPhase,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("WAF Benchmark Tool v%s (commit: %s)\n", version, commit)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)

	rootCmd.Flags().StringVar(&configPath, "config", "", "Path to benchmark_config.yaml (auto-detected in current dir if not set)")
	rootCmd.Flags().StringVarP(&phase, "phase", "p", "a", "Phase to run (a, b, c, d, e, or r)")
	rootCmd.Flags().StringVar(&payloadTier, "payload-tier", "all", "Payload tier: basic, advanced, bypass, or all (Phase A only)")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for reports")
	rootCmd.Flags().StringVar(&targetHost, "target-host", "", "UPSTREAM target host (overrides config)")
	rootCmd.Flags().IntVar(&targetPort, "target-port", 0, "UPSTREAM target port (overrides config)")
	rootCmd.Flags().StringVar(&wafHost, "waf-host", "", "WAF proxy host (overrides config)")
	rootCmd.Flags().IntVar(&wafPort, "waf-port", 0, "WAF proxy port (overrides config)")
	rootCmd.Flags().IntVar(&wafAdminPort, "waf-admin-port", 0, "WAF admin API port (overrides config)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Dry run: simulate results without connecting to endpoints")
}

// buildConfig returns a Config built from defaults → config file → CLI flags (priority).
func buildConfig(cmd *cobra.Command, defaultPhase, defaultOutputDir string) (*config.Config, error) {
	cfg := config.DefaultConfig()

	// 1. Load YAML config file (overrides defaults)
	loadedPath, err := config.LoadConfig(cfg, configPath)
	if err != nil {
		return nil, fmt.Errorf("config load error: %w", err)
	}
	cfg.ConfigFilePath = loadedPath

	if loadedPath != "" {
		fmt.Printf("📋 Loaded config: %s\n", loadedPath)
	}

	// 2. CLI flags override config file values (only when explicitly set)
	if cmd.Flags().Changed("target-host") {
		cfg.TargetHost = targetHost
	}
	if cmd.Flags().Changed("target-port") {
		cfg.TargetPort = targetPort
	}
	if cmd.Flags().Changed("waf-host") {
		cfg.WAFHost = wafHost
	}
	if cmd.Flags().Changed("waf-port") {
		cfg.WAFPort = wafPort
	}
	if cmd.Flags().Changed("waf-admin-port") {
		cfg.WAFAdminPort = wafAdminPort
	}
	if cmd.Flags().Changed("verbose") {
		cfg.Verbose = verbose
	}
	if cmd.Flags().Changed("phase") {
		cfg.Phase = phase
	}
	if cmd.Flags().Changed("payload-tier") {
		cfg.PayloadTier = strings.ToLower(strings.TrimSpace(payloadTier))
	}
	if cmd.Flags().Changed("output") {
		cfg.OutputDir = outputDir
	}

	// Set phase-specific defaults if not already set
	if !cmd.Flags().Changed("phase") {
		cfg.Phase = defaultPhase
	}
	if !cmd.Flags().Changed("output") && cfg.OutputDir == "./reports/phase_a" && defaultOutputDir != "" {
		cfg.OutputDir = defaultOutputDir
	}

	return cfg, nil
}

func runPhase(cmd *cobra.Command, args []string) error {
	phase = strings.ToLower(strings.TrimSpace(phase))
	switch phase {
	case "a":
		return runPhaseA(cmd, args)
	case "b":
		return runPhaseB(cmd, args)
	case "c":
		return runPhaseC(cmd, args)
	case "d":
		return runPhaseD(cmd, args)
	case "e":
		return runPhaseE(cmd, args)
	case "r":
		return runPhaseR(cmd, args)
	default:
		return fmt.Errorf("unknown phase: %q (valid: a, b, c, d, e, r)", phase)
	}
}

func runPhaseA(cmd *cobra.Command, args []string) error {
	cfg, err := buildConfig(cmd, "a", "./reports/phase_a")
	if err != nil {
		return err
	}
	cfg.PayloadTier = strings.ToLower(strings.TrimSpace(payloadTier))
	if !cmd.Flags().Changed("payload-tier") {
		// Preserve config value unless explicitly set
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "./reports/phase_a"
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := cfg.EnsureOutputDir(); err != nil {
		return fmt.Errorf("cannot create output dir: %w", err)
	}

	payloadReg, err := phasea.LoadPayloads(cfg.ExploitsDir)
	if err != nil {
		return fmt.Errorf("cannot load payloads: %w", err)
	}

	engineCfg := &phasea.ConfigWrapper{
		TargetBaseURL: cfg.TargetBaseURL(),
		WAFBaseURL:    cfg.WAFBaseURL(),
		WAFAdminURL:   cfg.WAFAdminURL(),
		ControlSecret: cfg.ControlSecret,
		TimeoutSec:    cfg.RequestTimeoutSec,
		PayloadTier:   cfg.PayloadTier,
		Verbose:       cfg.Verbose,
	}

	pool := crossphase.NewPool()

	// Create challenge solver for 429 challenge lifecycle evaluation
	chSolver := challenge.NewSolver(&http.Client{
		Timeout: time.Duration(cfg.RequestTimeoutSec) * time.Second,
	}, cfg.WAFBaseURL(), cfg.RequestTimeoutSec, cfg.Verbose, dryRun)

	engine := phasea.NewEngine(engineCfg, payloadReg, pool, chSolver)

	startTime := time.Now()
	result, err := engine.Run()
	if err != nil {
		return fmt.Errorf("phase A execution failed: %w", err)
	}
	elapsed := time.Since(startTime)

	phasea.DisplayPhaseAResult(result, cfg.PayloadTier)

	// SEC-02: Cross-phase outbound filtering
	sec02Result := pool.ComputeSEC02()
	fmt.Println()
	crossphase.DisplaySEC02(sec02Result)
	if genErr := crossphase.GenerateReport(sec02Result, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  SEC-02 report warning: %v\n", genErr)
	}

	if genErr := phasea.GenerateReport(result, cfg.OutputDir, cfg.PayloadTier); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Report generation warning: %v\n", genErr)
	}

	// Challenge lifecycle summary (429_challenge.md)
	chSummary := challenge.BuildPhaseSummary("A", chSolver.Results)
	fmt.Println()
	challenge.DisplayPhaseChallengeSummary(chSummary)
	if genErr := challenge.GenerateReport(chSummary, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Challenge report warning: %v\n", genErr)
	}

	fmt.Printf("\nCompleted in %.1fs | Phase A: SEC-01 = %.2f/15\n",
		elapsed.Seconds(), result.SEC01Score)

	return nil
}

func runPhaseB(cmd *cobra.Command, args []string) error {
	cfg, err := buildConfig(cmd, "b", "./reports/phase_b")
	if err != nil {
		return err
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "./reports/phase_b"
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := cfg.EnsureOutputDir(); err != nil {
		return fmt.Errorf("cannot create output dir: %w", err)
	}

	engineCfg := &phaseb.BConfigWrapper{
		TargetBaseURL: cfg.TargetBaseURL(),
		WAFBaseURL:    cfg.WAFBaseURL(),
		WAFAdminURL:   cfg.WAFAdminURL(),
		ControlSecret: cfg.ControlSecret,
		TimeoutSec:    cfg.RequestTimeoutSec,
		Verbose:       cfg.Verbose,
		DryRun:        dryRun,
	}

	pool := crossphase.NewPool()

	// Create challenge solver for 429 challenge lifecycle evaluation
	chSolverB := challenge.NewSolver(&http.Client{
		Timeout: time.Duration(cfg.RequestTimeoutSec) * time.Second,
	}, cfg.WAFBaseURL(), cfg.RequestTimeoutSec, cfg.Verbose, dryRun)

	engine := phaseb.NewBEngine(engineCfg, pool, chSolverB)

	startTime := time.Now()
	result, err := engine.Run()
	if err != nil {
		return fmt.Errorf("phase B execution failed: %w", err)
	}
	elapsed := time.Since(startTime)

	if dryRun {
		fmt.Println("🧪 DRY RUN MODE — No actual HTTP requests were made")
		fmt.Println()
	}

	phaseb.DisplayPhaseBResult(result)

	// SEC-02: Cross-phase outbound filtering
	sec02Result := pool.ComputeSEC02()
	fmt.Println()
	crossphase.DisplaySEC02(sec02Result)
	if genErr := crossphase.GenerateReport(sec02Result, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  SEC-02 report warning: %v\n", genErr)
	}

	if genErr := phaseb.GenerateReport(result, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Report generation warning: %v\n", genErr)
	}

	// Challenge lifecycle summary (429_challenge.md)
	chSummaryB := challenge.BuildPhaseSummary("B", chSolverB.Results)
	fmt.Println()
	challenge.DisplayPhaseChallengeSummary(chSummaryB)
	if genErr := challenge.GenerateReport(chSummaryB, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Challenge report warning: %v\n", genErr)
	}

	fmt.Printf("\nCompleted in %.1fs | Phase B Total: %.1f/%.0f\n",
		elapsed.Seconds(), result.TotalScore, result.MaxScore)

	return nil
}

func runPhaseC(cmd *cobra.Command, args []string) error {
	cfg, err := buildConfig(cmd, "c", "./reports/phase_c")
	if err != nil {
		return err
	}
	cfg.PayloadTier = "all"
	if cfg.OutputDir == "" {
		cfg.OutputDir = "./reports/phase_c"
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := cfg.EnsureOutputDir(); err != nil {
		return fmt.Errorf("cannot create output dir: %w", err)
	}

	engineCfg := &phasec.CConfigWrapper{
		TargetBaseURL: cfg.TargetBaseURL(),
		WAFBaseURL:    cfg.WAFBaseURL(),
		WAFAdminURL:   cfg.WAFAdminURL(),
		ControlSecret: cfg.ControlSecret,
		TimeoutSec:    cfg.RequestTimeoutSec,
		Verbose:       cfg.Verbose,
		DryRun:        dryRun,
	}

	pool := crossphase.NewPool()

	// Create challenge solver (detection-only during load test)
	chSolverC := challenge.NewSolver(&http.Client{
		Timeout: time.Duration(cfg.RequestTimeoutSec) * time.Second,
	}, cfg.WAFBaseURL(), cfg.RequestTimeoutSec, cfg.Verbose, dryRun)

	engine := phasec.NewCEngine(engineCfg, pool, chSolverC)

	startTime := time.Now()
	result, err := engine.Run()
	if err != nil {
		return fmt.Errorf("phase C execution failed: %w", err)
	}
	elapsed := time.Since(startTime)

	if dryRun {
		fmt.Println("🧪 DRY RUN MODE — No actual HTTP requests were made")
		fmt.Println()
	}

	phasec.DisplayPhaseCResult(result)

	if genErr := phasec.GenerateReport(result, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Report generation warning: %v\n", genErr)
	}

	// Challenge lifecycle summary (429_challenge.md)
	chSummaryC := challenge.BuildPhaseSummary("C", chSolverC.Results)
	fmt.Println()
	challenge.DisplayPhaseChallengeSummary(chSummaryC)
	if genErr := challenge.GenerateReport(chSummaryC, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Challenge report warning: %v\n", genErr)
	}

	fmt.Printf("\nCompleted in %.1fs | Phase C Score: %.0f/%.0f\n",
		elapsed.Seconds(), result.PhaseCTotal, result.PhaseCMax)

	return nil
}

func runPhaseD(cmd *cobra.Command, args []string) error {
	cfg, err := buildConfig(cmd, "d", "./reports/phase_d")
	if err != nil {
		return err
	}
	cfg.PayloadTier = "all"
	if cfg.OutputDir == "" {
		cfg.OutputDir = "./reports/phase_d"
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := cfg.EnsureOutputDir(); err != nil {
		return fmt.Errorf("cannot create output dir: %w", err)
	}

	engineCfg := &phased.DConfigWrapper{
		TargetBaseURL: cfg.TargetBaseURL(),
		WAFBaseURL:    cfg.WAFBaseURL(),
		WAFAdminURL:   cfg.WAFAdminURL(),
		ControlSecret: cfg.ControlSecret,
		TimeoutSec:    cfg.RequestTimeoutSec,
		Verbose:       cfg.Verbose,
		DryRun:        dryRun,
	}

	pool := crossphase.NewPool()

	// Create challenge solver (detection-only during resilience test)
	chSolverD := challenge.NewSolver(&http.Client{
		Timeout: time.Duration(cfg.RequestTimeoutSec) * time.Second,
	}, cfg.WAFBaseURL(), cfg.RequestTimeoutSec, cfg.Verbose, dryRun)

	engine := phased.NewDEngine(engineCfg, pool, chSolverD)

	startTime := time.Now()
	result, err := engine.Run()
	if err != nil {
		return fmt.Errorf("phase D execution failed: %w", err)
	}
	elapsed := time.Since(startTime)

	if dryRun {
		fmt.Println("🧪 DRY RUN MODE — No actual HTTP requests were made")
		fmt.Println()
	}

	phased.DisplayPhaseDResult(result)

	// SEC-02: Cross-phase outbound filtering
	sec02Result := pool.ComputeSEC02()
	fmt.Println()
	crossphase.DisplaySEC02(sec02Result)
	if genErr := crossphase.GenerateReport(sec02Result, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  SEC-02 report warning: %v\n", genErr)
	}

	if genErr := phased.GenerateReport(result, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Report generation warning: %v\n", genErr)
	}

	// Challenge lifecycle summary (429_challenge.md)
	chSummaryD := challenge.BuildPhaseSummary("D", chSolverD.Results)
	fmt.Println()
	challenge.DisplayPhaseChallengeSummary(chSummaryD)
	if genErr := challenge.GenerateReport(chSummaryD, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Challenge report warning: %v\n", genErr)
	}

	fmt.Printf("\nCompleted in %.1fs | Phase D: INT-04 = %.1f/%.0f (raw: %.1f/%.1f)\n",
		elapsed.Seconds(), result.INT04Score, result.INT04Cap, result.RawScore, result.RawMaxScore)

	return nil
}

func runPhaseE(cmd *cobra.Command, args []string) error {
	cfg, err := buildConfig(cmd, "e", "./reports/phase_e")
	if err != nil {
		return err
	}
	cfg.PayloadTier = "all"
	if cfg.OutputDir == "" {
		cfg.OutputDir = "./reports/phase_e"
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := cfg.EnsureOutputDir(); err != nil {
		return fmt.Errorf("cannot create output dir: %w", err)
	}

	engineCfg := &phasee.EConfigWrapper{
		TargetBaseURL: cfg.TargetBaseURL(),
		WAFBaseURL:    cfg.WAFBaseURL(),
		WAFAdminURL:   cfg.WAFAdminURL(),
		ControlSecret: cfg.ControlSecret,
		TimeoutSec:    cfg.RequestTimeoutSec,
		Verbose:       cfg.Verbose,
		DryRun:        dryRun,
	}

	pool := crossphase.NewPool()

	// Create challenge solver (detection-only during extensibility test)
	chSolverE := challenge.NewSolver(&http.Client{
		Timeout: time.Duration(cfg.RequestTimeoutSec) * time.Second,
	}, cfg.WAFBaseURL(), cfg.RequestTimeoutSec, cfg.Verbose, dryRun)

	engine := phasee.NewEEngine(engineCfg, pool, chSolverE)

	startTime := time.Now()
	result, err := engine.Run()
	if err != nil {
		return fmt.Errorf("phase E execution failed: %w", err)
	}
	elapsed := time.Since(startTime)

	if dryRun {
		fmt.Println("🧪 DRY RUN MODE — No actual HTTP requests were made")
		fmt.Println()
	}

	phasee.DisplayPhaseEResult(result)

	// SEC-02: Cross-phase outbound filtering
	sec02Result := pool.ComputeSEC02()
	fmt.Println()
	crossphase.DisplaySEC02(sec02Result)
	if genErr := crossphase.GenerateReport(sec02Result, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  SEC-02 report warning: %v\n", genErr)
	}

	if genErr := phasee.GenerateReport(result, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Report generation warning: %v\n", genErr)
	}

	// Challenge lifecycle summary (429_challenge.md)
	chSummaryE := challenge.BuildPhaseSummary("E", chSolverE.Results)
	fmt.Println()
	challenge.DisplayPhaseChallengeSummary(chSummaryE)
	if genErr := challenge.GenerateReport(chSummaryE, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Challenge report warning: %v\n", genErr)
	}

	fmt.Printf("\nCompleted in %.1fs | Phase E (automated): EXT-03 = %.0f/%.0f pts | EXT-01/EXT-02: MANUAL (BTC)\n",
		elapsed.Seconds(), result.TotalScore, result.MaxScore)

	return nil
}

func runPhaseR(cmd *cobra.Command, args []string) error {
	cfg, err := buildConfig(cmd, "r", "./reports/phase_r")
	if err != nil {
		return err
	}
	cfg.PayloadTier = "all"
	if cfg.OutputDir == "" {
		cfg.OutputDir = "./reports/phase_r"
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	if err := cfg.EnsureOutputDir(); err != nil {
		return fmt.Errorf("cannot create output dir: %w", err)
	}

	engineCfg := &phaser.RConfigWrapper{
		TargetBaseURL: cfg.TargetBaseURL(),
		WAFBaseURL:    cfg.WAFBaseURL(),
		WAFAdminURL:   cfg.WAFAdminURL(),
		ControlSecret: cfg.ControlSecret,
		TimeoutSec:    cfg.RequestTimeoutSec,
		Verbose:       cfg.Verbose,
		DryRun:        dryRun,
	}

	pool := crossphase.NewPool()
	engine := phaser.NewREngine(engineCfg, pool)

	startTime := time.Now()
	result, err := engine.Run()
	if err != nil {
		// Non-fatal: print error but still display partial results
		fmt.Fprintf(os.Stderr, "⚠️  Phase R: %v\n", err)
	}
	elapsed := time.Since(startTime)

	if dryRun {
		fmt.Println("🧪 DRY RUN MODE — No actual HTTP requests were made")
		fmt.Println()
	}

	phaser.DisplayPhaseRResult(result)

	// SEC-02: Cross-phase outbound filtering
	sec02Result := pool.ComputeSEC02()
	fmt.Println()
	crossphase.DisplaySEC02(sec02Result)
	if genErr := crossphase.GenerateReport(sec02Result, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  SEC-02 report warning: %v\n", genErr)
	}

	if genErr := phaser.GenerateReport(result, cfg.OutputDir); genErr != nil {
		fmt.Fprintf(os.Stderr, "⚠️  Report generation warning: %v\n", genErr)
	}

	fmt.Printf("\nCompleted in %.1fs | Phase R: SEC-05 = %.0f/%.0f pts\n",
		elapsed.Seconds(), result.SEC05Score, result.SEC05Max)

	return nil
}
