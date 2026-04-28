package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/waf-hackathon/benchmark/internal/config"
	"github.com/waf-hackathon/benchmark/internal/httpclient"
	"github.com/waf-hackathon/benchmark/internal/logger"
	"github.com/waf-hackathon/benchmark/internal/phases"
	"github.com/waf-hackathon/benchmark/internal/report"
	"github.com/waf-hackathon/benchmark/internal/scoring"
	"github.com/waf-hackathon/benchmark/internal/target"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

// BenchmarkRunner orchestrates the full benchmark execution
type BenchmarkRunner struct {
	Config         *config.Config
	Logger         *logger.Logger
	TargetClient   *target.Client
	WAFClient      *waf.WAFClient
	Capabilities   *target.AppCapabilities
	Control        *target.Control
	Auth           *target.Auth
	Pool           *httpclient.Pool
	Results        *BenchmarkResults
	PartialResults *PartialResults
	ShutdownChan   chan os.Signal
	IsShuttingDown bool
}

// BenchmarkResults contains results from all phases
type BenchmarkResults struct {
	PhaseA        *phases.PhaseAResult
	PhaseB        *phases.PhaseBResult
	PhaseC        *phases.PhaseCResult
	PhaseD        *phases.PhaseDResult
	PhaseE        *phases.PhaseEResult
	RiskLifecycle *phases.RiskLifecycleResult
	DurationMs    int64
	Completed     []string
}

// PartialResults tracks progress for saving on interrupt
type PartialResults struct {
	CompletedPhases []string
	PhaseA          *phases.PhaseAResult
	PhaseB          *phases.PhaseBResult
	PhaseC          *phases.PhaseCResult
	PhaseD          *phases.PhaseDResult
	PhaseE          *phases.PhaseEResult
	RiskLifecycle   *phases.RiskLifecycleResult
	Timestamp       time.Time
}

// NewBenchmarkRunner creates a new benchmark runner
func NewBenchmarkRunner(cfg *config.Config, log *logger.Logger) *BenchmarkRunner {
	return &BenchmarkRunner{
		Config:       cfg,
		Logger:       log,
		Results:      &BenchmarkResults{},
		PartialResults: &PartialResults{
			CompletedPhases: []string{},
			Timestamp:       time.Now(),
		},
		ShutdownChan: make(chan os.Signal, 1),
	}
}

// SetupSignalHandling sets up graceful shutdown on interrupt signals
func (br *BenchmarkRunner) SetupSignalHandling() {
	signal.Notify(br.ShutdownChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-br.ShutdownChan
		br.IsShuttingDown = true
		br.Logger.Warn("Received interrupt signal, initiating graceful shutdown...")
		br.SavePartialResults()
		os.Exit(1)
	}()
}

// HealthCheck performs pre-flight checks
type HealthCheck struct {
	Name    string
	Check   func() error
	Passed  bool
	Error   string
}

// RunHealthChecks performs all pre-flight health checks
func (br *BenchmarkRunner) RunHealthChecks() ([]HealthCheck, bool) {
	br.Logger.Info("Running pre-flight health checks...")

	checks := []HealthCheck{
		{
			Name: "Target App Connectivity",
			Check: func() error {
				client := target.NewClientWithScheme(
					br.Config.Benchmark.TargetApp.Host,
					br.Config.Benchmark.TargetApp.Port,
					br.Config.Benchmark.TargetApp.Scheme,
					br.Config.Benchmark.TargetApp.ControlSecret,
				)
				if err := client.Health(); err != nil {
					return fmt.Errorf("target app not responding on %s: %w", br.Config.TargetAddr(), err)
				}
				return nil
			},
		},
		{
			Name: "WAF Connectivity",
			Check: func() error {
				wafClient := waf.NewWAFClientWithScheme(
					br.Config.Benchmark.WAF.Scheme,
					br.Config.Benchmark.WAF.Host,
					br.Config.Benchmark.WAF.Port,
					5*time.Second,
				)
				if err := wafClient.Health(); err != nil {
					return fmt.Errorf("WAF not responding on %s: %w", br.Config.WAFAddr(), err)
				}
				return nil
			},
		},
		{
			Name: "Loopback Aliases",
			Check: func() error {
				// Check if we can bind to at least one IP in the test range
				testIP := "127.0.0.10"
				opts := httpclient.DefaultClientOptions()
				_, err := httpclient.NewBoundClient(testIP, opts)
				if err != nil {
					return fmt.Errorf("cannot bind to %s: %w. Run: sudo ifconfig lo:add 127.0.0.10-99", testIP, err)
				}
				return nil
			},
		},
		{
			Name: "Shared Files - Tor Exit Nodes",
			Check: func() error {
				paths := []string{
					"shared/tor_exit_nodes.txt",
					"../shared/tor_exit_nodes.txt",
					"/var/www/benchmark/shared/tor_exit_nodes.txt",
				}
				for _, path := range paths {
					if _, err := os.Stat(path); err == nil {
						return nil
					}
				}
				return fmt.Errorf("tor_exit_nodes.txt not found in shared/ directory")
			},
		},
		{
			Name: "Shared Files - Datacenter ASNs",
			Check: func() error {
				paths := []string{
					"shared/datacenter_asns.txt",
					"../shared/datacenter_asns.txt",
					"/var/www/benchmark/shared/datacenter_asns.txt",
				}
				for _, path := range paths {
					if _, err := os.Stat(path); err == nil {
						return nil
					}
				}
				return fmt.Errorf("datacenter_asns.txt not found in shared/ directory")
			},
		},
		{
			Name: "Capabilities File",
			Check: func() error {
				paths := []string{
					"testdata/app_capabilities.json",
					"../testdata/app_capabilities.json",
					"/var/www/benchmark/testdata/app_capabilities.json",
				}
				for _, path := range paths {
					if _, err := os.Stat(path); err == nil {
						return nil
					}
				}
				return fmt.Errorf("app_capabilities.json not found in testdata/ directory")
			},
		},
	}

	allPassed := true
	for i := range checks {
		br.Logger.Info(fmt.Sprintf("  Checking: %s...", checks[i].Name))
		if err := checks[i].Check(); err != nil {
			checks[i].Passed = false
			checks[i].Error = err.Error()
			br.Logger.Error(fmt.Sprintf("    FAIL: %s", err.Error()))
			allPassed = false
		} else {
			checks[i].Passed = true
			br.Logger.Info("    PASS")
		}
	}

	return checks, allPassed
}

// Initialize sets up all clients and loads capabilities
func (br *BenchmarkRunner) Initialize() error {
	br.Logger.Info("Initializing benchmark components...")

	// Create target client
	br.TargetClient = target.NewClientWithScheme(
		br.Config.Benchmark.TargetApp.Host,
		br.Config.Benchmark.TargetApp.Port,
		br.Config.Benchmark.TargetApp.Scheme,
		br.Config.Benchmark.TargetApp.ControlSecret,
	)

	// Create control client
	br.Control = target.NewControl(br.TargetClient)

	// Create auth helper
	br.Auth = target.NewAuth(br.TargetClient)

	// Load capabilities from target
	var err error
	br.Capabilities, err = br.TargetClient.ReadCapabilities()
	if err != nil {
		br.Logger.Warn(fmt.Sprintf("Could not load capabilities from target: %v. Using defaults.", err))
		br.Capabilities = &target.AppCapabilities{
			VulnsActive: target.GetVulnCategories(),
			LeaksActive: target.GetLeakCategories(),
			Version:     "default",
		}
	}

	// Create HTTP client pool
	poolOpts := httpclient.PoolOptions{
		ClientOptions: httpclient.ClientOptions{
			Timeout:       30 * time.Second,
			UserAgent:     "WAF-Benchmark/2.1",
			SkipTLSVerify: true,
			MaxConns:      100,
		},
		MaxRequestsPerSecondPerIP: 0,
	}
	br.Pool = httpclient.NewPool(poolOpts)

	// Create WAF client
	br.WAFClient = waf.NewWAFClientWithScheme(
		br.Config.Benchmark.WAF.Scheme,
		br.Config.Benchmark.WAF.Host,
		br.Config.Benchmark.WAF.Port,
		30*time.Second,
	)

	br.Logger.Info("Initialization complete")
	return nil
}

// RunBenchmark executes the specified phases
func (br *BenchmarkRunner) RunBenchmark(phasesToRun []string) (*BenchmarkResults, error) {
	start := time.Now()

	if len(phasesToRun) == 1 && phasesToRun[0] == "all" {
		phasesToRun = []string{"a", "b", "c", "d", "e", "risk"}
	}

	br.Logger.Info(fmt.Sprintf("Running phases: %s", strings.Join(phasesToRun, ", ")))

	for _, phase := range phasesToRun {
		if br.IsShuttingDown {
			break
		}

		phase = strings.ToLower(phase)
		br.Logger.Info(fmt.Sprintf("=== Starting Phase %s ===", strings.ToUpper(phase)))

		switch phase {
		case "a":
			if err := br.runPhaseA(); err != nil {
				br.Logger.Error(fmt.Sprintf("Phase A failed: %v", err))
			}
		case "b":
			if err := br.runPhaseB(); err != nil {
				br.Logger.Error(fmt.Sprintf("Phase B failed: %v", err))
			}
		case "c":
			if err := br.runPhaseC(); err != nil {
				br.Logger.Error(fmt.Sprintf("Phase C failed: %v", err))
			}
		case "d":
			if err := br.runPhaseD(); err != nil {
				br.Logger.Error(fmt.Sprintf("Phase D failed: %v", err))
			}
		case "e":
			if err := br.runPhaseE(); err != nil {
				br.Logger.Error(fmt.Sprintf("Phase E failed: %v", err))
			}
		case "risk", "lifecycle", "r":
			if err := br.runRiskLifecycle(); err != nil {
				br.Logger.Error(fmt.Sprintf("Risk Lifecycle failed: %v", err))
			}
		default:
			br.Logger.Warn(fmt.Sprintf("Unknown phase: %s", phase))
		}
	}

	br.Results.DurationMs = time.Since(start).Milliseconds()
	return br.Results, nil
}

type phaseAAuthorityReport struct {
	Results []struct {
		TestID   string `json:"TestID"`
		Category string `json:"Category"`
		Passed   bool   `json:"Passed"`
		Reason   string `json:"Reason"`
	} `json:"Results"`
}

func determinePhaseATargetProfile(cfg *config.Config) string {
	host := strings.ToLower(strings.TrimSpace(cfg.Benchmark.WAF.Host))
	if host == "localhost" || strings.HasPrefix(host, "127.") {
		return "internal"
	}
	return "external"
}

func toLegacyExploitDecision(passed bool) waf.Decision {
	if passed {
		return waf.Block
	}
	return waf.Allow
}

func (br *BenchmarkRunner) runPhaseA() error {
	if err := br.Control.Reset(); err != nil {
		br.Logger.Warn(fmt.Sprintf("Failed to reset target: %v", err))
	}

	tmpDir, err := os.MkdirTemp("", "phase-a-authority-")
	if err != nil {
		return fmt.Errorf("failed to create temp directory for Phase A authority runner: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	targetURL := fmt.Sprintf("http://%s:%d", br.Config.Benchmark.WAF.Host, br.Config.Benchmark.WAF.Port)
	profile := determinePhaseATargetProfile(br.Config)
	jsonPath := filepath.Join(tmpDir, "phase_a_report.json")

	cmd := exec.Command(
		"go", "run", "./cmd/waf-benchmark-phase-a",
		"-target", targetURL,
		"-target-profile", profile,
		"-payload", "all",
		"-output", tmpDir,
		"-no-html",
	)
	cmd.Dir = "."
	output, runErr := cmd.CombinedOutput()
	if runErr != nil {
		return fmt.Errorf("authoritative Phase A runner failed: %w\n%s", runErr, strings.TrimSpace(string(output)))
	}

	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		return fmt.Errorf("failed to read authoritative Phase A JSON output (%s): %w", jsonPath, err)
	}

	var authority phaseAAuthorityReport
	if err := json.Unmarshal(raw, &authority); err != nil {
		return fmt.Errorf("failed to parse authoritative Phase A JSON output: %w", err)
	}

	type agg struct {
		testID   string
		category string
		passed   bool
		reason   string
	}
	exploitAgg := make(map[string]*agg)
	leakAgg := make(map[string]*agg)

	for _, r := range authority.Results {
		id := strings.TrimSpace(r.TestID)
		cat := strings.TrimSpace(r.Category)
		if id == "" || strings.EqualFold(cat, "canary") {
			continue
		}

		targetMap := exploitAgg
		if strings.EqualFold(cat, "leak") {
			targetMap = leakAgg
		}

		current, ok := targetMap[id]
		if !ok {
			targetMap[id] = &agg{testID: id, category: cat, passed: r.Passed, reason: r.Reason}
			continue
		}

		current.passed = current.passed && r.Passed
		if !r.Passed && strings.TrimSpace(r.Reason) != "" {
			current.reason = r.Reason
		}
	}

	result := &phases.PhaseAResult{
		ExploitTests: make([]phases.ExploitResult, 0, len(exploitAgg)),
		LeakTests:    make([]phases.LeakResult, 0, len(leakAgg)),
	}

	exploitIDs := make([]string, 0, len(exploitAgg))
	for id := range exploitAgg {
		exploitIDs = append(exploitIDs, id)
	}
	sort.Strings(exploitIDs)
	for _, id := range exploitIDs {
		a := exploitAgg[id]
		result.ExploitTests = append(result.ExploitTests, phases.ExploitResult{
			TestID:      a.testID,
			Category:    a.category,
			Decision:    toLegacyExploitDecision(a.passed),
			Passed:      a.passed,
			Bypassed:    !a.passed,
			Description: a.reason,
		})
		result.TotalExploits++
		if a.passed {
			result.BlockedExploits++
		}
	}

	leakIDs := make([]string, 0, len(leakAgg))
	for id := range leakAgg {
		leakIDs = append(leakIDs, id)
	}
	sort.Strings(leakIDs)
	for _, id := range leakIDs {
		a := leakAgg[id]
		result.LeakTests = append(result.LeakTests, phases.LeakResult{
			TestID:       a.testID,
			Passed:       a.passed,
			LeakDetected: !a.passed,
		})
		result.TotalLeaks++
		if a.passed {
			result.FilteredLeaks++
		}
	}

	if result.TotalExploits > 0 {
		result.ExploitPreventionRate = float64(result.BlockedExploits) / float64(result.TotalExploits) * 100
	}
	if result.TotalLeaks > 0 {
		result.OutboundFilterRate = float64(result.FilteredLeaks) / float64(result.TotalLeaks) * 100
	}

	br.Results.PhaseA = result
	br.PartialResults.PhaseA = result
	br.PartialResults.CompletedPhases = append(br.PartialResults.CompletedPhases, "a")
	br.Results.Completed = append(br.Results.Completed, "a")

	br.Logger.Info(fmt.Sprintf("Phase A complete: %.1f%% exploit prevention, %.1f%% outbound filter",
		result.ExploitPreventionRate, result.OutboundFilterRate))
	return nil
}

func (br *BenchmarkRunner) runPhaseB() error {
	// Reset target before Phase B
	if err := br.Control.Reset(); err != nil {
		br.Logger.Warn(fmt.Sprintf("Failed to reset target: %v", err))
	}

	result, err := phases.RunPhaseB(br.WAFClient, br.Auth, br.Control, br.Config)
	if err != nil {
		return err
	}

	br.Results.PhaseB = result
	br.PartialResults.PhaseB = result
	br.PartialResults.CompletedPhases = append(br.PartialResults.CompletedPhases, "b")
	br.Results.Completed = append(br.Results.Completed, "b")

	br.Logger.Info(fmt.Sprintf("Phase B complete: %.1f%% abuse detection rate",
		result.AbuseDetectionRate))
	return nil
}

func (br *BenchmarkRunner) runPhaseC() error {
	result, err := phases.RunPhaseC(br.TargetClient, br.WAFClient, br.Pool)
	if err != nil {
		return err
	}

	br.Results.PhaseC = result
	br.PartialResults.PhaseC = result
	br.PartialResults.CompletedPhases = append(br.PartialResults.CompletedPhases, "c")
	br.Results.Completed = append(br.Results.Completed, "c")

	br.Logger.Info(fmt.Sprintf("Phase C complete: Peak RPS=%.0f, Sustained RPS=%.0f",
		result.PeakRPS, result.SustainedRPS))
	return nil
}

func (br *BenchmarkRunner) runPhaseD() error {
	// Reset target before Phase D
	if err := br.Control.Reset(); err != nil {
		br.Logger.Warn(fmt.Sprintf("Failed to reset target: %v", err))
	}

	result, err := phases.RunPhaseD(br.WAFClient, br.TargetClient, br.Control)
	if err != nil {
		return err
	}

	br.Results.PhaseD = result
	br.PartialResults.PhaseD = result
	br.PartialResults.CompletedPhases = append(br.PartialResults.CompletedPhases, "d")
	br.Results.Completed = append(br.Results.Completed, "d")

	br.Logger.Info(fmt.Sprintf("Phase D complete: DDoS=%.1f, Backend=%.1f, FailMode=%.1f",
		result.DDoSScore, result.BackendScore, result.FailModeScore))
	return nil
}

func (br *BenchmarkRunner) runPhaseE() error {
	result, err := phases.RunPhaseE(br.WAFClient, br.Config.Benchmark.WAF.ConfigPath)
	if err != nil {
		return err
	}

	br.Results.PhaseE = result
	br.PartialResults.PhaseE = result
	br.PartialResults.CompletedPhases = append(br.PartialResults.CompletedPhases, "e")
	br.Results.Completed = append(br.Results.Completed, "e")

	br.Logger.Info(fmt.Sprintf("Phase E complete: HotReload=%.1f, Caching=%.1f",
		result.HotReloadScore, result.CachingScore))
	return nil
}

func (br *BenchmarkRunner) runRiskLifecycle() error {
	tester := phases.NewRiskLifecycleTester(br.WAFClient, br.TargetClient)
	result, err := tester.RunRiskLifecycle()
	if err != nil {
		return err
	}

	br.Results.RiskLifecycle = result
	br.PartialResults.RiskLifecycle = result
	br.PartialResults.CompletedPhases = append(br.PartialResults.CompletedPhases, "risk")
	br.Results.Completed = append(br.Results.Completed, "risk")

	br.Logger.Info(fmt.Sprintf("Risk Lifecycle complete: %.1f/8 points",
		result.TotalScore))
	return nil
}

// SavePartialResults saves partial results on interrupt
func (br *BenchmarkRunner) SavePartialResults() {
	if len(br.PartialResults.CompletedPhases) == 0 {
		return
	}

	br.PartialResults.Timestamp = time.Now()

	filename := fmt.Sprintf("partial_results_%d.json", time.Now().Unix())
	data, err := json.MarshalIndent(br.PartialResults, "", "  ")
	if err != nil {
		br.Logger.Error(fmt.Sprintf("Failed to marshal partial results: %v", err))
		return
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		br.Logger.Error(fmt.Sprintf("Failed to write partial results: %v", err))
		return
	}

	br.Logger.Info(fmt.Sprintf("Partial results saved to: %s", filename))
}

// GenerateReports generates JSON and/or HTML reports
func (br *BenchmarkRunner) GenerateReports(outputDir string, jsonFormat, htmlFormat bool) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create score report
	scoreReport := scoring.NewScoreReport(
		br.Results.PhaseA,
		br.Results.PhaseB,
		br.Results.PhaseC,
		br.Results.PhaseD,
		br.Results.PhaseE,
		br.Results.RiskLifecycle,
	)

	reportGen := report.NewReportGenerator(true, true)

	if jsonFormat {
		jsonData, err := reportGen.GenerateJSONReport(scoreReport)
		if err != nil {
			return fmt.Errorf("failed to generate JSON report: %w", err)
		}

		jsonPath := filepath.Join(outputDir, "benchmark_report.json")
		if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}
		br.Logger.Info(fmt.Sprintf("JSON report saved to: %s", jsonPath))
	}

	if htmlFormat {
		htmlData, err := reportGen.GenerateHTMLReport(scoreReport)
		if err != nil {
			return fmt.Errorf("failed to generate HTML report: %w", err)
		}

		htmlPath := filepath.Join(outputDir, "benchmark_report.html")
		if err := os.WriteFile(htmlPath, htmlData, 0644); err != nil {
			return fmt.Errorf("failed to write HTML report: %w", err)
		}
		br.Logger.Info(fmt.Sprintf("HTML report saved to: %s", htmlPath))
	}

	return nil
}

// PrintSummary prints a text summary of results
func (br *BenchmarkRunner) PrintSummary() {
	scoreReport := scoring.NewScoreReport(
		br.Results.PhaseA,
		br.Results.PhaseB,
		br.Results.PhaseC,
		br.Results.PhaseD,
		br.Results.PhaseE,
		br.Results.RiskLifecycle,
	)

	reportGen := report.NewReportGenerator(false, false)
	summary := reportGen.GenerateTextReport(scoreReport)

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println(summary)
	fmt.Println(strings.Repeat("=", 60))
}

// RunBenchmarkWithContext runs the benchmark with context for timeout/cancellation
func RunBenchmarkWithContext(ctx context.Context, cfg *config.Config, log *logger.Logger, phases []string, outputDir string, jsonFormat, htmlFormat, skipHealth bool) error {
	runner := NewBenchmarkRunner(cfg, log)
	runner.SetupSignalHandling()

	// Run health checks
	if !skipHealth {
		checks, allPassed := runner.RunHealthChecks()
		if !allPassed {
			log.Error("Pre-flight checks failed:")
			for _, check := range checks {
				if !check.Passed {
					log.Error(fmt.Sprintf("  - %s: %s", check.Name, check.Error))
				}
			}
			return fmt.Errorf("health checks failed")
		}
	}

	// Initialize components
	if err := runner.Initialize(); err != nil {
		return fmt.Errorf("initialization failed: %w", err)
	}

	// Run benchmark
	done := make(chan error, 1)
	go func() {
		_, err := runner.RunBenchmark(phases)
		done <- err
	}()

	select {
	case <-ctx.Done():
		runner.SavePartialResults()
		return ctx.Err()
	case err := <-done:
		if err != nil {
			return err
		}
	}

	// Print summary
	runner.PrintSummary()

	// Generate reports
	if err := runner.GenerateReports(outputDir, jsonFormat, htmlFormat); err != nil {
		log.Error(fmt.Sprintf("Failed to generate reports: %v", err))
	}

	return nil
}
