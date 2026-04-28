package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/waf-hackathon/benchmark/internal/config"
)

const toolVersion = "0.1.0"

func main() {
	var (
		configPath = flag.String("config", "benchmark_config.yaml", "Path to benchmark configuration file")
		outputDir  = flag.String("output", defaultPhaseEOutputDir(), "Output directory for Phase E reports")
		noHTML     = flag.Bool("no-html", false, "Skip HTML report generation")
		noJSON     = flag.Bool("no-json", false, "Skip JSON report generation")
	)
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		color.Red("❌ Failed to load config: %v", err)
		os.Exit(1)
	}

	color.Cyan("🎯 Phase E target: %s", cfg.TargetAddr())
	color.Cyan("🛡️  Phase E WAF:    %s", cfg.WAFAddr())

	start := time.Now()
	report, err := RunPhaseEBenchmark(cfg, *configPath)
	if err != nil {
		color.Red("❌ Phase E benchmark failed: %v", err)
		os.Exit(2)
	}
	report.Metadata.DurationMs = time.Since(start).Milliseconds()

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		color.Red("❌ Failed to create output dir: %v", err)
		os.Exit(3)
	}

	if !*noJSON {
		jsonPath := filepath.Join(*outputDir, "phase_e_caching_report.json")
		if err := WriteJSONReport(report, jsonPath); err != nil {
			color.Red("❌ Failed to write JSON report: %v", err)
			os.Exit(4)
		}
		color.Green("📄 JSON report: %s", jsonPath)
	}

	if !*noHTML {
		htmlPath := filepath.Join(*outputDir, "phase_e_caching_report.html")
		if err := WriteHTMLReport(report, htmlPath); err != nil {
			color.Red("❌ Failed to write HTML report: %v", err)
			os.Exit(5)
		}
		color.Green("📄 HTML report: %s", htmlPath)
	}

	printSummary(report)
	if !report.Summary.Pass {
		os.Exit(1)
	}
}

func printSummary(report *PhaseEReport) {
	line := strings.Repeat("=", 74)
	fmt.Println("\n" + line)
	if report.Summary.Pass {
		color.Green("✅ Phase E PASSED (%d/%d cases)", report.Summary.PassedCases, report.Summary.TotalCases)
	} else {
		color.Red("❌ Phase E FAILED (%d/%d cases)", report.Summary.PassedCases, report.Summary.TotalCases)
	}
	fmt.Printf("Score: %.0f/%.0f\n", report.Summary.Score, report.Summary.MaxScore)
	fmt.Printf("Endpoint readiness: %v\n", report.Summary.EndpointReady)
	fmt.Printf("Tie-break quality score: %.3f\n", report.TieBreak.PhaseEQualityScore)

	fmt.Println("\nFailed cases:")
	failed := 0
	for _, id := range report.CaseOrder {
		c, ok := report.Cases[id]
		if !ok || c.Passed {
			continue
		}
		failed++
		fmt.Printf("  - %s %s\n    Reason: %s\n    Observed: %s\n", c.CaseID, c.Name, c.Reason, c.Observed)
	}
	if failed == 0 {
		fmt.Println("  (none)")
	}
	fmt.Println(line)
}

func defaultPhaseEOutputDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "./cmd/waf-benchmark-phase-e/reports"
	}
	return filepath.Join(filepath.Dir(file), "reports")
}
