package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/waf-hackathon/benchmark/internal/config"
)

const toolVersion = "0.1.0"

func main() {
	var (
		configPath = flag.String("config", "benchmark_config.yaml", "Path to benchmark configuration file")
		outputDir  = flag.String("output", "./reports/phase-d", "Output directory for Phase D reports")
		noHTML     = flag.Bool("no-html", false, "Skip HTML report generation")
		noJSON     = flag.Bool("no-json", false, "Skip JSON report generation")
	)
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		color.Red("❌ Failed to load config: %v", err)
		os.Exit(1)
	}

	color.Cyan("🎯 Phase D target: %s", cfg.TargetAddr())
	color.Cyan("🛡️  Phase D WAF:    %s", cfg.WAFAddr())

	start := time.Now()
	report, err := RunPhaseDBenchmark(cfg, *configPath)
	if err != nil {
		color.Red("❌ Phase D benchmark failed: %v", err)
		os.Exit(2)
	}
	report.Metadata.DurationMs = time.Since(start).Milliseconds()

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		color.Red("❌ Failed to create output dir: %v", err)
		os.Exit(3)
	}

	if !*noJSON {
		jsonPath := filepath.Join(*outputDir, "phase_d_report.json")
		if err := WriteJSONReport(report, jsonPath); err != nil {
			color.Red("❌ Failed to write JSON report: %v", err)
			os.Exit(4)
		}
		color.Green("📄 JSON report: %s", jsonPath)
	}

	if !*noHTML {
		htmlPath := filepath.Join(*outputDir, "phase_d_report.html")
		if err := WriteHTMLReport(report, htmlPath); err != nil {
			color.Red("❌ Failed to write HTML report: %v", err)
			os.Exit(5)
		}
		color.Green("📄 HTML report: %s", htmlPath)
	}

	printSummary(report)
	if !report.PhaseDSummary.Pass {
		os.Exit(1)
	}
}

func printSummary(report *PhaseDReport) {
	line := strings.Repeat("=", 72)
	fmt.Println("\n" + line)
	if report.PhaseDSummary.Pass {
		color.Green("✅ Phase D PASSED (%d/%d cases)", report.PhaseDSummary.PassedCases, report.PhaseDSummary.TotalCases)
	} else {
		color.Red("❌ Phase D FAILED (%d/%d cases)", report.PhaseDSummary.PassedCases, report.PhaseDSummary.TotalCases)
	}
	fmt.Printf("Score: %.0f/%.0f (DDoS %.0f, Backend %.0f, Fail-Mode %.0f)\n",
		report.PhaseDSummary.Score,
		report.PhaseDSummary.MaxScore,
		report.PhaseDSummary.DDoSScore,
		report.PhaseDSummary.BackendScore,
		report.PhaseDSummary.FailModeScore,
	)

	fmt.Println("\nFailed cases:")
	failed := 0
	for _, id := range report.CaseOrder {
		c := report.Cases[id]
		if c.Passed {
			continue
		}
		failed++
		fmt.Printf("  - %s %s\n    Reason: %s\n    Observed: %s\n", c.TestID, c.Name, c.Reason, c.Observed)
	}
	if failed == 0 {
		fmt.Println("  (none)")
	}
	fmt.Println(line)
}
