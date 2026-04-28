// WAF Benchmark Phase A - Main Entry Point
// Comprehensive exploit testing based on exploit_catalogue.md

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
)

func main() {
	// Parse command line flags
	var (
		targetURL     = flag.String("target", "", "Target URL override (if empty, resolved from -target-profile)")
		targetProfile = flag.String("target-profile", "external", "Target profile: internal or external")
		outputDir     = flag.String("output", "./reports", "Output directory for reports")
		noHTML        = flag.Bool("no-html", false, "Skip HTML report generation")
		noJSON        = flag.Bool("no-json", false, "Skip JSON report generation")
		verbose       = flag.Bool("verbose", false, "Enable verbose output")
		_             = verbose // Will be used later
		testID        = flag.String("test", "", "Run specific test ID only (e.g., V01, V06)")
		_             = testID // Will be used later
		payloadMode   = flag.String("payload", "all", "Payload execution set: simple, advanced, or all")
	)
	flag.Parse()

	resolvedTargetURL, resolvedProfile, err := resolveTargetFromFlags(*targetURL, *targetProfile)
	if err != nil {
		color.Red("❌ Invalid target selection: %v", err)
		os.Exit(1)
	}

	activeModes, err := resolveActiveModesFromFlag(*payloadMode)
	if err != nil {
		color.Red("❌ Invalid -payload value: %v", err)
		os.Exit(1)
	}

	// Print banner
	printBanner(resolvedTargetURL, resolvedProfile)
	color.Cyan("🔀 Target profile: %s", resolvedProfile)
	color.Cyan("🧪 Active payload mode set: %s → %s", strings.ToLower(strings.TrimSpace(*payloadMode)), strings.Join(activeModes, ", "))

	// Create test suite
	ts := NewTestSuite(resolvedTargetURL, resolvedProfile, activeModes)

	// Authenticate if needed
	color.Yellow("🔐 Attempting authentication...")
	if err := ts.Authenticate(); err != nil {
		color.Yellow("⚠️  Authentication failed (some tests may be skipped): %v", err)
	} else {
		color.Green("✅ Authenticated as alice (SID: %s...)", ts.AuthSession.SID[:8])
	}

	// Run tests
	color.Yellow("\n🚀 Running Phase A tests...")
	if err := ts.RunTests(); err != nil {
		color.Red("❌ Benchmark halted: %v", err)
		os.Exit(2)
	}

	// Print summary to console
	printConsoleSummary(ts)

	// Generate reports
	if !*noHTML {
		htmlPath := *outputDir + "/phase_a_report.html"
		if err := ts.GenerateEnhancedHTMLReport(htmlPath); err != nil {
			color.Red("❌ Failed to generate HTML report: %v", err)
		} else {
			color.Green("📄 HTML report: %s", htmlPath)
		}
	}

	if !*noJSON {
		jsonPath := *outputDir + "/phase_a_report.json"
		if err := ts.GenerateJSONReport(jsonPath); err != nil {
			color.Red("❌ Failed to generate JSON report: %v", err)
		} else {
			color.Green("📄 JSON report: %s", jsonPath)
		}
	}

	// Exit with error code if tests failed
	if ts.Summary.Failed > 0 {
		color.Red("\n⚠️  %d test(s) failed - WAF may have vulnerabilities", ts.Summary.Failed)
		os.Exit(1)
	}

	color.Green("\n✅ All tests passed!")
}

func resolveActiveModesFromFlag(payloadMode string) ([]string, error) {
	switch strings.ToLower(strings.TrimSpace(payloadMode)) {
	case "simple":
		return []string{"mode1_malformed_request_only"}, nil
	case "advanced":
		return []string{"mode2_smuggling", "mode3_header_cannibalism", "mode4_slow_post", "mode5_chunked_variation"}, nil
	case "all", "":
		return []string{
			"mode1_malformed_request_only",
			"mode2_smuggling",
			"mode3_header_cannibalism",
			"mode4_slow_post",
			"mode5_chunked_variation",
		}, nil
	default:
		return nil, fmt.Errorf("expected one of: simple, advanced, all (got %q)", payloadMode)
	}
}

func printBanner(target string, profile string) {
	banner := `
╔══════════════════════════════════════════════════════════════╗
║     🔒 WAF BENCHMARK - PHASE A: SECURITY EFFECTIVENESS       ║
╠══════════════════════════════════════════════════════════════╣
║  Based on: exploit_catalogue.md & scoring_matrix.csv       ║
║  Tests: V01-V23 (Exploits), L01-L05 (Leaks), Canaries       ║
║  Scoring: SEC-01 (15 pts), SEC-02 (5 pts), SEC-04 (2 pts)   ║
╚══════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
	color.Cyan("🎯 Target: %s", target)
	color.Cyan("🏷️  Profile: %s\n", profile)
}

func resolveTargetFromFlags(targetURL string, targetProfile string) (string, string, error) {
	profile := strings.ToLower(strings.TrimSpace(targetProfile))
	if profile == "" {
		profile = "external"
	}

	resolvedURL := strings.TrimSpace(targetURL)
	if resolvedURL == "" {
		switch profile {
		case "internal":
			resolvedURL = "http://localhost:8080"
		case "external":
			resolvedURL = "http://sec-team.waf-exams.info"
		default:
			return "", "", fmt.Errorf("target profile must be one of: internal, external")
		}
	}

	if !strings.HasPrefix(resolvedURL, "http://") && !strings.HasPrefix(resolvedURL, "https://") {
		return "", "", fmt.Errorf("target URL must start with http:// or https://")
	}

	resolvedURL = strings.TrimRight(resolvedURL, "/")
	return resolvedURL, profile, nil
}

func printConsoleSummary(ts *TestSuiteResults) {
	fmt.Println("\n" + strings.Repeat("=", 70))
	color.Yellow("📊 TEST SUMMARY")
	fmt.Println(strings.Repeat("=", 70))

	fmt.Printf("Total Tests:     %d\n", ts.Summary.TotalTests)
	color.Green("Passed:          %d", ts.Summary.Passed)
	color.Red("Failed:          %d", ts.Summary.Failed)
	fmt.Printf("Skipped:         %d\n", ts.Summary.TotalTests-ts.Summary.Passed-ts.Summary.Failed)
	fmt.Println(strings.Repeat("-", 70))

	// Score display
	percentage := ts.Summary.Percentage
	scoreClass := color.GreenString
	if percentage < 70 {
		scoreClass = color.RedString
	} else if percentage < 90 {
		scoreClass = color.YellowString
	}

	fmt.Printf("Overall Score:   %s (%.1f/%.1f points)\n",
		scoreClass("%.1f%%", percentage),
		ts.Summary.TotalScore,
		ts.Summary.MaxPossibleScore)

	// Category breakdown
	fmt.Println("\n📋 Category Breakdown:")
	for cat, score := range ts.Summary.CategoryScores {
		status := color.GreenString("✅")
		if score.Passed < score.Total {
			status = color.RedString("❌")
		}
		fmt.Printf("  %s %s: %d/%d passed (%.1f%%)\n",
			status, cat, score.Passed, score.Total, score.Percentage)
	}

	// Failed tests details
	if ts.Summary.Failed > 0 {
		fmt.Println("\n❌ Failed Tests (Vulnerabilities Detected):")
		for _, r := range ts.Results {
			if !r.Passed {
				fmt.Printf("  • %s (%s): %s\n", r.TestID, r.Technique, r.Reason)
				if r.MarkerFound {
					markerToShow := r.MarkerExpected
					if r.MatchedMarker != "" {
						markerToShow = r.MatchedMarker
					}
					fmt.Printf("    → Marker '%s' (%s) found in %s\n", markerToShow, r.MarkerMatchType, r.MarkerLocation)
				}
			}
		}
	}

	fmt.Println(strings.Repeat("=", 70))
}
