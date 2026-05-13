package crossphase

import (
	"fmt"
	"strings"
)

// DisplaySEC02 in kết quả SEC-02 ra console theo template cross_phase.md §7.1.
func DisplaySEC02(r SEC02Result) {
	w := 66

	printSep("═", w)
	fmt.Println("  §CROSS-1 — GLOBAL OUTBOUND FILTERING (SEC-02)")
	printSep("─", w)

	// Negative control
	fmt.Println("  Negative Control:")
	markerIDs := []string{"L01", "L02", "L03", "L04", "L05"}
	markerNames := []string{
		"__L01_STACKTRACE__",
		"__L02_INTERNAL_IP__",
		"__L03_DEBUG_SQL__",
		"__L04_PII__",
		"__L05_VERBOSE_404__",
	}

	for i, id := range markerIDs {
		name := markerNames[i]
		status := "✓ valid"
		if !r.NegativeControlPassed[name] {
			status = "✗ SKIP"
		}
		fmt.Printf("    %s (%-24s) ... %s\n", id, name, status)
	}

	fmt.Println()
	fmt.Println("  Global Response Scan:")
	fmt.Printf("    Total responses scanned:   %s\n", formatNum(r.TotalResponses))
	fmt.Printf("    Clean (no __L*__ markers): %s\n", formatNum(r.CleanResponses))
	fmt.Printf("    Leaked (≥1 __L*__ marker): %s\n", formatNum(r.LeakedResponses))

	fmt.Println()
	fmt.Println("  Per-Marker Breakdown:")
	for _, id := range markerIDs {
		name := markerNames[idToIdx(id)]
		stats := r.MarkerBreakdown[id]
		phaseList := strings.Join(stats.Phases, ", ")
		if phaseList == "" {
			phaseList = "—"
		}
		fmt.Printf("    %s  %-28s %3d occurrences  (Phases: %s)\n",
			id, name, stats.TotalMatches, phaseList)
	}

	printSep("─", w)
	fmt.Printf("  SEC-02   (Outbound Filtering) %s/%s × 5  =  %5.2f / 5\n",
		formatNum(r.CleanResponses), formatNum(r.TotalResponses), r.Score)
	printSep("═", w)
}

func idToIdx(id string) int {
	switch id {
	case "L01":
		return 0
	case "L02":
		return 1
	case "L03":
		return 2
	case "L04":
		return 3
	case "L05":
		return 4
	default:
		return 0
	}
}

func printSep(ch string, w int) {
	fmt.Println(strings.Repeat(ch, w))
}

func formatNum(n int) string {
	if n >= 10000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	if len(s) < 4 {
		return strings.Repeat(" ", 3-len(s)) + s
	}
	return s
}
