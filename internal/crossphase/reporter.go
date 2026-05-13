package crossphase

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// SEC02Report là cấu trúc JSON cho SEC-02 report.
type SEC02Report struct {
	Criterion          string              `json:"criterion"`
	Phase              string              `json:"phase"`
	NegativeControl    map[string]bool     `json:"negative_control"`
	TotalResponses     int                 `json:"total_responses"`
	CleanResponses     int                 `json:"clean_responses"`
	LeakedResponses    int                 `json:"leaked_responses"`
	GlobalFilterRate   float64             `json:"global_filter_rate"`
	Score              float64             `json:"score"`
	MaxScore           float64             `json:"max_score"`
	MarkerBreakdown    map[string]MarkerBreakdownJSON `json:"marker_breakdown"`
}

// MarkerBreakdownJSON là thống kê marker cho JSON export.
type MarkerBreakdownJSON struct {
	TotalMatches int      `json:"total_matches"`
	Phases       []string `json:"phases"`
}

// GenerateReport ghi report_cross_phase.json.
func GenerateReport(r SEC02Result, outputDir string) error {
	report := SEC02Report{
		Criterion:        "SEC-02",
		Phase:            "Cross-1",
		NegativeControl:  r.NegativeControlPassed,
		TotalResponses:   r.TotalResponses,
		CleanResponses:   r.CleanResponses,
		LeakedResponses:  r.LeakedResponses,
		GlobalFilterRate: r.GlobalFilterRate,
		Score:            r.Score,
		MaxScore:         r.MaxScore,
		MarkerBreakdown:  make(map[string]MarkerBreakdownJSON),
	}

	for marker, stats := range r.MarkerBreakdown {
		phases := stats.Phases
		if phases == nil {
			phases = []string{}
		}
		report.MarkerBreakdown[marker] = MarkerBreakdownJSON{
			TotalMatches: stats.TotalMatches,
			Phases:       phases,
		}
	}

	jsonPath := filepath.Join(outputDir, "report_cross_phase.json")
	if err := os.MkdirAll(filepath.Dir(jsonPath), 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	f, err := os.Create(jsonPath)
	if err != nil {
		return fmt.Errorf("create JSON: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}

	fmt.Printf("📄 SEC-02 report: %s\n", jsonPath)
	return nil
}
