package scoring

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ScoringMatrixEntry represents a single entry in the scoring matrix
type ScoringMatrixEntry struct {
	TestID      string
	Category    string
	SubCategory string
	Points      float64
	Criteria    string
	Description string
}

// ScoringMatrix contains all scoring criteria
type ScoringMatrix struct {
	Entries []ScoringMatrixEntry
	ByID    map[string]ScoringMatrixEntry
}

// NewScoringMatrix creates a new scoring matrix
func NewScoringMatrix() *ScoringMatrix {
	return &ScoringMatrix{
		Entries: make([]ScoringMatrixEntry, 0),
		ByID:    make(map[string]ScoringMatrixEntry),
	}
}

// LoadFromCSV loads the scoring matrix from a CSV file.
// It resolves columns by header name and only ingests score-bearing rows (SEC/PERF/INT/EXT/ARCH/UI/DEP).
func (sm *ScoringMatrix) LoadFromCSV(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open scoring matrix: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return fmt.Errorf("failed to read CSV: %w", err)
	}
	if len(records) == 0 {
		return fmt.Errorf("scoring matrix CSV is empty")
	}

	headerIndex := make(map[string]int)
	for i, h := range records[0] {
		headerIndex[strings.ToLower(strings.TrimSpace(h))] = i
	}

	required := []string{"id", "category", "criterion", "description", "max_points"}
	for _, col := range required {
		if _, ok := headerIndex[col]; !ok {
			return fmt.Errorf("missing required CSV header: %s", col)
		}
	}

	sm.Entries = sm.Entries[:0]
	sm.ByID = make(map[string]ScoringMatrixEntry)

	for row := 1; row < len(records); row++ {
		rec := records[row]
		id := strings.TrimSpace(rec[headerIndex["id"]])
		if id == "" {
			continue
		}

		// Ignore separators and non-score rows.
		if !isScoreCriterionID(id) {
			continue
		}

		maxRaw := strings.TrimSpace(rec[headerIndex["max_points"]])
		points, err := strconv.ParseFloat(maxRaw, 64)
		if err != nil {
			return fmt.Errorf("invalid max_points for %s: %q", id, maxRaw)
		}

		entry := ScoringMatrixEntry{
			TestID:      id,
			Category:    strings.TrimSpace(rec[headerIndex["category"]]),
			SubCategory: strings.TrimSpace(rec[headerIndex["criterion"]]),
			Points:      points,
			Criteria:    strings.TrimSpace(rec[headerIndex["criterion"]]),
			Description: strings.TrimSpace(rec[headerIndex["description"]]),
		}

		sm.Entries = append(sm.Entries, entry)
		sm.ByID[entry.TestID] = entry
	}

	if len(sm.Entries) == 0 {
		return fmt.Errorf("no score-bearing entries parsed from %s", path)
	}

	return nil
}

func isScoreCriterionID(id string) bool {
	id = strings.ToUpper(strings.TrimSpace(id))
	prefixes := []string{"SEC-", "PERF-", "INT-", "EXT-", "ARCH-", "UI-", "DEP-"}
	for _, p := range prefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// GetPoints returns the points for a specific test ID
func (sm *ScoringMatrix) GetPoints(testID string) float64 {
	if entry, ok := sm.ByID[testID]; ok {
		return entry.Points
	}
	return 0
}

// GetCategoryPoints returns total points for a category
func (sm *ScoringMatrix) GetCategoryPoints(category string) float64 {
	total := 0.0
	for _, entry := range sm.Entries {
		if strings.EqualFold(entry.Category, category) {
			total += entry.Points
		}
	}
	return total
}

// DefaultScoringMatrix returns the default scoring matrix for WAF Benchmark (Option A: full 120-point profile).
func DefaultScoringMatrix() *ScoringMatrix {
	sm := NewScoringMatrix()

	sm.Entries = append(sm.Entries,
		ScoringMatrixEntry{TestID: "SEC-01", Category: "Security Effectiveness", SubCategory: "Exploit Prevention", Points: 15, Criteria: "15 × prevention_rate", Description: "Block exploit attempts across vulnerability families"},
		ScoringMatrixEntry{TestID: "SEC-02", Category: "Security Effectiveness", SubCategory: "Outbound Filtering", Points: 5, Criteria: "5 × filter_rate", Description: "Strip leaked data from responses"},
		ScoringMatrixEntry{TestID: "SEC-03", Category: "Security Effectiveness", SubCategory: "Abuse Detection", Points: 10, Criteria: "10 × detection_rate", Description: "Detect brute force / stuffing / spraying / recon"},
		ScoringMatrixEntry{TestID: "SEC-04", Category: "Security Effectiveness", SubCategory: "Canary Detection", Points: 2, Criteria: "binary", Description: "Block all canary endpoints"},
		ScoringMatrixEntry{TestID: "SEC-05", Category: "Security Effectiveness", SubCategory: "Risk Lifecycle", Points: 8, Criteria: "sum of step scores", Description: "Risk score correctness across 7 sequential steps"},

		ScoringMatrixEntry{TestID: "PERF-01", Category: "Performance", SubCategory: "p99 Latency", Points: 10, Criteria: "binary", Description: "p99 latency overhead at 5k RPS"},
		ScoringMatrixEntry{TestID: "PERF-02", Category: "Performance", SubCategory: "Throughput", Points: 5, Criteria: "binary", Description: "Sustained RPS while p99 ≤ 5ms"},
		ScoringMatrixEntry{TestID: "PERF-03", Category: "Performance", SubCategory: "Memory Footprint", Points: 3, Criteria: "binary", Description: "Peak RSS under load"},
		ScoringMatrixEntry{TestID: "PERF-04", Category: "Performance", SubCategory: "Graceful Degradation", Points: 2, Criteria: "binary", Description: "Behavior at 2× target load"},

		ScoringMatrixEntry{TestID: "INT-01", Category: "Intelligence & Adaptiveness", SubCategory: "Transaction Fraud Detection", Points: 4, Criteria: "4 × pass_rate", Description: "Detect fraudulent transactions"},
		ScoringMatrixEntry{TestID: "INT-02", Category: "Intelligence & Adaptiveness", SubCategory: "Behavioral Anomaly Detection", Points: 4, Criteria: "4 × pass_rate", Description: "Detect anomalous behavior"},
		ScoringMatrixEntry{TestID: "INT-03", Category: "Intelligence & Adaptiveness", SubCategory: "Relay Detection", Points: 4, Criteria: "4 × pass_rate", Description: "Detect proxy / relay attackers"},
		ScoringMatrixEntry{TestID: "INT-04", Category: "Intelligence & Adaptiveness", SubCategory: "Resilience / DDoS", Points: 8, Criteria: "sum of sub-scores", Description: "Survive flood / slowloris / fail-mode tests"},

		ScoringMatrixEntry{TestID: "EXT-01", Category: "Extensibility", SubCategory: "Hot-reload Add Rule", Points: 3, Criteria: "binary", Description: "Add new rule without restart"},
		ScoringMatrixEntry{TestID: "EXT-02", Category: "Extensibility", SubCategory: "Hot-reload Remove Rule", Points: 3, Criteria: "binary", Description: "Remove existing rule without restart"},
		ScoringMatrixEntry{TestID: "EXT-03", Category: "Extensibility", SubCategory: "Caching Correctness", Points: 4, Criteria: "1 point per sub-test", Description: "Cache behavior per route tier"},

		ScoringMatrixEntry{TestID: "ARCH-01", Category: "Architecture & Code Quality", SubCategory: "Code Quality / Idioms", Points: 5, Criteria: "manual", Description: "Idiomatic structure and readability"},
		ScoringMatrixEntry{TestID: "ARCH-02", Category: "Architecture & Code Quality", SubCategory: "Error Handling & Safety", Points: 4, Criteria: "manual", Description: "Safety and panic avoidance"},
		ScoringMatrixEntry{TestID: "ARCH-03", Category: "Architecture & Code Quality", SubCategory: "Test Coverage", Points: 3, Criteria: "manual", Description: "Unit + integration tests"},
		ScoringMatrixEntry{TestID: "ARCH-04", Category: "Architecture & Code Quality", SubCategory: "Documentation", Points: 3, Criteria: "manual", Description: "README + runbook + config docs"},

		ScoringMatrixEntry{TestID: "UI-01", Category: "Dashboard UI/UX", SubCategory: "Live Attack Feed", Points: 2, Criteria: "manual", Description: "Real-time attack visualization"},
		ScoringMatrixEntry{TestID: "UI-02", Category: "Dashboard UI/UX", SubCategory: "Hot Config Controls", Points: 2, Criteria: "manual", Description: "In-dashboard config/rule toggle"},
		ScoringMatrixEntry{TestID: "UI-03", Category: "Dashboard UI/UX", SubCategory: "Real-time Log Readability", Points: 1, Criteria: "binary", Description: "Readable live log stream"},
		ScoringMatrixEntry{TestID: "UI-04", Category: "Dashboard UI/UX", SubCategory: "Observability Headers", Points: 5, Criteria: "1 point per header", Description: "X-WAF-* header coverage"},

		ScoringMatrixEntry{TestID: "DEP-01", Category: "Deployment & Operability", SubCategory: "Single Binary + Startup", Points: 2, Criteria: "manual", Description: "Single command startup"},
		ScoringMatrixEntry{TestID: "DEP-02", Category: "Deployment & Operability", SubCategory: "Configurable Fail-mode", Points: 2, Criteria: "binary", Description: "Per-tier fail-close/fail-open config + behavior"},
		ScoringMatrixEntry{TestID: "DEP-03", Category: "Deployment & Operability", SubCategory: "Audit Log Format", Points: 1, Criteria: "binary", Description: "Audit log conforms to contract"},
	)

	for _, entry := range sm.Entries {
		sm.ByID[entry.TestID] = entry
	}

	return sm
}

// GetTotalPossiblePoints returns the maximum possible score
func (sm *ScoringMatrix) GetTotalPossiblePoints() float64 {
	total := 0.0
	for _, entry := range sm.Entries {
		total += entry.Points
	}
	return total
}

// GetCategoryBreakdown returns points breakdown by category
func (sm *ScoringMatrix) GetCategoryBreakdown() map[string]float64 {
	breakdown := make(map[string]float64)
	for _, entry := range sm.Entries {
		breakdown[entry.Category] += entry.Points
	}
	return breakdown
}
