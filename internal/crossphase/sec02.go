package crossphase

// SEC02Result holds the complete SEC-02 computation result (cross_phase.md §4.1–§4.2).
type SEC02Result struct {
	// Negative control verification
	NegativeControlPassed map[string]bool // L01-L05 → valid/invalid

	// Scan results
	TotalResponses  int
	CleanResponses  int
	LeakedResponses int

	// Rate and score
	GlobalFilterRate float64
	Score            float64
	MaxScore         float64 // always 5.0

	// Per-marker breakdown
	MarkerBreakdown map[string]MarkerStats
}

// MarkerStats holds per-marker statistics.
type MarkerStats struct {
	TotalMatches int
	Phases       []string // which phases this marker appeared in
}
