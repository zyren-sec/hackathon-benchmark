// Type Definitions for WAF Benchmark Phase A
// All shared types defined here for use across multiple files

package main

import (
	"time"
)

// TestID mapping from exploit_catalogue.md
type TestDefinition struct {
	ID          string
	Category    string
	Method      string
	Path        string
	Auth        bool
	Marker      string
	Severity    string
	Description string
	Payloads    []AdvancedPayload
}

// AdvancedPayload with bypass techniques
type AdvancedPayload struct {
	Name        string
	RawPayload  string
	Variants    []string // Encoded/Obfuscated versions
	Technique   string   // concat, unicode, comment, double_encode, etc.
	ContentType string
}

// TestResult with detailed information
type DetailedResult struct {
	TestID             string
	Category           string
	Method             string
	Path               string
	AuthRequired       bool
	PayloadUsed        string
	PayloadVariant     string
	Technique          string
	AttackMode         string
	CurlCommand        string
	RawRequest         string
	RawResponse        string
	ReproductionScript string
	ResponseStatus     int
	ResponseHeaders    map[string]string
	ResponseBody       string
	FullResponse       string
	MarkerExpected      string
	MainMarkerFound     bool
	MainMarkerLocation  string
	OtherMarkerFound    bool
	OtherMarker         string
	OtherMarkerLocation string
	MarkerFound         bool
	MarkerLocation      string // body, header, not_found
	MarkerFoundInBody   bool
	MarkerFoundInHeader bool
	MatchedMarker       string // actual matched marker (main or fallback)
	MarkerMatchType     string // main, fallback, none
	StatusCompliant     bool
	StatusEvidence     string
	Passed             bool
	Evidence           string
	Reason             string
	Score              float64
	MaxScore           float64
	DurationMs         int64
	Timestamp          time.Time
}

// TestSuite results
type TestSuiteResults struct {
	Target            string
	TargetProfile     string
	StartTime         time.Time
	EndTime           time.Time
	Results           []DetailedResult
	AuthSession       *AuthSession
	Summary           TestSummary
	ActiveModes       []string
	ExploitPayloads   map[string][]string
	ExploitBasePath   string
	ExploitCategories []string
}

type AuthSession struct {
	SID        string
	LoginToken string
	Username   string
	ObtainedAt time.Time
}

type TestSummary struct {
	TotalTests       int
	Passed           int
	Failed           int
	Skipped          int
	TotalScore       float64
	MaxPossibleScore float64
	Percentage       float64
	CategoryScores   map[string]CategoryScore
}

type CategoryScore struct {
	Category   string
	Passed     int
	Total      int
	Score      float64
	MaxScore   float64
	Percentage float64
}

// Scoring weights from scoring_matrix.csv
var ScoringWeights = map[string]float64{
	"V01-V19": 15.0, // SEC-01: Exploit Prevention
	"L01-L05": 5.0,  // SEC-02: Outbound Filtering
	"AB":      10.0, // SEC-03: Abuse Detection (split)
	"CANARY":  2.0,  // SEC-04: Canary Detection
}
