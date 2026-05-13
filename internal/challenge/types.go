package challenge

import (
	"net/http"
	"time"
)

// ── Challenge Detection ──

// ChallengeInfo holds parsed challenge data from a WAF 429 response.
type ChallengeInfo struct {
	Format         string // "json" or "html"
	ChallengeToken string // extracted challenge_token
	SubmitURL      string // extracted submit_url (absolute or relative)
	SubmitMethod   string // "POST" (default) or from JSON field
	RawBody        string // original response body for logging
}

// ── Challenge Solving ──

// SolveResult holds the outcome of solving one challenge.
type SolveResult struct {
	// Parsing
	ParseSuccess bool
	ParseError   string
	ChallengeInfo *ChallengeInfo

	// Submit
	SubmitStatusCode int
	SubmitSuccess    bool
	SubmitError      string
	SubmitBody       string

	// Session extraction
	SessionExtracted   bool
	SessionCookieName  string
	SessionCookieValue string
	SessionToken       string // from JSON body if present

	// Re-send original request
	ResendStatusCode int
	ResendSuccess    bool
	ResendWAFAction  string
	ResendBody       string

	// Timing
	LatencyMs float64
}

// ── Lifecycle Evaluation (per 429_challenge.md §4) ──

// LifecycleResult is the complete challenge lifecycle evaluation.
type LifecycleResult struct {
	TestID     string // which test triggered the challenge
	Phase      string // "A", "B", "C", "D", "E"
	Endpoint   string
	Method     string

	// BA01/BA02: Challenge body format checks
	BA01Passed bool // challenge body well-formed
	BA01Detail string
	BA02Passed bool // challenge body contains required fields
	BA02Detail string

	// Mandatory challenge
	MandatoryChallengeCheck bool   // challenge must be scored
	MandatoryPassed         bool
	MandatoryDetail         string

	// Session suspension (v2.9.1)
	SessionSuspensionCheck bool
	SessionSuspensionPassed bool
	SessionSuspensionDetail string
	OldSession              string // if applicable

	// Submit
	SubmitPassed bool
	SubmitDetail string
	SubmitStatusCode int

	// Session after submit
	NewSessionExtracted bool
	NewSessionValue     string

	// Access restore
	AccessRestored bool
	AccessRestoreDetail string
	ResendStatusCode int
	ResendWAFAction string

	// Overall
	OverallPassed bool
	FailCodes     []string // CL-F1, CL-F2, etc.
	Notes         []string

	// Timing
	DurationMs int64

	// Reproducibility
	SolveResult *SolveResult
}

// ── Challenge Accumulator (per-phase) ──

// PhaseChallengeSummary aggregates challenge results for one phase.
type PhaseChallengeSummary struct {
	Phase              string
	TotalChallenges    int
	PassedChallenges   int
	FailedChallenges   int
	SkippedChallenges  int
	LifecycleResults   []LifecycleResult
	BA01Passed         int
	BA02Passed         int
	MandatoryPassed    int
	SessionSuspension  int // total checks
	SessionSuspensionOK int
	SubmitOK           int
	AccessRestoredOK   int
}

// ── Cross-Phase Challenge Report ──

// CrossPhaseChallengeReport aggregates challenge results across all phases.
type CrossPhaseChallengeReport struct {
	GeneratedAt  time.Time
	Phases       []PhaseChallengeSummary
	TotalDetected int
	TotalPassed   int
	TotalFailed   int
}

// ── Challenge Solver Component ──

// Solver is the shared challenge-solving component used by all phases.
// It wraps an HTTP client, WAF URL, and timeout configuration.
type Solver struct {
	Client     *http.Client
	WAFBaseURL string
	TimeoutSec int
	Verbose    bool
	DryRun     bool

	// Accumulated results
	Results []LifecycleResult
}

// ── Per-phase hooks ──

// PhaseHookContext provides the context needed when a phase engine
// encounters a 429 challenge response and needs to hand off to the solver.
type PhaseHookContext struct {
	Phase            string
	TestID           string
	Method           string
	Endpoint         string
	RequestBody      string
	RequestHeaders   map[string]string
	StatusCode       int
	ResponseBody     string
	ResponseHeaders  map[string]string
	OldSession       string // existing session cookie value, if any
}
