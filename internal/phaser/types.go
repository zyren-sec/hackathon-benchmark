package phaser

import "time"

// ── Phase R Core Types ──
// Implements SEC-05 (Risk Score Lifecycle) per docs/hackathon/workflow/phase_R.md

// RConfigWrapper holds Phase R engine configuration.
type RConfigWrapper struct {
	TargetBaseURL string
	WAFBaseURL    string
	WAFAdminURL   string
	ControlSecret string
	TimeoutSec    int
	Verbose       bool
	DryRun        bool
}

// DeviceSignature represents a device fingerprint (UA + Accept-Language).
type DeviceSignature struct {
	Name           string // "D1" or "D2"
	UserAgent      string
	AcceptLanguage string
}

// Device signatures per phase_R.md §4
var (
	DeviceD1 = DeviceSignature{
		Name:           "D1",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		AcceptLanguage: "en-US,en;q=0.9",
	}
	DeviceD2 = DeviceSignature{
		Name:           "D2",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		AcceptLanguage: "fr-FR,fr;q=0.9",
	}
)

// Source IPs per phase_R.md §1.1 — fresh loopback aliases not used in other phases
const (
	IPSteps1to3 = "127.0.0.200" // Steps 1–3: baseline → attack → canary
	IPStep4     = "127.0.0.201" // Step 4: device fingerprint carry-over (new IP, same device)
	IPSteps5to7 = "127.0.0.202" // Steps 5–7: decay → challenge → recovery
)

// ── Reset Step ──

// RResetStep represents one step in the Phase R Full Reset Sequence (§3.1).
type RResetStep struct {
	StepNum    int
	Name       string
	Method     string
	URL        string
	StatusCode int
	Success    bool
	LatencyMs  float64
	Error      string
	Fatal      bool
}

// ── Step Result ──

// StepResult holds the result of one Phase R step (Steps 1–7).
type StepResult struct {
	Step        int
	Description string
	SourceIP    string
	Device      string // "D1" or "D2"

	// Request details
	Method   string
	Endpoint string

	// Observed WAF response
	ObservedScore  int
	ObservedAction string
	HTTPStatus     int
	LatencyMs      float64

	// Expected ranges
	ExpectedScoreMin int
	ExpectedScoreMax int // -1 means exact match (e.g. 100)
	ExpectedActions  []string

	// Decay trajectory (Step 5 only)
	DecayTrajectory []DecayPoint

	// Challenge details (Steps 6–7)
	ChallengeIssued     bool
	ChallengeType       string // "proof_of_work" or "html_form"
	ChallengeToken      string
	ChallengeDiff       int
	ChallengeSubmitURL  string
	ChallengeSolved     bool
	ChallengeNonce      string
	ChallengeSolveMs    float64
	ChallengeSkipReason string // "challenge_timeout", "challenge_too_hard", "challenge_unsolvable", "challenge_submit_failed", "score_not_reduced"

	// Pass/Fail
	Pass       bool
	Skipped    bool
	SkipReason string
	FailReason string

	// Scoring
	MaxPts int
	Pts    int
}

// DecayPoint is one observation during Step 5 decay monitoring.
type DecayPoint struct {
	RequestNum int
	RiskScore  int
	Action     string
	HTTPStatus int
	LatencyMs  float64
}

// ── Phase R Result ──

// PhaseRResult is the complete Phase R run result.
type PhaseRResult struct {
	StartTime time.Time
	EndTime   time.Time
	WAFTarget string
	WAFMode   string

	// Pre-flight
	WAFAlive      bool
	UpstreamAlive bool

	// Reset sequence
	ResetSteps     []RResetStep
	ResetAllPassed bool

	// Step results (Steps 1–7)
	StepResults []StepResult

	// SEC-05 scoring
	SEC05Score float64
	SEC05Max   float64 // always 8.0

	// Challenge details (Step 7)
	ChallengeSolved  bool
	ChallengeType    string
	ChallengeToken   string
	ChallengeNonce   string
	ChallengeSolveMs float64

	// Duration
	DurationMs float64

	// Counts
	PassedSteps  int
	FailedSteps  int
	SkippedSteps int
}

// ── JSON Report Types ──

// PhaseRReport is the JSON report structure.
type PhaseRReport struct {
	Phase     string    `json:"phase"`
	Timestamp time.Time `json:"timestamp"`
	WAFTarget string    `json:"waf_target"`
	WAFMode   string    `json:"waf_mode"`

	SourceIPs struct {
		Steps1to3 string `json:"steps_1_3"`
		Step4     string `json:"step_4"`
		Steps5to7 string `json:"steps_5_7"`
	} `json:"source_ips"`

	DeviceSignatures struct {
		D1 DeviceSig `json:"D1"`
		D2 DeviceSig `json:"D2"`
	} `json:"device_signatures"`

	ResetSequence []RResetStepReport `json:"reset_sequence"`
	ResetPassed   bool               `json:"reset_passed"`

	Steps []StepReport `json:"steps"`

	ChallengeSolved  bool    `json:"challenge_solved"`
	ChallengeType    string  `json:"challenge_type,omitempty"`
	ChallengeToken   string  `json:"challenge_token,omitempty"`
	ChallengeNonce   string  `json:"challenge_nonce,omitempty"`
	ChallengeSolveMs float64 `json:"challenge_solve_ms,omitempty"`

	SEC05Score float64 `json:"sec05_score"`
	SEC05Max   float64 `json:"sec05_max"`
	DurationMs float64 `json:"duration_ms"`
}

// DeviceSig is the JSON representation of a device signature.
type DeviceSig struct {
	UA         string `json:"ua"`
	AcceptLang string `json:"accept_lang"`
}

// RResetStepReport is the JSON representation of a reset step.
type RResetStepReport struct {
	Step       int     `json:"step"`
	Name       string  `json:"name"`
	Method     string  `json:"method"`
	URL        string  `json:"url"`
	StatusCode int     `json:"status_code"`
	Success    bool    `json:"success"`
	LatencyMs  float64 `json:"latency_ms"`
	Error      string  `json:"error,omitempty"`
}

// StepReport is the JSON representation of one step result.
type StepReport struct {
	Step               int          `json:"step"`
	Description        string       `json:"description"`
	SourceIP           string       `json:"source_ip"`
	Device             string       `json:"device"`
	ExpectedAction     string       `json:"expected_action"`
	ObservedAction     string       `json:"observed_action"`
	ObservedScore      int          `json:"observed_score"`
	ExpectedScoreRange string       `json:"expected_score_range"`
	Pass               bool         `json:"pass"`
	Skipped            bool         `json:"skipped,omitempty"`
	SkipReason         string       `json:"skip_reason,omitempty"`
	FailReason         string       `json:"fail_reason,omitempty"`
	Pts                int          `json:"pts"`
	MaxPts             int          `json:"max_pts"`
	DecayTrajectory    []DecayPoint `json:"decay_trajectory,omitempty"`
}
