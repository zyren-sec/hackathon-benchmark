package phaseb

import "time"

// ── Phase B Test Definition ──

// BTestCategory groups Phase B tests by category and maps to scoring criteria.
type BTestCategory struct {
	ID          string   // "brute_force", "relay", "behavioral", "transaction", "recon"
	Name        string   // Human-readable name
	Criterion   string   // "SEC-03", "INT-03", "INT-02", "INT-01", "SEC-03+SEC-04"
	MaxScore    float64  // Maximum points for this criterion
	Denominator int      // Number of tests in denominator
	IPRange     string   // "127.0.0.10–19" etc.
}

// BTest defines a single Phase B test case.
type BTest struct {
	ID             string            // AB01, AB02, ..., RE04
	Name           string            // Human-readable short name
	Category       string            // brute_force, relay, behavioral, transaction, recon
	Criterion      string            // SEC-03, INT-03, INT-02, INT-01, SEC-04
	Method         string            // GET, POST, PUT
	Endpoint       string            // Request path
	SourceIP       string            // Loopback alias IP for this test
	ExtraHeaders   map[string]string // Extra HTTP headers
	BodyTemplate   string            // %s substitution or raw body
	ContentType    string            // Request content type
	ExpectedAction string            // Expected WAF action: "block", "challenge", "rate_limit", "allow"
	RiskMin        int               // Minimum expected risk score
	RiskMax        int               // Maximum expected risk score
	Description    string            // Human-readable description
	PassCriterion  string            // Human-readable pass criterion
	NegativeControl bool             // Is this a negative control?
	NegControlDesc string            // Negative control description
	AbuseType      string            // brute, credential_stuffing, spray, relay, proxy, bot, fraud, recon, canary

	// For multi-request tests
	RequestCount   int               // Number of requests to send (e.g., 50 for brute force)
	RequestsPerBatch int             // Requests per batch
	BatchDelayMs   int               // Delay between batches in ms
	PayloadFile    string            // Path to payload file (e.g., credentials.txt)
	UseProxy       bool              // Whether to use SOCKS5 proxy
	IPFile         string            // Path to threat intel IP file

	// For behavioral tests
	SessionRequired bool
	TimingPattern   string            // "uniform", "zero_depth", "rapid"
	AuthUser        string            // Username for auto-login (alice, bob, charlie, testuser_N)
	AuthPassword    string            // Password for auto-login
	AuthOTP         string            // OTP code for auto-login
	NeedsAuth       bool              // Computed: true if endpoint requires auth (deposit, withdrawal, profile, settings)

	// For multi-step tests (TF02, TF03)
	SubSteps        []BTestSubStep    // Sequential sub-steps to execute

	// Reproduce script (curl/bash, self-contained, user can copy-paste)
	ReproduceScript string           // Bash script to reproduce this test
}

// BTestSubStep defines a sub-step in a multi-step fraud/behavioral test.
type BTestSubStep struct {
	Method      string // GET, POST, PUT
	Endpoint    string // Request path
	Body        string // Literal body (no %d substitution)
	ContentType string // Content-Type header
}

// ── Phase B Test Results ──

// BTestResult holds the result of a single Phase B test.
type BTestResult struct {
	TestID         string            // AB01, AB02, ...
	Name           string            // Human-readable name
	Category       string            // brute_force, relay, ...
	Criterion      string            // SEC-03, INT-03, ...
	SourceIP       string            // IP used for the test
	Method         string            // HTTP method
	Endpoint       string            // Request path
	Description    string            // Description
	PassCriterion  string            // What constitutes a pass
	NegativeControl bool
	AbuseType      string            // brute, credential_stuffing, spray, relay, proxy, bot, fraud, recon, canary

	// Execution results
	TotalRequests  int               // Total requests sent
	BlockedAt      int               // Request number where WAF blocked (-1 if never blocked)
	Passed         bool              // Overall test passed?
	FailReason     string            // Reason for failure
	Skipped        bool
	SkipReason     string

	// Sample requests/responses (first and last few)
	Requests       []BRequestResult  // Key requests for evidence

	// Metrics
	AvgLatencyMs   float64
	MaxLatencyMs   float64
	MinLatencyMs   float64
	MaxRiskScore   int
	MinRiskScore   int
	AvgRiskScore   float64
	RiskBaseline   int               // Baseline risk before test
	RiskDelta      int               // Max risk - baseline

	// Specific to test type
	InterventionPoint int            // AB: which attempt was blocked; RE01: which req

	// Reproduce script (from definition)
	ReproduceScript string           // Self-contained bash script to reproduce

	// Auth tracking (v2.6)
	AuthUsed      bool              // Whether authentication was performed
	SessionID     string            // Session ID used (sid cookie value, truncated for display)
	ResetBefore   bool              // Whether a reset was performed before this test
	ResetType     string            // "UPSTREAM+WAF" or ""
	CanaryResult      *CanaryResult  // RE04: canary test result
	LeakMarkers       []string       // RE03: leak markers found

	// Action persistence (F6: action flip-flop detection, §5.2)
	F6Violation          bool
	F6Details            string
	EscalationDetected   bool
	DeEscalationDetected bool

	// Rate-limit maintenance (BA04, RE02)
	RateLimitMaintained bool

	// Pass/Fail condition tracking (§5.2-5.3)
	PassConditions []string
	FailConditions []string

	// Challenge lifecycle (v2.9: P6 mandatory for BA01/BA02)
	ChallengeResult *ChallengeLifecycleSummary // nil if no challenge encountered

	// Negative control result (AR01, AR06)
	NegControlResult *NegControlResult

	// Action persistence detail (§5.2 F6 + §7.1)
	FirstBlockAt          int    // Request index where WAF first blocked
	ActionSequenceSummary string // e.g. "allow(1-7), rate_limit(8-50)"

	// Risk score progression (§7.1) — sampled key points
	RiskProgression []RiskProgressionPoint

	// Observability (§7.1 + Phụ lục A)
	Observability ObservabilityResult
}

// BRequestResult holds a single request's result within a Phase B test.
type BRequestResult struct {
	Index         int               // 1-based request index
	URL           string            // Full request URL
	Method        string            // HTTP method
	RequestBody   string            // Request body
	RequestHeaders map[string]string

	StatusCode    int               // HTTP status code
	LatencyMs     float64           // Response latency
	ResponseBody  string            // Response body (truncated)
	ResponseHeaders map[string]string

	WAFAction     string            // X-WAF-Action header
	RiskScore     int               // X-WAF-Risk-Score value
	Blocked       bool              // Was this request blocked?
	FailReason    string            // If request failed at HTTP level
	CurlCommand   string            // Ready-to-use curl command for reproduction
}

// CanaryResult holds RE04 canary test details.
type CanaryResult struct {
	Endpoints      []string          // Canary endpoints tested
	Results        map[string]int    // Endpoint → HTTP status
	AllBlocked     bool              // All 4 canaries blocked?
	FollowUpBlocked bool             // Follow-up request after canary blocked?
}

// ChallengeLifecycleSummary holds challenge lifecycle results for display/report (v2.9).
type ChallengeLifecycleSummary struct {
	Encountered     bool     // Was a 429 challenge encountered?
	Passed          bool     // Did the challenge lifecycle pass?
	Format          string   // "json" or "html"
	ChallengeToken  string   // Extracted challenge_token
	SubmitURL       string   // Extracted submit_url
	SubmitPassed    bool
	SessionExtracted bool
	AccessRestored  bool
	SessionSuspended bool   // F6a/F6b: old session properly suspended
	FailCodes       []string
	DurationMs      int64
}

// NegControlResult holds negative control results (AR01, AR06).
type NegControlResult struct {
	ExpectedAction string `json:"expected_action"`
	ActualAction   string `json:"actual_action"`
	ExpectedStatus int    `json:"expected_status"`
	ActualStatus   int    `json:"actual_status"`
	FalsePositive  bool   `json:"false_positive"`
	RiskExpected   int    `json:"risk_score_expected"`
	RiskActual     int    `json:"risk_score_actual"`
}

// RiskProgressionPoint is one sampled point in risk score timeline (§7.1).
type RiskProgressionPoint struct {
	Request int `json:"request"`
	Score   int `json:"score"`
}

// ObservabilityResult tracks which WAF headers are present/missing (§7.1 + Phụ lục A).
type ObservabilityResult struct {
	HeadersUsed    []string `json:"headers_used"`
	HeadersMissing []string `json:"headers_missing"`
	Score          float64  `json:"observability_score"` // 0.0–1.0
}

// ── Phase B Overall ──

// PhaseBResult is the complete Phase B run result.
type PhaseBResult struct {
	StartTime   time.Time
	EndTime     time.Time
	WAFTarget   string
	WAFMode     string

	// Pre-check
	PreCheckPassed  bool
	PreCheckAlive   int
	PreCheckTotal   int
	PreCheckWarning bool

	// AB negative control
	ABNegControlPassed bool

	// Reset sequence
	ResetSteps     []BResetStep
	ResetAllPassed bool

	// Category results
	Categories []BCategoryResult

	// All test results
	TestResults []BTestResult

	// Scoring
	Scores map[string]float64       // criterion → points
	TotalScore float64
	MaxScore   float64
}

// BResetStep represents one step in the 5-step reset sequence.
type BResetStep struct {
	StepNum    int
	Name       string
	Method     string
	URL        string
	StatusCode int
	Success    bool
	LatencyMs  float64
	Error      string
}

// BCategoryResult groups Phase B test results for display.
type BCategoryResult struct {
	CatID        string           // category ID
	Name         string           // Category name
	Criterion    string           // Scoring criterion
	MaxScore     float64          // Max points
	Denominator  int              // Total tests
	IPRange      string           // IP range for this category
	Tests        []BTestResult    // Test results in this category
	PassedCount  int              // Number of passed tests
	TotalCount   int              // Total tests in category
	Score        float64          // Computed score for this criterion
}

// ── Report Types ──

// PhaseBReport is the top-level JSON report structure.
type PhaseBReport struct {
	Phase         string              `json:"phase"`
	Timestamp     string              `json:"timestamp"`
	WAFTarget     string              `json:"waf_target"`
	WAFMode       string              `json:"waf_mode"`
	DurationMs    int64               `json:"duration_ms"`

	// Pre-check
	PreCheckPassed  bool              `json:"pre_check_passed"`
	PreCheckAlive   int               `json:"pre_check_alive"`
	PreCheckTotal   int               `json:"pre_check_total"`
	PreCheckWarning bool              `json:"pre_check_warning,omitempty"`

	// Reset sequence
	ResetSequence []BResetStepJSON    `json:"reset_sequence"`

	// Categories
	Categories    []BCatSummaryJSON   `json:"categories"`

	// Tests
	Tests         []BTestEntryJSON    `json:"tests"`

	// Scoring
	Scores        map[string]float64  `json:"scores"`
	TotalScore    float64             `json:"total_score"`
	MaxScore      float64             `json:"max_score"`
}

// BCatSummaryJSON is a category summary for JSON export.
type BCatSummaryJSON struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Criterion  string  `json:"criterion"`
	MaxScore   float64 `json:"max_score"`
	IPRange    string  `json:"ip_range"`
	Passed     int     `json:"passed"`
	Total      int     `json:"total"`
	Score      float64 `json:"score"`
}

// BTestEntryJSON is one test entry for JSON export.
type BTestEntryJSON struct {
	TestID         string              `json:"test_id"`
	Name           string              `json:"name"`
	Category       string              `json:"category"`
	Criterion      string              `json:"criterion"`
	SourceIP       string              `json:"source_ip"`
	Endpoint       string              `json:"endpoint"`
	Method         string              `json:"method"`
	Description    string              `json:"description"`
	PassCriterion  string              `json:"pass_criterion"`
	NegativeControl bool               `json:"negative_control,omitempty"`
	TotalRequests  int                 `json:"total_requests"`
	BlockedAt      int                 `json:"blocked_at"`
	Passed         bool                `json:"passed"`
	FailReason     string              `json:"fail_reason,omitempty"`
	Skipped        bool                `json:"skipped,omitempty"`
	SkipReason     string              `json:"skip_reason,omitempty"`
	Result         string              `json:"result"`

	// Metrics
	AvgLatencyMs   float64             `json:"avg_latency_ms"`
	MaxLatencyMs   float64             `json:"max_latency_ms"`
	MaxRiskScore   int                 `json:"max_risk_score"`
	AvgRiskScore   float64             `json:"avg_risk_score"`
	RiskBaseline   int                 `json:"risk_baseline"`
	RiskDelta      int                 `json:"risk_delta"`
	InterventionPoint int              `json:"intervention_point,omitempty"`

	// Auth tracking
	AuthUsed      bool                `json:"auth_used,omitempty"`
	SessionID     string              `json:"session_id,omitempty"`
	ResetBefore   bool                `json:"reset_before,omitempty"`
	ResetType     string              `json:"reset_type,omitempty"`

	// Action persistence (F6: action flip-flop detection, §5.2)
	F6Violation        bool   `json:"f6_violation,omitempty"`
	F6Details          string `json:"f6_details,omitempty"`
	EscalationDetected bool   `json:"escalation_detected,omitempty"`
	DeEscalationDetected bool `json:"de_escalation_detected,omitempty"`

	// Rate-limit maintenance (BA04, RE02)
	RateLimitMaintained bool `json:"rate_limit_maintained,omitempty"`

	// Action persistence detail (§7.1)
	FirstBlockAt           int    `json:"first_block_at,omitempty"`
	ActionSequenceSummary  string `json:"action_sequence_summary,omitempty"`

	// Risk score progression (§7.1)
	RiskProgression []RiskProgressionPointJSON `json:"risk_progression,omitempty"`

	// Observability (§7.1)
	Observability *ObservabilityResultJSON `json:"observability,omitempty"`

	// Pass/Fail condition tracking (§5.2-5.3)
	PassConditions []string `json:"pass_conditions_met,omitempty"`
	FailConditions []string `json:"fail_conditions_triggered,omitempty"`

	// Challenge lifecycle (v2.9: P6 mandatory for BA01/BA02)
	ChallengeResult *ChallengeLifecycleSummary `json:"challenge_result,omitempty"`

	// Sample requests
	SampleRequests []BReqSampleJSON    `json:"sample_requests"`

	// Canary
	CanaryResult   *CanaryResultJSON   `json:"canary_result,omitempty"`

	// Negative control result
	NegControlResult *NegControlResultJSON `json:"negative_control_result,omitempty"`

	// Reproduce
	ReproduceScript string             `json:"reproduce_script,omitempty"`

	// Leak markers
	LeakMarkers    []string            `json:"leak_markers,omitempty"`
}

// BReqSampleJSON is a sample request for JSON export.
type BReqSampleJSON struct {
	Index           int                 `json:"index"`
	URL             string              `json:"url"`
	Method          string              `json:"method"`
	RequestBody     string              `json:"request_body,omitempty"`
	RequestHeaders  map[string]string   `json:"request_headers,omitempty"`
	StatusCode      int                 `json:"status_code"`
	LatencyMs       float64             `json:"latency_ms"`
	ResponseBody    string              `json:"response_body,omitempty"`
	ResponseHeaders map[string]string   `json:"response_headers,omitempty"`
	WAFAction       string              `json:"waf_action,omitempty"`
	RiskScore       int                 `json:"risk_score"`
	Blocked         bool                `json:"blocked"`
	CurlCommand     string              `json:"curl_command,omitempty"`
}

// CanaryResultJSON for RE04 export.
type CanaryResultJSON struct {
	Endpoints       []string            `json:"endpoints"`
	Results         map[string]int      `json:"results"`
	AllBlocked      bool                `json:"all_blocked"`
	FollowUpBlocked bool                `json:"follow_up_blocked"`
}

// NegControlResultJSON for AR01/AR06 export.
type NegControlResultJSON struct {
	ExpectedAction string `json:"expected_action"`
	ActualAction   string `json:"actual_action"`
	ExpectedStatus int    `json:"expected_status"`
	ActualStatus   int    `json:"actual_status"`
	FalsePositive  bool   `json:"false_positive"`
	RiskExpected   int    `json:"risk_score_expected"`
	RiskActual     int    `json:"risk_score_actual"`
}

// RiskProgressionPointJSON for risk score timeline export (§7.1).
type RiskProgressionPointJSON struct {
	Request int `json:"request"`
	Score   int `json:"score"`
}

// ObservabilityResultJSON for observability export (§7.1).
type ObservabilityResultJSON struct {
	HeadersUsed    []string `json:"headers_used"`
	HeadersMissing []string `json:"headers_missing"`
	Score          float64  `json:"observability_score"`
}

// BResetStepJSON for JSON export.
type BResetStepJSON struct {
	Step       int    `json:"step"`
	Name       string `json:"name"`
	StatusCode int    `json:"status_code"`
	Success    bool   `json:"success"`
	LatencyMs  float64 `json:"latency_ms"`
}

// ── Threat Category Map for Phase B ──

// BCategories maps category IDs to their metadata.
var BCategories = map[string]BTestCategory{
	"brute_force": {
		ID:          "brute_force",
		Name:        "Brute Force & Credential Attacks",
		Criterion:   "SEC-03",
		MaxScore:    10.0,
		Denominator: 3,
		IPRange:     "127.0.0.10–19",
	},
	"relay": {
		ID:          "relay",
		Name:        "Relay & Proxy Detection",
		Criterion:   "INT-03",
		MaxScore:    4.0,
		Denominator: 4, // v2.9: AR04/AR05 removed → 4 tests (AR01-AR03, AR06)
		IPRange:     "127.0.0.20–23",
	},
	"behavioral": {
		ID:          "behavioral",
		Name:        "Behavioral Anomaly",
		Criterion:   "INT-02",
		MaxScore:    4.0,
		Denominator: 5,
		IPRange:     "127.0.0.40–59",
	},
	"transaction": {
		ID:          "transaction",
		Name:        "Transaction Fraud",
		Criterion:   "INT-01",
		MaxScore:    4.0,
		Denominator: 4,
		IPRange:     "127.0.0.60–79",
	},
	"recon": {
		ID:          "recon",
		Name:        "Recon & Enumeration",
		Criterion:   "SEC-03+SEC-04",
		MaxScore:    10.0 + 2.0,
		Denominator: 4,
		IPRange:     "127.0.0.80–99",
	},
}

// Scoring formulas per phase_B.md v2.9 §6:
// SEC-03 = 10 × (pass_AB + pass_RE) / 6   (AB01-AB03: 3 + RE01-RE03: 3 = 6 tests)
// SEC-04 =  2 × (all 4 canaries blocked AND follow-up locked ? 1 : 0)
// INT-01 =  4 × pass_TF / 4
// INT-02 =  4 × pass_BA / 5
// INT-03 =  4 × pass_AR / 4  (v2.9: AR04/AR05 removed → 4 tests: AR01-AR03, AR06)
