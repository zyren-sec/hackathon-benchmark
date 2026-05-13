package phasea

import "time"

// ── Test Definition ──

// ThreatCategory groups V* tests by category and maps to decision matrix.
type ThreatCategory struct {
	Name          string   // e.g., "High-confidence injection"
	AcceptActions []string // e.g., ["block", "challenge"]
	StatusCodes   []int    // e.g., [403, 429]
}

// VulnTest defines a single V* test case.
type VulnTest struct {
	ID           string // V01, V02, ...
	Name         string // Human-readable short name
	Category     string // SQLi, XSS, PathTraversal, SSRF, etc.
	ThreatGroup  string // Maps to ThreatCategory.Name
	Method       string // GET, POST, PUT, DELETE
	Endpoint     string // Request path
	AuthRequired bool
	ProofMarker  string // e.g., "__V01_LOGIN_BYPASS__"
	Tier         string // CRITICAL, HIGH, MEDIUM
	RiskMin      int    // Minimum expected risk score
	RiskMax      int    // Maximum expected risk score
	Special      string // "" (normal), "v03_timing", "v05_stored", "v24_race"
	ContentType  string // Request content type
	Description  string // Human-readable description
	PayloadCat   string // Category for payload lookup (e.g., "sqli", "xss")
	ExtraHeaders map[string]string

	// BodyTemplate: %s = payload. Empty = send raw payload as-is.
	// e.g. `{"username":"%s","password":"x"}` for /login
	BodyTemplate string

	// QueryParam: for GET requests, append `?<QueryParam>=<url_encoded_payload>`
	// Empty = don't append query param.
	QueryParam string
}

// ── Payload ──

// Payload represents a single exploit payload with tier classification.
type Payload struct {
	Name        string
	RawPayload  string
	Category    string // sqli, xss, path_traversal, etc.
	Tier        string // basic, advanced, bypass
	Description string
	Severity    string
}

// ── Test Results ──

// VulnResult holds the result of testing a single V* vulnerability.
type VulnResult struct {
	VulnID       string
	Name         string
	Category     string
	Tier         string
	AuthRequired bool
	RiskMin      int
	RiskMax      int
	ProofMarker  string
	Special      string

	// Session
	AuthSuccess bool
	SessionID   string

	// Payload results (per-tier, one per payload tried)
	PayloadResults []PayloadResult

	// Overall
	OverallPassed bool
	PassCount     int
	FailCount     int
	SkipReason    string
	Skipped       bool
}

// PayloadResult is the outcome of sending one payload.
type PayloadResult struct {
	PayloadName string
	Payload     string
	Tier        string
	Index       int // 1-based index in display

	// Request (for reproducibility)
	RequestURL     string
	RequestMethod  string
	RequestBody    string
	RequestHeaders map[string]string
	FullRequest    string // Raw HTTP request string
	CurlCommand    string // Ready-to-use curl command

	// Response
	StatusCode      int
	LatencyMs       float64
	ResponseBody    string
	ResponseHeaders map[string]string

	// Decision analysis
	Passed         bool
	FailReason     string // "", "OWN MKR", "OTHER MKR", "MISSING HDR", "WRONG ACTION", "WRONG STATUS"
	MarkerFound    string // which marker was found, empty if none
	WAFAction      string // X-WAF-Action header value
	RiskScore      int    // X-WAF-Risk-Score value
	HasAllHeaders  bool   // all 6 required headers present
	ActionValid    bool   // action is in acceptable set
	StatusValid    bool   // status matches action
	ScoringExplain string // Human-readable explanation of why PASS/FAIL
}

// ── Phase A Overall ──

// PhaseAResult is the complete Phase A run result.
type PhaseAResult struct {
	StartTime time.Time
	EndTime   time.Time
	WAFTarget string
	WAFMode   string

	// Reset sequence
	ResetSteps     []ResetStep
	ResetAllPassed bool

	// Negative control
	NegControlSkipped bool
	NegControlReason  string

	// Category results (in display order)
	Categories []CategoryResult

	// All V* results
	VulnResults []VulnResult

	// Scoring
	TotalTests   int
	PassedTests  int
	FailedTests  int
	SEC01Score   float64
	RSBonusScore int
	RSBonusMax   int
}

// ResetStep represents one step in the 5-step reset sequence.
type ResetStep struct {
	StepNum    int
	Name       string
	Method     string
	URL        string
	StatusCode int
	Success    bool
	LatencyMs  float64
	Error      string
}

// CategoryResult groups V* results for display.
type CategoryResult struct {
	CatNum      int
	Title       string
	IDRange     string
	VulnResults []VulnResult
	PassedCount int
	TotalCount  int
}

// ── Threat Category Map ──

// ThreatCategories maps threat group names to their decision matrix.
var ThreatCategories = map[string]ThreatCategory{
	"High-confidence injection": {
		Name:          "High-confidence injection",
		AcceptActions: []string{"block", "challenge"},
		StatusCodes:   []int{403, 429},
	},
	"Blind / Timing-based injection": {
		Name:          "Blind / Timing-based injection",
		AcceptActions: []string{"block", "challenge"},
		StatusCodes:   []int{403, 429},
	},
	"Stored XSS": {
		Name:          "Stored XSS",
		AcceptActions: []string{"block", "challenge"},
		StatusCodes:   []int{403, 429},
	},
	"Path traversal": {
		Name:          "Path traversal",
		AcceptActions: []string{"block", "challenge"},
		StatusCodes:   []int{403, 429},
	},
	"Protocol/Header injection": {
		Name:          "Protocol/Header injection",
		AcceptActions: []string{"block", "challenge"},
		StatusCodes:   []int{403, 429},
	},
	"Input validation": {
		Name:          "Input validation",
		AcceptActions: []string{"block", "rate_limit"},
		StatusCodes:   []int{403, 429},
	},
	// V16 exception: Content-Type bypass uses block/challenge instead of block/rate_limit (§5.4)
	"Input validation ─ CT bypass": {
		Name:          "Input validation ─ CT bypass",
		AcceptActions: []string{"block", "challenge"},
		StatusCodes:   []int{403, 429},
	},
	"Supply chain / JNDI": {
		Name:          "Supply chain / JNDI",
		AcceptActions: []string{"block", "challenge"},
		StatusCodes:   []int{403, 429},
	},
	"Asymmetric DoS": {
		Name:          "Asymmetric DoS",
		AcceptActions: []string{"block", "rate_limit"},
		StatusCodes:   []int{403, 429},
	},
	"Access control bypass": {
		Name:          "Access control bypass",
		AcceptActions: []string{"block", "challenge"},
		StatusCodes:   []int{403, 429},
	},
	"Race condition": {
		Name:          "Race condition",
		AcceptActions: []string{"block", "challenge"},
		StatusCodes:   []int{403, 429},
	},
}

// ActionStatusMap maps WAF action to expected HTTP status.
var ActionStatusMap = map[string]int{
	"allow":           -1, // upstream response
	"block":           403,
	"challenge":       429,
	"rate_limit":      429,
	"timeout":         504,
	"circuit_breaker": 503,
}

// RequiredHeaders are the 6 mandatory WAF response headers per spec §5.1.
var RequiredHeaders = []string{
	"X-WAF-Request-Id",
	"X-WAF-Risk-Score",
	"X-WAF-Action",
	"X-WAF-Rule-Id",
	"X-WAF-Mode",
	"X-WAF-Cache",
}

// ── Report-specific types ──

// ReportEntry is one test entry for JSON/HTML reports.
type ReportEntry struct {
	VulnID       string          `json:"vuln_id"`
	Name         string          `json:"name"`
	Category     string          `json:"category"`
	Tier         string          `json:"tier"`
	AuthRequired bool            `json:"auth_required"`
	ProofMarker  string          `json:"proof_marker"`
	RiskRange    string          `json:"risk_range"`
	Special      string          `json:"special,omitempty"`
	Passed       bool            `json:"passed"`
	Skipped      bool            `json:"skipped"`
	SkipReason   string          `json:"skip_reason,omitempty"`
	AuthSuccess  bool            `json:"auth_success"`
	SessionID    string          `json:"session_id,omitempty"`
	Payloads     []ReportPayload `json:"payloads"`
	PassCount    int             `json:"pass_count"`
	FailCount    int             `json:"fail_count"`
	Result       string          `json:"result"`
	ResultReason string          `json:"result_reason,omitempty"`

	// Decision matrix for this V* test
	ThreatGroup     string             `json:"threat_group,omitempty"`
	AcceptActions   []string           `json:"accept_actions,omitempty"`
	AcceptStatuses  []int              `json:"accept_statuses,omitempty"`
	DecisionExplain string             `json:"decision_explain,omitempty"`
	ScoringCriteria []ScoringCriterion `json:"scoring_criteria,omitempty"`
}

// ScoringCriterion explains one scoring dimension.
type ScoringCriterion struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Satisfied   bool   `json:"satisfied"`
	Detail      string `json:"detail,omitempty"`
}

// ReportPayload is one payload result for reports.
type ReportPayload struct {
	Index        int               `json:"index"`
	Name         string            `json:"name"`
	Tier         string            `json:"tier"`
	Payload      string            `json:"payload"`
	StatusCode   int               `json:"status_code"`
	LatencyMs    float64           `json:"latency_ms"`
	Passed       bool              `json:"passed"`
	FailReason   string            `json:"fail_reason,omitempty"`
	MarkerFound  string            `json:"marker_found,omitempty"`
	WAFAction    string            `json:"waf_action,omitempty"`
	RiskScore    int               `json:"risk_score,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	ResponseBody string            `json:"response_body,omitempty"`

	// Reproducibility
	RequestURL     string            `json:"request_url,omitempty"`
	RequestMethod  string            `json:"request_method,omitempty"`
	RequestBody    string            `json:"request_body,omitempty"`
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
	FullRequest    string            `json:"full_request,omitempty"`
	CurlCommand    string            `json:"curl_command,omitempty"`

	// Scoring
	ScoringExplain string `json:"scoring_explanation,omitempty"`
	RiskRange      string `json:"risk_range,omitempty"`
	RiskInRange    bool   `json:"risk_in_range,omitempty"`
}

// PhaseAReport is the top-level JSON report structure.
type PhaseAReport struct {
	Phase                 string          `json:"phase"`
	Timestamp             string          `json:"timestamp"`
	WAFTarget             string          `json:"waf_target"`
	WAFMode               string          `json:"waf_mode"`
	PayloadTier           string          `json:"payload_tier"`
	ExploitPreventionRate float64         `json:"exploit_prevention_rate"`
	TotalExploits         int             `json:"total_exploits"`
	PassedExploits        int             `json:"passed_exploits"`
	FailedExploits        int             `json:"failed_exploits"`
	SEC01Score            float64         `json:"sec01_score"`
	SEC01Max              float64         `json:"sec01_max"`
	RSBonus               int             `json:"rs_bonus"`
	RSBonusMax            int             `json:"rs_bonus_max"`
	DurationMs            int64           `json:"duration_ms"`
	Exploits              []ReportEntry   `json:"exploits"`
	Categories            []CatSummary    `json:"categories"`
	ResetSequence         []ResetStepJSON `json:"reset_sequence"`
}

// CatSummary is a category summary for reports.
type CatSummary struct {
	Num    int    `json:"num"`
	Title  string `json:"title"`
	Passed int    `json:"passed"`
	Total  int    `json:"total"`
}

// ResetStepJSON is a reset step for JSON export.
type ResetStepJSON struct {
	Step       int     `json:"step"`
	Name       string  `json:"name"`
	StatusCode int     `json:"status_code"`
	Success    bool    `json:"success"`
	LatencyMs  float64 `json:"latency_ms"`
}
