package phasee

import "time"

// ── Phase E Core Types ──

// PhaseEResult is the complete Phase E run result.
type PhaseEResult struct {
	StartTime time.Time
	EndTime   time.Time
	WAFTarget string
	WAFMode   string

	// Pre-flight health checks
	WAFAlive      bool
	UpstreamAlive bool

	// Config detection
	ConfigFormat       string
	ConfigPath         string
	ConfigDetected     bool
	ConfigDetectError  string

	// Reset sequence
	ResetSteps     []EResetStep
	ResetAllPassed bool

	// Test results (in execution order)
	TestResults []ETestResult

	// Scoring
	EXT01Score float64
	EXT02Score float64
	EXT03Score float64
	EXT03SubScores map[string]float64 // E01, E02, E03, E04
	TotalScore float64
	MaxScore   float64
	PassedTests int
	FailedTests int
	SkippedTests int
}

// EResetStep represents one step in the Phase E reset sequence.
type EResetStep struct {
	StepNum    int
	Name       string
	Method     string
	URL        string
	StatusCode int
	Success    bool
	LatencyMs  float64
	Error      string
}

// ETestCategory groups Phase E tests by category.
type ETestCategory struct {
	ID        string
	Name      string
	Criterion string
}

// ETest defines a single Phase E test case.
type ETest struct {
	ID           string
	Name         string
	Category     string
	Criterion    string
	MaxScore     float64
	Description  string
	PassCriterion string
	FailReasons  map[string]string

	// Test parameters
	SourceIP    string
	Method      string
	Endpoint    string
	RequestBody string
	ReqHeaders  map[string]string
	DurationSec int
	WaitSec     int

	// Hot-reload parameters (EXT-01, EXT-02)
	HotReload    bool
	ConfigAction string // "add" or "remove"
	RuleTemplate string

	// Cache test parameters (EXT-03)
	CacheTest       bool
	CacheSubID      string // E01, E02, E03, E04
	ExpectedCache   string // "HIT", "MISS", or "" for not applicable
	ExpectedStatus  int
	ExpectedAction  string
	AuthRequired    bool

	// Verification
	VerifyRoutes []EVerifyRoute

	// Reproduce script
	ReproduceScript string
}

// EVerifyRoute defines a verification route for cache/hot-reload tests.
type EVerifyRoute struct {
	Method         string
	Endpoint       string
	ExpectedCode   int
	ExpectedCache  string
	Tier           string
	Description    string
	WithAuth       bool
}

// ── Test Results ──

// ETestResult holds the result of a single Phase E test.
type ETestResult struct {
	TestID        string
	Name          string
	Category      string
	Criterion     string
	Description   string
	PassCriterion string
	MaxScore      float64

	Passed  bool
	Skipped bool
	SkipReason string
	FailReason string
	FailConditions []EFailCondition

	// Hot-reload metrics
	ConfigModified     bool
	ConfigRestored     bool
	HotReloadSLAOk    bool
	HotReloadLatencyMs float64

	// Cache test metrics (EXT-03)
	CacheResults    []ECacheCheckResult

	// Verification
	VerifyResults  []EVerifyRouteResult
	VerifyPassed   bool

	// Duration
	DurationSec float64

	// Scoring
	ScoringExplain  string
	Score           float64
	EXT03SubScores  map[string]float64 // E01, E02, E03, E04

	// Reproduce script
	ReproduceScript string
}

// EFailCondition represents a condition checked for PASS/FAIL.
type EFailCondition struct {
	ID          string
	Description string
	Triggered   bool
	Evidence    string
}

// ECacheCheckResult holds the result of one cache check.
type ECacheCheckResult struct {
	RequestNum    int
	Endpoint      string
	Method        string
	StatusCode    int
	CacheHeader   string
	ExpectedCache string
	MatchExpected bool
	LatencyMs     float64
	WAFAction     string
	RiskScore     int
	ResponseBody  string
	CurlCommand   string
}

// EVerifyRouteResult is the result of verifying one route.
type EVerifyRouteResult struct {
	Method       string
	Endpoint     string
	StatusCode   int
	LatencyMs    float64
	WAFCache     string
	WAFAction    string
	RiskScore    int
	Passed       bool
	ExpectedCode int
	ExpectedCache string
	FailReason   string
	ResponseBody string
	CurlCommand  string
	Tier         string
}

// ── JSON Report Types ──

type PhaseEReport struct {
	Phase              string             `json:"phase"`
	Timestamp          string             `json:"timestamp"`
	WAFTarget          string             `json:"waf_target"`
	WAFMode            string             `json:"waf_mode"`
	DurationMs         int64              `json:"duration_ms"`

	PreCheckPassed  bool `json:"precheck_passed"`
	WAFAlive        bool `json:"waf_alive"`
	UpstreamAlive   bool `json:"upstream_alive"`

	ConfigFormat      string `json:"config_format"`
	ConfigPath        string `json:"config_path"`
	ConfigDetected    bool   `json:"config_detected"`

	ResetSequence   []EResetStepJSON    `json:"reset_sequence"`
	ResetAllPassed  bool                `json:"reset_all_passed"`

	Categories      []ECategorySummaryJSON `json:"categories"`
	Tests           []ETestEntryJSON       `json:"tests"`

	// Scoring
	EXT01Score   float64            `json:"ext01_score"`
	EXT01Max     float64            `json:"ext01_max"`
	EXT01Manual  bool               `json:"ext01_manual"`
	EXT02Score   float64            `json:"ext02_score"`
	EXT02Max     float64            `json:"ext02_max"`
	EXT02Manual  bool               `json:"ext02_manual"`
	EXT03Score   float64            `json:"ext03_score"`
	EXT03Max     float64            `json:"ext03_max"`
	EXT03SubScores map[string]float64 `json:"ext03_sub_scores"`
	TotalScore   float64            `json:"total_score"`
	MaxScore     float64            `json:"max_score"`

	PassedTests      int                 `json:"passed_tests"`
	FailedTests      int                 `json:"failed_tests"`
	SkippedTests     int                 `json:"skipped_tests"`
	PassRate         float64             `json:"pass_rate"`

	ScoringBreakdown []EScoringBreakdownJSON `json:"scoring_breakdown"`
	ScoringMap       EScoringMapJSON         `json:"scoring_map"`
	ScoringMethodology string                 `json:"scoring_methodology"`
}

type EResetStepJSON struct {
	Step       int     `json:"step"`
	Name       string  `json:"name"`
	StatusCode int     `json:"status_code"`
	Success    bool    `json:"success"`
	LatencyMs  float64 `json:"latency_ms"`
}

type ECategorySummaryJSON struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Criterion string  `json:"criterion"`
	Passed    int     `json:"passed"`
	Total     int     `json:"total"`
	Score     float64 `json:"score"`
	MaxScore  float64 `json:"max_score"`
}

type ETestEntryJSON struct {
	TestID          string             `json:"test_id"`
	Name            string             `json:"name"`
	Category        string             `json:"category"`
	Criterion       string             `json:"criterion,omitempty"`
	Description     string             `json:"description"`
	PassCriterion   string             `json:"pass_criterion"`
	MaxScore        float64            `json:"max_score"`
	Result          string             `json:"result"`
	Score           float64            `json:"score"`
	Passed          bool               `json:"passed"`
	Skipped         bool               `json:"skipped"`
	SkipReason      string             `json:"skip_reason,omitempty"`
	FailReason      string             `json:"fail_reason,omitempty"`
	FailConditions  []EFailCondJSON    `json:"fail_conditions,omitempty"`
	DurationSec     float64            `json:"duration_sec"`
	ScoringExplain  string             `json:"scoring_explain"`

	// Hot-reload metrics
	ConfigModified      bool    `json:"config_modified,omitempty"`
	ConfigRestored      bool    `json:"config_restored,omitempty"`
	HotReloadSLAOk      bool    `json:"hot_reload_sla_ok,omitempty"`
	HotReloadLatencyMs  float64 `json:"hot_reload_latency_ms,omitempty"`

	// Cache check results
	CacheResults    []ECacheCheckResultJSON `json:"cache_results,omitempty"`

	// Verification
	VerifyResults  []EVerifyRouteResultJSON `json:"verify_results,omitempty"`

	// Reproduce script
	ReproduceScript string `json:"reproduce_script,omitempty"`
}

type EFailCondJSON struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Triggered   bool   `json:"triggered"`
	Evidence    string `json:"evidence,omitempty"`
}

type ECacheCheckResultJSON struct {
	RequestNum    int     `json:"request_num"`
	Endpoint      string  `json:"endpoint"`
	Method        string  `json:"method"`
	StatusCode    int     `json:"status_code"`
	CacheHeader   string  `json:"cache_header"`
	ExpectedCache string  `json:"expected_cache"`
	MatchExpected bool    `json:"match_expected"`
	LatencyMs     float64 `json:"latency_ms"`
	WAFAction     string  `json:"waf_action"`
	RiskScore     int     `json:"risk_score"`
	CurlCommand   string  `json:"curl_command,omitempty"`
}

type EVerifyRouteResultJSON struct {
	Method        string  `json:"method"`
	Endpoint      string  `json:"endpoint"`
	StatusCode    int     `json:"status_code"`
	LatencyMs     float64 `json:"latency_ms"`
	WAFCache      string  `json:"waf_cache"`
	WAFAction     string  `json:"waf_action"`
	RiskScore     int     `json:"risk_score"`
	Passed        bool    `json:"passed"`
	ExpectedCode  int     `json:"expected_code"`
	ExpectedCache string  `json:"expected_cache"`
	FailReason    string  `json:"fail_reason,omitempty"`
	CurlCommand   string  `json:"curl_command,omitempty"`
	Tier          string  `json:"tier"`
}

type EScoringBreakdownJSON struct {
	TestID      string  `json:"test_id"`
	Name        string  `json:"name"`
	MaxScore    float64 `json:"max_score"`
	Passed      bool    `json:"passed"`
	Skipped     bool    `json:"skipped"`
	ScoreEarned float64 `json:"score_earned"`
	SubScores   map[string]float64 `json:"sub_scores,omitempty"`
}

type EScoringMapJSON struct {
	Criterion   string `json:"criterion"`
	Description string `json:"description"`
	MaxPoints   int    `json:"max_points"`
	Formula     string `json:"formula"`
}

// ── Category Map ──

var ECategories = map[string]ETestCategory{
	"hot_reload": {
		ID:        "hot_reload",
		Name:      "Hot-Reload Rules",
		Criterion: "EXT",
	},
	"caching": {
		ID:        "caching",
		Name:      "Caching Correctness",
		Criterion: "EXT",
	},
}

var ECategoryOrder = []string{"hot_reload", "caching"}

// ── Scoring Map ──

const ScoringMapDoc = `EXT — Extensibility (10 pts max, 4 pts automated)

Scoring Methodology (per phase_E.md v2.5 §1):

  EXT-01 — Hot-reload Add Rule    : 3 pts — MANUAL (evaluated by BTC during demo/live)
  EXT-02 — Hot-reload Remove Rule  : 3 pts — MANUAL (evaluated by BTC during demo/live)
  EXT-03 — Caching Correctness     : 4 pts — AUTOMATED (1 pt per sub-test E01–E04)

  Automated Total = EXT-03 = 4 pts
  Full Total (automated + manual) = 10 pts

  EXT-03 Sub-Tests:
    E01 — STATIC route cached (HIT)           : 1 pt
    E02 — CRITICAL route NOT cached            : 1 pt
    E03 — STATIC TTL expiry                     : 1 pt
    E04 — Authenticated route NOT cached        : 1 pt

  NOTE: EXT-01 and EXT-02 are NOT run by the benchmark tool.
  They are evaluated manually by BTC during demo/live evaluation.
  Only EXT-03 is automated in this version.`

// ── Required Headers ──

var RequiredHeaders = []string{
	"X-WAF-Request-Id",
	"X-WAF-Risk-Score",
	"X-WAF-Action",
	"X-WAF-Rule-Id",
	"X-WAF-Mode",
	"X-WAF-Cache",
}

// ── Config Template ──

const YamlRuleTemplate = `- id: "benchmark-hotreload-test"
  match:
    path: "/test-hotreload-path"
  action: "block"
  priority: 1`

const TomlRuleTemplate = `[[rules]]
id = "benchmark-hotreload-test"
action = "block"
priority = 1

[rules.match]
path = "/test-hotreload-path"`

// ── Route Tier Reference ──

var STATICCacheRoutes = []EVerifyRoute{
	{Method: "GET", Endpoint: "/static/js/app.js", ExpectedCode: 200, ExpectedCache: "HIT", Tier: "STATIC", Description: "Static JS (STATIC tier)"},
}

var CRITICALNoCacheRoutes = []EVerifyRoute{
	{Method: "POST", Endpoint: "/login", ExpectedCode: 200, ExpectedCache: "", Tier: "CRITICAL", Description: "Login (CRITICAL tier, no cache expected)"},
}

var AuthNoCacheRoutes = []EVerifyRoute{
	{Method: "GET", Endpoint: "/api/profile", ExpectedCode: 200, ExpectedCache: "", Tier: "MEDIUM", Description: "Profile (auth required, no cache)", WithAuth: true},
}
