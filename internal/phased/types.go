package phased

import "time"

// ── Phase D Core Types ──

// PhaseDResult is the complete Phase D run result.
type PhaseDResult struct {
	StartTime time.Time
	EndTime   time.Time
	WAFTarget string
	WAFMode   string

	// Resource tier
	ResourceTier  string // "min", "mid", "full"
	CgroupsActive bool   // cgroups v2 isolation active

	// Diagnostic flags
	DiagnosticFlags []string // e.g., "RESOURCE_CONSTRAINED", "MEMORY_PRESSURE"
	ProfilerActive  bool

	// Pre-flight health checks
	WAFAlive      bool
	UpstreamAlive bool

	// Reset sequence
	ResetSteps     []DResetStep
	ResetAllPassed bool

	// Test results (in execution order)
	TestResults []DTestResult

	// Scoring
	RawScore    float64
	RawMaxScore float64
	INT04Score  float64
	INT04Cap    float64
	PassedTests int
	FailedTests int
	SkippedTests int
}

// DResetStep represents one step in the Phase D reset sequence (9 steps).
type DResetStep struct {
	StepNum    int
	Name       string
	Method     string
	URL        string
	StatusCode int
	Success    bool
	LatencyMs  float64
	Error      string
}

// DTestCategory groups Phase D tests by category.
type DTestCategory struct {
	ID        string
	Name      string
	Criterion string
}

// DTest defines a single Phase D test case.
type DTest struct {
	ID           string
	Name         string
	Category     string
	MaxScore     float64
	Description  string
	PassCriterion string
	FailReasons  map[string]string

	// Test parameters
	SourceIP    string
	Tool        string
	DurationSec int
	Connections int
	TargetRPS   int
	RouteTier   string

	// Post-flood verification
	VerifyBefore  bool
	VerifyDuring  bool
	VerifyAfter   bool
	VerifyRoutes  []DVerifyRoute

	// Backend control
	BackendDown bool
	BackendSlow bool
	DelayMs     int

	// WAF config control (D08, D09)
	ConfigChange bool
	ConfigKey    string
	ConfigValue  string

	// Reproduce script
	ReproduceScript string
}

// DVerifyRoute defines a verification route.
type DVerifyRoute struct {
	Method         string
	Endpoint       string
	ExpectedCode   int
	ExpectedAction string
	Tier           string
	Description    string
}

// ── Test Results ──

// DTestResult holds the result of a single Phase D test.
type DTestResult struct {
	TestID        string
	Name          string
	Category      string
	Description   string
	PassCriterion string
	MaxScore      float64

	Passed     bool
	Skipped    bool
	SkipReason string
	FailReason string

	// Tool output
	ToolStdout   string
	ToolStderr   string
	ToolExitCode int
	ToolSummary  string

	// Flood metrics
	ActualRPS       float64
	TransferSec     string
	SocketErrors    map[string]int
	LatencyAvgMs    float64
	LatencyStdevMs  float64
	LatencyMaxMs    float64
	LatencyP50Ms    float64
	LatencyP75Ms    float64
	LatencyP90Ms    float64
	LatencyP99Ms    float64

	// Slow test metrics
	ConnectionsOpen    int
	ConnectionsClosed  int
	ConnectionsError   int
	ConnectionsPending int
	ServiceAvailable   bool

	// Verification
	PreVerifyResults    []DVerifyRouteResult
	PreVerifyPassed     bool
	PostVerifyResults   []DVerifyRouteResult
	PostVerifyPassed    bool
	DuringVerifyResults []DVerifyRouteResult
	DuringVerifyPassed  bool

	// Tier results (D04)
	TierResults map[string]DTierResult

	// Circuit breaker / timeout
	CircuitBroken   bool
	TimeoutDetected bool
	WAFAction       string

	// Recovery
	Recovered       bool
	RecoveryResults []DVerifyRouteResult

	// Duration
	DurationSec float64

	// Scoring
	ScoringExplain string

	// Reproduce script
	ReproduceScript string
}

// DVerifyRouteResult is the result of verifying one route.
type DVerifyRouteResult struct {
	Method         string
	Endpoint       string
	StatusCode     int
	LatencyMs      float64
	WAFAction      string
	RiskScore      int
	Passed         bool
	ExpectedCode   int
	ExpectedAction string
	FailReason     string
	ResponseBody   string
	CurlCommand    string
	Tier           string
}

// DTierResult holds aggregate results for a route tier.
type DTierResult struct {
	Tier         string
	Routes       []DVerifyRouteResult
	TotalRoutes  int
	PassedRoutes int
	ExpectedCode int
	ExpectedMode string
	AllPassed    bool
	FailReason   string
}

// ── JSON Report Types ──

type PhaseDReport struct {
	Phase              string                  `json:"phase"`
	Timestamp          string                  `json:"timestamp"`
	WAFTarget          string                  `json:"waf_target"`
	WAFMode            string                  `json:"waf_mode"`

	// Diagnostic
	ResourceTier    string   `json:"resource_tier"`
	CgroupsActive   bool     `json:"cgroups_active"`
	DiagnosticFlags []string `json:"diagnostic_flags,omitempty"`
	ProfilerActive  bool     `json:"profiler_active"`

	DurationMs         int64                   `json:"duration_ms"`
	PreCheckPassed     bool                    `json:"pre_check_passed"`
	WAFAlive           bool                    `json:"waf_alive"`
	UpstreamAlive      bool                    `json:"upstream_alive"`
	ResetAllPassed     bool                    `json:"reset_all_passed"`
	RawScore           float64                 `json:"raw_score"`
	RawMaxScore        float64                 `json:"raw_max_score"`
	INT04Score         float64                 `json:"int04_score"`
	INT04Cap           float64                 `json:"int04_cap"`
	PassedTests        int                     `json:"passed_tests"`
	FailedTests        int                     `json:"failed_tests"`
	SkippedTests       int                     `json:"skipped_tests"`
	PassRate           float64                 `json:"pass_rate"`
	ResetSequence      []DResetStepJSON        `json:"reset_sequence"`
	Tests              []DTestEntryJSON        `json:"tests"`
	Categories         []DCategorySummaryJSON  `json:"categories"`
	ScoringBreakdown   []DScoringBreakdownJSON `json:"scoring_breakdown"`
	ScoringMap         DSScoringMapJSON        `json:"scoring_map"`
	ScoringMethodology string                  `json:"scoring_methodology"`
}

type DTestEntryJSON struct {
	TestID          string                       `json:"test_id"`
	Name            string                       `json:"name"`
	Category        string                       `json:"category"`
	Description     string                       `json:"description"`
	PassCriterion   string                       `json:"pass_criterion"`
	MaxScore        float64                      `json:"max_score"`
	Passed          bool                         `json:"passed"`
	Skipped         bool                         `json:"skipped"`
	SkipReason      string                       `json:"skip_reason,omitempty"`
	FailReason      string                       `json:"fail_reason,omitempty"`
	Result          string                       `json:"result"`
	Score           float64                      `json:"score"`
	DurationSec     float64                      `json:"duration_sec"`
	ScoringExplain  string                       `json:"scoring_explanation"`
	ToolOutput      *DToolOutputJSON             `json:"tool_output,omitempty"`
	FloodMetrics    *DFloodMetricsJSON           `json:"flood_metrics,omitempty"`
	SlowMetrics     *DSlowMetricsJSON            `json:"slow_metrics,omitempty"`
	PreVerify       *DVerifyBlockJSON            `json:"pre_verify,omitempty"`
	DuringVerify    *DVerifyBlockJSON            `json:"during_verify,omitempty"`
	PostVerify      *DVerifyBlockJSON            `json:"post_verify,omitempty"`
	TierResults     map[string]DTierResultJSON   `json:"tier_results,omitempty"`
	CircuitBroken   bool                         `json:"circuit_breaker,omitempty"`
	TimeoutDetected bool                         `json:"timeout_detected,omitempty"`
	WAFAction       string                       `json:"waf_action,omitempty"`
	RecoveryResults []DVerifyRouteJSON           `json:"recovery_results,omitempty"`
	Recovered       bool                         `json:"recovered,omitempty"`
	ReproduceScript string                       `json:"reproduce_script,omitempty"`
	AcceptActions   []string                     `json:"accept_actions,omitempty"`
	NotAcceptActions []string                    `json:"not_accept_actions,omitempty"`
	FailConditions  []DFailConditionJSON         `json:"fail_conditions,omitempty"`
	ScoringFormula  string                       `json:"scoring_formula,omitempty"`
}

type DToolOutputJSON struct {
	Tool     string `json:"tool"`
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr,omitempty"`
	Summary  string `json:"summary"`
}

type DFloodMetricsJSON struct {
	TargetRPS      float64        `json:"target_rps"`
	ActualRPS      float64        `json:"actual_rps"`
	TransferSec    string         `json:"transfer_sec"`
	LatencyAvgMs   float64        `json:"latency_avg_ms"`
	LatencyStdevMs float64        `json:"latency_stdev_ms"`
	LatencyMaxMs   float64        `json:"latency_max_ms"`
	LatencyP50Ms   float64        `json:"latency_p50_ms"`
	LatencyP75Ms   float64        `json:"latency_p75_ms"`
	LatencyP90Ms   float64        `json:"latency_p90_ms"`
	LatencyP99Ms   float64        `json:"latency_p99_ms"`
	SocketErrors   map[string]int `json:"socket_errors"`
	TotalRequests  int            `json:"total_requests"`
	DurationSec    int            `json:"duration_sec"`
}

type DSlowMetricsJSON struct {
	ConnectionsOpen    int  `json:"connections_open"`
	ConnectionsClosed  int  `json:"connections_closed"`
	ConnectionsError   int  `json:"connections_error"`
	ConnectionsPending int  `json:"connections_pending"`
	ServiceAvailable   bool `json:"service_available"`
	ExitStatus         int  `json:"exit_status"`
	TestDurationSec    int  `json:"test_duration_sec"`
}

type DVerifyBlockJSON struct {
	Phase       string             `json:"phase"`
	AllPassed   bool               `json:"all_passed"`
	PassedCount int                `json:"passed_count"`
	TotalCount  int                `json:"total_count"`
	Routes      []DVerifyRouteJSON `json:"routes"`
}

type DVerifyRouteJSON struct {
	Method       string  `json:"method"`
	Endpoint     string  `json:"endpoint"`
	StatusCode   int     `json:"status_code"`
	ExpectedCode int     `json:"expected_code"`
	LatencyMs    float64 `json:"latency_ms"`
	WAFAction    string  `json:"waf_action,omitempty"`
	RiskScore    int     `json:"risk_score"`
	Passed       bool    `json:"passed"`
	FailReason   string  `json:"fail_reason,omitempty"`
	CurlCommand  string  `json:"curl_command,omitempty"`
	Tier         string  `json:"tier,omitempty"`
}

type DTierResultJSON struct {
	Tier         string             `json:"tier"`
	ExpectedCode int                `json:"expected_code"`
	ExpectedMode string             `json:"expected_mode"`
	TotalRoutes  int                `json:"total_routes"`
	PassedRoutes int                `json:"passed_routes"`
	AllPassed    bool               `json:"all_passed"`
	FailReason   string             `json:"fail_reason,omitempty"`
	Routes       []DVerifyRouteJSON `json:"routes"`
}

type DFailConditionJSON struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Triggered   bool   `json:"triggered"`
	Evidence    string `json:"evidence,omitempty"`
}

type DResetStepJSON struct {
	Step       int     `json:"step"`
	Name       string  `json:"name"`
	StatusCode int     `json:"status_code"`
	Success    bool    `json:"success"`
	LatencyMs  float64 `json:"latency_ms"`
}

type DCategorySummaryJSON struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Criterion string  `json:"criterion"`
	Passed    int     `json:"passed"`
	Total     int     `json:"total"`
	Score     float64 `json:"score"`
	MaxScore  float64 `json:"max_score"`
}

type DScoringBreakdownJSON struct {
	TestID      string  `json:"test_id"`
	Name        string  `json:"name"`
	MaxScore    float64 `json:"max_score"`
	ScoreEarned float64 `json:"score_earned"`
	Passed      bool    `json:"passed"`
	Skipped     bool    `json:"skipped"`
}

type DSScoringMapJSON struct {
	Criterion   string `json:"criterion"`
	Description string `json:"description"`
	MaxPoints   int    `json:"max_points"`
	Formula     string `json:"formula"`
	Cap         int    `json:"cap"`
	RawMax      int    `json:"raw_max"`
}

// ── Category Map ──

var DCategories = map[string]DTestCategory{
	"ddos": {
		ID:        "ddos",
		Name:      "DDoS Stress Tests",
		Criterion: "INT-04",
	},
	"backend_failure": {
		ID:        "backend_failure",
		Name:      "Backend Failure Tests",
		Criterion: "INT-04",
	},
	"fail_mode_config": {
		ID:        "fail_mode_config",
		Name:      "Fail-Mode Configurability",
		Criterion: "INT-04",
	},
}

var DCategoryOrder = []string{"ddos", "backend_failure", "fail_mode_config"}

// ── Scoring Map ──

const ScoringMapDoc = `INT-04 — Resilience & Degradation (cap 8 pts, raw max 20 pts)

Scoring Methodology (per phase_D.md v2.3 §6):

  raw_score = sum(D01..D09 sub-scores)
  INT-04   = min(8, raw_score)

  Where each sub-score = 0 if test FAIL/SKIP, else max_score

  D01 — HTTP Flood Survival     : 3 pts
  D02 — Slowloris Handling      : 2 pts
  D03 — RUDY Handling           : 2 pts
  D04 — Fail-Close (CRITICAL)   : 4 pts
  D04 — Fail-Open (MEDIUM)      : 3 pts
  D05 — Circuit Breaker         : 2 pts
  D06 — Backend Timeout         : 1 pt
  D07 — Recovery                : 1 pt
  D08+D09 — Fail-Mode Config    : 2 pts

  WAF cần đạt ≥ 8/20 điểm thô để max INT-04.
  Các tổ hợp đạt max: pass D01(3)+D04(4)+D05(2)=9, or D04(7)+D07(1)=8, etc.`

// ── Route Tiers ──

var CRITICALRoutes = []DVerifyRoute{
	{Method: "POST", Endpoint: "/login", ExpectedCode: 503, Tier: "CRITICAL", Description: "Login (POST)"},
	{Method: "POST", Endpoint: "/otp", ExpectedCode: 503, Tier: "CRITICAL", Description: "OTP (POST)"},
	{Method: "POST", Endpoint: "/deposit", ExpectedCode: 503, Tier: "CRITICAL", Description: "Deposit (POST, requires auth)"},
	{Method: "POST", Endpoint: "/withdrawal", ExpectedCode: 503, Tier: "CRITICAL", Description: "Withdrawal (POST, requires auth)"},
}

var MEDIUMRoutes = []DVerifyRoute{
	{Method: "GET", Endpoint: "/game/list", ExpectedCode: 200, Tier: "MEDIUM", Description: "Game List (GET)"},
	{Method: "GET", Endpoint: "/game/1", ExpectedCode: 200, Tier: "MEDIUM", Description: "Game Detail (GET)"},
	{Method: "GET", Endpoint: "/api/profile", ExpectedCode: 200, Tier: "MEDIUM", Description: "Profile (GET, requires auth)"},
	{Method: "GET", Endpoint: "/api/transactions", ExpectedCode: 200, Tier: "MEDIUM", Description: "Transactions (GET, requires auth)"},
	{Method: "GET", Endpoint: "/user/settings", ExpectedCode: 200, Tier: "MEDIUM", Description: "Settings (GET, requires auth)"},
}

var CATCHALLRoutes = []DVerifyRoute{
	{Method: "GET", Endpoint: "/", ExpectedCode: 200, Tier: "CATCH_ALL", Description: "Home (GET)"},
	{Method: "GET", Endpoint: "/about", ExpectedCode: 200, Tier: "CATCH_ALL", Description: "About (GET)"},
	{Method: "GET", Endpoint: "/sitemap.xml", ExpectedCode: 200, Tier: "CATCH_ALL", Description: "Sitemap (GET)"},
}

var STATICRoutes = []DVerifyRoute{
	{Method: "GET", Endpoint: "/static/js/app.js", ExpectedCode: 200, Tier: "STATIC", Description: "Static JS (GET)"},
	{Method: "GET", Endpoint: "/assets/css/style.css", ExpectedCode: 200, Tier: "STATIC", Description: "Assets CSS (GET)"},
}

var LegitimateRoutes = []DVerifyRoute{
	{Method: "GET", Endpoint: "/health", ExpectedCode: 200, Tier: "CATCH_ALL", Description: "Health (GET)"},
	{Method: "GET", Endpoint: "/", ExpectedCode: 200, Tier: "CATCH_ALL", Description: "Home (GET)"},
	{Method: "GET", Endpoint: "/game/list", ExpectedCode: 200, Tier: "MEDIUM", Description: "Game List (GET)"},
	{Method: "GET", Endpoint: "/about", ExpectedCode: 200, Tier: "CATCH_ALL", Description: "About (GET)"},
	{Method: "GET", Endpoint: "/sitemap.xml", ExpectedCode: 200, Tier: "CATCH_ALL", Description: "Sitemap (GET)"},
}

var RequiredHeaders = []string{
	"X-WAF-Request-Id",
	"X-WAF-Risk-Score",
	"X-WAF-Action",
	"X-WAF-Rule-Id",
	"X-WAF-Mode",
	"X-WAF-Cache",
}

// DMemorySnapshot holds a per-test memory reading.
type DMemorySnapshot struct {
	TestID      string
	RSSMB       float64
	HWMMB       float64 // VmHWM in MB
	PeakMB      float64 // VmPeak
	PressurePct float64 // percent of WAF memory.max used
}

// DMemoryReport summarizes memory across all Phase D tests.
type DMemoryReport struct {
	Snapshots    []DMemorySnapshot
	MaxHWMMB     float64
	MemoryLeak   bool
	OOMRisk      bool
	PressureFlag bool // MEMORY_PRESSURE if >90% of memory.max
}
