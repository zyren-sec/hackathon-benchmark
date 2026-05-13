package phasec

import "time"

// ── Phase C Core Types ──

// PhaseCResult is the complete Phase C run result.
type PhaseCResult struct {
	StartTime time.Time
	EndTime   time.Time
	WAFTarget string
	WAFMode   string

	// Resource tier
	ResourceTier      ResourceTier // "min", "mid", "full"
	TierConfig        TierConfig   // active tier configuration

	// Reset sequence
	ResetSteps     []CResetStep
	ResetAllPassed bool

	// Pre-flight
	WAFCheckPassed     bool
	UpstreamCheckOK    bool
	WAFPID             string
	MemoryMonitorOK    bool
	CgroupsActive      bool   // cgroups v2 isolation active
	PinningVerified    bool   // CPU pinning confirmed via per-core sampling

	// Baseline latency (direct to UPSTREAM :9000)
	Baseline         *BaselineLatency
	BaselineFailed   bool
	BaselineFailReason string

	// WAF latency (through WAF :8080)
	WAFLatency       *WAFLatencyResult

	// Load test steps
	LoadTestSteps    []LoadTestStepResult

	// False positive analysis
	FPCount          int
	FPRate           float64
	CollateralCount  int
	FPDetails        []FPDetail

	// Throughput & memory time series
	ThroughputTS     []ThroughputPoint
	MemoryTS         []MemoryPoint

	// Crash tracking
	WAFCrashed       bool
	CrashStep        int // which step caused crash

	// System Health Profiler
	ProfilerActive   bool
	NoiseReport      *NoiseReport // from SystemHealthProfiler

	// Scoring
	Scores           map[string]ScoreDetail
	PhaseCTotal      float64
	PhaseCMax        float64
}

// CResetStep represents one step in the Phase C reset sequence.
type CResetStep struct {
	StepNum    int
	Name       string
	Method     string
	URL        string
	StatusCode int
	Success    bool
	LatencyMs  float64
	Error      string
}

// BaselineLatency holds direct-to-UPSTREAM latency measurements.
type BaselineLatency struct {
	Classes   []LatencyClass
	TotalSamples int
}

// LatencyClass groups endpoints by criticality and stores metrics.
type LatencyClass struct {
	Name      string   // critical, high, medium, catch_all
	Endpoints []string
	Samples   int      // number of requests sent
	P50Ms     float64
	P99Ms     float64
	AvgMs     float64
}

// WAFLatencyResult holds WAF-proxied latency measurements.
type WAFLatencyResult struct {
	Classes      []WAFLatencyClass
	TotalSamples int
}

// WAFLatencyClass stores WAF latency + overhead per class.
type WAFLatencyClass struct {
	Name        string
	Endpoints   []string
	Samples     int
	P50Ms       float64
	P99Ms       float64
	AvgMs       float64
	OverheadP50 float64 // WAF P50 - Baseline P50
	OverheadP99 float64 // WAF P99 - Baseline P99
	OverheadPct float64 // (WAF Avg - Baseline Avg) / Baseline Avg * 100
}

// ── Load Test ──

// LoadTestConfig defines one load test step configuration.
type LoadTestConfig struct {
	StepNum     int
	TargetRPS   int
	DurationSec int
	Marker      string // "", "⬤ SLA TARGET", "⚡ STRESS TEST"
	Purpose     string
}

// LoadTestStepResult holds metrics for a single load test step.
type LoadTestStepResult struct {
	StepNum       int
	TargetRPS     int
	ActualRPS     float64
	DurationSec   int
	TotalRequests int
	SuccessCount  int
	ErrorCount    int
	BlockedCount  int

	// Latency percentiles (ms)
	P50Ms         float64
	P99Ms         float64
	MaxMs         float64

	// Rates
	SuccessRate   float64
	ErrorRate     float64
	BlockedRate   float64

	// Memory
	MemoryPeakMB  float64

	// False positives
	FalsePositiveCount int
	CollateralCount    int

	// DDoS burst stats
	DDoSBurstsTriggered int
	DDoSBurstReqs       int

	// Status
	Passed        bool // error rate < 5%
	FailReason    string
}

// FPDetail records a single false positive incident.
type FPDetail struct {
	Endpoint     string
	StatusCode   int
	ResponseBody string // truncated
	LatencyMs    float64
	WAFAction    string
	RiskScore    int
	DuringDDoS   bool
}

// ThroughputPoint is a time-series sample of throughput.
type ThroughputPoint struct {
	TimestampSec int
	ActualRPS    float64
}

// MemoryPoint is a time-series sample of memory usage (VmHWM — primary for PERF-03).
type MemoryPoint struct {
	TimestampSec int
	MemoryMB     float64 // VmHWM in MB — PRIMARY metric for PERF-03
	MemoryPeakMB float64 // VmPeak in MB — reference only (virtual memory)
}

// ── Scoring ──

// ScoreDetail holds PASS/FAIL + points for one scoring criterion.
type ScoreDetail struct {
	Pass        bool
	Points      float64
	MaxPoints   float64
	Measured    float64
	Threshold   float64
	Explanation string
}

// ── Traffic Mix ──

// TrafficType enumerates the 5 traffic categories.
type TrafficType int

const (
	TrafficLegitimate TrafficType = iota
	TrafficSuspicious
	TrafficExploit
	TrafficAbuse
	TrafficDDoS
)

func (t TrafficType) String() string {
	switch t {
	case TrafficLegitimate:
		return "Legitimate (Golden Path)"
	case TrafficSuspicious:
		return "Suspicious but Legitimate"
	case TrafficExploit:
		return "Exploit Payloads"
	case TrafficAbuse:
		return "Abuse Patterns"
	case TrafficDDoS:
		return "DDoS Bursts"
	}
	return "Unknown"
}

// TrafficMixEntry defines a traffic category with its ratio.
type TrafficMixEntry struct {
	Type  TrafficType
	Ratio float64 // e.g., 0.60 for 60%
}

// DefaultTrafficMix returns the Phase C default traffic mix.
func DefaultTrafficMix() []TrafficMixEntry {
	return []TrafficMixEntry{
		{TrafficLegitimate, 0.60},
		{TrafficSuspicious, 0.10},
		{TrafficExploit, 0.10},
		{TrafficAbuse, 0.10},
		{TrafficDDoS, 0.10},
	}
}

// ── Individual Request Result ──

// CRequestResult is a single HTTP request result in Phase C.
type CRequestResult struct {
	Index        int
	URL          string
	Method       string
	SourceIP     string
	TrafficType  TrafficType
	StatusCode   int
	LatencyMs    float64
	ResponseBody string
	ResponseHeaders map[string]string
	WAFAction    string
	RiskScore    int
	Blocked      bool
	CurlCommand  string
	Error        string
}

// ── Exploit Payload Config ──

// ExploitPayloadConfig defines one exploit used in Phase C blended traffic.
type ExploitPayloadConfig struct {
	VulnID      string // V01, V04, V06, V09
	Name        string
	Category    string // SQLi, XSS, PathTraversal, SSRF
	Method      string
	Endpoint    string
	Payload     string
	ContentType string
	ProofMarker string
	ExtraHeaders map[string]string
}

// ── Golden Path (Legitimate Traffic) ──

// GoldenPathStep is one step in the 10-step legitimate user flow.
type GoldenPathStep struct {
	StepNum     int
	Name        string
	Method      string
	Endpoint    string
	Body        string // empty for GET
	ContentType string
	ExpectedStatus int
}

// ── Desktop / Console Display ──

// Display helper types
type CDisplayTable struct {
	Header []string
	Rows   [][]string
	Widths []int
}

// ── Report Types (JSON + HTML) ──

// PhaseCReport is the top-level JSON report structure for Phase C.
type PhaseCReport struct {
	Phase           string                    `json:"phase"`
	Timestamp       string                    `json:"timestamp"`
	WAFTarget       string                    `json:"waf_target"`
	WAFMode         string                    `json:"waf_mode"`
	DurationMs      int64                     `json:"duration_ms"`

	// Reset
	ResetSequence   []CResetStepJSON          `json:"reset_sequence"`
	ResetAllPassed  bool                      `json:"reset_all_passed"`

	// Pre-flight
	WAFPID          string                    `json:"waf_pid"`
	MemoryMonitorOK bool                      `json:"memory_monitoring_enabled"`

	// Baseline
	Baseline        *CBaselineJSON            `json:"baseline_latency"`
	BaselineFailed  bool                      `json:"baseline_measurement_failed,omitempty"`

	// WAF Latency
	WAFLatency      *CWAFLatencyJSON          `json:"waf_latency"`

	// Load test
	LoadTestSteps   []CLoadTestStepJSON        `json:"load_test_steps"`

	// Timeseries
	ThroughputTS    []CThroughputPointJSON     `json:"throughput_time_series"`
	MemoryTS        []CMemoryPointJSON         `json:"memory_time_series"`

	// FP analysis
	FPCount         int                       `json:"false_positive_count"`
	FPRate          float64                   `json:"false_positive_rate"`
	CollateralCount int                       `json:"collateral_count"`
	FPDetails       []CFPDetailJSON           `json:"false_positive_details"`

	// Diagnostic
	ResourceTier      string               `json:"resource_tier"`
	CgroupsActive     bool                 `json:"cgroups_active"`
	PinningVerified   bool                 `json:"cpu_pinning_verified"`
	ProfilerActive    bool                 `json:"profiler_active"`
	NoiseFlag         string               `json:"noise_flag"`
	NoiseEstimateMs   float64              `json:"noise_estimate_ms"`
	NoiseCorrelation  *NoiseCorrelationJSON `json:"noise_correlation,omitempty"`

	// Scoring
	Scoring         map[string]CScoreDetailJSON `json:"scoring"`
	PhaseCTotal     float64                     `json:"phase_c_total"`
	PhaseCMax       float64                     `json:"phase_c_max"`

	// Crash
	GracefulDegradation bool                   `json:"graceful_degradation"`
	WAFCrashed      bool                       `json:"waf_crashed,omitempty"`
}

// CResetStepJSON for JSON export.
type CResetStepJSON struct {
	Step       int     `json:"step"`
	Name       string  `json:"name"`
	StatusCode int     `json:"status_code"`
	Success    bool    `json:"success"`
	LatencyMs  float64 `json:"latency_ms"`
}

// CBaselineJSON holds baseline latency for JSON.
type CBaselineJSON struct {
	Classes      []CLatencyClassJSON `json:"classes"`
	TotalSamples int                `json:"total_samples"`
}

// CLatencyClassJSON is one endpoint class with latency stats.
type CLatencyClassJSON struct {
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints"`
	Samples   int      `json:"samples"`
	P50Ms     float64  `json:"p50_ms"`
	P99Ms     float64  `json:"p99_ms"`
	AvgMs     float64  `json:"avg_ms"`
}

// CWAFLatencyJSON holds WAF proxied latency for JSON.
type CWAFLatencyJSON struct {
	Classes      []CWAFLatencyClassJSON `json:"classes"`
	TotalSamples int                   `json:"total_samples"`
}

// CWAFLatencyClassJSON is one endpoint class with WAF + overhead.
type CWAFLatencyClassJSON struct {
	Name        string   `json:"name"`
	Endpoints   []string `json:"endpoints"`
	Samples     int      `json:"samples"`
	P50Ms       float64  `json:"p50_ms"`
	P99Ms       float64  `json:"p99_ms"`
	AvgMs       float64  `json:"avg_ms"`
	OverheadP50 float64  `json:"overhead_p50_ms"`
	OverheadP99 float64  `json:"overhead_p99_ms"`
	OverheadPct float64  `json:"overhead_pct"`
}

// CLoadTestStepJSON for JSON export.
type CLoadTestStepJSON struct {
	StepNum            int     `json:"step_num"`
	TargetRPS          int     `json:"target_rps"`
	ActualRPS          float64 `json:"actual_rps"`
	DurationSec        int     `json:"duration_sec"`
	TotalRequests      int     `json:"total_requests"`
	SuccessCount       int     `json:"success_count"`
	ErrorCount         int     `json:"error_count"`
	BlockedCount       int     `json:"blocked_count"`
	SuccessRate        float64 `json:"success_rate"`
	ErrorRate          float64 `json:"error_rate"`
	BlockedRate        float64 `json:"blocked_rate"`
	P50Ms              float64 `json:"p50_latency_ms"`
	P99Ms              float64 `json:"p99_latency_ms"`
	MaxMs              float64 `json:"max_latency_ms"`
	MemoryPeakMB       float64 `json:"memory_peak_mb"`
	FPCount            int     `json:"false_positive_count"`
	CollateralCount    int     `json:"collateral_count"`
	DDoSBurstsTriggered int    `json:"ddos_bursts_triggered"`
	Passed             bool    `json:"passed"`
	FailReason         string  `json:"fail_reason,omitempty"`
}

// CThroughputPointJSON for JSON export time series.
type CThroughputPointJSON struct {
	TimestampSec int     `json:"timestamp_sec"`
	ActualRPS    float64 `json:"actual_rps"`
}

// CMemoryPointJSON for JSON export time series.
type CMemoryPointJSON struct {
	TimestampSec int     `json:"timestamp_sec"`
	MemoryMB     float64 `json:"memory_mb"`
}

// CFPDetailJSON for JSON export.
type CFPDetailJSON struct {
	Endpoint     string  `json:"endpoint"`
	StatusCode   int     `json:"status_code"`
	LatencyMs    float64 `json:"latency_ms"`
	WAFAction    string  `json:"waf_action"`
	RiskScore    int     `json:"risk_score"`
	DuringDDoS   bool    `json:"during_ddos"`
}

// CScoreDetailJSON for JSON export.
type CScoreDetailJSON struct {
	Pass        bool    `json:"pass"`
	Points      float64 `json:"weighted"`
	MaxPoints   float64 `json:"max_points"`
	Measured    float64 `json:"measured"`
	Threshold   float64 `json:"threshold"`
	Explanation string  `json:"explanation"`
}

// NoiseCorrelationJSON holds noise correlation data for JSON export.
type NoiseCorrelationJSON struct {
	WAFCPU    float64 `json:"latency_vs_waf_cpu"`
	BenchCPU  float64 `json:"latency_vs_bench_cpu"`
	CtxSwitch float64 `json:"latency_vs_ctx_switch"`
}

// ── Thresholds ──

// PhaseCThresholds holds all scoring thresholds.
type PhaseCThresholds struct {
	P99MaxMs            float64 // PERF-01: ≤5ms
	SustainedMinRPS     float64 // PERF-02: ≥5000
	MemoryMaxMB         float64 // PERF-03: <100MB
	ErrorRateMax        float64 // PERF-04: <5%
}

func DefaultThresholds() PhaseCThresholds {
	return PhaseCThresholds{
		P99MaxMs:        5.0,
		SustainedMinRPS: 5000,
		MemoryMaxMB:     100,
		ErrorRateMax:    0.05,
	}
}
