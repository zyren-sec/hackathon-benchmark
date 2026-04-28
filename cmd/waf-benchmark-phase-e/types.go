package main

import "time"

var phaseECaseOrder = []string{"E01", "E02", "E03", "E04"}

// PhaseEReport is the dedicated report artifact for cmd/waf-benchmark-phase-e.
type PhaseEReport struct {
	Metadata         ReportMetadata        `json:"metadata"`
	EndpointValidity EndpointValidity      `json:"endpoint_validity"`
	Cases            map[string]CaseReport `json:"cases"`
	CaseOrder        []string              `json:"case_order"`
	Summary          PhaseESummary         `json:"summary"`
	QualityMetrics   QualityMetrics        `json:"quality_metrics"`
	TieBreak         TieBreakSummary       `json:"tie_break"`
	Validation       ValidationSection     `json:"validation"`
}

type ReportMetadata struct {
	RunID        string    `json:"run_id"`
	GeneratedAt  time.Time `json:"generated_at"`
	Tool         string    `json:"tool"`
	Version      string    `json:"version"`
	ConfigPath   string    `json:"config_path"`
	TargetURL    string    `json:"target_url"`
	WAFURL       string    `json:"waf_url"`
	BenchmarkURL string    `json:"benchmark_url"`
	DurationMs   int64     `json:"duration_ms"`
}

type EndpointValidity struct {
	MappedFromDocs []MappedEndpoint `json:"mapped_from_docs"`
	Probes         []EndpointProbe  `json:"probes"`
	AllReachable   bool             `json:"all_reachable"`
	Notes          []string         `json:"notes"`
}

type MappedEndpoint struct {
	CaseID   string `json:"case_id"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Source   string `json:"source"`
	Expected string `json:"expected"`
}

type EndpointProbe struct {
	BaseURL      string `json:"base_url"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	StatusCode   int    `json:"status_code"`
	Reachable    bool   `json:"reachable"`
	LatencyMs    int64  `json:"latency_ms"`
	ServerHeader string `json:"server_header,omitempty"`
	CFRay        string `json:"cf_ray,omitempty"`
	ContentType  string `json:"content_type,omitempty"`
	Error        string `json:"error,omitempty"`
}

type CaseReport struct {
	CaseID      string                 `json:"case_id"`
	Name        string                 `json:"name"`
	Passed      bool                   `json:"passed"`
	Expected    string                 `json:"expected"`
	Observed    string                 `json:"observed"`
	Reason      string                 `json:"reason"`
	WAFFeedback string                 `json:"waf_feedback"`
	Evidence    map[string]interface{} `json:"evidence"`
}

type PhaseESummary struct {
	Pass          bool    `json:"pass"`
	PassedCases   int     `json:"passed_cases"`
	TotalCases    int     `json:"total_cases"`
	Score         float64 `json:"score"`
	MaxScore      float64 `json:"max_score"`
	EndpointReady bool    `json:"endpoint_ready"`
}

type QualityMetrics struct {
	CacheEfficiency      CacheEfficiencyMetrics      `json:"cache_efficiency"`
	Safety               SafetyMetrics               `json:"safety"`
	StabilityDeterminism StabilityDeterminismMetrics `json:"stability_determinism"`
	ResourceEfficiency   ResourceEfficiencyMetrics   `json:"resource_efficiency"`
}

type CacheEfficiencyMetrics struct {
	CacheHitRatioMedium    float64 `json:"cache_hit_ratio_medium"`
	CacheHitLatencyP50Ms   float64 `json:"cache_hit_latency_p50_ms"`
	CacheHitLatencyP95Ms   float64 `json:"cache_hit_latency_p95_ms"`
	CacheAccelerationRatio float64 `json:"cache_acceleration_ratio"`
	TTLExpiryAccuracy      float64 `json:"ttl_expiry_accuracy"`
}

type SafetyMetrics struct {
	CriticalCacheViolationCount int     `json:"critical_cache_violation_count"`
	AuthCacheViolationCount     int     `json:"auth_cache_violation_count"`
	TokenUniquenessRate         float64 `json:"token_uniqueness_rate"`
	AuthResponseSimilarityGuard float64 `json:"auth_response_similarity_guard"`
}

type StabilityDeterminismMetrics struct {
	DecisionFlapCount     int     `json:"decision_flap_count"`
	LatencyStddevHitMs    float64 `json:"latency_stddev_hit_ms"`
	LatencyStddevMissMs   float64 `json:"latency_stddev_miss_ms"`
	HeaderConsistencyRate float64 `json:"header_consistency_rate"`
}

type ResourceEfficiencyMetrics struct {
	MemoryCachePeakMB    float64 `json:"memory_cache_peak_mb"`
	EvictionRate         float64 `json:"eviction_rate"`
	CPUOverheadCachePath float64 `json:"cpu_overhead_cache_path_pct"`
}

type TieBreakSummary struct {
	PhaseEQualityScore float64            `json:"phase_e_quality_score"`
	Weights            map[string]float64 `json:"weights"`
	Signals            map[string]float64 `json:"signals"`
	RankingPolicy      []string           `json:"ranking_policy"`
}

type ValidationSection struct {
	WorkflowChecks []ValidationCheck `json:"workflow_checks"`
	ReportChecks   []ValidationCheck `json:"report_checks"`
	Passed         bool              `json:"passed"`
}

type ValidationCheck struct {
	ID       string `json:"id"`
	Passed   bool   `json:"passed"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
}
