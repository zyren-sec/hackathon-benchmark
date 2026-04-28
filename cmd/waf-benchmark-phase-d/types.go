package main

import "time"

// PhaseDReport is the dedicated report artifact for cmd/waf-benchmark-phase-d.
type PhaseDReport struct {
	Metadata       ReportMetadata        `json:"metadata"`
	PhaseDSummary  PhaseDSummary         `json:"phase_d_summary"`
	Cases          map[string]CaseReport `json:"cases"`
	CaseOrder      []string              `json:"case_order"`
	QualityMetrics QualityMetrics        `json:"quality_metrics"`
	TieBreak       TieBreakSummary       `json:"tie_break"`
}

// ReportMetadata captures run identity and environment.
type ReportMetadata struct {
	RunID       string    `json:"run_id"`
	GeneratedAt time.Time `json:"generated_at"`
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	ConfigPath  string    `json:"config_path"`
	TargetURL   string    `json:"target_url"`
	WAFURL      string    `json:"waf_url"`
	DurationMs  int64     `json:"duration_ms"`
}

// PhaseDSummary provides top-level verdict and score.
type PhaseDSummary struct {
	Pass          bool    `json:"pass"`
	PassedCases   int     `json:"passed_cases"`
	TotalCases    int     `json:"total_cases"`
	Score         float64 `json:"score"`
	MaxScore      float64 `json:"max_score"`
	DDoSScore     float64 `json:"ddos_score"`
	BackendScore  float64 `json:"backend_score"`
	FailModeScore float64 `json:"fail_mode_score"`
}

// QualityMetrics captures Section 4 post-pass optimization metrics.
type QualityMetrics struct {
	AccuracyDeterminism AccuracyDeterminismMetrics `json:"accuracy_determinism"`
	LatencyQuality      LatencyQualityMetrics      `json:"latency_quality"`
	ServiceContinuity   ServiceContinuityMetrics   `json:"service_continuity"`
	RecoveryControl     RecoveryControlMetrics     `json:"recovery_control"`
	ResourceEfficiency  ResourceEfficiencyMetrics  `json:"resource_efficiency"`
}

type AccuracyDeterminismMetrics struct {
	StatusOKRatioByCase     map[string]float64 `json:"status_ok_ratio_by_case"`
	DecisionFlapCountByCase map[string]int     `json:"decision_flap_count_by_case"`
	PolicyConsistencyScore  float64            `json:"policy_consistency_score"`
}

type LatencyStats struct {
	P50Ms    float64 `json:"p50_ms"`
	P95Ms    float64 `json:"p95_ms"`
	P99Ms    float64 `json:"p99_ms"`
	MaxMs    float64 `json:"max_ms"`
	StdDevMs float64 `json:"stddev_ms"`
}

type LatencyQualityMetrics struct {
	ByCase                  map[string]LatencyStats `json:"by_case"`
	LegitRecoveryLatencyP95 float64                 `json:"legit_recovery_latency_p95_ms"`
	FastFailP95             float64                 `json:"fast_fail_p95_ms"`
	TimeoutAlignmentErrorMs float64                 `json:"timeout_alignment_error_ms"`
}

type ServiceContinuityMetrics struct {
	LegitSuccessRatioUnderAttack float64 `json:"legit_success_ratio_under_attack"`
	CollateralBlockCount         int     `json:"collateral_block_count"`
	NewConnAcceptRatio           float64 `json:"new_conn_accept_ratio"`
}

type RecoveryControlMetrics struct {
	RecoveryTimeToGreenMs float64 `json:"recovery_time_to_green_ms"`
	ConfigApplyLatencyMs  float64 `json:"config_apply_latency_ms"`
	ConfigRollbackSafety  float64 `json:"config_rollback_safety"`
}

type ResourceEfficiencyMetrics struct {
	CPUPeakPct    float64 `json:"cpu_peak_pct"`
	MemoryPeakMB  float64 `json:"memory_peak_mb"`
	FDPeak        float64 `json:"fd_peak"`
	ConnTablePeak float64 `json:"conn_table_peak"`
}

type TieBreakSummary struct {
	PhaseDQualityScore float64            `json:"phase_d_quality_score"`
	Weights            map[string]float64 `json:"weights"`
	Signals            map[string]float64 `json:"signals"`
}

// CaseReport is a detailed per-case report item (D01..D09).
type CaseReport struct {
	TestID      string                 `json:"test_id"`
	Name        string                 `json:"name"`
	Category    string                 `json:"category"`
	Passed      bool                   `json:"passed"`
	Expected    string                 `json:"expected"`
	Observed    string                 `json:"observed"`
	Reason      string                 `json:"reason"`
	WAFFeedback string                 `json:"waf_feedback"`
	Evidence    map[string]interface{} `json:"evidence"`
}
