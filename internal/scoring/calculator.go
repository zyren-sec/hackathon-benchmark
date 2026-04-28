package scoring

import (
	"fmt"
	"math"
	"strings"

	"github.com/waf-hackathon/benchmark/internal/phases"
)

// ScoreCalculator calculates scores for each phase
type ScoreCalculator struct {
	Matrix *ScoringMatrix
}

// NewScoreCalculator creates a new score calculator
func NewScoreCalculator(matrix *ScoringMatrix) *ScoreCalculator {
	if matrix == nil {
		matrix = DefaultScoringMatrix()
	}
	return &ScoreCalculator{Matrix: matrix}
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

func clamp(v, minV, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func (sc *ScoreCalculator) matrixPoints(id string, fallback float64) float64 {
	if sc == nil || sc.Matrix == nil {
		return fallback
	}
	if p := sc.Matrix.GetPoints(id); p > 0 {
		return p
	}
	return fallback
}

// CalculatePhaseAScore calculates score for Phase A (Exploit Prevention)
// exploit_prevention_rate × 15 + outbound_filter_rate × 5 (normalized to 20 points)
func (sc *ScoreCalculator) CalculatePhaseAScore(results *phases.PhaseAResult) float64 {
	if results == nil {
		return 0
	}

	exploitMax := sc.matrixPoints("SEC-01", 15.0)
	outboundMax := sc.matrixPoints("SEC-02", 5.0)

	exploitScore := clamp(results.ExploitPreventionRate/100.0*exploitMax, 0, exploitMax)
	outboundScore := clamp(results.OutboundFilterRate/100.0*outboundMax, 0, outboundMax)

	return round1(exploitScore + outboundScore)
}

// CalculatePhaseBScore calculates score for Phase B (Abuse Detection)
// abuse_detection_rate × 10 (normalized to 10 points)
func (sc *ScoreCalculator) CalculatePhaseBScore(results *phases.PhaseBResult) float64 {
	if results == nil {
		return 0
	}

	maxPoints := sc.matrixPoints("SEC-03", 10.0)
	score := clamp(results.AbuseDetectionRate/100.0*maxPoints, 0, maxPoints)
	return round1(score)
}

// CalculatePhaseCScore calculates score for Phase C (Performance)
func (sc *ScoreCalculator) CalculatePhaseCScore(results *phases.PhaseCResult) float64 {
	if results == nil {
		return 0
	}
	total := results.LatencyScore + results.ThroughputScore + results.MemoryScore + results.GracefulScore
	maxPoints := sc.matrixPoints("PERF-01", 10) + sc.matrixPoints("PERF-02", 5) + sc.matrixPoints("PERF-03", 3) + sc.matrixPoints("PERF-04", 2)
	return round1(clamp(total, 0, maxPoints))
}

// CalculatePhaseDScore calculates score for Phase D (Resilience)
func (sc *ScoreCalculator) CalculatePhaseDScore(results *phases.PhaseDResult) float64 {
	if results == nil {
		return 0
	}
	total := results.DDoSScore + results.BackendScore + results.FailModeScore
	return round1(clamp(total, 0, 9.0))
}

// CalculatePhaseEScore calculates score for Phase E (Extensibility)
func (sc *ScoreCalculator) CalculatePhaseEScore(results *phases.PhaseEResult) float64 {
	if results == nil {
		return 0
	}
	total := results.HotReloadScore + results.CachingScore
	return round1(clamp(total, 0, 10.0))
}

// CalculateRiskLifecycleScore calculates score for Risk Lifecycle
func (sc *ScoreCalculator) CalculateRiskLifecycleScore(results *phases.RiskLifecycleResult) float64 {
	if results == nil || len(results.Steps) == 0 {
		return 0
	}

	score := 0.0
	for i, step := range results.Steps {
		if step.Passed {
			if i == 6 { // Step 7 is worth 2 points
				score += 2.0
			} else {
				score += 1.0
			}
		}
	}
	return round1(clamp(score, 0, sc.matrixPoints("SEC-05", 8.0)))
}

func (sc *ScoreCalculator) calculateCategoryRate(results *phases.PhaseBResult, prefix string) float64 {
	if results == nil {
		return 0
	}

	if len(results.AbuseTests) == 0 {
		return clamp(results.AbuseDetectionRate, 0, 100)
	}

	total := 0
	passed := 0
	for _, t := range results.AbuseTests {
		if strings.HasPrefix(strings.ToUpper(t.TestID), strings.ToUpper(prefix)) {
			total++
			if t.Passed {
				passed++
			}
		}
	}
	if total == 0 {
		return clamp(results.AbuseDetectionRate, 0, 100)
	}
	return float64(passed) / float64(total) * 100
}

func (sc *ScoreCalculator) calculateCanaryScore(phaseA *phases.PhaseAResult) float64 {
	maxPoints := sc.matrixPoints("SEC-04", 2.0)
	if phaseA == nil {
		return 0
	}

	// Strict binary semantics are not fully representable from current core result model.
	// Use conservative approximation until dedicated canary evidence is wired.
	if phaseA.ExploitPreventionRate >= 99.9 {
		return maxPoints
	}
	return 0
}

func (sc *ScoreCalculator) calculateIntelligenceScore(phaseB *phases.PhaseBResult, phaseD *phases.PhaseDResult) float64 {
	int01Max := sc.matrixPoints("INT-01", 4)
	int02Max := sc.matrixPoints("INT-02", 4)
	int03Max := sc.matrixPoints("INT-03", 4)
	int04Max := sc.matrixPoints("INT-04", 8)

	tfRate := sc.calculateCategoryRate(phaseB, "TF")
	baRate := sc.calculateCategoryRate(phaseB, "BA")
	arRate := sc.calculateCategoryRate(phaseB, "AR")

	int01 := clamp(tfRate/100.0*int01Max, 0, int01Max)
	int02 := clamp(baRate/100.0*int02Max, 0, int02Max)
	int03 := clamp(arRate/100.0*int03Max, 0, int03Max)

	int04 := 0.0
	if phaseD != nil {
		int04 = clamp((sc.CalculatePhaseDScore(phaseD)/9.0)*int04Max, 0, int04Max)
	}

	return round1(int01 + int02 + int03 + int04)
}

func (sc *ScoreCalculator) calculateExtensibilityScore(phaseE *phases.PhaseEResult) float64 {
	if phaseE == nil {
		return 0
	}
	ext01Max := sc.matrixPoints("EXT-01", 3)
	ext02Max := sc.matrixPoints("EXT-02", 3)
	ext03Max := sc.matrixPoints("EXT-03", 4)

	ext01 := 0.0
	ext02 := 0.0

	for _, t := range phaseE.HotReloadTests {
		id := strings.ToUpper(t.TestID)
		if (id == "E-ADD" || id == "EXT-01") && t.Passed {
			ext01 = ext01Max
		}
		if (id == "E-REMOVE" || id == "EXT-02") && t.Passed {
			ext02 = ext02Max
		}
	}

	// Fallback when per-test list is unavailable but aggregate score exists.
	if ext01 == 0 && phaseE.HotReloadScore >= 3 {
		ext01 = ext01Max
	}
	if ext02 == 0 && phaseE.HotReloadScore >= 6 {
		ext02 = ext02Max
	}

	ext03 := clamp(phaseE.CachingScore, 0, ext03Max)
	return round1(ext01 + ext02 + ext03)
}

func (sc *ScoreCalculator) calculateDeploymentScore(phaseD *phases.PhaseDResult) float64 {
	dep02Max := sc.matrixPoints("DEP-02", 2)
	if phaseD == nil {
		return 0
	}
	if phaseD.FailModeScore > 0 {
		return dep02Max
	}
	return 0
}

// OverallScore contains the complete scoring breakdown
type OverallScore struct {
	PhaseA        float64 `json:"phase_a_score"`
	PhaseB        float64 `json:"phase_b_score"`
	PhaseC        float64 `json:"phase_c_score"`
	PhaseD        float64 `json:"phase_d_score"`
	PhaseE        float64 `json:"phase_e_score"`
	RiskLifecycle float64 `json:"risk_lifecycle_score"`

	SecurityEffectiveness float64 `json:"security_effectiveness_score"`
	Performance           float64 `json:"performance_score"`
	Intelligence          float64 `json:"intelligence_score"`
	Extensibility         float64 `json:"extensibility_score"`
	Architecture          float64 `json:"architecture_score"`
	Dashboard             float64 `json:"dashboard_score"`
	Deployment            float64 `json:"deployment_score"`

	Total       float64 `json:"total_score"`
	MaxPossible float64 `json:"max_possible_score"`
	Percentage  float64 `json:"percentage"`
	Grade       string  `json:"grade"`
}

// CalculateOverallScore calculates the overall benchmark score.
// Option A profile: Full 120-point matrix parity with docs/scoring_matrix.csv
func (sc *ScoreCalculator) CalculateOverallScore(
	phaseA *phases.PhaseAResult,
	phaseB *phases.PhaseBResult,
	phaseC *phases.PhaseCResult,
	phaseD *phases.PhaseDResult,
	phaseE *phases.PhaseEResult,
	riskLifecycle *phases.RiskLifecycleResult,
) *OverallScore {
	if sc.Matrix == nil {
		sc.Matrix = DefaultScoringMatrix()
	}

	score := &OverallScore{
		MaxPossible: sc.Matrix.GetTotalPossiblePoints(),
	}
	if score.MaxPossible <= 0 {
		score.MaxPossible = 120.0
	}

	// Legacy phase views remain for backward-compatible report sections.
	score.PhaseA = sc.CalculatePhaseAScore(phaseA)
	score.PhaseB = sc.CalculatePhaseBScore(phaseB)
	score.PhaseC = sc.CalculatePhaseCScore(phaseC)
	score.PhaseD = sc.CalculatePhaseDScore(phaseD)
	score.PhaseE = sc.CalculatePhaseEScore(phaseE)
	score.RiskLifecycle = sc.CalculateRiskLifecycleScore(riskLifecycle)

	// 120-point matrix categories.
	score.SecurityEffectiveness = round1(score.PhaseA + score.PhaseB + sc.calculateCanaryScore(phaseA) + score.RiskLifecycle)
	score.Performance = round1(score.PhaseC)
	score.Intelligence = sc.calculateIntelligenceScore(phaseB, phaseD)
	score.Extensibility = sc.calculateExtensibilityScore(phaseE)
	score.Architecture = 0 // manual judge rubric (ARCH-01..04)
	score.Dashboard = 0    // UI manual/observability rubric (UI-01..04)
	score.Deployment = sc.calculateDeploymentScore(phaseD)

	score.Total = round1(
		score.SecurityEffectiveness +
			score.Performance +
			score.Intelligence +
			score.Extensibility +
			score.Architecture +
			score.Dashboard +
			score.Deployment,
	)
	score.Percentage = (score.Total / score.MaxPossible) * 100
	score.Grade = calculateGrade(score.Percentage)

	return score
}

// calculateGrade determines the letter grade based on percentage
func calculateGrade(percentage float64) string {
	switch {
	case percentage >= 95:
		return "A+"
	case percentage >= 90:
		return "A"
	case percentage >= 85:
		return "A-"
	case percentage >= 80:
		return "B+"
	case percentage >= 75:
		return "B"
	case percentage >= 70:
		return "B-"
	case percentage >= 65:
		return "C+"
	case percentage >= 60:
		return "C"
	case percentage >= 55:
		return "C-"
	case percentage >= 50:
		return "D"
	default:
		return "F"
	}
}

// ScoreReport contains the complete benchmark report with all details
type ScoreReport struct {
	OverallScore          *OverallScore                 `json:"overall_score"`
	PhaseADetails         *phases.PhaseAResult          `json:"phase_a_details,omitempty"`
	PhaseBDetails         *phases.PhaseBResult          `json:"phase_b_details,omitempty"`
	PhaseCDetails         *phases.PhaseCResult          `json:"phase_c_details,omitempty"`
	PhaseDDetails         *phases.PhaseDResult          `json:"phase_d_details,omitempty"`
	PhaseEDetails         *phases.PhaseEResult          `json:"phase_e_details,omitempty"`
	RiskLifecycleDetails  *phases.RiskLifecycleResult   `json:"risk_lifecycle_details,omitempty"`
}

// NewScoreReport creates a new score report from all phase results
func NewScoreReport(
	phaseA *phases.PhaseAResult,
	phaseB *phases.PhaseBResult,
	phaseC *phases.PhaseCResult,
	phaseD *phases.PhaseDResult,
	phaseE *phases.PhaseEResult,
	riskLifecycle *phases.RiskLifecycleResult,
) *ScoreReport {
	calculator := NewScoreCalculator(DefaultScoringMatrix())

	return &ScoreReport{
		OverallScore:         calculator.CalculateOverallScore(phaseA, phaseB, phaseC, phaseD, phaseE, riskLifecycle),
		PhaseADetails:        phaseA,
		PhaseBDetails:        phaseB,
		PhaseCDetails:        phaseC,
		PhaseDDetails:        phaseD,
		PhaseEDetails:        phaseE,
		RiskLifecycleDetails: riskLifecycle,
	}
}

// Summary returns a human-readable summary of the overall score
func (s *OverallScore) Summary() string {
	return fmt.Sprintf(
		"WAF Benchmark Score: %.1f/%.0f (%.1f%%) - Grade: %s\n"+
			"  SEC (Security Effectiveness): %.1f/40\n"+
			"  PERF (Performance):           %.1f/20\n"+
			"  INT (Intelligence):           %.1f/20\n"+
			"  EXT (Extensibility):          %.1f/10\n"+
			"  ARCH (Architecture):          %.1f/15\n"+
			"  UI (Dashboard):               %.1f/10\n"+
			"  DEP (Deployment):             %.1f/5",
		s.Total, s.MaxPossible, s.Percentage, s.Grade,
		s.SecurityEffectiveness, s.Performance, s.Intelligence, s.Extensibility, s.Architecture, s.Dashboard, s.Deployment,
	)
}
