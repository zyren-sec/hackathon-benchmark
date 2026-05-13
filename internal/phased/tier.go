package phased

import (
	"github.com/waf-hackathon/benchmark-new/internal/phasec"
)

// ── DFloodParams ──

// DFloodParams holds tier-adjusted flood parameters for Phase D tests.
type DFloodParams struct {
	Wrk2Connections      int
	Wrk2Threads          int
	Wrk2Duration         int
	SlowhttptestConns    int
	SlowhttptestDuration int
	SlowlorisDuration    int
	RudyRate             int
	RudyDuration         int
	D04_Wrk2Conns        int
}

// ── GetDTierFloodParams ──

// GetDTierFloodParams returns flood parameters adjusted for the given resource tier.
func GetDTierFloodParams(tier phasec.ResourceTier) DFloodParams {
	switch tier {
	case phasec.TierMin:
		return DFloodParams{
			Wrk2Connections:      200,
			Wrk2Threads:          2,
			Wrk2Duration:         45,
			SlowhttptestConns:    500,
			SlowhttptestDuration: 30,
			SlowlorisDuration:    30,
			RudyRate:             5,
			RudyDuration:         45,
			D04_Wrk2Conns:        200,
		}
	case phasec.TierFull:
		return DFloodParams{
			Wrk2Connections:      1000,
			Wrk2Threads:          6,
			Wrk2Duration:         60,
			SlowhttptestConns:    2000,
			SlowhttptestDuration: 40,
			SlowlorisDuration:    40,
			RudyRate:             10,
			RudyDuration:         60,
			D04_Wrk2Conns:        1000,
		}
	default: // phasec.TierMid
		return DFloodParams{
			Wrk2Connections:      500,
			Wrk2Threads:          4,
			Wrk2Duration:         60,
			SlowhttptestConns:    1000,
			SlowhttptestDuration: 40,
			SlowlorisDuration:    40,
			RudyRate:             10,
			RudyDuration:         60,
			D04_Wrk2Conns:        500,
		}
	}
}

// ── GetTierFlags ──

// GetTierFlags returns diagnostic flags for the given resource tier.
// TIER-MIN returns ["RESOURCE_CONSTRAINED", "POTENTIALLY_NOISY"]; others return nil.
func GetTierFlags(tier phasec.ResourceTier) []string {
	switch tier {
	case phasec.TierMin:
		return []string{"RESOURCE_CONSTRAINED", "POTENTIALLY_NOISY"}
	default:
		return nil
	}
}

// ── GetTierSamplingMs ──

// GetTierSamplingMs returns the sampling interval in milliseconds for the given tier.
// TIER-MIN returns 500; others return 1000.
func GetTierSamplingMs(tier phasec.ResourceTier) int {
	switch tier {
	case phasec.TierMin:
		return 500
	default:
		return 1000
	}
}
