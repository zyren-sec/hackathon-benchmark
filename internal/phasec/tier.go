package phasec

import (
	"fmt"
	"os"
	"strings"
)

// ── Resource Tier ──

// ResourceTier defines the resource tier for the benchmark.
type ResourceTier string

const (
	TierMin  ResourceTier = "min"
	TierMid  ResourceTier = "mid"
	TierFull ResourceTier = "full"
)

// ParseResourceTier parses a string into a ResourceTier.
// Returns an error if the string is not a valid tier.
func ParseResourceTier(s string) (ResourceTier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "min":
		return TierMin, nil
	case "mid":
		return TierMid, nil
	case "full":
		return TierFull, nil
	default:
		return "", fmt.Errorf("invalid resource tier: %q (valid: min, mid, full)", s)
	}
}

// ── Tier Configuration ──

// TierConfig holds the resource configuration for a given tier.
type TierConfig struct {
	WAFCores       int
	WAFCpuset      string
	WAFMemoryMax   int64 // bytes
	BenchCores     int
	BenchCpuset    string
	BenchMemoryMax int64 // bytes
	SLA_RPS        int
	Stress_RPS     int
}

// GetTierConfig returns the TierConfig for the given resource tier.
func GetTierConfig(tier ResourceTier) TierConfig {
	switch tier {
	case TierMin:
		return TierConfig{
			WAFCores:       2,
			WAFCpuset:      "0-1",
			WAFMemoryMax:   4294967296, // 4 GB
			BenchCores:     1,
			BenchCpuset:    "2",
			BenchMemoryMax: 536870912, // 512 MB
			SLA_RPS:        2000,
			Stress_RPS:     5000,
		}
	case TierFull:
		return TierConfig{
			WAFCores:       6,
			WAFCpuset:      "0-5",
			WAFMemoryMax:   12884901888, // 12 GB
			BenchCores:     1,
			BenchCpuset:    "6",
			BenchMemoryMax: 2147483648, // 2 GB
			SLA_RPS:        5000,
			Stress_RPS:     10000,
		}
	default: // TierMid
		return TierConfig{
			WAFCores:       4,
			WAFCpuset:      "0-3",
			WAFMemoryMax:   8589934592, // 8 GB
			BenchCores:     2,
			BenchCpuset:    "4-5",
			BenchMemoryMax: 1610612736, // 1.5 GB
			SLA_RPS:        5000,
			Stress_RPS:     10000,
		}
	}
}

// ── Detection ──

// DetectResourceTier reads the WAF_RESOURCE_TIER environment variable
// and returns the corresponding ResourceTier. Defaults to TierMid.
func DetectResourceTier() ResourceTier {
	s := os.Getenv("WAF_RESOURCE_TIER")
	if s == "" {
		return TierMid
	}
	tier, err := ParseResourceTier(s)
	if err != nil {
		return TierMid
	}
	return tier
}

// ── Tier-Adjusted Load Test Steps ──

// GetTierAdjustedLoadTestSteps returns the load test steps with RPS targets
// adjusted for the given resource tier.
func GetTierAdjustedLoadTestSteps(tier ResourceTier) []LoadTestConfig {
	cfg := GetTierConfig(tier)

	// Scale factors relative to the MID tier (which uses SLA=5000, Stress=10000)
	// Step 1: 20% of SLA_RPS
	// Step 2: 60% of SLA_RPS
	// Step 3: SLA_RPS (SLA target)
	// Step 4: Stress_RPS (stress test)
	return []LoadTestConfig{
		{
			StepNum:     1,
			TargetRPS:   cfg.SLA_RPS * 20 / 100,
			DurationSec: 30,
			Marker:      "",
			Purpose:     "Baseline load",
		},
		{
			StepNum:     2,
			TargetRPS:   cfg.SLA_RPS * 60 / 100,
			DurationSec: 30,
			Marker:      "",
			Purpose:     "Intermediate",
		},
		{
			StepNum:     3,
			TargetRPS:   cfg.SLA_RPS,
			DurationSec: 60,
			Marker:      "⬤ SLA TARGET",
			Purpose:     "Evaluates PERF-01 & PERF-02",
		},
		{
			StepNum:     4,
			TargetRPS:   cfg.Stress_RPS,
			DurationSec: 60,
			Marker:      "⚡ STRESS TEST",
			Purpose:     "Evaluates PERF-04 (graceful degradation)",
		},
	}
}

// CgroupsV2Available checks whether cgroups v2 is available on the system.
func CgroupsV2Available() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}
