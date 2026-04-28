package waf

import (
	"strconv"
	"strings"
)

// WAF Observability Headers as defined in the specification
const (
	// X-WAF-Risk-Score indicates the risk score assigned to the request (0-100)
	HeaderRiskScore = "X-WAF-Risk-Score"

	// X-WAF-Action indicates the action taken by the WAF (allow, block, challenge, rate_limit)
	HeaderAction = "X-WAF-Action"

	// X-WAF-Request-Id is a unique identifier for the request
	HeaderRequestID = "X-WAF-Request-Id"

	// X-WAF-Rule-Id identifies the rule that triggered (if any)
	HeaderRuleID = "X-WAF-Rule-Id"

	// X-WAF-Cache indicates cache status (HIT, MISS, BYPASS)
	HeaderCacheStatus = "X-WAF-Cache"

	// Additional common headers that might be used by WAFs
	HeaderQueryTimeMs   = "X-Query-Time-Ms"
	HeaderInternalHost  = "X-Internal-Host"
	HeaderDebugQuery    = "X-Debug-Query"
)

// ExtractRiskScore extracts the risk score from response headers
// Returns the score and true if found, or 0 and false if not present/invalid
func ExtractRiskScore(headers map[string]string) (int, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, HeaderRiskScore) {
			score, err := strconv.Atoi(value)
			if err != nil {
				return 0, false
			}
			return score, true
		}
	}
	return 0, false
}

// ExtractAction extracts the WAF action from response headers
// Returns the action string and true if found
func ExtractAction(headers map[string]string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, HeaderAction) {
			return strings.ToLower(value), true
		}
	}
	return "", false
}

// ExtractRequestID extracts the request ID from response headers
func ExtractRequestID(headers map[string]string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, HeaderRequestID) {
			return value, true
		}
	}
	return "", false
}

// ExtractRuleID extracts the rule ID from response headers
func ExtractRuleID(headers map[string]string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, HeaderRuleID) {
			return value, true
		}
	}
	return "", false
}

// ExtractCacheStatus extracts the cache status from response headers
// Returns: "HIT", "MISS", "BYPASS", or empty string if not present
func ExtractCacheStatus(headers map[string]string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, HeaderCacheStatus) {
			return strings.ToUpper(value), true
		}
	}
	return "", false
}

// ExtractQueryTimeMs extracts the query execution time from response headers
// This is used for timing-based detection tests (e.g., blind SQL injection)
func ExtractQueryTimeMs(headers map[string]string) (int, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, HeaderQueryTimeMs) {
			time, err := strconv.Atoi(value)
			if err != nil {
				return 0, false
			}
			return time, true
		}
	}
	return 0, false
}

// ExtractInternalHost extracts the internal host header (for leak detection)
func ExtractInternalHost(headers map[string]string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, HeaderInternalHost) {
			return value, true
		}
	}
	return "", false
}

// ExtractDebugQuery extracts the debug query header (for leak detection)
func ExtractDebugQuery(headers map[string]string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, HeaderDebugQuery) {
			return value, true
		}
	}
	return "", false
}

// HasRiskScore returns true if the response contains a risk score header
func HasRiskScore(headers map[string]string) bool {
	_, exists := ExtractRiskScore(headers)
	return exists
}

// HasCacheStatus returns true if the response contains a cache status header
func HasCacheStatus(headers map[string]string) bool {
	_, exists := ExtractCacheStatus(headers)
	return exists
}

// GetAllWAFHeaders extracts all WAF-related observability headers from the response
// Returns a map of all WAF headers found
func GetAllWAFHeaders(headers map[string]string) map[string]string {
	wafHeaders := make(map[string]string)

	wafHeaderNames := []string{
		HeaderRiskScore,
		HeaderAction,
		HeaderRequestID,
		HeaderRuleID,
		HeaderCacheStatus,
		HeaderQueryTimeMs,
		HeaderInternalHost,
		HeaderDebugQuery,
	}

	for _, headerName := range wafHeaderNames {
		for key, value := range headers {
			if strings.EqualFold(key, headerName) {
				wafHeaders[headerName] = value
				break
			}
		}
	}

	return wafHeaders
}

// ObservabilitySummary provides a summary of all WAF observability data
type ObservabilitySummary struct {
	RiskScore   int    `json:"risk_score"`
	Action      string `json:"action"`
	RequestID   string `json:"request_id"`
	RuleID      string `json:"rule_id"`
	CacheStatus string `json:"cache_status"`
}

// ExtractObservabilitySummary extracts a summary of all observability data
func ExtractObservabilitySummary(headers map[string]string) ObservabilitySummary {
	summary := ObservabilitySummary{}

	if score, ok := ExtractRiskScore(headers); ok {
		summary.RiskScore = score
	}

	if action, ok := ExtractAction(headers); ok {
		summary.Action = action
	}

	if reqID, ok := ExtractRequestID(headers); ok {
		summary.RequestID = reqID
	}

	if ruleID, ok := ExtractRuleID(headers); ok {
		summary.RuleID = ruleID
	}

	if cache, ok := ExtractCacheStatus(headers); ok {
		summary.CacheStatus = cache
	}

	return summary
}

// IsCacheHit returns true if the cache status indicates a cache hit
func IsCacheHit(headers map[string]string) bool {
	status, exists := ExtractCacheStatus(headers)
	if !exists {
		return false
	}
	return status == "HIT" || status == "hit"
}

// IsCacheMiss returns true if the cache status indicates a cache miss
func IsCacheMiss(headers map[string]string) bool {
	status, exists := ExtractCacheStatus(headers)
	if !exists {
		return false
	}
	return status == "MISS" || status == "miss"
}

// GetHeaderByName extracts a header value by name (case-insensitive)
func GetHeaderByName(headers map[string]string, name string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

// HeaderNames returns a list of all header names in the response
func HeaderNames(headers map[string]string) []string {
	names := make([]string, 0, len(headers))
	for key := range headers {
		names = append(names, key)
	}
	return names
}

// HasHeader checks if a header exists (case-insensitive)
func HasHeader(headers map[string]string, name string) bool {
	_, exists := GetHeaderByName(headers, name)
	return exists
}
