package waf

import (
	"bytes"
	"strings"
)

// Decision represents the WAF's decision for a request
type Decision int

const (
	// Allow means the request was allowed through to the target
	Allow Decision = iota
	// Block means the request was blocked (403 Forbidden)
	Block
	// Challenge means the request was challenged (429 with challenge)
	Challenge
	// RateLimit means the request was rate limited (429 without challenge)
	RateLimit
	// CircuitBreaker means the WAF activated circuit breaker (503)
	CircuitBreaker
	// Timeout means the request timed out (504)
	Timeout
	// UpstreamError means there was an error connecting to upstream
	UpstreamError
	// PreventedSanitized means the exploit was prevented/sanitized (200 OK but no markers)
	PreventedSanitized
	// ExploitPassed means the exploit succeeded (200 OK with markers)
	ExploitPassed
	// Unknown means the decision couldn't be determined
	Unknown
)

// String returns the string representation of the decision
func (d Decision) String() string {
	switch d {
	case Allow:
		return "Allow"
	case Block:
		return "Block"
	case Challenge:
		return "Challenge"
	case RateLimit:
		return "RateLimit"
	case CircuitBreaker:
		return "CircuitBreaker"
	case Timeout:
		return "Timeout"
	case UpstreamError:
		return "UpstreamError"
	case PreventedSanitized:
		return "PreventedSanitized"
	case ExploitPassed:
		return "ExploitPassed"
	case Unknown:
		return "Unknown"
	default:
		return "Unknown"
	}
}

// IsPrevented returns true if the WAF prevented the attack
func (d Decision) IsPrevented() bool {
	switch d {
	case Block, Challenge, RateLimit, CircuitBreaker, PreventedSanitized:
		return true
	default:
		return false
	}
}

// IsBypassed returns true if the exploit bypassed the WAF
func (d Decision) IsBypassed() bool {
	return d == ExploitPassed
}

// IsError returns true if there was an error processing the request
func (d Decision) IsError() bool {
	switch d {
	case Timeout, UpstreamError:
		return true
	default:
		return false
	}
}

// Classify determines the WAF decision based on response characteristics
// per the specification:
// - 403 → Block
// - 429 + body contains "challenge" → Challenge
// - 429 alone → RateLimit
// - 503 → CircuitBreaker
// - 504 → Timeout
// - 200 + markers → ExploitPassed (exploit succeeded)
// - 200 no markers → PreventedSanitized
func Classify(statusCode int, body []byte, headers map[string]string) Decision {
	switch statusCode {
	case 403:
		return Block

	case 429:
		// Check if body contains "challenge" to distinguish Challenge from RateLimit
		if containsChallenge(body, headers) {
			return Challenge
		}
		return RateLimit

	case 503:
		return CircuitBreaker

	case 504:
		return Timeout

	case 502, 505:
		return UpstreamError

	case 200:
		// Check for proof markers in response
		if hasMarkers(body, headers) {
			return ExploitPassed
		}
		return PreventedSanitized

	default:
		// For other status codes, check for markers
		if hasMarkers(body, headers) {
			return ExploitPassed
		}
		return Unknown
	}
}

// containsChallenge checks if the response indicates a challenge was presented
func containsChallenge(body []byte, headers map[string]string) bool {
	bodyStr := string(bytes.ToLower(body))

	// Check body for challenge indicators
	challengeIndicators := []string{
		"challenge",
		"captcha",
		"proof-of-work",
		"pow",
		"javascript challenge",
		"js challenge",
		"please wait",
		"verification",
		"verify you are human",
	}

	for _, indicator := range challengeIndicators {
		if strings.Contains(bodyStr, indicator) {
			return true
		}
	}

	// Check for challenge-related headers
	challengeHeaders := []string{
		"x-challenge-token",
		"x-pow-challenge",
		"cf-challenge",
		"x-js-challenge",
	}

	for _, header := range challengeHeaders {
		for key := range headers {
			if strings.EqualFold(key, header) {
				return true
			}
		}
	}

	return false
}

// hasMarkers checks if proof markers exist in the response
func hasMarkers(body []byte, headers map[string]string) bool {
	// Check body for markers using regex pattern: __[VL]\d+[a-b]?_\w+__
	bodyStr := string(body)

	// Simple check for marker pattern start
	if strings.Contains(bodyStr, "__V") || strings.Contains(bodyStr, "__L") {
		return true
	}

	// Check headers for markers
	for _, value := range headers {
		if strings.Contains(value, "__V") || strings.Contains(value, "__L") {
			return true
		}
	}

	return false
}

// ClassifyWithDetails returns the decision along with detailed classification info
func ClassifyWithDetails(statusCode int, body []byte, headers map[string]string) (Decision, map[string]interface{}) {
	decision := Classify(statusCode, body, headers)

	details := map[string]interface{}{
		"status_code":        statusCode,
		"decision":           decision.String(),
		"body_length":        len(body),
		"has_challenge_body": containsChallenge(body, headers),
		"has_markers":        hasMarkers(body, headers),
	}

	return decision, details
}
