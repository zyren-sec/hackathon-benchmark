package challenge

import "strings"

// IsChallenge checks whether an HTTP response represents a WAF 429 challenge.
// Returns true when status code is 429 AND X-WAF-Action header is "challenge".
func IsChallenge(statusCode int, headers map[string]string) bool {
	if statusCode != 429 {
		return false
	}
	for k, v := range headers {
		if strings.EqualFold(k, "X-WAF-Action") && strings.EqualFold(strings.TrimSpace(v), "challenge") {
			return true
		}
	}
	return false
}

// DetectChallenge examines a response body and headers to determine
// if it's a challenge and extracts challenge info.
// Returns nil if no challenge is detected.
func DetectChallenge(statusCode int, body string, headers map[string]string) *ChallengeInfo {
	if !IsChallenge(statusCode, headers) {
		return nil
	}

	// Determine content type
	contentType := ""
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			contentType = strings.TrimSpace(v)
			break
		}
	}

	// Try Format A: JSON
	if strings.Contains(contentType, "application/json") || looksLikeJSONChallenge(body) {
		info := parseJSONChallenge(body)
		if info != nil {
			return info
		}
	}

	// Try Format B: HTML
	if strings.Contains(contentType, "text/html") || looksLikeHTMLChallenge(body) {
		info := parseHTMLChallenge(body)
		if info != nil {
			return info
		}
	}

	// Neither format detected — still a challenge but unparseable
	return &ChallengeInfo{
		Format:  "unknown",
		RawBody: body,
	}
}

// looksLikeJSONChallenge heuristically checks if body starts with JSON challenge format.
func looksLikeJSONChallenge(body string) bool {
	trimmed := strings.TrimSpace(body)
	return strings.HasPrefix(trimmed, "{") && strings.Contains(trimmed, `"challenge"`)
}

// looksLikeHTMLChallenge heuristically checks if body contains HTML form with challenge_token.
func looksLikeHTMLChallenge(body string) bool {
	return strings.Contains(body, "<form") && strings.Contains(body, "challenge_token")
}
