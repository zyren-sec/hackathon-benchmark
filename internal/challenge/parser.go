package challenge

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ── Format A: JSON Challenge ──

// jsonChallengeBody matches the JSON challenge format from 429_challenge.md §1.
type jsonChallengeBody struct {
	Challenge      bool   `json:"challenge"`
	ChallengeType  string `json:"challenge_type"`
	ChallengeToken string `json:"challenge_token"`
	SubmitURL      string `json:"submit_url"`
	SubmitMethod   string `json:"submit_method"`
	SessionToken   string `json:"session_token"` // optional, for session extraction
}

// parseJSONChallenge parses a JSON-format challenge body.
func parseJSONChallenge(body string) *ChallengeInfo {
	var cb jsonChallengeBody
	if err := json.Unmarshal([]byte(body), &cb); err != nil {
		return nil
	}

	// Must have challenge: true
	if !cb.Challenge {
		return nil
	}

	// Must have challenge_token
	if cb.ChallengeToken == "" {
		return nil
	}

	// submit_url is required per spec §1
	if cb.SubmitURL == "" {
		return nil
	}

	method := cb.SubmitMethod
	if method == "" {
		method = "POST"
	}

	return &ChallengeInfo{
		Format:         "json",
		ChallengeToken: cb.ChallengeToken,
		SubmitURL:      cb.SubmitURL,
		SubmitMethod:   method,
		RawBody:        body,
	}
}

// ── Format B: HTML Challenge ──

var (
	// formActionRe extracts the action attribute from a <form> tag
	formActionRe = regexp.MustCompile(`(?i)<form[^>]*\s+action\s*=\s*["']([^"']+)["']`)

	// challengeTokenRe extracts challenge_token from an <input> tag
	challengeTokenRe = regexp.MustCompile(`(?i)<input[^>]*\s+name\s*=\s*["']challenge_token["'][^>]*\s+value\s*=\s*["']([^"']+)["']`)

	// altChallengeTokenRe handles value before name attribute
	altChallengeTokenRe = regexp.MustCompile(`(?i)<input[^>]*\s+value\s*=\s*["']([^"']+)["'][^>]*\s+name\s*=\s*["']challenge_token["']`)
)

// parseHTMLChallenge parses an HTML-format challenge body.
func parseHTMLChallenge(body string) *ChallengeInfo {
	// Extract form action (submit_url)
	actionMatch := formActionRe.FindStringSubmatch(body)
	if actionMatch == nil {
		return nil
	}
	submitURL := strings.TrimSpace(actionMatch[1])

	// Extract challenge_token
	tokenMatch := challengeTokenRe.FindStringSubmatch(body)
	if tokenMatch == nil {
		tokenMatch = altChallengeTokenRe.FindStringSubmatch(body)
	}
	if tokenMatch == nil {
		return nil
	}
	challengeToken := strings.TrimSpace(tokenMatch[1])

	if challengeToken == "" || submitURL == "" {
		return nil
	}

	return &ChallengeInfo{
		Format:         "html",
		ChallengeToken: challengeToken,
		SubmitURL:      submitURL,
		SubmitMethod:   "POST",
		RawBody:        body,
	}
}

// ExtractSessionCookie extracts a session cookie from Set-Cookie response headers.
// Returns (cookieName, cookieValue) or ("", "").
func ExtractSessionCookie(headers map[string]string) (string, string) {
	for k, v := range headers {
		if strings.EqualFold(k, "Set-Cookie") {
			// Parse: "sid=abc123; Path=/; HttpOnly"
			parts := strings.SplitN(v, ";", 2)
			kv := strings.SplitN(strings.TrimSpace(parts[0]), "=", 2)
			if len(kv) == 2 {
				return kv[0], kv[1]
			}
		}
	}
	return "", ""
}

// ExtractSessionTokenJSON extracts session_token from a JSON response body.
func ExtractSessionTokenJSON(body string) string {
	var resp struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return ""
	}
	return resp.SessionToken
}
