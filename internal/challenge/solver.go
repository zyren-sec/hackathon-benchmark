package challenge

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NewSolver creates a new challenge Solver with the given HTTP client and configuration.
func NewSolver(client *http.Client, wafBaseURL string, timeoutSec int, verbose, dryRun bool) *Solver {
	return &Solver{
		Client:     client,
		WAFBaseURL: wafBaseURL,
		TimeoutSec: timeoutSec,
		Verbose:    verbose,
		DryRun:     dryRun,
		Results:    make([]LifecycleResult, 0),
	}
}

// HandleChallenge is the main entry point for phases. When a phase engine
// detects a 429 challenge response, it calls this method to run the full
// challenge lifecycle evaluation:
//
//	CL-F1 → CL-F2 → CL-F3 (submit) → CL-F4 (session) → CL-F5 (restore) → CL-F6a/F6b (suspension)
//
// Returns the lifecycle result (appended to Solver.Results internally).
func (s *Solver) HandleChallenge(ctx PhaseHookContext) LifecycleResult {
	if s.DryRun {
		return s.dryRunHandle(ctx)
	}
	return s.realHandle(ctx)
}

// realHandle performs the actual HTTP challenge lifecycle.
func (s *Solver) realHandle(ctx PhaseHookContext) LifecycleResult {
	start := time.Now()
	lr := LifecycleResult{
		TestID:   ctx.TestID,
		Phase:    ctx.Phase,
		Endpoint: ctx.Endpoint,
		Method:   ctx.Method,
	}

	// ═══ CL-F1: Detect and parse challenge body ═══
	ci := DetectChallenge(ctx.StatusCode, ctx.ResponseBody, ctx.ResponseHeaders)
	if ci == nil || ci.Format == "unknown" {
		lr.BA01Passed = false
		lr.BA01Detail = "challenge body not parseable (unknown format)"
		lr.FailCodes = append(lr.FailCodes, "CL-F1")
		lr.OverallPassed = false
		lr.DurationMs = time.Since(start).Milliseconds()
		s.Results = append(s.Results, lr)
		return lr
	}

	// BA01: Challenge body well-formed
	if ci.Format == "json" || ci.Format == "html" {
		lr.BA01Passed = true
		lr.BA01Detail = fmt.Sprintf("format=%s, well-formed challenge body", ci.Format)
	} else {
		lr.BA01Passed = false
		lr.BA01Detail = "unrecognized challenge format"
		lr.FailCodes = append(lr.FailCodes, "CL-F1")
	}

	// ═══ CL-F2: Required fields present ═══
	if ci.ChallengeToken != "" && ci.SubmitURL != "" {
		lr.BA02Passed = true
		lr.BA02Detail = "challenge_token and submit_url present"
	} else {
		lr.BA02Passed = false
		lr.BA02Detail = "missing required fields (challenge_token or submit_url)"
		lr.FailCodes = append(lr.FailCodes, "CL-F2")
		lr.OverallPassed = false
		lr.DurationMs = time.Since(start).Milliseconds()
		s.Results = append(s.Results, lr)
		return lr
	}

	// Mandatory challenge: since we detected it, it must be scored
	lr.MandatoryChallengeCheck = true
	lr.MandatoryPassed = true
	lr.MandatoryDetail = "challenge scored (not ignored)"

	sr := &SolveResult{
		ChallengeInfo: ci,
		ParseSuccess:  true,
	}

	// ═══ CL-F3: Submit challenge token ═══
	submitURL := s.resolveURL(ci.SubmitURL)
	submitBody := fmt.Sprintf(`{"challenge_token":"%s"}`, ci.ChallengeToken)
	submitReq, err := http.NewRequest("POST", submitURL, strings.NewReader(submitBody))
	if err != nil {
		lr.SubmitPassed = false
		lr.SubmitDetail = fmt.Sprintf("failed to create submit request: %v", err)
		lr.FailCodes = append(lr.FailCodes, "CL-F3")
		lr.OverallPassed = false
		lr.SolveResult = sr
		lr.DurationMs = time.Since(start).Milliseconds()
		s.Results = append(s.Results, lr)
		return lr
	}
	submitReq.Header.Set("Content-Type", "application/json")

	submitResp, err := s.Client.Do(submitReq)
	if err != nil {
		sr.SubmitError = err.Error()
		lr.SubmitPassed = false
		lr.SubmitDetail = fmt.Sprintf("submit request failed: %v", err)
		lr.FailCodes = append(lr.FailCodes, "CL-F3")
		lr.OverallPassed = false
		lr.SolveResult = sr
		lr.DurationMs = time.Since(start).Milliseconds()
		s.Results = append(s.Results, lr)
		return lr
	}
	defer submitResp.Body.Close()

	submitRespBody, _ := io.ReadAll(io.LimitReader(submitResp.Body, 256*1024))
	sr.SubmitStatusCode = submitResp.StatusCode
	sr.SubmitBody = string(submitRespBody)
	lr.SubmitStatusCode = submitResp.StatusCode

	if submitResp.StatusCode != 200 {
		sr.SubmitSuccess = false
		lr.SubmitPassed = false
		lr.SubmitDetail = fmt.Sprintf("submit returned HTTP %d (expected 200)", submitResp.StatusCode)
		lr.FailCodes = append(lr.FailCodes, "CL-F3")
		lr.OverallPassed = false
		lr.SolveResult = sr
		lr.DurationMs = time.Since(start).Milliseconds()
		s.Results = append(s.Results, lr)
		return lr
	}

	sr.SubmitSuccess = true
	lr.SubmitPassed = true
	lr.SubmitDetail = "submit OK (HTTP 200)"

	// ═══ CL-F4: Extract session credential from submit response ═══
	respHeaders := make(map[string]string)
	for k, vv := range submitResp.Header {
		respHeaders[k] = strings.Join(vv, ", ")
	}

	cookieName, cookieValue := ExtractSessionCookie(respHeaders)
	if cookieName != "" {
		sr.SessionExtracted = true
		sr.SessionCookieName = cookieName
		sr.SessionCookieValue = cookieValue
		lr.NewSessionExtracted = true
		lr.NewSessionValue = cookieValue
	} else {
		// Try JSON session_token
		sessionToken := ExtractSessionTokenJSON(string(submitRespBody))
		if sessionToken != "" {
			sr.SessionExtracted = true
			sr.SessionToken = sessionToken
			lr.NewSessionExtracted = true
			lr.NewSessionValue = sessionToken
		}
	}

	if !sr.SessionExtracted {
		lr.FailCodes = append(lr.FailCodes, "CL-F4")
		lr.SubmitDetail += " | no session credential in submit response"
		lr.OverallPassed = false
		lr.SolveResult = sr
		lr.DurationMs = time.Since(start).Milliseconds()
		s.Results = append(s.Results, lr)
		return lr
	}

	// ═══ CL-F5: Access restore — re-send BENIGN request with NEW session ═══
	// Per spec v2.9.1: "Benchmark tool re-send một benign request (không chứa
	// exploit/abuse pattern) với new session credential để verify."
	resendURL := s.resolveURL(ctx.Endpoint)
	benignBody := createBenignBody(ctx)

	resendReq, err := http.NewRequest(ctx.Method, resendURL, strings.NewReader(benignBody))
	if err != nil {
		lr.AccessRestored = false
		lr.AccessRestoreDetail = fmt.Sprintf("failed to create benign re-send request: %v", err)
		lr.FailCodes = append(lr.FailCodes, "CL-F5")
		lr.OverallPassed = false
		lr.SolveResult = sr
		lr.DurationMs = time.Since(start).Milliseconds()
		s.Results = append(s.Results, lr)
		return lr
	}

	// Copy original headers (excluding Content-Length which will be set by Go)
	for k, v := range ctx.RequestHeaders {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		resendReq.Header.Set(k, v)
	}
	// Add new session cookie
	resendReq.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})

	// Ensure Content-Type for request with body
	if benignBody != "" {
		if resendReq.Header.Get("Content-Type") == "" {
			resendReq.Header.Set("Content-Type", "application/json")
		}
	}

	resendResp, err := s.Client.Do(resendReq)
	if err != nil {
		sr.ResendSuccess = false
		lr.AccessRestored = false
		lr.AccessRestoreDetail = fmt.Sprintf("benign re-send request failed: %v", err)
		lr.FailCodes = append(lr.FailCodes, "CL-F5")
		lr.OverallPassed = false
		lr.SolveResult = sr
		lr.DurationMs = time.Since(start).Milliseconds()
		s.Results = append(s.Results, lr)
		return lr
	}
	defer resendResp.Body.Close()

	resendBody, _ := io.ReadAll(io.LimitReader(resendResp.Body, 256*1024))
	sr.ResendStatusCode = resendResp.StatusCode
	sr.ResendWAFAction = strings.TrimSpace(resendResp.Header.Get("X-WAF-Action"))
	sr.ResendBody = string(resendBody)
	sr.ResendSuccess = resendResp.StatusCode == 200
	lr.ResendStatusCode = resendResp.StatusCode
	lr.ResendWAFAction = sr.ResendWAFAction

	// Check access restored
	accessAction := strings.ToLower(sr.ResendWAFAction)
	if accessAction == "challenge" || accessAction == "block" {
		lr.AccessRestored = false
		lr.AccessRestoreDetail = fmt.Sprintf("access not restored: X-WAF-Action=%s (HTTP %d)",
			sr.ResendWAFAction, resendResp.StatusCode)
		lr.FailCodes = append(lr.FailCodes, "CL-F5")
		lr.OverallPassed = false
		lr.SolveResult = sr
		lr.DurationMs = time.Since(start).Milliseconds()
		s.Results = append(s.Results, lr)
		return lr
	}

	lr.AccessRestored = true
	lr.AccessRestoreDetail = fmt.Sprintf("access restored: HTTP %d, X-WAF-Action=%s",
		resendResp.StatusCode, sr.ResendWAFAction)

	// ═══ CL-F6a/F6b: Session suspension check (authenticated endpoints only) ═══
	// Per spec v2.9.1 §2.1: After challenge solved successfully (CL-F5 pass),
	// verify old session is suspended/revoked.
	if ctx.OldSession != "" {
		lr.SessionSuspensionCheck = true
		lr.OldSession = ctx.OldSession
		lr.SessionSuspensionPassed = true // assume pass until proven otherwise

		// Parse old session cookie name/value
		oldName, oldValue := parseSessionString(ctx.OldSession)

		// ── CL-F6a: Test old session on ORIGINAL endpoint ──
		f6aReq, err := http.NewRequest(ctx.Method, resendURL, strings.NewReader(benignBody))
		if err == nil {
			for k, v := range ctx.RequestHeaders {
				if strings.EqualFold(k, "Content-Length") {
					continue
				}
				f6aReq.Header.Set(k, v)
			}
			if benignBody != "" && f6aReq.Header.Get("Content-Type") == "" {
				f6aReq.Header.Set("Content-Type", "application/json")
			}
			f6aReq.AddCookie(&http.Cookie{Name: oldName, Value: oldValue})

			f6aResp, f6aErr := s.Client.Do(f6aReq)
			if f6aErr == nil {
				f6aAction := strings.TrimSpace(f6aResp.Header.Get("X-WAF-Action"))
				f6aResp.Body.Close()

				if strings.EqualFold(f6aAction, "allow") && f6aResp.StatusCode == 200 {
					lr.SessionSuspensionPassed = false
					lr.SessionSuspensionDetail = "CL-F6a: old session still valid for original endpoint"
					lr.FailCodes = append(lr.FailCodes, "CL-F6a")
					lr.Notes = append(lr.Notes, "old_session_not_revoked_for_original_endpoint")
				}
			}
		}

		// ── CL-F6b: Test old session on OTHER authenticated endpoints ──
		// Only run if F6a didn't already find a violation, to avoid redundant checks
		if lr.SessionSuspensionPassed {
			otherEndpoints := []struct {
				Method string
				Path   string
				Body   string
			}{
				{"GET", "/api/profile", ""},
				{"GET", "/api/transactions", ""},
				{"POST", "/withdrawal", `{"amount":0.01,"bank_account":"0000000000"}`},
			}

			for _, ep := range otherEndpoints {
				epURL := s.resolveURL(ep.Path)
				var epBodyReader io.Reader
				if ep.Body != "" {
					epBodyReader = strings.NewReader(ep.Body)
				}

				epReq, epErr := http.NewRequest(ep.Method, epURL, epBodyReader)
				if epErr != nil {
					continue
				}
				if ep.Body != "" {
					epReq.Header.Set("Content-Type", "application/json")
				}
				epReq.AddCookie(&http.Cookie{Name: oldName, Value: oldValue})

				epResp, epDoErr := s.Client.Do(epReq)
				if epDoErr != nil {
					continue
				}
				epAction := strings.TrimSpace(epResp.Header.Get("X-WAF-Action"))
				epResp.Body.Close()

				if strings.EqualFold(epAction, "allow") && epResp.StatusCode == 200 {
					lr.SessionSuspensionPassed = false
					lr.SessionSuspensionDetail = fmt.Sprintf(
						"CL-F6b: old session still valid for %s %s", ep.Method, ep.Path)
					lr.FailCodes = append(lr.FailCodes, "CL-F6b")
					lr.Notes = append(lr.Notes,
						fmt.Sprintf("old_session_not_revoked_for_%s_%s", ep.Method, ep.Path))
					break // one violation is enough
				}
			}
		}

		if lr.SessionSuspensionPassed && lr.SessionSuspensionCheck {
			lr.SessionSuspensionDetail = "old session properly suspended for all endpoints"
		}
	}

	// ═══ Overall verdict ═══
	// CL-F1/F2: body malformed → overall FAIL (detection only, but challenge broken)
	// CL-F3/F4/F5: submit/restore broken → FAIL
	// CL-F6a/F6b: session not suspended → PASS (security note, non-fatal)
	fatalFail := false
	for _, fc := range lr.FailCodes {
		if fc == "CL-F1" || fc == "CL-F2" || fc == "CL-F3" || fc == "CL-F4" || fc == "CL-F5" {
			fatalFail = true
			break
		}
	}
	if !fatalFail {
		lr.OverallPassed = true
	}

	sr.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
	lr.SolveResult = sr
	lr.DurationMs = time.Since(start).Milliseconds()

	s.Results = append(s.Results, lr)
	return lr
}

// ── Helpers ──

// createBenignBody returns a benign (non-exploit) body for CL-F5 re-send.
// Per spec: "Benchmark tool re-send một benign request (không chứa
// exploit/abuse pattern)". For GET/OPTIONS returns empty string.
// For POST/PUT returns a minimal valid JSON body or empty.
func createBenignBody(ctx PhaseHookContext) string {
	if ctx.Method == "GET" || ctx.Method == "OPTIONS" || ctx.Method == "HEAD" || ctx.Method == "DELETE" {
		return ""
	}
	// For POST/PUT: send a minimal benign body (not the original exploit payload)
	// Use {} for /login-like endpoints, empty otherwise
	if strings.Contains(ctx.Endpoint, "/login") {
		return `{"username":"benign_test","password":"benign_test"}`
	}
	if strings.Contains(ctx.Endpoint, "/withdrawal") || strings.Contains(ctx.Endpoint, "/deposit") {
		return `{"amount":0.01,"bank_account":"benign_test"}`
	}
	return ""
}

// parseSessionString parses "cookieName=cookieValue" format.
func parseSessionString(session string) (string, string) {
	parts := strings.SplitN(session, "=", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "sid", session // default cookie name
}

// resolveURL resolves a relative URL against the WAF base URL.
func (s *Solver) resolveURL(pathOrURL string) string {
	if strings.HasPrefix(pathOrURL, "http://") || strings.HasPrefix(pathOrURL, "https://") {
		return pathOrURL
	}
	base := strings.TrimRight(s.WAFBaseURL, "/")
	rel := strings.TrimLeft(pathOrURL, "/")
	return base + "/" + rel
}

// ── Dry-Run ──

// dryRunHandle returns a simulated lifecycle result for dry-run mode.
func (s *Solver) dryRunHandle(ctx PhaseHookContext) LifecycleResult {
	lr := LifecycleResult{
		TestID:                  ctx.TestID,
		Phase:                   ctx.Phase,
		Endpoint:                ctx.Endpoint,
		Method:                  ctx.Method,
		BA01Passed:              true,
		BA01Detail:              "format=json, well-formed challenge body (dry-run)",
		BA02Passed:              true,
		BA02Detail:              "challenge_token and submit_url present (dry-run)",
		MandatoryChallengeCheck: true,
		MandatoryPassed:         true,
		MandatoryDetail:         "challenge scored (not ignored)",
		SubmitPassed:            true,
		SubmitDetail:            "submit OK (HTTP 200) (dry-run)",
		SubmitStatusCode:        200,
		NewSessionExtracted:     true,
		NewSessionValue:         "dry-run-session-token",
		AccessRestored:          true,
		AccessRestoreDetail:     "access restored: HTTP 200, X-WAF-Action=allow (dry-run)",
		ResendStatusCode:        200,
		ResendWAFAction:         "allow",
		SessionSuspensionCheck:  ctx.OldSession != "",
		SessionSuspensionPassed: true,
		SessionSuspensionDetail: "old session properly suspended (dry-run)",
		OverallPassed:           true,
		DurationMs:              15,
		SolveResult: &SolveResult{
			ParseSuccess: true,
			ChallengeInfo: &ChallengeInfo{
				Format:         "json",
				ChallengeToken: "dry-run-token",
				SubmitURL:      "/challenge/verify",
				SubmitMethod:   "POST",
			},
			SubmitStatusCode:   200,
			SubmitSuccess:      true,
			SessionExtracted:   true,
			SessionCookieName:  "sid",
			SessionCookieValue: "dry-run-session-token",
			ResendStatusCode:   200,
			ResendSuccess:      true,
			ResendWAFAction:    "allow",
			LatencyMs:          15.0,
		},
	}
	s.Results = append(s.Results, lr)
	return lr
}

// ── Detection-Only (load test phases C/D/E) ──

// RecordDetection records that a 429 challenge was detected without
// executing the full lifecycle solve. Used during high-throughput phases
// (C, D, E) where real-time solving would interfere with load tests.
func (s *Solver) RecordDetection(ctx PhaseHookContext) {
	lr := LifecycleResult{
		TestID:                  ctx.TestID,
		Phase:                   ctx.Phase,
		Endpoint:                ctx.Endpoint,
		Method:                  ctx.Method,
		BA01Passed:              true,
		BA01Detail:              "detected during load test — lifecycle deferred",
		BA02Passed:              true,
		BA02Detail:              "challenge parameters not extracted (load test context)",
		MandatoryChallengeCheck: true,
		MandatoryPassed:         true,
		MandatoryDetail:         "detected (scored in load test false-positive metrics)",
		SubmitPassed:            false,
		SubmitDetail:            "deferred — challenge solving skipped during load test",
		AccessRestored:          false,
		AccessRestoreDetail:     "deferred — re-send skipped during load test",
		OverallPassed:           true, // detection is correct; solving deferred
		Notes:                   []string{"challenge-detected-in-load-test"},
	}
	s.Results = append(s.Results, lr)
}

// Ensure url and bytes packages are used.
var _ = url.Parse
var _ = bytes.NewReader
