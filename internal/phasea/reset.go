package phasea

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

// ResetClient handles UPSTREAM and WAF Admin API calls for state management.
type ResetClient struct {
	targetBaseURL string
	wafAdminURL   string
	controlSecret string
	client        *http.Client
}

// NewResetClient creates a new reset/control client.
func NewResetClient(targetBaseURL, wafAdminURL, controlSecret string, timeoutSec int) *ResetClient {
	return &ResetClient{
		targetBaseURL: targetBaseURL,
		wafAdminURL:   wafAdminURL,
		controlSecret: controlSecret,
		client: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
	}
}

// FullResetSequence executes the 5-step reset per spec §3.1.
// Steps 1-3,5 are fatal. Step 4 is non-fatal (warn only).
func (rc *ResetClient) FullResetSequence() []ResetStep {
	var steps []ResetStep

	step := func(num int, name, method, url string, body string, fatal bool) ResetStep {
		rs := ResetStep{
			StepNum: num,
			Name:    name,
			Method:  method,
			URL:     url,
		}
		start := time.Now()

		req, err := http.NewRequest(method, url, bytes.NewReader([]byte(body)))
		if err != nil {
			rs.Error = err.Error()
			rs.LatencyMs = time.Since(start).Seconds() * 1000
			return rs
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("X-Benchmark-Secret", rc.controlSecret)

		// Retry up to 3 times with 2s backoff
		var resp *http.Response
		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(2 * time.Second)
			}
			resp, err = rc.client.Do(req)
			if err == nil {
				break
			}
		}

		rs.LatencyMs = time.Since(start).Seconds() * 1000

		if err != nil {
			rs.Error = err.Error()
			rs.Success = false
			return rs
		}
		defer resp.Body.Close()

		rs.StatusCode = resp.StatusCode

		// Step 4 (flush_cache): accept 200 or 501
		if num == 4 && (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotImplemented) {
			rs.Success = true
			return rs
		}

		// All other steps: must be 200
		if resp.StatusCode == http.StatusOK {
			rs.Success = true
		} else {
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			rs.Error = fmt.Sprintf("status %d: %s", resp.StatusCode, string(respBody))
			rs.Success = false
		}
		return rs
	}

	// Step 1: POST /__control/reset → UPSTREAM reset
	steps = append(steps, step(1,
		"Reset UPSTREAM",
		"POST",
		rc.targetBaseURL+"/__control/reset",
		"",
		true))

	// Step 2: GET /health → UPSTREAM health
	steps = append(steps, step(2,
		"UPSTREAM health check",
		"GET",
		rc.targetBaseURL+"/health",
		"",
		true))

	// Step 3: POST /__waf_control/set_profile → WAF mode enforce
	steps = append(steps, step(3,
		"Set WAF profile (enforce)",
		"POST",
		rc.wafAdminURL+"/__waf_control/set_profile",
		`{"scope":"all","mode":"enforce"}`,
		true))

	// Step 4: POST /__waf_control/flush_cache → WAF cache clear
	steps = append(steps, step(4,
		"Flush WAF cache",
		"POST",
		rc.wafAdminURL+"/__waf_control/flush_cache",
		"",
		false))

	// Step 5: POST /__waf_control/reset_state → WAF state clean
	steps = append(steps, step(5,
		"Reset WAF state",
		"POST",
		rc.wafAdminURL+"/__waf_control/reset_state",
		"",
		true))

	return steps
}

// ResetUpstreamOnly resets only UPSTREAM (between V* tests).
func (rc *ResetClient) ResetUpstreamOnly() error {
	url := rc.targetBaseURL + "/__control/reset"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Benchmark-Secret", rc.controlSecret)

	resp, err := rc.client.Do(req)
	if err != nil {
		return fmt.Errorf("upstream reset failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream reset returned %d", resp.StatusCode)
	}

	var r map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil // empty body is acceptable
	}
	if ok, exists := r["ok"]; exists && ok == true {
		return nil
	}
	if reset, exists := r["reset"]; exists && reset == true {
		return nil
	}
	return nil
}

// ── Authentication ──

// AuthSession holds a session cookie from UPSTREAM.
type AuthSession struct {
	SID     string
	Cookies []*http.Cookie
}

// Authenticate performs 2-step login (POST /login → POST /otp) and returns session.
func (rc *ResetClient) Authenticate(username, password string) (*AuthSession, error) {
	// Credentials per spec: testuser_90 / Test#90Pass / OTP: 000090
	otpCode := "000090"
	if username == "alice" {
		otpCode = "123456"
	}

	// Step 1: POST /login
	jar, _ := cookiejar.New(nil)
	saveJar := rc.client.Jar
	rc.client.Jar = jar
	defer func() { rc.client.Jar = saveJar }()

	loginBody := fmt.Sprintf(`{"username":"%s","password":"%s"}`, username, password)
	resp, err := rc.client.Post(
		rc.targetBaseURL+"/login",
		"application/json",
		bytes.NewReader([]byte(loginBody)),
	)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		return nil, fmt.Errorf("login returned %d", resp.StatusCode)
	}

	// Parse login_token from response
	var loginResp struct {
		LoginToken string `json:"login_token"`
	}
	json.Unmarshal(bodyBytes, &loginResp)
	if loginResp.LoginToken == "" {
		return nil, fmt.Errorf("no login_token in response")
	}

	// Collect cookies
	u, _ := url.Parse(rc.targetBaseURL)
	cookies := jar.Cookies(u)

	// Step 2: POST /otp with login_token + otp_code
	otpBody := fmt.Sprintf(`{"login_token":"%s","otp_code":"%s"}`, loginResp.LoginToken, otpCode)
	req, _ := http.NewRequest("POST", rc.targetBaseURL+"/otp", bytes.NewReader([]byte(otpBody)))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err = rc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("otp request failed: %w", err)
	}
	io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("otp returned %d", resp.StatusCode)
	}

	// Collect all cookies — sid comes from Set-Cookie header
	cookies = jar.Cookies(u)

	// Find SID cookie
	var sid string
	for _, c := range cookies {
		if c.Name == "sid" {
			sid = c.Value
			break
		}
	}
	if sid == "" {
		return nil, fmt.Errorf("no sid cookie found after auth")
	}

	return &AuthSession{
		SID:     sid,
		Cookies: cookies,
	}, nil
}