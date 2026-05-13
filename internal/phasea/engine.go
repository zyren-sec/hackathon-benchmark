package phasea

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/waf-hackathon/benchmark-new/internal/challenge"
	"github.com/waf-hackathon/benchmark-new/internal/crossphase"
)

// Engine runs Phase A exploit prevention tests.
type Engine struct {
	cfg             *ConfigWrapper
	payloadReg      *PayloadRegistry
	resetClient     *ResetClient
	pool            *crossphase.GlobalResponsePool // SEC-02 response collector
	challengeSolver *challenge.Solver              // 429 challenge lifecycle handler
	vulnTests       []VulnTest
	tierFilter      string
	authSessions    map[string]*AuthSession // keyed by username
	mu              sync.Mutex
}

// ConfigWrapper is a simplified config interface for the engine.
type ConfigWrapper struct {
	TargetBaseURL string
	WAFBaseURL    string
	WAFAdminURL   string
	ControlSecret string
	TimeoutSec    int
	PayloadTier   string
	Verbose       bool
	DryRun        bool
}

// NewEngine creates a new Phase A test engine.
func NewEngine(cfg *ConfigWrapper, payloadReg *PayloadRegistry, pool *crossphase.GlobalResponsePool, chSolver *challenge.Solver) *Engine {
	return &Engine{
		cfg:             cfg,
		payloadReg:      payloadReg,
		resetClient:     NewResetClient(cfg.TargetBaseURL, cfg.WAFAdminURL, cfg.ControlSecret, cfg.TimeoutSec),
		pool:            pool,
		challengeSolver: chSolver,
		vulnTests:       GetVulnTests(),
		tierFilter:      cfg.PayloadTier,
		authSessions:    make(map[string]*AuthSession),
	}
}

// Run executes the full Phase A workflow and returns results.
func (e *Engine) Run() (*PhaseAResult, error) {
	if e.cfg.DryRun {
		return e.simulateRun(), nil
	}
	return e.realRun()
}

// realRun executes actual HTTP requests against the target.
func (e *Engine) realRun() (*PhaseAResult, error) {
	result := &PhaseAResult{
		StartTime:         time.Now(),
		WAFTarget:         e.cfg.WAFBaseURL,
		WAFMode:           "enforce",
		NegControlSkipped: true,
		NegControlReason:  "UPSTREAM cố ý trả về proof marker trên GET /. Việc kiểm tra negative control tạm thời bị skip.",
	}

	// 1. Full Reset Sequence
	result.ResetSteps = e.resetClient.FullResetSequence()
	result.ResetAllPassed = true
	for _, s := range result.ResetSteps {
		if !s.Success && s.StepNum != 4 { // Step 4 is non-fatal
			result.ResetAllPassed = false
			break
		}
	}

	if !result.ResetAllPassed {
		result.EndTime = time.Now()
		return result, nil
	}

	// 2. Auth for testuser_90 (used across multiple V* tests)
	authUser := "testuser_90"
	authPass := "Test#90Pass"
	e.mu.Lock()
	_, hasAuth := e.authSessions[authUser]
	e.mu.Unlock()
	if !hasAuth {
		sess, err := e.resetClient.Authenticate(authUser, authPass)
		if err != nil && e.cfg.Verbose {
			// Auth failure is non-fatal; tests requiring auth will skip
		}
		if sess != nil {
			e.mu.Lock()
			e.authSessions[authUser] = sess
			e.mu.Unlock()
		}
	}

	// 3. Run all V* tests
	for _, vt := range e.vulnTests {
		vr := e.runVulnTest(&vt)
		result.VulnResults = append(result.VulnResults, vr)
	}

	// 4. Build category groupings
	cats := GetCategories()
	for _, cat := range cats {
		cr := CategoryResult{
			CatNum:  cat.Num,
			Title:   cat.Title,
			IDRange: cat.IDRange,
		}
		for _, vr := range result.VulnResults {
			for _, id := range cat.IDs {
				if vr.VulnID == id {
					cr.VulnResults = append(cr.VulnResults, vr)
					cr.TotalCount++
					if vr.OverallPassed {
						cr.PassedCount++
					}
				}
			}
		}
		result.Categories = append(result.Categories, cr)
	}

	// 5. Compute scoring
	result.TotalTests = len(result.VulnResults)
	for _, vr := range result.VulnResults {
		if vr.OverallPassed {
			result.PassedTests++
		} else {
			result.FailedTests++
		}
	}

	if result.TotalTests > 0 {
		result.SEC01Score = float64(result.PassedTests) / float64(result.TotalTests) * 15.0
	}

	// RS-BONUS: count PASS tests with risk score in range
	result.RSBonusMax = result.TotalTests
	for _, vr := range result.VulnResults {
		if vr.OverallPassed {
			for _, pr := range vr.PayloadResults {
				if pr.Passed && pr.RiskScore >= vr.RiskMin && pr.RiskScore <= vr.RiskMax {
					result.RSBonusScore++
					break // count once per V*
				}
			}
		}
	}

	result.EndTime = time.Now()
	return result, nil
}

// runVulnTest executes all payloads for a single V* test.
func (e *Engine) runVulnTest(vt *VulnTest) VulnResult {
	vr := VulnResult{
		VulnID:       vt.ID,
		Name:         vt.Name,
		Category:     vt.Category,
		Tier:         vt.Tier,
		AuthRequired: vt.AuthRequired,
		RiskMin:      vt.RiskMin,
		RiskMax:      vt.RiskMax,
		ProofMarker:  vt.ProofMarker,
		Special:      vt.Special,
	}

	// Auth check for tests requiring it
	authUser := "testuser_90"
	if vt.AuthRequired {
		e.mu.Lock()
		sess, ok := e.authSessions[authUser]
		e.mu.Unlock()
		if !ok || sess == nil {
			// Try again
			sess2, err := e.resetClient.Authenticate(authUser, "Test#90Pass")
			if err != nil || sess2 == nil {
				vr.AuthSuccess = false
				vr.SkipReason = "auth failed"
				vr.Skipped = true
				return vr
			}
			e.mu.Lock()
			e.authSessions[authUser] = sess2
			e.mu.Unlock()
			sess = sess2
		}
		vr.AuthSuccess = true
		vr.SessionID = sess.SID
	} else {
		vr.AuthSuccess = true // not needed
	}

	// Get payloads for this vulnerability
	payloads := e.payloadReg.GetPayloads(vt.PayloadCat, e.tierFilter)

	// V03 needs timing payloads (SLEEP/BENCHMARK/WAITFOR) which are "advanced" tier
	if vt.Special == "v03_timing" {
		payloads = e.payloadReg.GetPayloads(vt.PayloadCat, "all")
		payloads = filterTimingPayloads(payloads)
	}

	if len(payloads) == 0 {
		// Fallback: get all payloads for the category
		payloads = e.payloadReg.GetPayloads(vt.PayloadCat, "all")
	}
	if len(payloads) == 0 {
		vr.SkipReason = "no payloads for category " + vt.PayloadCat
		vr.Skipped = true
		return vr
	}

	// Build WAF-proxied request URL
	wafURL := e.cfg.WAFBaseURL + vt.Endpoint

	// Get session cookies
	var cookies []*http.Cookie
	if vt.AuthRequired {
		e.mu.Lock()
		sess := e.authSessions[authUser]
		e.mu.Unlock()
		if sess != nil {
			cookies = sess.Cookies
		}
	}

	client := &http.Client{Timeout: time.Duration(e.cfg.TimeoutSec) * time.Second}

	// Special handling for V03 (timing-based)
	if vt.Special == "v03_timing" {
		vr = e.runV03Test(vt, vr, payloads, wafURL, client, cookies)
		return vr
	}

	// Special handling for V05 (stored XSS, 2-step)
	if vt.Special == "v05_stored" {
		vr = e.runV05Test(vt, vr, payloads, wafURL, client, cookies)
		return vr
	}

	// Special handling for V24 (race condition)
	if vt.Special == "v24_race" {
		vr = e.runV24Test(vt, vr, payloads, wafURL, client, cookies)
		return vr
	}

	// Standard test: simple payload send + analyze
	for i, p := range payloads {
		// Reset upstream before each payload (per spec §3.2)
		e.resetClient.ResetUpstreamOnly()
		time.Sleep(50 * time.Millisecond)

		pr := e.sendPayload(vt, p, e.cfg.WAFBaseURL, client, cookies, i+1)
		vr.PayloadResults = append(vr.PayloadResults, pr)

		if pr.Passed {
			vr.PassCount++
		} else {
			vr.FailCount++
		}
	}

	vr.OverallPassed = (vr.FailCount == 0)
	return vr
}

// buildRequestURL constructs the full request URL with query params and/or path payload.
func buildRequestURL(baseURL, endpoint, rawPayload, queryParam string) string {
	u := baseURL + endpoint

	// V06/V07: append payload to URL path directly (path traversal)
	if strings.HasPrefix(endpoint, "/static/") && rawPayload != "" && !strings.HasPrefix(rawPayload, "{") {
		// Payload is the traversal path (e.g., "../../../etc/passwd")
		u = baseURL + endpoint + rawPayload
		return u
	}

	// If query param specified, append ?key=url_encoded_value
	if queryParam != "" {
		if strings.Contains(u, "?") {
			u += "&" + queryParam + "=" + url.QueryEscape(rawPayload)
		} else {
			u += "?" + queryParam + "=" + url.QueryEscape(rawPayload)
		}
	}

	return u
}

// buildRequestBody constructs the HTTP body by substituting payload into BodyTemplate.
// Returns the body bytes and whether a body should be sent.
func buildRequestBody(bodyTemplate, rawPayload, method string) ([]byte, bool) {
	// GET requests typically have no body
	if method == "GET" {
		return nil, false
	}

	if bodyTemplate == "" {
		// No template → send raw payload as-is
		return []byte(rawPayload), true
	}

	// Substitute %s with the raw payload (escape JSON special chars)
	escaped := escapeJSON(rawPayload)
	body := strings.Replace(bodyTemplate, "%s", escaped, 1)
	return []byte(body), true
}

// sendPayload sends a single payload through WAF to UPSTREAM and analyzes the result.
func (e *Engine) sendPayload(vt *VulnTest, p Payload, baseURL string, client *http.Client, cookies []*http.Cookie, idx int) PayloadResult {
	pr := PayloadResult{
		PayloadName: p.Name,
		Payload:     p.RawPayload,
		Tier:        p.Tier,
		Index:       idx,
	}

	// Build URL (handles query params + path traversal)
	targetURL := buildRequestURL(baseURL, vt.Endpoint, p.RawPayload, vt.QueryParam)

	// Build body (handles BodyTemplate substitution)
	bodyBytes, hasBody := buildRequestBody(vt.BodyTemplate, p.RawPayload, vt.Method)
	var bodyReader io.Reader
	if hasBody {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	start := time.Now()

	req, err := http.NewRequest(vt.Method, targetURL, bodyReader)
	if err != nil {
		pr.Passed = false
		pr.FailReason = "MISSING HDR"
		pr.LatencyMs = 0
		return pr
	}

	// Set content type for non-GET requests
	if vt.Method != "GET" {
		ct := vt.ContentType
		if ct == "" {
			ct = "application/json"
		}
		req.Header.Set("Content-Type", ct)
	}

	// Set extra headers (e.g., Host header for V11)
	for k, v := range vt.ExtraHeaders {
		req.Header.Set(k, v)
	}

	// For V11: set Host header from payload
	if vt.ID == "V11" {
		req.Host = p.RawPayload
	}

	// Add auth cookies
	for _, c := range cookies {
		req.AddCookie(c)
	}

	// ── Capture full request for report reproducibility ──
	pr.RequestURL = targetURL
	pr.RequestMethod = vt.Method
	if hasBody {
		pr.RequestBody = string(bodyBytes)
	}
	pr.RequestHeaders = make(map[string]string)
	for k, vv := range req.Header {
		pr.RequestHeaders[k] = strings.Join(vv, ", ")
	}
	// Build raw HTTP request string (manually to avoid consuming req.Body)
	pr.FullRequest = buildRawHTTPRequest(targetURL, vt.Method, req.Header, bodyBytes, hasBody)
	// Build curl command for reproducibility
	pr.CurlCommand = buildCurlCommand(targetURL, vt.Method, vt.ContentType, bodyBytes, pr.RequestHeaders, p.RawPayload)

	// Send through WAF
	resp, err := client.Do(req)
	pr.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		pr.Passed = false
		pr.FailReason = "MISSING HDR"
		return pr
	}
	defer resp.Body.Close()

	bodyBytes2, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024)) // 256KB max
	pr.StatusCode = resp.StatusCode
	pr.ResponseBody = string(bodyBytes2)

	// Collect response headers
	pr.ResponseHeaders = make(map[string]string)
	for k, vv := range resp.Header {
		pr.ResponseHeaders[k] = strings.Join(vv, ", ")
	}

	// Extract WAF headers
	pr.WAFAction = strings.TrimSpace(resp.Header.Get("X-WAF-Action"))
	if rs := resp.Header.Get("X-WAF-Risk-Score"); rs != "" {
		pr.RiskScore, _ = strconv.Atoi(strings.TrimSpace(rs))
	}

	// Append to global response pool for SEC-02 (cross_phase.md §3)
	if e.pool != nil {
		e.pool.Append("A", vt.ID, "127.0.0.1", vt.Endpoint, vt.Method,
			pr.StatusCode, pr.ResponseBody, pr.ResponseHeaders)
	}

	// 429 Challenge detection and lifecycle evaluation (429_challenge.md)
	if e.challengeSolver != nil && challenge.IsChallenge(pr.StatusCode, pr.ResponseHeaders) {
		ctx := challenge.PhaseHookContext{
			Phase:           "A",
			TestID:          vt.ID,
			Method:          vt.Method,
			Endpoint:        vt.Endpoint,
			RequestBody:     pr.RequestBody,
			RequestHeaders:  pr.RequestHeaders,
			StatusCode:      pr.StatusCode,
			ResponseBody:    pr.ResponseBody,
			ResponseHeaders: pr.ResponseHeaders,
		}
		lr := e.challengeSolver.HandleChallenge(ctx)
		if e.cfg.Verbose {
			challenge.DisplayChallengeResult(lr)
		}
	}

	// Decision cascade per spec §7.3
	pr = e.analyzePayload(vt, pr)

	// ── Scoring explanation for report ──
	pr.ScoringExplain = buildScoringExplanation(vt, &pr)
	pr.RequestBody = pr.RequestBody // already set above
	if len(pr.RequestHeaders) == 0 {
		pr.RequestHeaders = make(map[string]string)
	}

	return pr
}

// analyzePayload applies the decision cascade (STEP 0-3) to determine PASS/FAIL.
func (e *Engine) analyzePayload(vt *VulnTest, pr PayloadResult) PayloadResult {
	// STEP 0: Required Headers Gate (§5.1)
	pr.HasAllHeaders = true
	for _, h := range RequiredHeaders {
		if _, ok := pr.ResponseHeaders[h]; !ok {
			// Try case-insensitive
			found := false
			for k := range pr.ResponseHeaders {
				if strings.EqualFold(k, h) {
					found = true
					break
				}
			}
			if !found {
				pr.HasAllHeaders = false
				break
			}
		}
	}

	if !pr.HasAllHeaders {
		pr.Passed = false
		pr.FailReason = "MISSING HDR"
		return pr
	}

	// STEP 1: Marker Scan
	bodyLower := strings.ToLower(pr.ResponseBody)
	headersStr := ""
	for k, v := range pr.ResponseHeaders {
		headersStr += strings.ToLower(k) + ": " + strings.ToLower(v) + "\n"
	}

	// Build marker regex
	markerRe := regexp.MustCompile(`__[VL]\d+[a-z]?_\w+__`)

	// Check own marker
	ownMarkerLower := strings.ToLower(vt.ProofMarker)
	hasOwnMarker := false
	if vt.ProofMarker != "" && strings.Contains(bodyLower, ownMarkerLower) {
		hasOwnMarker = true
		pr.MarkerFound = vt.ProofMarker
	}
	// Also check markers in headers
	if !hasOwnMarker && vt.ProofMarker != "" && strings.Contains(headersStr, ownMarkerLower) {
		hasOwnMarker = true
		pr.MarkerFound = vt.ProofMarker
	}

	// Check for OTHER V* markers (exclude own) — scan body + headers per §7.3 STEP 1
	fullScanStr := pr.ResponseBody + "\n" + headersStr
	allMarkers := markerRe.FindAllString(fullScanStr, -1)
	for _, m := range allMarkers {
		ml := strings.ToLower(m)
		if vt.ProofMarker != "" && ml == ownMarkerLower {
			continue
		}
		if strings.HasPrefix(ml, "__v") {
			hasOwnMarker = true
			pr.MarkerFound = m
			break
		}
	}

	// F2/F3: proof marker found?
	if hasOwnMarker {
		pr.Passed = false
		if pr.MarkerFound == vt.ProofMarker {
			pr.FailReason = "OWN MKR"
		} else {
			pr.FailReason = "OTHER MKR"
		}
		return pr
	}

	// STEP 2: X-WAF-Action Validation (§5.4)
	tc, ok := ThreatCategories[vt.ThreatGroup]
	if !ok {
		// Default: block or challenge
		tc = ThreatCategory{
			AcceptActions: []string{"block", "challenge"},
			StatusCodes:   []int{403, 429},
		}
	}

	pr.ActionValid = false
	actionLower := strings.ToLower(strings.TrimSpace(pr.WAFAction))
	for _, aa := range tc.AcceptActions {
		if strings.EqualFold(pr.WAFAction, aa) {
			pr.ActionValid = true
			break
		}
	}

	if !pr.ActionValid {
		pr.Passed = false
		pr.FailReason = "WRONG ACTION"
		return pr
	}

	// STEP 3: Status Code Validation (§4 mapping)
	if expectedStatus, ok := ActionStatusMap[actionLower]; ok {
		pr.StatusValid = true
		if expectedStatus == -1 {
			// "allow" → upstream response status (any 2xx/3xx)
			if pr.StatusCode < 200 || pr.StatusCode >= 400 {
				pr.StatusValid = false
			}
		} else if pr.StatusCode != expectedStatus {
			// For challenge vs rate_limit, both map to 429
			if expectedStatus == 429 && pr.StatusCode == 429 {
				pr.StatusValid = true
			} else {
				pr.StatusValid = false
			}
		}
	} else {
		pr.StatusValid = false
	}

	if !pr.StatusValid {
		pr.Passed = false
		pr.FailReason = "WRONG STATUS"
		return pr
	}

	// All checks passed
	pr.Passed = true
	return pr
}

// runV03Test handles the special V03 (timing-based) logic.
func (e *Engine) runV03Test(vt *VulnTest, vr VulnResult, payloads []Payload, wafURL string, client *http.Client, cookies []*http.Cookie) VulnResult {
	for i, p := range payloads {
		e.resetClient.ResetUpstreamOnly()
		time.Sleep(50 * time.Millisecond)

		pr := PayloadResult{
			PayloadName: p.Name,
			Payload:     p.RawPayload,
			Tier:        p.Tier,
			Index:       i + 1,
		}

		// Build body using template (e.g., {"username":"%s","password":"x"})
		reqBodyBytes, _ := buildRequestBody(vt.BodyTemplate, p.RawPayload, vt.Method)
		bodyReader := bytes.NewReader(reqBodyBytes)
		req, err := http.NewRequest(vt.Method, wafURL, bodyReader)
		if err != nil {
			pr.FailReason = "MISSING HDR"
			pr.Passed = false
			vr.PayloadResults = append(vr.PayloadResults, pr)
			vr.FailCount++
			continue
		}
		req.Header.Set("Content-Type", vt.ContentType)

		// ── Capture request data ──
		pr.RequestURL = wafURL
		pr.RequestMethod = vt.Method
		pr.RequestBody = string(reqBodyBytes)
		pr.RequestHeaders = make(map[string]string)
		for k, vv := range req.Header {
			pr.RequestHeaders[k] = strings.Join(vv, ", ")
		}
		pr.FullRequest = buildRawHTTPRequest(wafURL, vt.Method, req.Header, reqBodyBytes, true)
		pr.CurlCommand = buildCurlCommand(wafURL, vt.Method, vt.ContentType, reqBodyBytes, pr.RequestHeaders, p.RawPayload)

		start := time.Now()
		resp, err := client.Do(req)
		pr.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0

		if err != nil {
			pr.FailReason = "MISSING HDR"
			pr.Passed = false
			vr.PayloadResults = append(vr.PayloadResults, pr)
			vr.FailCount++
			continue
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()

		pr.StatusCode = resp.StatusCode
		pr.ResponseBody = string(bodyBytes)
		pr.ResponseHeaders = make(map[string]string)
		for k, vv := range resp.Header {
			pr.ResponseHeaders[k] = strings.Join(vv, ", ")
		}
		pr.WAFAction = strings.TrimSpace(resp.Header.Get("X-WAF-Action"))
		if rs := resp.Header.Get("X-WAF-Risk-Score"); rs != "" {
			pr.RiskScore, _ = strconv.Atoi(strings.TrimSpace(rs))
		}

		// Append to global response pool for SEC-02
		if e.pool != nil {
			e.pool.Append("A", vt.ID, "127.0.0.1", vt.Endpoint, vt.Method,
				pr.StatusCode, pr.ResponseBody, pr.ResponseHeaders)
		}

		// Special V03 logic: PASS if WAF blocked quickly OR response time ≤ 5000ms
		queryTimeMs := 0
		if qtm := resp.Header.Get("X-Query-Time-Ms"); qtm != "" {
			queryTimeMs, _ = strconv.Atoi(strings.TrimSpace(qtm))
		}

		actionLower := strings.ToLower(pr.WAFAction)
		if actionLower == "block" || actionLower == "challenge" || actionLower == "rate_limit" {
			// WAF blocked - PASS
			pr.Passed = true
			pr.FailReason = ""
		} else if pr.LatencyMs <= 5000 && queryTimeMs <= 5000 {
			// Not blocked but fast enough - PASS (optimistic)
			pr.Passed = true
			pr.FailReason = ""
		} else if pr.LatencyMs > 5000 && queryTimeMs > 5000 {
			// Slow - potential timing-based exploit succeeded
			pr.Passed = false
			pr.FailReason = "OWN MKR" // timing success indicates exploit
		} else {
			pr.Passed = false
			pr.FailReason = "OWN MKR"
		}

		pr.ScoringExplain = buildScoringExplanation(vt, &pr)
		vr.PayloadResults = append(vr.PayloadResults, pr)
		if pr.Passed {
			vr.PassCount++
		} else {
			vr.FailCount++
		}
	}

	vr.OverallPassed = (vr.FailCount == 0)
	return vr
}

// runV05Test handles the special V05 (stored XSS, 2-step) logic.
func (e *Engine) runV05Test(vt *VulnTest, vr VulnResult, payloads []Payload, wafURL string, client *http.Client, cookies []*http.Cookie) VulnResult {
	for i, p := range payloads {
		e.resetClient.ResetUpstreamOnly()
		time.Sleep(50 * time.Millisecond)

		pr := PayloadResult{
			PayloadName: p.Name,
			Payload:     p.RawPayload,
			Tier:        p.Tier,
			Index:       i + 1,
		}

		// Step 1: PUT /api/profile with XSS payload
		putURL := e.cfg.WAFBaseURL + "/api/profile"
		putBody := fmt.Sprintf(`{"display_name":"%s"}`, escapeJSON(p.RawPayload))
		req, _ := http.NewRequest("PUT", putURL, bytes.NewReader([]byte(putBody)))
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			pr.FailReason = "MISSING HDR"
			pr.Passed = false
			vr.PayloadResults = append(vr.PayloadResults, pr)
			vr.FailCount++
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// If PUT was blocked, the exploit is prevented
		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			pr.StatusCode = resp.StatusCode
			pr.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0
			pr.ResponseHeaders = make(map[string]string)
			for k, vv := range resp.Header {
				pr.ResponseHeaders[k] = strings.Join(vv, ", ")
			}
			pr.WAFAction = strings.TrimSpace(resp.Header.Get("X-WAF-Action"))
			if rs := resp.Header.Get("X-WAF-Risk-Score"); rs != "" {
				pr.RiskScore, _ = strconv.Atoi(strings.TrimSpace(rs))
			}

			// Append to global response pool for SEC-02
			if e.pool != nil {
				e.pool.Append("A", vt.ID, "127.0.0.1", vt.Endpoint, vt.Method,
					pr.StatusCode, pr.ResponseBody, pr.ResponseHeaders)
			}

			// Decision cascade for the block
			pr = e.analyzePayload(vt, pr)
			vr.PayloadResults = append(vr.PayloadResults, pr)
			if pr.Passed {
				vr.PassCount++
			} else {
				vr.FailCount++
			}
			continue
		}

		// Step 2: GET to verify if XSS payload is reflected back
		getURL := e.cfg.WAFBaseURL + "/api/profile"
		req2, _ := http.NewRequest("GET", getURL, nil)
		for _, c := range cookies {
			req2.AddCookie(c)
		}

		start2 := time.Now()
		resp2, err2 := client.Do(req2)
		pr.LatencyMs = float64(time.Since(start2).Microseconds()) / 1000.0
		if err2 != nil {
			pr.FailReason = "MISSING HDR"
			pr.Passed = false
			vr.PayloadResults = append(vr.PayloadResults, pr)
			vr.FailCount++
			continue
		}

		bodyBytes, _ := io.ReadAll(io.LimitReader(resp2.Body, 256*1024))
		resp2.Body.Close()

		pr.StatusCode = resp2.StatusCode
		pr.ResponseBody = string(bodyBytes)
		pr.ResponseHeaders = make(map[string]string)
		for k, vv := range resp2.Header {
			pr.ResponseHeaders[k] = strings.Join(vv, ", ")
		}
		pr.WAFAction = strings.TrimSpace(resp2.Header.Get("X-WAF-Action"))
		if rs := resp2.Header.Get("X-WAF-Risk-Score"); rs != "" {
			pr.RiskScore, _ = strconv.Atoi(strings.TrimSpace(rs))
		}

		// Append to global response pool for SEC-02
		if e.pool != nil {
			e.pool.Append("A", vt.ID, "127.0.0.1", vt.Endpoint, "GET",
				pr.StatusCode, pr.ResponseBody, pr.ResponseHeaders)
		}

		// Check if the XSS payload is present in the response
		if strings.Contains(strings.ToLower(pr.ResponseBody), strings.ToLower(p.RawPayload)) {
			pr.FailReason = "OWN MKR"
			pr.Passed = false
		} else {
			// Apply decision cascade
			pr = e.analyzePayload(vt, pr)
		}

		vr.PayloadResults = append(vr.PayloadResults, pr)
		if pr.Passed {
			vr.PassCount++
		} else {
			vr.FailCount++
		}
	}

	vr.OverallPassed = (vr.FailCount == 0)
	return vr
}

// runV24Test handles the special V24 (race condition, concurrent) logic.
func (e *Engine) runV24Test(vt *VulnTest, vr VulnResult, payloads []Payload, wafURL string, client *http.Client, cookies []*http.Cookie) VulnResult {
	// V24 sends 2 concurrent requests; both must be blocked for PASS
	e.resetClient.ResetUpstreamOnly()
	time.Sleep(50 * time.Millisecond)

	// For race condition, we send a few payloads but each as a concurrent pair
	for i, p := range payloads {
		pr := PayloadResult{
			PayloadName: p.Name + " (req-1)",
			Payload:     p.RawPayload,
			Tier:        p.Tier,
			Index:       i*2 + 1,
		}

		bodyReader1 := bytes.NewReader([]byte(p.RawPayload))
		req1, _ := http.NewRequest(vt.Method, wafURL, bodyReader1)
		req1.Header.Set("Content-Type", vt.ContentType)
		for _, c := range cookies {
			req1.AddCookie(c)
		}

		bodyReader2 := bytes.NewReader([]byte(p.RawPayload))
		req2, _ := http.NewRequest(vt.Method, wafURL, bodyReader2)
		req2.Header.Set("Content-Type", vt.ContentType)
		for _, c := range cookies {
			req2.AddCookie(c)
		}

		// Send concurrently
		var wg sync.WaitGroup
		var resp1, resp2 *http.Response
		var err1, err2 error
		start := time.Now()

		wg.Add(2)
		go func() {
			defer wg.Done()
			resp1, err1 = client.Do(req1)
		}()
		go func() {
			defer wg.Done()
			resp2, err2 = client.Do(req2)
		}()
		wg.Wait()

		pr.LatencyMs = float64(time.Since(start).Microseconds()) / 1000.0

		if err1 != nil || err2 != nil {
			pr.FailReason = "MISSING HDR"
			pr.Passed = false
			vr.PayloadResults = append(vr.PayloadResults, pr)
			vr.FailCount++
			continue
		}

		pr.StatusCode = resp1.StatusCode
		if resp1.Body != nil {
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp1.Body, 256*1024))
			pr.ResponseBody = string(bodyBytes)
			resp1.Body.Close()
		}
		if resp2.Body != nil {
			io.Copy(io.Discard, resp2.Body)
			resp2.Body.Close()
		}

		pr.ResponseHeaders = make(map[string]string)
		for k, vv := range resp1.Header {
			pr.ResponseHeaders[k] = strings.Join(vv, ", ")
		}
		pr.WAFAction = strings.TrimSpace(resp1.Header.Get("X-WAF-Action"))
		if rs := resp1.Header.Get("X-WAF-Risk-Score"); rs != "" {
			pr.RiskScore, _ = strconv.Atoi(strings.TrimSpace(rs))
		}

		// Append to global response pool for SEC-02 (use resp1 as representative)
		if e.pool != nil {
			e.pool.Append("A", vt.ID, "127.0.0.1", vt.Endpoint, vt.Method,
				pr.StatusCode, pr.ResponseBody, pr.ResponseHeaders)
		}

		// If first response is blocked, check second
		if resp1.StatusCode == 403 || resp1.StatusCode == 429 {
			if resp2.StatusCode == 403 || resp2.StatusCode == 429 {
				pr = e.analyzePayload(vt, pr)
			} else {
				// One blocked, one bypassed → FAIL for race condition
				pr.FailReason = "OTHER MKR"
				pr.Passed = false
			}
		} else {
			pr = e.analyzePayload(vt, pr)
		}

		vr.PayloadResults = append(vr.PayloadResults, pr)
		if pr.Passed {
			vr.PassCount++
		} else {
			vr.FailCount++
		}
	}

	vr.OverallPassed = (vr.FailCount == 0)
	return vr
}

// escapeJSON escapes a string for inclusion in a JSON value.
func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

// filterTimingPayloads keeps only timing-based SQLi payloads (SLEEP, BENCHMARK, WAITFOR, pg_sleep).
func filterTimingPayloads(payloads []Payload) []Payload {
	var filtered []Payload
	for _, p := range payloads {
		upper := strings.ToUpper(p.Name)
		if strings.Contains(upper, "TIME") ||
			strings.Contains(upper, "SLEEP") ||
			strings.Contains(upper, "BENCHMARK") ||
			strings.Contains(upper, "WAITFOR") ||
			strings.Contains(upper, "PG_SLEEP") {
			filtered = append(filtered, p)
		}
	}
	if len(filtered) == 0 {
		return payloads // fallback: return all
	}
	return filtered
}

// simulateRun generates simulated results for dry-run / display verification.
func (e *Engine) simulateRun() *PhaseAResult {
	now := time.Now()
	result := &PhaseAResult{
		StartTime:         now,
		EndTime:           now.Add(2 * time.Second),
		WAFTarget:         e.cfg.WAFBaseURL,
		WAFMode:           "enforce",
		NegControlSkipped: true,
		NegControlReason:  "UPSTREAM cố ý trả về proof marker trên GET /. Việc kiểm tra negative control tạm thời bị skip.",
	}

	// Simulated reset steps (all successful)
	methods := []string{"POST", "GET", "POST", "POST", "POST"}
	for i := 0; i < 5; i++ {
		result.ResetSteps = append(result.ResetSteps, ResetStep{
			StepNum:    i + 1,
			Name:       fmt.Sprintf("Step %d", i+1),
			Method:     methods[i],
			StatusCode: 200,
			Success:    true,
			LatencyMs:  float64(10 + i*5),
		})
	}
	result.ResetAllPassed = true

	// Simulated V* test results
	vulnTests := GetVulnTests()
	for _, vt := range vulnTests {
		vr := VulnResult{
			VulnID:       vt.ID,
			Name:         vt.Name,
			Category:     vt.Category,
			Tier:         vt.Tier,
			AuthRequired: vt.AuthRequired,
			RiskMin:      vt.RiskMin,
			RiskMax:      vt.RiskMax,
			ProofMarker:  vt.ProofMarker,
			Special:      vt.Special,
			AuthSuccess:  true,
		}

		if vt.AuthRequired {
			vr.SessionID = "sim-session-abc123"
		}

		// Get simulated payloads
		payloads := e.payloadReg.GetPayloads(vt.PayloadCat, e.tierFilter)
		if len(payloads) == 0 {
			payloads = e.payloadReg.GetPayloads(vt.PayloadCat, "all")
		}
		if len(payloads) == 0 {
			payloads = []Payload{
				{Name: "SIM_BASIC_1", RawPayload: "simulated", Tier: "basic"},
				{Name: "SIM_ADV_1", RawPayload: "simulated", Tier: "advanced"},
			}
		}

		// Simulate: most pass, some strategic failures
		for i, p := range payloads {
			passed := true
			failReason := ""
			statusCode := 403
			latency := 1.5 + float64(i)*0.3

			if (vt.ID == "V01" || vt.ID == "V04" || vt.ID == "V14") && i >= len(payloads)-2 {
				passed = false
				statusCode = 200
				failReason = "OWN MKR"
			}

			simURL := e.cfg.WAFBaseURL + vt.Endpoint
			simBody := fmt.Sprintf(`{"username":"%s","password":"x"}`, escapeJSON(p.RawPayload))

			pr := PayloadResult{
				PayloadName: p.Name,
				Payload:     p.RawPayload,
				Tier:        p.Tier,
				Index:       i + 1,
				StatusCode:  statusCode,
				LatencyMs:   latency,
				Passed:      passed,
				FailReason:  failReason,
				WAFAction:   "block",
				RiskScore:   85,
				ResponseHeaders: map[string]string{
					"X-WAF-Request-Id": "sim-" + vt.ID,
					"X-WAF-Action":     "block",
					"X-WAF-Risk-Score": "85",
				},
				ResponseBody:   `{"status":"blocked","message":"Request blocked by WAF"}`,
				RequestURL:     simURL,
				RequestMethod:  vt.Method,
				RequestBody:    simBody,
				RequestHeaders: map[string]string{"Content-Type": "application/json"},
				CurlCommand: fmt.Sprintf("curl -X %s '%s' -H 'Content-Type: application/json' -d '%s'",
					vt.Method, simURL, simBody),
				ScoringExplain: "DRY RUN — Simulated result, no actual WAF was tested",
			}
			vr.PayloadResults = append(vr.PayloadResults, pr)

			if passed {
				vr.PassCount++
			} else {
				vr.FailCount++
			}
		}

		vr.OverallPassed = (vr.FailCount == 0)
		result.VulnResults = append(result.VulnResults, vr)
	}

	// Build categories
	cats := GetCategories()
	for _, cat := range cats {
		cr := CategoryResult{CatNum: cat.Num, Title: cat.Title, IDRange: cat.IDRange}
		for _, vr := range result.VulnResults {
			for _, id := range cat.IDs {
				if vr.VulnID == id {
					cr.VulnResults = append(cr.VulnResults, vr)
					cr.TotalCount++
					if vr.OverallPassed {
						cr.PassedCount++
					}
				}
			}
		}
		result.Categories = append(result.Categories, cr)
	}

	// Compute scores
	result.TotalTests = len(result.VulnResults)
	for _, vr := range result.VulnResults {
		if vr.OverallPassed {
			result.PassedTests++
		} else {
			result.FailedTests++
		}
	}
	if result.TotalTests > 0 {
		result.SEC01Score = float64(result.PassedTests) / float64(result.TotalTests) * 15.0
	}

	result.RSBonusMax = result.TotalTests
	for _, vr := range result.VulnResults {
		if vr.OverallPassed {
			for _, pr := range vr.PayloadResults {
				if pr.Passed && pr.RiskScore >= vr.RiskMin && pr.RiskScore <= vr.RiskMax {
					result.RSBonusScore++
					break
				}
			}
		}
	}

	return result
}

// ── Helper: buildRawHTTPRequest constructs a raw HTTP request string ──

func buildRawHTTPRequest(targetURL, method string, headers http.Header, bodyBytes []byte, hasBody bool) string {
	var sb strings.Builder

	// Parse URL to get path
	u, err := url.Parse(targetURL)
	path := targetURL
	if err == nil {
		path = u.Path
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
	}

	// Request line
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))

	// Host header
	host := u.Host
	if host == "" {
		host = "localhost"
	}
	sb.WriteString(fmt.Sprintf("Host: %s\r\n", host))

	// Other headers
	for k, vv := range headers {
		for _, v := range vv {
			sb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}

	// Empty line before body
	sb.WriteString("\r\n")

	// Body
	if hasBody && len(bodyBytes) > 0 {
		sb.Write(bodyBytes)
	}

	return sb.String()
}

// ── Helper: buildCurlCommand constructs a curl command for reproducibility ──

func buildCurlCommand(targetURL, method, contentType string, bodyBytes []byte, headers map[string]string, rawPayload string) string {
	var sb strings.Builder
	sb.WriteString("curl")

	// Method
	if method != "GET" {
		sb.WriteString(fmt.Sprintf(" -X %s", method))
	}

	// URL - use single quotes to avoid shell escaping issues
	sb.WriteString(fmt.Sprintf(" '%s'", shellEscape(targetURL)))

	// Content-Type header
	if contentType != "" && method != "GET" {
		sb.WriteString(fmt.Sprintf(" -H 'Content-Type: %s'", shellEscape(contentType)))
	}

	// Other important headers
	for k, v := range headers {
		kl := strings.ToLower(k)
		if kl == "content-type" || kl == "content-length" || kl == "host" || kl == "user-agent" {
			continue
		}
		sb.WriteString(fmt.Sprintf(" -H '%s: %s'", shellEscape(k), shellEscape(v)))
	}

	// Body
	if len(bodyBytes) > 0 {
		// For V15 oversize, provide a file-based approach
		if len(bodyBytes) > 8192 {
			sb.WriteString(fmt.Sprintf(" --data-binary @payload_%d_bytes.txt", len(bodyBytes)))
		} else {
			bodyStr := string(bodyBytes)
			sb.WriteString(fmt.Sprintf(" -d '%s'", shellEscape(bodyStr)))
		}
	}

	// Common flags
	sb.WriteString(" -s -o - -w '\\nHTTP_STATUS:%{http_code}' --max-time 30")

	return sb.String()
}

// shellEscape escapes single quotes in shell strings.
func shellEscape(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}

// ── Helper: buildScoringExplanation ──

func buildScoringExplanation(vt *VulnTest, pr *PayloadResult) string {
	var lines []string

	if pr.Passed {
		lines = append(lines, fmt.Sprintf("✓ PASS — WAF đã chặn thành công payload %s", pr.PayloadName))

		// Explain the checks that passed
		if pr.HasAllHeaders {
			lines = append(lines, "  • PASS_HEADERS: Đầy đủ 6 headers bắt buộc (§5.1)")
		}
		if pr.ActionValid {
			lines = append(lines, fmt.Sprintf("  • PASS_ACTION: X-WAF-Action=%s nằm trong tập chấp nhận được của nhóm %s", pr.WAFAction, vt.ThreatGroup))
		}
		if pr.StatusValid {
			lines = append(lines, fmt.Sprintf("  • PASS_STATUS: HTTP %d khớp với action=%s", pr.StatusCode, pr.WAFAction))
		}
		lines = append(lines, fmt.Sprintf("  • Latency: %.3fms", pr.LatencyMs))
		lines = append(lines, fmt.Sprintf("  • Risk Score: %d (range: %d–%d)%s",
			pr.RiskScore, vt.RiskMin, vt.RiskMax,
			map[bool]string{true: " ✓ IN RANGE", false: " ✗ OUT OF RANGE"}[pr.RiskScore >= vt.RiskMin && pr.RiskScore <= vt.RiskMax]))

		// RS-BONUS eligibility
		if pr.RiskScore >= vt.RiskMin && pr.RiskScore <= vt.RiskMax {
			lines = append(lines, "  → RS-BONUS eligible: Risk Score nằm trong khoảng quy định")
		}
	} else {
		lines = append(lines, fmt.Sprintf("✗ FAIL — WAF không chặn được payload %s", pr.PayloadName))

		switch pr.FailReason {
		case "OWN MKR":
			lines = append(lines, fmt.Sprintf("  • FAIL_MARKER: Proof marker '%s' xuất hiện trong response → exploit đã thành công", vt.ProofMarker))
			lines = append(lines, "  → Tiêu chí §5.2-F3: response chứa own proof marker → FAIL")
		case "OTHER MKR":
			lines = append(lines, fmt.Sprintf("  • FAIL_OTHER: Marker '%s' của exploit khác xuất hiện trong response → side-effect không mong muốn", pr.MarkerFound))
			lines = append(lines, "  → Tiêu chí §5.2-F2: response chứa marker của exploit khác → FAIL")
		case "MISSING HDR":
			lines = append(lines, "  • FAIL_HEADERS: Thiếu một hoặc nhiều headers bắt buộc (§5.1)")
			lines = append(lines, "  → Yêu cầu 6 headers: X-WAF-Request-Id, X-WAF-Risk-Score, X-WAF-Action, X-WAF-Rule-Id, X-WAF-Mode, X-WAF-Cache")
		case "WRONG ACTION":
			lines = append(lines, fmt.Sprintf("  • FAIL_ACTION: X-WAF-Action=%s không nằm trong tập chấp nhận được", pr.WAFAction))
			lines = append(lines, fmt.Sprintf("  → Nhóm %s yêu cầu action ∈ %v", vt.ThreatGroup, ThreatCategories[vt.ThreatGroup].AcceptActions))
		case "WRONG STATUS":
			lines = append(lines, fmt.Sprintf("  • FAIL_STATUS: HTTP %d không khớp với action=%s", pr.StatusCode, pr.WAFAction))
			expected, _ := ActionStatusMap[strings.ToLower(pr.WAFAction)]
			lines = append(lines, fmt.Sprintf("  → Với action=%s, HTTP status kỳ vọng là %d (§4 mapping)", pr.WAFAction, expected))
		}

		lines = append(lines, fmt.Sprintf("  • Latency: %.3fms", pr.LatencyMs))
		lines = append(lines, fmt.Sprintf("  • Risk Score: %d (range: %d–%d)", pr.RiskScore, vt.RiskMin, vt.RiskMax))
	}

	return strings.Join(lines, "\n")
}
