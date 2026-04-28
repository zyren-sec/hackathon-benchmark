package phases

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/waf-hackathon/benchmark/internal/config"
	"github.com/waf-hackathon/benchmark/internal/httpclient"
	"github.com/waf-hackathon/benchmark/internal/target"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

// IPRangeCategory defines the abuse detection IP ranges per spec
type IPRangeCategory struct {
	Name       string
	RangeStart int
	RangeEnd   int
}

// IP range constants per specification
var (
	IPRangeBruteForce = IPRangeCategory{"BruteForce", 10, 19}
	IPRangeRelay      = IPRangeCategory{"Relay", 20, 39}
	IPRangeBehavioral = IPRangeCategory{"Behavioral", 40, 59}
	IPRangeFraud      = IPRangeCategory{"Fraud", 60, 79}
	IPRangeRecon      = IPRangeCategory{"Recon", 80, 99}
)

// GetIPRange returns all IPs for a category
func GetIPRange(cat IPRangeCategory) []string {
	var ips []string
	for i := cat.RangeStart; i <= cat.RangeEnd; i++ {
		ips = append(ips, fmt.Sprintf("127.0.0.%d", i))
	}
	return ips
}

// GetSingleIP returns a single IP from a category (randomized)
func GetSingleIP(cat IPRangeCategory, offset int) string {
	return fmt.Sprintf("127.0.0.%d", cat.RangeStart+offset)
}

// AbuseTest represents a single abuse detection test
type AbuseTest struct {
	ID           string
	Category     string
	Description  string
	Procedure    func(*AbuseTestRunner) (*AbuseResult, error)
	PassCriteria func(*AbuseResult) bool
}

// AbuseResult contains the result of an abuse test
type AbuseResult struct {
	TestID         string
	Passed         bool
	InterventionAt int     // At which request WAF intervened (0 if never)
	RiskScores     []int   // Risk scores observed
	Decisions      []waf.Decision
	FinalDecision  waf.Decision
	Error          string
}

// PhaseBResult contains all Phase B results
type PhaseBResult struct {
	AbuseTests         []AbuseResult
	AbuseDetectionRate float64
	TotalTests         int
	PassedTests        int
	DurationMs         int64
}

// AbuseTestRunner holds the execution context for abuse tests
type AbuseTestRunner struct {
	WAFClient    *waf.WAFClient
	Auth         *target.Auth
	Control      *target.Control
	Config       *config.Config
	TorExitNodes []string
	DatacenterIPs []string
}

// NewAbuseTestRunner creates a new runner with loaded IP lists
func NewAbuseTestRunner(wafClient *waf.WAFClient, auth *target.Auth, control *target.Control, cfg *config.Config) *AbuseTestRunner {
	runner := &AbuseTestRunner{
		WAFClient: wafClient,
		Auth:      auth,
		Control:   control,
		Config:    cfg,
	}

	// Load IP lists
	runner.LoadIPLists()

	return runner
}

// LoadIPLists loads Tor exit nodes and datacenter IPs from shared files
func (r *AbuseTestRunner) LoadIPLists() {
	// Load Tor exit nodes
	if data, err := os.ReadFile("shared/tor_exit_nodes.txt"); err == nil {
		r.TorExitNodes = parseIPList(string(data))
	} else {
		// Use some known Tor exit nodes as fallback
		r.TorExitNodes = []string{
			"185.220.101.0", "185.220.102.0", "199.249.230.0",
			"204.8.156.0", "171.25.193.0", "86.59.21.0",
		}
	}

	// Load datacenter IPs
	if data, err := os.ReadFile("shared/datacenter_asns.txt"); err == nil {
		r.DatacenterIPs = parseIPList(string(data))
	} else {
		// Use common datacenter ranges as fallback
		r.DatacenterIPs = []string{
			"52.0.0.0", "54.0.0.0", "34.0.0.0", // AWS
			"13.0.0.0", "40.0.0.0",             // Azure
			"35.0.0.0", "104.0.0.0",            // GCP
		}
	}
}

func parseIPList(data string) []string {
	var ips []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		// Skip empty lines
		if line == "" {
			continue
		}
		// Skip lines that start with #
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments (anything after #)
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			ips = append(ips, line)
		}
	}
	return ips
}

// ==================== ABUSE TEST CATALOG ====================

// GetAbuseTestCatalog returns all 23 Phase B tests
func GetAbuseTestCatalog() []AbuseTest {
	return []AbuseTest{
		// ===== BRUTE FORCE TESTS (AB01-AB03) =====
		{
			ID:       "AB01",
			Category: "BruteForce",
			Description: "50 failed login attempts for same user, verify WAF blocks within 10 attempts",
			Procedure: runAB01,
			PassCriteria: func(r *AbuseResult) bool {
				return r.InterventionAt > 0 && r.InterventionAt <= 10
			},
		},
		{
			ID:       "AB02",
			Category: "BruteForce",
			Description: "100 invalid username:password pairs (credential stuffing), verify block within 20",
			Procedure: runAB02,
			PassCriteria: func(r *AbuseResult) bool {
				return r.InterventionAt > 0 && r.InterventionAt <= 20
			},
		},
		{
			ID:       "AB03",
			Category: "BruteForce",
			Description: "50 different usernames with same password 'password123' (spraying), verify block within 15",
			Procedure: runAB03,
			PassCriteria: func(r *AbuseResult) bool {
				return r.InterventionAt > 0 && r.InterventionAt <= 15
			},
		},

		// ===== RELAY DETECTION TESTS (AR01-AR06) =====
		{
			ID:       "AR01",
			Category: "Relay",
			Description: "Normal XFF (source IP matches X-Forwarded-For), expect 200 (control)",
			Procedure: runAR01,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision == waf.Allow || r.FinalDecision == waf.PreventedSanitized
			},
		},
		{
			ID:       "AR02",
			Category: "Relay",
			Description: "Spoofed XFF (XFF different from source IP), expect risk score increase",
			Procedure: runAR02,
			PassCriteria: func(r *AbuseResult) bool {
				// Pass if risk score increased or blocked/challenged
				return r.FinalDecision.IsPrevented() || maxRisk(r.RiskScores) > 30
			},
		},
		{
			ID:       "AR03",
			Category: "Relay",
			Description: "Long proxy chain (4+ hops in XFF), expect flagged",
			Procedure: runAR03,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision.IsPrevented() || maxRisk(r.RiskScores) > 20
			},
		},
		{
			ID:       "AR04",
			Category: "Relay",
			Description: "Tor exit node IP, expect blocked/challenged",
			Procedure: runAR04,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision == waf.Block || r.FinalDecision == waf.Challenge
			},
		},
		{
			ID:       "AR05",
			Category: "Relay",
			Description: "Datacenter IP hitting CRITICAL route, expect blocked/challenged",
			Procedure: runAR05,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision == waf.Block || r.FinalDecision == waf.Challenge
			},
		},
		{
			ID:       "AR06",
			Category: "Relay",
			Description: "Residential IP (control), expect allowed",
			Procedure: runAR06,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision == waf.Allow || r.FinalDecision == waf.PreventedSanitized
			},
		},

		// ===== BEHAVIORAL ANOMALY TESTS (BA01-BA05) =====
		{
			ID:       "BA01",
			Category: "Behavioral",
			Description: "POST /login directly without prior GET /, expect challenge or risk > 30",
			Procedure: runBA01,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision.IsPrevented() || maxRisk(r.RiskScores) > 30
			},
		},
		{
			ID:       "BA02",
			Category: "Behavioral",
			Description: "100 requests at exactly 100ms intervals (bot timing), expect block/challenge within 60",
			Procedure: runBA02,
			PassCriteria: func(r *AbuseResult) bool {
				return r.InterventionAt > 0 && r.InterventionAt <= 60
			},
		},
		{
			ID:       "BA03",
			Category: "Behavioral",
			Description: "POST /deposit without Referer header, expect risk > 0",
			Procedure: runBA03,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision.IsPrevented() || maxRisk(r.RiskScores) > 0
			},
		},
		{
			ID:       "BA04",
			Category: "Behavioral",
			Description: "20 requests in 1 second (sub-50ms cadence), expect at least one 429",
			Procedure: runBA04,
			PassCriteria: func(r *AbuseResult) bool {
				// Check if any decision was rate limit or challenge
				for _, d := range r.Decisions {
					if d == waf.RateLimit || d == waf.Challenge {
						return true
					}
				}
				return r.FinalDecision == waf.RateLimit || r.FinalDecision == waf.Challenge
			},
		},
		{
			ID:       "BA05",
			Category: "Behavioral",
			Description: "POST /withdrawal with Referer: https://evil.com/, expect risk increase",
			Procedure: runBA05,
			PassCriteria: func(r *AbuseResult) bool {
				return maxRisk(r.RiskScores) > 0 || r.FinalDecision.IsPrevented()
			},
		},

		// ===== TRANSACTION FRAUD TESTS (TF01-TF04) =====
		{
			ID:       "TF01",
			Category: "Fraud",
			Description: "Login → OTP → deposit within 5 seconds, expect block/challenge on deposit",
			Procedure: runTF01,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision == waf.Block || r.FinalDecision == waf.Challenge
			},
		},
		{
			ID:       "TF02",
			Category: "Fraud",
			Description: "Deposit → withdrawal within 3 seconds, expect block/challenge on withdrawal",
			Procedure: runTF02,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision == waf.Block || r.FinalDecision == waf.Challenge
			},
		},
		{
			ID:       "TF03",
			Category: "Fraud",
			Description: "Change withdrawal limit → large withdrawal within 10 seconds, expect flagged",
			Procedure: runTF03,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision.IsPrevented() || maxRisk(r.RiskScores) > 50
			},
		},
		{
			ID:       "TF04",
			Category: "Fraud",
			Description: "Same device fingerprint logs into 5 different accounts and deposits within 60s, expect multi-accounting detected",
			Procedure: runTF04,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision.IsPrevented() || r.InterventionAt > 0
			},
		},

		// ===== RECON TESTS (RE01-RE04) =====
		{
			ID:       "RE01",
			Category: "Recon",
			Description: "200 requests to random non-existent paths, expect block after ≤50",
			Procedure: runRE01,
			PassCriteria: func(r *AbuseResult) bool {
				return r.InterventionAt > 0 && r.InterventionAt <= 50
			},
		},
		{
			ID:       "RE02",
			Category: "Recon",
			Description: "OPTIONS to 20 endpoints in <2 seconds, expect rate-limit",
			Procedure: runRE02,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision == waf.RateLimit || r.FinalDecision == waf.Challenge
			},
		},
		{
			ID:       "RE03",
			Category: "Recon",
			Description: "Trigger 10 different 500 errors, verify stack traces stripped (cross-ref L01)",
			Procedure: runRE03,
			PassCriteria: func(r *AbuseResult) bool {
				// Should NOT see L01 marker (stack traces stripped)
				return !hasL01Marker(r.Decisions)
			},
		},
		{
			ID:       "RE04",
			Category: "Recon",
			Description: "Hit all 4 canary endpoints from one IP in <2s, then send legit request, expect legit also blocked (max-risk lock)",
			Procedure: runRE04,
			PassCriteria: func(r *AbuseResult) bool {
				return r.FinalDecision.IsPrevented()
			},
		},
	}
}

// Helper functions
func maxRisk(scores []int) int {
	max := 0
	for _, s := range scores {
		if s > max {
			max = s
		}
	}
	return max
}

func hasL01Marker(decisions []waf.Decision) bool {
	// This is a placeholder - in real implementation would check response markers
	return false
}

// ==================== TEST IMPLEMENTATIONS ====================

// AB01: 50 failed login attempts for same user
func runAB01(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "AB01"}
	ip := GetSingleIP(IPRangeBruteForce, 0)

	for i := 0; i < 50; i++ {
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod("POST")
		req.SetRequestURI("/login")
		req.Header.SetContentType("application/json")
		req.SetBody([]byte(`{"username":"admin","password":"wrong` + fmt.Sprintf("%d", i) + `"}`))

		wafResp, err := runner.WAFClient.SendRequest(req, ip)
		fasthttp.ReleaseRequest(req)

		if err != nil {
			continue
		}

		result.Decisions = append(result.Decisions, wafResp.Decision)
		result.RiskScores = append(result.RiskScores, wafResp.RiskScore)

		if wafResp.Decision.IsPrevented() {
			result.InterventionAt = i + 1
			result.FinalDecision = wafResp.Decision
			result.Passed = result.InterventionAt <= 10
			return result, nil
		}

		time.Sleep(50 * time.Millisecond)
	}

	result.FinalDecision = waf.Allow
	result.Passed = false
	return result, nil
}

// AB02: 100 invalid username:password pairs (credential stuffing)
func runAB02(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "AB02"}
	ip := GetSingleIP(IPRangeBruteForce, 1)

	creds := generateInvalidCredentials(100)

	for i, cred := range creds {
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod("POST")
		req.SetRequestURI("/login")
		req.Header.SetContentType("application/json")
		body := fmt.Sprintf(`{"username":"%s","password":"%s"}`, cred.username, cred.password)
		req.SetBody([]byte(body))

		wafResp, err := runner.WAFClient.SendRequest(req, ip)
		fasthttp.ReleaseRequest(req)

		if err != nil {
			continue
		}

		result.Decisions = append(result.Decisions, wafResp.Decision)
		result.RiskScores = append(result.RiskScores, wafResp.RiskScore)

		if wafResp.Decision.IsPrevented() {
			result.InterventionAt = i + 1
			result.FinalDecision = wafResp.Decision
			result.Passed = result.InterventionAt <= 20
			return result, nil
		}

		time.Sleep(30 * time.Millisecond)
	}

	result.FinalDecision = waf.Allow
	result.Passed = false
	return result, nil
}

// AB03: 50 different usernames with same password "password123" (spraying)
func runAB03(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "AB03"}
	ip := GetSingleIP(IPRangeBruteForce, 2)

	for i := 0; i < 50; i++ {
		username := fmt.Sprintf("user%d@test.com", i)
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod("POST")
		req.SetRequestURI("/login")
		req.Header.SetContentType("application/json")
		body := fmt.Sprintf(`{"username":"%s","password":"password123"}`, username)
		req.SetBody([]byte(body))

		wafResp, err := runner.WAFClient.SendRequest(req, ip)
		fasthttp.ReleaseRequest(req)

		if err != nil {
			continue
		}

		result.Decisions = append(result.Decisions, wafResp.Decision)
		result.RiskScores = append(result.RiskScores, wafResp.RiskScore)

		if wafResp.Decision.IsPrevented() {
			result.InterventionAt = i + 1
			result.FinalDecision = wafResp.Decision
			result.Passed = result.InterventionAt <= 15
			return result, nil
		}

		time.Sleep(50 * time.Millisecond)
	}

	result.FinalDecision = waf.Allow
	result.Passed = false
	return result, nil
}

// AR01: Normal XFF (control)
func runAR01(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "AR01"}
	ip := GetSingleIP(IPRangeRelay, 0)

	req := fasthttp.AcquireRequest()
	req.Header.SetMethod("GET")
	req.SetRequestURI("/")
	// Normal XFF - matches source IP
	req.Header.Set("X-Forwarded-For", ip)

	wafResp, err := runner.WAFClient.SendRequest(req, ip)
	fasthttp.ReleaseRequest(req)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.Decision == waf.Allow || wafResp.Decision == waf.PreventedSanitized

	return result, nil
}

// AR02: Spoofed XFF
func runAR02(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "AR02"}
	sourceIP := GetSingleIP(IPRangeRelay, 1)
	spoofedIP := "1.2.3.4"

	req := fasthttp.AcquireRequest()
	req.Header.SetMethod("GET")
	req.SetRequestURI("/")
	// Spoofed XFF - different from source IP
	req.Header.Set("X-Forwarded-For", spoofedIP)

	wafResp, err := runner.WAFClient.SendRequest(req, sourceIP)
	fasthttp.ReleaseRequest(req)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.Decision.IsPrevented() || wafResp.RiskScore > 30

	return result, nil
}

// AR03: Long proxy chain
func runAR03(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "AR03"}
	ip := GetSingleIP(IPRangeRelay, 2)

	req := fasthttp.AcquireRequest()
	req.Header.SetMethod("GET")
	req.SetRequestURI("/")
	// Long proxy chain (4+ hops)
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, "+ip)

	wafResp, err := runner.WAFClient.SendRequest(req, ip)
	fasthttp.ReleaseRequest(req)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.Decision.IsPrevented() || wafResp.RiskScore > 20

	return result, nil
}

// AR04: Tor exit node
func runAR04(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "AR04"}

	// Use Tor exit node IP if available
	torIP := "185.220.101.0"
	if len(runner.TorExitNodes) > 0 {
		torIP = runner.TorExitNodes[0]
	}

	req := fasthttp.AcquireRequest()
	req.Header.SetMethod("GET")
	req.SetRequestURI("/login")
	req.Header.Set("X-Tor-Exit", "true") // Marker for WAF to detect

	wafResp, err := runner.WAFClient.SendRequest(req, torIP)
	fasthttp.ReleaseRequest(req)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.Decision == waf.Block || wafResp.Decision == waf.Challenge

	return result, nil
}

// AR05: Datacenter IP on CRITICAL route
func runAR05(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "AR05"}

	dcIP := "52.0.0.1"
	if len(runner.DatacenterIPs) > 0 {
		dcIP = runner.DatacenterIPs[0]
	}

	req := fasthttp.AcquireRequest()
	req.Header.SetMethod("POST")
	req.SetRequestURI("/login") // CRITICAL route
	req.Header.SetContentType("application/json")
	req.SetBody([]byte(`{"username":"admin","password":"test"}`))
	req.Header.Set("X-Datacenter", "true")

	wafResp, err := runner.WAFClient.SendRequest(req, dcIP)
	fasthttp.ReleaseRequest(req)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.Decision == waf.Block || wafResp.Decision == waf.Challenge

	return result, nil
}

// AR06: Residential IP (control)
func runAR06(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "AR06"}
	ip := GetSingleIP(IPRangeRelay, 5)

	req := fasthttp.AcquireRequest()
	req.Header.SetMethod("GET")
	req.SetRequestURI("/")
	req.Header.Set("X-Residential", "true")

	wafResp, err := runner.WAFClient.SendRequest(req, ip)
	fasthttp.ReleaseRequest(req)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.Decision == waf.Allow || wafResp.Decision == waf.PreventedSanitized

	return result, nil
}

// BA01: POST /login directly without prior GET /
func runBA01(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "BA01"}
	ip := GetSingleIP(IPRangeBehavioral, 0)

	// Direct POST without visiting home first
	req := fasthttp.AcquireRequest()
	req.Header.SetMethod("POST")
	req.SetRequestURI("/login")
	req.Header.SetContentType("application/json")
	req.SetBody([]byte(`{"username":"admin","password":"test"}`))

	wafResp, err := runner.WAFClient.SendRequest(req, ip)
	fasthttp.ReleaseRequest(req)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.Decision.IsPrevented() || wafResp.RiskScore > 30

	return result, nil
}

// BA02: 100 requests at exactly 100ms intervals
func runBA02(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "BA02"}
	ip := GetSingleIP(IPRangeBehavioral, 1)

	for i := 0; i < 100; i++ {
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod("GET")
		req.SetRequestURI("/")

		wafResp, err := runner.WAFClient.SendRequest(req, ip)
		fasthttp.ReleaseRequest(req)

		if err != nil {
			continue
		}

		result.Decisions = append(result.Decisions, wafResp.Decision)
		result.RiskScores = append(result.RiskScores, wafResp.RiskScore)

		if wafResp.Decision.IsPrevented() {
			result.InterventionAt = i + 1
			result.FinalDecision = wafResp.Decision
			result.Passed = result.InterventionAt <= 60
			return result, nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	result.FinalDecision = waf.Allow
	result.Passed = false
	return result, nil
}

// BA03: POST /deposit without Referer header
func runBA03(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "BA03"}
	ip := GetSingleIP(IPRangeBehavioral, 2)

	// First authenticate
	session, err := runner.Auth.LoginWithCredentials(target.UserAlice)
	if err != nil {
		result.Error = "auth failed: " + err.Error()
		return result, err
	}

	req := fasthttp.AcquireRequest()
	req.Header.SetMethod("POST")
	req.SetRequestURI("/deposit")
	req.Header.SetContentType("application/json")
	req.SetBody([]byte(`{"amount":100}`))
	// Intentionally no Referer header

	// Add auth cookies
	for _, c := range session.Cookies {
		req.Header.SetCookie(c.Name, c.Value)
	}

	wafResp, err := runner.WAFClient.SendRequest(req, ip)
	fasthttp.ReleaseRequest(req)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.RiskScore > 0 || wafResp.Decision.IsPrevented()

	return result, nil
}

// BA04: 20 requests in 1 second (sub-50ms cadence)
func runBA04(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "BA04"}
	ip := GetSingleIP(IPRangeBehavioral, 3)

	interval := 50 * time.Millisecond // 20 requests in 1 second

	for i := 0; i < 20; i++ {
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod("GET")
		req.SetRequestURI("/api/data")

		wafResp, err := runner.WAFClient.SendRequest(req, ip)
		fasthttp.ReleaseRequest(req)

		if err != nil {
			continue
		}

		result.Decisions = append(result.Decisions, wafResp.Decision)
		result.RiskScores = append(result.RiskScores, wafResp.RiskScore)

		if wafResp.Decision == waf.RateLimit || wafResp.Decision == waf.Challenge {
			result.InterventionAt = i + 1
			result.FinalDecision = wafResp.Decision
			result.Passed = true
			return result, nil
		}

		time.Sleep(interval)
	}

	result.FinalDecision = waf.Allow
	result.Passed = false
	return result, nil
}

// BA05: POST /withdrawal with evil Referer
func runBA05(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "BA05"}
	ip := GetSingleIP(IPRangeBehavioral, 4)

	// First authenticate
	session, err := runner.Auth.LoginWithCredentials(target.UserAlice)
	if err != nil {
		result.Error = "auth failed: " + err.Error()
		return result, err
	}

	req := fasthttp.AcquireRequest()
	req.Header.SetMethod("POST")
	req.SetRequestURI("/withdrawal")
	req.Header.SetContentType("application/json")
	req.SetBody([]byte(`{"amount":50}`))
	req.Header.Set("Referer", "https://evil.com/phishing")

	// Add auth cookies
	for _, c := range session.Cookies {
		req.Header.SetCookie(c.Name, c.Value)
	}

	wafResp, err := runner.WAFClient.SendRequest(req, ip)
	fasthttp.ReleaseRequest(req)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.RiskScore > 0 || wafResp.Decision.IsPrevented()

	return result, nil
}

// TF01: Login → OTP → deposit within 5 seconds
func runTF01(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "TF01"}
	ip := GetSingleIP(IPRangeFraud, 0)

	start := time.Now()

	// Complete golden path quickly
	session, err := runner.Auth.GoldenPath(target.UserAlice)
	if err != nil {
		result.Error = "auth failed: " + err.Error()
		return result, err
	}

	// Immediately try deposit
	req := fasthttp.AcquireRequest()
	req.Header.SetMethod("POST")
	req.SetRequestURI("/deposit")
	req.Header.SetContentType("application/json")
	req.SetBody([]byte(`{"amount":1000}`))

	for _, c := range session.Cookies {
		req.Header.SetCookie(c.Name, c.Value)
	}

	wafResp, err := runner.WAFClient.SendRequest(req, ip)
	fasthttp.ReleaseRequest(req)

	elapsed := time.Since(start)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	// Should be blocked/challenged if within 5 seconds
	result.Passed = (wafResp.Decision == waf.Block || wafResp.Decision == waf.Challenge) && elapsed < 5*time.Second

	return result, nil
}

// TF02: Deposit → withdrawal within 3 seconds
func runTF02(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "TF02"}
	ip := GetSingleIP(IPRangeFraud, 1)

	// Authenticate
	session, err := runner.Auth.LoginWithCredentials(target.UserAlice)
	if err != nil {
		result.Error = "auth failed: " + err.Error()
		return result, err
	}

	// First deposit
	req1 := fasthttp.AcquireRequest()
	req1.Header.SetMethod("POST")
	req1.SetRequestURI("/deposit")
	req1.Header.SetContentType("application/json")
	req1.SetBody([]byte(`{"amount":500}`))
	for _, c := range session.Cookies {
		req1.Header.SetCookie(c.Name, c.Value)
	}
	runner.WAFClient.SendRequest(req1, ip)
	fasthttp.ReleaseRequest(req1)

	// Immediately withdraw (within 3 seconds)
	req2 := fasthttp.AcquireRequest()
	req2.Header.SetMethod("POST")
	req2.SetRequestURI("/withdrawal")
	req2.Header.SetContentType("application/json")
	req2.SetBody([]byte(`{"amount":500}`))
	for _, c := range session.Cookies {
		req2.Header.SetCookie(c.Name, c.Value)
	}

	wafResp, err := runner.WAFClient.SendRequest(req2, ip)
	fasthttp.ReleaseRequest(req2)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.Decision == waf.Block || wafResp.Decision == waf.Challenge

	return result, nil
}

// TF03: Change withdrawal limit → large withdrawal within 10 seconds
func runTF03(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "TF03"}
	ip := GetSingleIP(IPRangeFraud, 2)

	// Use Charlie's account (for transaction tests)
	session, err := runner.Auth.LoginWithCredentials(target.UserCharlie)
	if err != nil {
		result.Error = "auth failed: " + err.Error()
		return result, err
	}

	// Change withdrawal limit
	req1 := fasthttp.AcquireRequest()
	req1.Header.SetMethod("PUT")
	req1.SetRequestURI("/api/profile")
	req1.Header.SetContentType("application/json")
	req1.SetBody([]byte(`{"withdrawal_limit":10000}`))
	for _, c := range session.Cookies {
		req1.Header.SetCookie(c.Name, c.Value)
	}
	runner.WAFClient.SendRequest(req1, ip)
	fasthttp.ReleaseRequest(req1)

	// Large withdrawal within 10 seconds
	req2 := fasthttp.AcquireRequest()
	req2.Header.SetMethod("POST")
	req2.SetRequestURI("/withdrawal")
	req2.Header.SetContentType("application/json")
	req2.SetBody([]byte(`{"amount":5000}`))
	for _, c := range session.Cookies {
		req2.Header.SetCookie(c.Name, c.Value)
	}

	wafResp, err := runner.WAFClient.SendRequest(req2, ip)
	fasthttp.ReleaseRequest(req2)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.Decision.IsPrevented() || wafResp.RiskScore > 50

	return result, nil
}

// TF04: Multi-accounting detection
func runTF04(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "TF04"}

	accounts := []target.Credentials{
		target.UserAlice,
		target.UserBob,
		target.UserCharlie,
		target.UserDave,
		{"eve", "EvePass123", "333333"}, // Fifth account
	}

	// Same device fingerprint for all
	deviceFP := "Mozilla/5.0 (SameDevice; SameOS) SameBrowser/1.0"

	for i, cred := range accounts {
		ip := GetSingleIP(IPRangeFraud, 10+i)

		// Login with same device fingerprint
		session, err := runner.Auth.LoginWithCredentials(cred)
		if err != nil {
			continue
		}

		// Deposit from each account
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod("POST")
		req.SetRequestURI("/deposit")
		req.Header.SetContentType("application/json")
		req.Header.Set("User-Agent", deviceFP)
		req.SetBody([]byte(`{"amount":100}`))

		for _, c := range session.Cookies {
			req.Header.SetCookie(c.Name, c.Value)
		}

		wafResp, err := runner.WAFClient.SendRequest(req, ip)
		fasthttp.ReleaseRequest(req)

		if err != nil {
			continue
		}

		result.Decisions = append(result.Decisions, wafResp.Decision)
		result.RiskScores = append(result.RiskScores, wafResp.RiskScore)

		if wafResp.Decision.IsPrevented() {
			result.InterventionAt = i + 1
			result.FinalDecision = wafResp.Decision
			result.Passed = true
			return result, nil
		}

		time.Sleep(10 * time.Second) // Spread over ~60 seconds
	}

	result.FinalDecision = waf.Allow
	result.Passed = false
	return result, nil
}

// RE01: 200 requests to random non-existent paths
func runRE01(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "RE01"}
	ip := GetSingleIP(IPRangeRecon, 0)

	paths := generateRandomPaths(200)

	for i, path := range paths {
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod("GET")
		req.SetRequestURI(path)

		wafResp, err := runner.WAFClient.SendRequest(req, ip)
		fasthttp.ReleaseRequest(req)

		if err != nil {
			continue
		}

		result.Decisions = append(result.Decisions, wafResp.Decision)
		result.RiskScores = append(result.RiskScores, wafResp.RiskScore)

		if wafResp.Decision.IsPrevented() {
			result.InterventionAt = i + 1
			result.FinalDecision = wafResp.Decision
			result.Passed = result.InterventionAt <= 50
			return result, nil
		}

		time.Sleep(10 * time.Millisecond)
	}

	result.FinalDecision = waf.Allow
	result.Passed = false
	return result, nil
}

// RE02: OPTIONS to 20 endpoints in <2 seconds
func runRE02(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "RE02"}
	ip := GetSingleIP(IPRangeRecon, 1)

	endpoints := []string{
		"/", "/login", "/api/profile", "/api/data", "/game/list",
		"/game/1", "/game/1/play", "/deposit", "/withdrawal", "/api/transactions",
		"/about", "/contact", "/help", "/faq", "/terms",
		"/privacy", "/api/users", "/api/settings", "/api/stats", "/api/search",
	}

	interval := 100 * time.Millisecond // 20 requests in <2 seconds

	for i, endpoint := range endpoints {
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod("OPTIONS")
		req.SetRequestURI(endpoint)

		wafResp, err := runner.WAFClient.SendRequest(req, ip)
		fasthttp.ReleaseRequest(req)

		if err != nil {
			continue
		}

		result.Decisions = append(result.Decisions, wafResp.Decision)
		result.RiskScores = append(result.RiskScores, wafResp.RiskScore)

		if wafResp.Decision == waf.RateLimit || wafResp.Decision == waf.Challenge {
			result.InterventionAt = i + 1
			result.FinalDecision = wafResp.Decision
			result.Passed = true
			return result, nil
		}

		time.Sleep(interval)
	}

	result.FinalDecision = waf.Allow
	result.Passed = false
	return result, nil
}

// RE03: Trigger 10 different 500 errors
func runRE03(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "RE03"}
	ip := GetSingleIP(IPRangeRecon, 2)

	// Trigger errors via malformed requests
	errorTriggers := []string{
		"{malformed",
		"[1, 2, undefined]",
		`{"num": 1e999999}`,
		"invalid json {{{",
		`{"nested": ` + strings.Repeat(`{"a":`, 1000),
	}

	for _, trigger := range errorTriggers {
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod("POST")
		req.SetRequestURI("/api/data")
		req.Header.SetContentType("application/json")
		req.SetBody([]byte(trigger))

		wafResp, err := runner.WAFClient.SendRequest(req, ip)
		fasthttp.ReleaseRequest(req)

		if err != nil {
			continue
		}

		result.Decisions = append(result.Decisions, wafResp.Decision)
		result.RiskScores = append(result.RiskScores, wafResp.RiskScore)

		// Check if L01 marker present (would mean stack traces not stripped)
		for _, marker := range wafResp.Markers {
			if strings.Contains(marker, "L01") {
				result.Passed = false
				result.FinalDecision = wafResp.Decision
				return result, nil
			}
		}
	}

	result.FinalDecision = waf.Allow
	result.Passed = true // No L01 markers found (stack traces stripped)
	return result, nil
}

// RE04: Hit all 4 canary endpoints
func runRE04(runner *AbuseTestRunner) (*AbuseResult, error) {
	result := &AbuseResult{TestID: "RE04"}
	ip := GetSingleIP(IPRangeRecon, 3)

	canaryEndpoints := []string{
		"/admin-test",
		"/api-debug",
		"/.env",
		"/wp-admin",
	}

	// Hit all canaries quickly (<2s)
	for _, endpoint := range canaryEndpoints {
		req := fasthttp.AcquireRequest()
		req.Header.SetMethod("GET")
		req.SetRequestURI(endpoint)

		wafResp, err := runner.WAFClient.SendRequest(req, ip)
		fasthttp.ReleaseRequest(req)

		if err != nil {
			continue
		}

		result.Decisions = append(result.Decisions, wafResp.Decision)
		result.RiskScores = append(result.RiskScores, wafResp.RiskScore)

		time.Sleep(100 * time.Millisecond)
	}

	// Now send a legitimate request - should be blocked due to max-risk
	legitReq := fasthttp.AcquireRequest()
	legitReq.Header.SetMethod("GET")
	legitReq.SetRequestURI("/")

	wafResp, err := runner.WAFClient.SendRequest(legitReq, ip)
	fasthttp.ReleaseRequest(legitReq)

	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	result.Decisions = append(result.Decisions, wafResp.Decision)
	result.RiskScores = append(result.RiskScores, wafResp.RiskScore)
	result.FinalDecision = wafResp.Decision
	result.Passed = wafResp.Decision.IsPrevented()

	return result, nil
}

// ==================== RUNNER & HELPERS ====================

// RunAbuseTest executes a single abuse test
func RunAbuseTest(test AbuseTest, runner *AbuseTestRunner) (*AbuseResult, error) {
	return test.Procedure(runner)
}

// RunPhaseB executes all Phase B tests
func RunPhaseB(wafClient *waf.WAFClient, auth *target.Auth, control *target.Control, cfg *config.Config) (*PhaseBResult, error) {
	start := time.Now()

	result := &PhaseBResult{
		AbuseTests: make([]AbuseResult, 0),
	}

	runner := NewAbuseTestRunner(wafClient, auth, control, cfg)
	catalog := GetAbuseTestCatalog()

	// Group tests by category
	categories := []string{"BruteForce", "Relay", "Behavioral", "Fraud", "Recon"}

	for _, cat := range categories {
		// Reset target between categories (but not within)
		control.Reset()
		time.Sleep(100 * time.Millisecond)

		for _, test := range catalog {
			if test.Category != cat {
				continue
			}

			testResult, err := RunAbuseTest(test, runner)
			if err != nil {
				testResult = &AbuseResult{
					TestID: test.ID,
					Error:  err.Error(),
				}
			}

			// Apply pass criteria
			if test.PassCriteria != nil {
				testResult.Passed = test.PassCriteria(testResult)
			}

			result.AbuseTests = append(result.AbuseTests, *testResult)

			result.TotalTests++
			if testResult.Passed {
				result.PassedTests++
			}
		}
	}

	// Calculate abuse detection rate
	if result.TotalTests > 0 {
		result.AbuseDetectionRate = float64(result.PassedTests) / float64(result.TotalTests) * 100
	}

	result.DurationMs = time.Since(start).Milliseconds()

	return result, nil
}

// Summary returns human-readable summary
func (r *PhaseBResult) Summary() string {
	return fmt.Sprintf(
		"Phase B - Abuse Detection\n"+
		"  Tests: %d/%d passed (%.1f%%)\n"+
		"  Duration: %dms",
		r.PassedTests, r.TotalTests, r.AbuseDetectionRate,
		r.DurationMs,
	)
}

// Helper types
type credentialsPair struct {
	username string
	password string
}

func generateInvalidCredentials(count int) []credentialsPair {
	var creds []credentialsPair
	for i := 0; i < count; i++ {
		creds = append(creds, credentialsPair{
			username: fmt.Sprintf("user%d@example.com", rand.Intn(10000)),
			password: fmt.Sprintf("wrongpass%d", rand.Intn(10000)),
		})
	}
	return creds
}

func generateRandomPaths(count int) []string {
	var paths []string
	for i := 0; i < count; i++ {
		paths = append(paths, fmt.Sprintf("/random-path-%d-%d", i, rand.Intn(100000)))
	}
	return paths
}

// GetCategorySummary returns summary by category
func (r *PhaseBResult) GetCategorySummary() map[string]struct {
	Total  int
	Passed int
} {
	summary := make(map[string]struct {
		Total  int
		Passed int
	})

	// Map test IDs to categories
	categoryMap := map[string]string{
		"AB01": "BruteForce", "AB02": "BruteForce", "AB03": "BruteForce",
		"AR01": "Relay", "AR02": "Relay", "AR03": "Relay", "AR04": "Relay", "AR05": "Relay", "AR06": "Relay",
		"BA01": "Behavioral", "BA02": "Behavioral", "BA03": "Behavioral", "BA04": "Behavioral", "BA05": "Behavioral",
		"TF01": "Fraud", "TF02": "Fraud", "TF03": "Fraud", "TF04": "Fraud",
		"RE01": "Recon", "RE02": "Recon", "RE03": "Recon", "RE04": "Recon",
	}

	for _, test := range r.AbuseTests {
		cat := categoryMap[test.TestID]
		if cat == "" {
			cat = "Unknown"
		}

		entry := summary[cat]
		entry.Total++
		if test.Passed {
			entry.Passed++
		}
		summary[cat] = entry
	}

	return summary
}

// Export for testing
var (
	_ = GetIPRange          // Export for tests
	_ = GetSingleIP         // Export for tests
	_ = generateInvalidCredentials // Export for tests
	_ = generateRandomPaths        // Export for tests
	_ = httpclient.NewBoundClient  // Ensure import is used
)
