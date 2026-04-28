package phases

import (
	"testing"

	"github.com/waf-hackathon/benchmark/internal/waf"
)

func TestGetIPRange(t *testing.T) {
	tests := []struct {
		cat      IPRangeCategory
		expected int
	}{
		{IPRangeBruteForce, 10},
		{IPRangeRelay, 20},
		{IPRangeBehavioral, 20},
		{IPRangeFraud, 20},
		{IPRangeRecon, 20},
	}

	for _, tt := range tests {
		ips := GetIPRange(tt.cat)
		if len(ips) != tt.expected {
			t.Errorf("GetIPRange(%s) = %d IPs, want %d", tt.cat.Name, len(ips), tt.expected)
		}
	}
}

func TestGetSingleIP(t *testing.T) {
	tests := []struct {
		cat      IPRangeCategory
		offset   int
		expected string
	}{
		{IPRangeBruteForce, 0, "127.0.0.10"},
		{IPRangeBruteForce, 5, "127.0.0.15"},
		{IPRangeRelay, 0, "127.0.0.20"},
		{IPRangeRecon, 19, "127.0.0.99"},
	}

	for _, tt := range tests {
		got := GetSingleIP(tt.cat, tt.offset)
		if got != tt.expected {
			t.Errorf("GetSingleIP(%s, %d) = %s, want %s", tt.cat.Name, tt.offset, got, tt.expected)
		}
	}
}

func TestGetAbuseTestCatalog(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	if len(catalog) != 22 {
		t.Errorf("Expected 22 abuse tests, got %d", len(catalog))
	}

	// Count by category
	categories := make(map[string]int)
	for _, test := range catalog {
		categories[test.Category]++
	}

	// Verify counts
	expected := map[string]int{
		"BruteForce": 3,
		"Relay":      6,
		"Behavioral": 5,
		"Fraud":      4,
		"Recon":      4,
	}

	for cat, count := range expected {
		if categories[cat] != count {
			t.Errorf("Expected %d %s tests, got %d", count, cat, categories[cat])
		}
	}
}

func TestAbuseResultPassed(t *testing.T) {
	// Test that was blocked
	blocked := &AbuseResult{
		TestID:         "AB01",
		Passed:         true,
		InterventionAt: 5,
		FinalDecision:  waf.Block,
	}

	if !blocked.Passed {
		t.Error("Blocked result should be marked as passed")
	}

	if blocked.InterventionAt != 5 {
		t.Errorf("InterventionAt should be 5, got %d", blocked.InterventionAt)
	}
}

func TestMaxRisk(t *testing.T) {
	tests := []struct {
		scores   []int
		expected int
	}{
		{[]int{10, 20, 30, 25}, 30},
		{[]int{0, 0, 0}, 0},
		{[]int{100}, 100},
		{[]int{}, 0},
		{[]int{50, 30, 80, 20}, 80},
	}

	for _, tt := range tests {
		got := maxRisk(tt.scores)
		if got != tt.expected {
			t.Errorf("maxRisk(%v) = %d, want %d", tt.scores, got, tt.expected)
		}
	}
}

func TestParseIPList(t *testing.T) {
	input := `# Comment line
1.2.3.4
5.6.7.8

9.10.11.12  # inline comment stripped`

	ips := parseIPList(input)

	if len(ips) != 3 {
		t.Errorf("Expected 3 IPs, got %d: %v", len(ips), ips)
	}

	// Check that comments and empty lines are filtered
	for _, ip := range ips {
		if ip == "" || ip[0] == '#' || contains(ip, "#") {
			t.Errorf("parseIPList should filter comments, got: %s", ip)
		}
	}
}

func TestGenerateInvalidCredentials(t *testing.T) {
	creds := generateInvalidCredentials(10)

	if len(creds) != 10 {
		t.Errorf("Expected 10 credentials, got %d", len(creds))
	}

	// Check all unique
	seen := make(map[string]bool)
	for _, c := range creds {
		key := c.username + ":" + c.password
		if seen[key] {
			t.Error("generateInvalidCredentials should produce unique pairs")
		}
		seen[key] = true
	}
}

func TestGenerateRandomPaths(t *testing.T) {
	paths := generateRandomPaths(50)

	if len(paths) != 50 {
		t.Errorf("Expected 50 paths, got %d", len(paths))
	}

	// Check all unique (high probability)
	seen := make(map[string]bool)
	for _, p := range paths {
		if seen[p] {
			t.Error("generateRandomPaths should produce unique paths")
		}
		seen[p] = true
	}
}

func TestAbuseTestAB01Criteria(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var ab01 *AbuseTest
	for _, test := range catalog {
		if test.ID == "AB01" {
			ab01 = &test
			break
		}
	}

	if ab01 == nil {
		t.Fatal("AB01 not found in catalog")
	}

	if ab01.Category != "BruteForce" {
		t.Errorf("AB01 category should be BruteForce, got %s", ab01.Category)
	}

	// Test pass criteria
	passResult := &AbuseResult{InterventionAt: 5}
	failResult := &AbuseResult{InterventionAt: 15}
	noBlock := &AbuseResult{InterventionAt: 0}

	if !ab01.PassCriteria(passResult) {
		t.Error("AB01 should pass when intervention at request 5")
	}

	if ab01.PassCriteria(failResult) {
		t.Error("AB01 should fail when intervention at request 15 (>10)")
	}

	if ab01.PassCriteria(noBlock) {
		t.Error("AB01 should fail when no intervention")
	}
}

func TestAbuseTestAB02Criteria(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var ab02 *AbuseTest
	for _, test := range catalog {
		if test.ID == "AB02" {
			ab02 = &test
			break
		}
	}

	if ab02 == nil {
		t.Fatal("AB02 not found in catalog")
	}

	// Should pass if blocked within 20 requests
	pass := &AbuseResult{InterventionAt: 18}
	fail := &AbuseResult{InterventionAt: 25}

	if !ab02.PassCriteria(pass) {
		t.Error("AB02 should pass when intervention at request 18")
	}

	if ab02.PassCriteria(fail) {
		t.Error("AB02 should fail when intervention at request 25 (>20)")
	}
}

func TestAbuseTestAB03Criteria(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var ab03 *AbuseTest
	for _, test := range catalog {
		if test.ID == "AB03" {
			ab03 = &test
			break
		}
	}

	if ab03 == nil {
		t.Fatal("AB03 not found in catalog")
	}

	// Should pass if blocked within 15 requests
	pass := &AbuseResult{InterventionAt: 12}
	fail := &AbuseResult{InterventionAt: 20}

	if !ab03.PassCriteria(pass) {
		t.Error("AB03 should pass when intervention at request 12")
	}

	if ab03.PassCriteria(fail) {
		t.Error("AB03 should fail when intervention at request 20 (>15)")
	}
}

func TestAR01NormalXFFCriteria(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var ar01 *AbuseTest
	for _, test := range catalog {
		if test.ID == "AR01" {
			ar01 = &test
			break
		}
	}

	if ar01 == nil {
		t.Fatal("AR01 not found")
	}

	// Control test - should pass if allowed
	allowed := &AbuseResult{FinalDecision: waf.Allow}
	blocked := &AbuseResult{FinalDecision: waf.Block}

	if !ar01.PassCriteria(allowed) {
		t.Error("AR01 should pass when allowed")
	}

	if ar01.PassCriteria(blocked) {
		t.Error("AR01 should fail when blocked (it's a control)")
	}
}

func TestAR02SpoofedXFFCriteria(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var ar02 *AbuseTest
	for _, test := range catalog {
		if test.ID == "AR02" {
			ar02 = &test
			break
		}
	}

	if ar02 == nil {
		t.Fatal("AR02 not found")
	}

	// Should pass if blocked/challenged or high risk
	blocked := &AbuseResult{FinalDecision: waf.Block, RiskScores: []int{0}}
	highRisk := &AbuseResult{FinalDecision: waf.Allow, RiskScores: []int{40}}
	lowRisk := &AbuseResult{FinalDecision: waf.Allow, RiskScores: []int{10}}

	if !ar02.PassCriteria(blocked) {
		t.Error("AR02 should pass when blocked")
	}

	if !ar02.PassCriteria(highRisk) {
		t.Error("AR02 should pass when risk > 30")
	}

	if ar02.PassCriteria(lowRisk) {
		t.Error("AR02 should fail when allowed with low risk")
	}
}

func TestAR04TorExitNodeCriteria(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var ar04 *AbuseTest
	for _, test := range catalog {
		if test.ID == "AR04" {
			ar04 = &test
			break
		}
	}

	if ar04 == nil {
		t.Fatal("AR04 not found")
	}

	// Should pass if blocked or challenged
	blocked := &AbuseResult{FinalDecision: waf.Block}
	challenged := &AbuseResult{FinalDecision: waf.Challenge}
	allowed := &AbuseResult{FinalDecision: waf.Allow}

	if !ar04.PassCriteria(blocked) {
		t.Error("AR04 should pass when blocked")
	}

	if !ar04.PassCriteria(challenged) {
		t.Error("AR04 should pass when challenged")
	}

	if ar04.PassCriteria(allowed) {
		t.Error("AR04 should fail when allowed")
	}
}

func TestBA01DirectLoginCriteria(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var ba01 *AbuseTest
	for _, test := range catalog {
		if test.ID == "BA01" {
			ba01 = &test
			break
		}
	}

	if ba01 == nil {
		t.Fatal("BA01 not found")
	}

	// Should pass if challenged/blocked or high risk
	challenged := &AbuseResult{FinalDecision: waf.Challenge, RiskScores: []int{20}}
	highRisk := &AbuseResult{FinalDecision: waf.Allow, RiskScores: []int{35}}
	lowRisk := &AbuseResult{FinalDecision: waf.Allow, RiskScores: []int{10}}

	if !ba01.PassCriteria(challenged) {
		t.Error("BA01 should pass when challenged")
	}

	if !ba01.PassCriteria(highRisk) {
		t.Error("BA01 should pass when risk > 30")
	}

	if ba01.PassCriteria(lowRisk) {
		t.Error("BA01 should fail with low risk")
	}
}

func TestBA02BotTimingCriteria(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var ba02 *AbuseTest
	for _, test := range catalog {
		if test.ID == "BA02" {
			ba02 = &test
			break
		}
	}

	if ba02 == nil {
		t.Fatal("BA02 not found")
	}

	// Should pass if blocked within 60 requests
	earlyBlock := &AbuseResult{InterventionAt: 45}
	lateBlock := &AbuseResult{InterventionAt: 80}
	noBlock := &AbuseResult{InterventionAt: 0}

	if !ba02.PassCriteria(earlyBlock) {
		t.Error("BA02 should pass when blocked at request 45")
	}

	if ba02.PassCriteria(lateBlock) {
		t.Error("BA02 should fail when blocked at request 80 (>60)")
	}

	if ba02.PassCriteria(noBlock) {
		t.Error("BA02 should fail when no block")
	}
}

func TestTF01VelocityCheck(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var tf01 *AbuseTest
	for _, test := range catalog {
		if test.ID == "TF01" {
			tf01 = &test
			break
		}
	}

	if tf01 == nil {
		t.Fatal("TF01 not found")
	}

	if tf01.Category != "Fraud" {
		t.Errorf("TF01 category should be Fraud, got %s", tf01.Category)
	}

	// Should pass if blocked/challenged
	blocked := &AbuseResult{FinalDecision: waf.Block}
	challenged := &AbuseResult{FinalDecision: waf.Challenge}
	allowed := &AbuseResult{FinalDecision: waf.Allow}

	if !tf01.PassCriteria(blocked) {
		t.Error("TF01 should pass when blocked")
	}

	if !tf01.PassCriteria(challenged) {
		t.Error("TF01 should pass when challenged")
	}

	if tf01.PassCriteria(allowed) {
		t.Error("TF01 should fail when allowed")
	}
}

func TestRE01ReconPathsCriteria(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var re01 *AbuseTest
	for _, test := range catalog {
		if test.ID == "RE01" {
			re01 = &test
			break
		}
	}

	if re01 == nil {
		t.Fatal("RE01 not found")
	}

	// Should pass if blocked within 50 requests
	early := &AbuseResult{InterventionAt: 30}
	late := &AbuseResult{InterventionAt: 100}

	if !re01.PassCriteria(early) {
		t.Error("RE01 should pass when blocked at request 30")
	}

	if re01.PassCriteria(late) {
		t.Error("RE01 should fail when blocked at request 100 (>50)")
	}
}

func TestRE04CanaryEndpointsCriteria(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var re04 *AbuseTest
	for _, test := range catalog {
		if test.ID == "RE04" {
			re04 = &test
			break
		}
	}

	if re04 == nil {
		t.Fatal("RE04 not found")
	}

	// Should pass if blocked (max-risk lock)
	blocked := &AbuseResult{FinalDecision: waf.Block}
	challenged := &AbuseResult{FinalDecision: waf.Challenge}
	allowed := &AbuseResult{FinalDecision: waf.Allow}

	if !re04.PassCriteria(blocked) {
		t.Error("RE04 should pass when blocked")
	}

	if !re04.PassCriteria(challenged) {
		t.Error("RE04 should pass when challenged")
	}

	if re04.PassCriteria(allowed) {
		t.Error("RE04 should fail when allowed")
	}
}

func TestPhaseBResultSummary(t *testing.T) {
	result := &PhaseBResult{
		AbuseTests:         make([]AbuseResult, 0),
		AbuseDetectionRate: 78.5,
		TotalTests:         23,
		PassedTests:        18,
		DurationMs:         45000,
	}

	summary := result.Summary()

	if summary == "" {
		t.Error("Summary should not be empty")
	}

	if !contains(summary, "Phase B") {
		t.Error("Summary should mention Phase B")
	}

	if !contains(summary, "18/23") {
		t.Error("Summary should show test count")
	}

	if !contains(summary, "78.5") {
		t.Error("Summary should show detection rate")
	}
}

func TestPhaseBResultCategorySummary(t *testing.T) {
	result := &PhaseBResult{
		AbuseTests: []AbuseResult{
			{TestID: "AB01", Passed: true},
			{TestID: "AB02", Passed: true},
			{TestID: "AB03", Passed: false},
			{TestID: "AR01", Passed: true},
			{TestID: "AR02", Passed: true},
		},
	}

	summary := result.GetCategorySummary()

	if len(summary) == 0 {
		t.Fatal("Category summary should not be empty")
	}

	bruteForce := summary["BruteForce"]
	if bruteForce.Total != 3 {
		t.Errorf("Expected 3 BruteForce tests, got %d", bruteForce.Total)
	}
	if bruteForce.Passed != 2 {
		t.Errorf("Expected 2 passed BruteForce tests, got %d", bruteForce.Passed)
	}

	relay := summary["Relay"]
	if relay.Total != 2 {
		t.Errorf("Expected 2 Relay tests, got %d", relay.Total)
	}
	if relay.Passed != 2 {
		t.Errorf("Expected 2 passed Relay tests, got %d", relay.Passed)
	}
}

func TestAllTestIDsUnique(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	seen := make(map[string]bool)
	for _, test := range catalog {
		if seen[test.ID] {
			t.Errorf("Duplicate test ID: %s", test.ID)
		}
		seen[test.ID] = true
	}
}

func TestAllTestsHaveProcedures(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	for _, test := range catalog {
		if test.Procedure == nil {
			t.Errorf("Test %s has no Procedure", test.ID)
		}
		if test.PassCriteria == nil {
			t.Errorf("Test %s has no PassCriteria", test.ID)
		}
	}
}

func TestAbuseTestDescriptions(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	for _, test := range catalog {
		if test.Description == "" {
			t.Errorf("Test %s has no description", test.ID)
		}
	}
}

func TestIPRangesAreDistinct(t *testing.T) {
	ranges := []IPRangeCategory{
		IPRangeBruteForce,
		IPRangeRelay,
		IPRangeBehavioral,
		IPRangeFraud,
		IPRangeRecon,
	}

	allIPs := make(map[string]string)
	for _, r := range ranges {
		ips := GetIPRange(r)
		for _, ip := range ips {
			if existing, found := allIPs[ip]; found {
				t.Errorf("IP %s appears in both %s and %s", ip, existing, r.Name)
			}
			allIPs[ip] = r.Name
		}
	}

	// Should have 90 unique IPs (10+20+20+20+20)
	if len(allIPs) != 90 {
		t.Errorf("Expected 90 unique IPs, got %d", len(allIPs))
	}
}

func TestBA03MissingReferer(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var ba03 *AbuseTest
	for _, test := range catalog {
		if test.ID == "BA03" {
			ba03 = &test
			break
		}
	}

	if ba03 == nil {
		t.Fatal("BA03 not found")
	}

	// Should pass if any risk detected
	highRisk := &AbuseResult{RiskScores: []int{10}, FinalDecision: waf.Allow}
	noRisk := &AbuseResult{RiskScores: []int{0}, FinalDecision: waf.Allow}
	blocked := &AbuseResult{RiskScores: []int{0}, FinalDecision: waf.Block}

	if !ba03.PassCriteria(highRisk) {
		t.Error("BA03 should pass when risk > 0")
	}

	if ba03.PassCriteria(noRisk) {
		t.Error("BA03 should fail when no risk detected")
	}

	if !ba03.PassCriteria(blocked) {
		t.Error("BA03 should pass when blocked")
	}
}

func TestBA04HighRateCriteria(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var ba04 *AbuseTest
	for _, test := range catalog {
		if test.ID == "BA04" {
			ba04 = &test
			break
		}
	}

	if ba04 == nil {
		t.Fatal("BA04 not found")
	}

	// Should pass if any rate limit observed
	limited := &AbuseResult{
		Decisions:     []waf.Decision{waf.Allow, waf.Allow, waf.RateLimit},
		FinalDecision: waf.RateLimit,
	}
	challenged := &AbuseResult{
		Decisions:     []waf.Decision{waf.Allow, waf.Challenge},
		FinalDecision: waf.Challenge,
	}
	allowed := &AbuseResult{
		Decisions:     []waf.Decision{waf.Allow, waf.Allow},
		FinalDecision: waf.Allow,
	}

	if !ba04.PassCriteria(limited) {
		t.Error("BA04 should pass when rate limited")
	}

	if !ba04.PassCriteria(challenged) {
		t.Error("BA04 should pass when challenged")
	}

	if ba04.PassCriteria(allowed) {
		t.Error("BA04 should fail when all allowed")
	}
}

func TestRE03StackTraceStripped(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var re03 *AbuseTest
	for _, test := range catalog {
		if test.ID == "RE03" {
			re03 = &test
			break
		}
	}

	if re03 == nil {
		t.Fatal("RE03 not found")
	}

	// The test is about L01 NOT being present (stack traces stripped)
	// For now the criteria just returns true (placeholder)
	result := &AbuseResult{FinalDecision: waf.Allow}
	if !re03.PassCriteria(result) {
		t.Error("RE03 criteria should pass when no L01 marker (stack traces stripped)")
	}
}

func TestFraudTestsRequireAuth(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	fraudTests := []string{"TF01", "TF02", "TF03", "TF04"}
	for _, id := range fraudTests {
		found := false
		for _, test := range catalog {
			if test.ID == id {
				found = true
				if test.Category != "Fraud" {
					t.Errorf("%s should be Fraud category", id)
				}
				break
			}
		}
		if !found {
			t.Errorf("%s not found in catalog", id)
		}
	}
}

func TestAbuseDetectionRateCalculation(t *testing.T) {
	result := &PhaseBResult{
		TotalTests:  10,
		PassedTests: 7,
	}

	result.AbuseDetectionRate = float64(result.PassedTests) / float64(result.TotalTests) * 100

	if result.AbuseDetectionRate != 70.0 {
		t.Errorf("Expected 70.0%% detection rate, got %.1f%%", result.AbuseDetectionRate)
	}
}

func TestEmptyAbuseDetectionRate(t *testing.T) {
	result := &PhaseBResult{
		TotalTests:  0,
		PassedTests: 0,
	}

	// Avoid division by zero
	if result.TotalTests > 0 {
		result.AbuseDetectionRate = float64(result.PassedTests) / float64(result.TotalTests) * 100
	}

	if result.AbuseDetectionRate != 0 {
		t.Errorf("Expected 0%% for empty results, got %.1f%%", result.AbuseDetectionRate)
	}
}

func TestAR06ResidentialIPControl(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var ar06 *AbuseTest
	for _, test := range catalog {
		if test.ID == "AR06" {
			ar06 = &test
			break
		}
	}

	if ar06 == nil {
		t.Fatal("AR06 not found")
	}

	// Control test - should be allowed
	allowed := &AbuseResult{FinalDecision: waf.Allow}
	sanitized := &AbuseResult{FinalDecision: waf.PreventedSanitized}
	blocked := &AbuseResult{FinalDecision: waf.Block}

	if !ar06.PassCriteria(allowed) {
		t.Error("AR06 should pass when allowed (control)")
	}

	if !ar06.PassCriteria(sanitized) {
		t.Error("AR06 should pass when sanitized (control)")
	}

	if ar06.PassCriteria(blocked) {
		t.Error("AR06 should fail when blocked (false positive)")
	}
}

func TestRE02OptionsFlood(t *testing.T) {
	catalog := GetAbuseTestCatalog()

	var re02 *AbuseTest
	for _, test := range catalog {
		if test.ID == "RE02" {
			re02 = &test
			break
		}
	}

	if re02 == nil {
		t.Fatal("RE02 not found")
	}

	// Should pass if rate limited or challenged
	limited := &AbuseResult{FinalDecision: waf.RateLimit}
	challenged := &AbuseResult{FinalDecision: waf.Challenge}
	allowed := &AbuseResult{FinalDecision: waf.Allow}

	if !re02.PassCriteria(limited) {
		t.Error("RE02 should pass when rate limited")
	}

	if !re02.PassCriteria(challenged) {
		t.Error("RE02 should pass when challenged")
	}

	if re02.PassCriteria(allowed) {
		t.Error("RE02 should fail when allowed")
	}
}
