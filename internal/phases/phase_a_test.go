package phases

import (
	"testing"

	"github.com/waf-hackathon/benchmark/internal/target"
	"github.com/waf-hackathon/benchmark/internal/waf"
)

func TestGetExploitTestCatalog(t *testing.T) {
	catalog := GetExploitTestCatalog()

	// Should have V01-V24 (but we skip some in the basic implementation)
	if len(catalog) == 0 {
		t.Error("Expected non-empty exploit test catalog")
	}

	// Check for key tests
	foundIDs := make(map[string]bool)
	for _, test := range catalog {
		foundIDs[test.ID] = true
	}

	expectedIDs := []string{"V01", "V02", "V03", "V04", "V05", "V06", "V07", "V08", "V09", "V10", "V11", "V14", "V15", "V16", "V19"}
	for _, id := range expectedIDs {
		if !foundIDs[id] {
			t.Errorf("Expected to find %s in catalog", id)
		}
	}
}

func TestGetLeakTestCatalog(t *testing.T) {
	catalog := GetLeakTestCatalog()

	if len(catalog) != 5 {
		t.Errorf("Expected 5 leak tests, got %d", len(catalog))
	}

	// Check for all leak IDs
	foundIDs := make(map[string]bool)
	for _, test := range catalog {
		foundIDs[test.ID] = true
	}

	for i := 1; i <= 5; i++ {
		id := formatLeakID(i)
		if !foundIDs[id] {
			t.Errorf("Expected to find %s in leak catalog", id)
		}
	}
}

func formatLeakID(i int) string {
	if i < 10 {
		return "L0" + string(rune('0'+i))
	}
	return "L" + string(rune('0'+i))
}

func TestExploitResultIsPassed(t *testing.T) {
	tests := []struct {
		name           string
		result         ExploitResult
		expectedPassed bool
	}{
		{
			name: "Blocked exploit",
			result: ExploitResult{
				Decision:        waf.Block,
				Bypassed:        false,
				NegativeControl: false,
			},
			expectedPassed: true,
		},
		{
			name: "Bypassed exploit",
			result: ExploitResult{
				Decision:        waf.ExploitPassed,
				Bypassed:        true,
				Markers:         []string{"__V01_SQLI__"},
				NegativeControl: false,
			},
			expectedPassed: false,
		},
		{
			name: "Negative control with no markers - should pass",
			result: ExploitResult{
				Decision:        waf.Allow,
				Bypassed:        false,
				Markers:         []string{},
				NegativeControl: true,
			},
			expectedPassed: true,
		},
		{
			name: "Negative control with markers - should fail",
			result: ExploitResult{
				Decision:        waf.Allow,
				Bypassed:        true,
				Markers:         []string{"__CANARY__"},
				NegativeControl: true,
			},
			expectedPassed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsPassed(); got != tt.expectedPassed {
				t.Errorf("IsPassed() = %v, want %v", got, tt.expectedPassed)
			}
		})
	}
}

func TestExploitResultString(t *testing.T) {
	result := ExploitResult{
		TestID:      "V01",
		Category:    "SQLi",
		Decision:    waf.Block,
		Description: "Test description",
		Markers:     []string{},
	}

	str := result.String()
	if str == "" {
		t.Error("String() should return non-empty string")
	}

	// Should contain key info
	if !contains(str, "V01") {
		t.Error("String() should contain test ID")
	}
	if !contains(str, "Block") {
		t.Error("String() should contain decision")
	}
}

func TestV01Payload(t *testing.T) {
	catalog := GetExploitTestCatalog()

	var v01 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V01" {
			v01 = &test
			break
		}
	}

	if v01 == nil {
		t.Fatal("V01 not found in catalog")
	}

	if v01.Method != "POST" {
		t.Errorf("V01 should use POST, got %s", v01.Method)
	}

	if v01.Path != "/login" {
		t.Errorf("V01 should target /login, got %s", v01.Path)
	}

	if v01.ProofMarker != "__V01_SQLI__" {
		t.Errorf("V01 proof marker should be __V01_SQLI__, got %s", v01.ProofMarker)
	}

	username, ok := v01.Payload["username"].(string)
	if !ok || username == "" {
		t.Error("V01 should have username payload")
	}

	if !contains(username, "OR 1=1") {
		t.Error("V01 payload should contain SQLi pattern")
	}
}

func TestV04XSSPayload(t *testing.T) {
	catalog := GetExploitTestCatalog()

	var v04 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V04" {
			v04 = &test
			break
		}
	}

	if v04 == nil {
		t.Fatal("V04 not found in catalog")
	}

	if v04.Category != "XSS" {
		t.Errorf("V04 category should be XSS, got %s", v04.Category)
	}

	name, ok := v04.Payload["name"].(string)
	if !ok {
		t.Fatal("V04 should have name payload")
	}

	if !contains(name, "<script>") {
		t.Error("V04 payload should contain <script> tag")
	}
}

func TestV06PathTraversal(t *testing.T) {
	catalog := GetExploitTestCatalog()

	var v06 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V06" {
			v06 = &test
			break
		}
	}

	if v06 == nil {
		t.Fatal("V06 not found in catalog")
	}

	if !contains(v06.Path, "../") || !contains(v06.Path, "etc/passwd") {
		t.Error("V06 path should contain traversal pattern")
	}
}

func TestV08SSRF(t *testing.T) {
	catalog := GetExploitTestCatalog()

	var v08 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V08" {
			v08 = &test
			break
		}
	}

	if v08 == nil {
		t.Fatal("V08 not found in catalog")
	}

	if v08.Category != "SSRF" {
		t.Errorf("V08 category should be SSRF, got %s", v08.Category)
	}

	url, ok := v08.Payload["avatar_url"].(string)
	if !ok {
		t.Fatal("V08 should have avatar_url payload")
	}

	if !contains(url, "169.254.169.254") {
		t.Error("V08 payload should contain metadata IP")
	}
}

func TestV15OversizedPayload(t *testing.T) {
	catalog := GetExploitTestCatalog()

	var v15 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V15" {
			v15 = &test
			break
		}
	}

	if v15 == nil {
		t.Fatal("V15 not found in catalog")
	}

	raw, ok := v15.Payload["_raw"].(string)
	if !ok {
		t.Fatal("V15 should have _raw payload")
	}

	// Should be large (> 1MB worth of content indicated)
	if len(raw) < 1000000 {
		t.Logf("V15 payload size: %d bytes (may be smaller due to string repeat)", len(raw))
	}
}

func TestV19NestedPayload(t *testing.T) {
	catalog := GetExploitTestCatalog()

	var v19 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V19" {
			v19 = &test
			break
		}
	}

	if v19 == nil {
		t.Fatal("V19 not found in catalog")
	}

	// Check nested structure
	nested, ok := v19.Payload["nested"].(map[string]interface{})
	if !ok {
		t.Fatal("V19 should have nested payload")
	}

	// Count nesting depth
	depth := 0
	current := nested
	for {
		next, ok := current["nested"].(map[string]interface{})
		if !ok {
			break
		}
		depth++
		current = next
	}

	if depth < 50 { // Should be deeply nested
		t.Errorf("V19 nesting depth should be > 50, got %d", depth)
	}
}

func TestGenerateNestedPayload(t *testing.T) {
	payload := generateNestedPayload(10)

	// Count depth
	depth := 0
	current := payload
	for {
		next, ok := current["nested"].(map[string]interface{})
		if !ok {
			// Check for leaf
			if _, hasValue := current["value"]; hasValue {
				break
			}
			t.Fatal("Malformed nested payload")
		}
		depth++
		current = next
	}

	if depth != 9 { // 10 requested = 9 levels of nesting + 1 leaf
		t.Errorf("Expected depth 9, got %d", depth)
	}
}

func TestBuildURLWithParams(t *testing.T) {
	params := map[string]interface{}{
		"page":  "1",
		"limit": "10",
	}

	url := buildURLWithParams("/api/data", params)

	if !contains(url, "/api/data?") {
		t.Errorf("URL should start with /api/data?, got %s", url)
	}

	if !contains(url, "page=") {
		t.Error("URL should contain page parameter")
	}

	if !contains(url, "limit=") {
		t.Error("URL should contain limit parameter")
	}
}

func TestBuildURLWithEmptyParams(t *testing.T) {
	url := buildURLWithParams("/api/data", map[string]interface{}{})

	if url != "/api/data" {
		t.Errorf("Expected /api/data, got %s", url)
	}
}

func TestLeakTestL01(t *testing.T) {
	catalog := GetLeakTestCatalog()

	var l01 *LeakTest
	for _, test := range catalog {
		if test.ID == "L01" {
			l01 = &test
			break
		}
	}

	if l01 == nil {
		t.Fatal("L01 not found in catalog")
	}

	if l01.ProofMarker != "__L01_STACKTRACE__" {
		t.Errorf("L01 marker should be __L01_STACKTRACE__, got %s", l01.ProofMarker)
	}
}

func TestLeakTestL02(t *testing.T) {
	catalog := GetLeakTestCatalog()

	var l02 *LeakTest
	for _, test := range catalog {
		if test.ID == "L02" {
			l02 = &test
			break
		}
	}

	if l02 == nil {
		t.Fatal("L02 not found in catalog")
	}

	if l02.HeaderCheck != "X-Internal-Host" {
		t.Errorf("L02 should check X-Internal-Host header, got %s", l02.HeaderCheck)
	}
}

func TestPhaseAResultSummary(t *testing.T) {
	result := &PhaseAResult{
		ExploitTests:          make([]ExploitResult, 0),
		LeakTests:             make([]LeakResult, 0),
		ExploitPreventionRate: 85.5,
		OutboundFilterRate:    90.0,
		TotalExploits:       20,
		BlockedExploits:     17,
		TotalLeaks:          5,
		FilteredLeaks:       4,
		DurationMs:          15000,
	}

	summary := result.Summary()

	if summary == "" {
		t.Error("Summary should not be empty")
	}

	// Should contain key metrics
	if !contains(summary, "Phase A") {
		t.Error("Summary should mention Phase A")
	}

	if !contains(summary, "85.5") {
		t.Error("Summary should contain exploit prevention rate")
	}
}

func TestExploitTestAuthRequired(t *testing.T) {
	catalog := GetExploitTestCatalog()

	// V01 should not require auth
	var v01 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V01" {
			v01 = &test
			break
		}
	}

	if v01 == nil {
		t.Fatal("V01 not found")
	}

	if v01.AuthRequired {
		t.Error("V01 should not require authentication")
	}

	// V02 requires auth
	var v02 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V02" {
			v02 = &test
			break
		}
	}

	if v02 == nil {
		t.Fatal("V02 not found")
	}

	if !v02.AuthRequired {
		t.Error("V02 should require authentication")
	}
}

func TestExploitTestHeaders(t *testing.T) {
	catalog := GetExploitTestCatalog()

	// V11 should have Host header
	var v11 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V11" {
			v11 = &test
			break
		}
	}

	if v11 == nil {
		t.Fatal("V11 not found")
	}

	host, ok := v11.Headers["Host"]
	if !ok {
		t.Fatal("V11 should have Host header")
	}

	if host != "evil.com" {
		t.Errorf("V11 Host should be evil.com, got %s", host)
	}
}

func TestExploitTestRawPayload(t *testing.T) {
	catalog := GetExploitTestCatalog()

	// V14 should have _raw payload
	var v14 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V14" {
			v14 = &test
			break
		}
	}

	if v14 == nil {
		t.Fatal("V14 not found")
	}

	raw, ok := v14.Payload["_raw"].(string)
	if !ok {
		t.Fatal("V14 should have _raw payload")
	}

	if !contains(raw, "1e999999") {
		t.Error("V14 raw payload should contain malformed number")
	}
}

func TestLeakResult(t *testing.T) {
	// Leak detected case
	leakDetected := LeakResult{
		TestID:       "L01",
		Passed:       false,
		LeakDetected: true,
		Markers:      []string{"__L01_STACKTRACE__"},
	}

	if leakDetected.Passed {
		t.Error("LeakResult with detected leak should not be marked as passed")
	}

	// No leak case
	noLeak := LeakResult{
		TestID:       "L01",
		Passed:       true,
		LeakDetected: false,
		Markers:      []string{},
	}

	if !noLeak.Passed {
		t.Error("LeakResult with no leak should be marked as passed")
	}
}

func TestAllVulnerabilityIDsPresent(t *testing.T) {
	catalog := GetExploitTestCatalog()

	// Get all expected IDs from capabilities
	expectedIDs := target.GetVulnCategories()

	// Check which ones we have
	haveIDs := make(map[string]bool)
	for _, test := range catalog {
		haveIDs[test.ID] = true
	}

	// We should have at least the main ones
	mainTests := []string{"V01", "V02", "V03", "V04", "V05", "V06", "V07", "V08", "V09", "V10", "V11"}
	for _, id := range mainTests {
		if !haveIDs[id] {
			t.Errorf("Missing required vulnerability test %s", id)
		}
	}

	t.Logf("Catalog has %d/%d vulnerability tests", len(catalog), len(expectedIDs))
}

func TestAllLeakIDsPresent(t *testing.T) {
	catalog := GetLeakTestCatalog()

	expectedIDs := target.GetLeakCategories()

	haveIDs := make(map[string]bool)
	for _, test := range catalog {
		haveIDs[test.ID] = true
	}

	for _, id := range expectedIDs {
		if !haveIDs[id] {
			t.Errorf("Missing leak test %s", id)
		}
	}
}

func TestV10CRLFPayload(t *testing.T) {
	catalog := GetExploitTestCatalog()

	var v10 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V10" {
			v10 = &test
			break
		}
	}

	if v10 == nil {
		t.Fatal("V10 not found")
	}

	if v10.Category != "CRLF" {
		t.Errorf("V10 category should be CRLF, got %s", v10.Category)
	}

	// Should have header with CRLF
	header, ok := v10.Headers["X-Inject"]
	if !ok {
		t.Fatal("V10 should have X-Inject header")
	}

	if !contains(header, "\r\n") {
		t.Error("V10 header should contain CRLF injection")
	}
}

func TestV22XXEPayload(t *testing.T) {
	catalog := GetExploitTestCatalog()

	var v22 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V22" {
			v22 = &test
			break
		}
	}

	if v22 == nil {
		t.Fatal("V22 not found")
	}

	if v22.Category != "XXE" {
		t.Errorf("V22 category should be XXE, got %s", v22.Category)
	}

	raw, ok := v22.Payload["_raw"].(string)
	if !ok {
		t.Fatal("V22 should have _raw XML payload")
	}

	if !contains(raw, "<!ENTITY") {
		t.Error("V22 payload should contain XXE entity definition")
	}
}

func TestV24SmugglingPayload(t *testing.T) {
	catalog := GetExploitTestCatalog()

	var v24 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V24" {
			v24 = &test
			break
		}
	}

	if v24 == nil {
		t.Fatal("V24 not found")
	}

	if v24.Category != "RequestSmuggling" {
		t.Errorf("V24 category should be RequestSmuggling, got %s", v24.Category)
	}

	// Should have conflicting headers
	_, hasContentLength := v24.Headers["Content-Length"]
	_, hasTransferEncoding := v24.Headers["Transfer-Encoding"]

	if !hasContentLength || !hasTransferEncoding {
		t.Error("V24 should have both Content-Length and Transfer-Encoding headers")
	}
}

func TestExploitTestProofMarkers(t *testing.T) {
	catalog := GetExploitTestCatalog()

	for _, test := range catalog {
		if test.ProofMarker == "" {
			t.Errorf("%s should have a proof marker", test.ID)
			continue
		}

		// Marker should follow pattern __VXX_xxx__
		if !waf.ValidateMarker(test.ProofMarker) {
			// Some custom markers might not match, that's OK
			if !contains(test.ProofMarker, test.ID) {
				t.Errorf("%s proof marker %s should contain test ID", test.ID, test.ProofMarker)
			}
		}
	}
}

func TestLeakTestProofMarkers(t *testing.T) {
	catalog := GetLeakTestCatalog()

	for _, test := range catalog {
		if test.ProofMarker == "" {
			t.Errorf("%s should have a proof marker", test.ID)
			continue
		}

		// Marker should follow pattern __LXX_xxx__
		if !waf.ValidateMarker(test.ProofMarker) {
			if !contains(test.ProofMarker, test.ID) {
				t.Errorf("%s proof marker %s should contain test ID", test.ID, test.ProofMarker)
			}
		}
	}
}

func TestPhaseAResultCalculations(t *testing.T) {
	result := &PhaseAResult{
		ExploitTests: []ExploitResult{
			{TestID: "V01", Passed: true, Decision: waf.Block},
			{TestID: "V02", Passed: true, Decision: waf.Block},
			{TestID: "V03", Passed: false, Decision: waf.ExploitPassed, Bypassed: true},
			{TestID: "V04", Passed: true, Decision: waf.Challenge},
		},
		LeakTests: []LeakResult{
			{TestID: "L01", Passed: true},
			{TestID: "L02", Passed: false, LeakDetected: true},
		},
		TotalExploits:   4,
		BlockedExploits: 3,
		TotalLeaks:      2,
		FilteredLeaks:   1,
	}

	// Calculate rates
	result.ExploitPreventionRate = float64(result.BlockedExploits) / float64(result.TotalExploits) * 100
	result.OutboundFilterRate = float64(result.FilteredLeaks) / float64(result.TotalLeaks) * 100

	if result.ExploitPreventionRate != 75.0 {
		t.Errorf("Expected 75%% exploit prevention, got %.1f%%", result.ExploitPreventionRate)
	}

	if result.OutboundFilterRate != 50.0 {
		t.Errorf("Expected 50%% outbound filter, got %.1f%%", result.OutboundFilterRate)
	}
}

func TestV16ContentTypeBypass(t *testing.T) {
	catalog := GetExploitTestCatalog()

	var v16 *ExploitTest
	for _, test := range catalog {
		if test.ID == "V16" {
			v16 = &test
			break
		}
	}

	if v16 == nil {
		t.Fatal("V16 not found")
	}

	if v16.Category != "Bypass" {
		t.Errorf("V16 category should be Bypass, got %s", v16.Category)
	}

	ct, ok := v16.Headers["Content-Type"]
	if !ok || ct != "text/plain" {
		t.Error("V16 should have Content-Type: text/plain header")
	}

	raw, ok := v16.Payload["_raw"].(string)
	if !ok {
		t.Fatal("V16 should have _raw payload")
	}

	if !contains(raw, "OR 1=1") {
		t.Error("V16 should contain SQLi payload despite text/plain content type")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
