package httpclient

import (
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func TestNewBoundClient(t *testing.T) {
	opts := DefaultClientOptions()
	client, err := NewBoundClient("127.0.0.10", opts)
	if err != nil {
		t.Fatalf("Failed to create bound client: %v", err)
	}
	defer client.Close()

	if client.SourceIP() != "127.0.0.10" {
		t.Errorf("Expected source IP 127.0.0.10, got %s", client.SourceIP())
	}
}

func TestNewBoundClientInvalidIP(t *testing.T) {
	opts := DefaultClientOptions()
	_, err := NewBoundClient("invalid-ip", opts)
	if err == nil {
		t.Error("Expected error for invalid IP")
	}
}

func TestRequestBuilderWithJSONBodyAndStats(t *testing.T) {
	opts := DefaultClientOptions()
	client, err := NewBoundClient("127.0.0.11", opts)
	if err != nil {
		t.Fatalf("Failed to create bound client: %v", err)
	}
	defer client.Close()

	stats := client.Stats()
	if stats["source_ip"] != "127.0.0.11" {
		t.Errorf("Expected source_ip 127.0.0.11, got %v", stats["source_ip"])
	}
	if stats["timeout_ms"] != opts.Timeout.Milliseconds() {
		t.Errorf("Expected timeout_ms %d, got %v", opts.Timeout.Milliseconds(), stats["timeout_ms"])
	}
}

func TestClientOptionsDefaultsInHelpers(t *testing.T) {
	opts := DefaultClientOptions()
	if opts.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", opts.Timeout)
	}
	if !opts.SkipTLSVerify {
		t.Error("Expected SkipTLSVerify to be true")
	}
	if opts.MaxConns != 100 {
		t.Errorf("Expected MaxConns 100, got %d", opts.MaxConns)
	}
}

func TestNewRequest(t *testing.T) {
	rb := NewRequest("GET", "http://example.com/test")
	req := rb.Build()
	defer ReleaseRequest(req)

	if string(req.Header.Method()) != "GET" {
		t.Errorf("Expected method GET, got %s", req.Header.Method())
	}
	if string(req.RequestURI()) != "http://example.com/test" {
		t.Errorf("Expected URI http://example.com/test, got %s", req.RequestURI())
	}
}

func TestRequestBuilderWithJSONBody(t *testing.T) {
	data := map[string]string{"key": "value"}
	rb, err := NewRequest("POST", "http://example.com/api").WithJSONBody(data)
	if err != nil {
		t.Fatalf("Failed to set JSON body: %v", err)
	}

	req := rb.Build()
	defer ReleaseRequest(req)

	contentType := string(req.Header.ContentType())
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	body := string(req.Body())
	if body != `{"key":"value"}` {
		t.Errorf("Expected JSON body, got %s", body)
	}
}

func TestRequestBuilderWithHeaders(t *testing.T) {
	rb := NewRequest("GET", "http://example.com").
		WithHeader("X-Custom-Header", "value1").
		WithHeaders(map[string]string{"X-Another": "value2"})

	req := rb.Build()
	defer ReleaseRequest(req)

	if string(req.Header.Peek("X-Custom-Header")) != "value1" {
		t.Error("Expected X-Custom-Header: value1")
	}
	if string(req.Header.Peek("X-Another")) != "value2" {
		t.Error("Expected X-Another: value2")
	}
}

func TestParseResponse(t *testing.T) {
	// Create a mock fasthttp response
	fresp := fasthttp.AcquireResponse()
	fresp.SetStatusCode(200)
	fresp.Header.Set("Content-Type", "application/json")
	fresp.Header.Set("X-Custom-Header", "custom-value")
	fresp.SetBody([]byte(`{"status":"ok"}`))

	resp := ParseResponse(fresp)
	fasthttp.ReleaseResponse(fresp)

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	if string(resp.Body) != `{"status":"ok"}` {
		t.Errorf("Expected body, got %s", string(resp.Body))
	}

	contentType, exists := resp.GetHeader("Content-Type")
	if !exists || contentType != "application/json" {
		t.Error("Expected Content-Type header")
	}

	customHeader, exists := resp.GetHeader("X-Custom-Header")
	if !exists || customHeader != "custom-value" {
		t.Error("Expected X-Custom-Header")
	}
}

func TestParseIPRange(t *testing.T) {
	tests := []struct {
		ipRange string
		want    int
		wantErr bool
	}{
		{"127.0.0.10-12", 3, false},
		{"127.0.0.10-10", 1, false},
		{"127.0.0.10-19", 10, false},
		{"invalid", 0, true},
		{"127.0.0.10-5", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.ipRange, func(t *testing.T) {
			ips, err := ParseIPRange(tt.ipRange)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseIPRange() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(ips) != tt.want {
				t.Errorf("Expected %d IPs, got %d", tt.want, len(ips))
			}
		})
	}
}

func TestParseIPRangeContent(t *testing.T) {
	ips, err := ParseIPRange("127.0.0.10-12")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expected := []string{"127.0.0.10", "127.0.0.11", "127.0.0.12"}
	for i, ip := range expected {
		if ips[i] != ip {
			t.Errorf("Expected IP %s at index %d, got %s", ip, i, ips[i])
		}
	}
}

func TestBuildURLSimple(t *testing.T) {
	got := BuildURL("http", "localhost", 8080, "/api/test", nil)
	want := "http://localhost:8080/api/test"
	if got != want {
		t.Errorf("BuildURL() = %v, want %v", got, want)
	}
}

func TestBuildURLHTTPSDefaultPort(t *testing.T) {
	got := BuildURL("https", "example.com", 443, "/path", nil)
	want := "https://example.com/path"
	if got != want {
		t.Errorf("BuildURL() = %v, want %v", got, want)
	}
}

func TestBuildURLNoScheme(t *testing.T) {
	got := BuildURL("", "localhost", 8080, "/test", nil)
	want := "http://localhost:8080/test"
	if got != want {
		t.Errorf("BuildURL() = %v, want %v", got, want)
	}
}

func TestExtractMarkers(t *testing.T) {
	body := []byte(`{"message": "error", "debug": "__V01_LOGIN_BYPASS__ some text __L01_STACKTRACE__"}`)
	markers := ExtractMarkers(body)

	if len(markers) != 2 {
		t.Errorf("Expected 2 markers, got %d", len(markers))
	}

	foundV01 := false
	foundL01 := false
	for _, m := range markers {
		if m == "__V01_LOGIN_BYPASS__" {
			foundV01 = true
		}
		if m == "__L01_STACKTRACE__" {
			foundL01 = true
		}
	}

	if !foundV01 {
		t.Error("Expected to find __V01_LOGIN_BYPASS__ marker")
	}
	if !foundL01 {
		t.Error("Expected to find __L01_STACKTRACE__ marker")
	}
}

func TestHasMarker(t *testing.T) {
	body := []byte(`{"error": "__V01_LOGIN_BYPASS__"}`)
	if !HasMarker(body, "__V01_LOGIN_BYPASS__") {
		t.Error("Expected HasMarker to return true")
	}
	if HasMarker(body, "__NONEXISTENT__") {
		t.Error("Expected HasMarker to return false for non-existent marker")
	}
}

func TestSetSourceIPHeader(t *testing.T) {
	req := fasthttp.AcquireRequest()
	defer ReleaseRequest(req)

	SetSourceIPHeader(req, "192.168.1.100", []string{"10.0.0.1", "10.0.0.2"})

	xff := string(req.Header.Peek("X-Forwarded-For"))
	expected := "10.0.0.1, 10.0.0.2, 192.168.1.100"
	if xff != expected {
		t.Errorf("Expected X-Forwarded-For: %s, got %s", expected, xff)
	}

	xri := string(req.Header.Peek("X-Real-IP"))
	if xri != "192.168.1.100" {
		t.Errorf("Expected X-Real-IP: 192.168.1.100, got %s", xri)
	}
}

func TestSetSourceIPHeaderNoChain(t *testing.T) {
	req := fasthttp.AcquireRequest()
	defer ReleaseRequest(req)

	SetSourceIPHeader(req, "192.168.1.100", nil)

	xff := string(req.Header.Peek("X-Forwarded-For"))
	if xff != "192.168.1.100" {
		t.Errorf("Expected X-Forwarded-For: 192.168.1.100, got %s", xff)
	}
}

func TestResponseHasHeader(t *testing.T) {
	resp := &Response{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: []byte("{}"),
	}

	if !resp.HasHeader("Content-Type") {
		t.Error("Expected HasHeader(Content-Type) to be true")
	}
	if resp.HasHeader("X-Nonexistent") {
		t.Error("Expected HasHeader(X-Nonexistent) to be false")
	}
}

func TestResponseGetHeaderCaseInsensitive(t *testing.T) {
	resp := &Response{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: []byte("{}"),
	}

	value, exists := resp.GetHeader("content-type")
	if !exists || value != "application/json" {
		t.Error("Expected case-insensitive header lookup to work")
	}
}
