package target

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	client := NewClient("127.0.0.1", 9000, "test-secret")
	if client == nil {
		t.Fatal("Expected client to be non-nil")
	}
	if client.BaseURL != "http://127.0.0.1:9000" {
		t.Errorf("Expected BaseURL http://127.0.0.1:9000, got %s", client.BaseURL)
	}
	if client.Secret != "test-secret" {
		t.Errorf("Expected secret 'test-secret', got %s", client.Secret)
	}
}

func TestClientHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__control/health" {
			t.Errorf("Expected path /__control/health, got %s", r.URL.Path)
		}
		if r.Header.Get("X-Benchmark-Secret") != "test-secret" {
			t.Error("Expected X-Benchmark-Secret header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "test-secret", server.Client())
	// Override baseURL to use test server
	client.BaseURL = server.URL

	err := client.Health()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestClientHealthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "test-secret", server.Client())
	client.BaseURL = server.URL

	err := client.Health()
	if err == nil {
		t.Error("Expected error for non-200 status")
	}
}

func TestClientGetState(t *testing.T) {
	expectedState := AppState{
		Healthy:    true,
		SlowDelay:  0,
		ErrorMode:  "none",
		ResetCount: 5,
		Metadata:   map[string]string{"version": "1.0"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__control/state" {
			t.Errorf("Expected path /__control/state, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedState)
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "test-secret", server.Client())
	client.BaseURL = server.URL

	state, err := client.GetState()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !state.Healthy {
		t.Error("Expected state to be healthy")
	}
	if state.ResetCount != 5 {
		t.Errorf("Expected reset count 5, got %d", state.ResetCount)
	}
}

func TestClientReadCapabilities(t *testing.T) {
	expectedCaps := AppCapabilities{
		VulnsActive:  []string{"V01", "V02", "V03"},
		VulnsSkipped: []string{"V04"},
		LeaksActive:  []string{"L01", "L02"},
		LeaksSkipped: []string{},
		Version:      "1.0",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__control/capabilities" {
			t.Errorf("Expected path /__control/capabilities, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedCaps)
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "test-secret", server.Client())
	client.BaseURL = server.URL

	caps, err := client.ReadCapabilities()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(caps.VulnsActive) != 3 {
		t.Errorf("Expected 3 active vulns, got %d", len(caps.VulnsActive))
	}
	if !caps.IsVulnActive("V01") {
		t.Error("Expected V01 to be active")
	}
	if caps.IsVulnActive("V04") {
		t.Error("Expected V04 to be inactive")
	}
}

func TestClientGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}
		if r.URL.Path != "/api/test" {
			t.Errorf("Expected path /api/test, got %s", r.URL.Path)
		}
		if r.Header.Get("X-Custom") != "value" {
			t.Error("Expected X-Custom header")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "test-secret", server.Client())
	client.BaseURL = server.URL

	resp, err := client.Get("/api/test", map[string]string{"X-Custom": "value"})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"status":"ok"}` {
		t.Errorf("Expected body, got %s", string(body))
	}
}

func TestClientPost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"test":"data"}` {
			t.Errorf("Expected body, got %s", string(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "test-secret", server.Client())
	client.BaseURL = server.URL

	resp, err := client.Post("/api/test", "application/json", []byte(`{"test":"data"}`), nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestClientBaseURL(t *testing.T) {
	client := NewClient("192.168.1.1", 8080, "secret")
	if client.GetBaseURL() != "http://192.168.1.1:8080" {
		t.Errorf("Expected GetBaseURL http://192.168.1.1:8080, got %s", client.GetBaseURL())
	}
}
