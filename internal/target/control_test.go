package target

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControlReset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__control/reset" {
			t.Errorf("Expected path /__control/reset, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.Header.Get("X-Benchmark-Secret") != "test-secret" {
			t.Error("Expected X-Benchmark-Secret header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "test-secret", server.Client())
	client.BaseURL = server.URL

	control := NewControl(client)
	err := control.Reset()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestControlResetFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "test-secret", server.Client())
	client.BaseURL = server.URL

	control := NewControl(client)
	err := control.Reset()
	if err == nil {
		t.Error("Expected error for non-200 status")
	}
}

func TestControlSetSlow(t *testing.T) {
	var receivedDelay int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__control/slow" {
			t.Errorf("Expected path /__control/slow, got %s", r.URL.Path)
		}
		if r.Header.Get("X-Benchmark-Secret") != "test-secret" {
			t.Error("Expected X-Benchmark-Secret header")
		}

		var payload map[string]int
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &payload)
		receivedDelay = payload["delay_ms"]

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "test-secret", server.Client())
	client.BaseURL = server.URL

	control := NewControl(client)
	err := control.SetSlow(5000)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if receivedDelay != 5000 {
		t.Errorf("Expected delay_ms 5000, got %d", receivedDelay)
	}
}

func TestControlSetErrorMode(t *testing.T) {
	var receivedMode string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__control/error_mode" {
			t.Errorf("Expected path /__control/error_mode, got %s", r.URL.Path)
		}

		var payload map[string]string
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &payload)
		receivedMode = payload["mode"]

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "test-secret", server.Client())
	client.BaseURL = server.URL

	control := NewControl(client)
	err := control.SetErrorMode("500_error")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if receivedMode != "500_error" {
		t.Errorf("Expected mode '500_error', got %s", receivedMode)
	}
}

func TestControlSetHealthMode(t *testing.T) {
	var receivedDown bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__control/health_mode" {
			t.Errorf("Expected path /__control/health_mode, got %s", r.URL.Path)
		}

		var payload map[string]bool
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &payload)
		receivedDown = payload["down"]

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "test-secret", server.Client())
	client.BaseURL = server.URL

	control := NewControl(client)

	// Test setting down=true
	err := control.SetHealthMode(true)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !receivedDown {
		t.Error("Expected down=true")
	}

	// Test setting down=false
	err = control.SetHealthMode(false)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if receivedDown {
		t.Error("Expected down=false")
	}
}
