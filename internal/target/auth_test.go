package target

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthNewAuth(t *testing.T) {
	client := NewClient("127.0.0.1", 9000, "secret")
	auth := NewAuth(client)
	if auth == nil {
		t.Fatal("Expected auth to be non-nil")
	}
	if auth.client != client {
		t.Error("Expected auth.client to match the provided client")
	}
}

func TestAuthLogin(t *testing.T) {
	expectedResult := LoginResult{
		LoginToken:  "test-token-123",
		RequiresOTP: true,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login" {
			t.Errorf("Expected path /login, got %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		var creds map[string]string
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &creds)

		if creds["username"] != "alice" || creds["password"] != "P@ssw0rd1" {
			t.Errorf("Unexpected credentials: %v", creds)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(expectedResult)
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "secret", server.Client())
	client.BaseURL = server.URL

	auth := NewAuth(client)
	result, err := auth.Login("alice", "P@ssw0rd1")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.LoginToken != "test-token-123" {
		t.Errorf("Expected token 'test-token-123', got %s", result.LoginToken)
	}
	if !result.RequiresOTP {
		t.Error("Expected RequiresOTP to be true")
	}
}

func TestAuthExchangeOTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/otp" {
			t.Errorf("Expected path /otp, got %s", r.URL.Path)
		}

		var payload map[string]string
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &payload)

		if payload["login_token"] != "test-token" || payload["otp_code"] != "123456" {
			t.Errorf("Unexpected payload: %v", payload)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"session_id": "session-abc-123",
			"expires_in": 3600,
		})
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "secret", server.Client())
	client.BaseURL = server.URL

	auth := NewAuth(client)
	session, err := auth.ExchangeOTP("test-token", "123456")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if session.SessionID != "session-abc-123" {
		t.Errorf("Expected session_id 'session-abc-123', got %s", session.SessionID)
	}
	if session.LoginToken != "test-token" {
		t.Errorf("Expected login_token 'test-token', got %s", session.LoginToken)
	}
	if session.IsExpired() {
		t.Error("Expected session to not be expired")
	}
}

func TestSessionIsExpired(t *testing.T) {
	session := &Session{
		SessionID:  "test",
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	}

	if !session.IsExpired() {
		t.Error("Expected expired session")
	}

	session.ExpiresAt = time.Now().Add(1 * time.Hour)
	if session.IsExpired() {
		t.Error("Expected non-expired session")
	}
}

func TestAuthLoginWithCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			json.NewEncoder(w).Encode(LoginResult{
				LoginToken:  "token-123",
				RequiresOTP: true,
			})
		case "/otp":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"session_id": "session-xyz",
				"expires_in": 3600,
			})
		default:
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "secret", server.Client())
	client.BaseURL = server.URL

	auth := NewAuth(client)
	session, err := auth.LoginWithCredentials(UserAlice)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if session.SessionID != "session-xyz" {
		t.Errorf("Expected session_id 'session-xyz', got %s", session.SessionID)
	}
}

func TestAuthGoldenPath(t *testing.T) {
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)

		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
		case "/game/list":
			w.WriteHeader(http.StatusOK)
		case "/login":
			json.NewEncoder(w).Encode(LoginResult{
				LoginToken:  "token-123",
				RequiresOTP: true,
			})
		case "/otp":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"session_id": "session-abc",
				"expires_in": 3600,
			})
		case "/api/profile":
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			t.Errorf("Unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClientWithHTTP("127.0.0.1", 9000, "secret", server.Client())
	client.BaseURL = server.URL

	auth := NewAuth(client)
	session, err := auth.GoldenPath(UserAlice)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if session.SessionID != "session-abc" {
		t.Errorf("Expected session_id 'session-abc', got %s", session.SessionID)
	}

	// Verify all paths were visited
	expectedPaths := []string{"/", "/game/list", "/login", "/otp", "/api/profile"}
	for _, path := range expectedPaths {
		found := false
		for _, p := range paths {
			if p == path {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected path %s to be visited", path)
		}
	}
}

func TestPredefinedCredentials(t *testing.T) {
	// Verify all predefined credentials are valid
	creds := []Credentials{UserAlice, UserBob, UserCharlie, UserDave}

	for _, c := range creds {
		if c.Username == "" {
			t.Error("Username should not be empty")
		}
		if c.Password == "" {
			t.Error("Password should not be empty")
		}
		if c.OTP == "" {
			t.Error("OTP should not be empty")
		}
		if len(c.OTP) != 6 {
			t.Errorf("OTP should be 6 digits, got %d", len(c.OTP))
		}
	}
}
