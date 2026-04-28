package target

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Auth provides authentication helpers for the target application
type Auth struct {
	client *Client
}

// NewAuth creates a new authentication helper
func NewAuth(client *Client) *Auth {
	return &Auth{client: client}
}

// Credentials represents user login credentials
type Credentials struct {
	Username string
	Password string
	OTP      string
}

// Predefined credentials for testing
var (
	// UserAlice - regular user
	UserAlice = Credentials{
		Username: "alice",
		Password: "P@ssw0rd1",
		OTP:      "123456",
	}
	// UserBob - regular user
	UserBob = Credentials{
		Username: "bob",
		Password: "S3cureP@ss",
		OTP:      "654321",
	}
	// UserCharlie - user for transaction tests
	UserCharlie = Credentials{
		Username: "charlie",
		Password: "Ch@rlie123",
		OTP:      "111111",
	}
	// UserDave - user for testing
	UserDave = Credentials{
		Username: "dave",
		Password: "D@v3Pass99",
		OTP:      "222222",
	}
)

// LoginResult contains the result of a login attempt
type LoginResult struct {
	LoginToken  string `json:"login_token"`
	RequiresOTP bool   `json:"requires_otp"`
}

// Session represents an authenticated session
type Session struct {
	SessionID  string         `json:"session_id"`
	LoginToken string         `json:"login_token,omitempty"`
	ExpiresAt  time.Time      `json:"expires_at"`
	Cookies    []*http.Cookie
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Login performs a login and returns the login token
func (a *Auth) Login(username, password string) (*LoginResult, error) {
	url := fmt.Sprintf("%s/login", a.client.BaseURL)
	payload := map[string]string{
		"username": username,
		"password": password,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal login request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusUnauthorized {
		return nil, fmt.Errorf("login returned unexpected status %d", resp.StatusCode)
	}

	var result LoginResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode login response: %w", err)
	}

	return &result, nil
}

// ExchangeOTP exchanges the login token and OTP code for a session
func (a *Auth) ExchangeOTP(loginToken, otpCode string) (*Session, error) {
	url := fmt.Sprintf("%s/otp", a.client.BaseURL)
	payload := map[string]string{
		"login_token": loginToken,
		"otp_code":    otpCode,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OTP request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create OTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OTP exchange returned status %d", resp.StatusCode)
	}

	var data struct {
		SessionID string `json:"session_id"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode OTP response: %w", err)
	}

	session := &Session{
		SessionID:  data.SessionID,
		LoginToken: loginToken,
		ExpiresAt:  time.Now().Add(time.Duration(data.ExpiresIn) * time.Second),
		Cookies:    resp.Cookies(),
	}

	return session, nil
}

// GetAuthenticatedClient returns an HTTP client with session cookies
func (a *Auth) GetAuthenticatedClient(session *Session) *http.Client {
	// Create a new client that includes the session cookies
	jar, _ := cookieJarFromCookies(session.Cookies)

	return &http.Client{
		Timeout:   a.client.HTTPClient.Timeout,
		Jar:       jar,
		Transport: a.client.HTTPClient.Transport,
	}
}

// LoginWithCredentials performs full login flow with predefined credentials
func (a *Auth) LoginWithCredentials(creds Credentials) (*Session, error) {
	result, err := a.Login(creds.Username, creds.Password)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	if !result.RequiresOTP {
		return nil, fmt.Errorf("expected OTP requirement")
	}

	session, err := a.ExchangeOTP(result.LoginToken, creds.OTP)
	if err != nil {
		return nil, fmt.Errorf("OTP exchange failed: %w", err)
	}

	return session, nil
}

// GoldenPath performs the complete golden path authentication
// This mimics a normal user: GET / → /game/list → POST /login → /otp → /api/profile
func (a *Auth) GoldenPath(creds Credentials) (*Session, error) {
	// Step 1: Visit home page
	_, err := a.client.Get("/", nil)
	if err != nil {
		return nil, fmt.Errorf("golden path: home page failed: %w", err)
	}

	// Step 2: Visit game list
	_, err = a.client.Get("/game/list", nil)
	if err != nil {
		return nil, fmt.Errorf("golden path: game list failed: %w", err)
	}

	// Step 3-4: Login and OTP
	session, err := a.LoginWithCredentials(creds)
	if err != nil {
		return nil, fmt.Errorf("golden path: auth failed: %w", err)
	}

	// Step 5: Access profile with authenticated client
	authClient := a.GetAuthenticatedClient(session)
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/profile", a.client.BaseURL), nil)
	resp, err := authClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("golden path: profile access failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("golden path: profile returned status %d", resp.StatusCode)
	}

	return session, nil
}

// GetTestCredentials returns all predefined test credentials
func GetTestCredentials() []Credentials {
	return []Credentials{UserAlice, UserBob, UserCharlie, UserDave}
}
type cookieJar struct {
	cookies []*http.Cookie
}

func (j *cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.cookies = append(j.cookies, cookies...)
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
	return j.cookies
}

func cookieJarFromCookies(cookies []*http.Cookie) (*cookieJar, error) {
	return &cookieJar{cookies: cookies}, nil
}
