package target

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client provides an interface to interact with the target vulnerable application
type Client struct {
	HTTPClient *http.Client
	BaseURL    string
	Secret     string
}

// NewClient creates a new target app client
func NewClient(host string, port int, secret string) *Client {
	return NewClientWithScheme(host, port, "http", secret)
}

// NewClientWithScheme creates a new target app client with explicit scheme.
func NewClientWithScheme(host string, port int, scheme string, secret string) *Client {
	if scheme == "" {
		scheme = "http"
	}
	return &Client{
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		BaseURL: fmt.Sprintf("%s://%s:%d", scheme, host, port),
		Secret:  secret,
	}
}

// NewClientWithHTTP creates a client with a custom HTTP client
func NewClientWithHTTP(host string, port int, secret string, httpClient *http.Client) *Client {
	return NewClientWithHTTPAndScheme(host, port, "http", secret, httpClient)
}

// NewClientWithHTTPAndScheme creates a client with custom HTTP client and explicit scheme.
func NewClientWithHTTPAndScheme(host string, port int, scheme string, secret string, httpClient *http.Client) *Client {
	if scheme == "" {
		scheme = "http"
	}
	return &Client{
		HTTPClient: httpClient,
		BaseURL:    fmt.Sprintf("%s://%s:%d", scheme, host, port),
		Secret:     secret,
	}
}

// Health checks if the target application is healthy
func (c *Client) Health() error {
	url := fmt.Sprintf("%s/__control/health", c.BaseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create health request: %w", err)
	}

	req.Header.Set("X-Benchmark-Secret", c.Secret)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	return nil
}

// GetState retrieves the current state of the target application
func (c *Client) GetState() (*AppState, error) {
	url := fmt.Sprintf("%s/__control/state", c.BaseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create state request: %w", err)
	}

	req.Header.Set("X-Benchmark-Secret", c.Secret)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get state: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("state request returned status %d", resp.StatusCode)
	}

	var state AppState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		return nil, fmt.Errorf("failed to decode state: %w", err)
	}

	return &state, nil
}

// ReadCapabilities reads the application capabilities from the target
func (c *Client) ReadCapabilities() (*AppCapabilities, error) {
	url := fmt.Sprintf("%s/__control/capabilities", c.BaseURL)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create capabilities request: %w", err)
	}

	req.Header.Set("X-Benchmark-Secret", c.Secret)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to read capabilities: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("capabilities request returned status %d", resp.StatusCode)
	}

	var caps AppCapabilities
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return nil, fmt.Errorf("failed to decode capabilities: %w", err)
	}

	return &caps, nil
}

// Get performs a GET request to the target
func (c *Client) Get(path string, headers map[string]string) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", c.BaseURL, path)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.HTTPClient.Do(req)
}

// Post performs a POST request to the target
func (c *Client) Post(path string, contentType string, body []byte, headers map[string]string) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", c.BaseURL, path)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.HTTPClient.Do(req)
}

// GetBaseURL returns the base URL of the target
func (c *Client) GetBaseURL() string {
	return c.BaseURL
}
