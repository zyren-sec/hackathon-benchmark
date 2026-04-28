package waf

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/valyala/fasthttp"
	"github.com/waf-hackathon/benchmark/internal/httpclient"
)

// WAFClient provides an interface to interact with the WAF
// It wraps BoundClient for high-performance HTTP operations with source IP binding
type WAFClient struct {
	scheme     string
	host       string
	port       int
	clientPool map[string]*httpclient.BoundClient // source IP -> client
	timeout    time.Duration
}

// WAFResponse represents a response from the WAF with additional metadata
type WAFResponse struct {
	StatusCode  int
	Body        []byte
	Headers     map[string]string
	Decision    Decision
	Markers     []string
	RiskScore   int
	Action      string
	RequestID   string
	RuleID      string
	CacheStatus string
	LatencyMs   int64
	SourceIP    string
}

// NewWAFClient creates a new WAF client
func NewWAFClient(host string, port int, timeout time.Duration) *WAFClient {
	return NewWAFClientWithScheme("http", host, port, timeout)
}

// NewWAFClientWithScheme creates a new WAF client with explicit scheme.
func NewWAFClientWithScheme(scheme, host string, port int, timeout time.Duration) *WAFClient {
	if scheme == "" {
		scheme = "http"
	}
	return &WAFClient{
		scheme:     scheme,
		host:       host,
		port:       port,
		clientPool: make(map[string]*httpclient.BoundClient),
		timeout:    timeout,
	}
}

// GetBaseURL returns the WAF base URL
func (c *WAFClient) GetBaseURL() string {
	return fmt.Sprintf("%s://%s:%d", c.scheme, c.host, c.port)
}

// Health checks if the WAF is healthy.
// WAF is considered healthy if it responds with any HTTP status.
func (c *WAFClient) Health() error {
	_, err := c.SendSimpleRequest("GET", "/", "127.0.0.1", nil, nil)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	return nil
}

// SendRequest sends an HTTP request through the WAF from a specific source IP.
// If the bound source IP cannot be used at runtime, it retries once via a
// generic local bind (0.0.0.0) to keep live remote benchmark execution working.
func (c *WAFClient) SendRequest(req *fasthttp.Request, sourceIP string) (*WAFResponse, error) {
	start := time.Now()

	// Get or create bound client for the source IP
	client, err := c.getOrCreateClient(sourceIP)
	if err != nil {
		return nil, fmt.Errorf("failed to get client for %s: %w", sourceIP, err)
	}

	// Set the request URI to go through WAF but reach the target
	// The WAF will proxy to the target app
	originalURI := string(req.RequestURI())
	wafURL := fmt.Sprintf("%s%s", c.GetBaseURL(), originalURI)
	req.SetRequestURI(wafURL)

	// Send the request
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	if err := client.Do(req, resp); err != nil {
		fallback, fbErr := c.getOrCreateClient("0.0.0.0")
		if fbErr != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}
		if retryErr := fallback.Do(req, resp); retryErr != nil {
			return nil, fmt.Errorf("request failed (initial=%v, retry=%v)", err, retryErr)
		}
	}

	latency := time.Since(start).Milliseconds()

	// Parse the response
	return c.parseResponse(resp, sourceIP, latency)
}

// SendSimpleRequest is a convenience method for simple requests
func (c *WAFClient) SendSimpleRequest(method, path, sourceIP string, headers map[string]string, body []byte) (*WAFResponse, error) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethod(method)
	req.SetRequestURI(path)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if len(body) > 0 {
		req.SetBody(body)
	}

	return c.SendRequest(req, sourceIP)
}

// SendRequestWithIP sends a request with JSON payload and custom headers from a specific source IP
func (c *WAFClient) SendRequestWithIP(method, path string, payload map[string]interface{}, headers map[string]string, sourceIP string) (*WAFResponse, error) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethod(method)
	req.SetRequestURI(path)

	// Set default content type for requests with payload
	if payload != nil {
		req.Header.SetContentType("application/json")

		// Marshal payload to JSON
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %w", err)
		}
		req.SetBody(body)
	}

	// Set custom headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return c.SendRequest(req, sourceIP)
}

// getOrCreateClient gets an existing client or creates a new one for the source IP.
// If strict source binding cannot be established on this host/network, it falls back
// to an unspecified local bind (0.0.0.0) so live remote benchmarks can still run.
func (c *WAFClient) getOrCreateClient(sourceIP string) (*httpclient.BoundClient, error) {
	if client, exists := c.clientPool[sourceIP]; exists {
		return client, nil
	}

	opts := httpclient.ClientOptions{
		Timeout:       c.timeout,
		UserAgent:     "WAF-Benchmark/2.1",
		SkipTLSVerify: true,
		MaxConns:      100,
	}

	client, err := httpclient.NewBoundClient(sourceIP, opts)
	if err != nil {
		fallbackKey := sourceIP + "#fallback"
		if fallback, ok := c.clientPool[fallbackKey]; ok {
			return fallback, nil
		}

		fallback, fallbackErr := httpclient.NewBoundClient("0.0.0.0", opts)
		if fallbackErr != nil {
			return nil, err
		}
		c.clientPool[fallbackKey] = fallback
		return fallback, nil
	}

	c.clientPool[sourceIP] = client
	return client, nil
}

// parseResponse converts fasthttp.Response to WAFResponse with all metadata
func (c *WAFClient) parseResponse(resp *fasthttp.Response, sourceIP string, latency int64) (*WAFResponse, error) {
	statusCode := resp.StatusCode()
	body := make([]byte, len(resp.Body()))
	copy(body, resp.Body())

	// Extract headers
	headers := make(map[string]string)
	resp.Header.VisitAll(func(key, value []byte) {
		headers[string(key)] = string(value)
	})

	// Detect markers in body
	markers := httpclient.ExtractMarkers(body)

	// Classify the decision
	decision := Classify(statusCode, body, headers)

	// Extract observability headers
	riskScore, _ := ExtractRiskScore(headers)
	action, _ := ExtractAction(headers)
	requestID, _ := ExtractRequestID(headers)
	ruleID, _ := ExtractRuleID(headers)
	cacheStatus, _ := ExtractCacheStatus(headers)

	return &WAFResponse{
		StatusCode:  statusCode,
		Body:        body,
		Headers:     headers,
		Decision:    decision,
		Markers:     markers,
		RiskScore:   riskScore,
		Action:      action,
		RequestID:   requestID,
		RuleID:      ruleID,
		CacheStatus: cacheStatus,
		LatencyMs:   latency,
		SourceIP:    sourceIP,
	}, nil
}

// Close releases all clients in the pool
func (c *WAFClient) Close() error {
	for _, client := range c.clientPool {
		client.Close()
	}
	c.clientPool = make(map[string]*httpclient.BoundClient)
	return nil
}

// GetClientStats returns statistics for all clients in the pool
func (c *WAFClient) GetClientStats() map[string]interface{} {
	stats := make(map[string]interface{})
	for ip, client := range c.clientPool {
		stats[ip] = client.Stats()
	}
	return stats
}

// String returns a human-readable summary of the response
func (r *WAFResponse) String() string {
	return fmt.Sprintf("WAFResponse{Status: %d, Decision: %s, RiskScore: %d, Markers: %v, Latency: %dms}",
		r.StatusCode, r.Decision.String(), r.RiskScore, r.Markers, r.LatencyMs)
}

// HasMarker checks if a specific marker was found in the response
func (r *WAFResponse) HasMarker(marker string) bool {
	for _, m := range r.Markers {
		if m == marker {
			return true
		}
	}
	return false
}

// IsBlocked returns true if the request was blocked by the WAF
func (r *WAFResponse) IsBlocked() bool {
	return r.Decision == Block
}

// IsChallenged returns true if the request was challenged
func (r *WAFResponse) IsChallenged() bool {
	return r.Decision == Challenge
}

// IsAllowed returns true if the request was allowed through
func (r *WAFResponse) IsAllowed() bool {
	return r.Decision == Allow || r.Decision == PreventedSanitized
}

// ExploitSucceeded returns true if the response contains proof markers (exploit got through)
func (r *WAFResponse) ExploitSucceeded() bool {
	return len(r.Markers) > 0 && r.StatusCode == 200
}
