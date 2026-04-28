package httpclient

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/valyala/fasthttp"
)

// BoundClient is an HTTP client that binds to a specific source IP address.
//
// It provides safe browser-like behavior for benchmark realism:
// - Connection reuse / keep-alive
// - Cookie jar handling
// - Optional HTTP/2 attempts (for TLS endpoints)
// - Browser-style default headers (without exact spoofing guarantees)
type BoundClient struct {
	sourceIP  string
	client    *http.Client
	transport *http.Transport
	timeout   time.Duration
	userAgent string
	opts      ClientOptions
}

// ClientOptions contains configuration options for BoundClient.
type ClientOptions struct {
	Timeout                  time.Duration
	UserAgent                string
	SkipTLSVerify            bool
	MaxConns                 int
	EnableHTTP2              bool
	EnableBrowserLikeHeaders bool
	AcceptLanguage           string
	AcceptEncoding           string
}

// DefaultClientOptions returns default client options.
func DefaultClientOptions() ClientOptions {
	return ClientOptions{
		Timeout:                  30 * time.Second,
		UserAgent:                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		SkipTLSVerify:            true,
		MaxConns:                 100,
		EnableHTTP2:              true,
		EnableBrowserLikeHeaders: true,
		AcceptLanguage:           "en-US,en;q=0.9",
		AcceptEncoding:           "gzip, deflate, br, zstd",
	}
}

// NewBoundClient creates a new HTTP client bound to a specific source IP.
func NewBoundClient(sourceIP string, opts ClientOptions) (*BoundClient, error) {
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid source IP: %s", sourceIP)
	}

	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = 100
	}
	if strings.TrimSpace(opts.UserAgent) == "" {
		opts.UserAgent = DefaultClientOptions().UserAgent
	}
	if strings.TrimSpace(opts.AcceptLanguage) == "" {
		opts.AcceptLanguage = DefaultClientOptions().AcceptLanguage
	}
	if strings.TrimSpace(opts.AcceptEncoding) == "" {
		opts.AcceptEncoding = DefaultClientOptions().AcceptEncoding
	}

	dialer := &net.Dialer{
		Timeout:   opts.Timeout,
		KeepAlive: 30 * time.Second,
		LocalAddr: &net.TCPAddr{IP: ip, Port: 0},
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     opts.EnableHTTP2,
		MaxIdleConns:          opts.MaxConns * 2,
		MaxIdleConnsPerHost:   opts.MaxConns,
		MaxConnsPerHost:       opts.MaxConns,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true, // keep raw encoded body so we can support br/zstd decode ourselves
	}

	if opts.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		Jar:       jar,
	}

	return &BoundClient{
		sourceIP:  sourceIP,
		client:    httpClient,
		transport: transport,
		timeout:   opts.Timeout,
		userAgent: opts.UserAgent,
		opts:      opts,
	}, nil
}

// Do sends an HTTP request and fills the provided response.
func (c *BoundClient) Do(req *fasthttp.Request, resp *fasthttp.Response) error {
	return c.doWithContext(req, resp, context.Background())
}

// DoTimeout sends a request with a custom timeout.
func (c *BoundClient) DoTimeout(req *fasthttp.Request, resp *fasthttp.Response, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return c.doWithContext(req, resp, ctx)
}

// DoDeadline sends a request with a deadline.
func (c *BoundClient) DoDeadline(req *fasthttp.Request, resp *fasthttp.Response, deadline time.Time) error {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	return c.doWithContext(req, resp, ctx)
}

func (c *BoundClient) doWithContext(req *fasthttp.Request, resp *fasthttp.Response, ctx context.Context) error {
	if req == nil || resp == nil {
		return fmt.Errorf("request/response must not be nil")
	}

	if len(req.Header.UserAgent()) == 0 {
		req.Header.SetUserAgent(c.userAgent)
	}
	if c.opts.EnableBrowserLikeHeaders {
		ApplySafeChromeHeaders(req, BrowserHeaderProfile{
			UserAgent:      c.userAgent,
			AcceptLanguage: c.opts.AcceptLanguage,
			AcceptEncoding: c.opts.AcceptEncoding,
		})
	}

	httpReq, err := fasthttpToHTTPRequest(req, ctx)
	if err != nil {
		return err
	}

	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	return httpResponseToFastHTTP(httpResp, resp)
}

func fasthttpToHTTPRequest(req *fasthttp.Request, ctx context.Context) (*http.Request, error) {
	method := string(req.Header.Method())
	if method == "" {
		method = http.MethodGet
	}

	reqURL := string(req.URI().FullURI())
	httpReq, err := http.NewRequestWithContext(ctx, method, reqURL, bytes.NewReader(req.Body()))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.VisitAll(func(key, value []byte) {
		httpReq.Header.Add(string(key), string(value))
	})

	if host := string(req.Header.Host()); host != "" {
		httpReq.Host = host
	}

	return httpReq, nil
}

func httpResponseToFastHTTP(httpResp *http.Response, resp *fasthttp.Response) error {
	resp.Reset()
	resp.SetStatusCode(httpResp.StatusCode)

	for key, values := range httpResp.Header {
		for _, value := range values {
			resp.Header.Add(key, value)
		}
	}

	rawBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	decodedBody, decoded := decodeContentEncoding(rawBody, httpResp.Header.Get("Content-Encoding"))
	resp.SetBody(decodedBody)
	if decoded {
		resp.Header.Del("Content-Encoding")
		resp.Header.SetContentLength(len(decodedBody))
	}

	return nil
}

func decodeContentEncoding(body []byte, encoding string) ([]byte, bool) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if enc == "" || len(body) == 0 {
		return body, false
	}

	switch enc {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, false
		}
		defer r.Close()
		decoded, err := io.ReadAll(r)
		if err != nil {
			return body, false
		}
		return decoded, true
	case "deflate":
		r := flate.NewReader(bytes.NewReader(body))
		defer r.Close()
		decoded, err := io.ReadAll(r)
		if err != nil {
			return body, false
		}
		return decoded, true
	case "br":
		r := brotli.NewReader(bytes.NewReader(body))
		decoded, err := io.ReadAll(r)
		if err != nil {
			return body, false
		}
		return decoded, true
	case "zstd":
		zr, err := zstd.NewReader(nil)
		if err != nil {
			return body, false
		}
		defer zr.Close()
		decoded, err := zr.DecodeAll(body, nil)
		if err != nil {
			return body, false
		}
		return decoded, true
	default:
		// Unknown encoding: keep raw body.
		return body, false
	}
}

// Get is a convenience method for GET requests.
func (c *BoundClient) Get(url string) (*fasthttp.Response, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI(url)

	if err := c.Do(req, resp); err != nil {
		fasthttp.ReleaseResponse(resp)
		return nil, err
	}

	return resp, nil
}

// Post is a convenience method for POST requests.
func (c *BoundClient) Post(url string, contentType string, body []byte) (*fasthttp.Response, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	defer fasthttp.ReleaseRequest(req)

	req.Header.SetMethod(fasthttp.MethodPost)
	req.SetRequestURI(url)
	req.Header.SetContentType(contentType)
	req.SetBody(body)

	if err := c.Do(req, resp); err != nil {
		fasthttp.ReleaseResponse(resp)
		return nil, err
	}

	return resp, nil
}

// SourceIP returns the source IP this client is bound to.
func (c *BoundClient) SourceIP() string {
	return c.sourceIP
}

// Close releases resources held by the client.
func (c *BoundClient) Close() error {
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	c.client = nil
	c.transport = nil
	return nil
}

// Stats returns connection statistics.
func (c *BoundClient) Stats() map[string]interface{} {
	return map[string]interface{}{
		"source_ip":        c.sourceIP,
		"timeout_ms":       c.timeout.Milliseconds(),
		"user_agent":       c.userAgent,
		"http2_enabled":    c.opts.EnableHTTP2,
		"browser_profile":  c.opts.EnableBrowserLikeHeaders,
		"accept_language":  c.opts.AcceptLanguage,
		"accept_encoding":  c.opts.AcceptEncoding,
	}
}
