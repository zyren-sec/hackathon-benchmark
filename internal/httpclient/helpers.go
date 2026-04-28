package httpclient

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/valyala/fasthttp"
)

// RequestBuilder helps build HTTP requests
type RequestBuilder struct {
	method      string
	url         string
	contentType string
	headers     map[string]string
	body        []byte
	formData    url.Values
}

// NewRequest creates a new request builder
func NewRequest(method, url string) *RequestBuilder {
	return &RequestBuilder{
		method:  strings.ToUpper(method),
		url:     url,
		headers: make(map[string]string),
	}
}

// WithHeader adds a header to the request
func (rb *RequestBuilder) WithHeader(key, value string) *RequestBuilder {
	rb.headers[key] = value
	return rb
}

// WithHeaders adds multiple headers
func (rb *RequestBuilder) WithHeaders(headers map[string]string) *RequestBuilder {
	for k, v := range headers {
		rb.headers[k] = v
	}
	return rb
}

// WithContentType sets the Content-Type header
func (rb *RequestBuilder) WithContentType(ct string) *RequestBuilder {
	rb.contentType = ct
	return rb
}

// WithJSONBody sets a JSON body
func (rb *RequestBuilder) WithJSONBody(data interface{}) (*RequestBuilder, error) {
	body, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}
	rb.body = body
	rb.contentType = "application/json"
	return rb, nil
}

// WithBody sets the raw body
func (rb *RequestBuilder) WithBody(body []byte) *RequestBuilder {
	rb.body = body
	return rb
}

// WithStringBody sets a string body
func (rb *RequestBuilder) WithStringBody(body string) *RequestBuilder {
	rb.body = []byte(body)
	return rb
}

// WithFormData sets form data
func (rb *RequestBuilder) WithFormData(data url.Values) *RequestBuilder {
	rb.formData = data
	rb.body = []byte(data.Encode())
	rb.contentType = "application/x-www-form-urlencoded"
	return rb
}

// Build creates the fasthttp.Request
func (rb *RequestBuilder) Build() *fasthttp.Request {
	req := fasthttp.AcquireRequest()

	req.Header.SetMethod(rb.method)
	req.SetRequestURI(rb.url)

	if rb.contentType != "" {
		req.Header.SetContentType(rb.contentType)
	}

	for k, v := range rb.headers {
		req.Header.Set(k, v)
	}

	if len(rb.body) > 0 {
		req.SetBody(rb.body)
	}

	return req
}

// Response represents a simplified HTTP response
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

// String returns the body as a string
func (r *Response) String() string {
	return string(r.Body)
}

// JSON parses the body as JSON
func (r *Response) JSON(v interface{}) error {
	return json.Unmarshal(r.Body, v)
}

// HasHeader checks if a header exists (case-insensitive)
func (r *Response) HasHeader(name string) bool {
	_, exists := r.GetHeader(name)
	return exists
}

// GetHeader gets a header value (case-insensitive)
func (r *Response) GetHeader(name string) (string, bool) {
	for k, v := range r.Headers {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// ParseResponse converts a fasthttp.Response to our Response type
func ParseResponse(fresp *fasthttp.Response) *Response {
	resp := &Response{
		StatusCode: fresp.StatusCode(),
		Headers:    make(map[string]string),
		Body:       make([]byte, len(fresp.Body())),
	}

	// Copy body
	copy(resp.Body, fresp.Body())

	// Copy headers
	fresp.Header.VisitAll(func(key, value []byte) {
		resp.Headers[string(key)] = string(value)
	})

	return resp
}

// ParseIPRange parses an IP range string like "127.0.0.10-19"
func ParseIPRange(ipRange string) ([]string, error) {
	var start, end int
	_, err := fmt.Sscanf(ipRange, "127.0.0.%d-%d", &start, &end)
	if err != nil {
		return nil, fmt.Errorf("invalid IP range format: %s (expected 127.0.0.start-end)", ipRange)
	}

	if start > end || start < 1 || end > 255 {
		return nil, fmt.Errorf("invalid IP range: %d-%d", start, end)
	}

	var ips []string
	for i := start; i <= end; i++ {
		ips = append(ips, fmt.Sprintf("127.0.0.%d", i))
	}
	return ips, nil
}

// SetSourceIPHeader sets the X-Forwarded-For header to simulate proxy chains
func SetSourceIPHeader(req *fasthttp.Request, sourceIP string, proxyChain []string) {
	var xff string
	if len(proxyChain) > 0 {
		xff = strings.Join(proxyChain, ", ") + ", " + sourceIP
	} else {
		xff = sourceIP
	}
	req.Header.Set("X-Forwarded-For", xff)
	req.Header.Set("X-Real-IP", sourceIP)
}

// BuildURL builds a URL from components
func BuildURL(scheme, host string, port int, path string, query map[string]string) string {
	var sb strings.Builder
	if scheme == "" {
		scheme = "http"
	}
	sb.WriteString(scheme)
	sb.WriteString("://")
	sb.WriteString(host)
	if port > 0 && ((scheme == "http" && port != 80) || (scheme == "https" && port != 443)) {
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(port))
	}
	if !strings.HasPrefix(path, "/") {
		sb.WriteString("/")
	}
	sb.WriteString(path)

	if len(query) > 0 {
		sb.WriteString("?")
		first := true
		for k, v := range query {
			if !first {
				sb.WriteString("&")
			}
			first = false
			sb.WriteString(url.QueryEscape(k))
			sb.WriteString("=")
			sb.WriteString(url.QueryEscape(v))
		}
	}

	return sb.String()
}

// ExtractMarkers extracts proof markers from response body using regex
// Pattern: __[VL]\d+[a-b]?_\w+__
func ExtractMarkers(body []byte) []string {
	re := regexp.MustCompile(`__[VL]\d+[a-b]?_\w+__`)
	return re.FindAllString(string(body), -1)
}

// HasMarker checks if a specific marker exists in the response
func HasMarker(body []byte, marker string) bool {
	return strings.Contains(string(body), marker)
}

// ExtractHeader extracts a header value from fasthttp response
func ExtractHeader(resp *fasthttp.Response, name string) string {
	return string(resp.Header.Peek(name))
}

// CommonContentTypes
const (
	ContentTypeJSON           = "application/json"
	ContentTypeForm           = "application/x-www-form-urlencoded"
	ContentTypeText           = "text/plain"
	ContentTypeHTML           = "text/html"
	ContentTypeMultipart      = "multipart/form-data"
	ContentTypeOctetStream    = "application/octet-stream"
)

// CommonHeaders for testing
var (
	HeaderAcceptJSON      = map[string]string{"Accept": "application/json"}
	HeaderAcceptHTML      = map[string]string{"Accept": "text/html"}
	HeaderContentTypeJSON = map[string]string{"Content-Type": "application/json"}
)

// ReleaseResponse safely releases a response back to the pool
func ReleaseResponse(resp *fasthttp.Response) {
	if resp != nil {
		fasthttp.ReleaseResponse(resp)
	}
}

// ReleaseRequest safely releases a request back to the pool
func ReleaseRequest(req *fasthttp.Request) {
	if req != nil {
		fasthttp.ReleaseRequest(req)
	}
}
