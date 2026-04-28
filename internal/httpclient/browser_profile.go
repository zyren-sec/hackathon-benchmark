package httpclient

import (
	"strings"

	"github.com/valyala/fasthttp"
)

// BrowserHeaderProfile defines a safe browser-like header profile.
//
// This profile is intentionally approximate and intended for defensive
// benchmark realism only, not exact anti-detection impersonation.
type BrowserHeaderProfile struct {
	UserAgent      string
	AcceptLanguage string
	AcceptEncoding string
	Platform       string
	Mobile         string
	SecCHUA        string
}

// DefaultBrowserHeaderProfile returns a Chrome-style (approximate) profile.
func DefaultBrowserHeaderProfile() BrowserHeaderProfile {
	return BrowserHeaderProfile{
		UserAgent:      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		AcceptLanguage: "en-US,en;q=0.9",
		AcceptEncoding: "gzip, deflate, br, zstd",
		Platform:       "\"Linux\"",
		Mobile:         "?0",
		SecCHUA:        "\"Chromium\";v=\"135\", \"Google Chrome\";v=\"135\", \"Not.A/Brand\";v=\"24\"",
	}
}

// ApplySafeChromeHeaders applies an ordered, browser-like header set.
//
// Note: This sets an approximate Chrome-style set and order for realism, but
// does not claim exact byte-perfect browser fingerprint equivalence.
func ApplySafeChromeHeaders(req *fasthttp.Request, p BrowserHeaderProfile) {
	if req == nil {
		return
	}

	if strings.TrimSpace(p.UserAgent) == "" ||
		strings.TrimSpace(p.AcceptLanguage) == "" ||
		strings.TrimSpace(p.AcceptEncoding) == "" ||
		strings.TrimSpace(p.Platform) == "" ||
		strings.TrimSpace(p.Mobile) == "" ||
		strings.TrimSpace(p.SecCHUA) == "" {
		p = DefaultBrowserHeaderProfile()
	}

	// Ensure host is explicit when available in URI.
	if len(req.Header.Host()) == 0 && len(req.URI().Host()) > 0 {
		req.Header.SetHostBytes(req.URI().Host())
	}

	// Reset browser-relevant headers before applying in preferred order.
	orderedKeys := []string{
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"Accept",
		"Sec-Fetch-Site",
		"Sec-Fetch-Mode",
		"Sec-Fetch-User",
		"Sec-Fetch-Dest",
		"Accept-Encoding",
		"Accept-Language",
	}
	for _, k := range orderedKeys {
		req.Header.Del(k)
	}

	// fasthttp serializes Host separately; keep it explicit above and then set
	// the rest in deterministic insertion order.
	req.Header.SetBytesKV([]byte("sec-ch-ua"), []byte(p.SecCHUA))
	req.Header.SetBytesKV([]byte("sec-ch-ua-mobile"), []byte(p.Mobile))
	req.Header.SetBytesKV([]byte("sec-ch-ua-platform"), []byte(p.Platform))
	req.Header.SetBytesKV([]byte("Upgrade-Insecure-Requests"), []byte("1"))
	req.Header.SetUserAgent(p.UserAgent)

	if len(req.Header.Peek("Accept")) == 0 {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	}

	if len(req.Header.Peek("Sec-Fetch-Site")) == 0 {
		req.Header.Set("Sec-Fetch-Site", "none")
	}
	if len(req.Header.Peek("Sec-Fetch-Mode")) == 0 {
		req.Header.Set("Sec-Fetch-Mode", "navigate")
	}
	if len(req.Header.Peek("Sec-Fetch-User")) == 0 {
		req.Header.Set("Sec-Fetch-User", "?1")
	}
	if len(req.Header.Peek("Sec-Fetch-Dest")) == 0 {
		req.Header.Set("Sec-Fetch-Dest", "document")
	}

	req.Header.Set("Accept-Encoding", p.AcceptEncoding)
	req.Header.Set("Accept-Language", p.AcceptLanguage)
	// Keep-alive is implicit in HTTP/1.1 and managed by transport; setting this
	// header helps preserve browser-like semantics for intermediaries.
	req.Header.Set("Connection", "keep-alive")
}
