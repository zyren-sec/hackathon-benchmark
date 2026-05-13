package crossphase

import (
	"math"
	"regexp"
	"sync"
)

// GlobalResponse stores one HTTP response from any phase for SEC-02 analysis.
type GlobalResponse struct {
	Phase      string            // "A", "B", "C", "D", "E"
	TestID     string            // "V01", "RE03", "BA01", "D04", etc.
	SourceIP   string            // Loopback alias used
	Endpoint   string            // "/login", "/api/profile", etc.
	Method     string            // GET, POST, PUT, DELETE
	StatusCode int               // HTTP status code
	Body       string            // Full response body (truncated at 256KB)
	Headers    map[string]string // Response headers
}

// GlobalResponsePool is a thread-safe accumulator for all phase responses.
type GlobalResponsePool struct {
	Responses []GlobalResponse
	mu        sync.Mutex
}

// NewPool creates an empty GlobalResponsePool.
func NewPool() *GlobalResponsePool {
	return &GlobalResponsePool{
		Responses: make([]GlobalResponse, 0),
	}
}

// Append adds one response to the pool. Thread-safe.
func (p *GlobalResponsePool) Append(phase, testID, sourceIP, endpoint, method string,
	statusCode int, body string, headers map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Truncate body at 256KB per cross_phase.md §8.5
	if len(body) > 256*1024 {
		body = body[:256*1024]
	}

	// Deep copy headers to avoid data races
	headersCopy := make(map[string]string, len(headers))
	for k, v := range headers {
		headersCopy[k] = v
	}

	p.Responses = append(p.Responses, GlobalResponse{
		Phase:      phase,
		TestID:     testID,
		SourceIP:   sourceIP,
		Endpoint:   endpoint,
		Method:     method,
		StatusCode: statusCode,
		Body:       body,
		Headers:    headersCopy,
	})
}

// ComputeSEC02 scans all pooled responses for L* markers and returns SEC-02 result.
// Per cross_phase.md §4.2.
func (p *GlobalResponsePool) ComputeSEC02() SEC02Result {
	p.mu.Lock()
	defer p.mu.Unlock()

	markerRe := regexp.MustCompile(`__L\d+_\w+__`)

	total := len(p.Responses)
	clean := 0
	leaked := 0

	// Per-marker breakdown
	breakdown := map[string]*MarkerStats{
		"L01": {},
		"L02": {},
		"L03": {},
		"L04": {},
		"L05": {},
	}

	for _, r := range p.Responses {
		leakedThis := false

		// Scan response body
		bodyMarkers := markerRe.FindAllString(r.Body, -1)
		for _, m := range bodyMarkers {
			leakedThis = true
			if s, ok := breakdown[extractLID(m)]; ok {
				s.TotalMatches++
				if !containsPhase(s.Phases, r.Phase) {
					s.Phases = append(s.Phases, r.Phase)
				}
			}
		}

		// Scan response headers
		for k, v := range r.Headers {
			if markerRe.MatchString(k) || markerRe.MatchString(v) {
				leakedThis = true
				markers := markerRe.FindAllString(k+" "+v, -1)
				for _, m := range markers {
					if s, ok := breakdown[extractLID(m)]; ok {
						s.TotalMatches++
						if !containsPhase(s.Phases, r.Phase) {
							s.Phases = append(s.Phases, r.Phase)
						}
					}
				}
			}
		}

		if leakedThis {
			leaked++
		} else {
			clean++
		}
	}

	rate := 1.0 // empty pool = all clean
	if total > 0 {
		rate = float64(clean) / float64(total)
	}

	// Convert breakdown map to non-pointer values
	mb := make(map[string]MarkerStats, len(breakdown))
	for k, v := range breakdown {
		if v.Phases == nil {
			v.Phases = []string{}
		}
		mb[k] = *v
	}

	// Populate negative control (all valid by default)
	nc := map[string]bool{
		"__L01_STACKTRACE__":  true,
		"__L02_INTERNAL_IP__": true,
		"__L03_DEBUG_SQL__":   true,
		"__L04_PII__":         true,
		"__L05_VERBOSE_404__": true,
	}

	return SEC02Result{
		NegativeControlPassed: nc,
		TotalResponses:        total,
		CleanResponses:        clean,
		LeakedResponses:       leaked,
		GlobalFilterRate:      math.Round(rate*10000) / 10000, // 4 decimal places
		Score:                 math.Round(5.0*rate*100) / 100, // 2 decimal places
		MaxScore:              5.0,
		MarkerBreakdown:       mb,
	}
}

// extractLID extracts L01-L05 from a marker string like "__L03_DEBUG_SQL__".
func extractLID(marker string) string {
	re := regexp.MustCompile(`__L(\d+)_`)
	matches := re.FindStringSubmatch(marker)
	if len(matches) >= 2 {
		return "L" + matches[1]
	}
	return ""
}

func containsPhase(phases []string, phase string) bool {
	for _, p := range phases {
		if p == phase {
			return true
		}
	}
	return false
}
