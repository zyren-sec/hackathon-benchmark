// reproduce_waf_latency.go — Phase C WAF Latency Reproduction Script
//
// This script mirrors the benchmark tool's internal measureWAFLatency()
// method exactly: sends requests through WAF (:8080) → UPSTREAM (:9000),
// using the same endpoint classes, sample counts, and measurement methodology.
//
// Usage:
//   go run reproduce_waf_latency.go
//
// Environment variables:
//   WAF_URL        — WAF proxy base URL (default: http://127.0.0.1:8080)
//   UPSTREAM_URL   — upstream target for baseline (default: http://127.0.0.1:9000)
//   BASELINE_ONLY  — if set, only measure baseline (skip WAF)

package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"
)

// ── Endpoint Classes (mirrors GetEndpointClasses() in internal/phasec/definitions.go) ──

type endpointClass struct {
	Name      string
	Endpoints []string
	Samples   int
}

var endpointClasses = []endpointClass{
	{Name: "critical", Endpoints: []string{"/login", "/deposit", "/withdraw"}, Samples: 150},
	{Name: "high", Endpoints: []string{"/api/profile", "/game/list"}, Samples: 100},
	{Name: "medium", Endpoints: []string{"/static/js/app.js", "/static/css/style.css", "/api/transactions"}, Samples: 100},
	{Name: "catch_all", Endpoints: []string{"/health", "/"}, Samples: 100},
}

type classResult struct {
	Name      string
	Endpoints []string
	Samples   int
	P50Ms     float64
	P99Ms     float64
	AvgMs     float64
	MinMs     float64
	MaxMs     float64
}

// measure sends GET requests to baseURL + endpoint and returns sorted latencies.
func measure(client *http.Client, baseURL string, cls endpointClass) ([]float64, int) {
	var latencies []float64
	perEndpoint := cls.Samples / len(cls.Endpoints)
	if perEndpoint < 1 {
		perEndpoint = 1
	}

	for _, ep := range cls.Endpoints {
		for i := 0; i < perEndpoint; i++ {
			t0 := time.Now()
			resp, err := client.Get(baseURL + ep)
			lat := float64(time.Since(t0).Nanoseconds()) / 1_000_000.0

			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			latencies = append(latencies, lat)
		}
	}

	return latencies, perEndpoint * len(cls.Endpoints)
}

// computeStats sorts latencies and returns P50, P99, Avg, Min, Max.
func computeStats(latencies []float64) (p50, p99, avg, min, max float64) {
	if len(latencies) == 0 {
		return 0, 0, 0, 0, 0
	}

	sort.Float64s(latencies)
	n := len(latencies)

	p50 = latencies[n*50/100]
	p99 = latencies[n*99/100]
	min = latencies[0]
	max = latencies[n-1]

	var sum float64
	for _, l := range latencies {
		sum += l
	}
	avg = sum / float64(n)

	return
}

func main() {
	wafURL := "http://127.0.0.1:8080"
	upstreamURL := "http://127.0.0.1:9000"

	if v := os.Getenv("WAF_URL"); v != "" {
		wafURL = v
	}
	if v := os.Getenv("UPSTREAM_URL"); v != "" {
		upstreamURL = v
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Println("  PHASE C — WAF LATENCY REPRODUCTION")
	fmt.Printf("  WAF PROXY:  %s\n", wafURL)
	fmt.Printf("  UPSTREAM:   %s\n", upstreamURL)
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Println()

	// ── Step 1: Baseline (direct to UPSTREAM) ──
	fmt.Println("── Step 1: BASELINE (Direct → UPSTREAM) ──")
	fmt.Println()

	var baselineResults []classResult
	for _, cls := range endpointClasses {
		latencies, total := measure(client, upstreamURL, cls)
		if len(latencies) == 0 {
			fmt.Printf("  ⚠️  Class %s: no samples — skipping\n\n", cls.Name)
			continue
		}
		p50, p99, avg, min, max := computeStats(latencies)

		baselineResults = append(baselineResults, classResult{
			Name: cls.Name, Endpoints: cls.Endpoints, Samples: total,
			P50Ms: p50, P99Ms: p99, AvgMs: avg, MinMs: min, MaxMs: max,
		})

		fmt.Printf("  %-10s  P50: %8.3fms  P99: %8.3fms  Avg: %8.3fms\n",
			cls.Name, p50, p99, avg)
	}

	// Build baseline lookup
	baselineMap := make(map[string]classResult)
	for _, r := range baselineResults {
		baselineMap[r.Name] = r
	}

	// ── Step 2: WAF Latency (through WAF :8080) ──
	fmt.Println()
	fmt.Println("── Step 2: WAF LATENCY (Through WAF → UPSTREAM) ──")
	fmt.Println()

	var wafResults []classResult
	for _, cls := range endpointClasses {
		latencies, total := measure(client, wafURL, cls)
		if len(latencies) == 0 {
			fmt.Printf("  ⚠️  Class %s: no samples — skipping\n\n", cls.Name)
			continue
		}
		p50, p99, avg, min, max := computeStats(latencies)

		wafResults = append(wafResults, classResult{
			Name: cls.Name, Endpoints: cls.Endpoints, Samples: total,
			P50Ms: p50, P99Ms: p99, AvgMs: avg, MinMs: min, MaxMs: max,
		})

		fmt.Printf("  %-10s  P50: %8.3fms  P99: %8.3fms  Avg: %8.3fms\n",
			cls.Name, p50, p99, avg)
	}

	// ── Step 3: Overhead Calculation ──
	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Println("  OVERHEAD COMPARISON (WAF − Baseline)")
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Println()

	fmt.Printf("  %-12s %10s %10s %10s %10s %10s %10s %9s\n",
		"Class", "Base P50", "WAF P50", "ΔP50", "Base P99", "WAF P99", "ΔP99", "Overhead%")
	fmt.Println("  ────────────────────────────────────────────────────────────────────────────────────")

	totalOverhead := 0.0
	count := 0
	for _, waf := range wafResults {
		base, ok := baselineMap[waf.Name]
		if !ok {
			fmt.Printf("  %-12s %12s %10.3fms %12s %12s %10.3fms %12s\n",
				waf.Name, "(no baseline)", waf.P50Ms, "—", "(no baseline)", waf.P99Ms, "—")
			continue
		}

		deltaP50 := waf.P50Ms - base.P50Ms
		deltaP99 := waf.P99Ms - base.P99Ms
		overheadPct := 0.0
		if base.AvgMs > 0 {
			overheadPct = (waf.AvgMs - base.AvgMs) / base.AvgMs * 100
		}

		fmt.Printf("  %-12s %10.3fms %10.3fms %+10.3fms %10.3fms %10.3fms %+10.3fms %+9.1f%%\n",
			waf.Name,
			base.P50Ms, waf.P50Ms, deltaP50,
			base.P99Ms, waf.P99Ms, deltaP99,
			overheadPct)

		totalOverhead += deltaP99
		count++
	}

	if count > 0 {
		avgOverhead := totalOverhead / float64(count)
		fmt.Println("  ────────────────────────────────────────────────────────────────────────────────────")
		fmt.Printf("  %-12s %12s %12s %12s %12s %12s %+10.3fms\n",
			"AVERAGE", "—", "—", "—", "—", "—", avgOverhead)
	}

	fmt.Println()
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Println("  PERF-01 CHECK")
	fmt.Printf("  Average p99 WAF overhead: %.3fms\n", totalOverhead/float64(max(count, 1)))
	if totalOverhead/float64(max(count, 1)) <= 5.0 {
		fmt.Println("  Result: PASS ✓ (≤ 5ms)")
	} else {
		fmt.Println("  Result: FAIL ✗ (> 5ms)")
	}
	fmt.Println("══════════════════════════════════════════════════════════════════")
}
