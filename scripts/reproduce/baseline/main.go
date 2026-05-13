// reproduce_baseline.go — Phase C Baseline Latency Reproduction Script
//
// This script mirrors the benchmark tool's internal measureBaselineLatency()
// method exactly: same endpoint classes, same sample counts, same measurement
// methodology (time.Now / time.Since on http.Client.Get).
//
// Usage:
//   go run reproduce_baseline.go
//
// The script sends requests directly to UPSTREAM (:9000), bypassing WAF,
// and computes P50, P99, and Avg latency for each endpoint class.

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
	Samples   int // total samples for this class (split evenly across endpoints)
}

var endpointClasses = []endpointClass{
	{Name: "critical", Endpoints: []string{"/login", "/deposit", "/withdraw"}, Samples: 150},
	{Name: "high", Endpoints: []string{"/api/profile", "/game/list"}, Samples: 100},
	{Name: "medium", Endpoints: []string{"/static/js/app.js", "/static/css/style.css", "/api/transactions"}, Samples: 100},
	{Name: "catch_all", Endpoints: []string{"/health", "/"}, Samples: 100},
}

// ── Result ──

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

func main() {
	baseURL := "http://127.0.0.1:9000"
	if v := os.Getenv("UPSTREAM_URL"); v != "" {
		baseURL = v
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		// Disable keep-alive to avoid connection reuse skewing per-request latency
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	var results []classResult
	totalSamples := 0

	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Println("  PHASE C — BASELINE LATENCY REPRODUCTION")
	fmt.Println("  Direct → UPSTREAM", baseURL)
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Println()

	for _, cls := range endpointClasses {
		var latencies []float64
		perEndpoint := cls.Samples / len(cls.Endpoints)
		if perEndpoint < 1 {
			perEndpoint = 1
		}

		fmt.Printf("▶ Class %-10s (%d samples × %d endpoints = %d total)\n",
			cls.Name, perEndpoint, len(cls.Endpoints), perEndpoint*len(cls.Endpoints))

		for _, ep := range cls.Endpoints {
			for i := 0; i < perEndpoint; i++ {
				t0 := time.Now()
				resp, err := client.Get(baseURL + ep)
				// latency in milliseconds (same formula as benchmark tool)
				lat := float64(time.Since(t0).Nanoseconds()) / 1_000_000.0

				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				// Include even failed requests (mirrors benchmark tool behavior)
				latencies = append(latencies, lat)
			}
		}

		if len(latencies) == 0 {
			fmt.Printf("  ⚠️  No samples collected — skipping\n\n")
			continue
		}

		// Sort and compute percentiles (mirrors benchmark tool exactly)
		sort.Float64s(latencies)
		n := len(latencies)

		p50 := latencies[n*50/100]
		p99 := latencies[n*99/100]
		min := latencies[0]
		max := latencies[n-1]

		var sum float64
		for _, l := range latencies {
			sum += l
		}
		avg := sum / float64(n)

		results = append(results, classResult{
			Name:      cls.Name,
			Endpoints: cls.Endpoints,
			Samples:   n,
			P50Ms:     p50,
			P99Ms:     p99,
			AvgMs:     avg,
			MinMs:     min,
			MaxMs:     max,
		})
		totalSamples += n

		fmt.Printf("  P50: %.3fms  P99: %.3fms  Avg: %.3fms  Min: %.3fms  Max: %.3fms\n\n",
			p50, p99, avg, min, max)
	}

	// ── Summary ──
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Println("  BASELINE SUMMARY")
	fmt.Println("══════════════════════════════════════════════════════════════════")
	fmt.Printf("  %-12s %8s %10s %10s %10s %10s %10s\n",
		"Class", "Samples", "P50(ms)", "P99(ms)", "Avg(ms)", "Min(ms)", "Max(ms)")
	fmt.Println("  ──────────────────────────────────────────────────────────────────")
	for _, r := range results {
		fmt.Printf("  %-12s %8d %10.3f %10.3f %10.3f %10.3f %10.3f\n",
			r.Name, r.Samples, r.P50Ms, r.P99Ms, r.AvgMs, r.MinMs, r.MaxMs)
	}
	fmt.Printf("  %-12s %8d\n", "TOTAL", totalSamples)
	fmt.Println("══════════════════════════════════════════════════════════════════")
}
