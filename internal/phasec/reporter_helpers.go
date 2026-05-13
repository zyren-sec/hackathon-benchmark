package phasec

import (
	"fmt"
	"strings"
)

// ── Executive Summary Builder ──

func buildExecutiveSummary(r *PhaseCReport) string {
	var sb strings.Builder
	sb.WriteString(`<div class="section" style="border-color:var(--blue);"><h2>📋 Executive Summary</h2>`)

	sb.WriteString(`<p style="color:var(--muted);margin-bottom:16px;">Phase C measures your WAF's <strong>performance under blended traffic load</strong> (60% legitimate user journeys + 10% suspicious-but-valid + 10% exploit payloads + 10% abuse patterns + 10% DDoS bursts). The benchmark tool sends traffic through your WAF at escalating rates (1K → 3K → 5K → 10K RPS) and measures latency, throughput, memory, and error rate.</p>`)

	scoreColor := "var(--green)"
	scoreLabel := "EXCELLENT"
	if r.PhaseCTotal < 15 {
		scoreColor = "var(--yellow)"
		scoreLabel = "NEEDS IMPROVEMENT"
	}
	if r.PhaseCTotal < 5 {
		scoreColor = "var(--red)"
		scoreLabel = "CRITICAL"
	}

	sb.WriteString(fmt.Sprintf(`<div style="background:rgba(59,130,246,0.06);border:1px solid var(--border2);border-radius:8px;padding:16px;margin-bottom:16px;">
<div style="display:flex;align-items:center;gap:16px;">
<div style="font-size:2rem;font-weight:800;color:%s;">%.0f<span style="font-size:1rem;color:var(--muted);">/%.0f</span></div>
<div><strong style="color:%s;">%s</strong><br><span style="color:var(--muted);font-size:0.85rem;">Phase C Performance Score</span></div>
</div></div>`, scoreColor, r.PhaseCTotal, r.PhaseCMax, scoreColor, scoreLabel))

	var passed, failed []string
	for _, id := range []string{"PERF-01", "PERF-02", "PERF-03", "PERF-04"} {
		sc, ok := r.Scoring[id]
		if !ok {
			continue
		}
		desc := map[string]string{
			"PERF-01": "p99 Latency ≤ 5ms",
			"PERF-02": "Throughput ≥ 5K RPS",
			"PERF-03": "Memory < 100MB",
			"PERF-04": "No crash + Error < 5%",
		}[id]
		if sc.Pass {
			passed = append(passed, fmt.Sprintf(`<span style="color:var(--green);">✅ %s (%s)</span>`, id, desc))
		} else {
			valStr := fmt.Sprintf("%.3f", sc.Measured)
			switch id {
			case "PERF-01":
				valStr = fmt.Sprintf("%.1f ms", sc.Measured)
			case "PERF-02":
				valStr = fmt.Sprintf("%.1f RPS", sc.Measured)
			case "PERF-03":
				valStr = fmt.Sprintf("%.1f MB", sc.Measured)
			case "PERF-04":
				valStr = fmt.Sprintf("%.1f%% errors", sc.Measured*100)
			}
			failed = append(failed, fmt.Sprintf(`<span style="color:var(--red);">❌ %s (%s — measured: %s, threshold: %.0f)</span>`, id, desc, valStr, sc.Threshold))
		}
	}

	sb.WriteString(`<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:8px;">`)
	sb.WriteString(`<div><strong style="color:var(--green);">PASSED</strong><ul style="list-style:none;padding:0;margin:8px 0 0;font-size:0.9rem;">`)
	for _, p := range passed {
		sb.WriteString(fmt.Sprintf("<li style=\"margin:4px 0;\">%s</li>", p))
	}
	sb.WriteString(`</ul></div>`)
	sb.WriteString(`<div><strong style="color:var(--red);">FAILED</strong><ul style="list-style:none;padding:0;margin:8px 0 0;font-size:0.9rem;">`)
	for _, f := range failed {
		sb.WriteString(fmt.Sprintf("<li style=\"margin:4px 0;\">%s</li>", f))
	}
	if len(failed) == 0 {
		sb.WriteString(`<li style="color:var(--green);">None — all criteria passed!</li>`)
	}
	sb.WriteString(`</ul></div></div>`)

	if len(failed) > 0 {
		sb.WriteString(`<p style="margin-top:12px;color:var(--yellow);font-size:0.85rem;">⚠️ Phase C is also <strong>Tiebreaker TB-02</strong> — the team with the lowest p99 latency at 5K RPS wins if security scores are tied.</p>`)
	}

	sb.WriteString(`</div>`)
	return sb.String()
}

// ── Traffic Mix Table Builder ──

func buildTrafficMixTable() string {
	return `<div style="margin-bottom:20px;">
<details open><summary style="font-weight:700;font-size:0.95rem;cursor:pointer;color:var(--blue);">📊 Traffic Mix Details — What Each Type Means</summary>
<div class="table-wrap" style="margin-top:12px;"><table>
<thead><tr><th>Type</th><th>Ratio</th><th>Description</th><th>What the WAF should do</th></tr></thead>
<tbody>
<tr>
<td style="font-weight:600;color:var(--green);">Legitimate<br>(Golden Path)</td>
<td>60%</td>
<td>Full user journey: GET / → GET /game/list → POST /login → POST /otp → GET /api/profile → GET /game/{id} → POST /game/{id}/play → POST /deposit → GET /api/transactions → POST /withdrawal</td>
<td><strong>Allow (200)</strong> with low latency</td>
</tr>
<tr>
<td style="font-weight:600;color:var(--yellow);">Suspicious<br>but Legitimate</td>
<td>10%</td>
<td>Same golden path, but with unusual User-Agent (<code>python-requests/2.28</code>, <code>Bot/1.0</code>) and faster timing (100–300 ms between requests). Credentials are valid.</td>
<td>Allow or challenge; if blocked → counts as <strong style="color:var(--red);">false positive</strong></td>
</tr>
<tr>
<td style="font-weight:600;color:var(--red);">Exploit<br>Payloads</td>
<td>10%</td>
<td>Active vulnerabilities from the catalogue: SQLi (V01, V02), XSS (V04), Path Traversal (V06, V07), SSRF (V08, V09), Malformed JSON (V14), Supply-chain (V20), Asymmetric DoS (V21), Race Condition (V24). Authenticated payloads include a full login-OTP flow first.</td>
<td><strong>Block (403)</strong>, challenge, or rate-limit</td>
</tr>
<tr>
<td style="font-weight:600;color:var(--orange);">Abuse<br>Patterns</td>
<td>10%</td>
<td>Failed login attempts (<code>admin</code> / wrong password) and random path scanning (<code>/api/invalid-path-{random}</code>).</td>
<td><strong>Rate-limit (429)</strong> or block after threshold</td>
</tr>
<tr>
<td style="font-weight:600;color:var(--purple);">DDoS<br>Bursts</td>
<td>10%</td>
<td>High-volume <code>GET /</code> and <code>GET /game/list</code> fired in burst windows: every 10 seconds, a 2-second burst of pure DDoS traffic is injected (only when target RPS ≥ 1,000).</td>
<td>Rate-limit or drop; legitimate requests blocked inside burst windows are counted as <strong>collateral</strong>, not false positives</td>
</tr>
</tbody></table></div>
</details></div>`
}

// ── PERF Interpretation Builder ──

func buildPERFInterpretation(r *PhaseCReport) string {
	var sb strings.Builder

	hasFailed := false
	for _, id := range []string{"PERF-01", "PERF-02", "PERF-03", "PERF-04"} {
		sc, ok := r.Scoring[id]
		if !ok || sc.Pass {
			continue
		}
		hasFailed = true
		sb.WriteString(`<div class="section" style="border-color:var(--red);"><h2>🔴 `)
		sb.WriteString(fmt.Sprintf(`%s — Why did it fail?</h2>`, id))

		switch id {
		case "PERF-01":
			sb.WriteString(buildPERF01Interpretation(r, sc))
		case "PERF-02":
			sb.WriteString(buildPERF02Interpretation(r, sc))
		case "PERF-03":
			sb.WriteString(buildPERF03Interpretation(r, sc))
		case "PERF-04":
			sb.WriteString(buildPERF04Interpretation(r, sc))
		}
		sb.WriteString(`</div>`)
	}

	if !hasFailed {
		return ""
	}
	return sb.String()
}

func buildPERF01Interpretation(r *PhaseCReport, sc CScoreDetailJSON) string {
	var sb strings.Builder

	var step3 *CLoadTestStepJSON
	for i := range r.LoadTestSteps {
		if r.LoadTestSteps[i].StepNum == 3 {
			step3 = &r.LoadTestSteps[i]
			break
		}
	}

	sb.WriteString(fmt.Sprintf(`<p>Your WAF added <strong style="color:var(--red);">%.1f ms</strong> of p99 latency at 5,000 RPS. The threshold is <strong>5 ms</strong>. This means 99%% of requests through your WAF were delayed by more than <strong>%.0f×</strong> the allowed overhead.</p>`,
		sc.Measured, sc.Measured/5.0))

	sb.WriteString(`<div style="background:rgba(0,0,0,0.2);border-radius:8px;padding:12px 16px;margin:12px 0;"><strong>Key observations from the data:</strong><ul style="margin:8px 0 0;padding-left:20px;">`)

	if r.Baseline != nil && len(r.Baseline.Classes) > 0 && r.WAFLatency != nil && len(r.WAFLatency.Classes) > 0 {
		worstOv := 0.0
		worstName := ""
		for _, cls := range r.WAFLatency.Classes {
			if cls.OverheadP99 > worstOv {
				worstOv = cls.OverheadP99
				worstName = cls.Name
			}
		}
		sb.WriteString(fmt.Sprintf(`<li>The low-concurrency latency measurement (450 samples, sequential) shows acceptable WAF overhead (~%.0f–%.0f ms), but under <strong>real blended load</strong> at Step 3 (5,000 RPS, 60s), p99 latency ballooned to <strong>%.1f ms</strong> — a degradation of <strong>two orders of magnitude</strong>.</li>`,
			r.WAFLatency.Classes[0].OverheadP50, r.WAFLatency.Classes[len(r.WAFLatency.Classes)-1].OverheadP99, sc.Measured))

		if worstName != "" {
			sb.WriteString(fmt.Sprintf(`<li>Worst endpoint class for overhead: <strong>%s</strong> (ΔP99 = %.1f ms).</li>`, worstName, worstOv))
		}
	}

	if step3 != nil {
		sb.WriteString(fmt.Sprintf(`<li>Step 3 actual throughput was only <strong>%.1f RPS</strong> (target: 5,000) — the WAF could not keep up with the request rate. P50: %.1f ms, Max: %.1f ms.</li>`,
			step3.ActualRPS, step3.P50Ms, step3.MaxMs))
	}

	sb.WriteString(`<li>This pattern typically indicates: <strong>synchronous rule evaluation</strong>, lack of connection pooling, unbounded internal queueing under mixed traffic, or blocking I/O in the WAF request path.</li>`)
	sb.WriteString(`</ul></div>`)
	sb.WriteString(`<p style="color:var(--muted);font-size:0.85rem;"><strong>How to fix:</strong> Profile your WAF under load to identify the bottleneck. Consider async rule evaluation, connection pooling to upstream, bounded queues with early rejection, and non-blocking I/O.</p>`)
	return sb.String()
}

func buildPERF02Interpretation(r *PhaseCReport, sc CScoreDetailJSON) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`<p>Your WAF sustained only <strong style="color:var(--red);">%.1f RPS</strong> out of a 5,000 RPS target. The benchmark tool attempted to generate 5,000 RPS, but the WAF could only process ~<strong>%.1f%%</strong> of that rate.</p>`,
		sc.Measured, sc.Measured/5000*100))

	sb.WriteString(`<div style="background:rgba(0,0,0,0.2);border-radius:8px;padding:12px 16px;margin:12px 0;"><strong>Key observations from the data:</strong><ul style="margin:8px 0 0;padding-left:20px;">`)

	for _, step := range r.LoadTestSteps {
		pct := step.ActualRPS / float64(step.TargetRPS) * 100
		label := ""
		switch step.StepNum {
		case 1:
			label = " — warm-up"
		case 2:
			if step.ActualRPS < r.LoadTestSteps[0].ActualRPS {
				label = " — worse than Step 1"
			}
		case 3:
			label = " — SLA target failed"
		case 4:
			label = " — stress test"
		}
		sb.WriteString(fmt.Sprintf(`<li>Step %d (%d RPS target): actual = <strong>%.1f RPS</strong> (%.1f%% of target)%s</li>`,
			step.StepNum, step.TargetRPS, step.ActualRPS, pct, label))
	}

	if len(r.LoadTestSteps) >= 3 {
		first := r.LoadTestSteps[0].ActualRPS
		last := r.LoadTestSteps[len(r.LoadTestSteps)-1].ActualRPS
		if last < first {
			sb.WriteString(`<li>The throughput curve is <strong>inverse to the target</strong>: higher target RPS → lower actual RPS. This suggests the WAF is bottlenecked by a <strong>shared resource</strong> (single-threaded worker, lock contention, or upstream connection limit) that collapses under load.</li>`)
		}
	}

	allZeroErrors := true
	for _, step := range r.LoadTestSteps {
		if step.ErrorCount > 0 {
			allZeroErrors = false
			break
		}
	}
	if allZeroErrors {
		sb.WriteString(`<li>Notably, <strong>error rate is 0.00%</strong> across all steps — requests are not rejected, they are simply <strong>queued or processed very slowly</strong>.</li>`)
	}

	sb.WriteString(`</ul></div>`)
	sb.WriteString(`<p style="color:var(--muted);font-size:0.85rem;"><strong>How to fix:</strong> Increase WAF worker pool size, remove lock contention, implement connection pooling to upstream, and add backpressure to shed excess load gracefully.</p>`)
	return sb.String()
}

func buildPERF03Interpretation(r *PhaseCReport, sc CScoreDetailJSON) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<p>Your WAF's peak memory footprint was <strong style="color:var(--red);">%.1f MB</strong>. The threshold is <strong>%.0f MB</strong>.</p>`,
		sc.Measured, sc.Threshold))

	sb.WriteString(`<div style="background:rgba(0,0,0,0.2);border-radius:8px;padding:12px 16px;margin:12px 0;"><strong>Key observations:</strong><ul style="margin:8px 0 0;padding-left:20px;">`)

	if len(r.MemoryTS) >= 2 {
		firstMem := r.MemoryTS[0].MemoryMB
		lastMem := r.MemoryTS[len(r.MemoryTS)-1].MemoryMB
		growth := lastMem - firstMem
		if growth > 10 {
			sb.WriteString(fmt.Sprintf(`<li>Memory grew by <strong>%.1f MB</strong> during the test (%.1f → %.1f MB) — indicates a <strong>memory leak</strong> or unbounded allocation.</li>`, growth, firstMem, lastMem))
		} else {
			sb.WriteString(fmt.Sprintf(`<li>Memory was <strong>stable</strong> throughout (%.1f → %.1f MB) but exceeded the %.0f MB threshold — baseline footprint is too high.</li>`, firstMem, lastMem, sc.Threshold))
		}
	}

	sb.WriteString(`<li>High memory under load typically indicates: large per-request buffers, unbounded request/response caching, or retaining connection state for too long.</li>`)
	sb.WriteString(`</ul></div>`)
	sb.WriteString(`<p style="color:var(--muted);font-size:0.85rem;"><strong>How to fix:</strong> Profile memory allocations under load. Reduce per-request buffers, implement bounded caches with eviction, release connection state promptly.</p>`)
	return sb.String()
}

func buildPERF04Interpretation(r *PhaseCReport, sc CScoreDetailJSON) string {
	var sb strings.Builder

	if r.WAFCrashed {
		sb.WriteString(`<p><strong style="color:var(--red);">Your WAF crashed</strong> during Step 4 (10,000 RPS stress test). The WAF process terminated before the step completed.</p>`)
		sb.WriteString(`<div style="background:rgba(0,0,0,0.2);border-radius:8px;padding:12px 16px;margin:12px 0;"><strong>Key observations:</strong><ul style="margin:8px 0 0;padding-left:20px;">`)
		sb.WriteString(`<li>A crash at 10K RPS typically indicates: <strong>out-of-memory (OOM)</strong>, <strong>panic/unhandled exception</strong>, or <strong>resource exhaustion</strong> (file descriptors, threads).</li>`)
		sb.WriteString(`<li>Check WAF logs for the crash reason. If OOM, review memory trends in earlier steps for warning signs.</li>`)
		sb.WriteString(`</ul></div>`)
		sb.WriteString(`<p style="color:var(--muted);font-size:0.85rem;"><strong>How to fix:</strong> Add crash recovery (auto-restart), implement graceful shutdown, set resource limits, stress-test incrementally.</p>`)
	} else {
		sb.WriteString(fmt.Sprintf(`<p>Your WAF survived the stress test but had <strong style="color:var(--red);">%.1f%%</strong> error rate at 10,000 RPS. The threshold is <strong>%.0f%%</strong>.</p>`,
			sc.Measured*100, sc.Threshold*100))

		sb.WriteString(`<div style="background:rgba(0,0,0,0.2);border-radius:8px;padding:12px 16px;margin:12px 0;"><strong>Key observations:</strong><ul style="margin:8px 0 0;padding-left:20px;">`)

		for _, step := range r.LoadTestSteps {
			if step.StepNum == 4 {
				sb.WriteString(fmt.Sprintf(`<li>Step 4 (10K RPS): %d errors out of %d requests — error rate = %.2f%%.</li>`,
					step.ErrorCount, step.TotalRequests, step.ErrorRate*100))
				sb.WriteString(fmt.Sprintf(`<li>P50 latency: %.1f ms  |  P99: %.1f ms  |  Max: %.1f ms  |  Memory: %.1f MB</li>`,
					step.P50Ms, step.P99Ms, step.MaxMs, step.MemoryPeakMB))
				break
			}
		}

		sb.WriteString(`<li>High error rates under stress usually mean the WAF is <strong>rejecting connections</strong> (connection refused, timeout) rather than queueing — a sign of exhausted listen backlog or thread pool.</li>`)
		sb.WriteString(`</ul></div>`)
		sb.WriteString(`<p style="color:var(--muted);font-size:0.85rem;"><strong>How to fix:</strong> Increase listen backlog, expand worker pool, add request queueing with bounded size, implement graceful degradation (503 + Retry-After).</p>`)
	}
	return sb.String()
}
