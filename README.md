# WAF Benchmark Tool

> Automated security validation and scoring framework for evaluating Web Application Firewalls (WAFs) against the WAF Hackathon v2.1 contract.

![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white)
![Protocol](https://img.shields.io/badge/Protocol-v2.1-blue)
![Reports](https://img.shields.io/badge/Reports-JSON%20%7C%20HTML-green)
![Scope](https://img.shields.io/badge/Scope-WAF%20Security%20Benchmark-red)

## Table of Contents

- [Overview](#overview)
- [What This Tool Tests](#what-this-tool-tests)
- [Repository Layout](#repository-layout)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [CLI Usage](#cli-usage)
- [Benchmark Phases](#benchmark-phases)
- [Scoring Model](#scoring-model)
- [Reports](#reports)
- [HTTP Client and Traffic Model](#http-client-and-traffic-model)
- [Payload Corpus](#payload-corpus)
- [Live Profiles](#live-profiles)
- [Standalone Tools](#standalone-tools)
- [Required Runtime Data](#required-runtime-data)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Security and Ethics](#security-and-ethics)

## Overview

The WAF Benchmark Tool is a Go-based benchmark runner that evaluates a WAF from an attacker-and-defender perspective. It sends realistic exploit traffic, abuse traffic, risk-lifecycle traffic, performance traffic, resilience traffic, and extensibility checks through a WAF, then produces machine-readable and reviewer-friendly reports.

The tool is designed around the WAF Hackathon v2.1 benchmark model and validates whether a WAF can:

- Block or neutralize common web exploits.
- Detect abuse patterns such as brute force, scanners, proxy relay, and abnormal behavior.
- Maintain acceptable latency and throughput under load.
- Survive stress conditions, slow attacks, and backend failure scenarios.
- Support hot-reload and correct cache behavior by route tier.
- Expose observability signals such as request IDs, decisions, rule IDs, risk scores, and cache status.

The primary executable is `waf-benchmark`, implemented under `cmd/waf-benchmark/`.

## What This Tool Tests

At a high level, the benchmark validates seven dimensions:

| Area | Purpose |
|---|---|
| Exploit Prevention | Tests SQLi, XSS, traversal, SSRF, RFI/LFI, command injection, NoSQL, XXE, XPath, LDAP, template injection, and outbound leak protection. |
| Abuse Detection | Tests brute force, credential stuffing, relay/proxy patterns, bot behavior, fraud velocity, and reconnaissance. |
| Performance | Measures latency, throughput, error rate, false positives, memory-related scoring, and graceful degradation. |
| Resilience | Exercises HTTP flood, slow request patterns, backend outage handling, and fail-mode semantics. |
| Extensibility | Verifies hot-reload and route-tier cache correctness. |
| Risk Lifecycle | Validates persistent risk scoring, device carry-over, canary behavior, decay, and recovery. |
| Observability | Captures WAF decision evidence through headers and report artifacts. |

## Repository Layout

```text
benchmark/
├── cmd/
│   ├── waf-benchmark/             # Main all-phase CLI runner
│   ├── waf-benchmark-phase-a/     # Standalone Phase A runner/prototype
│   ├── waf-benchmark-phase-d/     # Standalone Phase D runner/prototype
│   ├── waf-benchmark-phase-e/     # Standalone Phase E runner/prototype
│   ├── simple-test/               # Small smoke-test utility
│   └── enhanced-test/             # Enhanced smoke-test utility
├── internal/
│   ├── config/                    # YAML config loading and validation
│   ├── httpclient/                # Bound-source-IP HTTP clients and browser profiles
│   ├── logger/                    # Structured benchmark logging
│   ├── orchestrator/              # Benchmark runner, health checks, phase orchestration
│   ├── phases/                    # Phase A/B/C/D/E and risk lifecycle implementations
│   ├── report/                    # JSON and HTML report generation
│   ├── scoring/                   # Score calculator and scoring matrix logic
│   ├── target/                    # Target app control/auth/capabilities client
│   └── waf/                       # WAF client, headers, markers, decision parsing
├── exploits/                      # Payload corpus by vulnerability class
├── docs/                          # Benchmark specifications and workflow notes
├── shared/                        # Shared intelligence lists and runtime data
├── testdata/                      # Test fixtures and app capability fixtures
├── benchmark_config.yaml          # Default local benchmark profile
├── live_http_no_waf.yaml          # Example HTTP live profile
├── live_https_waf.yaml            # Example HTTPS live profile
├── Makefile                       # Build/test/development tasks
├── Dockerfile                     # Container image definition
├── go.mod
└── go.sum
```

## Architecture

The benchmark runner has five main layers:

1. **CLI Layer**
   - Parses flags, selects phases, applies address overrides, configures output format, and starts the runner.
   - Main command: `cmd/waf-benchmark/main.go`.

2. **Configuration Layer**
   - Loads YAML profile files.
   - Supports `http` and `https` schemes for both target and WAF.
   - Provides defaults for local testing.

3. **Orchestration Layer**
   - Runs pre-flight health checks.
   - Initializes target, WAF, auth, control, and HTTP client components.
   - Runs selected phases in order.
   - Saves partial results on interruption.

4. **Phase Engines**
   - Each phase owns its own test workflow, request patterns, pass/fail decisions, and phase-level metrics.

5. **Scoring and Reporting Layer**
   - Converts phase results into a scoring report.
   - Emits JSON and optional HTML reports in the output directory.

## Prerequisites

### Required

- Go 1.21 or newer.
- Linux is recommended, especially for source-IP binding tests using `127.0.0.0/8`.
- A target application that implements the WAF Hackathon target contract.
- A WAF under test that proxies traffic to the target application.

### Expected Target App Capabilities

The target app should expose control endpoints used by the benchmark, including:

```text
GET  /__control/health
POST /__control/reset
GET  /__control/capabilities
```

The configured control secret must match the target app control plane.

Default secret:

```text
waf-hackathon-2026-ctrl
```

### Expected WAF Behavior

The WAF should:

- Listen on the configured WAF host/port.
- Forward traffic to the configured target application.
- Return stable HTTP responses under concurrent load.
- Preferably expose observability headers such as:
  - `X-WAF-Request-Id`
  - `X-WAF-Action`
  - `X-WAF-Rule-Id`
  - `X-WAF-Risk-Score`
  - `X-WAF-Cache`

## Quick Start

### 1. Clone and build

For a new server or clean installation, the only hard prerequisite is Go 1.21 or newer. The build will fail on older toolchains because this repository uses APIs such as `os.ReadFile` and dependencies that require Go 1.18+ and Go 1.21+.

Verify the toolchain first:

```bash
go version
```

Expected output should be at least `go1.21.x`, for example `go version go1.24.2 linux/amd64`.

Then clone and build:

```bash
git clone https://github.com/zyren-sec/hackathon-benchmark.git
cd hackathon-benchmark
make deps
make build
```

If Go is too old, `make deps` and `make build` now fail fast with a clear version error instead of surfacing confusing compiler errors from dependencies.

If you do not want to install Go locally, build with Docker instead:

```bash
git clone https://github.com/zyren-sec/hackathon-benchmark.git
cd hackathon-benchmark
docker build -t waf-benchmark .
```

If you are reusing an old clone and want to rebuild from a clean state:

```bash
cd /opt/hackathon-benchmark
git fetch origin main
git reset --hard origin/main
git clean -fd
go clean -modcache
make deps
make build
```

The errors below are a strong signal that the machine is using an outdated Go toolchain and must be upgraded before building:

- `note: module requires Go 1.18`
- `note: module requires Go 1.21`
- `undefined: os.ReadFile`
- `undefined: context.WithCancelCause`

> Note: the current module path in `go.mod` remains `github.com/waf-hackathon/benchmark`. That does not prevent builds from `https://github.com/zyren-sec/hackathon-benchmark`, because the import path inside the module can differ from the Git remote URL.

The binary will be created at:

```text
./bin/waf-benchmark
```

You can also build directly:

```bash
mkdir -p ./bin
go build -o ./bin/waf-benchmark ./cmd/waf-benchmark
```

### 2. Optional: build standalone utilities

The main benchmark runner is `waf-benchmark`, but this repository also contains standalone phase and smoke-test commands:

```bash
go build -o ./bin/waf-benchmark-phase-d ./cmd/waf-benchmark-phase-d
go build -o ./bin/waf-benchmark-phase-e ./cmd/waf-benchmark-phase-e
go build -o ./bin/simple-test ./cmd/simple-test
```

`cmd/enhanced-test/` is an experimental utility. If `go test ./...` reports a build-format issue in that package, validate the main CLI and stable standalone tools with targeted `go build` commands instead.

### 3. Start the target app and WAF

Default local topology:

```text
Benchmark Tool -> WAF 127.0.0.1:8080 -> Target App 127.0.0.1:9000
```

Default config file:

```text
benchmark_config.yaml
```

### 4. Run health checks

```bash
./bin/waf-benchmark health -c benchmark_config.yaml
```

### 5. List available phases

```bash
./bin/waf-benchmark phases
```

### 6. Run a focused benchmark

Run only exploit-prevention tests:

```bash
./bin/waf-benchmark -c benchmark_config.yaml -p a --html -o ./reports
```

Run all phases:

```bash
./bin/waf-benchmark -c benchmark_config.yaml -p all --html -o ./reports
```

## Configuration

The default configuration is `benchmark_config.yaml`:

```yaml
benchmark:
  version: "2.1"

  target_app:
    scheme: "http"
    host: "127.0.0.1"
    port: 9000
    control_secret: "waf-hackathon-2026-ctrl"

  waf:
    scheme: "http"
    host: "127.0.0.1"
    port: 8080
    binary_path: "./waf"
    config_path: "./waf.yaml"
    audit_log_path: "./waf_audit.log"

  phases:
    phase_a:
      reset_before_each: true
      timeout_per_test_ms: 5000

    phase_b:
      ip_ranges:
        brute_force: "127.0.0.10-19"
        relay: "127.0.0.20-39"
        behavioral: "127.0.0.40-59"
        fraud: "127.0.0.60-79"
        recon: "127.0.0.80-99"

    phase_c:
      duration_per_step_seconds: 30
      target_rps_steps: [1000, 3000, 5000, 10000]

    phase_d:
      ddos_duration_seconds: 60
      slowloris_connections: 500

  scoring:
    security_effectiveness: 40
    performance: 20
    intelligence: 20
    extensibility: 10
    architecture: 15
    dashboard: 10
    deployment: 5

  thresholds:
    p99_latency_ms: 5
    max_memory_mb: 100
    false_positive_rate_max: 0.01
```

### Address Overrides

You can override addresses without editing YAML:

```bash
./bin/waf-benchmark \
  --target-host 127.0.0.1 \
  --target-port 9000 \
  --waf-host 127.0.0.1 \
  --waf-port 8080 \
  -p a,b \
  --html
```

### HTTPS Profile

Use `live_https_waf.yaml` as a template for HTTPS WAF deployments:

```bash
./bin/waf-benchmark -c live_https_waf.yaml -p a,e --html -o ./reports/live-https
```

### HTTP Profile

Use `live_http_no_waf.yaml` as a template for direct HTTP/live-environment validation:

```bash
./bin/waf-benchmark -c live_http_no_waf.yaml -p a --html -o ./reports/live-http
```

## CLI Usage

```text
waf-benchmark [flags]
waf-benchmark [command]
```

### Commands

| Command | Description |
|---|---|
| `health` | Run pre-flight checks only. |
| `phases` | List available benchmark phases. |
| `version` | Print tool version, commit, protocol version, and supported phases. |
| `help` | Show help for any command. |

### Main Flags

| Flag | Default | Description |
|---|---:|---|
| `-c, --config` | `benchmark_config.yaml` | Path to benchmark YAML config. |
| `-o, --output` | `./reports` | Output directory for reports. |
| `--json` | `true` | Generate JSON report. |
| `--html` | `false` | Generate HTML report. |
| `--waf-binary` | empty | Override WAF binary path metadata. |
| `--waf-config` | empty | Override WAF config path metadata. |
| `--target-host` | empty | Override target host. |
| `--target-port` | `0` | Override target port. |
| `--waf-host` | empty | Override WAF host. |
| `--waf-port` | `0` | Override WAF port. |
| `--control-secret` | empty | Override target control secret. |
| `-p, --phases` | `all` | Phases to run: `a,b,c,d,e,risk,all`. |
| `--skip-reset` | `false` | Skip target reset between phases. |
| `--skip-health` | `false` | Skip pre-flight health checks. |
| `--timeout` | none | Global timeout, e.g. `30m`. |
| `-v, --verbose` | `false` | Enable verbose output. |
| `--debug` | `false` | Enable very verbose debug logging. |

### Examples

Run all phases with HTML report:

```bash
./bin/waf-benchmark -c benchmark_config.yaml -p all --html -o ./reports/full
```

Run Phase A only:

```bash
./bin/waf-benchmark -p a --html -o ./reports/phase-a
```

Run Phase B and risk lifecycle with debug logs:

```bash
./bin/waf-benchmark -p b,risk --debug -o ./reports/abuse-risk
```

Run with a timeout:

```bash
./bin/waf-benchmark -p all --timeout 45m --html
```

Run against a remote WAF:

```bash
./bin/waf-benchmark \
  -c benchmark_config.yaml \
  --target-host target.example.com \
  --target-port 9000 \
  --waf-host waf.example.com \
  --waf-port 443 \
  -p a,b,e \
  --html
```

## Benchmark Phases

### Phase A — Exploit Prevention

Phase A validates whether the WAF detects, blocks, sanitizes, or safely handles common web vulnerabilities.

Coverage includes:

- SQL Injection.
- Cross-Site Scripting.
- Path Traversal.
- Local File Inclusion.
- Remote File Inclusion.
- Server-Side Request Forgery.
- Command Injection.
- NoSQL Injection.
- LDAP Injection.
- XPath Injection.
- XML External Entity attacks.
- Server-side template injection.
- Outbound data leakage checks.

Payloads are stored under `exploits/` by attack class.

### Phase B — Abuse Detection

Phase B tests abuse and bot-defense logic beyond single-request exploit blocking.

Coverage includes:

- Brute force.
- Credential stuffing.
- Password spraying.
- Header spoofing and proxy chain abuse.
- Datacenter/Tor/relay behavior.
- Bot-like timing and missing-browser-context patterns.
- Transaction velocity anomalies.
- Reconnaissance and fuzzing patterns.

This phase uses configurable loopback source IP ranges such as `127.0.0.10-99` to emulate multiple identities and traffic origins.

### Phase C — Performance

Phase C measures WAF behavior under increasing load.

Metrics include:

- Peak RPS.
- Sustained RPS.
- p99 latency.
- Error rate.
- False-positive rate under clean traffic.
- Latency/throughput/memory/graceful-degradation scoring.

Default load steps:

```text
1000, 3000, 5000, 10000 RPS
```

The built-in mixed traffic model is intentionally adversarial but not purely malicious: roughly 70% legitimate requests, 10% suspicious-but-legitimate requests, 10% exploit payloads, and 10% abuse-pattern traffic. This helps measure false positives, security effectiveness, and graceful degradation in one run.

### Phase D — Resilience

Phase D exercises WAF behavior under operational stress and failure conditions.

Coverage includes:

- `D01` HTTP flood handling.
- `D02` Slowloris-style slow headers.
- `D03` Slow POST/RUDY-style behavior.
- `D04` WAF-targeted flood behavior.
- `D05` backend down behavior.
- `D06` backend slow behavior.
- `D07` backend recovery behavior.
- `D08` fail-mode configuration change.
- `D09` fail-mode restoration.

Standalone Phase D code also exists under `cmd/waf-benchmark-phase-d/` for focused development and experimentation.

### Phase E — Extensibility

Phase E focuses on WAF configurability and cache correctness.

Coverage includes:

- Hot-reload behavior.
- Rule add/remove propagation.
- `E01` static asset caching for MEDIUM/cacheable routes.
- `E02` CRITICAL route no-cache enforcement.
- `E03` TTL expiry correctness.
- `E04` authenticated/dynamic route no-cache enforcement.

Phase E scoring is split into hot-reload behavior and caching correctness. The dedicated cache workflow also records tie-break metrics such as cache efficiency, safety, determinism, and resource behavior when available. The cache correctness workflow is documented in `docs/workflow/phaseE.md`.

### Risk Lifecycle

The risk lifecycle test verifies that the WAF can maintain and evolve risk state over time.

Typical steps include:

1. Clean baseline traffic should remain low risk.
2. Exploit attempts should raise risk.
3. Canary/honeypot hits should push risk to high severity.
4. Device identity should carry risk across network changes.
5. Risk should decay after clean behavior.
6. Recovery should be observable and deterministic.
7. Final decision should match configured thresholds.

## Scoring Model

The report generator produces a normalized scoring breakdown by phase.

Default score categories from the YAML profile:

| Category | Weight |
|---|---:|
| Security Effectiveness | 40 |
| Performance | 20 |
| Intelligence | 20 |
| Extensibility | 10 |
| Architecture | 15 |
| Dashboard | 10 |
| Deployment | 5 |

The automated scoring calculator combines phase scores into the 120-point category model. Architecture and Dashboard are judge/manual-review rubrics in the current implementation, so they are represented as report categories but are not fully auto-scored from traffic alone.

The internal report currently emits phase-oriented scores:

| Phase | Max Points |
|---|---:|
| Phase A | 20 |
| Phase B | 10 |
| Phase C | 20 |
| Phase D | 9 |
| Phase E | 10 |
| Risk Lifecycle | 8 |

Final scoring is written to the JSON and HTML reports.

## Reports

By default, benchmark output is written to `./reports`.

Common artifacts:

```text
reports/
├── benchmark_report.json
└── benchmark_report.html
```

The JSON report contains:

- Metadata.
- Overall summary.
- Grade and percentage.
- Per-phase scores.
- Phase-specific results.
- Observability data when available.

Example report metadata:

```json
{
  "metadata": {
    "version": "2.1",
    "tool_version": "2.1.0",
    "scoring_profile": "option_a_full_120",
    "scoring_profile_version": "scoring_matrix.csv@v2.1"
  }
}
```

Generate JSON and HTML:

```bash
./bin/waf-benchmark -p all --json --html -o ./reports
```

## HTTP Client and Traffic Model

The benchmark HTTP layer supports:

- Binding requests to specific loopback source IPs.
- Connection pooling.
- Browser-like header profiles.
- Helper functions for request normalization.
- Source-IP simulation for abuse scenarios.

Important implementation areas:

```text
internal/httpclient/bound_client.go
internal/httpclient/browser_profile.go
internal/httpclient/pool.go
```

For loopback identity simulation, Linux usually allows `127.0.0.0/8` by default. If your environment is restrictive, explicitly add addresses:

```bash
sudo ip addr add 127.0.0.10/8 dev lo
sudo ip addr add 127.0.0.20/8 dev lo
sudo ip addr add 127.0.0.30/8 dev lo
```

## Payload Corpus

Attack payloads are organized by vulnerability class:

```text
exploits/
├── command_injection/payloads.txt
├── ldap_injection/payloads.txt
├── lfi/payloads.txt
├── path_traversal/payloads.txt
├── rfi/payloads.txt
├── sqli/payloads.txt
├── ssrf/payloads.txt
├── template_injection/payloads.txt
├── xpath_injection/payloads.txt
├── xss/payloads.txt
└── xxe/payloads.txt
```

Use these payloads only against systems you own or are explicitly authorized to test.

## Live Profiles

This repository includes example live-environment profiles:

| File | Purpose |
|---|---|
| `live_http_no_waf.yaml` | HTTP profile template for direct/live baseline testing. |
| `live_https_waf.yaml` | HTTPS profile template for WAF-protected live testing. |

Before committing or sharing live profiles, remove secrets and environment-specific sensitive values.

## Standalone Tools

Besides the main `cmd/waf-benchmark/` runner, the repository includes focused utilities that are useful during development and demos.

### Standalone Phase D runner

```bash
go run ./cmd/waf-benchmark-phase-d \
  -config benchmark_config.yaml \
  -output ./reports/phase-d
```

Common artifacts:

```text
reports/phase-d/
├── phase_d_report.json
└── phase_d_report.html
```

Use `-no-html` or `-no-json` to disable a report format.

### Standalone Phase E runner

```bash
go run ./cmd/waf-benchmark-phase-e \
  -config benchmark_config.yaml \
  -output ./reports/phase-e
```

Common artifacts:

```text
reports/phase-e/
├── phase_e_caching_report.json
└── phase_e_caching_report.html
```

Use this when you only need cache correctness and hot-reload validation without running the full benchmark suite.

### Simple remote smoke test

```bash
go run ./cmd/simple-test http://sec-team.waf-exams.info
```

This utility runs a compact exploit-focused smoke test and writes standard benchmark-style reports under `./reports`.

### Enhanced remote smoke test

```bash
go run ./cmd/enhanced-test http://sec-team.waf-exams.info
```

This experimental utility runs a larger OWASP-style remote test suite. Treat it as a development helper rather than the canonical scoring runner.

## Required Runtime Data

The health checks and phase engines expect several repository data files to be present:

| Path | Purpose |
|---|---|
| `testdata/app_capabilities.json` | Target capability fixture used to decide which exploit/leak checks are applicable. |
| `shared/tor_exit_nodes.txt` | Abuse-intelligence fixture for Tor/relay simulation. |
| `shared/datacenter_asns.txt` | Abuse-intelligence fixture for datacenter/proxy simulation. |
| `exploits/*/payloads.txt` | Payload corpora used by Phase A and related smoke tests. |

Do not delete these files from the GitHub repository. If you replace them with environment-specific data, avoid committing secrets or private intelligence feeds.

## Development

### Make Targets

```bash
make help
```

Available targets:

| Target | Description |
|---|---|
| `make build` | Build `./bin/waf-benchmark`. |
| `make test` | Run all tests with race detector and coverage. |
| `make test-short` | Run short tests. |
| `make clean` | Remove build artifacts, reports, and Go cache. |
| `make install` | Copy binary to Go bin path when possible. |
| `make deps` | Download and verify dependencies. |
| `make tidy` | Run `go mod tidy`. |
| `make fmt` | Format Go files. |
| `make lint` | Run `golangci-lint` if installed. |
| `make run` | Build and run with default config. |
| `make docker-build` | Build Docker image. |
| `make docker-run` | Run Docker container with reports mounted. |
| `make coverage` | Generate HTML coverage report. |

### Run Tests

```bash
make test-short
make test
```

Or directly:

```bash
go test ./...
go test -race ./...
```

If you only need to validate the stable release path before publishing the repository, run targeted builds:

```bash
go build -o /tmp/waf-benchmark-check ./cmd/waf-benchmark
go build -o /tmp/waf-benchmark-phase-d-check ./cmd/waf-benchmark-phase-d
go build -o /tmp/waf-benchmark-phase-e-check ./cmd/waf-benchmark-phase-e
go build -o /tmp/simple-test-check ./cmd/simple-test
```

### Format

```bash
make fmt
```

### Build Docker Image

```bash
make docker-build
```

Run container:

```bash
make docker-run
```

## Troubleshooting

### Health check fails: target app not responding

Verify the configured target address:

```bash
curl -i http://127.0.0.1:9000/__control/health
```

Then check:

- `benchmark.target_app.scheme`
- `benchmark.target_app.host`
- `benchmark.target_app.port`
- `benchmark.target_app.control_secret`

### Health check fails: WAF not responding

Verify the configured WAF address:

```bash
curl -i http://127.0.0.1:8080/health
```

If your WAF does not expose `/health`, ensure it still returns a valid HTTP response for the benchmark health probe expected by your implementation.

### Cannot bind source IP

If Phase B or health checks report source-IP bind failures, add loopback aliases or run on Linux with `127.0.0.0/8` enabled:

```bash
sudo ip addr add 127.0.0.10/8 dev lo
```

### Reports are missing

Ensure the process can write to the output directory:

```bash
mkdir -p ./reports
./bin/waf-benchmark -p a --html -o ./reports
```

### Remote HTTPS test fails

Check that the profile uses `scheme: "https"` and the right port:

```yaml
target_app:
  scheme: "https"
  port: 443

waf:
  scheme: "https"
  port: 443
```

### Phase C results look worse than expected

Benchmark from a stable network location and avoid testing a public domain from the same host if it hairpins through external routing. For local WAF throughput tests, prefer local address plus the expected `Host` header.

Example:

```bash
wrk -t10 -c100 -d30s -H 'Host: waf.example.com' http://127.0.0.1/
```

## Security and Ethics

This tool sends exploit payloads, abuse simulations, and load traffic. Only run it against systems you own or have explicit written authorization to test.

Recommended safety practices:

- Do not run destructive phases against production without a maintenance window.
- Use isolated lab environments for exploit and DDoS-style tests.
- Keep control secrets private.
- Review generated logs before publishing reports.
- Do not commit target-specific secrets, tokens, cookies, or private IP intelligence files.

## License

Add your project license here before publishing the repository.

## Acknowledgements

This benchmark is based on the WAF Hackathon v2.1 evaluation model and includes security, performance, resilience, and extensibility workflows intended to help teams build stronger and more observable WAFs.
