# WAF Benchmark Tool v2.1

Automated Security Validation Framework for WAF Evaluation

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

The WAF Benchmark Tool is a comprehensive testing framework designed to evaluate Web Application Firewalls (WAFs) across multiple dimensions:

- **Security Effectiveness**: Exploit prevention, abuse detection, risk lifecycle
- **Performance**: Latency, throughput, resource usage under load
- **Resilience**: DDoS protection, backend failure handling, fail-mode behavior
- **Extensibility**: Hot-reload, caching, configuration management

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Benchmark Phases](#benchmark-phases)
- [Scoring](#scoring)
- [Reports](#reports)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Installation

### Prerequisites

- Go 1.21 or later
- Linux environment (for IP binding to 127.0.0.0/8)
- Target vulnerable application running on port 9000
- WAF under test running on port 8080

### From Source

```bash
# Clone the repository
git clone https://github.com/waf-hackathon/benchmark.git
cd benchmark

# Build the binary
go build -o waf-benchmark ./cmd/waf-benchmark/

# Or use make
make build
```

### Docker

```bash
# Build Docker image
make docker-build

# Or manually
docker build -t waf-benchmark:latest .
```

## Quick Start

### 1. Setup Target Application

Ensure the target vulnerable app is running on port 9000:

```bash
# Target app should expose control endpoints on :9000
# - GET /__control/health - Health check
# - POST /__control/reset - Reset state
# - GET /__control/capabilities - App capabilities
```

### 2. Setup WAF

Ensure the WAF is running and proxying to the target:

```bash
# WAF should listen on :8080 and forward to :9000
```

### 3. Configure Loopback Aliases

The benchmark uses multiple source IPs (127.0.0.10-99):

```bash
# Linux
sudo ip addr add 127.0.0.10/8 dev lo
# Or use the helper script
sudo ./scripts/setup-loopback.sh
```

### 4. Run Benchmark

```bash
# Run all phases
./waf-benchmark

# Run specific phases
./waf-benchmark -p a,b,c

# With custom config
./waf-benchmark -c myconfig.yaml --html -o ./reports
```

## Configuration

### Configuration File

Create `benchmark_config.yaml`:

```yaml
benchmark:
  version: "2.1"
  
  target_app:
    host: "127.0.0.1"
    port: 9000
    control_secret: "waf-hackathon-2026-ctrl"
  
  waf:
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
  
  thresholds:
    p99_latency_ms: 5
    max_memory_mb: 100
    false_positive_rate_max: 0.01
```

### Environment Variables

Override config values via environment:

```bash
export BENCHMARK_TARGET_HOST=127.0.0.1
export BENCHMARK_TARGET_PORT=9000
export BENCHMARK_WAF_HOST=127.0.0.1
export BENCHMARK_WAF_PORT=8080
```

## Usage

### Command Line Options

```
Usage:
  waf-benchmark [flags]
  waf-benchmark [command]

Available Commands:
  completion  Generate shell autocompletion
  health      Run pre-flight health checks
  help        Help about any command
  phases      List available phases
  version     Print version information

Flags:
  -c, --config string        Path to config file (default "benchmark_config.yaml")
  -o, --output string        Output directory for reports (default "./reports")
      --json                 Generate JSON report (default true)
      --html                 Generate HTML report
  -p, --phases strings       Phases to run: a,b,c,d,e,risk,all (default [all])
      --skip-reset           Skip target reset between phases
      --timeout duration     Global timeout (e.g., 30m)
  -v, --verbose              Enable verbose output
      --debug                Enable debug logging

  Override Flags:
      --target-host string   Override target host
      --target-port int      Override target port
      --waf-host string      Override WAF host
      --waf-port int         Override WAF port
      --waf-config string    Override WAF config path
```

### Examples

```bash
# Run all phases with default config
./waf-benchmark

# Run only Phase A (Exploit Prevention)
./waf-benchmark -p a

# Run phases A and B with verbose output
./waf-benchmark -p a,b -v

# Generate HTML report
./waf-benchmark --html -o ./reports

# Custom timeout (30 minutes)
./waf-benchmark --timeout 30m

# Override target and WAF addresses
./waf-benchmark --target-host 10.0.0.5 --target-port 8080 --waf-host 10.0.0.10

# Run health checks only
./waf-benchmark health

# List available phases
./waf-benchmark phases
```

## Benchmark Phases

### Phase A: Exploit Prevention (20 points)

Tests WAF ability to prevent common exploits:

- **V01-V24**: 24 vulnerability tests
  - SQL Injection (Classic, UNION, Blind)
  - XSS (Reflected, Stored)
  - Path Traversal
  - SSRF
  - Command Injection
  - NoSQL Injection
  - XML/XXE
  - Deserialization

- **L01-L05**: 5 outbound leak tests
  - Stack trace leakage
  - Internal IP exposure
  - Debug information
  - PII leakage
  - Verbose errors

### Phase B: Abuse Detection (10 points)

Tests WAF ability to detect and block abuse patterns:

- **AB01-AB03**: Brute force detection (login, credential stuffing, spraying)
- **AR01-AR06**: Relay detection (XFF spoofing, proxy chains, Tor, datacenter)
- **BA01-BA05**: Behavioral anomalies (bot timing, missing referers)
- **TF01-TF04**: Transaction fraud (velocity checks, multi-accounting)
- **RE01-RE04**: Reconnaissance detection (fuzzing, scanning)

### Phase C: Performance (20 points)

Tests WAF performance under load:

- Baseline latency measurement
- Load tests: 1000, 3000, 5000, 10000 RPS
- p99 latency scoring (≤5ms = 10 pts)
- Throughput scoring (≥5000 RPS = 5 pts)
- Memory usage (<100MB = 3 pts)
- Graceful degradation (<5% false positives = 2 pts)

### Phase D: Resilience (9 points)

Tests WAF resilience under attack:

- **D01**: HTTP Flood (50k req/s)
- **D02**: Slowloris (slow header attacks)
- **D03**: RUDY (slow POST attacks)
- **D04**: WAF-targeted flood with fail-mode tests
- **D05-D07**: Backend failure handling
- **D08-D09**: Fail-mode configurability

### Phase E: Extensibility (10 points)

Tests WAF configuration and caching:

- Hot-reload tests (add/remove rules within 10s)
- Caching tests (static assets, no caching for auth)

### Risk Lifecycle (8 points)

7-step test verifying risk scoring and device fingerprinting:

1. Baseline (legitimate requests, risk 0-10)
2. Exploit attempt (risk 40-70)
3. Canary hit (risk 100)
4. Device carry (risk 80-100 on new IP)
5. Risk decay (decreasing over time)
6. Anomaly detection (risk 30-70)
7. Challenge resolution (risk <30 after solving)

## Scoring

The WAF Benchmark uses a weighted scoring system with a maximum of 77 points:

| Category | Points | Criteria |
|----------|--------|----------|
| Exploit Prevention | 15 | Block rate × 15 |
| Outbound Filter | 5 | Filter rate × 5 |
| Abuse Detection | 10 | Detection rate × 10 |
| Performance - Latency | 10 | p99 ≤ 5ms |
| Performance - Throughput | 5 | Sustained 5000 RPS |
| Performance - Memory | 3 | < 100MB |
| Performance - Graceful | 2 | < 5% false positives |
| Resilience - DDoS | 4 | Pass D01-D04 |
| Resilience - Backend | 3 | Pass D05-D07 |
| Resilience - Fail Mode | 2 | Pass D08-D09 |
| Extensibility - Hot Reload | 6 | Add/remove rules |
| Extensibility - Caching | 4 | Cache behavior |
| Risk Lifecycle | 8 | 7 steps, step 7 worth 2pts |

### Grade Scale

| Grade | Percentage | Score Range |
|-------|------------|-------------|
| A+ | 95-100% | 73.2-77 |
| A | 90-94% | 69.3-73.1 |
| A- | 85-89% | 65.5-69.2 |
| B+ | 80-84% | 61.6-65.4 |
| B | 75-79% | 57.8-61.5 |
| B- | 70-74% | 53.9-57.7 |
| C+ | 65-69% | 50.1-53.8 |
| C | 60-64% | 46.2-50.0 |
| D | 50-59% | 38.5-46.1 |
| F | <50% | <38.5 |

## Reports

### JSON Report

```json
{
  "metadata": {
    "version": "2.1",
    "timestamp": "2026-04-21T10:30:00Z",
    "duration_ms": 300000
  },
  "summary": {
    "total_score": 65.5,
    "max_possible": 77.0,
    "percentage": 85.1,
    "grade": "A-"
  },
  "scores": {
    "phase_a": { "score": 18.0, "max": 20 },
    "phase_b": { "score": 8.5, "max": 10 },
    "phase_c": { "score": 17.0, "max": 20 },
    "phase_d": { "score": 7.0, "max": 9 },
    "phase_e": { "score": 9.0, "max": 10 },
    "risk_lifecycle": { "score": 6.0, "max": 8 }
  },
  "phase_results": {
    "phase_a": { ... },
    "phase_b": { ... },
    ...
  }
}
```

### HTML Report

Visual dashboard with:
- Overall score and grade
- Phase-by-phase breakdown
- Color-coded pass/fail status
- Interactive charts
- Detailed test results

## Troubleshooting

### Health Check Failures

**Target app not responding**
```
[FAIL] Target App Connectivity: target app not responding on 127.0.0.1:9000
```
- Verify target app is running
- Check firewall rules
- Verify control secret matches

**WAF not responding**
```
[FAIL] WAF Connectivity: WAF not responding on 127.0.0.1:8080
```
- Verify WAF is running
- Check WAF logs for errors
- Verify WAF can reach target

**Loopback aliases not configured**
```
[FAIL] Loopback Aliases: cannot bind to 127.0.0.10
```
- Run setup script: `sudo ./scripts/setup-loopback.sh`
- Or manually: `sudo ip addr add 127.0.0.10-99/8 dev lo`

### Phase Failures

**Phase A: Exploits bypassing WAF**
- Check WAF rules are loaded
- Verify WAF is proxying correctly
- Check for rule bypass techniques

**Phase C: Cannot sustain load**
- Increase system limits: `ulimit -n 65536`
- Check available memory
- Reduce concurrent connections

**Phase D: DDoS test fails**
- Verify WAF has DDoS protection enabled
- Check rate limiting configuration
- Verify backend health

### Performance Issues

**High memory usage**
- Reduce pool size in config
- Enable connection limits
- Profile with: `go tool pprof`

**Slow test execution**
- Enable verbose logging: `-v`
- Check network latency
- Verify target app performance

## Development

### Project Structure

```
benchmark/
├── cmd/waf-benchmark/      # CLI entry point
├── internal/
│   ├── config/             # Configuration management
│   ├── httpclient/         # HTTP client with IP binding
│   ├── logger/             # Structured logging
│   ├── orchestrator/       # Benchmark orchestration
│   ├── phases/             # Test phases (A, B, C, D, E, Risk)
│   ├── report/             # Report generation
│   ├── scoring/            # Score calculation
│   ├── target/             # Target app client
│   └── waf/                # WAF client and decision engine
├── shared/                 # Shared data files
├── testdata/              # Test fixtures
├── scripts/               # Helper scripts
├── Makefile              # Build automation
└── Dockerfile            # Container build
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test ./internal/phases/...

# Verbose output
go test -v ./...

# Race detection
go test -race ./...
```

### Adding New Tests

1. Define test in appropriate phase file
2. Add to phase runner
3. Update scoring matrix if needed
4. Add unit tests
5. Update documentation

### Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

## License

MIT License - see LICENSE file for details

## Acknowledgments

- Built for the WAF Hackathon 2026
- Inspired by industry-standard WAF testing methodologies
- Uses [fasthttp](https://github.com/valyala/fasthttp) for high-performance HTTP
- CLI powered by [Cobra](https://github.com/spf13/cobra)

## Support

For issues and questions:
- GitHub Issues: https://github.com/waf-hackathon/benchmark/issues
- Documentation: https://github.com/waf-hackathon/benchmark/docs

---

**Version**: 2.1  
**Last Updated**: 2026-04-21
