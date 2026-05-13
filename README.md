# WAF Benchmark Tool

**Version:** 2.9.0 | **Go:** 1.21+

Automated WAF (Web Application Firewall) evaluation framework covering exploit prevention, abuse detection, performance, resilience, extensibility, and risk score lifecycle.

## Table of Contents

- [Requirements](#requirements)
- [Build Instructions](#build-instructions)
- [Usage Guide](#usage-guide)
  - [CLI Flags](#cli-flags)
  - [Running by Phase](#running-by-phase)
  - [Running with Make](#running-with-make)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Report Output](#report-output)

---

## Requirements

### Software & Environment

| Dependency | Version / Notes |
|---|---|
| **Go** | `1.21+` — tool is written in Go |
| **OS** | Linux (kernel tuning scripts target `sysctl`) |
| **Target App (UPSTREAM)** | HTTP service running on a reachable host/port |
| **WAF-PROXY** | The WAF proxy binary under test (must be pre-deployed) |
| **WAF-FE Dashboard** | Optional; can be disabled via config |
| **sudo** | Required for kernel tuning scripts (Phase C/D) |

### Go Dependencies

No external packages need to be installed manually — `go mod` handles everything at build time.

```
github.com/spf13/cobra v1.8.0
gopkg.in/yaml.v3 v3.0.1
```

### Optional: Kernel Tuning (Phase C & D)

Before running Phase C or D, run the kernel tuning script to ensure accurate network measurement:

```bash
sudo ./scripts/tune-kernel.sh [min|mid|full]
# Defaults to "mid" if no tier is specified
# Reads WAF_RESOURCE_TIER env var as fallback
```

Resource tiers:
- `min` — 2 CPU cores / 4 GB RAM
- `mid` — 4 CPU cores / 8 GB RAM (default)
- `full` — 6 CPU cores / 12 GB RAM

---

## Build Instructions

### 1. Clone / Navigate to the Project

```bash
cd /var/www/WAF-BENCHMARK-NEW
```

### 2. Build the Binary

**Using Go directly:**
```bash
go build -ldflags="-s -w" -o waf-benchmark .
```

**Using Make:**
```bash
make build
```

Both commands produce the `waf-benchmark` binary in the project root.

### 3. Verify the Build

```bash
./waf-benchmark version
# Output: WAF Benchmark Tool v2.9.0 (commit: phase-e-v2.5)
```

### 4. (Optional) Run Unit Tests

```bash
make test
# or: go test ./...
```

---

## Usage Guide

### CLI Flags

| Flag | Short | Default | Description |
|---|---|---|---|
| `--config` | - | auto-detect `benchmark_config.yaml` | Path to config file |
| `--phase` | `-p` | `a` | Phase to run: `a`, `b`, `c`, `d`, `e`, `r` |
| `--payload-tier` | - | `all` | Payload tier for Phase A: `basic`, `advanced`, `bypass`, `all` |
| `--output` / `-o` | - | (required) | Output directory for reports |
| `--target-host` | - | (from config) | UPSTREAM target host (overrides config) |
| `--target-port` | - | (from config) | UPSTREAM target port (overrides config) |
| `--waf-host` | - | (from config) | WAF proxy host (overrides config) |
| `--waf-port` | - | (from config) | WAF proxy port (overrides config) |
| `--waf-admin-port` | - | (from config) | WAF admin API port (overrides config) |
| `--verbose` | `-v` | `false` | Verbose output |
| `--dry-run` | - | `false` | Simulate results without connecting to endpoints |
| `--help` | `-h` | - | Show help |

### Running by Phase

**Phase A — Exploit Prevention:**
```bash
./waf-benchmark -p a --payload-tier all -o ./reports/phase_a

# Tier-specific runs
./waf-benchmark -p a --payload-tier basic   -o ./reports/phase_a
./waf-benchmark -p a --payload-tier advanced -o ./reports/phase_a
./waf-benchmark -p a --payload-tier bypass   -o ./reports/phase_a
```

**Phase B — Abuse Detection:**
```bash
./waf-benchmark -p b -o ./reports/phase_b
```

**Phase C — Performance & Throughput:**
```bash
# Ensure kernel is tuned first
sudo ./scripts/tune-kernel.sh mid

./waf-benchmark -p c -o ./reports/phase_c
./waf-benchmark -p c --dry-run -o ./reports/phase_c   # dry run
```

**Phase D — Resilience & Degradation:**
```bash
sudo ./scripts/tune-kernel.sh mid

./waf-benchmark -p d -o ./reports/phase_d
./waf-benchmark -p d --dry-run -o ./reports/phase_d    # dry run
```

**Phase E — Extensibility (EXT-03 automated caching, EXT-01/02 manual):**
```bash
./waf-benchmark -p e -o ./reports/phase_e
./waf-benchmark -p e --dry-run -o ./reports/phase_e   # dry run
```

**Phase R — Risk Score Lifecycle (SEC-05):**
> ⚠️ Phase R must be run **last**, after all other phases.
```bash
./waf-benchmark -p r -o ./reports/phase_r
./waf-benchmark -p r --dry-run -o ./reports/phase_r   # dry run
```

### Running with Make

The [`Makefile`](WAF-BENCHMARK-NEW/Makefile) provides convenience targets:

```bash
make build                  # Build the binary

# Phase A variants
make run-phase-a-basic
make run-phase-a-advanced
make run-phase-a-bypass
make run-phase-a-all

make run-phase-b          # Phase B
make run-phase-c          # Phase C
make run-phase-c-dry     # Phase C (dry run)
make run-phase-e          # Phase E
make run-phase-e-dry     # Phase E (dry run)

make test                 # Run unit tests
make clean               # Remove binary and reports/
```

### Custom Configuration

Point to a non-default config file with `--config`:

```bash
./waf-benchmark --config /path/to/custom_config.yaml -p a -o ./reports/phase_a
```

Override individual endpoints via CLI flags:

```bash
./waf-benchmark -p b \
  --waf-host 192.168.1.100 \
  --waf-port 8080 \
  --target-host 192.168.1.101 \
  --target-port 9000 \
  -o ./reports/phase_b
```

---

## Configuration

The tool auto-detects [`benchmark_config.yaml`](WAF-BENCHMARK-NEW/benchmark_config.yaml) in the current working directory. The file defines:

```yaml
benchmark:
  version: "2.1"

  target_app:
    scheme: "http"
    host: "220.158.233.101"
    port: 9000
    control_secret: "waf-hackathon-2026-ctrl"

  waf:
    scheme: "http"
    host: "220.158.233.101"
    port: 8080
    admin_port: 8081
    metrics_port: 6190
    binary_path: "/var/www/WAF-PROXY/target/release/waf"
    config_path: "/var/www/WAF-PROXY/waf.yaml"
    audit_log_path: "/var/www/WAF-PROXY/waf_audit.log"

  waf_fe:
    host: "220.158.233.101"
    port: 3000
    enabled: true
    skip_if_unavailable: true

  resource_tier: "mid"    # min | mid | full

  proxy_pool_path: "/var/www/docs/hackathon/proxy_ip.md"
```

Configuration precedence (highest to lowest):
1. CLI flags
2. YAML config file
3. Built-in defaults

---

## Architecture

The tool is structured around independent **phases**, each implemented as a self-contained package under [`internal/`](WAF-BENCHMARK-NEW/internal):

| Phase | Package | Purpose |
|---|---|---|
| **Phase A** | `internal/phasea` | Exploit prevention — validates WAF blocks attack payloads |
| **Phase B** | `internal/phaseb` | Abuse detection — tests WAF's abuse/anti-bot capabilities |
| **Phase C** | `internal/phasec` | Performance & throughput — measures RPS, latency under load |
| **Phase D** | `internal/phased` | Resilience & degradation — tests behavior under stress/attack |
| **Phase E** | `internal/phasee` | Extensibility — automated caching tests (EXT-03) |
| **Phase R** | `internal/phaser` | Risk score lifecycle — SEC-05 risk score management |
| **Cross-phase** | `internal/crossphase` | Shared context pooling and cross-phase reporting |
| **Challenge** | `internal/challenge` | Challenge detection, parsing, and display |

**Payload sources** are organized under [`exploits/`](WAF-BENCHMARK-NEW/exploits):
- `xss/`, `sqli/`, `lfi/`, `rfi/`, `ssrf/`, `xxe/`
- `command_injection/`, `path_traversal/`, `header_injection/`
- `ldap_injection/`, `nosql/`, `template_injection/`, `xpath_injection/`

---

## Report Output

Each phase writes output to the specified `--output` directory:

```
<output_dir>/
├── report_phase_<x>.html    # Human-readable HTML report
├── report_phase_<x>.json    # Machine-readable JSON report
├── report_cross_phase.json  # Cross-phase consistency report
└── (phase-specific files)
```

Example:
```
./reports/phase_a/
├── report_phase_a.html
├── report_phase_a.json
└── report_cross_phase.json
```

---

## Quick Reference

```bash
# Full build + run Phase A
make build
./waf-benchmark -p a --payload-tier all -o ./reports/phase_a

# Run all phases sequentially (manual)
for phase in a b c d e; do
  ./waf-benchmark -p $phase -o ./reports/phase_$phase
done
./waf-benchmark -p r -o ./reports/phase_r   # run LAST

# Check version
./waf-benchmark version