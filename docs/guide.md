# WAF Benchmark Guide

This guide covers how to build and run the benchmark tools, including Phase A payload modes (`simple`, `advanced`, `all`).

## 1) Build tools

Run from project root: `benchmark/`

### Build main benchmark CLI

```bash
cd /var/www/benchmark
make build
```

Binary output:

- `./bin/waf-benchmark`

### Build Phase A authoritative runner

```bash
cd /var/www/benchmark/cmd/waf-benchmark-phase-a
go build -o ./waf-benchmark-phase-a .
```

Binary output:

- `./waf-benchmark-phase-a`

## 2) Run tool for a single phase

Use the main CLI (`waf-benchmark`) and select phase with `-p` / `--phases`.

### Example: run only Phase A

```bash
cd /var/www/benchmark
./bin/waf-benchmark -c benchmark_config.yaml -p a --json --html -o ./reports
```

### Other single-phase examples

```bash
# Phase B
./bin/waf-benchmark -c benchmark_config.yaml -p b --json -o ./reports

# Risk lifecycle only
./bin/waf-benchmark -c benchmark_config.yaml -p risk --json -o ./reports
```

## 3) Run tool for all phases

Run all phases (`a,b,c,d,e,risk`) using `all`:

```bash
cd /var/www/benchmark
./bin/waf-benchmark -c benchmark_config.yaml -p all --json --html -o ./reports
```

Generated reports:

- `./reports/benchmark_report.json` (when `--json=true`)
- `./reports/benchmark_report.html` (when `--html=true`)

---

## Phase A payload mode (`--payload simple|advanced|all`)

Phase A payload flag belongs to the authoritative runner in `cmd/waf-benchmark-phase-a`.

### Common command template

```bash
cd /var/www/benchmark
go run ./cmd/waf-benchmark-phase-a \
  -target-profile external \
  -payload all \
  -output ./reports/phase-a \
  -no-html=false \
  -no-json=false
```

### Run only simple payload set

```bash
cd /var/www/benchmark
go run ./cmd/waf-benchmark-phase-a \
  -target-profile external \
  -payload simple \
  -output ./reports/phase-a-simple
```

### Run only advanced payload set

```bash
cd /var/www/benchmark
go run ./cmd/waf-benchmark-phase-a \
  -target-profile external \
  -payload advanced \
  -output ./reports/phase-a-advanced
```

### Run full payload set (simple + advanced)

```bash
cd /var/www/benchmark
go run ./cmd/waf-benchmark-phase-a \
  -target-profile external \
  -payload all \
  -output ./reports/phase-a-all
```

### Optional target override

If you want to directly set a target URL (instead of profile resolution):

```bash
go run ./cmd/waf-benchmark-phase-a \
  -target http://127.0.0.1:8080 \
  -payload all \
  -output ./reports/phase-a-direct
```

### Phase A outputs

By default, Phase A writes:

- `phase_a_report.json` (unless `-no-json=true`)
- `phase_a_report.html` (unless `-no-html=true`)

inside the directory passed to `-output`.

---

## Phase D dedicated runner (`cmd/waf-benchmark-phase-d`)

Phase D has a dedicated CLI runner with detailed D01–D09 evidence and post-pass quality/tie-break metrics.

### Build Phase D runner

```bash
cd /var/www/benchmark/cmd/waf-benchmark-phase-d
go build -o ./waf-benchmark-phase-d .
```

Binary output:

- `./waf-benchmark-phase-d`

### Common command template

```bash
cd /var/www/benchmark
go run ./cmd/waf-benchmark-phase-d \
  -config ./benchmark_config.yaml \
  -output ./reports/phase-d \
  -no-html=false \
  -no-json=false
```

### Run with live no-WAF config

```bash
cd /var/www/benchmark
go run ./cmd/waf-benchmark-phase-d \
  -config ./live_http_no_waf.yaml \
  -output ./cmd/waf-benchmark-phase-d/reports/live-http
```

### Run with live WAF config

```bash
cd /var/www/benchmark
go run ./cmd/waf-benchmark-phase-d \
  -config ./live_https_waf.yaml \
  -output ./cmd/waf-benchmark-phase-d/reports/live-https
```

### Output control flags

- Disable HTML generation: `-no-html=true`
- Disable JSON generation: `-no-json=true`

### Phase D outputs

By default, Phase D writes:

- `phase_d_report.json` (unless `-no-json=true`)
- `phase_d_report.html` (unless `-no-html=true`)

inside the directory passed to `-output`.

### Exit code behavior

- Exit `0`: Phase D pass
- Exit `1`: Phase D executed but final verdict is fail
- Exit `2+`: execution/runtime failure (config/load/report errors)
