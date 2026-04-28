# WAF Benchmark Tool - Technical Specification (As-Built)

## 1. Document Purpose

This specification describes the **current implementation reality** of the benchmark tool in this repository, not an aspirational design. It is intended for engineers, evaluators, and AI systems that need an accurate execution model of how the tool works today.

Primary code authority for this document:

- CLI entrypoint and runtime flags
- Orchestrator lifecycle and phase scheduling
- Authoritative Phase A runner behavior
- Scoring and report generation pipeline

## 2. Scope and Source of Truth

The source of truth is the code under this repository. If this document and code diverge, code wins.

Current operational scope includes:

- Main CLI benchmark runner (phases: `a,b,c,d,e,risk,all`)
- Authoritative Phase A execution delegated to `cmd/waf-benchmark-phase-a`
- Phase B/C/D/E and Risk Lifecycle execution via internal phase packages
- Text summary + JSON/HTML reports generated at the orchestrator layer

## 3. Current Runtime Architecture

At runtime, execution follows this topology:

1. User executes the benchmark CLI.
2. CLI loads configuration and applies runtime overrides.
3. Orchestrator runs optional pre-flight checks.
4. Orchestrator initializes clients (target, control, auth, WAF, HTTP pool).
5. Orchestrator executes selected phases in order.
6. Scores are computed from collected phase results.
7. Reports are emitted (text + JSON/optional HTML).

### 3.1 Components

- **CLI layer**: command parsing, overrides, timeout context, report format selection.
- **Orchestrator layer**: health checks, initialization, phase sequencing, partial-result safety handling.
- **Phase engines**:
  - Phase A: authoritative external runner command (`cmd/waf-benchmark-phase-a`), then adapter mapping into orchestrator result shape.
  - Phase B/C/D/E/Risk: internal package execution.
- **Scoring layer**: builds a score report from all available phase results.
- **Reporting layer**: generates text, JSON, and optional HTML output.

## 4. End-to-End Workflow (Step by Step)

### Step 1 - CLI startup and flag resolution

The benchmark starts from the root CLI command. Core behaviors:

- Load config file (default: `benchmark_config.yaml`, fallback to defaults if file missing).
- Apply CLI overrides (target/WAF host/port, binary path, config path, control secret).
- Validate requested phases against allowed values.
- Ensure output directory exists.
- Apply optional global timeout context.

### Step 2 - Runner setup

The orchestrator runner is created and signal handling is installed.

- On interrupt/termination, partial results are saved to a timestamped JSON file.

### Step 3 - Optional health checks

Unless disabled via skip-health, pre-flight checks include:

1. Target app connectivity
2. WAF connectivity
3. Loopback alias bind capability for source-IP simulation
4. Required shared files availability
5. Target capabilities file availability

If any check fails, execution stops before phase execution.

### Step 4 - Initialization

Runner initializes core clients and state:

1. Target client
2. Control client
3. Auth helper
4. Target capabilities (fallback defaults if unavailable)
5. HTTP client pool
6. WAF client

### Step 5 - Phase list expansion and ordering

Phase input behavior:

- If phase list is exactly `all`, it expands to: `a,b,c,d,e,risk`.
- Unknown phase tokens are warned and skipped.
- Execution is sequential in the provided/expanded order.

### Step 6 - Execute each phase

#### 6.1 Phase A workflow (authoritative runner path)

This is the most important architecture decision in the current codebase.

1. Orchestrator resets target control state.
2. Orchestrator creates a temporary working directory.
3. Orchestrator determines `target-profile` (`internal` for localhost/127.*, else `external`).
4. Orchestrator executes:
   - `go run ./cmd/waf-benchmark-phase-a`
   - with target URL pointing at configured WAF host/port
   - payload mode forced to `all`
   - JSON output enabled (HTML disabled in this path)
5. Orchestrator reads generated `phase_a_report.json`.
6. Orchestrator parses authoritative results.
7. Orchestrator aggregates per-test pass/fail across mode runs.
8. Orchestrator maps aggregated data into legacy `PhaseAResult` structure used by scoring/reporting.

Consequently, the authoritative test semantics for Phase A now live in the dedicated command package, while the orchestrator acts as execution adapter and results bridge.

#### 6.2 Phase B workflow

1. Reset target.
2. Execute Phase B abuse tests through internal phase package.
3. Store result into orchestrator result set.
4. Mark phase complete.

#### 6.3 Phase C workflow

1. Execute performance tests (RPS/latency style workload path).
2. Capture metrics into `PhaseCResult`.
3. Mark phase complete.

#### 6.4 Phase D workflow

1. Reset target.
2. Execute resilience suite (DDoS/backend/fail-mode dimensions).
3. Persist results and mark complete.

#### 6.5 Phase E workflow

1. Execute hot-reload and caching tests.
2. Persist results and mark complete.

#### 6.6 Risk Lifecycle workflow

1. Instantiate lifecycle tester.
2. Execute risk lifecycle sequence.
3. Persist results and mark complete.

### Step 7 - Summary, scoring, and report generation

After phase execution:

1. Build score report from available phase detail structs.
2. Print text summary to console.
3. Generate report files based on selected output formats:
   - `benchmark_report.json` when JSON enabled
   - `benchmark_report.html` when HTML enabled

## 5. Phase A Authoritative Runner Workflow (Detailed)

The Phase A command package has its own internal lifecycle.

### 5.1 High-level execution sequence

1. Parse command flags (`target`, `target-profile`, `payload`, output format controls).
2. Resolve target URL/profile.
3. Resolve active payload mode set from payload flag.
4. Authenticate (login + OTP exchange for session where needed).
5. Execute tests in two major groups:
   - Non-auth-required definitions first
   - Auth-required definitions second
6. Within each group, execute by category.
7. For each category:
   - Build execution plan
   - Run each payload variant across active attack modes
   - Record detailed result per execution
   - Perform reset + health verify + re-auth lifecycle before moving on
8. Calculate summary and emit reports.

### 5.2 Payload mode semantics

- `simple` => `mode1_malformed_request_only`
- `advanced` => `mode2_smuggling`, `mode3_header_cannibalism`, `mode4_slow_post`, `mode5_chunked_variation`
- `all` => simple + advanced

### 5.3 Execution-model implication

A non-trivial operational trade-off exists in advanced mode:

- Slow-post mode intentionally throttles request body transmission in small chunks with sleeps.
- This can make progress appear "stuck" in later portions of category execution, while still functioning as designed.
- This behavior is bounded by timeout guards, so it is slow but not infinite.

### 5.4 Detection and verdict contract (current hardened behavior)

For each detailed test execution:

1. Capture response status, headers, body, and raw request/response artifacts.
2. Attempt marker detection using expected marker first, then valid fallback markers.
3. Enforce marker format contract via marker regex gate.
4. Record marker presence in both body and headers.
5. Evaluate status-code contract by test class.
6. Final verdict logic:
   - If marker found => fail
   - Else require status contract compliance to pass

This dynamic ensures both marker evidence and status behavior participate in decisioning, preventing optimistic pass outcomes that ignore contract violations.

## 6. Data and Configuration Contracts

### 6.1 Main config structure

Top-level config shape:

- `benchmark.version`
- `benchmark.target_app` (host, port, control secret)
- `benchmark.waf` (host, port, binary path, config path, audit log path)
- `benchmark.phases` (`phase_a`, `phase_b`, `phase_c`, `phase_d`)
- `benchmark.scoring`
- `benchmark.thresholds`

### 6.2 Phase selection contract

Valid phase values:

- `a`, `b`, `c`, `d`, `e`, `risk`, `all`

### 6.3 Output contract

Main benchmark outputs:

- `benchmark_report.json`
- `benchmark_report.html` (optional)

Phase A direct runner outputs:

- `phase_a_report.json`
- `phase_a_report.html` (optional)

## 7. Current CLI Surface (Main Benchmark)

Core flags in active use:

- Config and output:
  - `--config`, `--output`, `--json`, `--html`
- Environment overrides:
  - `--waf-binary`, `--waf-config`, `--target-host`, `--target-port`, `--waf-host`, `--waf-port`, `--control-secret`
- Execution control:
  - `--phases`, `--skip-reset`, `--skip-health`, `--timeout`
- Logging:
  - `--verbose`, `--debug`

Subcommands:

- `version`
- `health`
- `phases`

## 8. Build and Execution Overview

### 8.1 Main benchmark CLI

- Build via repository Makefile or direct Go build.
- Execute with selected phases and report format flags.

### 8.2 Phase A authoritative runner

- Can be run directly for focused security-effectiveness execution.
- Supports explicit payload-set control (`simple`, `advanced`, `all`).

## 9. Operational Notes and Known Characteristics

1. Phase A in orchestrator always uses authoritative command-runner path and currently forces payload mode `all`.
2. Category lifecycle in Phase A includes reset + health + re-auth after each category.
3. Interrupt safety is implemented through partial-results snapshots.
4. Reporting layer supports both machine-readable and dashboard-style outputs.

## 10. References

### 10.1 Related Documents

| Document | Purpose |
|----------|---------|
| `docs/exploit_catalogue.md` | Canonical exploit/leak catalog and test intent |
| `docs/guide.md` | Practical build/run guide for operators |
| `docs/openapi.yaml` | API contract reference used by benchmark context |
| `docs/VI_WAF_Interop_Contract_v2_1.md` | WAF decision and interoperability contract |
| `../docs/hackathon/VI_Benchmark_Specification_v2_1.md` | Competition-level benchmark specification |
| `../docs/hackathon/VI_Target_App_Contract_v2_1.md` | Target application contract |

### 10.2 Code Entry References

| Code Location | Role |
|---------------|------|
| `cmd/waf-benchmark/main.go` | Main CLI and global runtime controls |
| `internal/orchestrator/runner.go` | Runtime orchestration, phase control, reporting |
| `cmd/waf-benchmark-phase-a/main.go` | Authoritative Phase A command entrypoint |
| `cmd/waf-benchmark-phase-a/engine.go` | Phase A execution engine and verdict contract logic |
| `internal/report/generator.go` | Text/JSON/HTML report generation |
| `internal/config/config.go` | Config schema, defaults, validation |

### 10.3 Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.2 | 2026-04-22 | Rewritten in English to reflect as-built code reality; clarified end-to-end workflow; documented authoritative Phase A delegation and current report/config contracts |
| 1.1 | 2026-04-22 | Reverse-updated snapshot |
| 1.0 | 2026-04-21 | Initial specification draft |
