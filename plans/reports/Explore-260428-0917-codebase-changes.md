# Codebase Changes Scout Report
**Date:** 2026-04-28 | **Since:** 2026-04-23 (docs update) | **Commits:** ~50

## Overview
Four major changes: (1) SQLi modularization with 19 detection patterns and comprehensive testing, (2) E2E test suite infrastructure with 5 test runners, (3) waf-api build.rs placeholder for admin-panel isolation, (4) audit/CLI linting fixes.

---

## New/Changed Modules per Crate

### waf-engine (SQLi Enhancement Phase)
**New modules:**
- `src/checks/sql_injection_patterns.rs` (149 lines) — 19 compiled regex patterns with descriptions (SQLI-001..019)
  - Classic patterns (001-012): UNION, comments, stacked queries, time-based blind, xp_cmdshell, INFORMATION_SCHEMA, OR/AND tautologies, LOAD_FILE, INTO OUTFILE, hex-encoding, quote escapes, system tables
  - Blind/error-based (013-019): Numeric tautology, SUBSTRING/ASCII/LENGTH, IF(), @@version/@@datadir, CAST/CONVERT/DOUBLE overflow
- `src/checks/sql_injection_scanners.rs` (8 lines) — Scanner trait implementations, ReDoS mitigations

**Modified modules:**
- `src/checks/sql_injection.rs` — Refactored to <80-line API layer (was 800+ monolithic)
- `src/checks/owasp.rs` — Enhanced with new scanner/OWASP rule logic (+146 lines in e2e commit)
- `src/checks/scanner.rs` — Extended client blocking logic (+128 lines in e2e commit)

**Test infrastructure:**
- `tests/sql_injection_acceptance.rs` (621 lines) — 63 acceptance tests covering headers, query params, JSON bodies, URL decode edge cases
- `benches/sql_injection.rs` (192 lines) — Criterion benchmarks validating p99 < 500µs clean, < 1ms malicious payloads
- `benches/README.md` (63 lines) — Benchmark methodology and performance baselines

---

### waf-api (Build System)
**New files:**
- `build.rs` (60 lines) — Rust proc-macro isolation: creates placeholder `/web/admin-panel/dist/index.html` if missing
  - Prevents `cargo build/clippy/check` failures in CI/sandboxed environments where npm build hasn't run
  - Allows real production builds to skip placeholder (already present)

---

### waf-cluster (E2E test changes)
**Modified:**
- `src/lib.rs` — Cluster mode detection, sync logic refinements (+35 lines in e2e)
- `src/transport/client.rs` — Transport enhancements (+10 lines)
- `src/transport/server.rs` — Server-side improvements (+21 lines)

**Test suite:**
- `tests/` already contains 4 integration tests (cluster_integration, election_test, integration_test, peer_eviction_test) — no new files added

---

### waf-common (Configuration)
**Modified `src/config.rs`:**
- Added `SqliScanConfig` struct (17 lines):
  - `scan_headers: bool` — Enable/disable header scanning
  - `header_denylist: Vec<String>` — Excluded headers (content-length, content-type, host, connection, accept-encoding, cookie)
  - `header_allowlist: Vec<String>` — Whitelist override
  - `header_scan_cap: usize` — Max bytes/header (4096)
  - `json_parse_cap: usize` — Max bytes for JSON body (256 KB)

**Modified `src/types.rs`:**
- Added scanner rule enhancements (+14 lines in e2e commit)

---

## E2E Test Infrastructure (tests/e2e/)

**Test runners (5 shell scripts):**
1. `run-rules-engine.sh` (194 lines) — Validates OWASP CRS, bot detection, scanner detection rules
2. `run-gateway.sh` (123 lines) — Proxy behavior tests (SSL, auth, caching)
3. `run-api.sh` (129 lines) — Admin API endpoints (CRUD, auth)
4. `run-cluster.sh` (217 lines) — Cluster sync, node failover, election logic
5. `render-report.sh` (220 lines) — JUnit XML + JSON + Markdown aggregation for GitHub

**Infrastructure:**
- `lib.sh` (266 lines) — Shared assertions, JUnit/JSON writers, Docker container helpers
- `docker-compose.e2e.yml` (81 lines) — PostgreSQL + go-httpbin (httpbin upstream) + prx-waf stack
- `cluster-override.yml` (24 lines) — Cluster mode config for test runner
- `configs/e2e.toml` (49 lines) — WAF config (rules paths, API settings, httpbin upstream)
- `README.md` (54 lines) — Setup, running locally, GitHub artifact/Checks tab integration

**GitHub Actions:**
- `.github/workflows/nightly-e2e.yml` (369+ lines) — Scheduled nightly runs, per-test failure reporting via mikepenz/action-junit-report

---

## Build/Deployment Artifacts

1. **build.rs isolation** — Allows cargo in sand boxed/CI without full admin-panel build
2. **Docker layers** — Dockerfile.prebuilt copies pre-built prx-waf binary, expects `data/` + `web/admin-panel/dist/`
3. **E2E CI** — Nightly workflow publishes JUnit, JSON, HTML to artifact + Checks tab

---

## Audit/CLI Linting
- Commit 92ff1c3: Fixed `clippy::expect_used`, `clippy::unwrap_used` across 11 files
- Workspace-wide lint policy tightened; SQLi module has scoped-allow for build-time `expect!` on regex compilation

---

## Notable for Docs

1. **SQLi modularization** — Move from monolithic 800+ line check to 3-module, pattern-driven design. Document new pattern registry (SQLI-001..019).
2. **Header/JSON/query SQLi scanning** — New config-driven controls in `SqliScanConfig` — document allowed/denylist semantics.
3. **E2E suite** — Multi-tier testing: unit benchmarks, integration e2e, GitHub artifact pipeline.
4. **Build isolation** — Explain cargo build.rs workaround for admin-panel SPA dependency; when/why placeholder is used.
5. **Cluster enhancements** — Refinements to sync, transport, election in e2e branch but no new public API.

---

## Unresolved Questions

- [ ] Is admin-panel dist committed to repo, or always built fresh? (Affects build.rs necessity)
- [ ] SQLi pattern descriptions (SQLI-001..019) — should examples (common payloads, bypass techniques) be added to docs?
- [ ] E2E suite failure reporting — does Checks tab integration work cross-repo (for external contributors)?
- [ ] Cluster mode: are the transport refinements documented in deployment/ops guides?

