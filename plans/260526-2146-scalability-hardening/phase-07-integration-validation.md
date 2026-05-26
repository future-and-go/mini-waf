---
phase: 7
title: "Integration Validation"
status: pending
priority: P2
effort: "3h"
dependencies: [1, 2, 3, 4, 5, 6]
---

# Phase 7: Integration Validation

## Overview

Final gate after all 6 implementation phases. Verify that all changes compose correctly: workspace compiles, all tests pass, and manual smoke tests confirm end-to-end behavior under simulated failure conditions.

## Key Insights

- Phases 1-6 touch distinct files (no merge conflicts), but integration failures can emerge from:
  - New fields on shared structs (`AppState`, `WafEngine`)
  - New `use` imports causing ambiguity
  - Background task lifecycle (batch writer + health check + sidecar restart competing for runtime)
- Workspace has multiple crates with cross-dependencies; a change in `waf-storage` error types propagates to `waf-engine` and `prx-waf`

## Requirements

**Functional:**
- `cargo check --workspace` passes with zero errors, zero warnings
- `cargo test --workspace` passes (all existing + new tests)
- `cargo fmt --all -- --check` passes (CI gate)
- `cargo clippy --workspace` passes (no new warnings)

**Non-functional:**
- No performance regression on hot path (regex eval, request proxy)
- No new `unwrap()` in production code
- No `todo!()` / `unimplemented!()` in production code

## Automated Validation

### Step 1: Compile Check

```bash
cargo fmt --all
cargo check --workspace
cargo clippy --workspace -- -D warnings
```

### Step 2: Full Test Suite

```bash
cargo test --workspace -- --nocapture
```

### Step 3: Audit for Banned Patterns

```bash
# RED-TEAM FIX: use cargo clippy with unwrap_used lint instead of grep
# grep-based approaches fail to exclude test modules correctly
cargo clippy --workspace -- -W clippy::unwrap_used 2>&1 | grep -v '/tests/' | head -50

# No unwrap in production source files (exclude test files entirely)
grep -rn '\.unwrap()' crates/ --include='*.rs' | grep -v '/tests/' | grep -v '_test.rs' | head -50

# No todo/unimplemented
grep -rn 'todo!\|unimplemented!\|unreachable!' crates/ --include='*.rs' | grep -v '/tests/' | head -50

# No std::sync::Mutex in production
grep -rn 'std::sync::Mutex' crates/ --include='*.rs' | grep -v '/tests/' | head -50
```

## Manual Smoke Tests

### Smoke 1: Batch Writer Under Load

1. Start WAF with Docker: `podman-compose up -d --build`
2. Simulate DDoS: send 5k blocked requests/sec using `wrk` or `hey`
3. Verify:
   - No OOM (watch RSS via `ps`)
   - `attack_logs` table receives batched INSERTs (check pg_stat_statements)
   - Channel-full warnings appear at expected threshold (not per-request)
   - Latency stays under p99 target

### Smoke 2: VictoriaLogs Sidecar Restart

1. Start WAF, confirm VictoriaLogs healthy: `curl http://localhost:9428/health`
2. Kill VictoriaLogs child: `kill $(pgrep victoria-logs)`
3. Verify:
   - Restart log appears within backoff window (1s initially)
   - `/health` returns 200 after restart
   - Audit events resume flowing

### Smoke 3: DB Connection Retry

1. Start WAF with PostgreSQL stopped
2. Verify: retry logs appear (attempt 1/3, 2/3, 3/3)
3. Start PostgreSQL before retry 3
4. Verify: connection established, WAF starts normally

### Smoke 4: Dynamic Log Level

1. Start WAF at default INFO level
2. `curl -X POST http://localhost:16827/api/admin/logs/level -H 'Content-Type: application/json' -d '{"filter":"debug,waf_engine=trace"}'`
3. Verify: debug logs now appear in output
4. Reset: same endpoint with `{"filter":"info"}`
5. Verify: debug logs stop

### Smoke 5: Circuit Breaker

1. Configure AppSec to point at non-existent endpoint
2. Send requests; observe circuit breaker warnings after threshold
3. Verify: subsequent requests return immediately (no HTTP timeout wait)

### Smoke 6: Regex Pre-Compilation

1. Create custom rule with invalid regex via API
2. Verify: API returns error, rule not loaded
3. Create rule with valid regex
4. Verify: rule matches correctly; no runtime compilation in logs

## Success Criteria

- [ ] `cargo check --workspace` — zero errors
- [ ] `cargo test --workspace` — all tests pass
- [ ] `cargo fmt --all -- --check` — no formatting drift
- [ ] `cargo clippy --workspace -- -D warnings` — no warnings
- [ ] No banned patterns (`unwrap`, `todo!`, `std::sync::Mutex`) in production code
- [ ] Smoke 1: Batch writer handles 5k blocks/sec
- [ ] Smoke 2: Sidecar restarts within backoff
- [ ] Smoke 3: DB retry connects after transient failure
- [ ] Smoke 4: Log level changeable at runtime
- [ ] Smoke 5: Circuit breaker short-circuits after threshold
- [ ] Smoke 6: Invalid regex rejected at load

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Cross-phase import conflicts | Low | Low | Phases touch distinct files |
| New AppState field breaks existing construction | Medium | Low | Add with default None; wire explicitly in main.rs |
| Background tasks compete for runtime (batch writer + health check + sidecar) | Low | Low | All are lightweight; total: 3 background tasks |
| CI clippy version difference | Low | Low | Pin clippy in CI; run locally before push |

## Dependency Map

- **Depends on**: Phases 1, 2, 3, 4, 5, 6 (all must be complete)
- **Blocks**: nothing (final phase)
- **File ownership**: none (read-only validation; no file modifications)
