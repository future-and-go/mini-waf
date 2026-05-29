---
phase: 7
title: "Validation and Regression"
status: pending
priority: P1
effort: "1h"
dependencies: [1, 2, 3, 4, 5, 6]
---

# Phase 7: Validation and Regression

## Overview

Full workspace validation: compile, test, clippy, fmt. Verify no regressions in existing behavior. Confirm contract §3 compliance. Mark parent plan Phase 1 as completed.

## Requirements

**Functional:**
- All 6 contract decision classes present and tested
- log_only semantics match contract §2.5
- Rate-limit actions produce `rate_limit` (not `block`)
- Gateway handles all new variants

**Non-functional:**
- `cargo check --workspace` — zero errors
- `cargo test --workspace` — zero failures
- `cargo clippy --workspace -- -D warnings` — zero warnings
- `cargo fmt --all -- --check` — zero diffs

## Implementation Steps

### 1. Full workspace compile check

```bash
cargo check --workspace
```

Expected: zero errors. If any, fix in the originating phase.

### 2. Full workspace test suite

```bash
cargo test --workspace
```

Expected: zero failures. Key test suites to verify:

| Test Suite | What It Validates |
|------------|-------------------|
| `waf-common::types::tests` | WafAction serde, RuleAction, cookie parsing |
| `waf-common/tests/types_decisions.rs` | WafDecision constructors, enrichment, contract strings |
| `waf-engine/tests/engine_evaluate_log_only.rs` | log_only preserves intended action + sets mode |
| `waf-engine/tests/engine_evaluate_attack.rs` | Attack detection still produces Block in enforce mode |
| `waf-engine/tests/engine_evaluate_clean.rs` | Clean requests still produce Allow |
| `waf-engine/tests/engine_evaluate_lists.rs` | IP/URL lists unchanged |
| `waf-engine/tests/engine_late_log_only_geo.rs` | GeoIP + log_only integration |
| `waf-engine/tests/risk_scorer_decision_matrix.rs` | Risk scorer threshold actions |
| `waf-engine/tests/interop_mode_registry.rs` | ModeRegistry resolve/set operations |
| `waf-engine/src/checks/rate_limit/check.rs` | Rate-limit DetectionResult + phase |
| `gateway/tests/proxy_waf_response_writer.rs` | Response writing for all action variants |

### 3. Clippy lint check

```bash
cargo clippy --workspace -- -D warnings
```

Expected: zero warnings. Common issues to watch:
- `#[deprecated]` usage without `#[allow(deprecated)]`
- Unused imports from moved `InteropMode`
- Redundant clone on builder methods

### 4. Format check

```bash
cargo fmt --all -- --check
```

Expected: zero diffs. If any, run `cargo fmt --all` to fix.

### 5. Verify contract §3 compliance checklist

Manually verify (code review, not automated):

| Contract Requirement | Verification |
|---------------------|--------------|
| `allow` decision class exists | `WafAction::Allow` — present |
| `block` decision class exists | `WafAction::Block { status, body }` — present |
| `challenge` decision class exists | `WafAction::Challenge` — present |
| `rate_limit` decision class exists | `WafAction::RateLimit { status, body }` — NEW |
| `timeout` decision class exists | `WafAction::Timeout { status }` — NEW (type only; no producer yet — RT-10) |
| `circuit_breaker` decision class exists | `WafAction::CircuitBreaker { status, body }` — NEW (type only; no producer yet — RT-10) |
| `as_contract_str()` returns exact strings | Tested in Phase 1 TDD tests |
| Rate-limit phase → `rate_limit` action | Phase 5 wiring |
| log_only preserves intended action | Phase 4 semantic fix |
| log_only sets `mode: LogOnly` | Phase 4 semantic fix |
| `X-WAF-Action` header values correct | Depends on §5 header injection (separate plan phase) |
| `X-WAF-Mode` header values correct | Depends on §5 header injection (separate plan phase) |

### 6. Verify backward compatibility

Run existing CI test matrix (if available):

```bash
# Database event serialization unchanged
cargo test -p waf-storage

# API endpoints unchanged
cargo test -p waf-api
```

### 7. Update parent plan status

Mark Phase 1 of `plans/260527-1157-waf-interop-v23-critical-compliance/plan.md` as completed. This plan's scope supersedes it.

```bash
cd plans/260527-1157-waf-interop-v23-critical-compliance && ck plan check phase-01
```

## Success Criteria

- [ ] `cargo check --workspace` — zero errors
- [ ] `cargo test --workspace` — zero failures
- [ ] `cargo clippy --workspace -- -D warnings` — zero warnings
- [ ] `cargo fmt --all -- --check` — zero diffs
- [ ] All 6 contract decision classes present with correct `as_contract_str()` output
- [ ] log_only mode preserves intended action and sets `mode: LogOnly`
- [ ] Rate-limit produces `WafAction::RateLimit { status: 429 }`
- [ ] Gateway handles RateLimit, Timeout, CircuitBreaker responses
- [ ] Parent plan Phase 1 marked completed
- [ ] No regressions in existing test suites

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Flaky integration tests unrelated to changes | False failure signal | Re-run; check if failure is in modified code |
| waf-storage tests fail on schema change | No schema change in this plan | WafAction serde is additive; stored events use string action field |
| waf-api tests fail on InteropMode move | Import path change | Re-export from `waf_engine::interop` preserves path |
