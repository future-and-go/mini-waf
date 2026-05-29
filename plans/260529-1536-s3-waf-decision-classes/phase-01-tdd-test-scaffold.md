---
phase: 1
title: "TDD Test Scaffold"
status: pending
priority: P1
effort: "2h"
dependencies: []
---

# Phase 1: TDD Test Scaffold

## Overview

Write all tests FIRST — before any production code changes. Tests initially fail (won't compile or assert wrong values). Phases 2-6 make them pass. This ensures every behavioral change is regression-locked.

## Context Links

- Current WafAction tests: `crates/waf-common/tests/types_decisions.rs`
- Current engine log_only tests: `crates/waf-engine/tests/engine_evaluate_log_only.rs`
- Current gateway tests: `crates/gateway/tests/proxy_waf_response_writer.rs`
- Rate-limit check tests: `crates/waf-engine/src/checks/rate_limit/check.rs` (inline `#[cfg(test)]`)

## Requirements

**Functional:**
- Tests for new `WafAction` variants serde round-trip
- Tests for `WafDecision` enrichment fields (risk_score, mode, rule_id)
- Tests for `is_enforcement_allowed()` mode-aware semantics
- Tests for `as_contract_str()` producing contract-compliant strings
- Tests for engine log_only preserving intended action
- Tests for rate-limit producing `WafAction::RateLimit` (not `Block`)
- Tests for gateway handling new action variants

**Non-functional:**
- Tests compile only after Phase 2-3 add the types (expected)
- Tests placed in existing test files to follow codebase patterns

## Architecture

**Strategy: extend existing test files, don't create new ones.**

| Test Category | File | Tests |
|---------------|------|-------|
| WafAction serde | `crates/waf-common/tests/types_decisions.rs` | 4 new tests |
| WafDecision enrichment | `crates/waf-common/tests/types_decisions.rs` | 5 new tests |
| Contract string mapping | `crates/waf-common/tests/types_decisions.rs` | 1 new test |
| Engine log_only semantics | `crates/waf-engine/tests/engine_evaluate_log_only.rs` | 3 modified tests |
| Rate-limit action | `crates/waf-engine/src/checks/rate_limit/check.rs` | 1 new inline test |
| Gateway response handler | `crates/gateway/tests/proxy_waf_response_writer.rs` | 3 new tests |

## Related Code Files

**Modify:**
- `crates/waf-common/tests/types_decisions.rs` — add serde + enrichment + contract string tests
- `crates/waf-engine/tests/engine_evaluate_log_only.rs` — update assertions from `WafAction::LogOnly` to `WafAction::Block` + `mode: LogOnly`
- `crates/gateway/tests/proxy_waf_response_writer.rs` — add tests for RateLimit/Timeout/CircuitBreaker handling

## Implementation Steps

### 1. WafAction serde tests in `types_decisions.rs`

Add after existing `waf_action_serde_tagged_snake_case` test:

```rust
#[test]
fn waf_action_rate_limit_serde_round_trip() {
    let action = WafAction::RateLimit { status: 429, body: Some("rate limited".into()) };
    let json = serde_json::to_string(&action).unwrap();
    assert!(json.contains("\"rate_limit\""));
    let back: WafAction = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, WafAction::RateLimit { status: 429, .. }));
}

#[test]
fn waf_action_timeout_serde_round_trip() {
    let action = WafAction::Timeout { status: 504 };
    let json = serde_json::to_string(&action).unwrap();
    assert!(json.contains("\"timeout\""));
    let back: WafAction = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, WafAction::Timeout { status: 504 }));
}

#[test]
fn waf_action_circuit_breaker_serde_round_trip() {
    let action = WafAction::CircuitBreaker { status: 503, body: Some("upstream down".into()) };
    let json = serde_json::to_string(&action).unwrap();
    assert!(json.contains("\"circuit_breaker\""));
    let back: WafAction = serde_json::from_str(&json).unwrap();
    assert!(matches!(back, WafAction::CircuitBreaker { status: 503, .. }));
}

#[test]
fn waf_action_existing_variants_serde_unchanged() {
    // Backward compat: existing variant serialization must not change
    let allow_json = serde_json::to_string(&WafAction::Allow).unwrap();
    assert_eq!(allow_json, r#"{"type":"allow"}"#);

    let block_json = serde_json::to_string(&WafAction::Block { status: 403, body: None }).unwrap();
    assert!(block_json.contains("\"block\""));

    let challenge_json = serde_json::to_string(&WafAction::Challenge).unwrap();
    assert!(challenge_json.contains("\"challenge\""));
}
```

### 2. WafAction contract string tests

```rust
#[test]
fn waf_action_as_contract_str_covers_all_six() {
    assert_eq!(WafAction::Allow.as_contract_str(), "allow");
    assert_eq!(WafAction::Block { status: 403, body: None }.as_contract_str(), "block");
    assert_eq!(WafAction::Challenge.as_contract_str(), "challenge");
    assert_eq!(WafAction::RateLimit { status: 429, body: None }.as_contract_str(), "rate_limit");
    assert_eq!(WafAction::Timeout { status: 504 }.as_contract_str(), "timeout");
    assert_eq!(WafAction::CircuitBreaker { status: 503, body: None }.as_contract_str(), "circuit_breaker");
}
```

### 3. WafDecision enrichment tests

```rust
#[test]
fn waf_decision_allow_has_default_metadata() {
    let d = WafDecision::allow();
    assert_eq!(d.risk_score, 0);
    assert_eq!(d.mode, InteropMode::Enforce);
    assert!(d.rule_id.is_none());
}

#[test]
fn waf_decision_block_has_enforce_mode() {
    let r = DetectionResult {
        rule_id: Some("R1".into()),
        rule_name: "test".into(),
        phase: Phase::SqlInjection,
        detail: "found".into(),
        rule_action: None,
        action_status: None,
    };
    let d = WafDecision::block(403, Some("denied".into()), r);
    assert_eq!(d.mode, InteropMode::Enforce);
    assert_eq!(d.rule_id.as_deref(), Some("R1"));
}

#[test]
fn waf_decision_with_risk_score_builder() {
    let d = WafDecision::allow().with_risk_score(42);
    assert_eq!(d.risk_score, 42);
}

#[test]
fn waf_decision_with_mode_builder() {
    let d = WafDecision::allow().with_mode(InteropMode::LogOnly);
    assert_eq!(d.mode, InteropMode::LogOnly);
}

#[test]
fn is_enforcement_allowed_mode_aware() {
    // Allow + Enforce → allowed
    let d = WafDecision::allow();
    assert!(d.is_enforcement_allowed());

    // Block + Enforce → NOT allowed
    let r = DetectionResult { rule_id: None, rule_name: "t".into(), phase: Phase::SqlInjection, detail: "".into(), rule_action: None, action_status: None };
    let d = WafDecision::block(403, None, r.clone());
    assert!(!d.is_enforcement_allowed());

    // Block + LogOnly → allowed (mode overrides)
    let d = WafDecision::block(403, None, r).with_mode(InteropMode::LogOnly);
    assert!(d.is_enforcement_allowed());
}
```

### 4. Engine log_only test updates in `engine_evaluate_log_only.rs`

Update existing assertions. Currently they assert `WafAction::LogOnly`; after Phase 4 they should assert the INTENDED action + `mode: LogOnly`:

```rust
// BEFORE (current):
assert!(matches!(d.action, WafAction::LogOnly), "XSS LogOnly: got {:?}", d.action);

// AFTER (Phase 4 makes this pass):
assert!(matches!(d.action, WafAction::Block { .. }), "XSS should preserve Block action in log_only: got {:?}", d.action);
assert_eq!(d.mode, InteropMode::LogOnly, "mode must be LogOnly");
assert!(d.is_enforcement_allowed(), "log_only must allow enforcement bypass");
```

Apply this pattern to: `xss_in_log_only_mode`, `directory_traversal_in_log_only_mode`, `rce_in_log_only_mode`, `scanner_ua_in_log_only_mode`.

### 5. Gateway response handler tests in `proxy_waf_response_writer.rs`

```rust
#[tokio::test]
async fn write_waf_decision_rate_limit_writes_429() {
    // Setup mock session, create WafDecision with RateLimit{429, body}
    // Assert: status 429 written, body written, returns Ok(true)
}

#[tokio::test]
async fn write_waf_decision_timeout_writes_504() {
    // Setup mock session, create WafDecision with Timeout{504}
    // Assert: status 504 written, returns Ok(true)
}

#[tokio::test]
async fn write_waf_decision_circuit_breaker_writes_503() {
    // Setup mock session, create WafDecision with CircuitBreaker{503, body}
    // Assert: status 503 written, body written, returns Ok(true)
}
```

### 6. Verify test scaffold compiles (after Phase 2-3)

Run `cargo test --workspace --no-run` — all tests compile.
Run `cargo test --workspace` — new tests pass, existing tests pass.

## Success Criteria

- [ ] All new test functions written in existing test files
- [ ] Tests cover all 6 contract action types (serde, contract string, enrichment)
- [ ] Tests cover mode-aware `is_enforcement_allowed()` semantics
- [ ] Engine log_only tests updated to assert intended-action-preserved behavior
- [ ] Gateway tests added for RateLimit, Timeout, CircuitBreaker response writing
- [ ] After Phase 7: `cargo test --workspace` — zero failures

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Tests won't compile until Phase 2-3 adds types | Expected — write test bodies as comments initially, uncomment in Phase 2-3 |
| Existing engine log_only tests break during refactor | Update assertions atomically with engine changes in Phase 4 |
