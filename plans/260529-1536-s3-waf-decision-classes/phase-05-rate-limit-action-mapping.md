---
phase: 5
title: "Rate-Limit Action Mapping"
status: pending
priority: P1
effort: "1h"
dependencies: [3]
---

# Phase 5: Rate-Limit Action Mapping

## Overview

Change the rate-limit detection phase to produce `WafAction::RateLimit { status: 429 }` instead of `WafAction::Block { status: 403 }`. The contract §3 requires `rate_limit` as a distinct decision class so the benchmarker's classification matrix (§7) can distinguish rate-limited requests from security blocks.

This phase runs in **parallel** with Phase 4 (they modify different engine.rs lines).

## Context Links

- Rate-limit check: `crates/waf-engine/src/checks/rate_limit/check.rs` — returns `DetectionResult` (not `WafAction`)
- Engine checker pipeline: `crates/waf-engine/src/engine.rs:659–678` — wraps checker results as `WafDecision::block(403, ...)`
- `Phase::RateLimit` discriminant: `crates/waf-common/src/types.rs:182` (value = 11)
- DDoS phase: `crates/waf-engine/src/engine.rs:586–600` — similar burst detection but distinct from rate-limit
- Contract §3 matrix: `rate_limit` is acceptable for auth abuse, volumetric abuse, recon — NOT for injection or upstream degradation

## Requirements

**Functional:**
- Rate-limit phase (Phase 11 in the detection pipeline) produces `WafAction::RateLimit { status: 429, body }` when a rate limit is breached
- DDoS burst detection (Phase 19) continues to produce `WafAction::Block { status: 403 }` — DDoS is a security block, not rate-limiting per contract §3 matrix
- `X-WAF-Action` header will emit `"rate_limit"` for rate-limited requests (via `as_contract_str()` from Phase 2)

**Non-functional:**
- `RateLimitCheck` itself unchanged — it returns `DetectionResult`, not `WafAction`
- Only the engine's wrapper logic changes (phase-aware action selection)
- Existing rate-limit tests in `check.rs` remain valid (they test DetectionResult, not WafAction)

## Architecture

### Phase-Aware Action Selection

The engine's `for checker in &self.checkers` loop (line 659) currently wraps ALL checker results identically as `WafDecision::block(403, ...)`. To differentiate rate-limit, inspect `DetectionResult.phase`:

```rust
for checker in &self.checkers {
    if let Some(result) = checker.check(ctx) {
        let rule_name = result.rule_name.clone();
        let decision = match result.phase {
            Phase::RateLimit => {
                let body = render_block_page(ctx, &rule_name);
                let mut d = WafDecision::rate_limit(429, Some(body), result);
                if ctx.host_config.log_only_mode {
                    d.mode = InteropMode::LogOnly;
                }
                d
            }
            _ => self.make_block_decision(ctx, &rule_name, result, 403),
        };
        self.log_security_event(ctx, &decision);
        self.report_community_signal(ctx, &decision);
        self.send_audit_event(ctx, &decision);
        return decision;
    }
}
```

### Why Not Change the Check Trait?

The `Check` trait returns `Option<DetectionResult>`. Changing it to return `WafAction` or `WafDecision` would require modifying every checker module (11 modules). The phase-aware approach in the engine is surgical: one match block, one file, zero trait changes.

### TxVelocity Phase

`TxVelocityCheck` is also in the `checkers` Vec (index 1, after RateLimitCheck). Its `DetectionResult.phase` is different from `Phase::RateLimit`, so it falls through to the default `Block` arm. No special handling needed.

## Related Code Files

**Modify:**
- `crates/waf-engine/src/engine.rs` — checker pipeline loop (line 659–678)

**No change:**
- `crates/waf-engine/src/checks/rate_limit/check.rs` — returns `DetectionResult`, unchanged
- `crates/waf-engine/src/checks/rate_limit/store/` — store layer unchanged

## Implementation Steps

### 1. Modify checker pipeline loop in `engine.rs:659`

Replace the uniform `make_block_decision()` call with a phase-aware match on `result.phase`. Only `Phase::RateLimit` gets special treatment; all other phases use the existing block decision helper.

### 2. Verify DDoS phase is NOT affected

The DDoS check (line 586) runs BEFORE the checker loop and has its own decision-building block. It already uses `make_block_decision()` (after Phase 4) with status 403. No change needed — DDoS burst is a security block per contract §3 matrix.

### 3. Add rate-limit action test

In `crates/waf-engine/src/checks/rate_limit/check.rs` inline tests, add a test verifying `DetectionResult.phase == Phase::RateLimit` (this is already the case, but making it explicit for the contract):

```rust
#[test]
fn rate_limit_result_has_correct_phase() {
    // Verify the phase is set so engine's phase-aware logic works
    let result = RateLimitCheck::block("RL-IP", "per-IP", Decision::BurstExceeded);
    assert_eq!(result.phase, Phase::RateLimit);
}
```

### 4. Engine-level integration test

Add to existing engine test suite or inline:

```rust
// Verify rate-limit breach produces RateLimit action, not Block
// (requires seeded host + exhausted rate-limit tokens)
```

This test requires the full engine fixture. If existing `integration_under_then_over_limit` test (check.rs:303) only validates `DetectionResult`, add an engine-level test in `crates/waf-engine/tests/` that runs `engine.inspect()` and checks `WafAction::RateLimit`.

### 5. Validate

Run `cargo check --workspace` — zero errors.
Run `cargo test -p waf-engine` — all tests pass.

## Success Criteria

- [ ] Rate-limit breaches produce `WafAction::RateLimit { status: 429, .. }`
- [ ] DDoS breaches still produce `WafAction::Block { status: 403, .. }`
- [ ] All other checker phases still produce `WafAction::Block { status: 403, .. }`
- [ ] `as_contract_str()` returns `"rate_limit"` for rate-limit decisions
- [ ] Rate-limit check inline tests pass
- [ ] `cargo test -p waf-engine` passes

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Phase discrimination misses a rate-limit result | Rate-limit classified as `block` | Only `RateLimitCheck` returns `Phase::RateLimit`; verified in step 3 |
| Status 429 breaks client expectations | Minor — HTTP 429 is standard | Was 403 before; 429 is semantically correct per RFC 6585 |
| DDoS accidentally matched as rate-limit | Wrong classification | DDoS has its own code path before the checker loop; never enters the `for checker` branch |
