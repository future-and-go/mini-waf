---
phase: 4
title: "Engine log_only Semantic Fix"
status: done
priority: P1
effort: "3h"
dependencies: [3]
---

# Phase 4: Engine log_only Semantic Fix

## Overview

Refactor all 11 `log_only_mode` branches in `engine.rs` to preserve the intended action (Block/Challenge) and set `mode: InteropMode::LogOnly` instead of replacing the action with `WafAction::LogOnly`. This is the contract §2.5 semantic fix — the single most impactful change for benchmark compatibility.

## Context Links

- Contract §2.5 log_only semantics: `analysis/docs/EN_waf_interop_contract_v2.3.md` §2.5
- Current engine log_only branches: `crates/waf-engine/src/engine.rs` (grep-verified: 11 branches at lines 588, 607, 627, 643, 663, 683, 704, 725, 756, 774, 792)
- Existing log_only tests: `crates/waf-engine/tests/engine_evaluate_log_only.rs`
- Existing late log_only tests: `crates/waf-engine/tests/engine_late_log_only_geo.rs`

## Requirements

**Functional:**
- Every detection phase that triggers in log_only mode MUST:
  1. Produce the same `WafAction` it would in enforce mode (e.g., `Block { status: 403, body }`)
  2. Set `decision.mode = InteropMode::LogOnly`
  3. Result in `is_enforcement_allowed() == true` (request passes to upstream)
- `WafDecision::LogOnly` variant no longer constructed anywhere in engine.rs
- Logging helpers continue to work (they match on `WafAction`, not mode)

**Non-functional:**
- Zero changes to the `Check` trait or individual checker modules
- All existing engine tests pass (assertions updated where needed)
- No behavioral change for `log_only_mode = false` (enforce mode unchanged)

## Architecture

### Current Pattern (WRONG per contract)

```rust
// Repeated 11 times across detection phases
let decision = if ctx.host_config.log_only_mode {
    WafDecision {
        action: WafAction::LogOnly,
        result: Some(result),
        risk_score: 0,
        mode: InteropMode::Enforce,  // Phase 3 added these defaults
        rule_id: None,
    }
} else {
    let body = render_block_page(ctx, &rule_name);
    WafDecision::block(403, Some(body), result)
};
```

### Fixed Pattern

```rust
// Extract helper to reduce duplication across 11 sites
let body = render_block_page(ctx, &rule_name);
let mut decision = WafDecision::block(403, Some(body), result);
if ctx.host_config.log_only_mode {
    decision.mode = InteropMode::LogOnly;
}
```

The intended action (`Block { status: 403, body }`) is preserved. The mode field signals that enforcement should be skipped. `is_enforcement_allowed()` returns `true` when `mode == LogOnly`, so gateway skips writing the block response.

### DRY: Extract Helper Function

11 identical branches → extract to a private method on `WafEngine`:

```rust
impl WafEngine {
    fn make_block_decision(
        &self,
        ctx: &RequestCtx,
        rule_name: &str,
        result: DetectionResult,
        status: u16,
    ) -> WafDecision {
        let body = render_block_page(ctx, rule_name);
        let mut decision = WafDecision::block(status, Some(body), result);
        if ctx.host_config.log_only_mode {
            decision.mode = InteropMode::LogOnly;
        }
        decision
    }
}
```

Each detection phase replaces the if/else block with:
```rust
let decision = self.make_block_decision(ctx, &rule_name, result, 403);
```

### Phase-Specific Status Codes

Most phases use 403. Rate-limit will use 429 (Phase 5). The helper accepts `status` as parameter to support this.

## Related Code Files

**Modify:**
- `crates/waf-engine/src/engine.rs` — 11 log_only branches + add helper method

**Modify (test assertions):**
- `crates/waf-engine/tests/engine_evaluate_log_only.rs` — update 4 assertions
- `crates/waf-engine/tests/engine_late_log_only_geo.rs` — update assertions if present

## Implementation Steps

### 1. Add `make_block_decision()` helper to `WafEngine` impl

Add as a private method. Place near the logging helpers (around line 830).

```rust
fn make_block_decision(
    &self,
    ctx: &RequestCtx,
    rule_name: &str,
    result: DetectionResult,
    status: u16,
) -> WafDecision {
    let body = render_block_page(ctx, rule_name);
    let mut decision = WafDecision::block(status, Some(body), result);
    if ctx.host_config.log_only_mode {
        decision.mode = InteropMode::LogOnly;
    }
    decision
}
```

### 2. Refactor Phase 19 (DDoS) — line 588

**Before:**
```rust
let decision = if ctx.host_config.log_only_mode {
    WafDecision { action: WafAction::LogOnly, result: Some(result), ... }
} else {
    let body = render_block_page(ctx, &rule_name);
    WafDecision::block(403, Some(body), result)
};
```

**After:**
```rust
let decision = self.make_block_decision(ctx, &rule_name, result, 403);
```

### 3. Refactor Phase 16a (CrowdSec Bouncer) — line 607

Same transformation as step 2.

### 4. Refactor Phase 18 (Community) — line 627

Same transformation as step 2.

### 5. Refactor Phase 17 (GeoIP) — line 643

Same transformation as step 2.

### 6. Refactor Phase 5-11 loop (Attack pipeline) — line 663

Same transformation as step 2. The `for checker in &self.checkers` body becomes:

```rust
if let Some(result) = checker.check(ctx) {
    let rule_name = result.rule_name.clone();
    let decision = self.make_block_decision(ctx, &rule_name, result, 403);
    self.log_security_event(ctx, &decision);
    self.report_community_signal(ctx, &decision);
    self.send_audit_event(ctx, &decision);
    return decision;
}
```

### 7. Refactor SQLi check — line 683

Same transformation as step 2.

### 8. Refactor Phase 16b (CrowdSec AppSec) — line 704

Same transformation as step 2.

### 9. Refactor Custom rules engine — line 725

**Special case:** Custom rules may have `rule_action` and `action_status` overrides. The custom rules branch uses `result.rule_action` to call `to_waf_action(status, body)`. This path does NOT use `make_block_decision()` because `to_waf_action()` may produce Allow or Challenge, not just Block (RT-11: documented bypass).

**RT-08 fix:** `RuleAction::Log` currently maps to `WafAction::LogOnly` via `to_waf_action()`. After this refactor, `RuleAction::Log` must map to `WafAction::Allow` in `to_waf_action()` — rule-author "log" intent means "allow request, log the match." The mode field on `WafDecision` (not the action) carries log-only semantics. Update `to_waf_action()` in `types.rs:137`:

```rust
// BEFORE: Self::Log => WafAction::LogOnly
// AFTER:  Self::Log => WafAction::Allow
Self::Log => WafAction::Allow,
```

Then in the custom rules branch:

```rust
let status = result.action_status.unwrap_or(403);
let action = result.rule_action
    .unwrap_or(RuleAction::Block)
    .to_waf_action(status, Some(render_block_page(ctx, &rule_name)));
let rule_id = result.rule_id.clone();
let mut decision = WafDecision {
    action,
    result: Some(result),
    risk_score: 0,
    mode: InteropMode::Enforce,
    rule_id,
};
if ctx.host_config.log_only_mode {
    decision.mode = InteropMode::LogOnly;
}
```

### 10. Refactor OWASP phase — line 756

Same transformation as step 2.

### 11. Refactor Sensitive data phase — line 774

Same transformation as step 2.

### 12. Refactor Anti-hotlink phase — line 792

Same transformation as step 2.

### 13. Update test assertions in `engine_evaluate_log_only.rs`

For each test (`xss_in_log_only_mode`, `directory_traversal_in_log_only_mode`, `rce_in_log_only_mode`, `scanner_ua_in_log_only_mode`):

**Before:**
```rust
assert!(matches!(d.action, WafAction::LogOnly), "XSS LogOnly: got {:?}", d.action);
```

**After:**
```rust
assert!(
    matches!(d.action, WafAction::Block { .. }),
    "XSS must preserve Block action in log_only: got {:?}", d.action
);
assert_eq!(d.mode, InteropMode::LogOnly, "mode must be LogOnly");
assert!(d.is_enforcement_allowed(), "log_only must allow enforcement bypass");
assert!(d.result.is_some(), "detection result must be preserved");
```

### 14. Update `engine_late_log_only_geo.rs` assertions (RT-07: 2 confirmed sites)

Lines 108 and 128 both assert `matches!(d.action, WafAction::LogOnly)`. Apply the same update as step 13:
- `sensitive_in_log_only_mode_returns_log_only` (line 108) → assert `Block { .. }` + `mode: LogOnly`
- `hotlink_in_log_only_mode_returns_log_only` (line 128) → assert `Block { .. }` + `mode: LogOnly`

**Total test assertion updates: 6** (4 in `engine_evaluate_log_only.rs` + 2 in `engine_late_log_only_geo.rs`).

### 15. Remove `#[allow(deprecated)]` on `WafAction::LogOnly` usage

After all 11 branches no longer construct `WafAction::LogOnly`, the deprecation annotations added in Phase 2 for engine.rs can be removed. Only test files and the `is_allowed()` wrapper still reference it.

### 16. Validate

Run `cargo check --workspace` — zero errors.
Run `cargo test -p waf-engine` — all tests pass including updated log_only tests.
Run `cargo clippy --workspace -- -D warnings` — clean.

## Success Criteria

- [ ] All 11 `log_only_mode` branches use `make_block_decision()` or equivalent
- [ ] Zero construction of `WafAction::LogOnly` in engine.rs
- [ ] Log_only decisions preserve intended action (Block/Challenge)
- [ ] Log_only decisions have `mode: InteropMode::LogOnly`
- [ ] `is_enforcement_allowed()` returns `true` for all log_only decisions
- [ ] All 4 engine log_only tests updated and pass
- [ ] `engine_late_log_only_geo.rs` tests pass
- [ ] `cargo test -p waf-engine` — zero failures
- [ ] `cargo check --workspace` — zero errors

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Missed a log_only branch | One phase still produces `LogOnly` action | grep-verify: exactly 11 branches, all addressed in steps 2-12 |
| Custom rules branch has special action logic | Wrong action for custom rules in log_only | Step 9 preserves `to_waf_action()` call; only mode changes |
| `ip_blacklist_block_path` test expects non-Allow | Test validates IP blacklist ignores log_only | No change — IP blacklist (Phase 2) doesn't check log_only_mode |
| Gateway still checks `is_allowed()` | Deprecated wrapper works identically | `is_allowed()` delegates to `is_enforcement_allowed()` — mode-aware |
