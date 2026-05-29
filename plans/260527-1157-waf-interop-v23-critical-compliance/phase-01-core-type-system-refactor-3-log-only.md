---
phase: 1
title: "Core Type System Refactor (§3 + log_only)"
status: pending
priority: P1
effort: "1-2d"
dependencies: []
---

# Phase 1: Core Type System Refactor (§3 + log_only)

## Overview

Extend `WafAction` with 3 missing decision classes (`RateLimit`, `Timeout`, `CircuitBreaker`), enrich `WafDecision` with contract-required metadata (`risk_score`, `mode`, `rule_id`), and fix log_only semantics to preserve the intended action instead of replacing it.

## Context Links

- Contract §3: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 285–313
- Contract §2.5 (log_only semantics): same file lines 139–259
- Gap report §3 + §5.2/§6: `plans/reports/contract-gap-analysis-260527-1133-waf-interop-v23-report.md`
- Current WafAction: `crates/waf-common/src/types.rs:92–107`
- Current WafDecision: `crates/waf-common/src/types.rs:143–168`
- Engine log_only handling: `crates/waf-engine/src/engine.rs` (detection phases (grep-verify count; RT-07: 11 found))

## Requirements

**Functional:**
- `WafAction` must have exactly 6 contract-compatible variants: `Allow`, `Block`, `Challenge`, `RateLimit`, `Timeout`, `CircuitBreaker`
- `WafDecision` must carry `risk_score: u16`, `mode: InteropMode`, `rule_id: Option<String>`
- In log_only mode, the engine must preserve the intended action (e.g., `Block`) and set `mode: LogOnly` — NOT replace with `WafAction::LogOnly`
- `WafDecision::is_allowed()` must return `true` when `mode == LogOnly` regardless of action
- Rate-limit phase must produce `WafAction::RateLimit` instead of `WafAction::Block`

**Non-functional:**
- Zero breakage of existing tests (backward compat)
- `WafAction::LogOnly` deprecated but kept with `#[deprecated]` for one release cycle
- `WafAction::Redirect` preserved — not in contract but used internally
- All changes compile with `cargo check --workspace`

## Red-Team Fixes Applied

| Finding | Fix |
|---------|-----|
| RT-04: `is_allowed()` rename breaks 10+ callers | Keep `is_allowed()` as deprecated wrapper calling `is_enforcement_allowed()` |
| RT-07: Engine has 11 `log_only_mode` branches, not 12 | Grep-verify actual count before implementing; refactor all found branches |
| RT-08: `RuleAction::Log` maps to deprecated `WafAction::LogOnly` | Update `to_waf_action()` to return `WafAction::Allow` (rules with `log` intent handled via mode) |
| RT-09: `WafDecision::block()` is `const fn`, can't populate `rule_id` | Remove `const` qualifier from `block()` and `allow()` constructors |
| RT-10: No risk_score plumbing exists | Add `with_risk_score()` builder; engine populates from risk scorer's actor accumulator. Default 0 when scorer unavailable |
| RT-11: WafAction serde uses internally-tagged format | `as_contract_str()` produces plain string for headers/JSONL; existing serde tag preserved for backward compat |
| RT-01: No `peer_addr`/`socket_ip` on RequestCtx | Add `socket_ip: IpAddr` field, populated from `peer_addr.ip()` in ctx_builder |

## Architecture

### New Types in `waf-common/src/types.rs`

```rust
/// Contract-aligned enforcement mode (§2.5)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InteropMode {
    #[default]
    Enforce,
    LogOnly,
}

/// Enriched WAF decision carrying contract-required metadata
#[derive(Debug, Clone)]
pub struct WafDecision {
    pub action: WafAction,
    pub result: Option<DetectionResult>,
    pub risk_score: u16,           // 0–100, contract §5.1
    pub mode: InteropMode,         // enforce|log_only, contract §2.5
    pub rule_id: Option<String>,   // dominant contributor, contract §5.1
}
```

### WafAction Enum Changes

```rust
pub enum WafAction {
    Allow,
    Block { status: u16, body: Option<String> },
    Challenge,
    RateLimit { status: u16, body: Option<String> },     // NEW — §3
    Timeout { status: u16 },                              // NEW — §3
    CircuitBreaker { status: u16, body: Option<String> }, // NEW — §3
    Redirect { url: String },                             // kept, not in contract
    #[deprecated(note = "use InteropMode::LogOnly on WafDecision instead")]
    LogOnly,                                              // kept for compat
}
```

### log_only Semantic Fix in Engine

**Current (wrong):**
```rust
if ctx.host_config.log_only_mode {
    WafDecision { action: WafAction::LogOnly, result: Some(result) }
} else {
    WafDecision::block(403, Some(body), result)
}
```

**Fixed:**
```rust
let mut decision = WafDecision::block(403, Some(body), result);
if ctx.host_config.log_only_mode {
    decision.mode = InteropMode::LogOnly;
}
decision
```

The engine preserves the intended action. `WafDecision::is_allowed()` checks mode:
```rust
/// New mode-aware check
pub fn is_enforcement_allowed(&self) -> bool {
    matches!(self.action, WafAction::Allow) || self.mode == InteropMode::LogOnly
}

/// Keep old name as deprecated wrapper (RT-04: 10+ callers)
#[deprecated(note = "use is_enforcement_allowed() — mode-aware")]
pub fn is_allowed(&self) -> bool {
    self.is_enforcement_allowed()
}
```

### `const fn` Removal (RT-09)

`WafDecision::block()` and `allow()` must drop `const` qualifier to support `rule_id: Option<String>` population and `Clone` calls. This is safe — no caller depends on const evaluation.

### `RuleAction::Log` Mapping Fix (RT-08)

```rust
// OLD: Self::Log => WafAction::LogOnly
// NEW: Log-intent rules produce Allow action; caller sets mode=LogOnly on decision
Self::Log => WafAction::Allow,
```

### `socket_ip` on RequestCtx (RT-01)

Add `pub socket_ip: IpAddr` to `RequestCtx`, populated from `peer_addr.ip()` in `request_ctx_builder.rs:79`. This is the TCP peer address, never XFF-resolved. Used by Phase 3 (JSONL audit `ip` field) and Phase 4 (rate-limit key for loopback alias distinction per contract §10).

### Risk Score Plumbing (RT-10)

The risk scorer's per-actor accumulator (L1 state machine) produces a cumulative score. After engine evaluation, extract the score and attach to `WafDecision`:
```rust
let risk_score = self.risk_scorer
    .as_ref()
    .and_then(|s| s.current_score(&actor_key))
    .unwrap_or(0);
decision = decision.with_risk_score(risk_score);
```
When risk scorer is not configured, default to 0.

### Rate-Limit Action Mapping

Current rate-limit phase returns `WafAction::Block { status: 429, .. }`. Change to `WafAction::RateLimit { status: 429, .. }` so the contract header `X-WAF-Action: rate_limit` is accurate.

### CircuitBreaker: Wire FR-039

**User decision:** Implement real circuit breaker, not a stub. FR-039 circuit breaker already exists for rate-limit Redis fallback (`BreakerStore`). Extend it to produce `WafAction::CircuitBreaker { status: 503, body }` when upstream is marked unhealthy. Wire into the upstream health check path in `proxy.rs` — when `upstream_peer` selection fails due to all backends being down, return CircuitBreaker instead of a generic 502.

## Related Code Files

**Modify:**
- `crates/waf-common/src/types.rs` — WafAction, WafDecision, add InteropMode
- `crates/waf-common/src/lib.rs` — re-export InteropMode
- `crates/waf-engine/src/engine.rs` — fix log_only handling across detection phases (grep-verify count; RT-07: 11 found)
- `crates/waf-engine/src/rate_limit/` — change Block to RateLimit action
- `crates/gateway/src/proxy_waf_response.rs` — handle new WafAction variants in write_waf_decision
- `crates/gateway/src/proxy.rs` — propagate new WafDecision fields

**No new files** — all changes are modifications to existing types/logic.

## Implementation Steps

### TDD: Write Tests First

1. **Unit tests for new WafAction variants** in `crates/waf-common/src/types.rs` `#[cfg(test)]`:
   - Test serde round-trip for `RateLimit`, `Timeout`, `CircuitBreaker`
   - Test `WafAction` tag serialization matches contract strings: `"rate_limit"`, `"timeout"`, `"circuit_breaker"`
   - Test backward compat: existing `Block`/`Allow`/`Challenge` serialization unchanged

2. **Unit tests for WafDecision enrichment**:
   - `WafDecision::allow()` has `risk_score: 0`, `mode: Enforce`, `rule_id: None`
   - `WafDecision::block(...)` has `mode: Enforce` by default
   - `is_enforcement_allowed()` returns `true` for Allow, `true` for Block+LogOnly, `false` for Block+Enforce

3. **Engine log_only tests** in `crates/waf-engine/tests/engine_evaluate_log_only.rs`:
   - Verify that when `log_only_mode=true`, a SQLi attack produces `action: Block` + `mode: LogOnly` (NOT `action: LogOnly`)
   - Verify that `is_enforcement_allowed()` returns true in log_only
   - Verify risk_score is populated from scorer

4. **Rate-limit action test** in `crates/waf-engine/tests/` (existing rate-limit test files):
   - Verify rate-limit breach produces `WafAction::RateLimit` not `WafAction::Block`

5. **Gateway response test** in `crates/gateway/tests/proxy_waf_response_writer.rs`:
   - Verify `write_waf_decision` handles `RateLimit` (returns 429)
   - Verify `write_waf_decision` handles `Timeout` (returns 504)
   - Verify `write_waf_decision` handles `CircuitBreaker` (returns 503)

### Implement

6. **Add `InteropMode` enum** to `crates/waf-common/src/types.rs`

7. **Add new `WafAction` variants**: `RateLimit { status, body }`, `Timeout { status }`, `CircuitBreaker { status, body }`

8. **Enrich `WafDecision`** with `risk_score`, `mode`, `rule_id` fields. Update constructors:
   - `WafDecision::allow()` → sets defaults
   - `WafDecision::block()` → sets mode=Enforce, extracts rule_id from DetectionResult
   - Add `WafDecision::rate_limit()`, `WafDecision::timeout()`, `WafDecision::circuit_breaker()` constructors
   - Add `with_risk_score(mut self, score: u16) -> Self` builder method
   - Add `with_mode(mut self, mode: InteropMode) -> Self` builder method
   - Rename `is_allowed()` → `is_enforcement_allowed()` to reflect mode-aware semantics

9. **Fix engine log_only handling** in `engine.rs`:
   - Run `grep -n "log_only_mode" engine.rs` to find exact branch count (RT-07: verified 11, not 12)
   - At each branch where `log_only_mode` is checked:
   - Remove `WafAction::LogOnly` substitution
   - Instead set `decision.mode = InteropMode::LogOnly`
   - Preserve original intended action (Block/Challenge/RateLimit)

10. **Change rate-limit action** in the rate-limit phase:
    - Replace `WafAction::Block { status: 429, body }` with `WafAction::RateLimit { status: 429, body }`

11. **Update `proxy_waf_response.rs`** `write_waf_decision`:
    - Add match arms for `RateLimit` (write 429 response), `Timeout` (write 504), `CircuitBreaker` (write 503)
    - Check `decision.mode`: if `LogOnly`, skip enforcement (return `Ok(false)`)
    - Deprecate the `WafAction::LogOnly` match arm

12. **Update all call sites** that reference `WafDecision` fields — search for `decision.action`, `decision.result`, `is_allowed()` across workspace

### Validate

13. Run `cargo check --workspace` — zero errors
14. Run `cargo test --workspace` — all existing tests pass
15. Run new TDD tests — all pass
16. Run `cargo clippy --workspace -- -D warnings` — zero warnings

## Success Criteria

- [ ] `WafAction` has 6 contract-compatible variants + Redirect + deprecated LogOnly
- [ ] `WafDecision` carries `risk_score`, `mode`, `rule_id`
- [ ] Engine log_only preserves intended action, sets `mode: LogOnly`
- [ ] Rate-limit phase produces `WafAction::RateLimit`
- [ ] `cargo check --workspace` passes
- [ ] All existing tests pass (zero regressions)
- [ ] New TDD tests pass
- [ ] `cargo clippy --workspace -- -D warnings` clean

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| `WafAction` serde change breaks stored/logged data | Medium | `#[serde(rename_all = "snake_case")]` already used; new variants just add new tags |
| `is_allowed()` rename breaks callers | High | Search all callers with grep; update systematically |
| Engine log_only refactor misses a branch | High | Grep for all `log_only_mode` usage; test each detection phase |
| WafDecision field additions break struct-init patterns | Medium | Use `..Default::default()` or builder pattern |
