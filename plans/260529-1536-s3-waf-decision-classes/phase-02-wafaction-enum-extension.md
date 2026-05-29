---
phase: 2
title: "WafAction Enum Extension"
status: pending
priority: P1
effort: "2h"
dependencies: [1]
---

# Phase 2: WafAction Enum Extension

## Overview

Add 3 missing contract decision classes (`RateLimit`, `Timeout`, `CircuitBreaker`) to `WafAction` enum. Deprecate `LogOnly` variant. Add `as_contract_str()` method. Update all exhaustive match blocks across workspace to handle new variants.

## Context Links

- Current WafAction: `crates/waf-common/src/types.rs:92–107`
- Contract §3 decision classes: `analysis/docs/EN_waf_interop_contract_v2.3.md` §3
- Existing `InteropMode` (reuse, don't duplicate): `crates/waf-engine/src/interop/mode_registry.rs:9–12`

## Requirements

**Functional:**
- `WafAction` has 8 variants total: `Allow`, `Block`, `Challenge`, `RateLimit`, `Timeout`, `CircuitBreaker`, `Redirect`, `LogOnly`
- `RateLimit { status: u16, body: Option<String> }` — mirrors `Block` shape
- `Timeout { status: u16 }` — no body (upstream didn't respond)
- `CircuitBreaker { status: u16, body: Option<String> }` — mirrors `Block` shape
- `LogOnly` deprecated with `#[deprecated]` attribute
- `as_contract_str()` returns one of: `"allow"`, `"block"`, `"challenge"`, `"rate_limit"`, `"timeout"`, `"circuit_breaker"`
- Serde tag `rename_all = "snake_case"` already handles new variant names correctly

**Non-functional:**
- `cargo check --workspace` passes with zero errors (all match arms updated)
- Zero clippy warnings from new code
- Existing serde format for `Allow`, `Block`, `Challenge`, `Redirect` unchanged

## Architecture

### Enum After Changes

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WafAction {
    Allow,
    Block { status: u16, body: Option<String> },
    Challenge,
    RateLimit { status: u16, body: Option<String> },
    Timeout { status: u16 },
    CircuitBreaker { status: u16, body: Option<String> },
    Redirect { url: String },
    #[deprecated(note = "use InteropMode::LogOnly on WafDecision instead")]
    LogOnly,
}
```

### `as_contract_str()` Method

```rust
impl WafAction {
    pub fn as_contract_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block { .. } => "block",
            Self::Challenge => "challenge",
            Self::RateLimit { .. } => "rate_limit",
            Self::Timeout { .. } => "timeout",
            Self::CircuitBreaker { .. } => "circuit_breaker",
            #[allow(deprecated)]
            Self::Redirect { .. } | Self::LogOnly => "allow",
        }
    }
}
```

`Redirect` and `LogOnly` map to `"allow"` — they're internal variants not in the contract. `LogOnly` will be removed after migration.

## Related Code Files

**Modify:**
- `crates/waf-common/src/types.rs` — enum definition + `as_contract_str()`
- `crates/waf-engine/src/engine.rs` — 3 match blocks in logging helpers (lines 835, 891, 944)
- `crates/gateway/src/proxy_waf_response.rs` — match in `write_waf_decision()` (line 39) and `write_waf_body_decision()` (line 198)
- `crates/gateway/src/http3.rs` — match block (line 244)

## Implementation Steps

### 1. Add new variants to `WafAction` in `types.rs:92`

Insert `RateLimit`, `Timeout`, `CircuitBreaker` after `Challenge`. Add `#[deprecated]` to `LogOnly`. Keep `Redirect` as-is (internal use).

### 2. Add `as_contract_str()` impl block

Add after the enum definition. This produces the plain string for `X-WAF-Action` header and JSONL audit `action` field. Distinct from serde's internally-tagged format.

### 3. Update `RuleAction::to_waf_action()` in `types.rs:133`

No change in this phase — `RuleAction` only has `Block`, `Allow`, `Log`, `Challenge`. Phase 4 changes `RuleAction::Log` mapping from `WafAction::LogOnly` to `WafAction::Allow` (RT-08 fix).

### 4. Update engine `log_attack()` match block (`engine.rs:835`)

Add arms:
```rust
WafAction::RateLimit { .. } => "rate_limit",
WafAction::Timeout { .. } => "timeout",
WafAction::CircuitBreaker { .. } => "circuit_breaker",
```

### 5. Update engine `log_security_event()` match block (`engine.rs:891`)

Same 3 new arms as step 4.

### 6. Update engine `send_audit_event()` match block (`engine.rs:944`)

```rust
WafAction::RateLimit { .. } => AuditEventType::Block,
WafAction::Timeout { .. } => AuditEventType::Block,
WafAction::CircuitBreaker { .. } => AuditEventType::Block,
```

Map to `AuditEventType::Block` — closest VictoriaLogs category for non-allow decisions. The JSONL interop audit (Phase 3 of parent plan) uses `as_contract_str()` directly.

### 7. Update gateway `write_waf_decision()` in `proxy_waf_response.rs:39`

Add match arms inside `if !decision.is_allowed()` block. For now, handle identically to `Block`:

```rust
WafAction::RateLimit { status, body } => {
    // Same response writing as Block — status + body
}
WafAction::Timeout { status } => {
    let response = pingora_http::ResponseHeader::build(*status, None)?;
    session.write_response_header(Box::new(response), false).await?;
    session.write_response_body(Some(Bytes::from("Gateway Timeout")), true).await?;
    return Ok(true);
}
WafAction::CircuitBreaker { status, body } => {
    // Same response writing as Block — status + body
}
```

### 8. Update gateway `write_waf_body_decision()` in `proxy_waf_response.rs:198`

Same pattern as step 7.

### 9. Update gateway `http3.rs:244` match block

Add arms for `RateLimit`, `Timeout`, `CircuitBreaker` mirroring the `Block` handler.

### 10. Suppress deprecation warnings on `LogOnly` usage

Add `#[allow(deprecated)]` at each existing `WafAction::LogOnly` usage site until Phase 4 removes them. This prevents a flood of warnings during the transition.

### 11. Validate

Run `cargo check --workspace` — zero errors.
Run `cargo clippy --workspace -- -D warnings` — zero warnings.

## Success Criteria

- [ ] `WafAction` has 8 variants: Allow, Block, Challenge, RateLimit, Timeout, CircuitBreaker, Redirect, LogOnly(deprecated)
- [ ] `as_contract_str()` returns correct contract strings for all 6 contract types
- [ ] All exhaustive match blocks updated (engine: 3, gateway: 3)
- [ ] `cargo check --workspace` passes
- [ ] `cargo clippy --workspace -- -D warnings` clean (with `#[allow(deprecated)]` on LogOnly sites)

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Missed match arm causes compile error | Build fails (safe) | `cargo check --workspace` catches all |
| Serde tag collision with existing variants | Deserialization breaks | `snake_case` mapping is deterministic; `rate_limit`, `timeout`, `circuit_breaker` don't collide |
| `#[deprecated]` on `LogOnly` floods warnings | Noisy CI | `#[allow(deprecated)]` at usage sites until Phase 4 cleans them |
