---
phase: 3
title: "WafDecision Enrichment"
status: completed
priority: P1
effort: "2h"
dependencies: [2]
---

# Phase 3: WafDecision Enrichment

## Overview

Add contract-required metadata fields (`risk_score`, `mode`, `rule_id`) to `WafDecision`. Add builder methods. Deprecate `is_allowed()` in favor of mode-aware `is_enforcement_allowed()`. Drop `const` from constructors (required for `String` fields).

## Context Links

- Current WafDecision: `crates/waf-common/src/types.rs:143–168`
- `InteropMode` already exists: `crates/waf-engine/src/interop/mode_registry.rs:9–12`
- Callers of `is_allowed()`: `proxy_waf_response.rs:37,196`, `http3.rs:242`, `engine.rs:748`
- Callers of `WafDecision { action, result }` struct-init: `engine.rs` (11 log_only branches), `checker.rs:203,249`

## Requirements

**Functional:**
- `WafDecision` gains 3 fields: `risk_score: u8`, `mode: InteropMode`, `rule_id: Option<String>` (u8 matches `ScorerResult.score` range 0..=100; RT-04)
- `allow()` returns defaults: `risk_score: 0`, `mode: Enforce`, `rule_id: None`
- `block()` extracts `rule_id` from `DetectionResult.rule_id`, sets `mode: Enforce`
- `with_risk_score(score) -> Self` builder — chainable
- `with_mode(mode) -> Self` builder — chainable
- `is_enforcement_allowed()` returns `true` when `action == Allow` OR `mode == LogOnly`
- `is_allowed()` kept as `#[deprecated]` wrapper calling `is_enforcement_allowed()`

**Non-functional:**
- `InteropMode` must be re-exported from `waf-common` (currently only in `waf-engine`)
- All 10+ `is_allowed()` callers compile unchanged (deprecation warning only)
- Struct-init sites using `WafDecision { action, result }` must be updated to include new fields

## Architecture

### Enriched WafDecision

```rust
pub struct WafDecision {
    pub action: WafAction,
    pub result: Option<DetectionResult>,
    pub risk_score: u8,
    pub mode: InteropMode,
    pub rule_id: Option<String>,
}
```

### InteropMode Location Decision

`InteropMode` currently lives in `waf-engine::interop::mode_registry`. `WafDecision` lives in `waf-common::types`. To avoid circular dependency (`waf-common` cannot depend on `waf-engine`):

**Move `InteropMode` enum to `waf-common::types`**, re-export from `waf-engine::interop`. This is the correct layering — `InteropMode` is a shared primitive, not engine-specific.

```rust
// waf-common/src/types.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InteropMode {
    #[default]
    Enforce,
    LogOnly,
}

impl InteropMode {
    pub const fn as_contract_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::LogOnly => "log_only",
        }
    }

    pub fn from_contract_str(s: &str) -> Option<Self> {
        match s {
            "enforce" => Some(Self::Enforce),
            "log_only" => Some(Self::LogOnly),
            _ => None,
        }
    }
}
```

Then in `waf-engine/src/interop/mode_registry.rs`, replace the enum definition with a re-export:
```rust
pub use waf_common::InteropMode;
```

### Constructor Changes

```rust
impl WafDecision {
    pub fn allow() -> Self {
        Self {
            action: WafAction::Allow,
            result: None,
            risk_score: 0,
            mode: InteropMode::Enforce,
            rule_id: None,
        }
    }

    pub fn block(status: u16, body: Option<String>, result: DetectionResult) -> Self {
        let rule_id = result.rule_id.clone();
        Self {
            action: WafAction::Block { status, body },
            result: Some(result),
            risk_score: 0,
            mode: InteropMode::Enforce,
            rule_id,
        }
    }

    // NEW convenience constructors
    pub fn rate_limit(status: u16, body: Option<String>, result: DetectionResult) -> Self {
        let rule_id = result.rule_id.clone();
        Self {
            action: WafAction::RateLimit { status, body },
            result: Some(result),
            risk_score: 0,
            mode: InteropMode::Enforce,
            rule_id,
        }
    }

    pub fn timeout(status: u16) -> Self {
        Self {
            action: WafAction::Timeout { status },
            result: None,
            risk_score: 0,
            mode: InteropMode::Enforce,
            rule_id: None,
        }
    }

    pub fn circuit_breaker(status: u16, body: Option<String>) -> Self {
        Self {
            action: WafAction::CircuitBreaker { status, body },
            result: None,
            risk_score: 0,
            mode: InteropMode::Enforce,
            rule_id: None,
        }
    }

    // Builder methods
    pub fn with_risk_score(mut self, score: u8) -> Self {
        self.risk_score = score;
        self
    }

    pub fn with_mode(mut self, mode: InteropMode) -> Self {
        self.mode = mode;
        self
    }

    // Mode-aware enforcement check.
    // RT-03 fix: also match WafAction::LogOnly for backward compat during
    // the Phase 3→4 transition window (before engine stops producing LogOnly).
    #[allow(deprecated)]
    pub fn is_enforcement_allowed(&self) -> bool {
        matches!(self.action, WafAction::Allow | WafAction::LogOnly)
            || self.mode == InteropMode::LogOnly
    }

    #[deprecated(note = "use is_enforcement_allowed() — mode-aware")]
    pub fn is_allowed(&self) -> bool {
        self.is_enforcement_allowed()
    }
}
```

**Note:** `const fn` removed from `block()` and new constructors — `Clone` calls are not const-compatible. `allow()` **keeps** `const fn` because it only uses literals and `None` (RT-02 fix). `InteropMode::Enforce` is const-constructible via `#[default]`.

## Related Code Files

**Modify:**
- `crates/waf-common/src/types.rs` — WafDecision struct + constructors + InteropMode enum
- `crates/waf-common/src/lib.rs` — re-export `InteropMode`
- `crates/waf-engine/src/interop/mode_registry.rs` — replace `InteropMode` enum with `pub use waf_common::InteropMode`
- `crates/waf-engine/src/interop/mod.rs` — keep re-export chain intact
- `crates/waf-engine/src/engine.rs` — update 11 struct-init sites to include new fields
- `crates/waf-engine/src/checker.rs` — update struct-init in `check_ip_whitelist`, `check_ip_blacklist`, etc.
- `crates/waf-engine/src/risk/scorer.rs` — ScorerResult doesn't change, but engine integration point needs new fields
- `crates/waf-engine/src/risk/threshold.rs` — returns WafAction, not WafDecision (no change)

**Modify (test struct-inits — RT-01):**
- `crates/gateway/tests/proxy_waf_response_writer.rs` — 8 struct-init sites (lines 119, 191, 217, 248, 285, 321, 347, 373) need 3 new fields
- `crates/waf-common/tests/types_decisions.rs` — 2 struct-init sites (lines 40, 49) need 3 new fields

**No change needed:**
- `proxy_waf_response.rs` — uses `decision.is_allowed()` which still compiles (deprecated wrapper)
- `http3.rs` — same

## Implementation Steps

### 1. Move `InteropMode` to `waf-common/src/types.rs`

Copy the enum definition with `as_contract_str()` and `from_contract_str()`. Add `Default` derive (default = `Enforce`).

### 2. Re-export from `waf-common/src/lib.rs`

```rust
pub use types::InteropMode;
```

### 3. Update `waf-engine/src/interop/mode_registry.rs`

Replace the `InteropMode` enum block with:
```rust
pub use waf_common::InteropMode;
```

Remove the `as_contract_str()` and `from_contract_str()` impls (now in waf-common).

### 4. Add fields to `WafDecision` struct

Add `risk_score`, `mode`, `rule_id` after existing fields.

### 5. Update `WafDecision::allow()` and `block()` constructors

Remove `const` qualifier. Add default values for new fields. Extract `rule_id` from `DetectionResult` in `block()`.

### 6. Add new constructors: `rate_limit()`, `timeout()`, `circuit_breaker()`

### 7. Add builder methods: `with_risk_score()`, `with_mode()`

### 8. Add `is_enforcement_allowed()`, deprecate `is_allowed()`

### 9. Update all struct-init sites in engine.rs

The 11 `WafDecision { action: WafAction::LogOnly, result: Some(result) }` blocks need the 3 new fields. For now, add defaults:

```rust
WafDecision {
    action: WafAction::LogOnly,
    result: Some(result),
    risk_score: 0,
    mode: InteropMode::Enforce,
    rule_id: None,
}
```

Phase 4 will change these to preserve the intended action and set `mode: LogOnly`.

### 10. Update struct-init sites in checker.rs

`check_ip_whitelist` (line 203), `check_ip_blacklist` (line 249), etc. — add 3 new fields with defaults.

### 11. Update struct-inits in test files (RT-01)

Update all `WafDecision { action, result }` patterns in:
- `crates/gateway/tests/proxy_waf_response_writer.rs` (8 sites)
- `crates/waf-common/tests/types_decisions.rs` (2 sites)

Add `risk_score: 0, mode: InteropMode::Enforce, rule_id: None` to each.

### 12. Validate (RT-06: workspace-level, not just waf-common)

Run `cargo check --workspace` — zero errors (catches waf-api import paths).
Run `cargo test --workspace` — Phase 1 enrichment tests pass, existing tests pass.

## Success Criteria

- [x] `InteropMode` lives in `waf-common`, re-exported from `waf-engine::interop`
- [x] `WafDecision` has `risk_score`, `mode`, `rule_id` fields
- [x] `allow()` and `block()` constructors set defaults for new fields
- [x] `rate_limit()`, `timeout()`, `circuit_breaker()` constructors exist
- [x] `with_risk_score()` and `with_mode()` builder methods work
- [x] `is_enforcement_allowed()` is mode-aware; `is_allowed()` deprecated
- [x] All struct-init sites updated
- [x] `cargo check --workspace` passes
- [x] `cargo test -p waf-common` passes (24/24)

## Completion Notes

- `InteropMode` moved to `waf-common/src/types.rs` (with `#[default] Enforce`,
  `as_contract_str`/`from_contract_str`); `waf-engine::interop::mode_registry`
  now re-exports it via `pub use waf_common::InteropMode`. All `interop::`
  import paths and the `ModeRegistry` consumers compile unchanged.
- `allow()`/`timeout()`/`circuit_breaker()`/`with_risk_score()`/`with_mode()`
  kept `const`; `block()`/`rate_limit()` dropped `const` (clone `rule_id`).
- Internal `WafDecision::is_allowed()` callers migrated to
  `is_enforcement_allowed()` (engine.rs ×3, proxy_waf_response.rs ×2,
  http3.rs ×1, waf-common tests ×2) to keep zero deprecation warnings while
  preserving the deprecated wrapper for stored/external consumers (RT-13).
  Behaviour identical this phase — every decision has `mode: Enforce`.
- Struct-init sites updated: engine.rs ×12, checker.rs ×2 (URL-whitelist site
  now also populates `rule_id` from the matched rule), gateway test ×11,
  waf-common test ×2. Enrichment tests in `types_decisions.rs` uncommented.
- Validation: `cargo check --workspace` clean; `cargo clippy` (waf-common,
  waf-engine, gateway, all-targets) zero warnings; `cargo fmt --all --check`
  clean. Engine `*_log_only` integration tests require a Postgres
  testcontainer (no container runtime in this env) — failures are
  environmental, not code regressions; they compiled and ran to DB setup.

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Moving `InteropMode` causes import breakage in waf-engine consumers | Compile error | Re-export from `waf-engine::interop` preserves all import paths |
| Struct-init sites missed | Compile error (safe) | `cargo check --workspace` catches missing fields |
| `const fn` removal breaks something | Unlikely — verified no const-eval dependency | grep for `const { WafDecision::` across workspace |
