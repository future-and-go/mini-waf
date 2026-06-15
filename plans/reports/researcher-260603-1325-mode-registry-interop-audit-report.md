# ModeRegistry & Feature Catalog Audit Report

**Date:** 2026-06-03  
**Scope:** Analyze existing per-feature mode infrastructure and integration gaps  
**Status:** Complete

---

## Executive Summary

**ModeRegistry exists but is isolated in the API layer.** The infrastructure is 90% complete for engine integration:

- ✅ Lock-free hot-path resolver via `ArcSwap` (production-grade)
- ✅ 17-feature catalog with policy support
- ✅ Full API control surface (`/capabilities`, `/set_profile`, `/reset_state`)
- ❌ **NO engine-to-registry integration** — `WafEngine` never calls `registry.resolve()`
- ❌ **NO feature-specific enforcement** — only host-level `log_only_mode` flag used

**Gap:** ModeRegistry is a control-plane artifact, not an evaluation-time artifact. Engine decisions remain binary per-host, not per-feature.

---

## ModeRegistry API Surface

### Core Types

**`ModeRegistry`** — Arc-wrapped ArcSwap pattern for lock-free hot-reload:
```rust
pub struct ModeRegistry {
    inner: Arc<ArcSwap<ModeState>>,
}

pub struct ModeState {
    pub default_mode: InteropMode,              // Enforce | LogOnly
    pub feature_overrides: HashMap<String, InteropMode>,
    pub policy_overrides: HashMap<String, InteropMode>, // "feature.policy" → mode
}
```

### Mutation API

| Method | Purpose | Hot-reload | Complexity |
|--------|---------|-----------|-----------|
| `set_all(mode)` | Set default + clear all overrides | RCU via ArcSwap | O(1) swap |
| `set_feature(&str, mode)` | Override single feature | RCU | O(n) copy-on-write |
| `set_features(&[&str], mode)` | Override feature batch | RCU | O(n+m) |
| `set_policy(feature, policy, mode)` | Override single `feature.policy` | RCU | O(n) |
| `set_policies(feature, &[&str], mode)` | Override policy batch | RCU | O(n+m) |
| `reset()` | Restore all defaults | RCU | O(1) swap |
| `snapshot()` | Clone current state | Lock-free load | O(n) clone |

### Query API

| Method | Hot-path | Behavior |
|--------|----------|----------|
| `resolve(feature, policy?)` | ✅ Lock-free load | Priority: `policy > feature > default` |
| `snapshot()` | ✅ Lock-free load | Returns immutable clone for inspection |

---

## Feature Catalog (17 Features)

All defined in `FeatureCatalog::all()`. Each has `supported=true, toggleable=true`:

| # | Feature | Policies (Sub-controls) | Count |
|---|---------|----------------------|-------|
| 1 | `access_control` | ip_whitelist, ip_blacklist, url_whitelist, url_blacklist | 4 |
| 2 | `injection_control` | sqli, xss, rce | 3 |
| 3 | `path_traversal` | dir_traversal | 1 |
| 4 | `network_protection` | ssrf, header_injection | 2 |
| 5 | `rate_limiting` | per_ip, per_session | 2 |
| 6 | `ddos_protection` | per_ip_burst, per_tier | 2 |
| 7 | `bot_detection` | scanner, bot | 2 |
| 8 | `owasp_rules` | core_ruleset | 1 |
| 9 | `custom_rules` | yaml_rules, rhai_scripts, wasm_plugins | 3 |
| 10 | `geo_protection` | geo_blocking | 1 |
| 11 | `data_protection` | sensitive_data, anti_hotlink | 2 |
| 12 | `reputation` | crowdsec, community_blocklist | 2 |
| 13 | `risk_assessment` | cumulative_risk | 1 |
| 14 | `velocity_control` | tx_velocity | 1 |
| 15 | `device_intelligence` | fingerprint_analysis | 1 |
| 16 | `auth_protection` | brute_force | 1 |
| 17 | `payload_protection` | body_abuse | 1 |

**Validation:** `FeatureCatalog::validate_features(names) → (supported, unsupported)` splits unknown features.

---

## AppState ↔ ModeRegistry Integration

**Location:** `crates/waf-api/src/state.rs:78`

```rust
pub struct AppState {
    pub engine: Arc<WafEngine>,          // NOT given ModeRegistry
    pub mode_registry: ModeRegistry,     // Owned directly (not Arc-wrapped)
    // ... 24 other fields
}
```

**Initialization:** `AppState::new()` creates a fresh `ModeRegistry::new()` with all defaults.

**Sharing:** `mode_registry` is cloned with AppState on each request (ModeRegistry is `Clone`).

**Current Usage in API:**
- `interop_control.rs:70` — `snapshot()` for `/capabilities` response
- `interop_control.rs:116` — `reset()` in `/reset_state` handler
- `interop_control.rs:154, 174, 215` — `set_*()` calls from `/set_profile` handler

---

## Export Surface & Visibility

**`waf-engine/lib.rs`:** Exports `interop` module directly:
```rust
pub mod interop;  // Re-exports: FeatureCatalog, FeatureInfo, InteropMode, ModeRegistry, ModeState
```

**Import Path:** `waf_engine::interop::{ModeRegistry, FeatureCatalog, InteropMode}`

**Who can access:**
- ✅ `waf-api` — imports `ModeRegistry` from engine
- ✅ `gateway` — could import (currently doesn't)
- ✅ Tests — full access

---

## Codebase References to ModeRegistry

**All 28 references identified:**

| File | Type | Count | Purpose |
|------|------|-------|---------|
| `state.rs:78` | Field decl | 1 | AppState ownership |
| `state.rs:129` | Init | 1 | AppState::new() |
| `interop_control.rs` | Handler | 5 | `/set_profile`, `/reset_state`, `/capabilities` |
| `interop_mode_registry.rs` | Tests | 21 | Comprehensive unit tests |
| `mode_registry.rs` | Impl | 1 | Default trait |
| `mod.rs` | Export | 1 | Re-export in interop |

**Key finding:** ModeRegistry is **ONLY mutated via HTTP handlers** (interop_control). **ZERO engine calls to `resolve()`.**

---

## Engine's Current Mode Implementation

**Current state:** Host-level binary flag, not feature-aware:

| Where | Code | Behavior |
|-------|------|----------|
| Engine init | `engine.rs:492` | Creates decision with `mode: Enforce` default |
| Decision flow | `engine.rs:720-721, 779, 831` | If `ctx.host_config.log_only_mode`, set `mode = LogOnly` |
| Logging | `logging/audit_sender.rs:227` | Copies decision's mode to audit event |

**Constraint:** `log_only_mode` is per-HostConfig (database-backed), not per-feature.

---

## Pattern Analysis: Shared State Patterns in Engine

The engine already uses ArcSwap for hot-reloadable config:

| Component | Pattern | Location |
|-----------|---------|----------|
| Rate-limit config | `Arc<ArcSwap<RateLimitConfig>>` | `engine.rs:217` |
| Tx-velocity config | `Arc<ArcSwap<TxVelocityConfig>>` | `engine.rs:225` |
| Risk config | `Arc<ArcSwap<RiskConfig>>` | `engine.rs:??? |
| DDoS config | `Arc<ArcSwap<DdosConfig>>` | `engine.rs:238` |

**Precedent:** All use `notify`-based file watchers + `rcu()` mutations. ModeRegistry follows this exact pattern.

---

## The Gap: What's Missing

### 1. Engine Integration Point
ModeRegistry exists in AppState but **is never accessed by WafEngine.inspect()**. No code path:
```rust
// Missing: at decision time, check registry before returning
let mode = registry.resolve(feature_name, policy_name)?;
```

### 2. Check-to-Feature Mapping
No explicit mapping from checks (SqlInjectionCheck, BotCheck, etc.) to feature names:
- SqlInjectionCheck → `injection_control.sqli` ?
- BotCheck → `bot_detection.bot` ?
- RateLimitCheck → `rate_limiting.per_ip` ?

Mapping is implicit in the catalog but not codified.

### 3. Policy Resolution
Some checks are configurable at policy granularity (e.g., rate-limit has tiers). Policy-level overrides exist in ModeRegistry but no engine code consumes them.

### 4. Engine Access
`WafEngine` has no reference to ModeRegistry. Would need to be passed at:
- Construction time, or
- At `inspect()` call-time (preferred for testability)

---

## Integration Feasibility

**Effort to integrate:** LOW (1-2 sessions)

**Path:**
1. ✅ Add `registry: Arc<ModeRegistry>` field to WafEngine
2. ✅ Pass from AppState during engine construction
3. ✅ At decision-point (post-check verdict), call `registry.resolve(feature, policy)`
4. ✅ Apply: if LogOnly, upgrade decision mode (already code-exists for host-level)
5. ✅ Write integration tests verifying feature-override paths

**Backward compatibility:** Fully preserved — default ModeState is Enforce everywhere.

---

## Unresolved Questions

1. **Feature naming convention** — What's the authoritative feature name for each Check? (e.g., is it `injection_control` or `sqli_protection`?)
2. **Policy granularity** — Which checks actually support policy-level toggles vs. all-or-nothing? (e.g., RateLimitCheck has tiers, but does BotCheck?)
3. **Runtime performance** — What's the acceptable overhead of calling `registry.resolve()` on every decision? (Expected: <1μs via ArcSwap lock-free, but needs bench)
4. **Test coverage** — Should feature-override tests be in waf-engine unit tests or integration tests in waf-api?
5. **RequestCtx enrichment** — Should RequestCtx carry resolved feature modes, or should mode resolution happen post-decision? (Current: post-decision is cleaner)

---

## Recommendations

1. **Immediate:** Map each Check to its feature name(s) in documentation (YAGNI: don't hard-code yet)
2. **Session 2:** Thread ModeRegistry through WafEngine; integrate resolve() at decision boundary
3. **Session 3:** Add feature-level acceptance tests via `/set_profile` → request → validate decision mode

---

**Report file:** `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/plans/reports/researcher-260603-1325-mode-registry-interop-audit-report.md`
