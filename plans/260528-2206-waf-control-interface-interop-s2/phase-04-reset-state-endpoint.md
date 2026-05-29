---
phase: 4
title: "Reset State Endpoint"
status: completed
priority: P1
effort: "4-6h"
dependencies: [2]
---

# Phase 4: Reset State Endpoint

## Overview

Implement `POST /__waf_control/reset_state` — clears all temporary runtime state across 10+ subsystems without touching the audit log or static configuration. Must be synchronous and atomic: success response only after full clear.

## Context Links

- Contract §2.4: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 97–131
- State mapping (scout report): All 15 state components identified with clear methods
- Compliance report §1.2: `plans/reports/researcher-260528-2206-waf-control-contract-compliance-analysis-report.md` §1.2
- Existing cache flush: `crates/waf-api/src/cache_api.rs` → `cache_flush()`

## Requirements

**Functional (contract §2.4):**
- Clear: rate-limit counters, DDoS ban table + counters, risk scorer state, challenge/session state, response cache, behavioral anomaly state, tx velocity state, device fingerprint identity store, CrowdSec decision cache
- MUST NOT modify `./waf_audit.log` or audit log pipeline
- MUST NOT reset static config (rules, access lists, detection engines)
- Response: `{ "ok": true, "action": "reset_state", "audit_log_preserved": true, "ts_ms": <epoch_ms> }`
- Synchronous: success only after ALL state cleared

**Non-functional:**
- Total reset time should be < 500ms (all stores are in-memory)
- Idempotent: calling reset twice produces same result
- Thread-safe: in-flight requests may see pre or post state, never partial

## Architecture

```
POST /__waf_control/reset_state
  → benchmark_secret_guard
  → reset_state_handler:
     1. engine.reset_runtime_state().await     // clears all engine-internal stores
     2. state.cache.flush().await              // response cache
     3. state.crowdsec_cache?.clear_all()      // CrowdSec decisions
     4. mode_registry.reset()                  // back to default enforce
     5. Return { ok: true, ts_ms: now() }
```

### State Components to Clear

| Component | Location | Method | Arc Accessible |
|-----------|----------|--------|----------------|
| Rate limit store | `checks/rate_limit/store/memory.rs` | `clear_all()` (NEW) | Via WafEngine |
| DDoS ban table | `checks/ddos/action/ban.rs` | `clear()` (NEW) | `engine.ddos_ban_table()` |
| DDoS counter store | `checks/ddos/store/memory.rs` | `clear_all()` (NEW) | Via WafEngine |
| TX velocity store | `checks/tx_velocity/recorder.rs` | `clear_all()` (NEW) | `engine.tx_velocity_store` |
| Risk scorer store | `risk/store/memory.rs` | `reset_all()` (EXISTS) | Via WafEngine |
| Behavior recorder | `device_fp/behavior/recorder.rs` | `clear_all()` (NEW) | Via WafEngine |
| Identity store | `device_fp/identity/memory.rs` | `clear_all()` (NEW) | Via WafEngine |
| Response cache | `gateway/cache/store.rs` | `flush()` (EXISTS) | `state.cache` |
| CrowdSec cache | `crowdsec/cache.rs` | `clear_all()` (NEW) | `state.crowdsec_cache` |
| Mode registry | interop/mode_registry.rs | `reset()` (Phase 1) | `state.mode_registry` |

## Related Code Files

**Create:**
- `crates/waf-api/tests/interop_control_reset_state.rs`

**Modify:**
- `crates/waf-engine/src/engine.rs` — add `pub async fn reset_runtime_state(&self)`
- `crates/waf-engine/src/checks/rate_limit/store/mod.rs` — add `clear_all()` to trait
- `crates/waf-engine/src/checks/rate_limit/store/memory.rs` — implement `clear_all()`
- `crates/waf-engine/src/checks/ddos/action/ban.rs` — add `clear()` to DynamicBanTable
- `crates/waf-engine/src/checks/ddos/store/mod.rs` — add `clear_all()` to CounterStore trait
- `crates/waf-engine/src/checks/ddos/store/memory.rs` — implement `clear_all()`
- `crates/waf-engine/src/checks/tx_velocity/recorder.rs` — add `clear_all()` to TxStore
- `crates/waf-engine/src/device_fp/behavior/recorder.rs` — add `clear_all()` to Recorder
- `crates/waf-engine/src/device_fp/identity/identity_trait.rs` — add `clear_all()` to IdentityStore trait
- `crates/waf-engine/src/device_fp/identity/memory.rs` — implement `clear_all()`
- `crates/waf-engine/src/crowdsec/cache.rs` — add `clear_all()` to DecisionCache
- `crates/waf-api/src/interop_control.rs` — replace stub `reset_state_handler`

## Implementation Steps

### TDD: Write Tests First

1. Add `clear_all()` test to each store's existing test module:

```rust
// In rate_limit/store/memory.rs tests:
#[tokio::test]
async fn clear_all_empties_store() {
    let store = MemoryStore::new();
    let cfg = test_cfg();
    store.check_and_consume("key1", &cfg, 1000).await.unwrap();
    store.check_and_consume("key2", &cfg, 1000).await.unwrap();
    store.clear_all().await.unwrap();
    // Next check should behave as if fresh (full burst capacity)
    let result = store.check_and_consume("key1", &cfg, 2000).await.unwrap();
    assert_eq!(result, Decision::Allow);
}
```

```rust
// In ddos/action/ban.rs tests:
#[test]
fn clear_empties_ban_table() {
    let table = DynamicBanTable::new();
    table.insert("1.2.3.4".parse().unwrap(), i64::MAX);
    assert!(!table.is_empty());
    table.clear();
    assert!(table.is_empty());
}
```

```rust
// In crowdsec/cache.rs tests:
#[test]
fn clear_all_empties_all_tiers() {
    let cache = DecisionCache::new();
    cache.add_ip_decision("1.2.3.4".parse().unwrap(), /* decision */);
    cache.clear_all();
    assert_eq!(cache.total_cached(), 0);
}
```

2. Create `crates/waf-api/tests/interop_control_reset_state.rs`:

```rust
// Test: reset_state returns correct schema
#[tokio::test]
async fn reset_state_returns_correct_schema() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/reset_state", json!({})).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["action"], "reset_state");
    assert_eq!(body["audit_log_preserved"], true);
    assert!(body["ts_ms"].is_number());
}

// Test: reset_state clears mode registry
#[tokio::test]
async fn reset_state_clears_mode_overrides() {
    let app = test_app_with_interop();
    app.mode_registry().set_feature("injection_control", InteropMode::LogOnly);
    authed_post(&app, "/__waf_control/reset_state", json!({})).await;
    let snap = app.mode_registry().snapshot();
    assert!(snap.feature_overrides.is_empty());
    assert_eq!(snap.default_mode, InteropMode::Enforce);
}

// Test: reset_state clears response cache
#[tokio::test]
async fn reset_state_flushes_cache() {
    let app = test_app_with_interop();
    // Insert a cache entry, reset, verify miss
    // (uses ResponseCache test fixtures)
}

// Test: reset_state is idempotent
#[tokio::test]
async fn reset_state_idempotent() {
    let app = test_app_with_interop();
    let r1 = authed_post(&app, "/__waf_control/reset_state", json!({})).await;
    let r2 = authed_post(&app, "/__waf_control/reset_state", json!({})).await;
    assert_eq!(r1.status(), 200);
    assert_eq!(r2.status(), 200);
}

// Test: ts_ms is valid epoch milliseconds
#[tokio::test]
async fn reset_state_ts_ms_is_epoch() {
    let before = epoch_ms_now();
    let body = authed_post_json(&app, "/__waf_control/reset_state", json!({})).await;
    let after = epoch_ms_now();
    let ts = body["ts_ms"].as_i64().unwrap();
    assert!(ts >= before && ts <= after);
}
```

### Implement

3. Add `clear_all()` method to each store trait and implementation:

**RateLimitStore trait** (`checks/rate_limit/store/mod.rs`):
```rust
async fn clear_all(&self) -> anyhow::Result<()>;
```

**MemoryStore** (`checks/rate_limit/store/memory.rs`):
```rust
async fn clear_all(&self) -> anyhow::Result<()> {
    self.buckets.clear();
    Ok(())
}
```

**DynamicBanTable** (`checks/ddos/action/ban.rs`):
```rust
pub fn clear(&self) {
    self.entries.clear();
}
```

**CounterStore trait** (`checks/ddos/store/mod.rs`):
```rust
async fn clear_all(&self) -> anyhow::Result<()>;
```

**MemoryCounterStore** (`checks/ddos/store/memory.rs`):
```rust
async fn clear_all(&self) -> anyhow::Result<()> {
    self.entries.clear();
    Ok(())
}
```

**TxStore** (`checks/tx_velocity/recorder.rs`):
```rust
pub fn clear_all(&self) {
    self.actors.clear();
}
```

**Recorder** (`device_fp/behavior/recorder.rs`):
```rust
pub fn clear_all(&self) {
    self.actors.clear();
}
```

**IdentityStore trait** (`device_fp/identity/identity_trait.rs`):
```rust
async fn clear_all(&self) -> anyhow::Result<()>;
```

**MemoryIdentityStore** (`device_fp/identity/memory.rs`):
```rust
async fn clear_all(&self) -> anyhow::Result<()> {
    self.entries.clear();
    Ok(())
}
```

**DecisionCache** (`crowdsec/cache.rs`):
```rust
pub fn clear_all(&self) {
    self.ip_decisions.clear();
    self.other_decisions.clear();
    if let Ok(mut ranges) = self.range_decisions.write() {
        ranges.clear();
    }
    self.hits.store(0, Ordering::Relaxed);
    self.misses.store(0, Ordering::Relaxed);
    self.total_cached.store(0, Ordering::Relaxed);
}
```

4. Add `reset_runtime_state()` to `WafEngine` (`engine.rs`):

```rust
pub async fn reset_runtime_state(&self) -> anyhow::Result<()> {
    // Rate limit store (inside first checker)
    for checker in &self.checkers {
        checker.reset_state();
    }

    // DDoS ban table
    self.ddos_check.ban_table().clear();

    // TX velocity store
    self.tx_velocity_store.clear_all();

    // Risk store (if connected)
    // ... will need to expose risk_store or add reset to scorer

    // CrowdSec cache cleared at API layer (not engine)
    // Response cache cleared at API layer (not engine)

    Ok(())
}
```

> **Design note:** Since many stores are private inside `WafEngine`, the cleanest approach is to add a `fn reset_state(&self)` method to the `Check` trait with a default no-op, and override it in `RateLimitCheck`, `TxVelocityCheck`, `BotCheck`, etc. This way `reset_runtime_state()` just iterates `self.checkers` and calls `reset_state()` on each.

5. Add `reset_state()` to `Check` trait (`checker.rs` or `checks/mod.rs`):
```rust
fn reset_state(&self) {
    // Default no-op — override in checks that hold runtime state
}
```

6. Replace `reset_state_handler` stub in `interop_control.rs`:

```rust
async fn reset_state_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // 1. Engine internal state
    if let Err(e) = state.engine.reset_runtime_state().await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
            "ok": false, "error": format!("engine reset failed: {e}")
        }))).into_response();
    }

    // 2. Response cache
    state.cache.flush().await;

    // 3. CrowdSec cache
    if let Some(cc) = &state.crowdsec_cache {
        cc.clear_all();
    }

    // 4. Mode registry back to default
    state.mode_registry.reset();

    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    Json(json!({
        "ok": true,
        "action": "reset_state",
        "audit_log_preserved": true,
        "ts_ms": ts_ms,
    })).into_response()
}
```

### Validate

7. `cargo check --workspace`
8. `cargo test --workspace` (all existing tests must still pass)
9. `cargo test -p waf-api --test interop_control_reset_state`
10. `cargo test -p waf-engine` (store `clear_all()` unit tests)

## Success Criteria

- [ ] `clear_all()` added to RateLimitStore, CounterStore, IdentityStore traits
- [ ] `clear()` added to DynamicBanTable, TxStore, Recorder
- [ ] `clear_all()` added to DecisionCache
- [ ] `Check` trait has `reset_state()` with default no-op
- [ ] `WafEngine::reset_runtime_state()` orchestrates all internal clears
- [ ] Handler calls engine reset + cache flush + CrowdSec clear + mode reset
- [ ] Response matches contract schema exactly
- [ ] `audit_log_preserved: true` always returned
- [ ] `ts_ms` is valid epoch milliseconds
- [ ] Existing tests still pass (no regression)
- [ ] Idempotent: double-reset produces same result

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Missing a store during reset | High | Scout identified 15 components; each gets explicit clear |
| Store lacks `clear_all()` | Medium | Add to trait with default `Ok(())` for backwards compat |
| Background janitor re-populates after clear | Low | Janitors only purge expired; clearing an empty store is no-op |
| In-flight request sees partial state | Medium | Sequential clear is atomic per-store; full atomicity deferred to Phase 7 integration test |
| Redis-backed stores need clear too | Medium | `clear_all()` added to trait; Redis impl sends FLUSHDB or DEL pattern |
