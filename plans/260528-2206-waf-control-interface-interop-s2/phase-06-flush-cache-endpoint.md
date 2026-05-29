---
phase: 6
title: "Flush Cache Endpoint"
status: completed
priority: P2
effort: "1-2h"
dependencies: [2]
---

# Phase 6: Flush Cache Endpoint

## Overview

Implement `POST /__waf_control/flush_cache` — clears the response cache so benchmark runs are not affected by stale cached decisions. Reuses existing `ResponseCache::flush()` already proven in `cache_api.rs`.

## Context Links

- Contract 2.6: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 261-272
- Existing cache flush: `crates/waf-api/src/cache_api.rs` -> `cache_flush()`
- Response cache: `crates/gateway/src/cache/store.rs`
- Auth middleware: Phase 2 `./phase-02-benchmark-auth-middleware.md`

## Requirements

**Functional (contract 2.6):**
- Flush response cache synchronously
- Response: `{ "ok": true, "action": "flush_cache", "ts_ms": <epoch_ms> }`
- Idempotent: flushing empty cache returns same success response

**Non-functional:**
- < 50ms (in-memory Moka cache flush)
- Does not affect CrowdSec cache (that's reset_state's job)
- Does not affect any detection state

## Architecture

```
POST /__waf_control/flush_cache
  -> benchmark_secret_guard
  -> flush_cache_handler:
     1. state.cache.flush().await
     2. Return { ok: true, action: "flush_cache", ts_ms: now() }
```

## Related Code Files

**Modify:**
- `crates/waf-api/src/interop_control.rs` — replace stub `flush_cache_handler`

**Read (reference):**
- `crates/waf-api/src/cache_api.rs` — existing flush pattern
- `crates/gateway/src/cache/store.rs` — `ResponseCache::flush()`

**Create:**
- `crates/waf-api/tests/interop_control_flush_cache.rs`

## Implementation Steps

### TDD: Write Tests First

1. Create `crates/waf-api/tests/interop_control_flush_cache.rs`:

```rust
// Test: flush_cache returns correct schema
#[tokio::test]
async fn flush_cache_returns_correct_schema() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/flush_cache", json!({})).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["action"], "flush_cache");
    assert!(body["ts_ms"].is_number());
}

// Test: flush_cache is idempotent
#[tokio::test]
async fn flush_cache_idempotent() {
    let app = test_app_with_interop();
    let r1 = authed_post(&app, "/__waf_control/flush_cache", json!({})).await;
    let r2 = authed_post(&app, "/__waf_control/flush_cache", json!({})).await;
    assert_eq!(r1.status(), 200);
    assert_eq!(r2.status(), 200);
}

// Test: flush_cache actually clears entries
#[tokio::test]
async fn flush_cache_clears_entries() {
    let app = test_app_with_interop();
    // Insert cache entry via test helper
    app.cache().insert_test_entry("key1", b"response").await;
    assert!(app.cache().get("key1").await.is_some());
    authed_post(&app, "/__waf_control/flush_cache", json!({})).await;
    assert!(app.cache().get("key1").await.is_none());
}

// Test: ts_ms is valid epoch milliseconds
#[tokio::test]
async fn flush_cache_ts_ms_is_epoch() {
    let before = epoch_ms_now();
    let body = authed_post_json(&app, "/__waf_control/flush_cache", json!({})).await;
    let after = epoch_ms_now();
    let ts = body["ts_ms"].as_i64().unwrap();
    assert!(ts >= before && ts <= after);
}

// Test: flush_cache requires benchmark secret
#[tokio::test]
async fn flush_cache_requires_auth() {
    let app = test_app_with_interop();
    let resp = app.post("/__waf_control/flush_cache").json(&json!({})).await;
    assert_eq!(resp.status(), 403);
}
```

### Implement

2. Replace `flush_cache_handler` stub in `interop_control.rs`:

```rust
async fn flush_cache_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    state.cache.flush().await;

    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    Json(json!({
        "ok": true,
        "action": "flush_cache",
        "ts_ms": ts_ms,
    }))
}
```

### Validate

3. `cargo check --workspace`
4. `cargo test -p waf-api --test interop_control_flush_cache`
5. `cargo clippy --workspace -- -D warnings`

## Success Criteria

- [ ] Returns `200 OK` with `{ ok: true, action: "flush_cache", ts_ms }`
- [ ] Cache entries cleared after call
- [ ] Idempotent: double-flush returns same success
- [ ] `ts_ms` is valid epoch milliseconds
- [ ] Requires benchmark secret (403 without)
- [ ] Does not touch detection state or CrowdSec cache
- [ ] `cargo check --workspace` passes

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Cache flush takes too long | Low | Moka flush is < 50ms for typical cache sizes |
| Confusion with reset_state | Medium | flush_cache only clears response cache; reset_state clears all runtime state |
