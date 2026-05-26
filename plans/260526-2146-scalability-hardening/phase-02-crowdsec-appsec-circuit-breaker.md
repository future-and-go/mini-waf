---
phase: 2
title: "CrowdSec AppSec Circuit Breaker"
finding: F3
status: pending
priority: P1
effort: "3h"
dependencies: []
---

# Phase 2: CrowdSec AppSec Circuit Breaker

## Overview

`AppSecClient::check_request_inner()` (appsec.rs:78) fires HTTP POST per request with no circuit breaker. On endpoint slowness, every request queues behind the timeout — cascade failure. Config schema exists (`circuit_breaker_threshold`, `circuit_breaker_reset_secs` at config.rs:400-404) but NOT wired to AppSec.

## Key Insights

- `AppSecConfig` has `timeout_ms` (per-request timeout) but no failure tracking
- **RED-TEAM FIX**: existing `circuit_breaker_threshold` and `circuit_breaker_reset_secs` belong to `ValkeyClientConfig` (config.rs:399-404), NOT `AppSecConfig`. Must add new fields to `AppSecConfig` (crowdsec/config.rs:82-93) with `#[serde(default)]` for backward compat
- On failure, `check_request()` (appsec.rs:44-51) returns `AppSecResult::Unavailable` — caller applies `failure_action`; CB should short-circuit to same result
- **RED-TEAM FIX**: `check_request_inner()` returns `Ok(Unavailable)` for HTTP 401/500/bad-status — these must ALSO trigger `on_failure()`, not just `Err` results. Otherwise persistent 500s never trip the circuit
- **RED-TEAM FIX**: Put `failure_count` inside the mutex (not separate `AtomicU32`) to avoid TOCTOU race between count check and state transition
- **RED-TEAM FIX**: Clamp threshold to minimum 1 in constructor (threshold=0 is ambiguous)
- Research recommends custom state machine (~50 LOC) over dead external crates
- `parking_lot::Mutex` already in workspace; ~10ns per lock

## Requirements

**Functional:**
- Track consecutive failures (timeout/network error) against threshold from config
- After N failures: open circuit, return `AppSecResult::Unavailable` immediately
- After `reset_secs`: transition to HalfOpen, allow 1 probe request
- On probe success: close. On probe fail: reopen.

**Non-functional:**
- Hot-path overhead < 20ns (single mutex lock + state check)
- Zero allocation in check path
- Thread-safe via `parking_lot::Mutex`

## Architecture

**State machine:**
```
         success
   ┌──────────────────┐
   v                  |
Closed ──N fails──> Open ──reset_secs──> HalfOpen
   ^                                       |
   └──────── probe success ────────────────┘
                  probe fail ──> Open
```

**Data flow (hot path):**
```
check_request()
  → cb.check_allow()?
    → Open: return Unavailable immediately (0 HTTP calls)
    → Closed/HalfOpen: proceed to HTTP POST
  → HTTP result
    → Ok: cb.on_success()
    → Err: cb.on_failure()
```

## Related Code Files

| File | Action | LOC Est. | Test Impact |
|------|--------|----------|-------------|
| `crates/waf-engine/src/crowdsec/circuit_breaker.rs` | Create | ~80 | 5 new tests |
| `crates/waf-engine/src/crowdsec/appsec.rs` | Modify | ~15 changed | Update existing tests |
| `crates/waf-engine/src/crowdsec/mod.rs` | Modify | +1 line | — |

## Tests Before (TDD)

Write these FIRST in `circuit_breaker.rs`:

1. **Test: starts Closed, allows requests**
   - `AppSecCircuitBreaker::new(threshold=3, reset_secs=30)`
   - Assert: `check_allow()` → `true`

2. **Test: N consecutive failures open circuit**
   - `on_failure()` x3 (threshold=3)
   - Assert: `check_allow()` → `false`

3. **Test: Open transitions to HalfOpen after reset_secs**
   - Open circuit, advance past reset duration
   - Assert: `check_allow()` → `true` (HalfOpen probe)

4. **Test: HalfOpen success closes circuit**
   - Transition to HalfOpen, call `on_success()`
   - Assert: `check_allow()` → `true`, failure_count reset

5. **Test: HalfOpen failure reopens**
   - Transition to HalfOpen, call `on_failure()`
   - Assert: `check_allow()` → `false`

## Implementation Steps

1. **Create `crates/waf-engine/src/crowdsec/circuit_breaker.rs`**:

   ```rust
   use std::time::{Duration, Instant};
   use parking_lot::Mutex;

   #[derive(Debug, Clone, Copy, PartialEq)]
   enum CircuitState {
       Closed { failure_count: u32 },
       Open { opened_at: Instant },
       HalfOpen,
   }

   pub struct AppSecCircuitBreaker {
       state: Mutex<CircuitState>,  // failure_count INSIDE mutex (RED-TEAM: avoids TOCTOU)
       threshold: u32,
       reset_duration: Duration,
   }

   impl AppSecCircuitBreaker {
       pub fn new(threshold: u32, reset_secs: u64) -> Self {
           Self {
               state: Mutex::new(CircuitState::Closed { failure_count: 0 }),
               threshold: threshold.max(1),  // RED-TEAM: clamp to min 1
               reset_duration: Duration::from_secs(reset_secs),
           }
       }
       pub fn check_allow(&self) -> bool { ... }
       pub fn on_success(&self) { ... }
       pub fn on_failure(&self) { ... }
   }
   ```

2. **Register module** in `crates/waf-engine/src/crowdsec/mod.rs`:
   - Add `pub mod circuit_breaker;`

3. **Integrate into `AppSecClient`** (appsec.rs:26-51):
   - Add `circuit_breaker: AppSecCircuitBreaker` field to struct (line 26-29)
   - In `new()` (line 32-37): init from `config.circuit_breaker_threshold`, `config.circuit_breaker_reset_secs`
   - Wrap `check_request()`:

   ```rust
   pub async fn check_request(&self, ctx: &RequestCtx) -> AppSecResult {
       if !self.circuit_breaker.check_allow() {
           warn!("AppSec circuit breaker OPEN; returning fallback");
           return AppSecResult::Unavailable;
       }
       match self.check_request_inner(ctx).await {
           Ok(AppSecResult::Unavailable) => {
               // RED-TEAM: HTTP 401/500/bad-status returns Ok(Unavailable) — treat as failure
               self.circuit_breaker.on_failure();
               AppSecResult::Unavailable
           }
           Ok(r) => { self.circuit_breaker.on_success(); r }
           Err(e) => {
               warn!("AppSec check error: {}", e);
               self.circuit_breaker.on_failure();
               AppSecResult::Unavailable
           }
       }
   }
   ```

4. **Add config fields** to `AppSecConfig` (crowdsec/config.rs:82-93):
   ```rust
   #[serde(default = "default_cb_threshold")]
   pub circuit_breaker_threshold: u32,  // default 5
   #[serde(default = "default_cb_reset_secs")]
   pub circuit_breaker_reset_secs: u64, // default 30
   ```
   With `#[serde(default)]` for backward compat — existing config files without these fields use defaults.

## Refactor

Changes to `appsec.rs` (~15 lines):
- Add field to struct
- Init in `new()`
- Replace `check_request()` body with CB-wrapped version (see above)

## Tests After (TDD)

1. **Test: success after N-1 failures keeps circuit Closed**
   - 2 failures then 1 success (threshold=3)
   - Assert: circuit stays Closed, failure_count reset

2. **Test: concurrent access is safe**
   - Spawn 10 threads calling `on_failure()` simultaneously
   - Assert: no panic, state consistent

## Regression Gate

```bash
cargo check -p waf-engine
cargo test -p waf-engine -- crowdsec
cargo test -p waf-engine -- circuit_breaker
```

## Success Criteria

- [ ] `AppSecCircuitBreaker` with Closed/Open/HalfOpen states
- [ ] Wired to existing config fields (no new config schema)
- [ ] `check_request()` short-circuits when Open
- [ ] 5+ new unit tests passing
- [ ] Existing 3 AppSec tests still pass
- [ ] `cargo check -p waf-engine` clean

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Circuit opens too aggressively | Medium | Medium | Threshold=5 default is conservative; tunable |
| HalfOpen probe during DDoS | Low | Low | Single probe; fails → reopen |
| `parking_lot::Mutex` contention | Very Low | Low | Lock held <10ns, no alloc inside |

## Test Scenario Matrix

| Scenario | Priority | Type |
|----------|----------|------|
| Closed → N fails → Open | Critical | Unit |
| Open → timeout → HalfOpen → success → Closed | Critical | Unit |
| HalfOpen → failure → Open | High | Unit |
| Success resets failure count | High | Unit |
| Concurrent multi-thread access | Medium | Unit |
| threshold=0 edge case | Medium | Unit |

## Dependency Map

- **Depends on**: nothing
- **Blocks**: Phase 7 (integration)
- **File ownership**: `crates/waf-engine/src/crowdsec/` — exclusive to this phase
