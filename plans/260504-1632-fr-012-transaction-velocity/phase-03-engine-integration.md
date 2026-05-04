---
phase: 3
title: "Engine Integration"
status: completed
priority: P1
effort: "0.5d"
dependencies: [2]
---

# Phase 3: Engine Integration

## Overview

Plug `TxVelocityCheck` into engine checker chain. Wire config loading at startup. Wire request context (path, status, session_key) into recorder.

## Requirements

**Functional:**
- `TxVelocityCheck` implements `Check` trait
- Inserted in `engine.rs:111-118` checker chain after rate-limit, before scanner
- Reads role from RoleTagger, extracts SessionKey, calls `Recorder::record(...)`
- Returns `None` (no direct block) — signals only

**Non-functional:**
- Zero allocations in hot path beyond unavoidable cookie/path slicing
- `Check::check()` returns within 100µs (verified Phase 4 bench)

## Architecture

```
engine.rs checker chain:
  RateLimitCheck → TxVelocityCheck → ScannerCheck → BotCheck → ...
                          │
                          ├─ tag role from path
                          ├─ extract SessionKey
                          └─ recorder.record(key, Event { role, ts_ms, ok })
```

`ok` derived from request stage. Note: at request-entry we don't yet have response status. Decision: use `ok = true` initially; track failed-login via response phase hook OR rely on absence of subsequent endpoint as failure signal.

**Pragmatic for hackathon:** Phase 3 records on request-entry only with `ok = true`. Response-side enrichment deferred (note in unresolved questions).

## Related Code Files

**Create:**
- `crates/waf-engine/src/checks/tx_velocity/check.rs` — `Check` trait impl

**Modify:**
- `crates/waf-engine/src/checks/tx_velocity/mod.rs` — pub re-export `TxVelocityCheck`
- `crates/waf-engine/src/engine.rs` — register check (~line 111-118)
- `crates/waf-engine/src/lib.rs` — if config loading happens here

**Reference:**
- `crates/waf-engine/src/checker.rs` — Check trait signature
- `crates/waf-engine/src/checks/rate_limit/check.rs` — registration pattern

## Implementation Steps

1. **Implement `Check` trait** (`check.rs`):
   ```rust
   pub struct TxVelocityCheck {
       config: Arc<ArcSwap<TxVelocityConfig>>,
       tagger: Arc<RoleTagger>,
       recorder: Arc<TxStore>,
   }

   impl Check for TxVelocityCheck {
       fn name(&self) -> &'static str { "tx_velocity" }
       fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
           let role = self.tagger.classify(ctx.path);
           if role == EndpointRole::None { return None; }
           let key = SessionKey::extract(ctx, &self.config.load())?;
           let now = now_ms();
           self.recorder.record(key, Event { role, ts_ms: now, ok: true });
           None  // signal-only, never blocks here
       }
   }
   ```

2. **Engine wire-up** (`engine.rs`):
   - Construct `TxVelocityCheck` with shared config + aggregator
   - Push into checker Vec after rate-limit, before scanner
   - Mirror pattern of `RateLimitCheck` registration

3. **Config loading**:
   - Load YAML on startup; spawn `notify` watcher to refresh `ArcSwap`
   - Construct classifier list from config
   - Construct recorder with classifier list + aggregator handle

4. **Verify** with `cargo run` against test backend:
   - Hit `/api/login` then `/api/otp` then `/api/deposit` rapidly
   - Confirm signal logged (debug log) — no block

## Todo List

- [x] Implement `TxVelocityCheck` struct + `Check` impl
- [x] Construct check with config + tagger + recorder + aggregator
- [x] Register in engine.rs checker chain (correct position)
- [x] Wire config file loading + notify watcher
- [x] Create default config file `configs/tx-velocity.yaml`
- [ ] Smoke test: synthetic Login→OTP→Deposit triggers signal in logs
- [x] `cargo build --release` clean

## Success Criteria

- [ ] `TxVelocityCheck` registered in engine
- [ ] Synthetic fast sequence emits signal (verify via debug log)
- [ ] No regression: existing checks still pass `cargo test -p waf-engine`
- [ ] No `.unwrap()` in production code
- [ ] Hot-reload tested: edit YAML → role tagger picks up new path within 1s

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Check ordering wrong — classified before rate-limit | Place AFTER rate-limit so blocked traffic doesn't pollute state |
| Adding check breaks engine init signature | Use builder/options pattern; default-off if config missing |
| `ok=true` always misses failed-login signal | Document; defer to response-phase enrichment in follow-up |

## Security Considerations

- If config missing/malformed, fail-safe: disable check (log warning), don't crash WAF (Iron Rule #4 + FR-037 fail-open for non-CRITICAL)
- For CRITICAL tier routes, document that this check is signal-only and risk engine handles fail-close
