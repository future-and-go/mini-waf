---
phase: 3
title: "Defer classifier eval to on_response"
status: complete
priority: P1
effort: "6-8h"
dependencies: [2]
---

# Phase 3: Defer classifier eval to on_response

## Overview

Today `TxStore::record()` appends an event AND runs classifiers in one go, with `ok = true` hard-coded at request entry. This phase splits the two halves AND incorporates red-team adjudications:

- **`Event.outcome`** is now tristate (`Outcome::{Pending, Ok, Failed}`) instead of `bool`. Classifiers count only `Ok | Failed` and ignore `Pending`. WAF-blocked / streaming-abandoned / dropped-connection events stay `Pending` forever → no ring poisoning, no false-positive bursts. *(Red-team C6.)*
- **`record()`** returns a `TxEventToken { key, slot, generation }`. The generation defeats the slot-was-evicted race. *(Red-team C1.)*
- **`record()`** also collapses a same-key + same-role Pending event within `dedupe_window_ms` (default 5s) into the existing slot instead of appending — defuses mobile retry storms. *(Red-team C9.)*
- **`set_outcome(token, outcome)`** flips that exact slot (if the generation still matches) and runs classifiers. *(Red-team C1.)*
- **`TxVelocityCheck::on_request_complete()`** (new trait method — see Phase 5 step 5.0) reads the token from `RequestCtx` (set by `check()`), maps `(status, upstream_reached)` → `Outcome::Ok | Failed | skip`, calls `set_outcome`.

Closes the `check.rs:60` "deferred to a follow-up phase" comment.

## Requirements

- **Functional**:
  - Request-entry path records an event with `ok = false` placeholder.
  - Upstream 2xx response → `ok` flipped to `true` on that event before classifiers see it.
  - Upstream non-2xx (4xx, 5xx) → `ok` stays `false`.
  - Classifier pipeline runs exactly once per event — on response, not on request.
  - Cooldown logic (`signal_cooldown_ms`) still applies, gated on `last_signal_ms` as before.
- **Non-functional**:
  - No new lock contention beyond the existing `DashMap` entry guard.
  - Hot path: `record()` becomes cheaper (no classifier work); `on_response()` shoulders the classifier cost, off the critical pre-upstream path.
  - `Event.outcome: Outcome` replaces `Event.ok: bool` (same width — single byte tag).

## Architecture

```
REQUEST ENTRY
─────────────
TxVelocityCheck::check(ctx)
  ├─ session_key = extract_session_key(ctx, cookie, device_fp)?       ← phase-02 wiring
  ├─ store.record(&session_key, role)
  │    └─ append Event { role, ts_ms, ok: false }    ← NO classifier eval
  └─ return None  (signal-only)

RESPONSE
────────
WafEngine::on_response(ctx, status)
  └─ for check in &self.checkers { check.on_request_complete(ctx, status, upstream_reached); }
       └─ TxVelocityCheck::on_request_complete(ctx, status, upstream_reached)
            ├─ if !snapshot.enabled → return
            ├─ role = role_tagger.classify(&ctx.path)
            ├─ if matches!(role, EndpointRole::None) → return
            ├─ key = extract_session_key(ctx, cookie, device_fp)?
            ├─ ok = (200..300).contains(&status)
            └─ store.set_outcome(&key, role, ok)
                 ├─ shard-guard: find most-recent slot matching `role` in the ring,
                 │  flip its `ok` to `ok`; release guard.
                 ├─ cooldown gate (now_ms - last_signal_ms < cfg.signal_cooldown_ms)
                 ├─ snapshot the ring (lock-free clone)
                 ├─ run classifiers on the snapshot
                 ├─ if signals non-empty:
                 │    ├─ mark_signal(now_ms)
                 │    └─ tokio::spawn aggregator.submit(fp_key, signals)
                 └─ done.
```

### Token-based `set_outcome` (Red-team C1)

```rust
// In waf-common (so RequestCtx can carry it without an engine dep):
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxEventToken {
    pub key: SessionKey,
    pub slot: u8,         // 0..WINDOW
    pub generation: u32,  // ActorTx.generation at record() time
}

pub fn set_outcome(&self, tok: &TxEventToken, outcome: Outcome) {
    let Some(mut entry) = self.actors.get_mut(&tok.key) else { return; };
    if entry.generation != tok.generation {
        return; // ring wrapped; slot was evicted; clean no-op
    }
    if let Some(slot) = entry.events.get_mut(tok.slot as usize)
        && let Some(ev) = slot.as_mut()
    {
        ev.outcome = outcome;
    }
    // Drop guard before classifier work — same pattern record() used.
    drop(entry);
    // cooldown + snapshot + classifier dispatch follow…
}
```

`ActorTx` gains `pub generation: u32` (bumped on every full ring wrap — i.e. when `head` rolls back to 0 with `len == WINDOW`).

### Tristate `Outcome` (Red-team C6)

```rust
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Outcome {
    #[default]
    Pending,
    Ok,
    Failed,
}

pub struct Event {
    pub role: EndpointRole,
    pub ts_ms: u64,
    pub outcome: Outcome,   // was: ok: bool
}
```

- `record()` writes `Outcome::Pending`.
- `set_outcome(token, Outcome::Ok | Failed)` flips it.
- Classifiers filter `outcome != Outcome::Pending` before counting — Pending events never feed velocity / sequence checks. WAF-blocked / streaming-abandoned events stay Pending forever and never poison the ring.
- Janitor purges actors past `session_ttl_secs` regardless of Pending vs settled — so Pending events can't accumulate beyond TTL.

### Retry-dedupe in `record()` (Red-team C9)

```rust
pub fn record(&self, key: &SessionKey, role: EndpointRole) -> TxEventToken {
    let cfg = self.cfg.load();
    let now_ms = self.now_ms();
    let dedupe_window_ms = cfg.dedupe_window_ms;   // new cfg field, default 5_000

    let mut entry = self.actors.entry(key.clone()).or_default();
    // Newest slot for this (key, role) within dedupe window AND still Pending?
    let newest_idx = if entry.len == 0 { None } else {
        Some((entry.head + WINDOW - 1) % WINDOW)
    };
    if let Some(idx) = newest_idx
        && let Some(Some(ev)) = entry.events.get(idx)
        && ev.role == role
        && ev.outcome == Outcome::Pending
        && now_ms.saturating_sub(ev.ts_ms) <= dedupe_window_ms
    {
        // Reuse the existing slot — refresh ts_ms only.
        if let Some(slot) = entry.events.get_mut(idx)
            && let Some(ev) = slot.as_mut()
        { ev.ts_ms = now_ms; }
        return TxEventToken {
            key: key.clone(),
            slot: idx as u8,
            generation: entry.generation,
        };
    }
    // Otherwise: append a new Pending event, return its token.
    let event = Event { role, ts_ms: now_ms, outcome: Outcome::Pending };
    let slot = entry.head;
    entry.record(event);   // existing ring-append logic; bumps generation on wrap
    TxEventToken {
        key: key.clone(),
        slot: slot as u8,
        generation: entry.generation,
    }
}
```

Defuses the mobile-retry storm: 4 retries for one logical withdrawal collapse to ONE Pending slot; the eventual 2xx flips that slot to `Ok` — classifier sees `count=1 ok_count=1`, not `count=4 ok_count=1`.

## Related Code Files

- **Add** `crates/waf-common/src/types.rs` — `TxEventToken` + `Outcome` types (so `RequestCtx` can carry the token without a `waf-engine` dep).
- **Modify** `crates/waf-engine/src/checks/tx_velocity/mod.rs` — `Event.ok: bool` → `Event.outcome: Outcome`.
- **Modify** `crates/waf-engine/src/checks/tx_velocity/recorder.rs`:
  - `ActorTx` gains `pub generation: u32`; bumped on full ring wrap inside `ActorTx::record`.
  - `TxStore::record(&self, key, role) -> TxEventToken` — append-only (or dedupe-collapse), returns token. Drop the `ok` parameter; events default to `Outcome::Pending`.
  - Add `TxStore::set_outcome(&self, tok: &TxEventToken, outcome: Outcome)` — flips the exact slot when generation matches, runs classifiers.
- **Modify** `crates/waf-engine/src/checks/tx_velocity/check.rs`:
  - `check()` — store the returned token into `ctx.tx_velocity_token` (note: `Check::check` currently takes `&RequestCtx`; this phase must widen the trait signature OR use interior mutability via a `Cell`. See Step 3.4 below.)
  - Implement `Check::on_response(&self, ctx: &RequestCtx, status: u16)` — reads token, calls `set_outcome`.
  - Delete the "response-side enrichment deferred" comment block.
- **Modify** `crates/waf-engine/src/checks/tx_velocity/classifier.rs` (or wherever classifier trait lives) — classifiers must filter `outcome != Outcome::Pending` before counting.
- **Modify** `crates/waf-engine/src/checks/tx_velocity/config.rs` — add `pub dedupe_window_ms: u64` (default `5_000`) to `TxVelocityConfig`.
- **Modify** `crates/waf-engine/src/checks/tx_velocity/session_key.rs` — `SessionIdent::Fingerprint { fp, ip }` (Phase 2 already covered the enum change; session_key.rs holds the constructor).
- **Read** `crates/waf-engine/src/checks/brute_force.rs:125-152` — reference shape for `on_response`.
- **Read** `crates/waf-engine/src/engine.rs:856-861` — `on_response` dispatch loop already calls every checker.
- **Read** `crates/waf-engine/src/checks/mod.rs:60` — `Check::on_response` default no-op already exists.

### Enumerated `record()` call sites — 27 total (Red-team C3)

This signature change cascades. Every site must move to the token-returning shape.

**Production**
1. `crates/waf-engine/src/checks/tx_velocity/check.rs:61`

**Recorder unit tests** (`crates/waf-engine/src/checks/tx_velocity/recorder.rs`)
2. `:306` `record_skips_role_none`
3. `:315` `record_appends_for_known_role`
4. `:326` `ring_caps_at_window_and_drops_oldest`
5. `:336` `mark_signal_updates_cooldown_marker`
6. `:347` `purge_expired_removes_idle_actors`
7. `:357` `purge_keeps_fresh_actors`
8. `:373` `concurrent_inserts_no_panic`
9. `:431` `pipeline_emits_signal_on_velocity_breach`
10. `:459` `pipeline_cooldown_suppresses_duplicate_signals` (×2)
11. `:464` (second loop in #10)
12. `:491` `pipeline_disabled_skips_classifier_submission`
13. `:515` `pipeline_uses_fingerprint_when_session_is_fp`

**Integration tests** (`crates/waf-engine/tests/tx_velocity_integration.rs`)
14–25. `:116, :123, :158, :188, :215, :220, :246, :275, :299, :305, :329, :376`

**Benches** (`crates/waf-engine/benches/tx_velocity_bench.rs`)
26. `:61` (+ `:81, :101, :137, :158, :191` — all callers in the bench harness)
27. Bench callers collapse to one mechanical sed: append `let _ = ` (token discarded for bench timing) OR rewrite the bench to also call `set_outcome` so the measured path is realistic.

`cargo check -p waf-engine --all-targets` after the signature change is the authoritative gate.

## TDD Steps

### Step 3.1 — failing test: record() no longer evaluates classifiers

Add to `crates/waf-engine/src/checks/tx_velocity/recorder.rs` `mod tests`:

```rust
#[tokio::test]
async fn record_alone_emits_no_signal_even_on_breach() {
    // With eval moved to set_outcome, calling record() three times
    // (breach threshold) MUST NOT submit — events are all Pending and
    // classifiers ignore Pending events.
    let cfg = cfg_pipeline(0);
    let agg = LoggingAggregator::new(8);
    let store = TxStore::with_pipeline(
        cfg,
        default_classifiers(&TxVelocityConfig::default()),
        Arc::new(agg.clone()),
    );

    let k = key("noeval");
    for _ in 0..3 {
        let _ = store.record(&k, EndpointRole::Withdrawal);
    }
    flush().await;
    assert!(agg.snapshot().is_empty(), "record() must not run classifiers");
}

#[tokio::test]
async fn set_outcome_runs_classifiers_with_real_outcome() {
    let cfg = cfg_pipeline(0);
    let agg = LoggingAggregator::new(8);
    let store = TxStore::with_pipeline(
        cfg,
        default_classifiers(&TxVelocityConfig::default()),
        Arc::new(agg.clone()),
    );

    let k = key("setoutcome");
    for _ in 0..3 {
        let tok = store.record(&k, EndpointRole::Withdrawal);
        // Settle each Pending immediately so dedupe doesn't collapse them.
        store.set_outcome(&tok, Outcome::Ok);
    }
    flush().await;

    assert!(
        !agg.snapshot().is_empty(),
        "set_outcome must drive classifier eval"
    );
}

#[tokio::test]
async fn set_outcome_flips_exact_slot_by_token() {
    let cfg = cfg_pipeline(60_000);  // suppress signal noise
    let store = TxStore::new(cfg);
    let k = key("flip-by-token");

    let t1 = store.record(&k, EndpointRole::Withdrawal);
    // Settle t1 BEFORE next record so dedupe doesn't collapse.
    store.set_outcome(&t1, Outcome::Failed);
    let _ = store.record(&k, EndpointRole::Otp);
    let t3 = store.record(&k, EndpointRole::Withdrawal);
    store.set_outcome(&t3, Outcome::Ok);

    let snap = store.snapshot(&k).expect("snapshot");
    let withdrawals: Vec<_> = snap.events.iter().filter(|e| e.role == EndpointRole::Withdrawal).collect();
    assert_eq!(withdrawals.len(), 2);
    // Oldest→newest iteration: first Withdrawal is Failed, last is Ok.
    assert_eq!(withdrawals.first().expect("first").outcome, Outcome::Failed);
    assert_eq!(withdrawals.last().expect("last").outcome, Outcome::Ok);
}

#[tokio::test]
async fn set_outcome_with_unknown_token_is_noop() {
    let cfg = cfg_pipeline(0);
    let store = TxStore::new(cfg);
    // Fabricate a token whose key was never recorded.
    let ghost = TxEventToken {
        key: key("ghost"),
        slot: 0,
        generation: 0,
    };
    store.set_outcome(&ghost, Outcome::Ok);  // must not panic
    assert!(store.is_empty());
}
```

Run: `cargo test -p waf-engine recorder::tests::record_alone_emits_no_signal_even_on_breach`. **Expected: fails** — current `record()` still evaluates inline.

### Step 3.2 — failing test: TxVelocityCheck::on_request_complete wires the outcome

Add to `crates/waf-engine/src/checks/tx_velocity/check.rs` `mod tests`:

```rust
use crate::checks::Check;

#[tokio::test]
async fn on_request_complete_2xx_marks_event_ok() {
    let cfg = cfg_enabled(
        "SID",
        &[RoleRule { role: EndpointRole::Withdrawal, path: "^/api/withdraw".to_string() }],
    );
    let store = Arc::new(TxStore::new(Arc::clone(&cfg)));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = ctx_with_path_and_cookie("/api/withdraw", "SID", "u-1");
    check.check(&mut ctx);                                  // appends Pending, sets tx_velocity_token
    check.on_request_complete(&ctx, 200, /* upstream_reached */ true);  // flips to Ok

    let key = SessionKey {
        host: ctx.host.clone(),
        ident: SessionIdent::Cookie("u-1".to_string()),
    };
    let snap = store.snapshot(&key).expect("snapshot");
    assert_eq!(snap.events.len(), 1);
    assert_eq!(snap.events.first().expect("ev").outcome, Outcome::Ok);
}

#[tokio::test]
async fn on_request_complete_4xx_marks_event_failed() {
    let cfg = cfg_enabled(
        "SID",
        &[RoleRule { role: EndpointRole::Withdrawal, path: "^/api/withdraw".to_string() }],
    );
    let store = Arc::new(TxStore::new(Arc::clone(&cfg)));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = ctx_with_path_and_cookie("/api/withdraw", "SID", "u-2");
    check.check(&mut ctx);
    check.on_request_complete(&ctx, 403, /* upstream_reached */ true);

    let key = SessionKey {
        host: ctx.host.clone(),
        ident: SessionIdent::Cookie("u-2".to_string()),
    };
    let snap = store.snapshot(&key).expect("snapshot");
    assert_eq!(snap.events.first().expect("ev").outcome, Outcome::Failed);
}

#[tokio::test]
async fn on_request_complete_origin_unreached_leaves_pending() {
    let cfg = cfg_enabled(
        "SID",
        &[RoleRule { role: EndpointRole::Withdrawal, path: "^/api/withdraw".to_string() }],
    );
    let store = Arc::new(TxStore::new(Arc::clone(&cfg)));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = ctx_with_path_and_cookie("/api/withdraw", "SID", "u-orig-down");
    check.check(&mut ctx);
    // Pingora-synthesized 502 (origin down). MUST stay Pending.
    check.on_request_complete(&ctx, 502, /* upstream_reached */ false);

    let key = SessionKey {
        host: ctx.host.clone(),
        ident: SessionIdent::Cookie("u-orig-down".to_string()),
    };
    let snap = store.snapshot(&key).expect("snapshot");
    assert_eq!(snap.events.first().expect("ev").outcome, Outcome::Pending);
}

#[tokio::test]
async fn on_request_complete_unmatched_path_no_token_is_noop() {
    let cfg = cfg_enabled(
        "SID",
        &[RoleRule { role: EndpointRole::Withdrawal, path: "^/api/withdraw".to_string() }],
    );
    let store = Arc::new(TxStore::new(Arc::clone(&cfg)));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    // No `check()` call → no token → on_request_complete is a clean no-op.
    let ctx = ctx_with_path_and_cookie("/api/other", "SID", "u-3");
    check.on_request_complete(&ctx, 200, true);
    assert!(store.is_empty());
}
```

Run: **Expected: fails** — `TxVelocityCheck` does not yet implement `on_request_complete` (added in Phase 5 step 5.0 — the trait method does not exist yet at Phase 3 start; this is intentional, and Phase 3 lands the trait extension as a prerequisite if Phase 5 isn't already underway).

### Step 3.3 — implement set_outcome + retool record()

In `crates/waf-engine/src/checks/tx_velocity/recorder.rs`:

1. **`Event` shape:** `pub outcome: Outcome` replaces `pub ok: bool` in `crates/waf-engine/src/checks/tx_velocity/mod.rs` (the `Event` struct).
2. **`ActorTx`** gains `pub generation: u32`. Increment inside `ActorTx::record` whenever a wrap happens — i.e. when `len == WINDOW` and an append overwrites slot 0 again. Simplest: `if self.head == 0 && self.len == WINDOW { self.generation = self.generation.wrapping_add(1); }`.
3. **Change `pub fn record(&self, key: &SessionKey, role: EndpointRole, ok: bool)` → `pub fn record(&self, key: &SessionKey, role: EndpointRole) -> TxEventToken`.** Inside, set `Event { outcome: Outcome::Pending, … }`. Apply the dedupe-collapse logic shown earlier. Return the `TxEventToken { key, slot, generation }`. Delete everything after the append — no classifier eval here.
4. **Implement `pub fn set_outcome(&self, tok: &TxEventToken, outcome: Outcome)`:**
   - Acquire `actors.get_mut(&tok.key)`. If absent → no-op.
   - If `entry.generation != tok.generation` → no-op (slot evicted).
   - Otherwise: `entry.events[tok.slot as usize].as_mut().outcome = outcome;`
   - Drop the guard.
   - Run the cooldown + snapshot + classifier dispatch loop that previously lived in `record()`.
   - Use the existing `fp_key_for_submission` helper and `tokio::spawn` for the aggregator submit.
5. The existing `mark_signal` helper is reused inside `set_outcome` — no change.

### Step 3.4 — implement on_response on TxVelocityCheck

The `Check::check` trait currently takes `&RequestCtx`, so it cannot write `tx_velocity_token` back. Two routes:

**Route A (preferred):** widen the trait to `&mut RequestCtx`. Every existing `Check::check` impl is stateless on `ctx` — verified by grep. Easy mechanical change.

**Route B:** keep `&RequestCtx`; have `RequestCtx.tx_velocity_token` be a `Cell<Option<TxEventToken>>` (interior mutability). Slightly uglier, but avoids touching every check.

Pick Route A — explicit > magic. Grep first: `grep -rn "fn check(&self, ctx:" crates/waf-engine/src/checks/` — count the impls (~15). All are `&RequestCtx`; flip them to `&mut RequestCtx` in one mechanical sweep.

```rust
impl Check for TxVelocityCheck {
    fn check(&self, ctx: &mut RequestCtx) -> Option<DetectionResult> {
        let snapshot = self.cfg.load();
        if !snapshot.enabled { return None; }
        let role = snapshot.role_tagger.classify(&ctx.path);
        if matches!(role, super::EndpointRole::None) { return None; }
        let key = extract_session_key(
            ctx,
            &snapshot.session_cookie,
            ctx.device_fp.as_deref(),
            ctx.client_ip,
        )?;
        let token = self.store.record(&key, role);
        ctx.tx_velocity_token = Some(token);
        None
    }

    fn on_request_complete(&self, ctx: &RequestCtx, status: u16, upstream_reached: bool) {
        let snapshot = self.cfg.load();
        if !snapshot.enabled { return; }
        let Some(token) = ctx.tx_velocity_token.as_ref() else { return; };
        // Pingora-synthesized responses (WAF gate block, origin down, TLS fail)
        // are NOT user denials — leave the event Pending. Red-team C2 + C6.
        if !upstream_reached { return; }
        let outcome = if (200..300).contains(&status) {
            Outcome::Ok
        } else {
            Outcome::Failed
        };
        self.store.set_outcome(token, outcome);
    }

    fn reset_state(&self) { self.store.clear_all(); }
}
```

Note `on_request_complete` no longer re-classifies role or re-extracts session key — the token captures both. **(Red-team C12 — hot-reload between `check` and request completion can no longer orphan events.)**

### Step 3.5 — port existing pipeline tests

Existing tests in `recorder.rs:419-524` need a two-step rewrite — `record()` returns a token, `set_outcome()` takes that token:

```rust
// BEFORE
store.record(&k, EndpointRole::Withdrawal, true);

// AFTER (typical case — settle each immediately to avoid dedupe collapse)
let tok = store.record(&k, EndpointRole::Withdrawal);
store.set_outcome(&tok, Outcome::Ok);
```

Per-test deltas:
- `pipeline_emits_signal_on_velocity_breach` → apply the two-step rewrite for each `record()` call. Example: `store.record(&k, EndpointRole::Withdrawal, true);` becomes `let tok = store.record(&k, EndpointRole::Withdrawal); store.set_outcome(&tok, Outcome::Ok);`.
- `pipeline_cooldown_suppresses_duplicate_signals` → same.
- `pipeline_disabled_skips_classifier_submission` → same.
- `pipeline_uses_fingerprint_when_session_is_fp` → same.

Module-level callers in `check.rs::tests` that use `store.record(...)`: mechanical rewrite. The 27 enumerated call sites in "Related Code Files" cover the full sweep.

### Step 3.6 — ring wraparound test (Red-team C15)

Add to `recorder.rs::tests`:

```rust
#[tokio::test]
async fn set_outcome_no_op_when_slot_wraps_out_from_under_token() {
    let cfg = cfg_pipeline(60_000);
    let store = TxStore::new(cfg);
    let k = key("wrap");

    // First record → token for slot 0, generation 0.
    let token = store.record(&k, EndpointRole::Withdrawal);

    // Fill 17 more events (WINDOW=16) — ring wraps once, generation = 1.
    for _ in 0..17 {
        let _ = store.record(&k, EndpointRole::Otp);
    }

    // Token's generation is stale; set_outcome must no-op cleanly.
    store.set_outcome(&token, Outcome::Ok);

    // Original Pending event is gone; only Otp events remain.
    let snap = store.snapshot(&k).expect("snapshot");
    assert!(snap.events.iter().all(|e| e.role == EndpointRole::Otp));
}

#[tokio::test]
async fn record_dedupes_pending_within_window() {
    let cfg = Arc::new(ArcSwap::from_pointee(TxVelocityConfig {
        dedupe_window_ms: 5_000,
        ..TxVelocityConfig::default()
    }));
    let store = TxStore::new(cfg);
    let k = key("retry");

    let t1 = store.record(&k, EndpointRole::Withdrawal);
    let t2 = store.record(&k, EndpointRole::Withdrawal);  // 0ms later, still Pending → dedupe
    assert_eq!(t1.slot, t2.slot, "dedupe must reuse the same slot");

    let snap = store.snapshot(&k).expect("snapshot");
    assert_eq!(snap.events.len(), 1, "retry must NOT append");
}

#[tokio::test]
async fn record_does_not_dedupe_after_set_outcome() {
    let cfg = Arc::new(ArcSwap::from_pointee(TxVelocityConfig {
        dedupe_window_ms: 5_000,
        ..TxVelocityConfig::default()
    }));
    let store = TxStore::new(cfg);
    let k = key("settled");

    let t1 = store.record(&k, EndpointRole::Withdrawal);
    store.set_outcome(&t1, Outcome::Ok);
    let _t2 = store.record(&k, EndpointRole::Withdrawal);  // settled → new slot

    let snap = store.snapshot(&k).expect("snapshot");
    assert_eq!(snap.events.len(), 2, "settled outcome must NOT trigger dedupe");
}

#[tokio::test]
async fn classifier_ignores_pending_events() {
    let cfg = cfg_pipeline(0);
    let agg = LoggingAggregator::new(8);
    let store = TxStore::with_pipeline(
        cfg,
        default_classifiers(&TxVelocityConfig::default()),
        Arc::new(agg.clone()),
    );
    let k = key("waf-blocked");

    // Three Pending events, none ever settle (simulates WAF gate-blocked requests).
    for _ in 0..3 {
        let _ = store.record(&k, EndpointRole::Withdrawal);
    }
    flush().await;

    assert!(agg.snapshot().is_empty(), "Pending events must NOT count toward velocity");
}
```

### Step 3.7 — tokio runtime note (Red-team C10)

`set_outcome` still spawns the aggregator submit via `tokio::spawn` (preserved from existing recorder). Any test calling `check.on_request_complete()` MUST be `#[tokio::test]`, not plain `#[test]`. New tests in this phase are already async-marked; verify no plain `#[test]` slipped in during the port.

### Step 3.8 — run

```bash
cargo test -p waf-engine tx_velocity
cargo test -p waf-engine on_response
cargo test --workspace
```

## Success Criteria

- [ ] All four new `recorder.rs` tests pass (`record_alone_emits_no_signal_even_on_breach`, `set_outcome_runs_classifiers_with_real_outcome`, `set_outcome_flips_exact_slot_by_token`, `set_outcome_with_unknown_token_is_noop`).
- [ ] All four new `check.rs` `on_request_complete_*` tests pass.
- [ ] All four new wraparound/dedupe/pending tests in Step 3.6 pass (`set_outcome_no_op_when_slot_wraps_out_from_under_token`, `record_dedupes_pending_within_window`, `record_does_not_dedupe_after_set_outcome`, `classifier_ignores_pending_events`).
- [ ] All previously-existing `tx_velocity` tests pass after the mechanical record→record+set_outcome rewrite (27 sites).
- [ ] `grep -n "response-side enrichment deferred" crates/waf-engine/src/checks/tx_velocity/check.rs` returns empty.
- [ ] `grep -rn "store.record(.*true)\|store.record(.*false)" crates/` returns empty (no caller still passes the old `ok` parameter).
- [ ] `grep -n "Event { ok\|\.ok = \|ev\.ok" crates/waf-engine/src/checks/tx_velocity/` returns empty (no stale field name in code or tests).
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] Iron Rule #1 — no `.unwrap()` outside tests.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| `set_outcome` walks 16 ring slots — measurable cost on hot response path | 16 array reads + role compare is sub-microsecond. Hot path was previously doing classifier eval; this is strictly cheaper. |
| Concurrent requests for same session race the `last withdrawal` slot | Single in-flight HTTP request per session is the dominant case. Race produces wrong-event flip in a corner case (multi-tab user). Documented; not blocking. |
| Cooldown semantics shift — was "cooldown since record", now "cooldown since set_outcome" | **NOT functionally equivalent (Red-team C14).** Signal emit moves T_request → T_response (T_request + upstream RTT). Out-of-order completions can interleave such that the strict-less-than cooldown check (`recorder.rs:191`) lets a boundary-case duplicate signal through. Documented. Default cooldown should be raised to `2× p99 upstream RTT` if telemetry shows duplicate signals. |
| Engine `on_response` not called when request blocked at WAF gate (e.g. by earlier check) | Event stays with `outcome=Failed (or Pending)`, classifiers never see it. **This is the correct behavior** — a blocked request is not a successful withdrawal. Documented. |
| Engine `on_response` not called from `prx-waf` integration tests that bypass the gateway | All call sites of `engine.evaluate` should pair with `engine.on_response` in production paths. Tests that don't are fine — they're testing the request path only. |

## Notes

After this phase, both `check.rs:55` and `check.rs:60` TODOs are closed. Phase-04 enriches the `Signal` payload with `ok_count`; phase-05 wires `engine.on_response` into the gateway response path (already done for FR-018, just verify FR-012 rides the same call).
