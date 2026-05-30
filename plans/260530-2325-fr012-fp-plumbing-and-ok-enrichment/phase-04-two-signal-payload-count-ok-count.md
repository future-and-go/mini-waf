---
phase: 4
title: "Two-signal payload (count + ok_count)"
status: complete
priority: P2
effort: "2h"
dependencies: [3]
---

# Phase 4: Two-signal payload (count + ok_count)

## Overview

Now that `Event.outcome` is honest (phase-03 — `Outcome::{Pending, Ok, Failed}`), expose it in the emitted signal. `Signal::WithdrawalVelocity` and `Signal::LimitChangeBurst` each gain an `ok_count: u32` field next to `count: u32`. Classifiers now also filter out `Outcome::Pending` events from both counters (request-in-flight / WAF-blocked events never feed velocity calculations). Risk scorers (FR-025) can then weight "3 of 3 withdrawals succeeded" differently from "3 of 3 denied withdrawals" — the original gap from the user prompt.

## Requirements

- **Functional**:
  - `Signal::WithdrawalVelocity { count, ok_count, window_sec }` — `count` is settled events (`Ok | Failed`) in the window, `ok_count` is the subset where `ev.outcome == Outcome::Ok`. `Pending` events are excluded from both. Always `ok_count <= count`.
  - `Signal::LimitChangeBurst { count, ok_count, window_sec }` — same shape.
  - `Signal::name()` strings unchanged (`"withdrawal_velocity"`, `"limit_change_burst"`).
- **Non-functional**:
  - Existing consumers using `Signal::WithdrawalVelocity { count, .. }` (with `..` rest pattern) continue to compile. Any consumer using exhaustive destructuring `{ count, window_sec }` becomes a compile error — intentional.

## Architecture

```
classifier evaluate()
  ├─ count    = events.filter(role == X && ts in window).count()
  ├─ count    = events.filter(role==X && ts in window && outcome != Pending).count()
  ├─ ok_count = events.filter(role==X && ts in window && outcome == Ok).count()
  └─ if count > max → emit Signal::WithdrawalVelocity { count, ok_count, window_sec }
```

`evaluate_velocity` returns `(count, ok_count, window_sec)` — one more u32 in the tuple. `LimitChangeBurst` reuses the same helper, so the fix lands once.

## Related Code Files

- **Modify** `crates/waf-engine/src/device_fp/signal.rs:50-53` — add `ok_count: u32` to both variants. Add doc-comment per Red-team C11.
- **Modify** `crates/waf-engine/src/checks/tx_velocity/classifiers/withdrawal_velocity.rs` — helper signature + variant construction + `debug_assert!(ok_count <= count)` (Red-team C13).
- **Modify** `crates/waf-engine/src/checks/tx_velocity/classifiers/limit_change_burst.rs` — variant construction.
- **Modify** `crates/waf-engine/src/risk/ingest/signal_to_contributor.rs:193-200` **(Red-team C4 — promoted from Read to Modify)** — exhaustively constructs `Signal::WithdrawalVelocity { count: 5, window_sec: 60 }` AND `Signal::LimitChangeBurst { count: 3, window_sec: 60 }`. Both must gain `ok_count: 5` / `ok_count: 3` (set to equal `count` for back-compat — FR-025 weighting on `ok_count` is opt-in for the team that owns risk scoring).
- **Modify** existing tests in those classifier files — expand expected `Signal` literals to include `ok_count`.
- **Read** `crates/waf-engine/src/device_fp/aggregator/logging.rs` — test util; uses `Debug`, no destructure breakage expected.

## TDD Steps

### Step 4.1 — failing test: signal carries ok_count

Add to `crates/waf-engine/src/checks/tx_velocity/classifiers/withdrawal_velocity.rs` `mod tests`:

```rust
#[test]
fn ok_count_reflects_event_outcome() {
    use crate::checks::tx_velocity::{Event, Outcome};
    let events = vec![
        Event { role: EndpointRole::Withdrawal, ts_ms: 100, outcome: Outcome::Ok },
        Event { role: EndpointRole::Withdrawal, ts_ms: 200, outcome: Outcome::Failed },
        Event { role: EndpointRole::Withdrawal, ts_ms: 300, outcome: Outcome::Ok },
        Event { role: EndpointRole::Withdrawal, ts_ms: 400, outcome: Outcome::Ok },
    ];
    let snap = ActorTxSnapshot { events, updated_ms: 400, last_signal_ms: 0 };
    let out = WithdrawalVelocityClassifier.evaluate(&snap, 500, &cfg_with(3, 60_000));
    assert_eq!(
        out,
        Some(Signal::WithdrawalVelocity { count: 4, ok_count: 3, window_sec: 60 }),
    );
}

#[test]
fn ok_count_zero_when_all_events_denied() {
    use crate::checks::tx_velocity::{Event, Outcome};
    let events = vec![
        Event { role: EndpointRole::Withdrawal, ts_ms: 100, outcome: Outcome::Failed },
        Event { role: EndpointRole::Withdrawal, ts_ms: 200, outcome: Outcome::Failed },
        Event { role: EndpointRole::Withdrawal, ts_ms: 300, outcome: Outcome::Failed },
        Event { role: EndpointRole::Withdrawal, ts_ms: 400, outcome: Outcome::Failed },
    ];
    let snap = ActorTxSnapshot { events, updated_ms: 400, last_signal_ms: 0 };
    let out = WithdrawalVelocityClassifier.evaluate(&snap, 500, &cfg_with(3, 60_000));
    assert_eq!(
        out,
        Some(Signal::WithdrawalVelocity { count: 4, ok_count: 0, window_sec: 60 }),
        "denied-burst must still fire (count > max) but signal ok_count = 0",
    );
}

#[test]
fn pending_events_excluded_from_count_and_ok_count() {
    use crate::checks::tx_velocity::{Event, Outcome};
    let events = vec![
        Event { role: EndpointRole::Withdrawal, ts_ms: 100, outcome: Outcome::Pending }, // in-flight
        Event { role: EndpointRole::Withdrawal, ts_ms: 200, outcome: Outcome::Ok },
        Event { role: EndpointRole::Withdrawal, ts_ms: 300, outcome: Outcome::Ok },
        Event { role: EndpointRole::Withdrawal, ts_ms: 400, outcome: Outcome::Pending }, // in-flight
    ];
    let snap = ActorTxSnapshot { events, updated_ms: 400, last_signal_ms: 0 };
    let out = WithdrawalVelocityClassifier.evaluate(&snap, 500, &cfg_with(1, 60_000));
    assert_eq!(
        out,
        Some(Signal::WithdrawalVelocity { count: 2, ok_count: 2, window_sec: 60 }),
        "Pending events must not feed the velocity counters",
    );
}
```

Run: **Expected: fails to compile** — `ok_count` field unknown on the variant.

Add a mirror test in `crates/waf-engine/src/checks/tx_velocity/classifiers/limit_change_burst.rs`:

```rust
#[test]
fn limit_change_signal_carries_ok_count() {
    use crate::checks::tx_velocity::{Event, Outcome};
    let events = vec![
        Event { role: EndpointRole::LimitChange, ts_ms: 100, outcome: Outcome::Ok },
        Event { role: EndpointRole::LimitChange, ts_ms: 200, outcome: Outcome::Failed },
        Event { role: EndpointRole::LimitChange, ts_ms: 300, outcome: Outcome::Ok },
    ];
    let snap = ActorTxSnapshot { events, updated_ms: 300, last_signal_ms: 0 };
    let out = LimitChangeBurstClassifier.evaluate(&snap, 400, &cfg_with(2, 60_000));
    assert_eq!(
        out,
        Some(Signal::LimitChangeBurst { count: 3, ok_count: 2, window_sec: 60 }),
    );
}
```

### Step 4.2 — extend Signal variants

In `crates/waf-engine/src/device_fp/signal.rs`:

```rust
// BEFORE
WithdrawalVelocity { count: u32, window_sec: u32 },
LimitChangeBurst { count: u32, window_sec: u32 },

// AFTER — with mandatory doc comment per Red-team C11
/// Burst of withdrawal-tagged requests within `window_sec`.
///
/// `count` is total attempts in the trailing window; `ok_count` is the
/// subset where the upstream returned 2xx. Both are bounded by the
/// recorder's ring buffer (`WINDOW = 16`) — so the ratio is a WINDOW-LOCAL
/// success indicator, NOT a lifetime success rate. Long-tail accounts will
/// see ring eviction; risk scorers must not treat `ok_count / count` as
/// the actor's true acceptance rate.
WithdrawalVelocity { count: u32, ok_count: u32, window_sec: u32 },

/// Burst of limit-change requests within `window_sec`. Same `count`/`ok_count`
/// caveat as `WithdrawalVelocity`.
LimitChangeBurst { count: u32, ok_count: u32, window_sec: u32 },
```

`name()` arm pattern uses `..` already (`Self::WithdrawalVelocity { .. }`) — unchanged.

### Step 4.3 — extend evaluate_velocity

In `crates/waf-engine/src/checks/tx_velocity/classifiers/withdrawal_velocity.rs`:

```rust
pub(super) fn evaluate_velocity(
    snap: &ActorTxSnapshot,
    now_ms: u64,
    cfg: &VelocityCfg,
    role: EndpointRole,
) -> Option<(u32, u32, u32)> {       // (count, ok_count, window_sec)
    if cfg.window_ms == 0 { return None; }
    let cutoff = now_ms.saturating_sub(cfg.window_ms);
    // Filter Pending out (Red-team C6) AND apply the role + window predicates.
    let (count, ok_count) = snap.events.iter()
        .filter(|e| e.role == role && e.ts_ms >= cutoff && e.outcome != Outcome::Pending)
        .fold((0u32, 0u32), |(c, ok), ev| {
            (
                c.saturating_add(1),
                ok.saturating_add(u32::from(ev.outcome == Outcome::Ok)),
            )
        });
    debug_assert!(ok_count <= count, "ok_count <= count invariant violated");  // Red-team C13
    if count > cfg.max_count {
        let window_sec: u32 = u32::try_from(cfg.window_ms.div_ceil(1_000)).unwrap_or(u32::MAX);
        Some((count, ok_count, window_sec))
    } else {
        None
    }
}
```

The `.fold` keeps the iterator chain idiomatic (Red-team C26 stylistic note), preserves saturating arithmetic on both counters, and tightens the predicate to ignore `Outcome::Pending` events.

Update both classifier `evaluate()` calls:

```rust
// withdrawal_velocity.rs
.map(|(count, ok_count, window_sec)| Signal::WithdrawalVelocity { count, ok_count, window_sec })

// limit_change_burst.rs
.map(|(count, ok_count, window_sec)| Signal::LimitChangeBurst { count, ok_count, window_sec })
```

### Step 4.4 — update existing classifier test expectations

Existing tests assert on `Signal::WithdrawalVelocity { count: N, window_sec: M }` literals. Each becomes `{ count: N, ok_count: K, window_sec: M }` where K is the count of `Outcome::Ok` events in the test snapshot. Where the fixture sets every event to `Outcome::Ok`, `ok_count == count`. Walk through and update — straightforward.

### Step 4.5 — grep-sweep downstream consumers

Split the grep into two passes (Red-team C4 — pattern-matches vs constructions are different beasts):

```bash
# Pass 1 — destructuring matchers (look for `{ ... }` after the variant)
grep -rn "Signal::WithdrawalVelocity {\|Signal::LimitChangeBurst {" crates/ --include="*.rs" | grep -v target

# Pass 2 — constructions vs matches: anything with `count:` in the brace expression
grep -rn "Signal::WithdrawalVelocity {.*count:\|Signal::LimitChangeBurst {.*count:" crates/ --include="*.rs" | grep -v target
```

For every hit:
- **Matcher with `..` rest** (e.g. `Signal::WithdrawalVelocity { count, .. }`) → no change.
- **Exhaustive matcher** (e.g. `Signal::WithdrawalVelocity { count, window_sec }`) → add `ok_count`.
- **Construction** (e.g. `Signal::WithdrawalVelocity { count: 5, window_sec: 60 }`) → add `ok_count: 5` (mirroring `count` is safe and back-compat).

Verified sites that need work:
- `crates/waf-engine/src/risk/ingest/signal_to_contributor.rs:193-200` — exhaustive constructions in test fixtures.
- `crates/waf-engine/src/checks/tx_velocity/classifiers/withdrawal_velocity.rs::tests` — every existing assert literal.
- `crates/waf-engine/src/checks/tx_velocity/classifiers/limit_change_burst.rs::tests` — same.
- `crates/waf-engine/src/checks/tx_velocity/recorder.rs::tests` (pipeline_* tests destructure `signals.first()`) — most use `..` rest already; verify.

### Step 4.6 — full test run

```bash
cargo test -p waf-engine
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Success Criteria

- [ ] Both new classifier tests pass.
- [ ] Existing `tx_velocity` classifier tests pass after updating expected `Signal` literals.
- [ ] Full workspace compiles — every match arm exhaustively destructuring the modified variants is updated.
- [ ] `Signal::name()` continues to return `"withdrawal_velocity"` / `"limit_change_burst"` (no telemetry breakage).
- [ ] `ok_count <= count` invariant holds — encoded by the loop construction.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| FR-025 risk scorer hard-codes weights against `count` only | Adding `ok_count` does not change `count`. Existing weighting keeps working. If FR-025 wants to use `ok_count`, it can — orthogonal change. |
| Telemetry / dashboards consume signal JSON | `serde(rename_all)` already snake-cases. New field will appear as `"ok_count": N` — additive, non-breaking for JSON consumers. |
| Saturating arithmetic masks an overflow bug | `count` overflowing u32 means >4 billion events in a 16-slot ring — physically impossible. `saturating_add` is defensive only. |

## Notes

After this phase, `Event.outcome` plumbing has end-to-end semantic value — request-entry recording (Pending), response-side enrichment (Ok/Failed), and signal payload (count + ok_count) all reflect the real outcome.
