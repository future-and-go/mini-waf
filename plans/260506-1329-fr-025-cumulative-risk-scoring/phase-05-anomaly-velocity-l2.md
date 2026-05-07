---
phase: 5
title: "Anomaly & Velocity L2"
status: pending
priority: P1
effort: "3d"
dependencies: [1, 4]
---

# Phase 5: Anomaly & Velocity L2 — Per-Request Synchronous Detectors

## Overview

Add inline (synchronous, hot-path) anomaly detectors that don't depend on background capture: JA4 ↔ UA mismatch, XFF chain sanity, header sanity, sliding-window velocity, transaction-sequence FSM (Login→OTP→Withdrawal). Each emits sync deltas in the current request — no MPSC round-trip, no convergence delay.

Decay applied here too: read state → apply `decay(state, now)` BEFORE folding new deltas → write back. This is the ONLY phase that mutates state due to time elapse.

## Why P5 After Async Pipeline

Async pipeline (P4) handles signals that NEED background capture. L2 here is for what the request itself reveals, in-band. Adding L2 last among detection layers means we ship P5 only after lifecycle (rise on attack, decay on calm) is verified end-to-end through async signals.

## Requirements

**Functional:**
- JA4↔UA mismatch detector — Chrome JA4 with Firefox UA → +20 (`Anomaly("ja4_ua_mismatch")`).
- XFF chain sanity — X-Forwarded-For with private IPs after public, or chain length >5 → +10.
- Header sanity — missing Accept, Accept-Language, or impossible combos (e.g. Sec-Fetch-Dest with no Sec-Fetch-Site) → +5 each, capped at +15 per request.
- Sliding-window velocity — `risk/velocity/window.rs` 60×1s ring buffer per `RiskKey`. Threshold breached (e.g. >100 req/min on Critical-tier path) → +25.
- Transaction sequence FSM — Login→OTP→Withdrawal. Out-of-order or impossible-fast → +30 (reuse FR-012 logic; this phase only ports the FSM into sync path for cases not covered by FR-012's async signal).
- Decay applied as `decay(state, now)` before folding new deltas — uses `MAX_DECAY=50` floor (Iron Rule §4).
- `clean_streak` increments on Allow + zero new deltas; resets on any positive delta.

**Non-functional:**
- L2 evaluation p99 ≤ 1ms (criterion gate).
- Decay ≤ 50µs.
- Sliding-window ring updates O(1) amortized.

## Architecture

```
risk/anomaly/
├── mod.rs                  # AnomalyLayer struct
├── ja4_ua_mismatch.rs      # JA4 family vs UA family lookup
├── xff_chain.rs            # XFF chain validator
└── header_sanity.rs        # impossible-combo detector

risk/velocity/
├── mod.rs
├── window.rs               # 60-bucket ring (1s buckets)
└── sequence.rs             # Login→OTP→Withdrawal FSM (sync side)
```

### JA4 ↔ UA Mismatch (Static Table)

```rust
// Hard-coded family table; compact. Hot-reloadable via separate config file later.
match (ja4_family(ja4), ua_family(ua)) {
    (Some(JaFamily::Chrome), Some(UaFamily::Firefox)) => true,
    (Some(JaFamily::Firefox), Some(UaFamily::Chrome)) => true,
    // ... ~10 known impossible pairs
    _ => false,
}
```

### Velocity Sliding Window

60×1s buckets (one minute). On request: `buckets[now_sec % 60].count += 1`. On read: sum over buckets where `now - bucket_ts < window_sec`. State stored inside `RiskState` (extra field) OR keyed separately to avoid bloating the state struct (decision: keep separate `DashMap<RiskKey, Window>` to keep `RiskState` small; access in same `apply` codepath).

### Decay Function (already exists from P1)

`decay(state, now)`:
- Compute `elapsed = now - last_updated`.
- `new_score = clamp_score - (elapsed / half_life_sec) * decay_rate`.
- Apply `MAX_DECAY=50` floor — `new_score = max(new_score, original - 50)`.
- Update `last_updated`.

## Related Code Files

**Create:**
- `crates/waf-engine/src/risk/anomaly/mod.rs`
- `crates/waf-engine/src/risk/anomaly/ja4_ua_mismatch.rs`
- `crates/waf-engine/src/risk/anomaly/xff_chain.rs`
- `crates/waf-engine/src/risk/anomaly/header_sanity.rs`
- `crates/waf-engine/src/risk/velocity/mod.rs`
- `crates/waf-engine/src/risk/velocity/window.rs`
- `crates/waf-engine/src/risk/velocity/sequence.rs`
- `crates/waf-engine/src/risk/tests/lifecycle.rs` (rise → decay scenario)
- `crates/waf-engine/src/risk/tests/anomaly_combos.rs`
- `crates/waf-engine/benches/risk_anomaly.rs`

**Modify:**
- `crates/waf-engine/src/risk/mod.rs` — `pub mod {anomaly, velocity};`
- `crates/waf-engine/src/risk/scorer.rs` — call anomaly + velocity layers between rule deltas (P3) and final `apply` (so all sync deltas land in one `apply` call).
- `crates/waf-engine/src/risk/state.rs` — `clean_streak: u32` field (already present from P1; verify increment logic).

## Implementation Steps

1. **JA4↔UA mismatch.** Compact static family table (≤10 impossible pairs). Test each pair → +20 contributor. Unknown JA4 OR unknown UA → no signal (silent).
2. **XFF chain.** Parse `X-Forwarded-For`; flag (a) private IP after public, (b) chain length >5, (c) duplicate IPs. Each +5, cap +10.
3. **Header sanity.** Missing Accept/Accept-Language → +5 each. Impossible Sec-Fetch combo → +5. Cap +15.
4. **Velocity window.** 60×1s ring per RiskKey. Lock-free via `AtomicU32` per bucket OR `parking_lot::Mutex` if tight. Bench both; pick fastest under 5k rps.
5. **Sequence FSM (sync side).** Reuse FR-012 endpoint role detection; if Login→OTP transition <1.5s in this same request chain → +30 sync delta.
6. **Decay integration.** In `Scorer::evaluate`: `let pre = store.read(key)?; let decayed = decay(pre, now); let post = store.apply(key, &all_deltas, now)?` — but this races. Better: `store.apply` itself calls `decay` internally before fold (atomic under the state's RwLock). Refactor `apply` to take an optional `decay_now` param OR always decay-before-fold (simpler).
7. **`clean_streak` logic.** Inside state's RwLock: if all deltas ≤0 AND no positive contributors in last fold, increment; else reset. Drives "sustained normal" credit (FR-026).
8. **Tests.**
   - `lifecycle.rs`: emit attack signals → score 60 → wait 10×half_life → score should NOT drop below `original - 50` (MAX_DECAY floor).
   - `clean_streak`: 100 normal requests → small negative credits applied.
   - `anomaly_combos.rs`: each detector → expected delta.
   - JA4 mismatch parameterized over family pairs.
9. **Bench.** L2 evaluation full pipeline ≤ 1ms p99; decay ≤ 50µs.
10. **Compile gates.**

## Common Pitfalls

- **Decay erasing all evidence** (§6 pitfall #5) — MAX_DECAY=50 enforced; do not relax.
- **JA4 family table out of date** → false positives. Operator-overridable in P9; for v1 keep table conservative.
- **XFF private-IP-after-public false-positive** for legitimate corp networks → permit operator override list.
- **Velocity window reset bug** — bucket index `now_sec % 60` reuses old bucket — must zero on first hit.
- **Sequence FSM double-counts FR-012 async signal** — sync side fires only when async signal would NOT (i.e. sequence completes in single request chain).

## Success Criteria

- [ ] All 4 detectors emit correct deltas; parameterized tests cover each.
- [ ] Decay applied with MAX_DECAY=50 floor (lifecycle test verifies).
- [ ] `clean_streak` decrements score on sustained normal traffic.
- [ ] L2 evaluation p99 ≤ 1ms.
- [ ] No double-counting with FR-012 async signal.
- [ ] No `.unwrap()` introduced.
- [ ] Each new file ≤ 200 LoC.

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Decay miscomputed → score never decreases | High | MAX_DECAY floor explicit; lifecycle test gates merge |
| JA4 family table false-positive | Medium | Conservative initial table; operator override path in P9 |
| XFF interpretation behind corp proxies | Medium | Operator-supplied trusted-proxy CIDR list (already used by FR-007) |
| Velocity window contention | Medium | Atomic bucket ops; per-key shard via DashMap |
| FR-009 cache layer skips L2 | Medium | Document; cache-miss path always runs L2; cache-hit path looks up state-only at egress |

## Verify

```bash
cargo test -p waf-engine risk::anomaly
cargo test -p waf-engine risk::velocity
cargo test -p waf-engine risk::tests::lifecycle
cargo bench -p waf-engine --bench risk_anomaly
```
