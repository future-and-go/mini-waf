---
phase: 2
title: "Classifiers + Signal Emission"
status: complete
priority: P1
effort: "1d"
dependencies: [1]
---

# Phase 2: Classifiers + Signal Emission

## Overview

Implement `Classifier` trait + 3 classifiers. Wire signal emission to existing `RiskAggregator`. Cooldown to suppress duplicate signals.

## Requirements

**Functional:**
- 3 classifiers: SequenceTiming, WithdrawalVelocity, LimitChangeBurst
- Each emits `Signal` enum variant with metadata
- Signal cooldown (`last_signal_ms` per actor) suppresses spam
- Submit signals to `RiskAggregator` (fire-and-forget async)

**Non-functional:**
- Per-classifier eval <20µs
- Total recorder.record(...) path <100µs (3 classifiers + cooldown check)

## Architecture

```rust
pub trait Classifier: Send + Sync {
    fn name(&self) -> &'static str;
    fn evaluate(&self, actor: &ActorTx, now_ms: u64, cfg: &TxVelocityConfig)
        -> Option<Signal>;
}
```

Recorder.record() invokes each Classifier; collects `Some(Signal)`; submits batch to aggregator if cooldown elapsed.

## Signal Variants (extend `device_fp::signal::Signal` OR new enum)

**Decision:** Add new variants to existing `Signal` enum (`crates/waf-engine/src/device_fp/signal.rs`). Keeps single signal sink.

- `Signal::TxSequenceTooFast { from: EndpointRole, to: EndpointRole, interval_ms: u64 }`
- `Signal::WithdrawalVelocity { count: u32, window_sec: u32 }`
- `Signal::LimitChangeBurst { count: u32, window_sec: u32 }`

## Related Code Files

**Create:**
- `crates/waf-engine/src/checks/tx_velocity/classifier.rs` — trait
- `crates/waf-engine/src/checks/tx_velocity/classifiers/mod.rs`
- `crates/waf-engine/src/checks/tx_velocity/classifiers/sequence_timing.rs`
- `crates/waf-engine/src/checks/tx_velocity/classifiers/withdrawal_velocity.rs`
- `crates/waf-engine/src/checks/tx_velocity/classifiers/limit_change_burst.rs`

**Modify:**
- `crates/waf-engine/src/device_fp/signal.rs` — add 3 variants
- `crates/waf-engine/src/checks/tx_velocity/recorder.rs` — invoke classifiers, submit to aggregator

## Implementation Steps

1. **Extend Signal enum** — add 3 variants; update any exhaustive matches (compiler will error-list them)

2. **Classifier trait** (`classifier.rs`):
   ```rust
   pub trait Classifier: Send + Sync {
       fn name(&self) -> &'static str;
       fn evaluate(&self, actor: &ActorTx, now_ms: u64, cfg: &Self::Cfg) -> Option<Signal>;
   }
   ```
   Use generic `Cfg` per classifier OR pass full `TxVelocityConfig` (KISS — pass full config).

3. **SequenceTimingClassifier**:
   - Scan ring buffer for transitions: most-recent Login→Otp, Otp→Deposit
   - If interval < threshold → `Signal::TxSequenceTooFast`
   - Only fire on the latest event being the "to" role

4. **WithdrawalVelocityClassifier**:
   - Count `Withdrawal` events with `ts_ms >= now_ms - window_sec*1000`
   - If count > max_per_window → emit signal

5. **LimitChangeBurstClassifier**:
   - Same shape as withdrawal velocity but `LimitChange` role + own thresholds

6. **Recorder integration**:
   - Hold `Vec<Box<dyn Classifier>>` constructed at startup from config
   - On record(): if `now_ms - actor.last_signal_ms >= cooldown_ms`, run classifiers
   - Collect emitted signals; submit batch via `RiskAggregator::submit(key, signals)`
   - Update `last_signal_ms` if any fired

7. **Aggregator wiring**:
   - Recorder constructor takes `Arc<dyn RiskAggregator>`
   - Submission is async fire-and-forget (tokio::spawn) — don't block request path

## Todo List

- [x] Extend `Signal` enum with 3 variants; fix any match-exhaustive sites
- [x] Implement `Classifier` trait
- [x] Implement SequenceTimingClassifier + unit tests
- [x] Implement WithdrawalVelocityClassifier + unit tests
- [x] Implement LimitChangeBurstClassifier + unit tests
- [x] Wire classifiers into recorder.record()
- [x] Implement signal cooldown logic
- [x] Wire RiskAggregator submission (fire-and-forget)
- [x] `cargo fmt && cargo clippy -- -D warnings && cargo test -p waf-engine` green

## Success Criteria

- [x] All 3 classifiers have ≥3 unit tests each (positive, negative, edge)
- [x] Cooldown verified: 2 sequential triggers within cooldown_ms → 1 signal
- [x] Aggregator receives submission (use mock impl in tests)
- [x] No clippy warnings
- [x] No `.unwrap()` outside tests

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Adding Signal variants breaks downstream matches | Compile-time exhaustiveness — fix at point of failure |
| Classifier loop cost grows with N classifiers | N=3, hardcoded; revisit if list grows |
| Aggregator backpressure stalls request path | Fire-and-forget via tokio::spawn; bounded channel if needed |

## Security Considerations

- Conservative defaults to minimize false positives
- Cooldown prevents signal flooding (DoS amplification)
- No PII in Signal payloads (role enums + numeric metadata only)
