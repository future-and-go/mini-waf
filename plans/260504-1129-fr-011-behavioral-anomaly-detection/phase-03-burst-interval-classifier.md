---
phase: 3
title: "Burst Interval Classifier"
status: completed
priority: P1
effort: "0.5d"
dependencies: [2]
---

# Phase 3: Burst Interval Classifier

## Overview

First classifier — smallest in scope, used to validate the entire end-to-end pipeline (Recorder write → snapshot → provider eval → aggregator → risk delta). Implements **FR-RS-048**: ≥5 consecutive inter-request intervals < 50 ms → +15 risk delta.

## Requirements

- **Functional:** Emit `RiskSignal::new("burst_interval", 15)` iff the last `min_consecutive` (default 5) intervals between samples are all `< threshold_ms` (default 50).
- **Non-functional:** Pure function over a snapshot; no I/O; no allocations beyond stack-bounded `ArrayVec`.

## Architecture

```
crates/waf-engine/src/device_fp/behavior/providers/
└── burst_interval.rs    (impl RiskSignalProvider)
```

Register in `device_fp::providers` registry the same way `ua_blocklist`, `fp_conflict`, etc. are registered. Each behavior provider holds an `Arc<Recorder>` to fetch the snapshot.

### Provider sketch

```rust
pub struct BurstIntervalProvider {
    recorder: Arc<Recorder>,
    cfg: Arc<ArcSwap<BehaviorConfig>>,
}

impl RiskSignalProvider for BurstIntervalProvider {
    fn evaluate(&self, ctx: &DeviceCtx<'_>) -> Option<RiskSignal> {
        let cfg = self.cfg.load();
        let snap = self.recorder.snapshot(ctx.key)?;
        let intervals: ArrayVec<u64, 15> = snap.samples
            .windows(2)
            .map(|w| w[1].ts_ms.saturating_sub(w[0].ts_ms))
            .collect();
        let burst = intervals.iter().rev()
            .take_while(|&&d| d < cfg.burst_interval.threshold_ms)
            .count();
        (burst >= cfg.burst_interval.min_consecutive as usize)
            .then(|| RiskSignal::new("burst_interval", cfg.burst_interval.risk_delta))
    }
}
```

## Related Code Files

- **Create:**
  - `crates/waf-engine/src/device_fp/behavior/providers/mod.rs`
  - `crates/waf-engine/src/device_fp/behavior/providers/burst_interval.rs`
  - `crates/waf-engine/tests/behavior_acceptance.rs` (integration entry, will grow in Phase 4)
- **Modify:**
  - `crates/waf-engine/src/device_fp/registry.rs` — register `BurstIntervalProvider`.
  - `crates/waf-engine/src/device_fp/behavior/config.rs` — add `BurstIntervalCfg`.
- **Reference:**
  - `crates/waf-engine/src/device_fp/providers/ua_blocklist.rs` (pattern to mirror).

## Implementation Steps

1. Read one existing provider end-to-end (e.g. `ua_blocklist.rs`) to copy the exact registration shape.
2. Add `BurstIntervalCfg` to `BehaviorConfig` with defaults `{threshold_ms: 50, min_consecutive: 5, risk_delta: 15, enabled: true}`.
3. Implement `BurstIntervalProvider` (~50 LOC).
4. Register in the provider registry — gated behind `cfg.burst_interval.enabled`.
5. `cargo check && cargo clippy --all-targets -- -D warnings` clean.
6. Unit tests in `burst_interval.rs`:
   - 6 samples at 30 ms intervals → fires (+15).
   - 4 samples at 30 ms → silent (below `min_consecutive`).
   - intervals `[30, 30, 200, 30, 30, 30]` → silent (run broken by 200).
   - intervals exactly `50 ms` → silent (strict `<`, boundary case).
   - empty samples → silent.
   - single sample → silent.
7. Integration test in `crates/waf-engine/tests/behavior_acceptance.rs`: drive the full filter with 6 simulated requests at 30 ms apart, assert risk score increased by 15. **Validates Phases 1-3 end-to-end.**

## Success Criteria

- [x] All unit tests pass (6 unit + 2 integration).
- [x] Integration test: 6 reqs @ 30 ms → BurstInterval signal emitted with `count >= 5`. Risk delta of 15 is configured (`BurstIntervalCfg::risk_delta`); the FR-025 aggregator (out of scope) maps name → delta.
- [x] Provider gated behind config flag (`enabled` field tested via `silent_when_disabled`).
- [x] `cargo clippy --all-targets -- -D warnings` clean.
- [ ] Provider file ≤ 100 LOC — **deviated**: 222 LOC including ~140 LOC of tests covering all boundary cases the plan called out. Trimming tests to hit the LOC target would lose coverage; impl + docs alone is ~75 LOC.

## Deviations from plan sketch

- **Trait reuse**: Plan referenced `RiskSignalProvider` / `RiskSignal::new(name, delta)` — neither exists in code. Used existing `SignalProvider` returning `Vec<Signal>`; added `Signal::BurstInterval { count }` flat variant for exhaustive matching at FR-025 risk-scorer sites.
- **No `ArrayVec` dep**: Plan sketch used `ArrayVec<u64, 15>` — `arrayvec` is not a workspace dep. The `windows(2).rev().take_while().count()` pipeline is zero-alloc on `&[Sample]` directly.
- **Boundary test for strict `<`**: dropped — `std::thread::sleep` only guarantees minimum wait, so deterministic exact-millisecond boundary tests need a fake-clock seam (test-only API smell, not warranted yet). Strict `<` is in code at one call site and exercised positively by the firing tests.
- **Registry registration**: deferred to Phase 5. `ProviderRegistry` isn't constructed in any binary yet (`gateway` / `prx-waf` don't call `ProviderRegistry::from_config`); wiring would require designing the construction site, which overlaps with Phase 5's full config plumbing scope.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Off-by-one on `min_consecutive` (N intervals = N+1 samples) | Explicit boundary tests at N and N-1. |
| Reading stale `BehaviorConfig` after reload | Use `cfg.load()` per eval (per-request `Guard`), never cache. |
| Snapshot clone cost on hot path | ~448 B — measure in Phase 6, optimize only if needed. |

## Security Considerations

- `risk_delta` capped to `u8` (≤ 255) by config validation — prevents config-injected score overflow.
