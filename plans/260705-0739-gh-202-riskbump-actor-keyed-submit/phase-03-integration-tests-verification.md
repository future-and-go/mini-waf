---
phase: 3
title: "Integration Tests & Verification"
status: pending
priority: P2
dependencies: [1, 2]
---

# Phase 3: Integration Tests & Verification

## Overview

End-to-end proof of all three GH-202 acceptance criteria against the real
ingest pipeline (`ScoringAggregator` → worker → `MemoryRiskStore`), plus a
current_thread panic-regression test and full quality gates.

## Requirements

- Functional: HardBurst on IP `a.b.c.d` measurably raises risk state readable
  at `RiskKey::from_ip(a.b.c.d)` — the same key shape the request-path scorer
  builds (`scorer.rs::build_key`).
- Non-functional: no test relies on `multi_thread` flavor to avoid a panic.

## Related Code Files

- Create: `crates/waf-engine/tests/ddos_risk_bump_acceptance.rs`
- Modify (verify only): none — phases 1-2 carry the source changes.

## Implementation Steps

1. **Acceptance test file** `tests/ddos_risk_bump_acceptance.rs`:

   - `hard_burst_raises_scored_actor_state` (`#[tokio::test]`, default
     current_thread — deliberately, to prove runtime-flavor agnosticism on
     the submit side):
     1. `MemoryRiskStore` as `Arc<dyn RiskStore>`;
        `ScoringAggregator::start(store.clone(), SignalWeights::default())`.
     2. `RiskBumpAction::new(Arc::new(agg))`, `execute(ip, HardBurst{..}, now)`
        — plain sync call, no `block_in_place`.
     3. Await worker drain (poll `metrics().processed_total() == 1` with
        timeout, matching existing ingest test style).
     4. `store.read(&RiskKey::from_ip(ip))` → state exists,
        `clamped_score > 0`, contributor kind is `Signal("ddos_burst")` and
        delta 100.
     - Note: worker runs on the same current_thread runtime — `tokio::spawn`
       is flavor-agnostic; only the deleted `block_in_place` was not.
   - `soft_anomaly_preserves_severity`: `SoftAnomaly(37)` → contributor
     delta 37 in the stored state (severity end-to-end, criterion 3).
   - `phantom_actor_regression`: after a HardBurst submit, assert **no**
     state exists under
     `RiskKey { ip: None, fp_hash: RiskKey::hash_fp_key(&FpKey { ja3: "ddos:{ip}" ... }), .. }`
     (the old smuggled key) — pins criterion 2 against regression.

2. **Current_thread panic regression, unit level**: confirmed by phase 2's
   conversion of `risk.rs` tests to plain `#[test]` (no runtime present at
   all); the acceptance test covers the in-runtime case.

3. **Quality gates** (from repo workflow):

   ```bash
   cargo test -p waf-engine ddos risk::ingest device_fp
   cargo test -p waf-engine --test ddos_risk_bump_acceptance
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo fmt --check
   ```

4. **Docs**: no user-facing behavior change (feature still unwired) — no
   `docs/` updates required. Update GH-202 handoff log via issue comment at
   ship time.

## Success Criteria

- [ ] All three GH-202 acceptance checkboxes provable by named tests:
      - runtime-flavor agnostic → `hard_burst_raises_scored_actor_state` on
        current_thread + plain `#[test]` unit tests
      - real actor key → same test reads `RiskKey::from_ip(ip)`
      - severity preserved → `soft_anomaly_preserves_severity`
- [ ] `phantom_actor_regression` locks out the smuggled-key shape.
- [ ] Workspace tests, clippy `-D warnings`, fmt all green.

## Risk Assessment

- Flaky drain waits: use bounded polling on `IngestMetrics::processed_total`
  (pattern already used in `aggregator_impl.rs` tests) instead of fixed
  sleeps where possible.
- `cargo test --workspace` runtime is long; acceptable per repo verify norms
  (narrow first, then broaden — shared `Signal` enum changed, so broadening
  is required).
