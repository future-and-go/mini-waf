---
phase: 2
title: "DdosBurst Signal + RiskBumpAction Rewrite"
status: completed
priority: P2
dependencies: [1]
---

# Phase 2: DdosBurst Signal + RiskBumpAction Rewrite

## Overview

Add a dedicated `Signal::DdosBurst { risk_delta }` variant that carries the
detector-decided severity end-to-end, then rewrite `RiskBumpAction::execute`
to use the phase-1 `submit_ip` seam. Deletes the `block_in_place` bridge and
the `FpKey` IP-smuggling helpers entirely.

## Requirements

- Functional: SoftAnomaly(δ) submits delta δ; HardBurst submits 100; the
  contributor delta equals the submitted delta (no 20/30 flattening).
- Non-functional: `risk.rs` has zero `tokio` imports; `execute` is pure sync.

## Architecture

Delta passthrough, not weight lookup: the DDoS detector already quantifies
severity (0-100). `signal_to_contributor` maps `DdosBurst` directly to
`Contributor { delta: i16::from(risk_delta) }` — deliberately **not** routed
through the `SignalWeights` table, because a static weight is exactly the
flattening bug being fixed. Score clamping already happens in the store fold.

## Related Code Files

- Modify: `crates/waf-engine/src/device_fp/signal.rs`
- Modify: `crates/waf-engine/src/risk/ingest/signal_to_contributor.rs`
- Modify: `crates/waf-engine/src/checks/ddos/action/risk.rs`

## Implementation Steps

1. **`device_fp/signal.rs`**: add variant with doc comment referencing GH-202
   semantics:

   ```rust
   /// FR-005 — DDoS detector verdict credited to the offending actor.
   /// `risk_delta` is the detector-decided severity (0-100), applied
   /// verbatim as the contributor delta — never weight-table mapped.
   DdosBurst { risk_delta: u8 },
   ```

   Extend `name()` → `"ddos_burst"`; add to `names_are_stable` test.
   (Serde derive is additive — signals are never persisted; verified the only
   consumers are in-process submit → contributor conversion.)

2. **`risk/ingest/signal_to_contributor.rs`**: new match arm:

   ```rust
   Signal::DdosBurst { risk_delta } => (
       ContributorKind::Signal("ddos_burst".into()),
       i16::from(*risk_delta),
   ),
   ```

   No `SignalWeights` entry (passthrough by design — document with a one-line
   comment). Add to `all_signal_variants_mapped` test; note the test asserts
   `delta > 0`, so use a nonzero `risk_delta` there. Add a dedicated test:
   `DdosBurst { risk_delta: 37 }` → delta 37; `{ 100 }` → 100.

3. **`checks/ddos/action/risk.rs` — rewrite**:
   - Delete `ip_to_fp_key`, `burst_signal`, the `block_in_place` block, and
     the `FpKey`/tokio imports.
   - `execute` becomes:

     ```rust
     let risk_delta = match verdict { /* unchanged Allow/Soft/Hard mapping */ };
     if risk_delta == 0 { return ActionResult::noop(); }
     self.aggregator.submit_ip(ip, &[Signal::DdosBurst { risk_delta }]);
     debug!(...);  // unchanged shape
     ActionResult { banned: false, ban_ttl_s: None, risk_delta }
     ```

   - Update module docs: fire-and-forget via sync `submit_ip`, actor = client
     IP on the `RiskKey` IP axis.

4. **Rewrite `risk.rs` unit tests**:
   - Convert the `#[tokio::test(flavor = "multi_thread")]` tests to plain
     `#[test]` — `execute` no longer needs any runtime (this is itself the
     panic-regression proof at the unit level).
   - Assert `LoggingAggregator` snapshot records
     `actor_ip == Some(ip)` and `[Signal::DdosBurst { risk_delta: 50 }]`
     (soft) / `{ 100 }` (hard).
   - Drop `fp_key_contains_ip` (helper deleted); keep Allow/zero-delta noop
     tests.

## Success Criteria

- [ ] `grep -c "tokio\|block_in_place\|block_on" crates/waf-engine/src/checks/ddos/action/risk.rs` → 0.
- [ ] `grep -rn "ddos:" crates/waf-engine/src/checks/ddos/action/` → no
      synthetic-FpKey remnants.
- [ ] SoftAnomaly(37) → contributor delta 37; HardBurst → 100 (unit tests).
- [ ] `cargo test -p waf-engine ddos::action risk::ingest device_fp::signal` green.

## Risk Assessment

- New enum variant: `Signal` matches are exhaustive by design; the compiler
  surfaces every site (verified: only `name()` and `signal_to_contributor`).
- Passthrough delta bypasses operator weight overrides for this one signal —
  intentional and documented; the delta source is the DDoS detector config,
  which is already operator-controlled.
