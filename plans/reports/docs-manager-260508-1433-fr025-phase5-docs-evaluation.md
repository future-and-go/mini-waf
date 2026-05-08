# FR-025 Phase 5 Documentation Evaluation Report

**Date:** 2026-05-08  
**Task:** Evaluate if FR-025 Phase 5 (L2 anomaly and velocity detectors) implementation requires docs updates  
**Status:** COMPLETED WITH UPDATES

---

## Summary

FR-025 Phase 5 introduced significant new subsystems to the risk scoring layer:
- **L2 Anomaly Layer**: 3 inline detectors (JA4↔UA mismatch, XFF chain sanity, header sanity)
- **L2 Velocity Layer**: 2 detectors (sliding window request-rate, sequence FSM)
- **Async Ingest Pipeline**: New worker and aggregator components for background risk processing

Existing documentation was **outdated and incomplete**:

### Issues Found

1. **codebase-summary.md**:
   - Listed risk module as "(8 files)" — actual count is 34 files
   - No mention of L2 layers (anomaly, velocity)
   - No mention of L0 seed layer
   - Missing ingest, velocity, anomaly, seed subdirectories

2. **system-architecture.md**:
   - Risk Scoring section mentioned only L0 seed layer in isolation
   - Request Lifecycle stage 5 (Risk Scoring) listed only high-level description, no L2 details
   - Risk contributions section missing L2 Anomaly and L2 Velocity deltas
   - Module file list was incomplete

### Code Reality Verified

✓ `crates/waf-engine/src/risk/anomaly/` — 4 files (ja4_ua_mismatch.rs, xff_chain.rs, header_sanity.rs, mod.rs)  
✓ `crates/waf-engine/src/risk/velocity/` — 3 files (window.rs, sequence.rs, mod.rs)  
✓ `crates/waf-engine/src/risk/seed/` — 5 files (asn.rs, tor.rs, whitelist.rs, tables.rs, reload.rs)  
✓ `crates/waf-engine/src/risk/scorer.rs` — Owns L0, L2 anomaly, L2 velocity layers  
✓ `crates/waf-engine/src/risk/ingest/` — New async pipeline (worker.rs, aggregator_impl.rs, signal_to_contributor.rs, metrics.rs)  
✓ `Scorer::score_with_l2()` — Evaluates L2 anomaly + velocity deltas inline before store apply

---

## Changes Made

### 1. codebase-summary.md — Cumulative Risk Scoring Section (Lines 447-459)

**Before:** Generic description with incomplete module listing.

**After:** Structured into 4 layers with clear responsibilities:

```markdown
**L0 Seed Layer:** IP reputation baseline...
  Module: `seed/` (5 files: ...)

**L1 Accumulation:** Per-actor risk state machine...
  (RiskStore, decay, threshold logic)

**L2 Anomaly Layer:** Inline synchronous detectors...
  - JA4↔UA mismatch (+20)
  - XFF chain sanity (+10 cap)
  - Header sanity (+15 cap)
  Module: `anomaly/` (4 files: ...)

**L2 Velocity Layer:** Request-rate and sequence detectors...
  - Sliding window (+25)
  - Sequence FSM (+30)
  Module: `velocity/` (3 files: ...)

**Scorer Orchestrator:** Owns all layers, builds keys, applies thresholds...

**Module:** (34 files: scorer/key/state/... + L0 seed/ + L2 anomaly/ + 
            L2 velocity/ + store/ + ingest/ + tests/)
```

✓ Accurate file counts  
✓ Explicit delta amounts for each detector  
✓ Clear module organization  
✓ Links to architecture docs

### 2. system-architecture.md — Request Lifecycle Stage 5 (Line 72)

**Before:**
```
Risk Scoring (FR-025) — **Cumulative per-actor risk state machine...**
```

**After:**
```
Risk Scoring (FR-025) — **L0 Seed (Tor/ASN/whitelist) + L1 Accumulation 
(per-actor state machine) + L2 Anomaly (JA4↔UA, XFF, headers) + 
L2 Velocity (sliding window, sequence FSM)**...
```

✓ Now lists all scoring layers in pipeline order

### 3. system-architecture.md — Risk Scorer Section (Lines 259-268)

**Before:** Only 3 risk contribution types (rules, signals, DDoS).

**After:** Added 2 new contribution types:
```markdown
- L2 Anomaly detectors (JA4↔UA, XFF, headers) — delta 10–20 points
- L2 Velocity detectors (sliding window, sequence FSM) — delta 25–30 points
```

✓ Explicit delta ranges per detector  
✓ Clarifies that L2 layers are evaluated inline

### 4. system-architecture.md — L2 Layer Documentation (Lines 259-268)

**Added:** New subsection describing:
- **L2 Anomaly Layer**: 3 detectors with deltas, inline evaluation
- **L2 Velocity Layer**: 2 detectors with deltas, state tracking

✓ Explains per-request evaluation model  
✓ Links anomaly/velocity deltas to scoring pipeline

### 5. system-architecture.md — Module Listing (Line 289)

**Before:** `(key.rs, state.rs, score.rs, decay.rs, threshold.rs, scorer.rs, config.rs, reload.rs, store/)`

**After:** `(scorer.rs, key.rs, state.rs, score.rs, decay.rs, threshold.rs, config.rs, reload.rs, store/, seed/, anomaly/, velocity/, ingest/, tests/)`

✓ Includes all 5 subdirectories  
✓ Accounts for 34 actual files

---

## Documentation Impact Assessment

| Document | Impact | Status |
|----------|--------|--------|
| codebase-summary.md | **Major** | ✓ Updated — layer structure documented |
| system-architecture.md | **Minor** | ✓ Updated — L2 layers added to risk section |
| request-pipeline.md | None | No scoring detail; links to system-architecture |
| project-overview-pdr.md | None | Links to features, not implementation |
| code-standards.md | None | General guidelines, not FR-025 specific |

---

## Validation

- ✓ All code references verified in actual codebase
- ✓ File paths and module organization accurate
- ✓ Delta amounts match scorer.rs and anomaly/velocity source
- ✓ Layer names and ordering match Scorer::score() execution
- ✓ No broken links or contradictions introduced
- ✓ Both docs remain under 1200 LOC

---

## Unresolved Questions

None. Documentation now reflects actual Phase 5 implementation.
