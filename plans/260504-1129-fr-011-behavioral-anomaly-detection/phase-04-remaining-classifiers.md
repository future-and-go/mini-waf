---
phase: 4
title: "Remaining Classifiers"
status: complete
priority: P1
effort: "1d"
dependencies: [3]
---

# Phase 4: Remaining Classifiers

## Overview

Add the three remaining classifiers in parallel: `regularity` (CV-based bot cadence), `zero_depth` (FR-RS-049), `missing_referer`. Each is a small `RiskSignalProvider` impl reading the same `Recorder` snapshot. All three follow the burst-interval template from Phase 3.

## Requirements

| Provider | Trigger | Risk Delta | FR ref |
|---|---|---|---|
| `regularity` | ≥6 samples, mean interval ≥ 100 ms, CV < 0.15 | +10 | new (FR-011 "bot timing") |
| `zero_depth` | ≥4 samples, all same path, ≥2 on `Tier::Critical`, no Referer in any | +10 | FR-RS-049 |
| `missing_referer` | first nav GET in session, non-exempt path/prefix, no Referer, no `Sec-Purpose: prefetch` | +5 | new |

## Architecture

```
crates/waf-engine/src/device_fp/behavior/providers/
├── burst_interval.rs    (Phase 3)
├── regularity.rs        (NEW)
├── zero_depth.rs        (NEW)
└── missing_referer.rs   (NEW)
```

### Resolved decisions

- **Open Q #3 (session identity for `missing_referer`):** v1 = treat first request from a previously-unseen `FpKey` as "first in session". No WAF cookie. Cookie issuance deferred. Reason: KISS; the device fingerprint is already our session-equivalent.
- **Open Q #5 (`Sec-Purpose: prefetch`):** full exempt. Browser-issued prefetch is a known false-positive source for missing-Referer; a 5-point delta is small enough that being conservative is correct.

### Regularity math

CV = stddev(intervals) / mean(intervals). Compute over the last `min_samples` (default 6) intervals only — not the full window — so the signal is locally responsive. Skip when `mean < min_mean_ms` (default 100) so well-behaved heartbeat clients above the burst threshold are not flagged.

### Zero-depth tier filter

Filter `samples` to those with `tier ∈ {Critical}` before counting. `distinct_paths` count must be exactly 1. If the only path is an exempt entry path (`/`, `/login`, `/index`), do **not** fire (those are legitimately zero-depth on entry).

### Missing-referer exempt list

```yaml
exempt_paths:    ["/", "/login", "/index", "/health"]
exempt_prefixes: ["/static/", "/assets/", "/api/"]
```

The "first in session" check uses `recorder.snapshot(key).is_none() || snapshot.samples.len() == 1` (the just-recorded sample). Note ordering: this provider must run **after** the recorder write that captured the current request, so the sample is in the snapshot.

## Related Code Files

- **Create:**
  - `crates/waf-engine/src/device_fp/behavior/providers/regularity.rs`
  - `crates/waf-engine/src/device_fp/behavior/providers/zero_depth.rs`
  - `crates/waf-engine/src/device_fp/behavior/providers/missing_referer.rs`
- **Modify:**
  - `crates/waf-engine/src/device_fp/behavior/config.rs` — add `RegularityCfg`, `ZeroDepthCfg`, `MissingRefererCfg`.
  - `crates/waf-engine/src/device_fp/behavior/providers/mod.rs` — module wiring.
  - `crates/waf-engine/src/device_fp/registry.rs` — register all three.
  - `crates/waf-engine/tests/behavior_acceptance.rs` — extend with AC2/AC3/AC4 scenarios.
  - `crates/waf-engine/src/device_fp/behavior/state.rs` — add `had_prefetch_hint: bool` to `Sample` if `Sec-Purpose: prefetch` capture is needed.
  - Pingora filter (Phase 2 site) — pass `Sec-Purpose: prefetch` presence and Referer presence into `recorder.record(...)`.

## Implementation Steps

1. Extend `Sample` with `had_prefetch_hint: bool` (additional 1 byte, padded — verify total still ≤ 32 B).
2. Extend `Recorder::record(...)` signature to accept the new field; update Phase 2 call site.
3. Implement `regularity.rs` (~60 LOC). Use integer math where possible (`u64` mean, scaled-int stddev) to avoid floats in hot path; if floats simpler, use `f32` and document.
4. Implement `zero_depth.rs` (~50 LOC). Reuse exempt-path check with `missing_referer` — extract a small `path_classifier.rs` helper if duplicated.
5. Implement `missing_referer.rs` (~50 LOC).
6. Register all three providers in registry, each behind `cfg.<name>.enabled`.
7. Unit tests per provider (matching AC table in research §6.1):
   - **regularity:** CV < 0.15 with 6 equal-spaced samples → fires; CV > 0.15 → silent; mean < 100 ms → silent (burst handles those); < 6 samples → silent; identical intervals (CV=0) → fires.
   - **zero_depth:** 1 path + 2 critical + no referer fires; with referer silent; 2 paths silent; on `Tier::Medium` only silent; entry path (`/login`) silent.
   - **missing_referer:** exempt path silent; exempt prefix silent; first nav fires; subsequent in-session silent; `Sec-Purpose: prefetch` silent.
8. Integration tests in `behavior_acceptance.rs`:
   - **AC2:** 8 reqs same path on `/admin/critical`, no Referer → +10 zero_depth.
   - **AC3:** GET `/dashboard/profile`, no Referer, no prior session → +5 missing_referer.
   - **AC4:** human-like trace (intervals 2300, 1800, 4100, 950, 2700 ms, varied paths, Referer chain) → no signals fire.

## Success Criteria

- [ ] All four AC scenarios in research §6.2 pass (AC1 from Phase 3 + AC2/3/4 here).
- [ ] Each provider file ≤ 100 LOC.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.
- [ ] No duplicated path-classifier logic (DRY: shared helper if used twice).
- [ ] All three providers individually toggleable via config.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Float math in `regularity` causes nondeterministic test failures | Use integer-scaled CV (CV × 1000 as u32) or pin `f32` and assert with epsilon. |
| `missing_referer` fires on legitimate bookmarks/typed URLs | Document as accepted trade-off; +5 is small; CRITICAL-tier rules can downweight via FR-023 scoping. |
| Provider order dependency (record-then-evaluate) | Document explicitly; integration test asserts ordering. |
| Float NaN propagation in CV when mean = 0 | Early-return if mean = 0 (skip eval). |

## Security Considerations

- `Sec-Purpose: prefetch` is client-supplied — a malicious bot could send it to bypass `missing_referer`. Acceptable: the +5 delta is the smallest of the four; bot still trips burst/regularity/zero-depth.
- Path normalization must strip query strings to prevent `/admin?nonce=N` evasion of zero-depth's distinct-path counter.
