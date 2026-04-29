# FR-002 Phase-05: Tier Classifier Wired into Request Lifecycle

**Date**: 2026-04-29 11:37
**Severity**: Low
**Component**: Gateway request context, tier classification pipeline
**Status**: Resolved

## What Happened

Completed phase-05 of FR-002 (Tiered Protection): wiring tier classifier into the request lifecycle. `RequestCtx` extended with non-Optional `tier: Tier` and `tier_policy: Arc<TierPolicy>` fields. Registry integrated at proxy startup and request build time.

## The Brutal Truth

The fixture bulk-edit was tedious. Yes, we automated the regex (`geo: None,`), but manual patch for the `geo: Some(...)` case in geo.rs broke the automation streak. The friction point: design doc mandated non-Optional fields on RequestCtx to avoid runtime panics on missing data. Right decision technically. Annoying in practice.

## Technical Details

**RequestCtx changes:**
- Added `pub tier: Tier` (defaults to `Tier::CatchAll`)
- Added `pub tier_policy: Arc<TierPolicy>` (Arc so consumers hold across `.await`)
- Implemented `RequestCtx::default_tier_policy()` using `OnceLock` — process-wide cached Arc so 30+ test fixtures share one allocation

**Request lifecycle wiring:**
- `request_ctx_builder.rs::build()` runs `TierPolicyRegistry::classify()` before returning
- Fallback: missing registry → logs info, uses `Tier::CatchAll + TierPolicy::default()`
- `Proxy` holds `Option<Arc<TierPolicyRegistry>>`; passed at `request_filter` and `upstream_peer` call sites

**Startup bootstrap:**
- `prx-waf::main::try_init_tier_registry()` loads TOML, spawns `TierConfigWatcher`
- Fail-open: missing config logs info, proceeds with CatchAll

**Test fixture reality:**
- Python regex script updated 30+ sites matching `geo: None,`
- Manual fix required for one `geo: Some(...)` occurrence (geo.rs line 191)
- ~48 files changed; all tests/clippy/release build green

## What We Tried

Nothing failed. Fixture updates were straightforward regex + one manual patch. No blockers.

## Root Cause Analysis

Non-optional RequestCtx fields enforce correctness at compile time. Trade-off: test setup verbosity. Accepted as worth paying.

## Lessons Learned

OnceLock for process-wide defaults is the pattern for shared, immutable allocations across test fixtures. Saves allocation churn and makes Arc costing explicit. Automation handles 95% of bulk edits; always budget manual pass for edge cases.

## Next Steps

Phase-06: Comprehensive test suite + performance benchmarks + consumer documentation. Expected to be the heavier lift for coverage validation and example code.

**Commit:** b765c73 — 48 files, all checks passing.
